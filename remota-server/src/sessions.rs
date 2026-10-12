//! Starting and running sessions (SidiOS `contracts/remota-api.md`, "Sessions"):
//!
//! 1. `POST /api/sessions` resolves the connection's effective settings, applies the policy and
//!    the limits, pins the addresses, and asks webOS for a single-use 60-second ticket;
//! 2. the browser opens `/session/{id}?ticket=…`; the ticket must match, belong to the same user,
//!    and be consumed with webOS, which only then releases the credentials;
//! 3. every 30 seconds webOS names the sessions whose users are no longer active, and an
//!    administrator can end sessions through the control port.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{ws::WebSocketUpgrade, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

use crate::{
    identity::WebosUser,
    model::{Effective, Protocol},
    policy::{resolve_pinned, Refusal},
    ssh::{self, Auth, Hop, Outcome, SshPlan},
    tree::{blocking, change, collect_garbage, ApiError, ApiResult},
    webos::{AuditEvent, Grant, NewCredential, SharedWebos, TicketRequest, WebosError},
    AppState,
};

/// A started session must be opened within this time (the ticket's own lifetime is 60 s).
const PENDING_LIFETIME: Duration = Duration::from_secs(90);
pub const CHECK_INTERVAL: Duration = Duration::from_secs(30);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/sessions", post(start))
        .route("/api/trust/forget", post(forget_trust))
        .route("/session/{id}", get(open))
}

struct Pending {
    user: String,
    ticket: String,
    created: Instant,
    plan: PendingPlan,
}

/// What a started session will connect to; credentials are added when the ticket is consumed.
#[derive(Clone)]
struct PendingPlan {
    protocol: Protocol,
    target: Endpoint,
    jump: Option<Endpoint>,
    one_time_password: Option<String>,
}

#[derive(Clone)]
struct Endpoint {
    address: std::net::SocketAddr,
    host: String,
    port: u16,
    username: String,
    credential_id: Option<String>,
}

struct Running {
    user: String,
    cancel: CancellationToken,
}

/// Started (not yet opened) and running sessions of this Remota instance.
#[derive(Clone, Default)]
pub struct Sessions {
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    running: Arc<Mutex<HashMap<String, Running>>>,
}

impl Sessions {
    fn count(&self, user: Option<&str>) -> usize {
        let pending = self.pending.lock().expect("sessions");
        let running = self.running.lock().expect("sessions");
        let mine = |owner: &str| user.is_none_or(|user| user == owner);
        pending
            .values()
            .filter(|p| p.created.elapsed() < PENDING_LIFETIME && mine(&p.user))
            .count()
            + running.values().filter(|r| mine(&r.user)).count()
    }

    fn take_pending(&self, id: &str, user: &str, ticket: &str) -> Option<Pending> {
        let mut pending = self.pending.lock().expect("sessions");
        pending.retain(|_, p| p.created.elapsed() < PENDING_LIFETIME);
        let entry = pending.get(id)?;
        let matches =
            entry.user == user && bool::from(entry.ticket.as_bytes().ct_eq(ticket.as_bytes()));
        if matches {
            pending.remove(id)
        } else {
            None
        }
    }

    /// Every running session as (user key, session ID), for the webOS check.
    pub fn running(&self) -> Vec<(String, String)> {
        self.running
            .lock()
            .expect("sessions")
            .iter()
            .map(|(id, running)| (running.user.clone(), id.clone()))
            .collect()
    }

    /// Ends the named sessions, or every session of `user`, or every session.
    pub fn end(&self, ids: Option<&[String]>, user: Option<&str>) -> usize {
        let running = self.running.lock().expect("sessions");
        let mut ended = 0;
        for (id, session) in running.iter() {
            let named = ids.is_none_or(|ids| ids.contains(id));
            let owned = user.is_none_or(|user| user == session.user);
            if named && owned {
                session.cancel.cancel();
                ended += 1;
            }
        }
        ended
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartBody {
    connection_id: String,
    #[serde(default)]
    one_time_secret: Option<String>,
    #[serde(default)]
    save_secret: bool,
}

async fn start(
    State(state): State<AppState>,
    user: WebosUser,
    Json(body): Json<StartBody>,
) -> ApiResult<Response> {
    let store = state.store.clone();
    let key = user.key.clone();
    let id = body.connection_id.clone();
    let effective = blocking(move || store.for_user(&key).document())
        .await?
        .effective(&id)
        .ok_or(ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    if effective.protocol == Protocol::Rdp {
        return Err(ApiError(StatusCode::NOT_IMPLEMENTED, "rdp_unavailable"));
    }
    let effective = with_secret(&state, &user.key, &body, effective).await?;
    let plan = plan(
        &state,
        &user.key,
        &effective,
        body.one_time_secret.filter(|_| !body.save_secret),
    )
    .await?;
    let ticket = issue(&state.webos, &user.key, &body.connection_id, &plan).await?;
    let session_id = uuid::Uuid::new_v4().to_string();
    state.sessions.pending.lock().expect("sessions").insert(
        session_id.clone(),
        Pending {
            user: user.key.clone(),
            ticket: ticket.clone(),
            created: Instant::now(),
            plan,
        },
    );
    let body = json!({
        "sessionId": session_id,
        "protocol": "ssh",
        "websocket": format!("/session/{session_id}?ticket={ticket}"),
    });
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// Seals a password typed at connect time when the user asked to save it; otherwise a connection
/// without any credential needs one.
async fn with_secret(
    state: &AppState,
    user: &str,
    body: &StartBody,
    mut effective: Effective,
) -> ApiResult<Effective> {
    let typed = body.one_time_secret.as_deref().filter(|s| !s.is_empty());
    match typed {
        Some(secret) if body.save_secret => {
            let credential = NewCredential {
                id: None,
                kind: "password".into(),
                label: effective.name.chars().take(120).collect(),
                username: effective.username.clone(),
                secret: secret.to_owned(),
                passphrase: None,
            };
            let id = state.webos.save_credential(user, credential).await?;
            let connection = body.connection_id.clone();
            let saved = id.clone();
            change(&state.store, user, move |doc| {
                doc.set_connection_credential(&connection, saved)
            })
            .await?;
            collect_garbage(state, user).await;
            effective.credential_id = Some(id);
            Ok(effective)
        }
        Some(_) => Ok(effective),
        None if effective.credential_id.is_none() => {
            Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "no_credential"))
        }
        None => Ok(effective),
    }
}

fn refusal(refusal: Refusal) -> ApiError {
    ApiError(StatusCode::FORBIDDEN, refusal.code())
}

async fn plan(
    state: &AppState,
    user: &str,
    effective: &Effective,
    one_time_password: Option<String>,
) -> ApiResult<PendingPlan> {
    let username = effective
        .username
        .clone()
        .ok_or(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "no_username"))?;
    let policy = state.policy.current().await.map_err(refusal)?;
    if state.sessions.count(Some(user)) >= policy.max_sessions_user
        || state.sessions.count(None) >= policy.max_sessions_total
    {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "session_limit"));
    }
    let pin = |host: String, port: u16| {
        let policy = policy.clone();
        let denies = state.denies.clone();
        async move { resolve_pinned(&policy, &denies, effective.protocol, &host, port).await }
    };
    let target = pin(effective.host.clone(), effective.port)
        .await
        .map_err(refusal)?;
    let jump = match &effective.jump {
        Some(jump) => Some(Endpoint {
            address: pin(jump.host.clone(), jump.port).await.map_err(refusal)?,
            host: jump.host.clone(),
            port: jump.port,
            username: jump.username.clone().unwrap_or_else(|| username.clone()),
            credential_id: jump.credential_id.clone(),
        }),
        None => None,
    };
    Ok(PendingPlan {
        protocol: effective.protocol,
        target: Endpoint {
            address: target,
            host: effective.host.clone(),
            port: effective.port,
            username,
            credential_id: effective.credential_id.clone(),
        },
        jump,
        one_time_password,
    })
}

async fn issue(
    webos: &SharedWebos,
    user: &str,
    connection: &str,
    plan: &PendingPlan,
) -> ApiResult<String> {
    let mut credential_ids: Vec<String> = plan
        .target
        .credential_id
        .iter()
        .chain(
            plan.jump
                .iter()
                .filter_map(|jump| jump.credential_id.as_ref()),
        )
        .cloned()
        .collect();
    credential_ids.dedup();
    let request = TicketRequest {
        connection_id: connection.to_owned(),
        credential_ids,
        jump: plan.jump.as_ref().map(|jump| jump.address.to_string()),
        protocol: plan.protocol.as_str().to_owned(),
        target: plan.target.address.to_string(),
    };
    Ok(webos.issue_ticket(user, request).await?)
}

#[derive(Deserialize)]
struct OpenQuery {
    ticket: String,
    #[serde(default)]
    cols: Option<u32>,
    #[serde(default)]
    rows: Option<u32>,
}

async fn open(
    State(state): State<AppState>,
    user: WebosUser,
    Path(id): Path<String>,
    Query(query): Query<OpenQuery>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let Some(pending) = state.sessions.take_pending(&id, &user.key, &query.ticket) else {
        return ApiError(StatusCode::UNAUTHORIZED, "ticket_invalid").into_response();
    };
    let grant = match state.webos.consume_ticket(&user.key, &pending.ticket).await {
        Ok(grant) => grant,
        Err(_) => return ApiError(StatusCode::UNAUTHORIZED, "ticket_invalid").into_response(),
    };
    let Some(plan) = ssh_plan(&pending.plan, &grant, query.cols, query.rows) else {
        return ApiError(StatusCode::UNPROCESSABLE_ENTITY, "no_credential").into_response();
    };
    let cancel = CancellationToken::new();
    state.sessions.running.lock().expect("sessions").insert(
        id.clone(),
        Running {
            user: user.key.clone(),
            cancel: cancel.clone(),
        },
    );
    let audit = audit_event(&pending.plan);
    upgrade.on_upgrade(move |socket| async move {
        state
            .webos
            .audit(&user.key, audit("remota.session.start", "started"))
            .await;
        let outcome = ssh::run(socket, plan, state.store.clone(), user.key.clone(), cancel).await;
        state.sessions.running.lock().expect("sessions").remove(&id);
        let result = match outcome {
            Outcome::Ended => "ended",
            Outcome::Revoked => "revoked",
            Outcome::Idle => "idle",
            Outcome::TrustRefused => "trust_refused",
            Outcome::Failed => "failed",
        };
        state
            .webos
            .audit(&user.key, audit("remota.session.end", result))
            .await;
    })
}

fn audit_event(plan: &PendingPlan) -> impl Fn(&'static str, &'static str) -> AuditEvent {
    let host = plan.target.host.clone();
    let port = plan.target.port;
    let protocol = plan.protocol.as_str();
    move |event, outcome| AuditEvent {
        event,
        outcome,
        protocol: Some(protocol),
        host: Some(host.clone()),
        port: Some(port),
    }
}

/// Pairs each hop with its released credential; a one-time password covers hops without one.
fn ssh_plan(
    plan: &PendingPlan,
    grant: &Grant,
    cols: Option<u32>,
    rows: Option<u32>,
) -> Option<SshPlan> {
    let auth_for = |endpoint: &Endpoint| -> Option<Auth> {
        let released = endpoint
            .credential_id
            .as_ref()
            .and_then(|id| grant.credentials.iter().find(|c| &c.id == id));
        match released {
            Some(c) if c.kind == "private_key" => Some(Auth::Key {
                pem: c.secret.clone(),
                passphrase: c.passphrase.clone(),
            }),
            Some(c) => Some(Auth::Password(c.secret.clone())),
            None => plan.one_time_password.clone().map(Auth::Password),
        }
    };
    let hop = |endpoint: &Endpoint| -> Option<Hop> {
        Some(Hop {
            address: endpoint.address,
            host: endpoint.host.clone(),
            port: endpoint.port,
            username: endpoint.username.clone(),
            auth: auth_for(endpoint)?,
        })
    };
    let jump = match &plan.jump {
        Some(endpoint) => Some(hop(endpoint)?),
        None => None,
    };
    Some(SshPlan {
        target: hop(&plan.target)?,
        jump,
        cols: cols.filter(|c| (1..=1000).contains(c)).unwrap_or(80),
        rows: rows.filter(|r| (1..=1000).contains(r)).unwrap_or(24),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ForgetBody {
    connection_id: String,
}

/// Forgets the trusted host key of a connection's target, after the user checked a changed key.
async fn forget_trust(
    State(state): State<AppState>,
    user: WebosUser,
    Json(body): Json<ForgetBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = state.store.clone();
    let key = user.key.clone();
    let forgotten = blocking(move || {
        let records = store.for_user(&key);
        let effective = records.document()?.effective(&body.connection_id).ok_or(
            crate::store::StoreError::Tree(crate::model::TreeError::NotFound),
        )?;
        records.forget(&effective.host, effective.port, effective.protocol)
    })
    .await?;
    if forgotten {
        state
            .webos
            .audit(
                &user.key,
                AuditEvent {
                    event: "remota.session.trust",
                    outcome: "forgotten",
                    protocol: None,
                    host: None,
                    port: None,
                },
            )
            .await;
    }
    Ok(Json(json!({ "forgotten": forgotten })))
}

/// Every 30 seconds: end the sessions of users who are no longer active, and every session when
/// Remota has been switched off.
pub async fn check_loop(webos: SharedWebos, sessions: Sessions) {
    let mut interval = tokio::time::interval(CHECK_INTERVAL);
    loop {
        interval.tick().await;
        check_once(&webos, &sessions).await;
    }
}

pub async fn check_once(webos: &SharedWebos, sessions: &Sessions) {
    let running = sessions.running();
    if running.is_empty() {
        return;
    }
    match webos.check_sessions(&running).await {
        Ok(ending) if !ending.is_empty() => {
            sessions.end(Some(&ending), None);
        }
        Err(WebosError::Refused(StatusCode::FORBIDDEN, _)) => {
            sessions.end(None, None);
        }
        _ => {}
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminateBody {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
}

#[derive(Clone)]
struct ControlState {
    sessions: Sessions,
    token: Arc<String>,
}

/// The control port (8081) for webOS only: end one session, a user's sessions, or all of them.
pub fn control_router(sessions: Sessions, token: String) -> Router {
    Router::new()
        .route("/control/terminate", post(terminate))
        .with_state(ControlState {
            sessions,
            token: Arc::new(token),
        })
}

async fn terminate(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(body): Json<TerminateBody>,
) -> Response {
    let presented = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    let authorized =
        !state.token.is_empty() && bool::from(presented.as_bytes().ct_eq(state.token.as_bytes()));
    if !authorized {
        return ApiError(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let ids = body.session_id.map(|id| vec![id]);
    let ended = state.sessions.end(ids.as_deref(), body.user_id.as_deref());
    Json(json!({ "ended": ended })).into_response()
}

#[cfg(test)]
mod tests {
    //! End to end: a real SSH server in this process, the HTTP start, the ticketed WebSocket,
    //! host-key trust, and checks that no secret ever reaches the browser.

    use std::{net::SocketAddr, path::PathBuf, sync::Arc};

    use futures_util::{SinkExt, StreamExt};
    use russh::{
        keys::{ssh_key::LineEnding, Algorithm, HashAlg, PrivateKey, PublicKey},
        server::{self, Auth as ServerAuth, Msg, Server as _, Session},
        Channel, ChannelId,
    };
    use serde_json::{json, Value};
    use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};

    use super::*;
    use crate::{
        model::{Connection, Credentials, Node, Protocol},
        policy::{Clipboard, Denies, Policy, Rule},
        router,
        store::Store,
        webos::{fake::FakeWebos, NewCredential, Webos},
    };

    const ADA: &str = "0123456789abcdef01234567";
    const BOB: &str = "76543210fedcba9876543210";
    const PASSWORD: &str = "s3cret-target-password";

    #[derive(Clone)]
    struct TestServer {
        client_key: PublicKey,
    }

    impl server::Server for TestServer {
        type Handler = Self;
        fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> Result<ServerAuth, Self::Error> {
            Ok(if user == "tester" && password == PASSWORD {
                ServerAuth::Accept
            } else {
                ServerAuth::reject()
            })
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> Result<ServerAuth, Self::Error> {
            Ok(
                if user == "tester" && key.key_data() == self.client_key.key_data() {
                    ServerAuth::Accept
                } else {
                    ServerAuth::reject()
                },
            )
        }

        async fn channel_open_session(
            &mut self,
            _: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, bytes::Bytes::from_static(b"welcome\r\n"))?;
            Ok(())
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let mut echo = b"echo:".to_vec();
            echo.extend_from_slice(data);
            session.data(channel, bytes::Bytes::from(echo))?;
            Ok(())
        }
    }

    fn random_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    /// Starts an SSH server with `host_key` on a free port; answers its address.
    async fn ssh_server(host_key: PrivateKey, client_key: PublicKey) -> SocketAddr {
        let mut config = server::Config::default();
        config.keys.push(host_key);
        config.auth_rejection_time = std::time::Duration::from_millis(10);
        let config = Arc::new(config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut server = TestServer { client_key };
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let handler = server.new_client(None);
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = server::run_stream(config, socket, handler).await;
                });
            }
        });
        address
    }

    fn policy(rules: Vec<Rule>, max_user: usize) -> Policy {
        Policy {
            allow_rdp_without_nla: false,
            clipboard: Clipboard {
                rdp: false,
                ssh: true,
            },
            max_sessions_total: 20,
            max_sessions_user: max_user,
            revision: 1,
            rules,
        }
    }

    fn allow_loopback() -> Vec<Rule> {
        vec![Rule {
            cidr: "127.0.0.0/8".into(),
            ports: "1-65535".into(),
            protocols: vec![Protocol::Ssh],
        }]
    }

    struct Harness {
        address: SocketAddr,
        state: AppState,
        webos: Arc<FakeWebos>,
        http: reqwest::Client,
    }

    impl Harness {
        /// Remota on a free port; loopback allowed by policy and not denied (tests only).
        async fn new() -> Self {
            let webos = Arc::new(FakeWebos::default());
            *webos.policy.lock().unwrap() = Some(policy(allow_loopback(), 5));
            let state = AppState::with_denies(
                Store::open_in_memory().unwrap(),
                webos.clone(),
                Denies::none(),
            );
            let app = router(PathBuf::from("missing-ui"), state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                address,
                state,
                webos,
                http: reqwest::Client::new(),
            }
        }

        async fn add_connection(&self, user: &str, ssh: SocketAddr, secret: Option<NewCredential>) {
            let credential_id = match secret {
                Some(secret) => Some(self.webos.save_credential(user, secret).await.unwrap()),
                None => None,
            };
            let node = Node::Connection {
                id: "web".into(),
                name: "web".into(),
                conn: Connection {
                    protocol: Protocol::Ssh,
                    host: ssh.ip().to_string(),
                    port: Some(ssh.port()),
                    credentials: Credentials {
                        username: Some("tester".into()),
                        domain: None,
                        secret: crate::model::Secret {
                            credential_id,
                            ..Default::default()
                        },
                    },
                    gateway: None,
                },
            };
            self.state
                .store
                .for_user(user)
                .update(|doc| doc.upsert(None, node))
                .unwrap();
        }

        async fn start(&self, user: &str, body: Value) -> (reqwest::StatusCode, Value) {
            let response = self
                .http
                .post(format!("http://{}/api/sessions", self.address))
                .header("x-webos-user", user)
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = response.status();
            (status, response.json().await.unwrap_or(Value::Null))
        }

        async fn socket(&self, user: &str, path: &str) -> Result<Socket, tungstenite::Error> {
            let mut request = format!("ws://{}{path}&cols=80&rows=24", self.address)
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert("x-webos-user", user.parse().unwrap());
            tokio_tungstenite::connect_async(request)
                .await
                .map(|(socket, _)| socket)
        }
    }

    type Socket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    fn password(secret: &str) -> NewCredential {
        NewCredential {
            id: None,
            kind: "password".into(),
            label: "web".into(),
            username: Some("tester".into()),
            secret: secret.into(),
            passphrase: None,
        }
    }

    /// Reads frames until `until` matches one, recording every frame as text for leak checks.
    async fn read_until(
        socket: &mut Socket,
        seen: &mut String,
        until: impl Fn(&tungstenite::Message) -> bool,
    ) -> tungstenite::Message {
        loop {
            let message = tokio::time::timeout(std::time::Duration::from_secs(10), socket.next())
                .await
                .expect("timed out")
                .expect("socket ended")
                .expect("socket error");
            seen.push_str(&String::from_utf8_lossy(&message.clone().into_data()));
            if until(&message) {
                return message;
            }
        }
    }

    fn is_trust(message: &tungstenite::Message) -> bool {
        matches!(message, tungstenite::Message::Text(t) if t.contains("\"trust\""))
    }

    fn has_text(needle: &'static str) -> impl Fn(&tungstenite::Message) -> bool {
        move |message| String::from_utf8_lossy(&message.clone().into_data()).contains(needle)
    }

    fn close_code(message: &tungstenite::Message) -> Option<u16> {
        match message {
            tungstenite::Message::Close(Some(frame)) => Some(frame.code.into()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn runs_an_ssh_session_with_trust_on_first_use_and_never_sends_the_password() {
        let host_key = random_key();
        let fingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let ssh = ssh_server(host_key, random_key().public_key().clone()).await;
        let h = Harness::new().await;
        h.add_connection(ADA, ssh, Some(password(PASSWORD))).await;

        let (status, start) = h.start(ADA, json!({ "connectionId": "web" })).await;
        assert_eq!(status, 201, "{start}");
        let mut seen = start.to_string();
        let mut socket = h
            .socket(ADA, start["websocket"].as_str().unwrap())
            .await
            .unwrap();

        let prompt = read_until(&mut socket, &mut seen, is_trust).await;
        let prompt: Value = serde_json::from_str(prompt.to_text().unwrap()).unwrap();
        assert_eq!(prompt["fingerprint"], fingerprint);
        socket
            .send(tungstenite::Message::Text(
                json!({ "type": "trust", "accept": true })
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        read_until(&mut socket, &mut seen, has_text("welcome")).await;
        socket
            .send(tungstenite::Message::Binary(b"ls".to_vec().into()))
            .await
            .unwrap();
        read_until(&mut socket, &mut seen, has_text("echo:ls")).await;
        socket.close(None).await.unwrap();

        assert!(!seen.contains(PASSWORD), "the password reached the browser");
        assert_eq!(
            h.state
                .store
                .for_user(ADA)
                .trusted(&ssh.ip().to_string(), ssh.port(), Protocol::Ssh)
                .unwrap(),
            Some(fingerprint)
        );

        // A second session to the same host asks nothing.
        let (_, again) = h.start(ADA, json!({ "connectionId": "web" })).await;
        let mut socket = h
            .socket(ADA, again["websocket"].as_str().unwrap())
            .await
            .unwrap();
        let first = read_until(&mut socket, &mut seen, |m| {
            is_trust(m) || has_text("welcome")(m)
        })
        .await;
        assert!(!is_trust(&first));
        let audits = h
            .webos
            .audits
            .lock()
            .unwrap()
            .iter()
            .map(|(_, e)| e.event)
            .collect::<Vec<_>>();
        assert!(audits.contains(&"remota.session.start"));
    }

    #[tokio::test]
    async fn signs_in_with_a_private_key() {
        let client = random_key();
        let ssh = ssh_server(random_key(), client.public_key().clone()).await;
        let h = Harness::new().await;
        let pem = client.to_openssh(LineEnding::LF).unwrap().to_string();
        let key = NewCredential {
            kind: "private_key".into(),
            secret: pem.clone(),
            ..password("")
        };
        h.add_connection(ADA, ssh, Some(key)).await;
        let (_, start) = h.start(ADA, json!({ "connectionId": "web" })).await;
        let mut socket = h
            .socket(ADA, start["websocket"].as_str().unwrap())
            .await
            .unwrap();
        let mut seen = String::new();
        read_until(&mut socket, &mut seen, is_trust).await;
        socket
            .send(tungstenite::Message::Text(
                json!({ "type": "trust", "accept": true })
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        read_until(&mut socket, &mut seen, has_text("welcome")).await;
        assert!(!seen.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn stops_on_a_changed_host_key_or_a_refused_prompt() {
        let ssh = ssh_server(random_key(), random_key().public_key().clone()).await;
        let h = Harness::new().await;
        h.add_connection(ADA, ssh, Some(password(PASSWORD))).await;
        h.state
            .store
            .for_user(ADA)
            .trust(
                &ssh.ip().to_string(),
                ssh.port(),
                Protocol::Ssh,
                "SHA256:old",
            )
            .unwrap();

        let (_, start) = h.start(ADA, json!({ "connectionId": "web" })).await;
        let mut socket = h
            .socket(ADA, start["websocket"].as_str().unwrap())
            .await
            .unwrap();
        let mut seen = String::new();
        read_until(&mut socket, &mut seen, has_text("changed")).await;
        let closed = read_until(&mut socket, &mut seen, |m| close_code(m).is_some()).await;
        assert_eq!(close_code(&closed), Some(ssh::close::TRUST));

        // After forgetting the old key, refusing the new one also stops the session.
        let forget = h
            .http
            .post(format!("http://{}/api/trust/forget", h.address))
            .header("x-webos-user", ADA)
            .json(&json!({ "connectionId": "web" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            forget.json::<Value>().await.unwrap(),
            json!({ "forgotten": true })
        );
        let (_, start) = h.start(ADA, json!({ "connectionId": "web" })).await;
        let mut socket = h
            .socket(ADA, start["websocket"].as_str().unwrap())
            .await
            .unwrap();
        read_until(&mut socket, &mut seen, is_trust).await;
        socket
            .send(tungstenite::Message::Text(
                json!({ "type": "trust", "accept": false })
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let closed = read_until(&mut socket, &mut seen, |m| close_code(m).is_some()).await;
        assert_eq!(close_code(&closed), Some(ssh::close::TRUST));
    }

    #[tokio::test]
    async fn a_ticket_works_once_and_only_for_its_user() {
        let ssh = ssh_server(random_key(), random_key().public_key().clone()).await;
        let h = Harness::new().await;
        h.add_connection(ADA, ssh, Some(password(PASSWORD))).await;
        let (_, start) = h.start(ADA, json!({ "connectionId": "web" })).await;
        let path = start["websocket"].as_str().unwrap();

        assert!(h.socket(BOB, path).await.is_err(), "another user");
        let tampered = format!("{}x", path);
        assert!(h.socket(ADA, &tampered).await.is_err(), "another ticket");
        let _first = h.socket(ADA, path).await.unwrap();
        assert!(h.socket(ADA, path).await.is_err(), "reused");
    }

    #[tokio::test]
    async fn refuses_targets_the_policy_does_not_allow_before_connecting() {
        let ssh = ssh_server(random_key(), random_key().public_key().clone()).await;
        let h = Harness::new().await;
        h.add_connection(ADA, ssh, Some(password(PASSWORD))).await;
        *h.webos.policy.lock().unwrap() = Some(policy(vec![], 5));
        // A new policy revision is fetched once the cached one is stale; use a fresh client here.
        let fresh = AppState::with_denies(h.state.store.clone(), h.webos.clone(), Denies::none());
        let app = router(PathBuf::from("missing-ui"), fresh);
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::post("/api/sessions")
                .header("x-webos-user", ADA)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({ "connectionId": "web" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            h.webos.tickets.lock().unwrap().is_empty(),
            "no ticket for a refused target"
        );

        *h.webos.policy.lock().unwrap() = None;
        let unavailable =
            AppState::with_denies(h.state.store.clone(), h.webos.clone(), Denies::none());
        let (status, body) = {
            let response = tower::ServiceExt::oneshot(
                router(PathBuf::from("missing-ui"), unavailable),
                axum::http::Request::post("/api/sessions")
                    .header("x-webos-user", ADA)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        json!({ "connectionId": "web" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
            let status = response.status();
            let bytes = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap())
        };
        assert_eq!(
            (status, body),
            (
                StatusCode::FORBIDDEN,
                json!({ "code": "policy_unavailable" })
            )
        );
    }

    #[tokio::test]
    async fn asks_for_a_password_when_none_is_saved_and_can_save_it() {
        let ssh = ssh_server(random_key(), random_key().public_key().clone()).await;
        let h = Harness::new().await;
        h.add_connection(ADA, ssh, None).await;
        let (status, body) = h.start(ADA, json!({ "connectionId": "web" })).await;
        assert_eq!(
            (status.as_u16(), body),
            (422, json!({ "code": "no_credential" }))
        );

        let (status, _) = h
            .start(
                ADA,
                json!({ "connectionId": "web", "oneTimeSecret": PASSWORD }),
            )
            .await;
        assert_eq!(status, 201);
        assert!(
            h.webos.credentials().is_empty(),
            "a one-time password is not saved"
        );

        let (status, start) = h
            .start(
                ADA,
                json!({ "connectionId": "web", "oneTimeSecret": PASSWORD, "saveSecret": true }),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(h.webos.credentials().len(), 1);
        assert!(h
            .state
            .store
            .for_user(ADA)
            .document()
            .unwrap()
            .effective("web")
            .unwrap()
            .credential_id
            .is_some());
        let mut socket = h
            .socket(ADA, start["websocket"].as_str().unwrap())
            .await
            .unwrap();
        let mut seen = String::new();
        read_until(&mut socket, &mut seen, is_trust).await;
    }

    #[tokio::test]
    async fn limits_sessions_per_user() {
        let ssh = ssh_server(random_key(), random_key().public_key().clone()).await;
        let h = Harness::new().await;
        *h.webos.policy.lock().unwrap() = Some(policy(allow_loopback(), 1));
        h.add_connection(ADA, ssh, Some(password(PASSWORD))).await;
        assert_eq!(h.start(ADA, json!({ "connectionId": "web" })).await.0, 201);
        let (status, body) = h.start(ADA, json!({ "connectionId": "web" })).await;
        assert_eq!(
            (status.as_u16(), body),
            (429, json!({ "code": "session_limit" }))
        );
    }

    /// Starts and opens a session for ADA and waits for the host-key prompt.
    async fn open_trusting(h: &Harness) -> Socket {
        let (_, start) = h.start(ADA, json!({ "connectionId": "web" })).await;
        let mut socket = h
            .socket(ADA, start["websocket"].as_str().unwrap())
            .await
            .unwrap();
        let mut seen = String::new();
        read_until(&mut socket, &mut seen, is_trust).await;
        socket
    }

    #[tokio::test]
    async fn ends_sessions_of_users_who_are_no_longer_active_and_on_admin_request() {
        let ssh = ssh_server(random_key(), random_key().public_key().clone()).await;
        let h = Harness::new().await;
        h.add_connection(ADA, ssh, Some(password(PASSWORD))).await;
        let mut socket = open_trusting(&h).await;
        h.webos.inactive.lock().unwrap().push(ADA.into());
        let webos: SharedWebos = h.webos.clone();
        check_once(&webos, &h.state.sessions).await;
        let mut seen = String::new();
        let closed = read_until(&mut socket, &mut seen, |m| close_code(m).is_some()).await;
        assert_eq!(close_code(&closed), Some(ssh::close::REVOKED));
        h.webos.inactive.lock().unwrap().clear();

        let mut socket = open_trusting(&h).await;
        let control = control_router(h.state.sessions.clone(), "control-token".into());
        let terminate = |token: &str| {
            axum::http::Request::post("/control/terminate")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(json!({ "userId": ADA }).to_string()))
                .unwrap()
        };
        let refused = tower::ServiceExt::oneshot(control.clone(), terminate("wrong"))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        let accepted = tower::ServiceExt::oneshot(control, terminate("control-token"))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let closed = read_until(&mut socket, &mut seen, |m| close_code(m).is_some()).await;
        assert_eq!(close_code(&closed), Some(ssh::close::REVOKED));
    }
}
