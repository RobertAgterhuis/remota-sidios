//! FTP and FTPS file-browser sessions (SidiOS US8).
//!
//! The session WebSocket (`/session/{id}?ticket=…`, as for SSH and RDP) carries the session's
//! lifetime and its small commands as JSON:
//!
//! - server → browser: `{"type":"ready","start":"/home/ada","secure":true}`, then one
//!   `{"type":"result","id":n,"ok":…}` per command;
//! - browser → server: `{"id":n,"op":"list","path":…}`, `{"id":n,"op":"mkdir","path":…}`,
//!   `{"id":n,"op":"rename","from":…,"to":…}`, `{"id":n,"op":"delete","path":…,"folder":bool}`.
//!
//! File contents never pass through the WebSocket: `GET /api/ftp/{id}/download?path=…` streams a
//! file to the browser and `PUT /api/ftp/{id}/upload?path=…` streams one to the server (at most
//! 1 GB). Both only answer the session's own user while the session runs. Transfers and deletions
//! are audited with the target, never with a path or contents.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::{Body, Bytes},
    extract::{
        ws::{CloseFrame, Message, WebSocket},
        Path, Query, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::OwnedMutexGuard,
};
use tokio_util::sync::CancellationToken;

use crate::{
    ftp::{self, Client, FtpFail, Login, Target},
    identity::WebosUser,
    model::Protocol,
    ssh::{close, IDLE_LIMIT},
    tree::{ApiError, ApiResult},
    webos::{AuditEvent, SharedWebos},
    AppState,
};

/// Largest upload (FR-019).
pub const MAX_UPLOAD: u64 = 1 << 30;
const KEEP_ALIVE: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_secs(15);
/// Close code for a server that refused the stored credential.
pub const REFUSED: u16 = close::REVOKED;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/ftp/{id}/download", get(download))
        .route("/api/ftp/{id}/upload", put(upload))
}

/// What an FTP session needs once its ticket is consumed.
#[derive(Clone, Debug)]
pub struct FtpPlan {
    pub secure: bool,
    /// FTPS only: the trusted certificate.
    pub fingerprint: Option<String>,
}

/// How an FTP session ended, for the audit log.
#[derive(Debug, PartialEq, Eq)]
pub enum FtpOutcome {
    Ended,
    Revoked,
    Idle,
    CertificateChanged,
    Refused,
    Failed,
}

impl FtpOutcome {
    pub fn audit(&self) -> &'static str {
        match self {
            Self::Ended => "ended",
            Self::Revoked => "revoked",
            Self::Idle => "idle",
            Self::CertificateChanged => "trust_refused",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }
}

type Shared = Arc<tokio::sync::Mutex<Option<Client>>>;

/// A running session, as the transfer routes find it.
struct Handle {
    user: String,
    client: Shared,
    cancel: CancellationToken,
    activity: Mutex<Instant>,
    audit: Audit,
}

impl Handle {
    fn touch(&self) {
        *self.activity.lock().expect("activity") = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.activity.lock().expect("activity").elapsed()
    }
}

/// Audits an event with the session's target; never a path or contents.
#[derive(Clone)]
struct Audit {
    webos: SharedWebos,
    user: String,
    protocol: Protocol,
    host: String,
    port: u16,
}

impl Audit {
    async fn send(&self, event: &'static str, outcome: &'static str) {
        let event = AuditEvent {
            event,
            outcome,
            protocol: Some(self.protocol.as_str()),
            host: Some(self.host.clone()),
            port: Some(self.port),
        };
        self.webos.audit(&self.user, event).await;
    }
}

/// The running FTP sessions of this Remota instance.
#[derive(Clone, Default)]
pub struct FtpSessions(Arc<Mutex<HashMap<String, Arc<Handle>>>>);

impl FtpSessions {
    fn insert(&self, id: &str, handle: Arc<Handle>) {
        self.0.lock().expect("ftp").insert(id.to_owned(), handle);
    }

    fn remove(&self, id: &str) {
        self.0.lock().expect("ftp").remove(id);
    }

    /// The session, only for its own user.
    fn find(&self, id: &str, user: &str) -> ApiResult<Arc<Handle>> {
        self.0
            .lock()
            .expect("ftp")
            .get(id)
            .filter(|handle| handle.user == user)
            .cloned()
            .ok_or(ApiError(StatusCode::NOT_FOUND, "not_found"))
    }
}

/// The answer to a start whose FTPS certificate the user must decide on first.
pub fn probe_error(error: FtpFail) -> ApiError {
    match error {
        FtpFail::TlsFailed => ApiError(StatusCode::BAD_GATEWAY, "tls_unavailable"),
        _ => ApiError(StatusCode::BAD_GATEWAY, "target_unreachable"),
    }
}

fn close_for(error: &FtpFail) -> (u16, &'static str, FtpOutcome) {
    match error {
        FtpFail::CertificateChanged { .. } => (
            close::TRUST,
            "certificate changed",
            FtpOutcome::CertificateChanged,
        ),
        FtpFail::Refused => (
            REFUSED,
            "target refused the stored credential",
            FtpOutcome::Refused,
        ),
        FtpFail::TlsFailed => (close::UNREACHABLE, "tls unavailable", FtpOutcome::Failed),
        _ => (close::UNREACHABLE, "target unreachable", FtpOutcome::Failed),
    }
}

/// One FTP session: signs in, then answers commands until either side ends it.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    socket: WebSocket,
    state: AppState,
    user: String,
    id: String,
    target: Target,
    protocol: Protocol,
    login: Login,
    plan: FtpPlan,
    cancel: CancellationToken,
) -> FtpOutcome {
    let (mut sink, mut source) = socket.split();
    let connected = tokio::select! {
        result = Client::connect(&target, &login, plan.fingerprint.as_deref()) => result,
        _ = cancel.cancelled() => Err(FtpFail::Closed),
    };
    drop(login);
    let client = match connected {
        Ok(client) => client,
        Err(error) => {
            let (code, reason, outcome) = if cancel.is_cancelled() {
                (close::REVOKED, "revoked", FtpOutcome::Revoked)
            } else {
                close_for(&error)
            };
            let _ = sink.send(closing(code, reason)).await;
            return outcome;
        }
    };
    let ready = json!({ "type": "ready", "start": client.start, "secure": target.secure });
    let handle = Arc::new(Handle {
        user: user.clone(),
        client: Arc::new(tokio::sync::Mutex::new(Some(client))),
        cancel: cancel.clone(),
        activity: Mutex::new(Instant::now()),
        audit: Audit {
            webos: state.webos.clone(),
            user,
            protocol,
            host: target.host.clone(),
            port: target.port(),
        },
    });
    state.ftp.insert(&id, handle.clone());
    let (code, reason, outcome) = if sink.send(text(&ready)).await.is_err() {
        (close::ENDED, "ended", FtpOutcome::Ended)
    } else {
        serve(&mut sink, &mut source, &handle).await
    };
    state.ftp.remove(&id);
    let _ = sink.send(closing(code, reason)).await;
    // Waits for a running transfer to end (the cancellation stops it) before signing out.
    if let Some(client) = handle.client.lock().await.take() {
        client.quit().await;
    }
    outcome
}

type Sink = futures_util::stream::SplitSink<WebSocket, Message>;
type Source = futures_util::stream::SplitStream<WebSocket>;

async fn serve(
    sink: &mut Sink,
    source: &mut Source,
    handle: &Handle,
) -> (u16, &'static str, FtpOutcome) {
    let mut tick = tokio::time::interval(TICK);
    let mut last_keep_alive = Instant::now();
    loop {
        tokio::select! {
            message = source.next() => match message {
                Some(Ok(Message::Text(body))) => {
                    handle.touch();
                    let answer = tokio::select! {
                        answer = command(handle, body.as_str()) => answer,
                        _ = handle.cancel.cancelled() => {
                            return (close::REVOKED, "revoked", FtpOutcome::Revoked);
                        }
                    };
                    let lost = answer["code"] == "connection_closed";
                    if sink.send(text(&answer)).await.is_err() {
                        return (close::ENDED, "ended", FtpOutcome::Ended);
                    }
                    if lost {
                        return (close::UNREACHABLE, "connection lost", FtpOutcome::Failed);
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                    return (close::ENDED, "ended", FtpOutcome::Ended);
                }
                Some(Ok(_)) => {}
            },
            _ = handle.cancel.cancelled() => return (close::REVOKED, "revoked", FtpOutcome::Revoked),
            _ = tick.tick() => {
                let Ok(mut client) = handle.client.try_lock() else {
                    // A transfer holds the connection: the session is in use.
                    handle.touch();
                    continue;
                };
                if handle.idle_for() >= IDLE_LIMIT {
                    return (close::IDLE, "idle", FtpOutcome::Idle);
                }
                if last_keep_alive.elapsed() >= KEEP_ALIVE {
                    last_keep_alive = Instant::now();
                    let alive = match client.as_mut() {
                        Some(client) => client.keep_alive().await.is_ok(),
                        None => false,
                    };
                    if !alive {
                        return (close::UNREACHABLE, "connection lost", FtpOutcome::Failed);
                    }
                }
            }
        }
    }
}

fn text(value: &Value) -> Message {
    Message::Text(value.to_string().into())
}

fn closing(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum Op {
    List {
        id: u64,
        path: String,
    },
    Mkdir {
        id: u64,
        path: String,
    },
    Rename {
        id: u64,
        from: String,
        to: String,
    },
    Delete {
        id: u64,
        path: String,
        #[serde(default)]
        folder: bool,
    },
}

impl Op {
    fn id(&self) -> u64 {
        match self {
            Self::List { id, .. }
            | Self::Mkdir { id, .. }
            | Self::Rename { id, .. }
            | Self::Delete { id, .. } => *id,
        }
    }
}

fn failure(id: Option<u64>, error: &FtpFail) -> Value {
    let mut answer = json!({ "type": "result", "id": id, "ok": false, "code": error.code() });
    if let FtpFail::Server(message) = error {
        if !message.is_empty() {
            answer["message"] = json!(message);
        }
    }
    answer
}

async fn command(handle: &Handle, body: &str) -> Value {
    let Ok(op) = serde_json::from_str::<Op>(body) else {
        let id = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|value| value["id"].as_u64());
        return json!({ "type": "result", "id": id, "ok": false, "code": "invalid_command" });
    };
    let id = op.id();
    let mut guard = handle.client.lock().await;
    let Some(client) = guard.as_mut() else {
        return failure(Some(id), &FtpFail::Closed);
    };
    let result = match &op {
        Op::List { path, .. } => client
            .list(path)
            .await
            .map(|(path, entries)| json!({ "path": path, "entries": entries })),
        Op::Mkdir { path, .. } => client.mkdir(path).await.map(|()| json!({})),
        Op::Rename { from, to, .. } => client.rename(from, to).await.map(|()| json!({})),
        Op::Delete { path, folder, .. } => {
            let deleted = client.delete(path, *folder).await;
            drop(guard);
            let outcome = if deleted.is_ok() { "done" } else { "failed" };
            handle.audit.send("remota.ftp.delete", outcome).await;
            deleted.map(|()| json!({}))
        }
    };
    match result {
        Ok(mut answer) => {
            answer["type"] = json!("result");
            answer["id"] = json!(id);
            answer["ok"] = json!(true);
            answer
        }
        Err(error) => failure(Some(id), &error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathQuery {
    path: String,
}

fn transfer_error(error: &FtpFail) -> Response {
    let status = match error {
        FtpFail::BadPath => StatusCode::BAD_REQUEST,
        FtpFail::Server(_) => StatusCode::CONFLICT,
        _ => StatusCode::BAD_GATEWAY,
    };
    (status, Json(failure(None, error))).into_response()
}

/// The file name for the browser's save dialog: the last path segment, percent-encoded.
fn attachment(path: &str) -> HeaderValue {
    let name = path
        .rsplit(['/', '\\'])
        .find(|segment| !segment.is_empty())
        .unwrap_or("download");
    let encoded: String = name
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{encoded}"))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

/// Audits a transfer once: done when it completed, failed when it was dropped before.
struct TransferAudit {
    audit: Audit,
    event: &'static str,
    outcome: Option<&'static str>,
}

impl TransferAudit {
    async fn finish(mut self, outcome: &'static str) {
        self.outcome = Some(outcome);
        self.audit.send(self.event, outcome).await;
    }
}

impl Drop for TransferAudit {
    fn drop(&mut self) {
        if self.outcome.is_none() {
            let (audit, event) = (self.audit.clone(), self.event);
            tokio::spawn(async move { audit.send(event, "failed").await });
        }
    }
}

struct Download {
    _guard: OwnedMutexGuard<Option<Client>>,
    transfer: Option<ftp::Transfer>,
    handle: Arc<Handle>,
    audit: Option<TransferAudit>,
    /// Bytes still to send when the length was announced: the HTTP side stops reading after the
    /// last one, so the transfer is completed (and audited) right there.
    remaining: Option<u64>,
}

impl Download {
    async fn complete(&mut self, transfer: ftp::Transfer) -> Result<(), FtpFail> {
        let finished = ftp::finish(transfer).await;
        let outcome = if finished.is_ok() { "done" } else { "failed" };
        if let Some(audit) = self.audit.take() {
            audit.finish(outcome).await;
        }
        finished
    }
}

async fn download(
    State(state): State<AppState>,
    user: WebosUser,
    Path(id): Path<String>,
    Query(query): Query<PathQuery>,
) -> ApiResult<Response> {
    let handle = state.ftp.find(&id, &user.key)?;
    handle.touch();
    let mut guard = handle.client.clone().lock_owned().await;
    let Some(client) = guard.as_mut() else {
        return Err(ApiError(StatusCode::NOT_FOUND, "not_found"));
    };
    let size = client.size(&query.path).await;
    let transfer = match client.download(&query.path).await {
        Ok(transfer) => transfer,
        Err(error) => {
            drop(guard);
            handle.audit.send("remota.ftp.download", "failed").await;
            return Ok(transfer_error(&error));
        }
    };
    let state = Download {
        _guard: guard,
        transfer: Some(transfer),
        handle: handle.clone(),
        audit: Some(TransferAudit {
            audit: handle.audit.clone(),
            event: "remota.ftp.download",
            outcome: None,
        }),
        remaining: size,
    };
    let stream = futures_util::stream::unfold(state, |mut state| async move {
        let mut transfer = state.transfer.take()?;
        let mut buffer = vec![0u8; 64 * 1024];
        let read = tokio::select! {
            read = transfer.read(&mut buffer) => read,
            _ = state.handle.cancel.cancelled() => Err(std::io::ErrorKind::Interrupted.into()),
        };
        match read {
            Ok(0) => match state.complete(transfer).await {
                Ok(()) => None,
                Err(_) => Some((Err(std::io::Error::other("transfer failed")), state)),
            },
            Ok(n) => {
                state.handle.touch();
                // A file that grew since `SIZE` is cut at the announced length.
                let n = state
                    .remaining
                    .map_or(n, |remaining| n.min(remaining as usize));
                buffer.truncate(n);
                state.remaining = state.remaining.map(|remaining| remaining - n as u64);
                if state.remaining == Some(0) {
                    let _ = state.complete(transfer).await;
                } else {
                    state.transfer = Some(transfer);
                }
                Some((Ok(Bytes::from(buffer)), state))
            }
            Err(error) => Some((Err(error), state)),
        }
    });
    let mut response = Body::from_stream(stream).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_DISPOSITION, attachment(&query.path));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Some(size) = size {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    }
    Ok(response)
}

fn too_large() -> ApiError {
    ApiError(StatusCode::PAYLOAD_TOO_LARGE, "file_too_large")
}

async fn upload(
    State(state): State<AppState>,
    user: WebosUser,
    Path(id): Path<String>,
    Query(query): Query<PathQuery>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let handle = state.ftp.find(&id, &user.key)?;
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_UPLOAD) {
        handle.audit.send("remota.ftp.upload", "too_large").await;
        return Err(too_large());
    }
    handle.touch();
    let mut guard = handle.client.clone().lock_owned().await;
    let Some(client) = guard.as_mut() else {
        return Err(ApiError(StatusCode::NOT_FOUND, "not_found"));
    };
    let audit = TransferAudit {
        audit: handle.audit.clone(),
        event: "remota.ftp.upload",
        outcome: None,
    };
    let mut transfer = match client.upload(&query.path).await {
        Ok(transfer) => transfer,
        Err(error) => {
            audit.finish("failed").await;
            return Ok(transfer_error(&error));
        }
    };
    let mut chunks = body.into_data_stream();
    let mut sent: u64 = 0;
    loop {
        let chunk = tokio::select! {
            chunk = chunks.next() => chunk,
            _ = handle.cancel.cancelled() => {
                drop(transfer);
                audit.finish("failed").await;
                return Err(ApiError(StatusCode::GONE, "session_ended"));
            }
        };
        match chunk {
            Some(Ok(bytes)) => {
                sent += bytes.len() as u64;
                if sent > MAX_UPLOAD {
                    drop(transfer);
                    // The partial file is removed; a failure to remove it is not hidden.
                    let _ = client.delete(&query.path, false).await;
                    audit.finish("too_large").await;
                    return Err(too_large());
                }
                if transfer.write_all(&bytes).await.is_err() {
                    drop(transfer);
                    audit.finish("failed").await;
                    return Err(ApiError(StatusCode::BAD_GATEWAY, "transfer_failed"));
                }
                handle.touch();
            }
            Some(Err(_)) => {
                drop(transfer);
                let _ = client.delete(&query.path, false).await;
                audit.finish("failed").await;
                return Err(ApiError(StatusCode::BAD_REQUEST, "upload_interrupted"));
            }
            None => break,
        }
    }
    let _ = transfer.flush().await;
    match ftp::finish(transfer).await {
        Ok(()) => {
            audit.finish("done").await;
            Ok((StatusCode::CREATED, Json(json!({ "size": sent }))).into_response())
        }
        Err(error) => {
            audit.finish("failed").await;
            Ok(transfer_error(&error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_downloads_by_their_last_segment() {
        assert_eq!(
            attachment("/srv/Report 2026.pdf"),
            "attachment; filename*=UTF-8''Report%202026.pdf"
        );
        assert_eq!(attachment("/a/b/"), "attachment; filename*=UTF-8''b");
        assert_eq!(attachment("/"), "attachment; filename*=UTF-8''download");
        assert_eq!(
            attachment("x\"y;z"),
            "attachment; filename*=UTF-8''x%22y%3Bz"
        );
    }

    #[test]
    fn maps_failures_to_close_codes_and_outcomes() {
        let changed = FtpFail::CertificateChanged {
            presented: "SHA256:x".into(),
        };
        assert_eq!(close_for(&changed).0, close::TRUST);
        assert_eq!(close_for(&changed).2.audit(), "trust_refused");
        assert_eq!(close_for(&FtpFail::Refused).0, REFUSED);
        assert_eq!(close_for(&FtpFail::Unreachable).0, close::UNREACHABLE);
        assert_eq!(
            failure(Some(3), &FtpFail::Server("550 No such file".into())),
            json!({ "type": "result", "id": 3, "ok": false, "code": "server_error", "message": "550 No such file" })
        );
    }
}
