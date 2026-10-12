//! RDP sessions (SidiOS US3): the browser's IronRDP client talks RDCleanPath over the session
//! WebSocket, and `rdp_inject` signs in to the target with the stored credential.
//!
//! Certificates are trusted like SSH host keys, but before the WebSocket opens: the session start
//! probes the target, a first-seen certificate is answered with `409 certificate_unknown` and its
//! fingerprint, and the user accepts it with `POST /api/trust/rdp`. A changed certificate is
//! answered with `409 certificate_changed` and is never replaced silently; the user forgets the old
//! one first (`POST /api/trust/forget`).

use std::time::Duration;

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket},
        State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_util::sync::CancellationToken;

use crate::{
    identity::WebosUser,
    model::Protocol,
    policy::{resolve_pinned, Refusal},
    rdp_inject::{self, GatewayCertificate, InjectError, Injection, TargetLogin, ThrowawayLogin},
    ssh::{close, IDLE_LIMIT},
    tree::{blocking, ApiError, ApiResult},
    webos::AuditEvent,
    AppState,
};

/// Close code for a target that refused the stored credential or required NLA.
pub const REFUSED: u16 = close::REVOKED;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/trust/rdp", post(accept_certificate))
}

/// Everything an RDP session needs once its ticket is consumed.
#[derive(Clone)]
pub struct RdpPlan {
    pub throwaway: ThrowawayLogin,
    pub fingerprint: String,
    pub allow_without_nla: bool,
    pub clipboard: bool,
    pub domain: Option<String>,
}

/// A certificate decision the user must make before the session can start.
pub fn certificate_answer(code: &'static str, fingerprint: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({ "code": code, "fingerprint": fingerprint })),
    )
        .into_response()
}

pub fn probe_error(error: InjectError) -> ApiError {
    match error {
        InjectError::NlaNotOffered => ApiError(StatusCode::FORBIDDEN, "nla_required"),
        _ => ApiError(StatusCode::BAD_GATEWAY, "target_unreachable"),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptBody {
    connection_id: String,
    fingerprint: String,
}

/// Trusts a connection's first-seen RDP certificate after the user compared its fingerprint. The
/// target is probed again; only the fingerprint the user saw is stored.
async fn accept_certificate(
    State(state): State<AppState>,
    user: WebosUser,
    Json(body): Json<AcceptBody>,
) -> ApiResult<Response> {
    let store = state.store.clone();
    let key = user.key.clone();
    let id = body.connection_id.clone();
    let effective = blocking(move || store.for_user(&key).document())
        .await?
        .effective(&id)
        .filter(|effective| effective.protocol == Protocol::Rdp)
        .ok_or(ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    let policy = state
        .policy
        .current()
        .await
        .map_err(|refusal: Refusal| ApiError(StatusCode::FORBIDDEN, refusal.code()))?;
    let address = resolve_pinned(
        &policy,
        &state.denies,
        Protocol::Rdp,
        &effective.host,
        effective.port,
    )
    .await
    .map_err(|refusal| ApiError(StatusCode::FORBIDDEN, refusal.code()))?;
    let probe = rdp_inject::probe(address, policy.allow_rdp_without_nla)
        .await
        .map_err(probe_error)?;
    if probe.fingerprint != body.fingerprint {
        return Ok(certificate_answer(
            "certificate_changed",
            &probe.fingerprint,
        ));
    }
    let store = state.store.clone();
    let key = user.key.clone();
    let (host, port, fingerprint) = (effective.host.clone(), effective.port, probe.fingerprint);
    let stored = fingerprint.clone();
    let trusted = blocking(move || {
        store
            .for_user(&key)
            .trust(&host, port, Protocol::Rdp, &stored)
    })
    .await?;
    if !trusted {
        // A different certificate is already trusted for this target: never replaced silently.
        return Ok(certificate_answer("certificate_changed", &fingerprint));
    }
    state
        .webos
        .audit(
            &user.key,
            AuditEvent {
                event: "remota.session.trust",
                outcome: "trusted",
                protocol: Some("rdp"),
                host: Some(effective.host.clone()),
                port: Some(effective.port),
            },
        )
        .await;
    Ok(Json(json!({ "trusted": true })).into_response())
}

/// How an RDP session ended, for the audit log.
#[derive(Debug, PartialEq, Eq)]
pub enum RdpOutcome {
    Ended,
    Revoked,
    Idle,
    CertificateChanged,
    Refused,
    Failed,
}

impl RdpOutcome {
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

/// Bridges the WebSocket's binary messages to a byte stream for `rdp_inject`, ends the session on
/// cancellation (revocation) or idleness, and closes the WebSocket with the outcome's code.
struct Bridge {
    stream: DuplexStream,
    close: tokio::sync::oneshot::Sender<(u16, &'static str)>,
    done: tokio::task::JoinHandle<RdpOutcome>,
}

fn bridge(socket: WebSocket, cancel: CancellationToken) -> Bridge {
    let (stream, inner) = tokio::io::duplex(1 << 16);
    let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<(u16, &'static str)>();
    let done = tokio::spawn(async move {
        let (mut sink, mut source) = socket.split();
        let (mut read, mut write) = tokio::io::split(inner);
        let mut buffer = vec![0u8; 16 * 1024];
        let idle = tokio::time::sleep(IDLE_LIMIT);
        tokio::pin!(idle);
        let (code, reason, outcome) = loop {
            tokio::select! {
                message = source.next() => match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + IDLE_LIMIT);
                        if write.write_all(&bytes).await.is_err() {
                            break (close::ENDED, "ended", RdpOutcome::Ended);
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                        break (close::ENDED, "ended", RdpOutcome::Ended);
                    }
                    Some(Ok(_)) => {}
                },
                read_bytes = read.read(&mut buffer) => match read_bytes {
                    Ok(0) | Err(_) => {
                        // The gateway side ended; `run` names the reason right after.
                        let (code, reason) =
                            tokio::time::timeout(Duration::from_secs(5), &mut close_rx)
                                .await
                                .ok()
                                .and_then(Result::ok)
                                .unwrap_or((close::ENDED, "ended"));
                        break (code, reason, outcome_for(code));
                    }
                    Ok(n) => {
                        if sink.send(Message::Binary(buffer[..n].to_vec().into())).await.is_err() {
                            break (close::ENDED, "ended", RdpOutcome::Ended);
                        }
                    }
                },
                requested = &mut close_rx => {
                    let (code, reason) = requested.unwrap_or((close::ENDED, "ended"));
                    break (code, reason, outcome_for(code));
                }
                _ = cancel.cancelled() => break (close::REVOKED, "revoked", RdpOutcome::Revoked),
                _ = &mut idle => break (close::IDLE, "idle", RdpOutcome::Idle),
            }
        };
        let _ = sink
            .send(Message::Close(Some(CloseFrame {
                code,
                reason: reason.into(),
            })))
            .await;
        outcome
    });
    Bridge {
        stream,
        close: close_tx,
        done,
    }
}

fn outcome_for(code: u16) -> RdpOutcome {
    match code {
        close::ENDED => RdpOutcome::Ended,
        close::TRUST => RdpOutcome::CertificateChanged,
        REFUSED => RdpOutcome::Refused,
        _ => RdpOutcome::Failed,
    }
}

fn close_for(error: &InjectError) -> (u16, &'static str) {
    match error {
        InjectError::CertificateChanged { .. } => (close::TRUST, "certificate changed"),
        InjectError::TargetRefused => (REFUSED, "target refused the stored credential"),
        InjectError::NlaNotOffered => (REFUSED, "target requires NLA"),
        InjectError::TargetUnreachable => (close::UNREACHABLE, "target unreachable"),
        InjectError::BadRequest | InjectError::ClientRefused | InjectError::ClientGone => {
            (4401, "session refused")
        }
    }
}

/// Runs one RDP session over the WebSocket until either side ends it.
pub async fn run(
    socket: WebSocket,
    target: std::net::SocketAddr,
    server_name: String,
    login: TargetLogin,
    plan: RdpPlan,
    gateway: std::sync::Arc<GatewayCertificate>,
    cancel: CancellationToken,
) -> RdpOutcome {
    let bridge = bridge(socket, cancel.clone());
    let injection = Injection {
        target,
        server_name: &server_name,
        login: &login,
        throwaway: &plan.throwaway,
        gateway: &gateway,
        trusted_fingerprint: Some(&plan.fingerprint),
        allow_without_nla: plan.allow_without_nla,
        clipboard: plan.clipboard,
    };
    let established = tokio::select! {
        result = rdp_inject::establish(bridge.stream, injection) => result,
        _ = cancel.cancelled() => Err(InjectError::ClientGone),
    };
    drop(login);
    match established {
        Ok(established) => {
            tokio::select! {
                _ = rdp_inject::relay(established) => {}
                _ = cancel.cancelled() => {}
            }
            let _ = bridge.close.send((close::ENDED, "ended"));
        }
        Err(error) => {
            let _ = bridge.close.send(close_for(&error));
        }
    }
    tokio::time::timeout(Duration::from_secs(5), bridge.done)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(RdpOutcome::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_refusals_to_close_codes_and_audit_outcomes() {
        let changed = InjectError::CertificateChanged {
            presented: "SHA256:x".into(),
        };
        assert_eq!(close_for(&changed).0, close::TRUST);
        assert_eq!(
            outcome_for(close_for(&changed).0),
            RdpOutcome::CertificateChanged
        );
        assert_eq!(close_for(&InjectError::TargetRefused).0, REFUSED);
        assert_eq!(outcome_for(REFUSED).audit(), "refused");
        assert_eq!(
            close_for(&InjectError::TargetUnreachable).0,
            close::UNREACHABLE
        );
        let refused = probe_error(InjectError::NlaNotOffered);
        assert_eq!(
            (refused.0, refused.1),
            (StatusCode::FORBIDDEN, "nla_required")
        );
    }
}
