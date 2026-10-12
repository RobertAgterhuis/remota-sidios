//! The SSH side of a session (SidiOS FR-006): the server signs in to the target (directly or
//! through a jump host) with the credential webOS released for this ticket, and the browser gets a
//! terminal stream only. Host keys are trusted on first use, after the user compares the
//! fingerprint; a changed key stops the connection.
//!
//! WebSocket frames: binary carries terminal data both ways; text carries JSON control messages
//! (SidiOS `contracts/remota-api.md`, "Sessions").

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use russh::{
    client::{self, AuthResult, Config, Handle, Handler, KeyboardInteractiveAuthResponse},
    keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey},
    ChannelMsg,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::{model::Protocol, store::Store};

/// A session closes after this long without input from the browser.
pub const IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
/// How long the user has to answer a host-key prompt.
const TRUST_WAIT: Duration = Duration::from_secs(60);

pub mod close {
    pub const ENDED: u16 = 1000;
    pub const REVOKED: u16 = 4403;
    pub const IDLE: u16 = 4408;
    pub const TRUST: u16 = 4409;
    pub const UNREACHABLE: u16 = 4502;
}

#[derive(Clone)]
pub enum Auth {
    Password(String),
    Key {
        pem: String,
        passphrase: Option<String>,
    },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Auth::Password(_) => "Auth::Password(..)",
            Auth::Key { .. } => "Auth::Key(..)",
        })
    }
}

/// One host to sign in to: where to connect (the pinned address), how the user named it (for
/// trust records and messages), and the login.
#[derive(Clone, Debug)]
pub struct Hop {
    pub address: SocketAddr,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: Auth,
}

#[derive(Clone, Debug)]
pub struct SshPlan {
    pub target: Hop,
    pub jump: Option<Hop>,
    pub cols: u32,
    pub rows: u32,
}

/// How a session ended, for the audit log.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Ended,
    Revoked,
    Idle,
    TrustRefused,
    Failed,
}

type Sink = Arc<Mutex<SplitSink<WebSocket, Message>>>;

/// Makes a host-key checker for each hop of one session.
struct Trust {
    browser: Arc<Browser>,
    store: Store,
    user: String,
    refused: Arc<std::sync::atomic::AtomicBool>,
}

impl Trust {
    fn handler(&self, hop: &Hop) -> TrustingHandler {
        TrustingHandler {
            browser: self.browser.clone(),
            store: self.store.clone(),
            user: self.user.clone(),
            host: hop.host.clone(),
            port: hop.port,
            refused: self.refused.clone(),
        }
    }
}

/// Shared by the handshake (host-key prompts) and the session loop: the browser's messages, read
/// by one task so neither has to own the socket.
pub struct Browser {
    sink: Sink,
    incoming: Mutex<mpsc::Receiver<Message>>,
}

impl Browser {
    /// Splits the WebSocket: one task reads the browser's messages into a queue.
    pub fn attach(socket: WebSocket) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let (sink, mut stream) = socket.split();
        let (sender, receiver) = mpsc::channel(256);
        let reader = tokio::spawn(async move {
            while let Some(Ok(message)) = stream.next().await {
                if sender.send(message).await.is_err() {
                    break;
                }
            }
        });
        let browser = Arc::new(Self {
            sink: Arc::new(Mutex::new(sink)),
            incoming: Mutex::new(receiver),
        });
        (browser, reader)
    }

    /// The browser's next message; `None` once it is gone.
    pub async fn next(&self) -> Option<Message> {
        self.incoming.lock().await.recv().await
    }

    /// False once the browser is gone.
    pub async fn send(&self, message: Message) -> bool {
        self.sink.lock().await.send(message).await.is_ok()
    }

    pub async fn control(&self, value: serde_json::Value) {
        let _ = self
            .sink
            .lock()
            .await
            .send(Message::Text(value.to_string().into()))
            .await;
    }

    pub async fn close(&self, code: u16, reason: &str) {
        let frame = CloseFrame {
            code,
            reason: reason.chars().take(100).collect::<String>().into(),
        };
        let mut sink = self.sink.lock().await;
        let _ = sink.send(Message::Close(Some(frame))).await;
        let _ = sink.close().await;
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Control {
    Resize { cols: u32, rows: u32 },
    Trust { accept: bool },
}

/// Checks host keys against the user's trust records and asks the browser about new ones.
struct TrustingHandler {
    browser: Arc<Browser>,
    store: Store,
    user: String,
    host: String,
    port: u16,
    refused: Arc<std::sync::atomic::AtomicBool>,
}

impl Handler for TrustingHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let accepted = self.decide(&fingerprint).await;
        if !accepted {
            self.refused
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(accepted)
    }
}

impl TrustingHandler {
    async fn decide(&self, fingerprint: &str) -> bool {
        let records = self.store.for_user(&self.user);
        match records.trusted(&self.host, self.port, Protocol::Ssh) {
            Ok(Some(known)) if known == fingerprint => true,
            Ok(Some(_)) => {
                let message = format!(
                    "The host key of {} changed. Connect only if you know why, and forget the old key in the connection's settings first.",
                    self.host
                );
                self.browser
                    .control(json!({ "type": "error", "message": message }))
                    .await;
                false
            }
            Ok(None) => self.ask(fingerprint).await,
            Err(_) => false,
        }
    }

    async fn ask(&self, fingerprint: &str) -> bool {
        self.browser
            .control(json!({ "type": "trust", "host": self.host, "port": self.port, "fingerprint": fingerprint }))
            .await;
        let answer = tokio::time::timeout(TRUST_WAIT, async {
            let mut incoming = self.browser.incoming.lock().await;
            while let Some(message) = incoming.recv().await {
                match message {
                    Message::Text(text) => {
                        if let Ok(Control::Trust { accept }) = serde_json::from_str(&text) {
                            return accept;
                        }
                    }
                    Message::Close(_) => return false,
                    _ => {}
                }
            }
            false
        })
        .await
        .unwrap_or(false);
        answer
            && self
                .store
                .for_user(&self.user)
                .trust(&self.host, self.port, Protocol::Ssh, fingerprint)
                .is_ok()
    }
}

/// Runs one SSH session over `socket` until either side ends it, `cancel` fires, or the browser
/// stays idle for 30 minutes.
pub async fn run(
    socket: WebSocket,
    plan: SshPlan,
    store: Store,
    user: String,
    cancel: CancellationToken,
) -> Outcome {
    let (browser, reader) = Browser::attach(socket);
    let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trust = Trust {
        browser: browser.clone(),
        store,
        user,
        refused: refused.clone(),
    };
    let outcome = tokio::select! {
        result = session(&browser, &plan, &trust) => match result {
            Ok(outcome) => outcome,
            Err(message) => {
                let refused = refused.load(std::sync::atomic::Ordering::SeqCst);
                if refused {
                    browser.close(close::TRUST, "host key not trusted").await;
                    reader.abort();
                    return Outcome::TrustRefused;
                }
                browser.control(json!({ "type": "error", "message": message })).await;
                browser.close(close::UNREACHABLE, "connection failed").await;
                Outcome::Failed
            }
        },
        () = cancel.cancelled() => {
            browser.close(close::REVOKED, "session ended by SidiOS").await;
            Outcome::Revoked
        }
    };
    reader.abort();
    outcome
}

/// A signed-in SSH connection; the jump host's connection, if any, stays open with it.
pub struct Connected {
    target: Handle<TrustingHandler>,
    _jump: Option<Handle<TrustingHandler>>,
}

/// Connects (through the jump host, if any), checks host keys, and signs in.
async fn reach(plan_target: &Hop, jump: Option<&Hop>, trust: &Trust) -> Result<Connected, String> {
    let config = Arc::new(Config::default());
    // The jump host's connection must stay open for the whole session, or the tunnel closes.
    let mut _jump: Option<Handle<TrustingHandler>> = None;
    let handle = match jump {
        Some(jump) => {
            let jump_handle = sign_in(
                connect(config.clone(), jump, trust.handler(jump)).await?,
                jump,
            )
            .await?;
            let channel = jump_handle
                .channel_open_direct_tcpip(
                    plan_target.address.ip().to_string(),
                    u32::from(plan_target.address.port()),
                    "127.0.0.1",
                    0,
                )
                .await
                .map_err(|_| format!("{} could not reach {}.", jump.host, plan_target.host))?;
            let handle =
                client::connect_stream(config, channel.into_stream(), trust.handler(plan_target))
                    .await
                    .map_err(|_| format!("Could not start SSH with {}.", plan_target.host))?;
            _jump = Some(jump_handle);
            handle
        }
        None => connect(config, plan_target, trust.handler(plan_target)).await?,
    };
    Ok(Connected {
        target: sign_in(handle, plan_target).await?,
        _jump,
    })
}

/// An SFTP session over SSH (US9), for the file browser. The SSH connection lives as long as it.
pub struct Sftp {
    pub session: russh_sftp::client::SftpSession,
    _ssh: Connected,
}

pub enum SftpFail {
    /// The user refused a new host key, or the key changed.
    TrustRefused,
    Failed(String),
}

/// Signs in like an SSH session (host-key prompts go to `browser`) and starts the SFTP subsystem.
pub async fn open_sftp(
    browser: &Arc<Browser>,
    target: &Hop,
    jump: Option<&Hop>,
    store: Store,
    user: String,
) -> Result<Sftp, SftpFail> {
    let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trust = Trust {
        browser: browser.clone(),
        store,
        user,
        refused: refused.clone(),
    };
    let failed = |message: String| {
        if refused.load(std::sync::atomic::Ordering::SeqCst) {
            SftpFail::TrustRefused
        } else {
            SftpFail::Failed(message)
        }
    };
    let connected = reach(target, jump, &trust).await.map_err(failed)?;
    let channel = connected
        .target
        .channel_open_session()
        .await
        .map_err(|_| failed("The server refused a session.".to_owned()))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|_| failed("The server does not offer SFTP.".to_owned()))?;
    let session = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|_| failed("SFTP could not start on the server.".to_owned()))?;
    Ok(Sftp {
        session,
        _ssh: connected,
    })
}

async fn session(browser: &Arc<Browser>, plan: &SshPlan, trust: &Trust) -> Result<Outcome, String> {
    let connected = reach(&plan.target, plan.jump.as_ref(), trust).await?;
    let mut channel = connected
        .target
        .channel_open_session()
        .await
        .map_err(|_| "The server refused a session.".to_owned())?;
    channel
        .request_pty(false, "xterm-256color", plan.cols, plan.rows, 0, 0, &[])
        .await
        .map_err(|_| "The server refused a terminal.".to_owned())?;
    channel
        .request_shell(true)
        .await
        .map_err(|_| "The server refused a shell.".to_owned())?;
    Ok(relay(browser, &mut channel).await)
}

async fn connect(
    config: Arc<Config>,
    hop: &Hop,
    handler: TrustingHandler,
) -> Result<Handle<TrustingHandler>, String> {
    tokio::time::timeout(
        Duration::from_secs(15),
        client::connect(config, hop.address, handler),
    )
    .await
    .map_err(|_| format!("{} did not answer.", hop.host))?
    .map_err(|_| format!("Could not connect to {}.", hop.host))
}

/// Signs in with a key, or with a password (trying keyboard-interactive when plain password
/// sign-in is refused).
async fn sign_in(
    mut handle: Handle<TrustingHandler>,
    hop: &Hop,
) -> Result<Handle<TrustingHandler>, String> {
    let signed_in = match &hop.auth {
        Auth::Key { pem, passphrase } => {
            let key = russh::keys::decode_secret_key(pem, passphrase.as_deref()).map_err(|_| {
                "The saved SSH key could not be read; check it and its passphrase.".to_owned()
            })?;
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            handle
                .authenticate_publickey(
                    &hop.username,
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map(|result| result.success())
                .unwrap_or(false)
        }
        Auth::Password(password) => password_sign_in(&mut handle, &hop.username, password).await,
    };
    if signed_in {
        Ok(handle)
    } else {
        Err(format!(
            "{} refused the sign-in for {}.",
            hop.host, hop.username
        ))
    }
}

async fn password_sign_in(
    handle: &mut Handle<TrustingHandler>,
    user: &str,
    password: &str,
) -> bool {
    if matches!(
        handle.authenticate_password(user, password).await,
        Ok(AuthResult::Success)
    ) {
        return true;
    }
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await;
    // Answer every prompt with the password, for at most a few rounds.
    for _ in 0..3 {
        match response {
            Ok(KeyboardInteractiveAuthResponse::Success) => return true,
            Ok(KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. }) => {
                let answers = prompts.iter().map(|_| password.to_owned()).collect();
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await;
            }
            _ => return false,
        }
    }
    false
}

async fn relay(browser: &Arc<Browser>, channel: &mut russh::Channel<client::Msg>) -> Outcome {
    let mut incoming = browser.incoming.lock().await;
    let idle = tokio::time::sleep(IDLE_LIMIT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    let sent = browser.sink.lock().await.send(Message::Binary(data.to_vec().into())).await;
                    if sent.is_err() {
                        return Outcome::Ended;
                    }
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    browser.close(close::ENDED, "session ended").await;
                    return Outcome::Ended;
                }
                _ => {}
            },
            message = incoming.recv() => {
                idle.as_mut().reset(tokio::time::Instant::now() + IDLE_LIMIT);
                match message {
                    Some(Message::Binary(bytes)) => {
                        if channel.data(&bytes[..]).await.is_err() {
                            return Outcome::Ended;
                        }
                    }
                    Some(Message::Text(text)) => {
                        if let Ok(Control::Resize { cols, rows }) = serde_json::from_str(&text) {
                            let _ = channel.window_change(cols.clamp(1, 1000), rows.clamp(1, 1000), 0, 0).await;
                        }
                    }
                    Some(Message::Close(_)) | None => {
                        let _ = channel.eof().await;
                        return Outcome::Ended;
                    }
                    _ => {}
                }
            }
            () = &mut idle => {
                browser.close(close::IDLE, "idle for 30 minutes").await;
                return Outcome::Idle;
            }
        }
    }
}
