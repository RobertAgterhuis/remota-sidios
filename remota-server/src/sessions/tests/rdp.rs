//! RDP sessions end to end (SidiOS T040): the HTTP start with certificate trust, the ticketed
//! WebSocket speaking RDCleanPath, credential injection toward a fake RDP target that runs a real
//! TLS server and CredSSP/NTLM server, and checks that no target secret reaches the browser.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use ironrdp_async::FramedWrite;
use ironrdp_pdu::nego::{
    ConnectionConfirm, ConnectionRequest, RequestFlags, ResponseFlags, SecurityProtocol,
};
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPath, RDCleanPathPdu};
use ironrdp_tokio::TokioFramed;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
use zeroize::Zeroizing;

use super::{policy, Harness, ADA, BOB};
use crate::{
    model::{Connection, Credentials, Node, Protocol, Secret},
    policy::Policy,
    rdp_inject::{
        self, client_credssp, public_key_of, read_tpkt, selected_protocol, target_credssp,
        GatewayCertificate, TargetLogin, ThrowawayLogin,
    },
    webos::{NewCredential, Webos},
};

const RDP_PASSWORD: &str = "rdp-target-password-7f3a";
const RDP_USER: &str = "administrator";

/// A target certificate the test can replace to simulate a changed server.
#[derive(Clone)]
struct TargetCert {
    der: Vec<u8>,
    key_der: Vec<u8>,
}

impl TargetCert {
    fn generate() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["rdp-target".to_owned()]).unwrap();
        Self {
            der: certified.cert.der().to_vec(),
            key_der: certified.key_pair.serialize_der(),
        }
    }
}

/// What the fake target saw after sign-in: everything the browser sent through the relay.
type Received = Arc<StdMutex<Vec<u8>>>;

/// A fake RDP server: X.224 with `protocol`, TLS with the current certificate, CredSSP/NTLM
/// accepting only the stored login when NLA is selected, then an echo of every byte prefixed with
/// `echo:`.
async fn rdp_target(
    protocol: SecurityProtocol,
    cert: Arc<StdMutex<TargetCert>>,
) -> (SocketAddr, Received) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let received: Received = Arc::default();
    let seen = received.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let current = cert.lock().unwrap().clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                if read_tpkt(&mut tcp).await.is_err() {
                    return;
                }
                let confirm = ironrdp_pdu::x224::X224(ConnectionConfirm::Response {
                    flags: ResponseFlags::empty(),
                    protocol,
                });
                let bytes = ironrdp_core::encode_vec(&confirm).unwrap();
                tcp.write_all(&bytes).await.unwrap();
                let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::pki_types::CertificateDer::from(current.der.clone())],
                    rustls::pki_types::PrivateKeyDer::try_from(current.key_der.clone()).unwrap(),
                )
                .unwrap();
                let Ok(tls) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                    .accept(tcp)
                    .await
                else {
                    return;
                };
                let mut framed = TokioFramed::new(tls);
                if protocol.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX) {
                    let login = ThrowawayLogin {
                        username: RDP_USER.into(),
                        password: Zeroizing::new(RDP_PASSWORD.into()),
                    };
                    let identity = GatewayCertificate {
                        public_key: public_key_of(&current.der).unwrap(),
                        der: current.der.clone(),
                    };
                    if client_credssp(&mut framed, &login, &identity, protocol)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                let (mut stream, leftover) = framed.into_inner();
                let mut buffer = leftover.to_vec();
                loop {
                    if !buffer.is_empty() {
                        seen.lock().unwrap().extend_from_slice(&buffer);
                        let mut answer = b"echo:".to_vec();
                        answer.extend_from_slice(&buffer);
                        if stream.write_all(&answer).await.is_err() {
                            return;
                        }
                        buffer.clear();
                    }
                    let mut chunk = [0u8; 4096];
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });
    (address, received)
}

impl Harness {
    async fn add_rdp_connection(&self, user: &str, target: SocketAddr) {
        let credential_id = self
            .webos
            .save_credential(
                user,
                NewCredential {
                    id: None,
                    kind: "password".into(),
                    label: "win".into(),
                    username: Some(RDP_USER.into()),
                    secret: RDP_PASSWORD.into(),
                    passphrase: None,
                },
            )
            .await
            .unwrap();
        let node = Node::Connection {
            id: "win".into(),
            name: "win".into(),
            conn: Connection {
                protocol: Protocol::Rdp,
                host: target.ip().to_string(),
                port: Some(target.port()),
                credentials: Credentials {
                    username: Some(RDP_USER.into()),
                    domain: Some("CORP".into()),
                    secret: Secret {
                        credential_id: Some(credential_id),
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

    async fn post(&self, user: &str, path: &str, body: Value) -> (reqwest::StatusCode, Value) {
        let response = self
            .http
            .post(format!("http://{}{path}", self.address))
            .header("x-webos-user", user)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// Starts an RDP session, trusting the certificate on first use as the user would.
    async fn start_rdp(&self, user: &str) -> Value {
        let (status, body) = self.start(user, json!({ "connectionId": "win" })).await;
        let body = if status == reqwest::StatusCode::CONFLICT {
            assert_eq!(body["code"], "certificate_unknown");
            let fingerprint = body["fingerprint"].as_str().unwrap().to_owned();
            let (status, _) = self
                .post(
                    user,
                    "/api/trust/rdp",
                    json!({ "connectionId": "win", "fingerprint": fingerprint }),
                )
                .await;
            assert_eq!(status, reqwest::StatusCode::OK);
            let (status, body) = self.start(user, json!({ "connectionId": "win" })).await;
            assert_eq!(status, reqwest::StatusCode::CREATED, "{body}");
            body
        } else {
            assert_eq!(status, reqwest::StatusCode::CREATED, "{body}");
            body
        };
        assert_eq!(body["protocol"], "rdp");
        body
    }

    /// The browser end of the session WebSocket as a byte stream; every byte the browser receives
    /// is recorded.
    async fn rdp_socket(
        &self,
        user: &str,
        path: &str,
    ) -> Result<(DuplexStream, Received, Arc<StdMutex<Option<u16>>>), tungstenite::Error> {
        let mut request = format!("ws://{}{path}", self.address)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("x-webos-user", user.parse().unwrap());
        let (socket, _) = tokio_tungstenite::connect_async(request).await?;
        let (browser, inner) = tokio::io::duplex(1 << 16);
        let seen: Received = Arc::default();
        let closed = Arc::new(StdMutex::new(None));
        let (record, close_code) = (seen.clone(), closed.clone());
        tokio::spawn(async move {
            let (mut sink, mut source) = socket.split();
            let (mut read, mut write) = tokio::io::split(inner);
            let mut buffer = vec![0u8; 16 * 1024];
            // Keep reading the WebSocket after the browser side is done, to see its close code.
            let mut browser_open = true;
            loop {
                tokio::select! {
                    message = source.next() => match message {
                        Some(Ok(tungstenite::Message::Binary(bytes))) => {
                            record.lock().unwrap().extend_from_slice(&bytes);
                            if browser_open && write.write_all(&bytes).await.is_err() {
                                browser_open = false;
                            }
                        }
                        Some(Ok(tungstenite::Message::Close(frame))) => {
                            *close_code.lock().unwrap() = frame.map(|f| u16::from(f.code));
                            return;
                        }
                        Some(Ok(_)) => {}
                        _ => return,
                    },
                    n = read.read(&mut buffer), if browser_open => match n {
                        Ok(0) | Err(_) => browser_open = false,
                        Ok(n) => {
                            if sink
                                .send(tungstenite::Message::Binary(buffer[..n].to_vec().into()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    },
                }
            }
        });
        Ok((browser, seen, closed))
    }
}

/// The browser side up to the RDP connection sequence: RDCleanPath, then CredSSP with the
/// throwaway login (when NLA was selected). Answers the stream, ready for RDP traffic.
async fn browser_handshake(
    mut stream: DuplexStream,
    login: &TargetLogin,
    offer_tls_only: bool,
) -> Result<TokioFramed<DuplexStream>, String> {
    let mut protocol = SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX;
    if offer_tls_only {
        protocol |= SecurityProtocol::SSL;
    }
    let request = ironrdp_core::encode_vec(&ironrdp_pdu::x224::X224(ConnectionRequest {
        nego_data: None,
        flags: RequestFlags::empty(),
        protocol,
    }))
    .unwrap();
    let pdu = RDCleanPathPdu::new_request(request, "win".into(), String::new(), None)
        .unwrap()
        .to_der()
        .unwrap();
    stream.write_all(&pdu).await.map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let DetectionResult::Detected { total_length, .. } = RDCleanPathPdu::detect(&answer) {
            if answer.len() >= total_length {
                break;
            }
        }
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .map_err(|_| "timed out".to_owned())?
            .map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("gateway closed".into());
        }
        answer.extend_from_slice(&chunk[..read]);
    }
    let RDCleanPath::Response {
        x224_connection_response,
        server_cert_chain,
        ..
    } = RDCleanPathPdu::from_der(&answer)
        .map_err(|e| e.to_string())?
        .into_enum()
        .map_err(|_| "not an RDCleanPath answer".to_owned())?
    else {
        return Err("gateway refused".into());
    };
    let selected =
        selected_protocol(x224_connection_response.as_bytes()).map_err(|e| e.to_string())?;
    let mut framed = TokioFramed::new(stream);
    if selected.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX) {
        let public_key = public_key_of(server_cert_chain[0].as_bytes()).unwrap();
        target_credssp(&mut framed, login, "win", selected, public_key)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(framed)
}

fn throwaway_of(start: &Value) -> TargetLogin {
    TargetLogin {
        username: start["rdpSessionLogin"]["username"]
            .as_str()
            .unwrap()
            .into(),
        domain: None,
        password: Zeroizing::new(
            start["rdpSessionLogin"]["password"]
                .as_str()
                .unwrap()
                .into(),
        ),
    }
}

/// Like a real client, the first RDP PDU after the security exchange is the MCS Connect Initial.
async fn connect(framed: &mut TokioFramed<DuplexStream>) {
    let pdu = connect_initial(&["rdpdr", "drdynvc"]);
    assert_eq!(echo(framed, &pdu).await.len(), pdu.len() + 5);
}

async fn echo(framed: &mut TokioFramed<DuplexStream>, message: &[u8]) -> Vec<u8> {
    framed.write_all(message).await.unwrap();
    let (stream, _) = framed.get_inner_mut();
    let mut answer = Vec::new();
    let mut chunk = [0u8; 4096];
    while answer.len() < message.len() + 5 {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("echo timed out")
            .unwrap();
        assert!(read > 0, "relay closed");
        answer.extend_from_slice(&chunk[..read]);
    }
    answer
}

/// The target password as it could appear on the wire: UTF-8, UTF-16LE, and its NT hash.
fn password_forms(password: &str) -> Vec<Vec<u8>> {
    use md4::{Digest as _, Md4};
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let nt_hash = Md4::digest(&utf16).to_vec();
    let hex: String = nt_hash.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        password.as_bytes().to_vec(),
        utf16,
        nt_hash,
        hex.into_bytes(),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

async fn wait_for_close(closed: &Arc<StdMutex<Option<u16>>>) -> Option<u16> {
    for _ in 0..100 {
        if let Some(code) = *closed.lock().unwrap() {
            return Some(code);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test]
async fn injects_the_stored_credential_and_never_sends_it_to_the_browser() {
    let cert = Arc::new(StdMutex::new(TargetCert::generate()));
    let (target, received) = rdp_target(SecurityProtocol::HYBRID_EX, cert).await;
    let h = Harness::new().await;
    h.add_rdp_connection(ADA, target).await;

    let start = h.start_rdp(ADA).await;
    let login = throwaway_of(&start);
    assert_ne!(login.password.as_str(), RDP_PASSWORD);
    assert!(!start.to_string().contains(RDP_PASSWORD));
    assert_eq!(start["clipboard"], false);

    let (stream, seen, _) = h
        .rdp_socket(ADA, start["websocket"].as_str().unwrap())
        .await
        .unwrap();
    let mut framed = browser_handshake(stream, &login, false).await.unwrap();
    connect(&mut framed).await;
    let answer = echo(&mut framed, b"hello target").await;
    assert_eq!(answer, b"echo:hello target");
    assert!(contains(&received.lock().unwrap(), b"hello target"));

    let seen = seen.lock().unwrap();
    for form in password_forms(RDP_PASSWORD) {
        assert!(
            !contains(&seen, &form),
            "the browser received a target password form"
        );
    }
    let audits: Vec<_> = h
        .webos
        .audits
        .lock()
        .unwrap()
        .iter()
        .map(|(_, e)| (e.event, e.outcome))
        .collect();
    assert!(audits.contains(&("remota.session.trust", "trusted")));
    assert!(audits.contains(&("remota.session.start", "started")));
}

#[tokio::test]
async fn issues_a_new_throwaway_login_per_session_and_refuses_reuse_and_wrong_logins() {
    let cert = Arc::new(StdMutex::new(TargetCert::generate()));
    let (target, _) = rdp_target(SecurityProtocol::HYBRID, cert).await;
    let h = Harness::new().await;
    h.add_rdp_connection(ADA, target).await;

    let first = h.start_rdp(ADA).await;
    let second = h.start_rdp(ADA).await;
    assert_ne!(first["rdpSessionLogin"], second["rdpSessionLogin"]);

    // A ticket opens its session once; the second open is refused before any RDP traffic.
    let path = first["websocket"].as_str().unwrap();
    let (stream, _, _) = h.rdp_socket(ADA, path).await.unwrap();
    let mut framed = browser_handshake(stream, &throwaway_of(&first), false)
        .await
        .unwrap();
    connect(&mut framed).await;
    assert_eq!(echo(&mut framed, b"one").await, b"echo:one");
    assert!(h.rdp_socket(ADA, path).await.is_err(), "reused ticket");
    // Another user cannot open someone else's session.
    assert!(h
        .rdp_socket(BOB, second["websocket"].as_str().unwrap())
        .await
        .is_err());

    // The second session's own login, not the first session's, is the only one accepted.
    let (stream, _, closed) = h
        .rdp_socket(ADA, second["websocket"].as_str().unwrap())
        .await
        .unwrap();
    assert!(browser_handshake(stream, &throwaway_of(&first), false)
        .await
        .is_err());
    assert_eq!(wait_for_close(&closed).await, Some(4401));
}

#[tokio::test]
async fn asks_about_new_certificates_and_never_accepts_a_changed_one_silently() {
    let cert = Arc::new(StdMutex::new(TargetCert::generate()));
    let (target, _) = rdp_target(SecurityProtocol::HYBRID_EX, cert.clone()).await;
    let h = Harness::new().await;
    h.add_rdp_connection(ADA, target).await;

    let (status, body) = h.start(ADA, json!({ "connectionId": "win" })).await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT);
    assert_eq!(body["code"], "certificate_unknown");
    let first = body["fingerprint"].as_str().unwrap().to_owned();
    assert!(first.starts_with("SHA256:"));
    // A fingerprint other than the one the target presents is not stored.
    let (status, body) = h
        .post(
            ADA,
            "/api/trust/rdp",
            json!({ "connectionId": "win", "fingerprint": "SHA256:other" }),
        )
        .await;
    assert_eq!(
        (status, body["code"].clone()),
        (reqwest::StatusCode::CONFLICT, json!("certificate_changed"))
    );
    h.start_rdp(ADA).await;

    // The target's certificate changes.
    *cert.lock().unwrap() = TargetCert::generate();
    let (status, body) = h.start(ADA, json!({ "connectionId": "win" })).await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT);
    assert_eq!(body["code"], "certificate_changed");
    let changed = body["fingerprint"].as_str().unwrap().to_owned();
    assert_ne!(changed, first);
    let (status, _) = h
        .post(
            ADA,
            "/api/trust/rdp",
            json!({ "connectionId": "win", "fingerprint": changed }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "replaced silently");

    // Only after the user forgets the old certificate can the new one be trusted.
    let (status, _) = h
        .post(ADA, "/api/trust/forget", json!({ "connectionId": "win" }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    h.start_rdp(ADA).await;
}

#[tokio::test]
async fn stops_a_session_whose_certificate_changed_after_the_start() {
    let cert = Arc::new(StdMutex::new(TargetCert::generate()));
    let (target, received) = rdp_target(SecurityProtocol::HYBRID_EX, cert.clone()).await;
    let h = Harness::new().await;
    h.add_rdp_connection(ADA, target).await;
    let start = h.start_rdp(ADA).await;
    *cert.lock().unwrap() = TargetCert::generate();

    let (stream, _, closed) = h
        .rdp_socket(ADA, start["websocket"].as_str().unwrap())
        .await
        .unwrap();
    assert!(browser_handshake(stream, &throwaway_of(&start), false)
        .await
        .is_err());
    assert_eq!(
        wait_for_close(&closed).await,
        Some(crate::ssh::close::TRUST)
    );
    assert!(received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn refuses_targets_without_nla_unless_the_policy_allows_them() {
    let cert = Arc::new(StdMutex::new(TargetCert::generate()));
    let (target, received) = rdp_target(SecurityProtocol::SSL, cert).await;

    let strict = Harness::new().await;
    strict.add_rdp_connection(ADA, target).await;
    let (status, body) = strict.start(ADA, json!({ "connectionId": "win" })).await;
    assert_eq!(
        (status, body["code"].clone()),
        (reqwest::StatusCode::FORBIDDEN, json!("nla_required"))
    );

    let mut allowing: Policy = policy(5);
    allowing.allow_rdp_without_nla = true;
    let h = Harness::with_policy(allowing).await;
    h.add_rdp_connection(ADA, target).await;
    let start = h.start_rdp(ADA).await;
    let (stream, _, _) = h
        .rdp_socket(ADA, start["websocket"].as_str().unwrap())
        .await
        .unwrap();
    let mut framed = browser_handshake(stream, &throwaway_of(&start), true)
        .await
        .unwrap();
    connect(&mut framed).await;
    assert_eq!(
        echo(&mut framed, b"logon screen").await,
        b"echo:logon screen"
    );
    assert!(contains(&received.lock().unwrap(), b"logon screen"));
}

/// An X.224-framed client MCS Connect Initial carrying the given static channels.
fn connect_initial(channels: &[&str]) -> Vec<u8> {
    let mut body = vec![0x02, 0xf0, 0x80, 0x7f, 0x65];
    body.extend_from_slice(&[0x02, 0xc0, 0x0c, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
    body.extend_from_slice(&0xC003u16.to_le_bytes());
    body.extend_from_slice(&((8 + 12 * channels.len()) as u16).to_le_bytes());
    body.extend_from_slice(&(channels.len() as u32).to_le_bytes());
    for name in channels {
        let mut field = [0u8; 8];
        field[..name.len()].copy_from_slice(name.as_bytes());
        body.extend_from_slice(&field);
        body.extend_from_slice(&0x8080_0000u32.to_le_bytes());
    }
    let mut pdu = vec![0x03, 0x00];
    pdu.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    pdu.extend_from_slice(&body);
    pdu
}

#[tokio::test]
async fn opens_the_clipboard_channel_only_when_the_policy_allows_it() {
    for allowed in [false, true] {
        let cert = Arc::new(StdMutex::new(TargetCert::generate()));
        let (target, received) = rdp_target(SecurityProtocol::HYBRID_EX, cert).await;
        let mut chosen: Policy = policy(5);
        chosen.clipboard.rdp = allowed;
        let h = Harness::with_policy(chosen).await;
        h.add_rdp_connection(ADA, target).await;
        let start = h.start_rdp(ADA).await;
        assert_eq!(start["clipboard"], allowed);
        let (stream, _, _) = h
            .rdp_socket(ADA, start["websocket"].as_str().unwrap())
            .await
            .unwrap();
        let mut framed = browser_handshake(stream, &throwaway_of(&start), false)
            .await
            .unwrap();
        let pdu = connect_initial(&["rdpdr", "cliprdr", "drdynvc"]);
        echo(&mut framed, &pdu).await;
        let at_target = received.lock().unwrap().clone();
        assert_eq!(
            contains(&at_target, b"cliprdr\0"),
            allowed,
            "allowed: {allowed}"
        );
        assert!(contains(&at_target, b"drdynvc\0"));
        assert_eq!(at_target.len(), pdu.len());
    }
}

#[tokio::test]
async fn refuses_rdp_through_a_jump_host() {
    let h = Harness::new().await;
    let node = Node::Connection {
        id: "win".into(),
        name: "win".into(),
        conn: Connection {
            protocol: Protocol::Rdp,
            host: "127.0.0.1".into(),
            port: Some(3389),
            credentials: Credentials::default(),
            gateway: Some(crate::model::Gateway {
                host: "127.0.0.1".into(),
                ..Default::default()
            }),
        },
    };
    h.state
        .store
        .for_user(ADA)
        .update(|doc| doc.upsert(None, node))
        .unwrap();
    let (status, body) = h.start(ADA, json!({ "connectionId": "win" })).await;
    assert_eq!(
        (status, body["code"].clone()),
        (
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            json!("rdp_jump_unsupported")
        )
    );
}

#[test]
fn the_probe_needs_no_credential() {
    // `probe` takes only an address and the NLA setting: nothing secret can reach the target.
    let _: fn(SocketAddr, bool) -> _ = rdp_inject::probe;
}

#[tokio::test]
async fn starts_no_session_for_an_https_connection() {
    let h = Harness::new().await;
    let node = Node::Connection {
        id: "web".into(),
        name: "router".into(),
        conn: Connection {
            protocol: Protocol::Https,
            host: "10.0.0.1".into(),
            port: Some(8443),
            credentials: Credentials::default(),
            gateway: None,
        },
    };
    h.state
        .store
        .for_user(ADA)
        .update(|doc| doc.upsert(None, node))
        .unwrap();
    let (status, body) = h.start(ADA, json!({ "connectionId": "web" })).await;
    assert_eq!(
        (status, body["code"].clone()),
        (
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            json!("open_in_browser")
        )
    );
    assert!(h.webos.tickets.lock().unwrap().is_empty());
}
