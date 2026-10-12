//! Spike tests (SidiOS T006). The end-to-end tests need the FreeRDP Shadow NLA fixture and run
//! only when it is configured:
//!
//! - `REMOTA_RDP_FIXTURE=host:port`, `REMOTA_RDP_FIXTURE_USER`, `REMOTA_RDP_FIXTURE_DOMAIN`, and
//!   `REMOTA_RDP_FIXTURE_PASSWORD_FILE` (the password is read from a file, never an argument);
//! - optionally `REMOTA_RDP_FIXTURE_DISPLAY` (for example `:99`) when the fixture's X display is
//!   reachable from the test, to check the mouse position on the remote desktop, and
//!   `REMOTA_RDP_FIXTURE_TYPED_LOG`, the log of the fixture's focused terminal, to check that typed
//!   text arrives.
//!
//! The "browser" is IronRDP's connector driven the way `ironrdp-web` drives it over RDCleanPath.

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use ironrdp_connector::{
    sspi::generator::NetworkRequest, ClientConnector, Config, ConnectorResult, Credentials,
    DesktopSize, Sequence,
};
use ironrdp_pdu::{gcc::KeyboardType, rdp::capability_sets::MajorPlatformType};
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use super::*;

/// The browser end of the WebSocket, recording every byte the browser receives.
struct Recording {
    inner: DuplexStream,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Recording {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let fresh = buf.filled()[before..].to_vec();
        self.seen.lock().unwrap().extend_from_slice(&fresh);
        polled
    }
}

impl AsyncWrite for Recording {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct NoNetwork;

impl ironrdp_async::NetworkClient for NoNetwork {
    async fn send(&mut self, _: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        Err(ironrdp_connector::general_err!(
            "no network requests in tests"
        ))
    }
}

fn browser_config(login: &ThrowawayLogin) -> Config {
    Config {
        desktop_size: DesktopSize {
            width: 1024,
            height: 768,
        },
        desktop_scale_factor: 0,
        enable_tls: false,
        enable_credssp: true,
        credentials: Credentials::UsernamePassword {
            username: login.username.clone(),
            password: login.password.to_string(),
        },
        domain: None,
        client_build: 0,
        client_name: "remota-test".to_owned(),
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0x409,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        performance_flags: Default::default(),
        license_cache: None,
        timezone_info: Default::default(),
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: true,
        multitransport_flags: None,
    }
}

/// What `ironrdp-web` does over RDCleanPath: X.224 request in an RDCleanPath request, the
/// response's certificate as the CredSSP key, then the rest of the connection sequence.
async fn browser_connect(
    stream: Recording,
    login: &ThrowawayLogin,
) -> ConnectorResult<(ironrdp_connector::ConnectionResult, TokioFramed<Recording>)> {
    let mut stream = stream;
    let mut connector =
        ClientConnector::new(browser_config(login), "127.0.0.1:50000".parse().unwrap());
    let mut buf = WriteBuf::new();
    let written = connector.step_no_input(&mut buf)?;
    let request = buf.filled()[..written.size().unwrap()].to_vec();
    let pdu = RDCleanPathPdu::new_request(request, "target".into(), String::new(), None)
        .unwrap()
        .to_der()
        .unwrap();
    stream.write_all(&pdu).await.unwrap();

    let mut answer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let DetectionResult::Detected { total_length, .. } = RDCleanPathPdu::detect(&answer) {
            if answer.len() >= total_length {
                break;
            }
        }
        let read = stream.read(&mut chunk).await.unwrap();
        if read == 0 {
            return Err(ironrdp_connector::general_err!("gateway closed"));
        }
        answer.extend_from_slice(&chunk[..read]);
    }
    let RDCleanPath::Response {
        x224_connection_response,
        server_cert_chain,
        ..
    } = RDCleanPathPdu::from_der(&answer)
        .unwrap()
        .into_enum()
        .unwrap()
    else {
        return Err(ironrdp_connector::general_err!("gateway refused"));
    };
    buf.clear();
    connector.step(x224_connection_response.as_bytes(), &mut buf)?;
    let should_upgrade = ironrdp_async::skip_connect_begin(&mut connector);
    let upgraded = ironrdp_async::mark_as_upgraded(should_upgrade, &mut connector);
    let public_key = public_key_of(server_cert_chain[0].as_bytes()).unwrap();
    let mut framed = TokioFramed::new(stream);
    let result = ironrdp_async::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut NoNetwork,
        ServerName::new("target"),
        public_key,
        None,
    )
    .await?;
    Ok((result, framed))
}

struct Fixture {
    address: SocketAddr,
    login: TargetLogin,
    display: Option<String>,
    typed_log: Option<String>,
}

fn fixture() -> Option<Fixture> {
    let address = std::env::var("REMOTA_RDP_FIXTURE").ok()?.parse().ok()?;
    let password_file = std::env::var("REMOTA_RDP_FIXTURE_PASSWORD_FILE").ok()?;
    let password = std::fs::read_to_string(password_file)
        .ok()?
        .trim()
        .to_owned();
    Some(Fixture {
        address,
        login: TargetLogin {
            username: std::env::var("REMOTA_RDP_FIXTURE_USER").ok()?,
            domain: std::env::var("REMOTA_RDP_FIXTURE_DOMAIN").ok(),
            password: Zeroizing::new(password),
        },
        display: std::env::var("REMOTA_RDP_FIXTURE_DISPLAY").ok(),
        typed_log: std::env::var("REMOTA_RDP_FIXTURE_TYPED_LOG").ok(),
    })
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
        hex.as_bytes().to_vec(),
        hex.to_uppercase().into_bytes(),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Starts the gateway side on one end of an in-memory "WebSocket" and the browser on the other.
async fn session(
    fixture: &Fixture,
    gateway_login: ThrowawayLogin,
    browser_login: ThrowawayLogin,
    trusted: Option<String>,
) -> (
    Result<String, InjectError>,
    ConnectorResult<(ironrdp_connector::ConnectionResult, TokioFramed<Recording>)>,
    Arc<Mutex<Vec<u8>>>,
) {
    let (browser_end, gateway_end) = duplex(1 << 20);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recording = Recording {
        inner: browser_end,
        seen: seen.clone(),
    };
    let gateway = GatewayCertificate::generate().unwrap();
    let address = fixture.address;
    let login = TargetLogin {
        username: fixture.login.username.clone(),
        domain: fixture.login.domain.clone(),
        password: fixture.login.password.clone(),
    };
    let gateway_task = tokio::spawn(async move {
        let established = establish(
            gateway_end,
            Injection {
                target: address,
                server_name: "fixture",
                login: &login,
                throwaway: &gateway_login,
                gateway: &gateway,
                trusted_fingerprint: trusted.as_deref(),
                allow_without_nla: false,
                clipboard: true,
            },
        )
        .await?;
        let fingerprint = established.fingerprint.clone();
        tokio::spawn(relay(established));
        Ok(fingerprint)
    });
    let browser = tokio::time::timeout(
        Duration::from_secs(30),
        browser_connect(recording, &browser_login),
    )
    .await
    .unwrap_or_else(|_| Err(ironrdp_connector::general_err!("timed out")));
    let gateway = gateway_task.await.unwrap();
    (gateway, browser, seen)
}

/// Reads server PDUs for a while; answers how many fast-path or X.224 updates arrived.
async fn read_updates(framed: &mut TokioFramed<Recording>, wait: Duration) -> usize {
    let mut count = 0;
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok((_, pdu))) = tokio::time::timeout_at(deadline, framed.read_pdu()).await {
        if !pdu.is_empty() {
            count += 1;
        }
    }
    count
}

fn scancode(ch: char) -> Option<u8> {
    let letters = b"\x1e\x30\x2e\x20\x12\x21\x22\x23\x17\x24\x25\x26\x32\x31\x18\x19\x10\x13\x1f\x14\x16\x2f\x11\x2d\x15\x2c";
    match ch {
        'a'..='z' => Some(letters[(ch as u8 - b'a') as usize]),
        '1'..='9' => Some(ch as u8 - b'1' + 0x02),
        '0' => Some(0x0b),
        '-' => Some(0x0c),
        '.' => Some(0x34),
        '/' => Some(0x35),
        ' ' => Some(0x39),
        '\n' => Some(0x1c),
        _ => None,
    }
}

/// Fast-path input: a lock-key synchronization, a click at (x, y), then `text` typed key by key.
fn input_events(x: u16, y: u16, text: &str) -> Vec<u8> {
    use ironrdp_pdu::input::{
        fast_path::{FastPathInput, FastPathInputEvent, KeyboardFlags, SynchronizeFlags},
        mouse::{MousePdu, PointerFlags},
    };
    let mouse = |flags: PointerFlags| {
        FastPathInputEvent::MouseEvent(MousePdu {
            flags,
            number_of_wheel_rotation_units: 0,
            x_position: x,
            y_position: y,
        })
    };
    // Real clients synchronize the lock keys first; FreeRDP Shadow drops keys until they do.
    let mut events = vec![
        FastPathInputEvent::SyncEvent(SynchronizeFlags::empty()),
        mouse(PointerFlags::MOVE),
        mouse(PointerFlags::LEFT_BUTTON | PointerFlags::DOWN),
        mouse(PointerFlags::LEFT_BUTTON),
    ];
    for code in text.chars().filter_map(scancode) {
        events.push(FastPathInputEvent::KeyboardEvent(
            KeyboardFlags::empty(),
            code,
        ));
        events.push(FastPathInputEvent::KeyboardEvent(
            KeyboardFlags::RELEASE,
            code,
        ));
    }
    let mut out = Vec::new();
    for chunk in events.chunks(15) {
        let pdu = FastPathInput::new(chunk.to_vec()).unwrap();
        out.extend(ironrdp_core::encode_vec(&pdu).unwrap());
    }
    out
}

#[test]
fn throwaway_logins_are_unique_and_long() {
    let a = ThrowawayLogin::generate();
    let b = ThrowawayLogin::generate();
    assert_ne!(a.username, b.username);
    assert_ne!(*a.password, *b.password);
    assert_eq!(a.password.len(), 64);
}

#[test]
fn the_gateway_certificate_yields_its_public_key() {
    let gateway = GatewayCertificate::generate().unwrap();
    assert_eq!(
        public_key_of(&gateway.der),
        Some(gateway.public_key.clone())
    );
    assert!(fingerprint(&gateway.der).starts_with("SHA256:"));
}

#[tokio::test]
async fn refuses_a_browser_stream_that_is_not_rdcleanpath() {
    let (mut browser, gateway_end) = duplex(4096);
    browser.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let login = TargetLogin {
        username: "u".into(),
        domain: None,
        password: Zeroizing::new("p".into()),
    };
    let throwaway = ThrowawayLogin::generate();
    let gateway = GatewayCertificate::generate().unwrap();
    let result = establish(
        gateway_end,
        Injection {
            target: "127.0.0.1:9".parse().unwrap(),
            server_name: "x",
            login: &login,
            throwaway: &throwaway,
            gateway: &gateway,
            trusted_fingerprint: None,
            allow_without_nla: false,
            clipboard: true,
        },
    )
    .await;
    assert_eq!(result.err(), Some(InjectError::BadRequest));
}

#[tokio::test]
async fn injects_the_target_credential_and_relays_a_working_desktop() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: REMOTA_RDP_FIXTURE is not set");
        return;
    };
    let login = ThrowawayLogin::generate();
    let (gateway, browser, seen) = session(&fixture, login.clone(), login, None).await;
    let fingerprint = gateway.expect("gateway leg");
    let (result, mut framed) = browser.expect("browser connection");
    assert!(result.desktop_size.width > 0);
    let updates = read_updates(&mut framed, Duration::from_secs(3)).await;
    assert!(updates > 0, "no desktop updates arrived");
    eprintln!(
        "desktop {}x{}, {updates} updates, target certificate {fingerprint}",
        result.desktop_size.width, result.desktop_size.height
    );

    if let Some(display) = &fixture.display {
        // A random lowercase word: typed (not run) into the remote terminal, then looked for in its log.
        let word: String = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .map(|c| {
                if c.is_ascii_digit() {
                    (b'g' + c as u8 - b'0') as char
                } else {
                    c
                }
            })
            .take(16)
            .collect();
        framed
            .write_all(&input_events(300, 200, &word))
            .await
            .unwrap();
        read_updates(&mut framed, Duration::from_secs(3)).await;
        let location = std::process::Command::new("xdotool")
            .arg("getmouselocation")
            .env("DISPLAY", display)
            .output()
            .unwrap();
        let location = String::from_utf8_lossy(&location.stdout).to_string();
        assert!(location.starts_with("x:300 y:200"), "mouse: {location}");
        if let Some(log) = &fixture.typed_log {
            let typed = std::fs::read_to_string(log).unwrap_or_default();
            assert!(
                typed.contains(&word),
                "keyboard: {word} did not reach the remote terminal"
            );
        }
    }

    let seen = seen.lock().unwrap();
    for form in password_forms(&fixture.login.password) {
        assert!(
            !contains(&seen, &form),
            "the browser received a target password form"
        );
    }
    eprintln!("inspected {} bytes sent to the browser", seen.len());
}

#[tokio::test]
async fn refuses_a_wrong_throwaway_login_without_signing_the_browser_in() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: REMOTA_RDP_FIXTURE is not set");
        return;
    };
    let expected = ThrowawayLogin::generate();
    let mut wrong = expected.clone();
    wrong.password = Zeroizing::new("not-the-throwaway".into());
    let (gateway, browser, _) = session(&fixture, expected, wrong, None).await;
    assert_eq!(gateway.err(), Some(InjectError::ClientRefused));
    assert!(browser.is_err());
}

#[tokio::test]
async fn stops_when_the_target_certificate_changed() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: REMOTA_RDP_FIXTURE is not set");
        return;
    };
    let login = ThrowawayLogin::generate();
    let (gateway, browser, seen) = session(
        &fixture,
        login.clone(),
        login,
        Some("SHA256:not-the-certificate".into()),
    )
    .await;
    assert!(matches!(
        gateway,
        Err(InjectError::CertificateChanged { .. })
    ));
    assert!(browser.is_err());
    // Nothing of the target leg reached the browser but the refusal.
    assert!(seen.lock().unwrap().len() < 64);
}

#[tokio::test]
async fn refuses_a_wrong_target_credential() {
    let Some(mut fixture) = fixture() else {
        eprintln!("skipped: REMOTA_RDP_FIXTURE is not set");
        return;
    };
    fixture.login.password = Zeroizing::new("wrong-target-password".into());
    let login = ThrowawayLogin::generate();
    let (gateway, browser, _) = session(&fixture, login.clone(), login, None).await;
    assert_eq!(gateway.err(), Some(InjectError::TargetRefused));
    assert!(browser.is_err());
}

/// A client network block (CS_NET) with the given static channels, between other GCC blocks.
fn connect_initial_with(channels: &[&str]) -> Vec<u8> {
    let mut pdu = vec![0x03, 0x00, 0x01, 0x2c, 0x02, 0xf0, 0x80, 0x7f, 0x65];
    // CS_SECURITY (0xC002), 12 bytes.
    pdu.extend_from_slice(&[0x02, 0xc0, 0x0c, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
    let length = 8 + 12 * channels.len();
    pdu.extend_from_slice(&0xC003u16.to_le_bytes());
    pdu.extend_from_slice(&(length as u16).to_le_bytes());
    pdu.extend_from_slice(&(channels.len() as u32).to_le_bytes());
    for name in channels {
        let mut field = [0u8; 8];
        field[..name.len()].copy_from_slice(name.as_bytes());
        pdu.extend_from_slice(&field);
        pdu.extend_from_slice(&0x8080_0000u32.to_le_bytes());
    }
    // CS_CLUSTER (0xC004) after it.
    pdu.extend_from_slice(&[0x04, 0xc0, 0x0c, 0x00, 0x0d, 0, 0, 0, 0, 0, 0, 0]);
    pdu
}

#[test]
fn closes_only_the_clipboard_channel_and_keeps_the_pdu_size() {
    let pdu = connect_initial_with(&["rdpdr", "cliprdr", "drdynvc"]);
    let filtered = without_clipboard_channel(&pdu).unwrap();
    assert_eq!(filtered.len(), pdu.len());
    assert!(!contains(&filtered, b"cliprdr"));
    assert!(contains(&filtered, b"remnocb\0"));
    assert!(contains(&filtered, b"rdpdr\0"));
    assert!(contains(&filtered, b"drdynvc\0"));
    // Only the 7 name bytes changed.
    let changed = pdu.iter().zip(&filtered).filter(|(a, b)| a != b).count();
    assert!(changed <= 7);
}

#[test]
fn leaves_a_connect_initial_without_the_clipboard_channel_alone() {
    let pdu = connect_initial_with(&["rdpdr", "drdynvc"]);
    assert_eq!(without_clipboard_channel(&pdu).unwrap(), pdu);
    let none = connect_initial_with(&[]);
    assert_eq!(without_clipboard_channel(&none).unwrap(), none);
}
