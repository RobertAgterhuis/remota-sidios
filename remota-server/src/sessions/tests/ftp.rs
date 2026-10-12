//! FTP and FTPS sessions end to end (SidiOS T075): the HTTP start with certificate trust, the
//! ticketed WebSocket's commands, streamed downloads and uploads, and a fake FTP server that
//! answers passive mode with another address, so only a pinned data connection reaches it.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};

use super::{Harness, Socket, ADA, BOB};
use crate::{
    model::{Connection, Credentials, Node, Protocol, Secret},
    webos::{NewCredential, Webos},
};

const FTP_USER: &str = "files";
const FTP_PASSWORD: &str = "ftp-target-password-4c1e";

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tls {
    None,
    Explicit,
    Implicit,
}

/// The fake server's state: its files and folders, its certificate, and every command it got.
#[derive(Clone)]
struct FakeFtp {
    tls: Tls,
    /// Offers `MLSD` (machine listings); otherwise only Unix `LIST`.
    machine: bool,
    certificate: Arc<StdMutex<(Vec<u8>, Vec<u8>)>>,
    files: Arc<StdMutex<BTreeMap<String, Vec<u8>>>>,
    folders: Arc<StdMutex<Vec<String>>>,
    commands: Arc<StdMutex<Vec<String>>>,
}

fn certificate() -> (Vec<u8>, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec!["ftp-target".to_owned()]).unwrap();
    (
        certified.cert.der().to_vec(),
        certified.key_pair.serialize_der(),
    )
}

impl FakeFtp {
    fn new(tls: Tls, machine: bool) -> Self {
        Self {
            tls,
            machine,
            certificate: Arc::new(StdMutex::new(certificate())),
            files: Arc::default(),
            folders: Arc::new(StdMutex::new(vec!["/".into()])),
            commands: Arc::default(),
        }
    }

    fn acceptor(&self) -> TlsAcceptor {
        let (der, key) = self.certificate.lock().unwrap().clone();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
        )
        .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    fn saw(&self, prefix: &str) -> bool {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .any(|command| command.starts_with(prefix))
    }

    async fn listen(self, port: u16) -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let server = self.clone();
                tokio::spawn(async move {
                    let stream: Box<dyn Io> = if server.tls == Tls::Implicit {
                        match server.acceptor().accept(tcp).await {
                            Ok(tls) => Box::new(tls),
                            Err(_) => return,
                        }
                    } else {
                        Box::new(tcp)
                    };
                    let _ = server.serve(stream).await;
                });
            }
        });
        address
    }

    async fn serve(&self, stream: Box<dyn Io>) -> std::io::Result<()> {
        let mut control = BufReader::new(stream);
        let mut cwd = "/".to_owned();
        let mut signed_in = false;
        let mut user = String::new();
        let mut protect = self.tls == Tls::Implicit;
        let mut rename_from: Option<String> = None;
        let mut data: Option<tokio::task::JoinHandle<Option<TcpStream>>> = None;
        control.write_all(b"220 fake ftp\r\n").await?;
        loop {
            let mut line = String::new();
            if control.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            let line = line.trim_end().to_owned();
            eprintln!("FTP< {line}");
            self.commands.lock().unwrap().push(line.clone());
            let (verb, arg) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            let reply = match verb.to_ascii_uppercase().as_str() {
                "AUTH" if self.tls == Tls::Explicit => {
                    control.write_all(b"234 go ahead\r\n").await?;
                    let tcp = control.into_inner();
                    let tls = self.acceptor().accept(tcp).await?;
                    control = BufReader::new(Box::new(tls));
                    continue;
                }
                "AUTH" => "502 no tls".into(),
                "PBSZ" => "200 ok".into(),
                "PROT" => {
                    protect = arg == "P";
                    "200 ok".into()
                }
                "USER" => {
                    user = arg.to_owned();
                    "331 password please".into()
                }
                "PASS" if user == FTP_USER && arg == FTP_PASSWORD => {
                    signed_in = true;
                    "230 welcome".into()
                }
                "PASS" => "530 Login incorrect".into(),
                "QUIT" => {
                    control.write_all(b"221 bye\r\n").await?;
                    return Ok(());
                }
                _ if !signed_in => "530 sign in first".into(),
                "TYPE" | "NOOP" => "200 ok".into(),
                "FEAT" if self.machine => "211-Features:\r\n MLST type*;size*;modify*;\r\n211 End".into(),
                "FEAT" => "211-Features:\r\n SIZE\r\n211 End".into(),
                "PWD" => format!("257 \"{cwd}\" is the current folder"),
                "CWD" => {
                    let target = resolve(&cwd, arg);
                    if self.folders.lock().unwrap().contains(&target) {
                        cwd = target;
                        "250 ok".into()
                    } else {
                        "550 No such folder".into()
                    }
                }
                "PASV" | "EPSV" => {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let port = listener.local_addr()?.port();
                    data = Some(tokio::spawn(async move {
                        tokio::time::timeout(Duration::from_secs(5), listener.accept())
                            .await
                            .ok()?
                            .ok()
                            .map(|(tcp, _)| tcp)
                    }));
                    if verb.eq_ignore_ascii_case("EPSV") {
                        format!("229 Entering Extended Passive Mode (|||{port}|)")
                    } else {
                        // Another address than the control connection's: a bounce attempt.
                        format!(
                            "227 Entering Passive Mode (10,255,255,1,{},{})",
                            port >> 8,
                            port & 0xff
                        )
                    }
                }
                "PORT" | "EPRT" => "500 active mode is not expected".into(),
                "MLSD" | "LIST" => {
                    let listing = self.listing(&cwd, verb.eq_ignore_ascii_case("MLSD"));
                    self.send(&mut control, &mut data, protect, listing.into_bytes())
                        .await?;
                    continue;
                }
                "SIZE" => match self.files.lock().unwrap().get(&resolve(&cwd, arg)) {
                    Some(bytes) => format!("213 {}", bytes.len()),
                    None => "550 No such file".into(),
                },
                "RETR" => {
                    let content = self.files.lock().unwrap().get(&resolve(&cwd, arg)).cloned();
                    match content {
                        Some(content) => {
                            self.send(&mut control, &mut data, protect, content).await?;
                            continue;
                        }
                        None => "550 No such file".into(),
                    }
                }
                "STOR" => {
                    let path = resolve(&cwd, arg);
                    let Some(mut stream) = self.open_data(&mut data, protect).await else {
                        control.write_all(b"425 no data connection\r\n").await?;
                        continue;
                    };
                    control.write_all(b"150 send it\r\n").await?;
                    let mut content = Vec::new();
                    let _ = stream.read_to_end(&mut content).await;
                    self.files.lock().unwrap().insert(path, content);
                    "226 stored".into()
                }
                "MKD" => {
                    self.folders.lock().unwrap().push(resolve(&cwd, arg));
                    "257 created".into()
                }
                "RNFR" => {
                    rename_from = Some(resolve(&cwd, arg));
                    "350 ready".into()
                }
                "RNTO" => {
                    let from = rename_from.take().unwrap_or_default();
                    let to = resolve(&cwd, arg);
                    let mut files = self.files.lock().unwrap();
                    match files.remove(&from) {
                        Some(content) => {
                            files.insert(to, content);
                            "250 renamed".into()
                        }
                        None => "550 No such file".into(),
                    }
                }
                "DELE" => match self.files.lock().unwrap().remove(&resolve(&cwd, arg)) {
                    Some(_) => "250 deleted".into(),
                    None => "550 No such file".into(),
                },
                "RMD" => {
                    let path = resolve(&cwd, arg);
                    self.folders.lock().unwrap().retain(|folder| folder != &path);
                    "250 removed".into()
                }
                _ => "502 not implemented".into(),
            };
            control.write_all(format!("{reply}\r\n").as_bytes()).await?;
        }
    }

    async fn open_data(
        &self,
        data: &mut Option<tokio::task::JoinHandle<Option<TcpStream>>>,
        protect: bool,
    ) -> Option<Box<dyn Io>> {
        let tcp = data.take()?.await.ok()??;
        if protect {
            Some(Box::new(self.acceptor().accept(tcp).await.ok()?))
        } else {
            Some(Box::new(tcp))
        }
    }

    async fn send(
        &self,
        control: &mut BufReader<Box<dyn Io>>,
        data: &mut Option<tokio::task::JoinHandle<Option<TcpStream>>>,
        protect: bool,
        content: Vec<u8>,
    ) -> std::io::Result<()> {
        let Some(mut stream) = self.open_data(data, protect).await else {
            return control.write_all(b"425 no data connection\r\n").await;
        };
        control.write_all(b"150 here it comes\r\n").await?;
        stream.write_all(&content).await?;
        stream.shutdown().await?;
        drop(stream);
        control.write_all(b"226 done\r\n").await
    }

    fn listing(&self, cwd: &str, machine: bool) -> String {
        let prefix = if cwd == "/" { "/".to_owned() } else { format!("{cwd}/") };
        let child = |path: &str| {
            path.strip_prefix(&prefix)
                .filter(|rest| !rest.is_empty() && !rest.contains('/'))
                .map(str::to_owned)
        };
        let mut lines = Vec::new();
        if machine {
            lines.push(format!("type=cdir;modify=20261012100000; {cwd}"));
        }
        for folder in self.folders.lock().unwrap().iter() {
            if let Some(name) = child(folder) {
                lines.push(if machine {
                    format!("type=dir;modify=20261012100000; {name}")
                } else {
                    format!("drwxr-xr-x    2 1000     1000         4096 Oct 12 10:00 {name}")
                });
            }
        }
        for (path, content) in self.files.lock().unwrap().iter() {
            if let Some(name) = child(path) {
                lines.push(if machine {
                    format!("type=file;size={};modify=20261012100000; {name}", content.len())
                } else {
                    format!(
                        "-rw-r--r--    1 1000     1000     {:>8} Oct 12 10:00 {name}",
                        content.len()
                    )
                });
            }
        }
        lines.iter().map(|line| format!("{line}\r\n")).collect()
    }
}

fn resolve(cwd: &str, path: &str) -> String {
    let joined = if path.starts_with('/') {
        path.to_owned()
    } else if cwd == "/" {
        format!("/{path}")
    } else {
        format!("{cwd}/{path}")
    };
    let trimmed = joined.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else {
        trimmed.into()
    }
}

/// The browser's end of an FTP session WebSocket.
struct FtpSocket {
    socket: Socket,
    next: u64,
    /// Every text message the browser received.
    seen: Vec<String>,
}

impl FtpSocket {
    async fn ready(&mut self) -> Value {
        let message = self.message().await.expect("ready");
        assert_eq!(message["type"], "ready", "{message}");
        message
    }

    async fn message(&mut self) -> Option<Value> {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(20), self.socket.next())
                .await
                .expect("FTP session answer")?;
            match message.ok()? {
                tungstenite::Message::Text(text) => {
                    self.seen.push(text.to_string());
                    return serde_json::from_str(&text).ok();
                }
                tungstenite::Message::Close(_) => return None,
                _ => {}
            }
        }
    }

    async fn close_code(&mut self) -> Option<u16> {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(20), self.socket.next())
                .await
                .expect("close")?;
            if let Ok(tungstenite::Message::Close(frame)) = message {
                return frame.map(|f| u16::from(f.code));
            }
        }
    }

    async fn call(&mut self, mut command: Value) -> Value {
        self.next += 1;
        command["id"] = json!(self.next);
        self.socket
            .send(tungstenite::Message::Text(command.to_string().into()))
            .await
            .unwrap();
        let answer = self.message().await.expect("answer");
        assert_eq!(answer["id"], json!(self.next), "{answer}");
        answer
    }

    async fn names(&mut self, path: &str) -> Vec<(String, String)> {
        let answer = self.call(json!({ "op": "list", "path": path })).await;
        assert_eq!(answer["ok"], true, "{answer}");
        answer["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["name"].as_str().unwrap().to_owned(),
                    e["kind"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }
}

impl Harness {
    async fn add_ftp_connection(&self, user: &str, protocol: Protocol, target: SocketAddr) {
        let credential_id = self
            .webos
            .save_credential(
                user,
                NewCredential {
                    id: None,
                    kind: "password".into(),
                    label: "files".into(),
                    username: Some(FTP_USER.into()),
                    secret: FTP_PASSWORD.into(),
                    passphrase: None,
                },
            )
            .await
            .unwrap();
        let node = Node::Connection {
            id: "files".into(),
            name: "files".into(),
            conn: Connection {
                protocol,
                host: target.ip().to_string(),
                port: Some(target.port()),
                credentials: Credentials {
                    username: Some(FTP_USER.into()),
                    domain: None,
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

    /// Starts an FTP session, trusting an FTPS certificate on first use as the user would.
    async fn start_ftp(&self, user: &str) -> Value {
        let (status, body) = self.start(user, json!({ "connectionId": "files" })).await;
        if status != reqwest::StatusCode::CONFLICT {
            assert_eq!(status, reqwest::StatusCode::CREATED, "{body}");
            return body;
        }
        assert_eq!(body["code"], "certificate_unknown");
        let (status, _) = self
            .post(
                user,
                "/api/trust/certificate",
                json!({ "connectionId": "files", "fingerprint": body["fingerprint"] }),
            )
            .await;
        assert_eq!(status, reqwest::StatusCode::OK);
        let (status, body) = self.start(user, json!({ "connectionId": "files" })).await;
        assert_eq!(status, reqwest::StatusCode::CREATED, "{body}");
        body
    }

    async fn ftp_socket(&self, user: &str, start: &Value) -> FtpSocket {
        let path = start["websocket"].as_str().unwrap();
        let mut request = format!("ws://{}{path}", self.address)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("x-webos-user", user.parse().unwrap());
        let (socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        FtpSocket {
            socket,
            next: 0,
            seen: Vec::new(),
        }
    }

    fn transfer_url(&self, start: &Value, action: &str, path: &str) -> String {
        format!(
            "http://{}/api/ftp/{}/{action}?path={}",
            self.address,
            start["sessionId"].as_str().unwrap(),
            path.replace(' ', "%20")
        )
    }

    fn ftp_audits(&self) -> Vec<(&'static str, &'static str)> {
        self.webos
            .audits
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| event.event.starts_with("remota.ftp."))
            .map(|(_, event)| (event.event, event.outcome))
            .collect()
    }
}

async fn eventually(check: impl Fn() -> bool) {
    for _ in 0..50 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(check(), "condition not reached");
}

#[tokio::test]
async fn browses_and_transfers_over_ftps_signed_in_with_the_stored_password_only_on_the_server() {
    let server = FakeFtp::new(Tls::Explicit, true);
    let target = server.clone().listen(0).await;
    let h = Harness::new().await;
    h.add_ftp_connection(ADA, Protocol::Ftps, target).await;

    let start = h.start_ftp(ADA).await;
    assert_eq!((start["protocol"].clone(), start["secure"].clone()), (json!("ftps"), json!(true)));
    let mut ftp = h.ftp_socket(ADA, &start).await;
    assert_eq!(ftp.ready().await["start"], "/");

    // Upload, list, download.
    let response = h
        .http
        .put(h.transfer_url(&start, "upload", "/hello world.txt"))
        .header("x-webos-user", ADA)
        .body("hello from SidiOS")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(
        ftp.names("/").await,
        [("hello world.txt".to_owned(), "file".to_owned())]
    );
    let response = h
        .http
        .get(h.transfer_url(&start, "download", "/hello world.txt"))
        .header("x-webos-user", ADA)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename*=UTF-8''hello%20world.txt"
    );
    assert_eq!(response.headers()["content-length"], "17");
    assert_eq!(response.text().await.unwrap(), "hello from SidiOS");

    // Folders, rename, delete.
    let made = ftp.call(json!({ "op": "mkdir", "path": "/docs" })).await;
    assert_eq!(made["ok"], true, "{made}");
    let renamed = ftp
        .call(json!({ "op": "rename", "from": "/hello world.txt", "to": "/docs/hello.txt" }))
        .await;
    assert_eq!(renamed["ok"], true, "{renamed}");
    assert_eq!(ftp.names("/").await, [("docs".to_owned(), "dir".to_owned())]);
    assert_eq!(
        ftp.names("/docs").await,
        [("hello.txt".to_owned(), "file".to_owned())]
    );
    let missing = ftp.call(json!({ "op": "list", "path": "/nowhere" })).await;
    assert_eq!(
        (missing["ok"].clone(), missing["code"].clone(), missing["message"].clone()),
        (json!(false), json!("server_error"), json!("No such folder"))
    );
    for (path, folder) in [("/docs/hello.txt", false), ("/docs", true)] {
        let deleted = ftp
            .call(json!({ "op": "delete", "path": path, "folder": folder }))
            .await;
        assert_eq!(deleted["ok"], true, "{deleted}");
    }
    assert!(ftp.names("/").await.is_empty());

    // The server signed in with the stored password, over TLS, in passive mode only; the
    // passive answer named another address, and the data still reached this server.
    assert!(server.saw("AUTH TLS"));
    assert!(server.saw(&format!("PASS {FTP_PASSWORD}")));
    assert!(server.saw("PROT P"));
    assert!(!server.saw("PORT") && !server.saw("EPRT"));
    // The password never reached the browser.
    let everything = format!("{start}{}", ftp.seen.join(""));
    assert!(!everything.contains(FTP_PASSWORD));

    drop(ftp);
    eventually(|| {
        h.ftp_audits()
            == [
                ("remota.ftp.upload", "done"),
                ("remota.ftp.download", "done"),
                ("remota.ftp.delete", "done"),
                ("remota.ftp.delete", "done"),
            ]
    })
    .await;
    eventually(|| server.saw("QUIT")).await;
}

#[tokio::test]
async fn plain_ftp_needs_no_certificate_and_reads_unix_listings() {
    let server = FakeFtp::new(Tls::None, false);
    server
        .files
        .lock()
        .unwrap()
        .insert("/readme.txt".into(), b"plain".to_vec());
    server.folders.lock().unwrap().push("/pub".into());
    let target = server.clone().listen(0).await;
    let h = Harness::new().await;
    h.add_ftp_connection(ADA, Protocol::Ftp, target).await;

    let (status, start) = h.start(ADA, json!({ "connectionId": "files" })).await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "{start}");
    assert_eq!(start["secure"], false);
    let mut ftp = h.ftp_socket(ADA, &start).await;
    assert_eq!(ftp.ready().await["secure"], false);
    assert_eq!(
        ftp.names("/").await,
        [
            ("pub".to_owned(), "dir".to_owned()),
            ("readme.txt".to_owned(), "file".to_owned())
        ]
    );
    assert!(!server.saw("AUTH"));
}

#[tokio::test]
async fn implicit_ftps_on_port_990() {
    let server = FakeFtp::new(Tls::Implicit, true);
    let Ok(probe) = TcpListener::bind("127.0.0.1:990").await else {
        eprintln!("skipped: port 990 is not available here");
        return;
    };
    drop(probe);
    let target = server.clone().listen(990).await;
    let h = Harness::new().await;
    h.add_ftp_connection(ADA, Protocol::Ftps, target).await;

    let start = h.start_ftp(ADA).await;
    let mut ftp = h.ftp_socket(ADA, &start).await;
    ftp.ready().await;
    assert!(ftp.names("/").await.is_empty());
    assert!(!server.saw("AUTH"), "implicit TLS needs no AUTH");
}

#[tokio::test]
async fn never_signs_in_to_a_changed_certificate() {
    let server = FakeFtp::new(Tls::Explicit, true);
    let target = server.clone().listen(0).await;
    let h = Harness::new().await;
    h.add_ftp_connection(ADA, Protocol::Ftps, target).await;

    let (status, body) = h.start(ADA, json!({ "connectionId": "files" })).await;
    assert_eq!((status, body["code"].clone()), (reqwest::StatusCode::CONFLICT, json!("certificate_unknown")));
    let (status, _) = h
        .post(
            ADA,
            "/api/trust/certificate",
            json!({ "connectionId": "files", "fingerprint": "SHA256:other" }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "only the presented certificate is trusted");
    let start = h.start_ftp(ADA).await;

    // The certificate changes between the start and the session.
    *server.certificate.lock().unwrap() = certificate();
    let mut ftp = h.ftp_socket(ADA, &start).await;
    assert_eq!(ftp.close_code().await, Some(4409));
    assert!(!server.saw("PASS"), "the password went to a changed certificate");

    let (status, body) = h.start(ADA, json!({ "connectionId": "files" })).await;
    assert_eq!((status, body["code"].clone()), (reqwest::StatusCode::CONFLICT, json!("certificate_changed")));
    let (status, _) = h
        .post(
            ADA,
            "/api/trust/certificate",
            json!({ "connectionId": "files", "fingerprint": body["fingerprint"] }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "replaced silently");
}

#[tokio::test]
async fn a_refused_password_ends_the_session() {
    let server = FakeFtp::new(Tls::None, true);
    let target = server.clone().listen(0).await;
    // No stored credential: the password typed at connect time is the wrong one.
    let h = Harness::new().await;
    let node = Node::Connection {
        id: "files".into(),
        name: "files".into(),
        conn: Connection {
            protocol: Protocol::Ftp,
            host: target.ip().to_string(),
            port: Some(target.port()),
            credentials: Credentials {
                username: Some(FTP_USER.into()),
                domain: None,
                secret: Secret::default(),
            },
            gateway: None,
        },
    };
    h.state
        .store
        .for_user(ADA)
        .update(|doc| doc.upsert(None, node))
        .unwrap();
    let (status, start) = h
        .start(
            ADA,
            json!({ "connectionId": "files", "oneTimeSecret": "wrong-password", "saveSecret": false }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "{start}");
    let mut ftp = h.ftp_socket(ADA, &start).await;
    assert_eq!(ftp.close_code().await, Some(4403));
}

#[tokio::test]
async fn transfers_answer_only_the_sessions_own_user_while_it_runs() {
    let server = FakeFtp::new(Tls::None, true);
    server
        .files
        .lock()
        .unwrap()
        .insert("/secret.txt".into(), b"mine".to_vec());
    let target = server.clone().listen(0).await;
    let h = Harness::new().await;
    h.add_ftp_connection(ADA, Protocol::Ftp, target).await;
    let start = h.start_ftp(ADA).await;
    let mut ftp = h.ftp_socket(ADA, &start).await;
    ftp.ready().await;

    let url = h.transfer_url(&start, "download", "/secret.txt");
    let status = |user: &'static str| {
        let request = h.http.get(&url).header("x-webos-user", user);
        async move { request.send().await.unwrap().status() }
    };
    assert_eq!(status(BOB).await, reqwest::StatusCode::NOT_FOUND);
    assert_eq!(status(ADA).await, reqwest::StatusCode::OK);

    // An upload that says it is larger than 1 GB is refused before any byte is read.
    let mut raw = TcpStream::connect(h.address).await.unwrap();
    let request = format!(
        "PUT /api/ftp/{}/upload?path=/big HTTP/1.1\r\nhost: remota\r\nx-webos-user: {ADA}\r\ncontent-length: {}\r\n\r\n",
        start["sessionId"].as_str().unwrap(),
        (1u64 << 30) + 1
    );
    raw.write_all(request.as_bytes()).await.unwrap();
    let mut head = vec![0u8; 12];
    raw.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 413");
    assert!(!server.saw("STOR"));

    // A path with a line break is never sent to the server.
    let answer = ftp
        .call(json!({ "op": "delete", "path": "/x\r\nDELE /secret.txt" }))
        .await;
    assert_eq!(answer["code"], "invalid_path");
    assert!(server.files.lock().unwrap().contains_key("/secret.txt"));

    // Revoked: the session ends and its transfers are gone.
    assert_eq!(h.state.sessions.end(None, Some(ADA)), 1);
    assert_eq!(ftp.close_code().await, Some(4403));
    eventually(|| h.state.sessions.running().is_empty()).await;
    assert_eq!(status(ADA).await, reqwest::StatusCode::NOT_FOUND);
    assert!(h
        .webos
        .audits
        .lock()
        .unwrap()
        .iter()
        .any(|(_, e)| e.event == "remota.session.end" && e.outcome == "revoked"));
    assert!(h.ftp_audits().contains(&("remota.ftp.upload", "too_large")));
}

#[tokio::test]
async fn refuses_ftp_through_a_jump_host() {
    let h = Harness::new().await;
    let node = Node::Connection {
        id: "files".into(),
        name: "files".into(),
        conn: Connection {
            protocol: Protocol::Ftp,
            host: "127.0.0.1".into(),
            port: Some(21),
            credentials: Credentials {
                username: Some(FTP_USER.into()),
                domain: None,
                secret: Secret::default(),
            },
            gateway: Some(crate::model::Gateway {
                host: "127.0.0.1".into(),
                port: Some(22),
                username: None,
                secret: Secret::default(),
            }),
        },
    };
    h.state
        .store
        .for_user(ADA)
        .update(|doc| doc.upsert(None, node))
        .unwrap();
    let (status, body) = h
        .start(ADA, json!({ "connectionId": "files", "oneTimeSecret": "x" }))
        .await;
    assert_eq!(
        (status, body["code"].clone()),
        (reqwest::StatusCode::UNPROCESSABLE_ENTITY, json!("jump_unsupported"))
    );
}
