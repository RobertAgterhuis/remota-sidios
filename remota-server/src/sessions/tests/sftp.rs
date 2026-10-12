//! SFTP file-browser sessions end to end (SidiOS US9): the SSH sign-in with the stored password, the
//! host-key prompt in the file browser, and the same commands and transfers as FTP, against an
//! in-process SSH server with an in-memory SFTP subsystem.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use russh::{
    keys::{Algorithm, PrivateKey},
    server::{self, Auth as ServerAuth, Msg, Server as _, Session},
    Channel, ChannelId,
};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};

use super::{Harness, Socket, ADA, BOB};
use crate::{
    model::{Connection, Credentials, Node, Protocol, Secret},
    webos::{NewCredential, Webos},
};

const SFTP_USER: &str = "tester";
const SFTP_PASSWORD: &str = "sftp-target-password-91d2";
const HOME: &str = "/home/tester";

/// The server's files and folders.
#[derive(Clone, Default)]
struct Fs {
    files: Arc<StdMutex<BTreeMap<String, Vec<u8>>>>,
    folders: Arc<StdMutex<BTreeSet<String>>>,
}

fn resolve(path: &str) -> String {
    let joined = if path.starts_with('/') {
        path.to_owned()
    } else if path.is_empty() || path == "." {
        HOME.to_owned()
    } else {
        format!("{HOME}/{path}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn attributes(size: Option<u64>) -> FileAttributes {
    let mut attrs = FileAttributes {
        size: Some(size.unwrap_or(0)),
        mtime: Some(1_791_800_000),
        permissions: Some(0o644),
        ..Default::default()
    };
    if size.is_some() {
        attrs.set_regular(true);
    } else {
        attrs.set_dir(true);
    }
    attrs
}

enum Open {
    Folder { path: String, done: bool },
    File { path: String },
}

struct SftpServer {
    fs: Fs,
    handles: HashMap<String, Open>,
    next: u32,
}

impl SftpServer {
    fn handle(&mut self, open: Open) -> String {
        self.next += 1;
        let handle = format!("h{}", self.next);
        self.handles.insert(handle.clone(), open);
        handle
    }

    fn stat_of(&self, path: &str) -> Option<FileAttributes> {
        let path = resolve(path);
        if self.fs.folders.lock().unwrap().contains(&path) {
            return Some(attributes(None));
        }
        let size = self.fs.files.lock().unwrap().get(&path)?.len() as u64;
        Some(attributes(Some(size)))
    }
}

impl russh_sftp::server::Handler for SftpServer {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![File::dummy(resolve(&path))],
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let path = resolve(&path);
        if !self.fs.folders.lock().unwrap().contains(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        let handle = self.handle(Open::Folder { path, done: false });
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Folder { path, done }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        if *done {
            return Err(StatusCode::Eof);
        }
        *done = true;
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        let child = |full: &String| {
            full.strip_prefix(&prefix)
                .filter(|rest| !rest.is_empty() && !rest.contains('/'))
                .map(str::to_owned)
        };
        let mut files = vec![
            File::new(".", attributes(None)),
            File::new("..", attributes(None)),
        ];
        for folder in self.fs.folders.lock().unwrap().iter() {
            if let Some(name) = child(folder) {
                files.push(File::new(name, attributes(None)));
            }
        }
        for (path, content) in self.fs.files.lock().unwrap().iter() {
            if let Some(name) = child(path) {
                files.push(File::new(name, attributes(Some(content.len() as u64))));
            }
        }
        Ok(Name { id, files })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = resolve(&filename);
        let mut files = self.fs.files.lock().unwrap();
        if flags.contains(OpenFlags::CREATE) {
            if flags.contains(OpenFlags::TRUNCATE) || !files.contains_key(&path) {
                files.insert(path.clone(), Vec::new());
            }
        } else if !files.contains_key(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        drop(files);
        let handle = self.handle(Open::File { path });
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let Some(Open::File { path }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let files = self.fs.files.lock().unwrap();
        let content = files.get(path).ok_or(StatusCode::NoSuchFile)?;
        let start = offset as usize;
        if start >= content.len() {
            return Err(StatusCode::Eof);
        }
        let end = (start + len as usize).min(content.len());
        Ok(Data {
            id,
            data: content[start..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let Some(Open::File { path }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let mut files = self.fs.files.lock().unwrap();
        let content = files.get_mut(path).ok_or(StatusCode::NoSuchFile)?;
        let start = offset as usize;
        if content.len() < start + data.len() {
            content.resize(start + data.len(), 0);
        }
        content[start..start + data.len()].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(ok(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let attrs = self.stat_of(&path).ok_or(StatusCode::NoSuchFile)?;
        Ok(Attrs { id, attrs })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File { path }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let path = path.clone();
        self.stat(id, path).await
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.fs.folders.lock().unwrap().insert(resolve(&path));
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        if self.fs.folders.lock().unwrap().remove(&resolve(&path)) {
            Ok(ok(id))
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        match self.fs.files.lock().unwrap().remove(&resolve(&filename)) {
            Some(_) => Ok(ok(id)),
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let mut files = self.fs.files.lock().unwrap();
        let content = files
            .remove(&resolve(&oldpath))
            .ok_or(StatusCode::NoSuchFile)?;
        files.insert(resolve(&newpath), content);
        Ok(ok(id))
    }
}

/// An SSH server that only offers the SFTP subsystem, with the test login.
#[derive(Clone)]
struct SshServer {
    fs: Fs,
    channels: Arc<tokio::sync::Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl server::Server for SshServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        Self {
            fs: self.fs.clone(),
            channels: Arc::default(),
        }
    }
}

impl server::Handler for SshServer {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<ServerAuth, Self::Error> {
        Ok(if user == SFTP_USER && password == SFTP_PASSWORD {
            ServerAuth::Accept
        } else {
            ServerAuth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let opened = self.channels.lock().await.remove(&channel);
        match opened {
            Some(opened) if name == "sftp" => {
                session.channel_success(channel)?;
                let handler = SftpServer {
                    fs: self.fs.clone(),
                    handles: HashMap::new(),
                    next: 0,
                };
                tokio::spawn(russh_sftp::server::run(opened.into_stream(), handler));
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }
}

async fn sftp_server(fs: Fs) -> (SocketAddr, PrivateKey) {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let mut config = server::Config::default();
    config.keys.push(host_key.clone());
    config.auth_rejection_time = Duration::from_millis(10);
    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut server = SshServer {
        fs,
        channels: Arc::default(),
    };
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let handler = server.new_client(None);
            let config = config.clone();
            tokio::spawn(async move {
                let _ = server::run_stream(config, socket, handler).await;
            });
        }
    });
    (address, host_key)
}

impl Harness {
    async fn add_sftp_connection(&self, user: &str, target: SocketAddr) {
        let credential_id = self
            .webos
            .save_credential(
                user,
                NewCredential {
                    id: None,
                    kind: "password".into(),
                    label: "sftp".into(),
                    username: Some(SFTP_USER.into()),
                    secret: SFTP_PASSWORD.into(),
                    passphrase: None,
                },
            )
            .await
            .unwrap();
        let node = Node::Connection {
            id: "sftp".into(),
            name: "sftp".into(),
            conn: Connection {
                path: None,
                protocol: Protocol::Sftp,
                host: target.ip().to_string(),
                port: Some(target.port()),
                credentials: Credentials {
                    username: Some(SFTP_USER.into()),
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
}

/// The browser's end of the session: every text message it received, and the close code.
struct Browser {
    socket: Socket,
    seen: Vec<String>,
    next: u64,
}

impl Browser {
    async fn message(&mut self) -> Result<Value, Option<u16>> {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(20), self.socket.next())
                .await
                .expect("an answer");
            match message {
                Some(Ok(tungstenite::Message::Text(text))) => {
                    self.seen.push(text.to_string());
                    return Ok(serde_json::from_str(&text).unwrap());
                }
                Some(Ok(tungstenite::Message::Close(frame))) => {
                    return Err(frame.map(|f| u16::from(f.code)))
                }
                Some(Ok(_)) => {}
                _ => return Err(None),
            }
        }
    }

    async fn send(&mut self, value: Value) {
        self.socket
            .send(tungstenite::Message::Text(value.to_string().into()))
            .await
            .unwrap();
    }

    async fn call(&mut self, mut command: Value) -> Value {
        self.next += 1;
        command["id"] = json!(self.next);
        self.send(command).await;
        let answer = self.message().await.expect("answer");
        assert_eq!(answer["id"], json!(self.next), "{answer}");
        answer
    }
}

async fn open(h: &Harness, user: &str) -> (Value, Browser) {
    let (status, start) = h.start(user, json!({ "connectionId": "sftp" })).await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "{start}");
    assert_eq!(
        (start["protocol"].clone(), start["secure"].clone()),
        (json!("sftp"), json!(true))
    );
    let mut request = format!("ws://{}{}", h.address, start["websocket"].as_str().unwrap())
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("x-webos-user", user.parse().unwrap());
    let (socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    (
        start,
        Browser {
            socket,
            seen: Vec::new(),
            next: 0,
        },
    )
}

#[tokio::test]
async fn browses_and_transfers_over_sftp_after_trusting_the_host_key() {
    let fs = Fs::default();
    fs.folders
        .lock()
        .unwrap()
        .extend(["/".to_owned(), "/home".to_owned(), HOME.to_owned()]);
    fs.files
        .lock()
        .unwrap()
        .insert(format!("{HOME}/notes.txt"), b"from the server".to_vec());
    let (target, host_key) = sftp_server(fs.clone()).await;
    let h = Harness::new().await;
    h.add_sftp_connection(ADA, target).await;

    let (start, mut browser) = open(&h, ADA).await;
    // A first-seen host key is shown, as in an SSH session.
    let prompt = browser.message().await.unwrap();
    assert_eq!(prompt["type"], "trust");
    let fingerprint = host_key
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();
    assert_eq!(prompt["fingerprint"], fingerprint);
    browser
        .send(json!({ "type": "trust", "accept": true }))
        .await;
    let ready = browser.message().await.unwrap();
    assert_eq!(
        (ready["type"].clone(), ready["start"].clone()),
        (json!("ready"), json!(HOME))
    );

    let listed = browser.call(json!({ "op": "list", "path": HOME })).await;
    assert_eq!(listed["entries"][0]["name"], "notes.txt", "{listed}");
    assert_eq!(listed["entries"][0]["size"], 15);

    let url = |action: &str, path: &str| {
        format!(
            "http://{}/api/ftp/{}/{action}?path={path}",
            h.address,
            start["sessionId"].as_str().unwrap()
        )
    };
    let response = h
        .http
        .put(url("upload", "/home/tester/up.bin"))
        .header("x-webos-user", ADA)
        .body(vec![7u8; 100_000])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(
        fs.files.lock().unwrap()[&format!("{HOME}/up.bin")].len(),
        100_000
    );
    let response = h
        .http
        .get(url("download", "/home/tester/notes.txt"))
        .header("x-webos-user", ADA)
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["content-length"], "15");
    assert_eq!(response.text().await.unwrap(), "from the server");
    let foreign = h
        .http
        .get(url("download", "/home/tester/notes.txt"))
        .header("x-webos-user", BOB)
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), reqwest::StatusCode::NOT_FOUND);

    for command in [
        json!({ "op": "mkdir", "path": "/home/tester/docs" }),
        json!({ "op": "rename", "from": "/home/tester/up.bin", "to": "/home/tester/docs/up.bin" }),
        json!({ "op": "delete", "path": "/home/tester/docs/up.bin", "folder": false }),
        json!({ "op": "delete", "path": "/home/tester/docs", "folder": true }),
    ] {
        let answer = browser.call(command.clone()).await;
        assert_eq!(answer["ok"], true, "{command} {answer}");
    }
    let missing = browser
        .call(json!({ "op": "list", "path": "/nowhere" }))
        .await;
    assert_eq!(missing["code"], "server_error", "{missing}");

    let everything = format!("{start}{}", browser.seen.join(""));
    assert!(!everything.contains(SFTP_PASSWORD));
    // The host key is trusted for SSH and SFTP alike.
    assert_eq!(
        h.state
            .store
            .for_user(ADA)
            .trusted(&target.ip().to_string(), target.port(), Protocol::Ssh)
            .unwrap(),
        Some(fingerprint)
    );

    // Revoked like any session.
    assert_eq!(h.state.sessions.end(None, Some(ADA)), 1);
    assert_eq!(browser.message().await, Err(Some(4403)));
}

#[tokio::test]
async fn a_refused_host_key_ends_the_session_before_signing_in() {
    let fs = Fs::default();
    fs.folders.lock().unwrap().insert(HOME.to_owned());
    let (target, _) = sftp_server(fs).await;
    let h = Harness::new().await;
    h.add_sftp_connection(ADA, target).await;
    let (_, mut browser) = open(&h, ADA).await;
    assert_eq!(browser.message().await.unwrap()["type"], "trust");
    browser
        .send(json!({ "type": "trust", "accept": false }))
        .await;
    assert_eq!(browser.message().await, Err(Some(4409)));
}
