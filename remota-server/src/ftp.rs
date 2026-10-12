//! FTP and FTPS for the file browser (SidiOS US8, FR-019).
//!
//! - The control connection goes to the address the policy already checked, and every data
//!   connection goes to that same address: the port from `PASV`/`EPSV` is used, the address the
//!   server names is ignored (no FTP bounce, no redirect to another host).
//! - FTPS is explicit (`AUTH TLS`) on any port and implicit on port 990. Certificates are trusted
//!   like RDP certificates: the TLS handshake fails unless the certificate's fingerprint is the
//!   trusted one, so the password is never sent to a changed certificate. Data connections are
//!   checked against the same fingerprint.
//! - Only passive mode is used; Remota never listens for a data connection.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde::Serialize;
use suppaftp::{
    list::File,
    tokio::{AsyncRustlsConnector, AsyncRustlsStream, ImplAsyncFtpStream, TransferStream},
    types::FileType,
    FtpError, Mode, Status,
};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::rdp_inject::fingerprint;

/// FTPS on this port is implicit (TLS before the greeting); on every other port it is explicit.
pub const IMPLICIT_PORT: u16 = 990;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest path Remota sends to a server.
pub const MAX_PATH: usize = 1024;

pub type Stream = ImplAsyncFtpStream<AsyncRustlsStream>;
pub type Transfer = TransferStream<AsyncRustlsStream>;

/// Where a session connects: the pinned address and the name the user gave (for TLS SNI).
#[derive(Clone, Debug)]
pub struct Target {
    pub address: SocketAddr,
    pub host: String,
    pub secure: bool,
}

impl Target {
    pub fn port(&self) -> u16 {
        self.address.port()
    }

    fn implicit(&self) -> bool {
        self.secure && self.address.port() == IMPLICIT_PORT
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FtpFail {
    /// The server presented another certificate than the trusted one.
    CertificateChanged {
        presented: String,
    },
    /// The server does not offer TLS (FTPS) or the handshake failed.
    TlsFailed,
    /// The server refused the stored credential.
    Refused,
    Unreachable,
    /// A path Remota will not send: empty, too long, or with a line break or NUL.
    BadPath,
    /// The server refused or failed a command; the reply is kept short for the user.
    Server(String),
    /// The control connection is gone.
    Closed,
}

impl FtpFail {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CertificateChanged { .. } => "certificate_changed",
            Self::TlsFailed => "tls_failed",
            Self::Refused => "target_refused",
            Self::Unreachable => "target_unreachable",
            Self::BadPath => "invalid_path",
            Self::Server(_) => "server_error",
            Self::Closed => "connection_closed",
        }
    }
}

/// The server's reply as the user sees it: at most 200 characters, one line.
fn server_message(error: &FtpError) -> FtpFail {
    match error {
        FtpError::UnexpectedResponse(response) => {
            let body = String::from_utf8_lossy(&response.body);
            let line: String = body
                .lines()
                .next()
                .unwrap_or_default()
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            FtpFail::Server(line)
        }
        FtpError::ConnectionError(_) => FtpFail::Closed,
        _ => FtpFail::Server(String::new()),
    }
}

/// Accepts a certificate only when its fingerprint is the expected one (or records it when no
/// fingerprint is expected yet, for the user's trust decision).
#[derive(Debug)]
struct Pinned {
    provider: Arc<rustls::crypto::CryptoProvider>,
    expected: Option<String>,
    seen: Mutex<Option<String>>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = fingerprint(end_entity.as_ref());
        let matches = self
            .expected
            .as_deref()
            .is_none_or(|expected| expected == presented);
        *self.seen.lock().expect("certificate") = Some(presented);
        if matches {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate changed".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn connector(expected: Option<&str>) -> (AsyncRustlsConnector, Arc<Pinned>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let pinned = Arc::new(Pinned {
        provider: provider.clone(),
        expected: expected.map(str::to_owned),
        seen: Mutex::new(None),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(pinned.clone())
        .with_no_client_auth();
    let connector = suppaftp::tokio_rustls::TlsConnector::from(Arc::new(config));
    (AsyncRustlsConnector::from(connector), pinned)
}

/// The TLS server name: the host the user gave when it is one, else a fixed name (the certificate
/// is checked by fingerprint, not by name).
fn tls_name(host: &str) -> String {
    if ServerName::try_from(host.to_owned()).is_ok() {
        host.to_owned()
    } else {
        "remota-target".to_owned()
    }
}

/// Opens the control connection (TLS too for FTPS) and reads the greeting; no credential yet.
async fn open(target: &Target, expected: Option<&str>) -> Result<(Stream, Arc<Pinned>), FtpFail> {
    let (tls, pinned) = connector(expected);
    let tls_failed = |pinned: &Pinned| {
        let seen = pinned.seen.lock().expect("certificate").clone();
        match (seen, expected) {
            (Some(presented), Some(expected)) if presented != expected => {
                FtpFail::CertificateChanged { presented }
            }
            _ => FtpFail::TlsFailed,
        }
    };
    let name = tls_name(&target.host);
    let stream = if target.implicit() {
        let connected = tokio::time::timeout(
            CONNECT_TIMEOUT,
            Stream::connect_secure_implicit(target.address, tls, &name),
        )
        .await
        .map_err(|_| FtpFail::Unreachable)?;
        match connected {
            Ok(stream) => stream,
            Err(FtpError::ConnectionError(_)) => return Err(FtpFail::Unreachable),
            Err(_) => return Err(tls_failed(&pinned)),
        }
    } else {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target.address))
            .await
            .map_err(|_| FtpFail::Unreachable)?
            .map_err(|_| FtpFail::Unreachable)?;
        let plain = tokio::time::timeout(CONNECT_TIMEOUT, Stream::connect_with_stream(tcp))
            .await
            .map_err(|_| FtpFail::Unreachable)?
            .map_err(|_| FtpFail::Unreachable)?;
        if target.secure {
            tokio::time::timeout(CONNECT_TIMEOUT, plain.into_secure(tls, &name))
                .await
                .map_err(|_| FtpFail::TlsFailed)?
                .map_err(|_| tls_failed(&pinned))?
        } else {
            plain
        }
    };
    // Data connections go to the checked address only; the server's address is ignored.
    let address = target.address;
    let mut stream = stream.passive_stream_builder(move |offered: SocketAddr| {
        let pinned = SocketAddr::new(address.ip(), offered.port());
        Box::pin(async move {
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(pinned))
                .await
                .map_err(|_| {
                    FtpError::ConnectionError(std::io::Error::from(std::io::ErrorKind::TimedOut))
                })?
                .map_err(FtpError::ConnectionError)
        })
    });
    stream.set_mode(if address.is_ipv6() {
        Mode::ExtendedPassive
    } else {
        Mode::Passive
    });
    Ok((stream, pinned))
}

/// The certificate an FTPS server presents, for the user's trust decision. No credential is sent.
pub async fn probe(target: &Target) -> Result<String, FtpFail> {
    let (mut stream, pinned) = open(target, None).await?;
    let _ = stream.quit().await;
    let seen = pinned.seen.lock().expect("certificate").clone();
    seen.ok_or(FtpFail::TlsFailed)
}

/// One listed entry; no owner, group, or permissions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    /// Milliseconds since the epoch, when the server gave a date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<u64>,
}

impl From<&File> for Entry {
    fn from(file: &File) -> Self {
        let kind = if file.is_directory() {
            "dir"
        } else if file.is_symlink() {
            "link"
        } else {
            "file"
        };
        let modified = file
            .modified()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|since| since.as_millis() as u64)
            .filter(|millis| *millis > 0);
        Self {
            name: file.name().to_owned(),
            kind,
            size: file.size() as u64,
            modified,
        }
    }
}

/// Parses `MLSD` or `LIST` lines; lines that are not entries ("total 12", ".", "..") are skipped.
pub fn parse_listing(lines: &[String], machine: bool) -> Vec<Entry> {
    let mut entries: Vec<Entry> = lines
        .iter()
        .filter_map(|line| {
            let line = line.trim_end_matches(['\r', '\n']);
            if machine {
                // MLSD's "type=cdir" and "type=pdir" are the folder itself and its parent.
                let facts = line
                    .split(' ')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if facts.contains("type=cdir;") || facts.contains("type=pdir;") {
                    return None;
                }
                suppaftp::list::ListParser::parse_mlsd(line).ok()
            } else {
                suppaftp::list::ListParser::parse_posix(line)
                    .or_else(|_| suppaftp::list::ListParser::parse_dos(line))
                    .ok()
            }
        })
        .map(|file| Entry::from(&file))
        .filter(|entry| !matches!(entry.name.as_str(), "" | "." | ".."))
        .collect();
    entries.sort_by(|a, b| {
        (a.kind != "dir", a.name.to_lowercase()).cmp(&(b.kind != "dir", b.name.to_lowercase()))
    });
    entries
}

/// A path Remota sends to the server: never a line break or NUL (no command injection).
pub fn check_path(path: &str) -> Result<&str, FtpFail> {
    if path.is_empty()
        || path.len() > MAX_PATH
        || path.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
    {
        Err(FtpFail::BadPath)
    } else {
        Ok(path)
    }
}

pub struct Login {
    pub username: String,
    pub password: Zeroizing<String>,
}

/// A signed-in FTP session.
pub struct Client {
    stream: Stream,
    /// The server supports `MLSD` (machine-readable listings).
    machine_listing: bool,
    pub start: String,
}

impl Client {
    /// Connects, checks the certificate (FTPS), and signs in with the stored credential.
    pub async fn connect(
        target: &Target,
        login: &Login,
        trusted: Option<&str>,
    ) -> Result<Self, FtpFail> {
        tokio::time::timeout(SIGN_IN_TIMEOUT, Self::sign_in(target, login, trusted))
            .await
            .map_err(|_| FtpFail::Unreachable)?
    }

    async fn sign_in(
        target: &Target,
        login: &Login,
        trusted: Option<&str>,
    ) -> Result<Self, FtpFail> {
        let (mut stream, _) = open(target, trusted).await?;
        match stream
            .login(login.username.as_str(), login.password.as_str())
            .await
        {
            Ok(()) => {}
            Err(FtpError::UnexpectedResponse(response))
                if response.status == Status::NotLoggedIn =>
            {
                return Err(FtpFail::Refused)
            }
            Err(FtpError::ConnectionError(_)) => return Err(FtpFail::Unreachable),
            Err(_) => return Err(FtpFail::Refused),
        }
        stream
            .transfer_type(FileType::Binary)
            .await
            .map_err(|e| server_message(&e))?;
        let machine_listing = match stream.feat().await {
            Ok(features) => features
                .keys()
                .any(|name| name.eq_ignore_ascii_case("MLST")),
            Err(_) => false,
        };
        let start = stream.pwd().await.unwrap_or_else(|_| "/".to_owned());
        Ok(Self {
            stream,
            machine_listing,
            start,
        })
    }

    /// Lists a folder; answers its full path as the server names it.
    pub async fn list(&mut self, path: &str) -> Result<(String, Vec<Entry>), FtpFail> {
        let path = check_path(path)?;
        self.stream
            .cwd(path)
            .await
            .map_err(|e| server_message(&e))?;
        let here = self.stream.pwd().await.unwrap_or_else(|_| path.to_owned());
        let lines = if self.machine_listing {
            self.stream.mlsd(None).await
        } else {
            self.stream.list(None).await
        }
        .map_err(|e| server_message(&e))?;
        Ok((here, parse_listing(&lines, self.machine_listing)))
    }

    pub async fn mkdir(&mut self, path: &str) -> Result<(), FtpFail> {
        let path = check_path(path)?;
        self.stream
            .mkdir(path)
            .await
            .map_err(|e| server_message(&e))
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<(), FtpFail> {
        let (from, to) = (check_path(from)?, check_path(to)?);
        self.stream
            .rename(from, to)
            .await
            .map_err(|e| server_message(&e))
    }

    pub async fn delete(&mut self, path: &str, folder: bool) -> Result<(), FtpFail> {
        let path = check_path(path)?;
        if folder {
            self.stream.rmdir(path).await
        } else {
            self.stream.rm(path).await
        }
        .map_err(|e| server_message(&e))
    }

    /// The file's size when the server tells it (for the download's length).
    pub async fn size(&mut self, path: &str) -> Option<u64> {
        let path = check_path(path).ok()?;
        self.stream.size(path).await.ok().map(|size| size as u64)
    }

    pub async fn download(&mut self, path: &str) -> Result<Transfer, FtpFail> {
        let path = check_path(path)?;
        self.stream
            .retr_as_stream(path)
            .await
            .map_err(|e| server_message(&e))
    }

    pub async fn upload(&mut self, path: &str) -> Result<Transfer, FtpFail> {
        let path = check_path(path)?;
        self.stream
            .put_with_stream(path)
            .await
            .map_err(|e| server_message(&e))
    }

    /// Keeps the control connection open while the user browses.
    pub async fn keep_alive(&mut self) -> Result<(), FtpFail> {
        self.stream.noop().await.map_err(|e| server_message(&e))
    }

    pub async fn quit(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.stream.quit()).await;
    }
}

/// Ends a transfer and reads the server's completion reply.
pub async fn finish(transfer: Transfer) -> Result<(), FtpFail> {
    transfer.finish().await.map_err(|e| server_message(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_paths_that_could_inject_commands() {
        assert_eq!(check_path("/srv/a b.txt"), Ok("/srv/a b.txt"));
        for bad in ["", "a\r\nDELE x", "a\nb", "a\0b"] {
            assert_eq!(check_path(bad), Err(FtpFail::BadPath), "{bad:?}");
        }
        assert_eq!(check_path(&"a".repeat(MAX_PATH + 1)), Err(FtpFail::BadPath));
    }

    #[test]
    fn parses_unix_dos_and_machine_listings_folders_first() {
        let unix = [
            "total 8",
            "-rw-r--r--    1 1000     1000           12 Oct 12 10:00 notes.txt",
            "drwxr-xr-x    2 1000     1000         4096 Oct 12 10:00 Backups",
            "drwxr-xr-x    2 1000     1000         4096 Oct 12 10:00 .",
        ]
        .map(String::from);
        let entries = parse_listing(&unix, false);
        let names: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert_eq!(names, [("Backups", "dir"), ("notes.txt", "file")]);
        assert_eq!(entries[1].size, 12);

        let dos = [
            "10-12-26  10:00AM       <DIR>          logs",
            "10-12-26  10:00AM                 5 a.cfg",
        ]
        .map(String::from);
        let names: Vec<_> = parse_listing(&dos, false)
            .into_iter()
            .map(|e| (e.name, e.kind))
            .collect();
        assert_eq!(
            names,
            [("logs".to_owned(), "dir"), ("a.cfg".to_owned(), "file")]
        );

        let machine = [
            "type=cdir;modify=20261012100000; /srv",
            "type=pdir;modify=20261012100000; /",
            "type=file;size=3;modify=20261012100000; b.bin",
        ]
        .map(String::from);
        let entries = parse_listing(&machine, true);
        assert_eq!(entries.len(), 1);
        assert_eq!((entries[0].name.as_str(), entries[0].size), ("b.bin", 3));
        assert!(entries[0].modified.is_some());
    }

    #[test]
    fn implicit_tls_only_on_port_990() {
        let target = |port, secure| Target {
            address: SocketAddr::from(([127, 0, 0, 1], port)),
            host: "files".into(),
            secure,
        };
        assert!(target(990, true).implicit());
        assert!(!target(21, true).implicit());
        assert!(!target(990, false).implicit());
        assert_eq!(tls_name("files.example"), "files.example");
        assert_eq!(tls_name("not a name"), "remota-target");
    }
}
