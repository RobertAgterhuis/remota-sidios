//! RDP credential injection (SidiOS spike T006, research R2): the browser never receives a target
//! credential.
//!
//! The browser's IronRDP client speaks RDCleanPath over the session WebSocket. The gateway
//!
//! 1. forwards the browser's X.224 connection request to the pinned target, upgrades that leg to
//!    TLS (remembering the target certificate, which must not change), and performs NLA/CredSSP
//!    toward the target as a client with the real credential from the SidiOS vault;
//! 2. answers the browser with the target's X.224 confirmation and the *gateway's* certificate, and
//!    performs CredSSP toward the browser as a server, accepting only the per-session throwaway login
//!    that the browser received with its session;
//! 3. relays the rest of the RDP connection, byte for byte, between the two legs.
//!
//! What reaches the browser: the X.224 confirmation, the gateway certificate, the CredSSP exchange
//! with the gateway (throwaway login only), and the target's RDP traffic after logon.

use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use ironrdp_acceptor::credssp::CredsspSequence as ServerCredssp;
use ironrdp_async::{FramedRead, FramedWrite};
use ironrdp_connector::{
    credssp::CredsspSequence as ClientCredssp,
    sspi::{credssp::EarlyUserAuthResult, AuthIdentity, Username},
    Credentials, ServerName, Written,
};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::nego::{ConnectionConfirm, SecurityProtocol};
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPath, RDCleanPathPdu};
use ironrdp_tokio::TokioFramed;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName as TlsName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// An RDCleanPath request is a few hundred bytes; anything far larger is refused.
const MAX_CLEANPATH_REQUEST: usize = 16 * 1024;

/// Why an injected session did not start. None of these carries a credential.
#[derive(Debug, PartialEq, Eq)]
pub enum InjectError {
    /// The browser did not send a valid RDCleanPath request.
    BadRequest,
    /// The target could not be reached or broke the connection sequence.
    TargetUnreachable,
    /// The target does not offer NLA (and the policy does not allow RDP without it).
    NlaNotOffered,
    /// The target refused the stored credential.
    TargetRefused,
    /// The target presented a certificate other than the trusted one.
    CertificateChanged { presented: String },
    /// The browser's CredSSP failed: wrong, reused, or missing throwaway login.
    ClientRefused,
    /// The browser went away or the handshake timed out.
    ClientGone,
}

impl fmt::Display for InjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The real login for the target, from the SidiOS vault (via a consumed ticket).
pub struct TargetLogin {
    pub username: String,
    pub domain: Option<String>,
    pub password: Zeroizing<String>,
}

/// A per-session login the browser may know: it opens nothing but this one session's gateway leg.
#[derive(Clone)]
pub struct ThrowawayLogin {
    pub username: String,
    pub password: Zeroizing<String>,
}

impl ThrowawayLogin {
    pub fn generate() -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let secret = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        Self {
            username: format!("remota-{}", &id[..12]),
            password: Zeroizing::new(secret),
        }
    }
}

/// The gateway's own certificate for the browser leg; the browser's CredSSP binds to its key.
pub struct GatewayCertificate {
    pub der: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl GatewayCertificate {
    pub fn generate() -> Result<Self, String> {
        let certified = rcgen::generate_simple_self_signed(vec!["remota-gateway".to_owned()])
            .map_err(|e| e.to_string())?;
        let der = certified.cert.der().to_vec();
        let public_key = public_key_of(&der).ok_or("unreadable gateway certificate")?;
        Ok(Self { der, public_key })
    }
}

/// The subjectPublicKey bits of an X.509 certificate: what CredSSP binds to (as IronRDP's web
/// client extracts it).
pub fn public_key_of(certificate: &[u8]) -> Option<Vec<u8>> {
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(certificate).ok()?;
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .map(<[u8]>::to_vec)
}

/// `SHA256:<base64>` of the certificate, as stored in a trust record.
pub fn fingerprint(certificate: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(certificate))
    )
}

/// Accepts any certificate during the handshake; the caller compares the fingerprint to the
/// trust record before any credential is sent.
#[derive(Debug)]
struct RecordOnly(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for RecordOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &TlsName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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
            &self.0.signature_verification_algorithms,
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
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_connector() -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RecordOnly(provider)))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Reads one TPKT-framed X.224 PDU.
async fn read_tpkt(stream: &mut TcpStream) -> Result<Vec<u8>, InjectError> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| InjectError::TargetUnreachable)?;
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if header[0] != 3 || !(11..=1024).contains(&length) {
        return Err(InjectError::TargetUnreachable);
    }
    let mut pdu = header.to_vec();
    pdu.resize(length, 0);
    stream
        .read_exact(&mut pdu[4..])
        .await
        .map_err(|_| InjectError::TargetUnreachable)?;
    Ok(pdu)
}

fn selected_protocol(confirm: &[u8]) -> Result<SecurityProtocol, InjectError> {
    let decoded: ironrdp_pdu::x224::X224<ConnectionConfirm> =
        ironrdp_core::decode(confirm).map_err(|_| InjectError::TargetUnreachable)?;
    match decoded.0 {
        ConnectionConfirm::Response { protocol, .. } => Ok(protocol),
        ConnectionConfirm::Failure { .. } => Err(InjectError::NlaNotOffered),
    }
}

/// The established target leg: TLS with NLA done, ready for the relay.
pub struct TargetLeg {
    pub framed: TokioFramed<TlsStream<TcpStream>>,
    pub x224_confirm: Vec<u8>,
    pub protocol: SecurityProtocol,
    pub fingerprint: String,
}

/// Connects to the target, checks its certificate against `trusted` (if any), and signs in with
/// the real credential.
pub async fn open_target(
    address: SocketAddr,
    server_name: &str,
    x224_request: &[u8],
    login: &TargetLogin,
    trusted: Option<&str>,
) -> Result<TargetLeg, InjectError> {
    let mut tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| InjectError::TargetUnreachable)?
        .map_err(|_| InjectError::TargetUnreachable)?;
    tcp.write_all(x224_request)
        .await
        .map_err(|_| InjectError::TargetUnreachable)?;
    let x224_confirm = read_tpkt(&mut tcp).await?;
    let protocol = selected_protocol(&x224_confirm)?;
    if !protocol.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX) {
        return Err(InjectError::NlaNotOffered);
    }

    let tls_name = TlsName::try_from("remota-target").expect("static name");
    let tls = tls_connector()
        .connect(tls_name, tcp)
        .await
        .map_err(|_| InjectError::TargetUnreachable)?;
    let certificate = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|cert| cert.as_ref().to_vec())
        .ok_or(InjectError::TargetUnreachable)?;
    let presented = fingerprint(&certificate);
    if trusted.is_some_and(|trusted| trusted != presented) {
        return Err(InjectError::CertificateChanged { presented });
    }
    let public_key = public_key_of(&certificate).ok_or(InjectError::TargetUnreachable)?;

    let mut framed = TokioFramed::new(tls);
    target_credssp(&mut framed, login, server_name, protocol, public_key).await?;
    Ok(TargetLeg {
        framed,
        x224_confirm,
        protocol,
        fingerprint: presented,
    })
}

async fn target_credssp<S>(
    framed: &mut ironrdp_async::Framed<S>,
    login: &TargetLogin,
    server_name: &str,
    protocol: SecurityProtocol,
    public_key: Vec<u8>,
) -> Result<(), InjectError>
where
    S: FramedRead + FramedWrite,
{
    let credentials = Credentials::UsernamePassword {
        username: login.username.clone(),
        password: login.password.to_string(),
    };
    let (mut sequence, first) = ClientCredssp::init(
        credentials,
        login.domain.as_deref(),
        protocol,
        ServerName::new(server_name),
        public_key,
        None,
    )
    .map_err(|_| InjectError::TargetRefused)?;
    let mut buf = WriteBuf::new();
    let mut request = Some(first);
    loop {
        if let Some(ts_request) = request.take() {
            let state = sequence
                .process_ts_request(ts_request)
                .resolve_to_result()
                .map_err(|_| InjectError::TargetRefused)?;
            buf.clear();
            let written = sequence
                .handle_process_result(state, &mut buf)
                .map_err(|_| InjectError::TargetRefused)?;
            if let Written::Size(size) = written {
                framed
                    .write_all(&buf.filled()[..size.get()])
                    .await
                    .map_err(|_| InjectError::TargetUnreachable)?;
            }
        }
        let Some(hint) = sequence.next_pdu_hint() else {
            return Ok(());
        };
        let pdu = tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.read_by_hint(hint))
            .await
            .map_err(|_| InjectError::TargetUnreachable)?
            .map_err(|_| InjectError::TargetRefused)?;
        // `None` is the early user authorization result (success); a denial is an error.
        request = sequence
            .decode_server_message(&pdu)
            .map_err(|_| InjectError::TargetRefused)?;
        if request.is_none() && sequence.next_pdu_hint().is_none() {
            return Ok(());
        }
    }
}

/// CredSSP toward the browser as a server: only the throwaway login is accepted.
async fn client_credssp<S>(
    framed: &mut ironrdp_async::Framed<S>,
    throwaway: &ThrowawayLogin,
    gateway: &GatewayCertificate,
    protocol: SecurityProtocol,
) -> Result<(), InjectError>
where
    S: FramedRead + FramedWrite,
{
    let identity = AuthIdentity {
        username: Username::new(&throwaway.username, None)
            .map_err(|_| InjectError::ClientRefused)?,
        password: throwaway.password.to_string().into(),
    };
    let mut sequence = ServerCredssp::init(
        &identity,
        ServerName::new("remota-client"),
        gateway.public_key.clone(),
        None,
    )
    .map_err(|_| InjectError::ClientRefused)?;
    let mut buf = WriteBuf::new();
    let refused = loop {
        let hint = match sequence.next_pdu_hint() {
            Ok(Some(hint)) => hint,
            Ok(None) => break false,
            Err(_) => break true,
        };
        let pdu = tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.read_by_hint(hint))
            .await
            .map_err(|_| InjectError::ClientGone)?
            .map_err(|_| InjectError::ClientGone)?;
        let request = sequence
            .decode_client_message(&pdu)
            .map_err(|_| InjectError::ClientRefused)?
            .ok_or(InjectError::ClientRefused)?;
        let result = sequence.process_ts_request(request).resolve_to_result();
        buf.clear();
        let written = sequence
            .handle_process_result(result, &mut buf)
            .map_err(|_| InjectError::ClientRefused)?;
        if let Written::Size(size) = written {
            framed
                .write_all(&buf.filled()[..size.get()])
                .await
                .map_err(|_| InjectError::ClientGone)?;
        }
    };
    if protocol.contains(SecurityProtocol::HYBRID_EX) {
        let mut result = Vec::new();
        let answer = if refused {
            EarlyUserAuthResult::AccessDenied
        } else {
            EarlyUserAuthResult::Success
        };
        answer
            .to_buffer(&mut result)
            .map_err(|_| InjectError::ClientGone)?;
        framed
            .write_all(&result)
            .await
            .map_err(|_| InjectError::ClientGone)?;
    }
    if refused {
        Err(InjectError::ClientRefused)
    } else {
        Ok(())
    }
}

/// Reads the browser's RDCleanPath request and answers its X.224 connection request PDU.
async fn read_cleanpath_request<C>(client: &mut C) -> Result<Vec<u8>, InjectError>
where
    C: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let total = loop {
        // An RDCleanPath PDU is a DER SEQUENCE; anything else is refused at once.
        if buffer.first().is_some_and(|byte| *byte != 0x30) {
            return Err(InjectError::BadRequest);
        }
        match RDCleanPathPdu::detect(&buffer) {
            DetectionResult::Detected { total_length, .. }
                if total_length <= MAX_CLEANPATH_REQUEST =>
            {
                if buffer.len() >= total_length {
                    break total_length;
                }
            }
            DetectionResult::NotEnoughBytes if buffer.len() < MAX_CLEANPATH_REQUEST => {}
            _ => return Err(InjectError::BadRequest),
        }
        let read = tokio::time::timeout(HANDSHAKE_TIMEOUT, client.read(&mut chunk))
            .await
            .map_err(|_| InjectError::ClientGone)?
            .map_err(|_| InjectError::ClientGone)?;
        if read == 0 {
            return Err(InjectError::ClientGone);
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    if buffer.len() != total {
        return Err(InjectError::BadRequest);
    }
    match RDCleanPathPdu::from_der(&buffer)
        .ok()
        .and_then(|pdu| pdu.into_enum().ok())
    {
        Some(RDCleanPath::Request {
            x224_connection_request,
            ..
        }) => Ok(x224_connection_request.as_bytes().to_vec()),
        _ => Err(InjectError::BadRequest),
    }
}

/// What the gateway needs for one injected session.
pub struct Injection<'a> {
    pub target: SocketAddr,
    pub server_name: &'a str,
    pub login: &'a TargetLogin,
    pub throwaway: &'a ThrowawayLogin,
    pub gateway: &'a GatewayCertificate,
    pub trusted_fingerprint: Option<&'a str>,
}

/// A started session: the certificate fingerprint to remember, and both legs ready to relay.
pub struct Established<C> {
    pub fingerprint: String,
    pub client: TokioFramed<C>,
    pub target: TokioFramed<TlsStream<TcpStream>>,
}

/// Runs both connection legs over `client` (the browser's byte stream, RDCleanPath first).
pub async fn establish<C>(mut client: C, plan: Injection<'_>) -> Result<Established<C>, InjectError>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    let x224_request = read_cleanpath_request(&mut client).await?;
    let leg = match open_target(
        plan.target,
        plan.server_name,
        &x224_request,
        plan.login,
        plan.trusted_fingerprint,
    )
    .await
    {
        Ok(leg) => leg,
        Err(error) => {
            if let Ok(der) = RDCleanPathPdu::new_general_error().to_der() {
                let _ = client.write_all(&der).await;
            }
            return Err(error);
        }
    };
    let response = RDCleanPathPdu::new_response(
        plan.target.to_string(),
        leg.x224_confirm.clone(),
        [plan.gateway.der.clone()],
    )
    .and_then(|pdu| pdu.to_der())
    .map_err(|_| InjectError::BadRequest)?;
    client
        .write_all(&response)
        .await
        .map_err(|_| InjectError::ClientGone)?;
    let mut framed = TokioFramed::new(client);
    client_credssp(&mut framed, plan.throwaway, plan.gateway, leg.protocol).await?;
    Ok(Established {
        fingerprint: leg.fingerprint,
        client: framed,
        target: leg.framed,
    })
}

/// Relays both legs until either side closes.
pub async fn relay<C>(established: Established<C>) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    let (mut client, client_leftover) = established.client.into_inner();
    let (mut target, target_leftover) = established.target.into_inner();
    if !client_leftover.is_empty() {
        target.write_all(&client_leftover).await?;
    }
    if !target_leftover.is_empty() {
        client.write_all(&target_leftover).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut target).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
