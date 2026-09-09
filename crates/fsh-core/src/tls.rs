use std::{
    collections::{BTreeSet, HashMap},
    fmt, fs,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_parser::prelude::parse_x509_certificate;

use crate::{ALPN, Error, Result};

/// A SHA-256 digest of the DER-encoded SubjectPublicKeyInfo in a server
/// certificate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SpkiPin(pub [u8; 32]);

impl SpkiPin {
    pub fn from_certificate(certificate_der: &[u8]) -> Result<Self> {
        let (_, certificate) =
            parse_x509_certificate(certificate_der).map_err(|_| Error::InvalidCertificate)?;
        Ok(Self(
            Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into(),
        ))
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let encoded = text
            .strip_prefix("FSH-SHA256:")
            .or_else(|| text.strip_prefix("sha256/"))
            .ok_or_else(|| Error::Protocol("SPKI pin must use FSH-SHA256: prefix".into()))?;
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded.as_bytes())
            })
            .map_err(|_| Error::Protocol("invalid base64 SPKI pin".into()))?;
        let pin: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Protocol("SPKI pin must contain 32 bytes".into()))?;
        Ok(Self(pin))
    }

    pub fn encoded(self) -> String {
        format!(
            "FSH-SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(self.0)
        )
    }
}

impl fmt::Display for SpkiPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded())
    }
}

/// An on-disk TOFU pin database. The file is intentionally much simpler than
/// `known_hosts`: FSH has one identity model and does not parse host-key
/// algorithms or wildcard patterns.
#[derive(Clone, Debug)]
pub struct KnownHosts {
    path: PathBuf,
    pins: HashMap<String, BTreeSet<SpkiPin>>,
}

impl KnownHosts {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut pins: HashMap<String, BTreeSet<SpkiPin>> = HashMap::new();
        match fs::read_to_string(&path) {
            Ok(contents) => {
                for (line_number, line) in contents.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let mut fields = line.split_whitespace();
                    let host = fields.next().ok_or_else(|| {
                        Error::Protocol(format!("invalid known-hosts line {}", line_number + 1))
                    })?;
                    let pin = fields.next().ok_or_else(|| {
                        Error::Protocol(format!("invalid known-hosts line {}", line_number + 1))
                    })?;
                    if fields.next().is_some() {
                        return Err(Error::Protocol(format!(
                            "too many fields on known-hosts line {}",
                            line_number + 1
                        )));
                    }
                    pins.entry(host.to_owned())
                        .or_default()
                        .insert(SpkiPin::from_text(pin)?);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self { path, pins })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, host: &str, port: u16) -> Option<SpkiPin> {
        self.pins
            .get(&host_key(host, port))
            .and_then(|pins| pins.iter().next().copied())
    }

    pub fn pins(&self, host: &str, port: u16) -> Option<&BTreeSet<SpkiPin>> {
        self.pins.get(&host_key(host, port))
    }

    pub fn insert(&mut self, host: &str, port: u16, pin: SpkiPin) -> Result<()> {
        self.pins
            .entry(host_key(host, port))
            .or_default()
            .insert(pin);
        self.save()
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut contents = String::new();
        let mut entries: Vec<_> = self.pins.iter().collect();
        entries.sort_by_key(|(left, _)| *left);
        for (host, pins) in entries {
            for pin in pins {
                contents.push_str(host);
                contents.push(' ');
                contents.push_str(&pin.encoded());
                contents.push('\n');
            }
        }
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(temporary, &self.path)?;
        Ok(())
    }
}

fn host_key(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// Server certificate and private key used by the QUIC endpoint.
#[derive(Clone, Debug)]
pub struct ServerIdentity {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    pin: SpkiPin,
}

impl ServerIdentity {
    pub fn load(certificate: impl AsRef<Path>, private_key: impl AsRef<Path>) -> Result<Self> {
        let certificate_der = read_certificate(certificate.as_ref())?;
        let private_key_der = read_private_key(private_key.as_ref())?;
        let pin = SpkiPin::from_certificate(&certificate_der)?;
        Ok(Self {
            certificate_der,
            private_key_der,
            pin,
        })
    }

    pub fn generate(certificate: impl AsRef<Path>, private_key: impl AsRef<Path>) -> Result<Self> {
        let generated = rcgen::generate_simple_self_signed(vec!["fsh.local".to_owned()])
            .map_err(|e| Error::Protocol(format!("cannot generate server certificate: {e}")))?;
        let certificate_der = generated.cert.der().to_vec();
        let private_key_der = generated.signing_key.serialize_der();
        if let Some(parent) = certificate.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = private_key.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(certificate.as_ref(), &certificate_der)?;
        fs::write(private_key.as_ref(), &private_key_der)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(private_key.as_ref(), fs::Permissions::from_mode(0o600))?;
        }
        let pin = SpkiPin::from_certificate(&certificate_der)?;
        Ok(Self {
            certificate_der,
            private_key_der,
            pin,
        })
    }

    pub fn load_or_generate(
        certificate: impl AsRef<Path>,
        private_key: impl AsRef<Path>,
    ) -> Result<Self> {
        match (certificate.as_ref().exists(), private_key.as_ref().exists()) {
            (true, true) => Self::load(certificate, private_key),
            (false, false) => Self::generate(certificate, private_key),
            _ => Err(Error::Protocol(
                "server certificate and private key must either both exist or both be absent"
                    .into(),
            )),
        }
    }

    pub fn pin(&self) -> SpkiPin {
        self.pin
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    fn private_key(&self) -> Result<PrivateKeyDer<'static>> {
        PrivateKeyDer::try_from(self.private_key_der.clone()).map_err(|_| Error::InvalidCertificate)
    }
}

/// A connected client endpoint plus the certificate pin observed during its
/// handshake. The observed pin is populated even for a first-use connection;
/// callers must explicitly persist/accept it before starting authentication.
#[derive(Clone)]
pub struct ClientTransport {
    pub endpoint: quinn::Endpoint,
    observed: Arc<Mutex<Option<SpkiPin>>>,
}

impl ClientTransport {
    pub fn observed_pin(&self) -> Option<SpkiPin> {
        self.observed.lock().ok().and_then(|pin| *pin)
    }
}

/// A server endpoint and the identity it presents.
pub struct ServerTransport {
    pub endpoint: quinn::Endpoint,
    pub identity: ServerIdentity,
}

pub fn make_client_endpoint(
    bind: SocketAddr,
    expected_pin: Option<SpkiPin>,
) -> Result<ClientTransport> {
    let observed = Arc::new(Mutex::new(None));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedVerifier {
        expected: expected_pin,
        observed: Arc::clone(&observed),
        provider: Arc::clone(&provider),
    };
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.resumption = rustls::client::Resumption::disabled();

    let quic_crypto = quinn_proto::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| Error::Protocol(format!("cannot build QUIC client TLS config: {e}")))?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let socket = UdpSocket::bind(bind)?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.supported_versions(vec![1]);
    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::Protocol("no compatible QUIC runtime found".into()))?;
    let mut endpoint = quinn::Endpoint::new(endpoint_config, None, socket, runtime)?;
    endpoint.set_default_client_config(client_config);
    Ok(ClientTransport { endpoint, observed })
}

pub fn make_server_endpoint(bind: SocketAddr, identity: ServerIdentity) -> Result<ServerTransport> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(identity.certificate_der.clone())],
            identity.private_key()?,
        )?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.send_tls13_tickets = 0;
    crypto.max_tls13_tickets = 0;

    let quic_crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|e| Error::Protocol(format!("cannot build QUIC server TLS config: {e}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| Error::Protocol("cannot configure QUIC transport".into()))?;
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(64))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(0))
        .stream_receive_window(quinn::VarInt::from_u32(2 * 1024 * 1024))
        .receive_window(quinn::VarInt::from_u32(16 * 1024 * 1024))
        .max_idle_timeout(Some(
            Duration::from_secs(300)
                .try_into()
                .map_err(|_| Error::Protocol("invalid QUIC idle timeout".into()))?,
        ))
        .keep_alive_interval(Some(Duration::from_secs(15)));
    let socket = UdpSocket::bind(bind)?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.supported_versions(vec![1]);
    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::Protocol("no compatible QUIC runtime found".into()))?;
    let endpoint = quinn::Endpoint::new(endpoint_config, Some(server_config), socket, runtime)?;
    Ok(ServerTransport { endpoint, identity })
}

#[derive(Debug)]
struct PinnedVerifier {
    expected: Option<SpkiPin>,
    observed: Arc<Mutex<Option<SpkiPin>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let pin = SpkiPin::from_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("malformed server certificate".into()))?;
        if let Some(expected) = self.expected
            && expected != pin
        {
            return Err(rustls::Error::General("server SPKI pin mismatch".into()));
        }
        if let Ok(mut observed) = self.observed.lock() {
            *observed = Some(pin);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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

fn read_certificate(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(b"-----BEGIN") {
        let mut reader = &bytes[..];
        rustls_pemfile::certs(&mut reader)
            .next()
            .transpose()
            .map_err(Error::Io)?
            .map(|certificate| certificate.to_vec())
            .ok_or(Error::InvalidCertificate)
    } else {
        Ok(bytes)
    }
}

fn read_private_key(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(b"-----BEGIN") {
        let mut reader = &bytes[..];
        let key = rustls_pemfile::private_key(&mut reader)
            .map_err(Error::Io)?
            .ok_or(Error::InvalidCertificate)?;
        Ok(key.secret_der().to_vec())
    } else {
        Ok(bytes)
    }
}
