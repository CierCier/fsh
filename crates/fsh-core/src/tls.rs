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
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName, UnixTime,
};
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
#[derive(Debug)]
pub struct ServerIdentity {
    certificate_der: Vec<u8>,
    private_key: PrivateKeyDer<'static>,
    pin: SpkiPin,
}

impl Clone for ServerIdentity {
    fn clone(&self) -> Self {
        Self {
            certificate_der: self.certificate_der.clone(),
            private_key: self.private_key.clone_key(),
            pin: self.pin,
        }
    }
}

impl ServerIdentity {
    pub fn load(certificate: impl AsRef<Path>, private_key: impl AsRef<Path>) -> Result<Self> {
        let certificate_der = read_certificate(certificate.as_ref())?;
        let private_key = read_private_key(private_key.as_ref())?;
        let pin = SpkiPin::from_certificate(&certificate_der)?;
        Ok(Self {
            certificate_der,
            private_key,
            pin,
        })
    }

    pub fn generate(
        certificate: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let generated = rcgen::generate_simple_self_signed(vec!["fsh.local".to_owned()])
            .map_err(|e| Error::Protocol(format!("cannot generate server certificate: {e}")))?;
        let certificate_der = generated.cert.der().to_vec();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ));
        if let Some(parent) = certificate.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = private_key_path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(certificate.as_ref(), &certificate_der)?;
        fs::write(private_key_path.as_ref(), private_key.secret_der())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(private_key_path.as_ref(), fs::Permissions::from_mode(0o600))?;
        }
        let pin = SpkiPin::from_certificate(&certificate_der)?;
        Ok(Self {
            certificate_der,
            private_key,
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
        Ok(self.private_key.clone_key())
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
        pem_blocks(&bytes, "CERTIFICATE")?
            .into_iter()
            .next()
            .ok_or(Error::InvalidCertificate)
    } else {
        Ok(bytes)
    }
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(b"-----BEGIN") {
        read_private_key_pem(&bytes)
    } else {
        Ok(classify_der_private_key(&bytes))
    }
}

/// Read one DER TLV header, returning `(tag, header_len, content_len)`.
fn der_header(bytes: &[u8], offset: usize) -> Option<(u8, usize, usize)> {
    let tag = *bytes.get(offset)?;
    let first = *bytes.get(offset + 1)?;
    let (header_len, content_len) = if first & 0x80 == 0 {
        (2usize, first as usize)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8) | *bytes.get(offset + 2 + index)? as usize;
        }
        (2 + count, length)
    };
    Some((tag, header_len, content_len))
}

/// A bare DER private key carries no format label, so sniff the structure.
/// All three formats (RFC 5208 PKCS#8, RFC 8017 PKCS#1, RFC 5915 SEC1) open
/// with `SEQUENCE(version)`; PKCS#8 continues with an AlgorithmIdentifier
/// `SEQUENCE`, PKCS#1 with the modulus `INTEGER` (version 1 for multi-prime
/// keys), and SEC1 uses version 1 followed by an `OCTET STRING`. Anything
/// else falls back to PKCS#8, which is what rustls validates.
fn classify_der_private_key(bytes: &[u8]) -> PrivateKeyDer<'static> {
    let pkcs8 = || PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes.to_vec()));
    let classified = (|| {
        let (outer_tag, version_offset, outer_len) = der_header(bytes, 0)?;
        if outer_tag != 0x30 || bytes.len() < version_offset + outer_len {
            return None;
        }
        let (version_tag, version_header, version_len) = der_header(bytes, version_offset)?;
        if version_tag != 0x02 || version_len != 1 {
            return None;
        }
        let version = *bytes.get(version_offset + version_header)?;
        let (next_tag, ..) = der_header(bytes, version_offset + version_header + version_len)?;
        Some(match (version, next_tag) {
            (0x00, 0x30) => pkcs8(),
            (0x00, 0x02) | (0x01, 0x02) => {
                PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(bytes.to_vec()))
            }
            (0x01, 0x04) => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(bytes.to_vec())),
            _ => pkcs8(),
        })
    })();
    classified.unwrap_or_else(pkcs8)
}

fn read_private_key_pem(bytes: &[u8]) -> Result<PrivateKeyDer<'static>> {
    for tag in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
        if let Some(der) = pem_blocks(bytes, tag)?.into_iter().next() {
            return Ok(match tag {
                "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
                "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
                _ => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
            });
        }
    }
    Err(Error::InvalidCertificate)
}

/// Minimal RFC 7468 PEM block extraction for the given label. This replaces
/// the unmaintained `rustls-pemfile` crate; FSH reads certificates and the
/// PKCS#8, PKCS#1, and SEC1 private-key forms that OpenSSL and rcgen emit.
fn pem_blocks(bytes: &[u8], tag: &str) -> Result<Vec<Vec<u8>>> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidCertificate)?;
    let begin = format!("-----BEGIN {tag}-----");
    let end = format!("-----END {tag}-----");
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after_begin = &rest[start + begin.len()..];
        let Some(end_offset) = after_begin.find(&end) else {
            return Err(Error::InvalidCertificate);
        };
        let body: String = after_begin[..end_offset]
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        if body.is_empty() {
            return Err(Error::InvalidCertificate);
        }
        blocks.push(
            STANDARD
                .decode(body.as_bytes())
                .map_err(|_| Error::InvalidCertificate)?,
        );
        rest = &after_begin[end_offset + end.len()..];
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn write_pem(path: &Path, tag: &str, der: &[u8]) {
        let encoded = STANDARD.encode(der);
        let mut contents = format!("-----BEGIN {tag}-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            writeln!(&mut contents, "{}", std::str::from_utf8(chunk).unwrap()).unwrap();
        }
        contents.push_str(&format!("-----END {tag}-----\n"));
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn pem_identity_matches_der_identity() {
        let stem = format!(
            "fsh-pem-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir();
        let der_certificate = directory.join(format!("{stem}.cert"));
        let der_key = directory.join(format!("{stem}.key"));
        let pem_certificate = directory.join(format!("{stem}.pem.cert"));
        let pem_key = directory.join(format!("{stem}.pem.key"));

        let identity = ServerIdentity::generate(&der_certificate, &der_key).unwrap();
        let key_der = read_private_key(&der_key).unwrap();
        write_pem(&pem_certificate, "CERTIFICATE", identity.certificate_der());
        write_pem(&pem_key, "PRIVATE KEY", key_der.secret_der());

        let pem_identity = ServerIdentity::load(&pem_certificate, &pem_key).unwrap();
        assert_eq!(pem_identity.pin(), identity.pin());

        for path in [&der_certificate, &der_key, &pem_certificate, &pem_key] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn pem_decoder_rejects_garbage_and_unmatched_blocks() {
        // An absent tag yields no blocks; a malformed block is an error.
        assert!(
            pem_blocks(b"not a pem file", "CERTIFICATE")
                .unwrap()
                .is_empty()
        );
        let truncated = b"-----BEGIN CERTIFICATE-----\nAAAA";
        assert!(pem_blocks(truncated, "CERTIFICATE").is_err());
        let invalid_base64 = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert!(pem_blocks(invalid_base64.as_bytes(), "CERTIFICATE").is_err());
        let missing_end = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END OTHER-----\n";
        assert!(pem_blocks(missing_end.as_bytes(), "CERTIFICATE").is_err());
    }

    #[test]
    fn private_key_pem_keeps_pkcs1_and_sec1_variants() {
        let directory = std::env::temp_dir();
        let stem = format!(
            "fsh-keyfmt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        // The loader only unwraps PEM to DER and picks the matching variant;
        // rustls validates the key material when the endpoint is built.
        let pkcs1_der = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        let sec1_der = vec![0x30, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let pkcs1_pem = directory.join(format!("{stem}.rsa.pem"));
        let sec1_pem = directory.join(format!("{stem}.ec.pem"));
        write_pem(&pkcs1_pem, "RSA PRIVATE KEY", &pkcs1_der);
        write_pem(&sec1_pem, "EC PRIVATE KEY", &sec1_der);

        match read_private_key(&pkcs1_pem).unwrap() {
            PrivateKeyDer::Pkcs1(key) => assert_eq!(key.secret_pkcs1_der(), &pkcs1_der),
            other => panic!("expected PKCS#1 variant, got {other:?}"),
        }
        match read_private_key(&sec1_pem).unwrap() {
            PrivateKeyDer::Sec1(key) => assert_eq!(key.secret_sec1_der(), &sec1_der),
            other => panic!("expected SEC1 variant, got {other:?}"),
        }

        let _ = fs::remove_file(&pkcs1_pem);
        let _ = fs::remove_file(&sec1_pem);
    }

    #[test]
    fn private_key_pem_without_known_tag_is_rejected() {
        let directory = std::env::temp_dir();
        let unknown = directory.join(format!(
            "fsh-keyfmt-unknown-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        write_pem(&unknown, "SOMETHING ELSE", &[1, 2, 3]);
        assert!(read_private_key(&unknown).is_err());
        let _ = fs::remove_file(&unknown);
    }

    #[test]
    fn bare_der_keys_are_classified_by_structure() {
        // SEQUENCE(version=0, AlgorithmIdentifier SEQUENCE) → PKCS#8.
        let pkcs8 = vec![0x30, 0x07, 0x02, 0x01, 0x00, 0x30, 0x02, 0x05, 0x00];
        assert!(matches!(
            classify_der_private_key(&pkcs8),
            PrivateKeyDer::Pkcs8(_)
        ));

        // SEQUENCE(version=0, modulus INTEGER) → PKCS#1.
        let pkcs1 = vec![
            0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04,
        ];
        assert!(matches!(
            classify_der_private_key(&pkcs1),
            PrivateKeyDer::Pkcs1(_)
        ));

        // SEQUENCE(version=1, OCTET STRING) → SEC1.
        let sec1 = vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0xAA, 0xBB];
        assert!(matches!(
            classify_der_private_key(&sec1),
            PrivateKeyDer::Sec1(_)
        ));

        // SEQUENCE(version=1, modulus INTEGER) → multi-prime PKCS#1.
        let multi_prime = vec![
            0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04,
        ];
        assert!(matches!(
            classify_der_private_key(&multi_prime),
            PrivateKeyDer::Pkcs1(_)
        ));

        // Long-form lengths and unparseable input fall back to PKCS#8.
        let long_form = vec![
            0x30, 0x82, 0x00, 0x07, 0x02, 0x01, 0x00, 0x30, 0x02, 0x05, 0x00,
        ];
        assert!(matches!(
            classify_der_private_key(&long_form),
            PrivateKeyDer::Pkcs8(_)
        ));
        assert!(matches!(
            classify_der_private_key(b"\x30\x02\x02\x01"),
            PrivateKeyDer::Pkcs8(_)
        ));
    }
}
