use std::{collections::HashMap, fs, path::Path, sync::Arc};

use rsa::pkcs1v15::SigningKey;
use sha2::{Sha256, Sha512};
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::{Algorithm, PrivateKey, PublicKey, Signature};

use crate::wire::{Decoder, Encoder, Frame, FramedReader, FramedWriter, WireError};
use crate::{EXPORTER_LEN, Error, Result, exporter_binding};

pub const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_UNIMPLEMENTED: u8 = 3;
const MSG_DEBUG: u8 = 4;
pub const MSG_SERVICE_REQUEST: u8 = 5;
pub const MSG_SERVICE_ACCEPT: u8 = 6;
pub const MSG_USERAUTH_REQUEST: u8 = 50;
pub const MSG_USERAUTH_FAILURE: u8 = 51;
pub const MSG_USERAUTH_SUCCESS: u8 = 52;
pub const MSG_USERAUTH_PK_OK: u8 = 60;

pub const USERAUTH_SERVICE: &str = "fsh-userauth";
pub const CONNECTION_SERVICE: &str = "fsh-connection";
pub const PUBLICKEY_METHOD: &str = "publickey";

const MAX_AUTH_ATTEMPTS: usize = 10;

/// A private identity loaded from an OpenSSH key file.
#[derive(Clone)]
pub struct Identity {
    private_key: PrivateKey,
    public_blob: Vec<u8>,
    algorithm: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("algorithm", &self.algorithm)
            .field(
                "fingerprint",
                &self.public_key().fingerprint(ssh_key::HashAlg::Sha256),
            )
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn load(path: impl AsRef<Path>, passphrase: Option<&str>) -> Result<Self> {
        let bytes = fs::read(path.as_ref())?;
        let mut private_key = PrivateKey::from_openssh(&bytes)
            .map_err(|e| Error::Auth(format!("cannot parse {}: {e}", path.as_ref().display())))?;
        if private_key.is_encrypted() {
            let passphrase = passphrase.ok_or_else(|| {
                Error::Auth(format!(
                    "private key {} is encrypted",
                    path.as_ref().display()
                ))
            })?;
            private_key = private_key
                .decrypt(passphrase)
                .map_err(|e| Error::Auth(format!("cannot decrypt identity: {e}")))?;
        }
        Self::from_private_key(private_key)
    }

    pub fn from_private_key(private_key: PrivateKey) -> Result<Self> {
        Self::from_private_key_with_algorithm(private_key, None)
    }

    /// Construct an identity and explicitly select the RSA signature hash.
    ///
    /// RSA public-key blobs use the `ssh-rsa` wire format, while FSH selects
    /// the RFC 8332 signature name in the authentication request.
    pub fn from_private_key_with_algorithm(
        private_key: PrivateKey,
        requested_algorithm: Option<&str>,
    ) -> Result<Self> {
        let public_blob = private_key
            .public_key()
            .to_bytes()
            .map_err(|e| Error::Auth(format!("cannot encode public key: {e}")))?;
        let default_algorithm = auth_algorithm_for_key(private_key.public_key())?;
        let algorithm = requested_algorithm.unwrap_or(&default_algorithm);
        validate_identity_algorithm(private_key.public_key(), algorithm)?;
        Ok(Self {
            private_key,
            public_blob,
            algorithm: algorithm.to_owned(),
        })
    }

    pub fn generate_ed25519(path: impl AsRef<Path>) -> Result<Self> {
        let mut rng = rand_core_06::OsRng;
        let private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .map_err(|e| Error::Auth(format!("cannot generate identity: {e}")))?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let pem = private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|e| Error::Auth(format!("cannot encode identity: {e}")))?;
        fs::write(path.as_ref(), pem.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path.as_ref(), fs::Permissions::from_mode(0o600))?;
        }
        Self::from_private_key(private_key)
    }

    pub fn public_key(&self) -> &PublicKey {
        self.private_key.public_key()
    }

    pub fn public_blob(&self) -> &[u8] {
        &self.public_blob
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn fingerprint(&self) -> String {
        self.public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    }

    pub fn sign(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        let signature = match self.algorithm.as_str() {
            "rsa-sha2-256" => {
                let keypair = self
                    .private_key
                    .key_data()
                    .rsa()
                    .ok_or_else(|| Error::Auth("identity is not an RSA key".into()))?;
                let key = rsa_private_key(keypair)?;
                let signature = SigningKey::<Sha256>::new(key).sign(transcript);
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(ssh_key::HashAlg::Sha256),
                    },
                    signature.to_vec(),
                )
                .map_err(|e| Error::Auth(format!("cannot encode RSA signature: {e}")))?
            }
            "rsa-sha2-512" => {
                let keypair = self
                    .private_key
                    .key_data()
                    .rsa()
                    .ok_or_else(|| Error::Auth("identity is not an RSA key".into()))?;
                let key = rsa_private_key(keypair)?;
                let signature = SigningKey::<Sha512>::new(key).sign(transcript);
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(ssh_key::HashAlg::Sha512),
                    },
                    signature.to_vec(),
                )
                .map_err(|e| Error::Auth(format!("cannot encode RSA signature: {e}")))?
            }
            _ => self
                .private_key
                .try_sign(transcript)
                .map_err(|e| Error::Auth(format!("cannot sign authentication transcript: {e}")))?,
        };
        if signature.algorithm().as_str() != self.algorithm {
            return Err(Error::Auth(format!(
                "identity produced signature algorithm {}, expected {}",
                signature.algorithm().as_str(),
                self.algorithm
            )));
        }
        signature
            .try_into()
            .map_err(|e: ssh_key::Error| Error::Auth(format!("cannot encode signature: {e}")))
    }
}

fn rsa_private_key(keypair: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    let n = rsa::BigUint::try_from(&keypair.public.n)
        .map_err(|e| Error::Auth(format!("invalid RSA modulus: {e}")))?;
    let e = rsa::BigUint::try_from(&keypair.public.e)
        .map_err(|e| Error::Auth(format!("invalid RSA exponent: {e}")))?;
    let d = rsa::BigUint::try_from(&keypair.private.d)
        .map_err(|e| Error::Auth(format!("invalid RSA private exponent: {e}")))?;
    let p = rsa::BigUint::try_from(&keypair.private.p)
        .map_err(|e| Error::Auth(format!("invalid RSA prime: {e}")))?;
    let q = rsa::BigUint::try_from(&keypair.private.q)
        .map_err(|e| Error::Auth(format!("invalid RSA prime: {e}")))?;
    rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|error| Error::Auth(format!("invalid RSA private key: {error}")))
}

/// A parsed authorized-keys file. OpenSSH options are intentionally rejected
/// rather than silently ignored because FSH does not implement their policy.
#[derive(Clone, Debug, Default)]
pub struct AuthorizedKeys {
    keys: Arc<HashMap<Vec<u8>, PublicKey>>,
}

impl AuthorizedKeys {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = fs::read_to_string(path.as_ref())?;
        Self::from_lines(&contents)
    }

    pub fn from_lines(contents: &str) -> Result<Self> {
        let mut keys = HashMap::new();
        for (line_number, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 2 {
                return Err(Error::Auth(format!(
                    "authorized_keys line {} has no key",
                    line_number + 1
                )));
            }
            if fields[0].contains('=') || fields[0].contains(',') {
                return Err(Error::Auth(format!(
                    "authorized_keys options are unsupported on line {}",
                    line_number + 1
                )));
            }
            let encoded = format!("{} {}", fields[0], fields[1]);
            let key = PublicKey::from_openssh(&encoded).map_err(|e| {
                Error::Auth(format!(
                    "invalid authorized key on line {}: {e}",
                    line_number + 1
                ))
            })?;
            let blob = key
                .to_bytes()
                .map_err(|e| Error::Auth(format!("cannot encode authorized key: {e}")))?;
            if !is_supported_public_key(&key) {
                return Err(Error::UnsupportedAlgorithm(
                    key.algorithm().as_str().to_string(),
                ));
            }
            keys.insert(blob, key);
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    fn lookup(&self, algorithm: &str, blob: &[u8]) -> Option<&PublicKey> {
        let key = self.keys.get(blob)?;
        let matches = match key.algorithm() {
            Algorithm::Rsa { .. } => matches!(algorithm, "rsa-sha2-256" | "rsa-sha2-512"),
            _ => auth_algorithm_for_key(key).ok().as_deref() == Some(algorithm),
        };
        if matches { Some(key) } else { None }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Client-side public-key authentication and service transition.
pub struct UserAuthClient {
    pub username: String,
    pub identity: Identity,
}

impl UserAuthClient {
    pub async fn authenticate(
        &self,
        connection: &quinn::Connection,
        mut reader: FramedReader<quinn::RecvStream>,
        mut writer: FramedWriter<quinn::SendStream>,
    ) -> Result<(
        FramedReader<quinn::RecvStream>,
        FramedWriter<quinn::SendStream>,
    )> {
        send_service(&mut writer, USERAUTH_SERVICE).await?;
        expect_service_accept(connection, &mut reader, &mut writer, USERAUTH_SERVICE).await?;

        let probe = AuthRequest::probe(&self.username, &self.identity);
        send_auth_request(&mut writer, &probe).await?;
        match next_control_frame(connection, &mut reader, &mut writer).await? {
            Frame {
                number: MSG_USERAUTH_PK_OK,
                payload,
            } => {
                let mut decoder = Decoder::new(&payload);
                let algorithm = match decoder.string() {
                    Ok(value) => value.to_owned(),
                    Err(error) => {
                        let error = error.into();
                        abort_auth_protocol(connection, &mut writer, "malformed USERAUTH_PK_OK")
                            .await;
                        return Err(error);
                    }
                };
                let blob = match decoder.bytes() {
                    Ok(value) => value.to_vec(),
                    Err(error) => {
                        let error = error.into();
                        abort_auth_protocol(connection, &mut writer, "malformed USERAUTH_PK_OK")
                            .await;
                        return Err(error);
                    }
                };
                if let Err(error) = decoder.finish() {
                    let error: Error = error.into();
                    abort_auth_protocol(connection, &mut writer, "malformed USERAUTH_PK_OK").await;
                    return Err(error);
                }
                if algorithm != self.identity.algorithm() || blob != self.identity.public_blob() {
                    let error = Error::Auth("server PK_OK did not echo the probed key".into());
                    abort_auth_protocol(connection, &mut writer, "unexpected USERAUTH_PK_OK").await;
                    return Err(error);
                }
            }
            Frame {
                number: MSG_USERAUTH_FAILURE,
                payload,
            } => {
                if let Err(error) = validate_failure(&payload) {
                    abort_auth_protocol(connection, &mut writer, "malformed USERAUTH_FAILURE")
                        .await;
                    return Err(error);
                }
                return Err(Error::Auth("public key was not authorized".into()));
            }
            frame => {
                let error = Error::Protocol(format!(
                    "expected USERAUTH_PK_OK, got message {}",
                    frame.number
                ));
                abort_auth_protocol(connection, &mut writer, "unexpected authentication reply")
                    .await;
                return Err(error);
            }
        }

        let binding = exporter_binding(connection)?;
        let signed = AuthRequest::signed(&self.username, &self.identity, &binding)?;
        send_auth_request(&mut writer, &signed).await?;
        loop {
            match next_control_frame(connection, &mut reader, &mut writer).await? {
                Frame {
                    number: MSG_USERAUTH_SUCCESS,
                    payload,
                } if payload.is_empty() => break,
                Frame {
                    number: MSG_USERAUTH_FAILURE,
                    payload,
                } => {
                    if let Err(error) = validate_failure(&payload) {
                        abort_auth_protocol(connection, &mut writer, "malformed USERAUTH_FAILURE")
                            .await;
                        return Err(error);
                    }
                    return Err(Error::Auth("public key signature was rejected".into()));
                }
                Frame {
                    number: MSG_USERAUTH_PK_OK,
                    payload,
                } => {
                    // A PK_OK after the signed request is unsolicited. It is
                    // still parsed strictly so malformed known messages cannot
                    // smuggle bytes into the next authentication response.
                    let mut decoder = Decoder::new(&payload);
                    if decoder.string().and_then(|_| decoder.bytes()).is_err()
                        || decoder.finish().is_err()
                    {
                        let error = Error::Protocol("malformed unsolicited USERAUTH_PK_OK".into());
                        abort_auth_protocol(connection, &mut writer, "malformed USERAUTH_PK_OK")
                            .await;
                        return Err(error);
                    }
                }
                frame => {
                    let error = Error::Protocol(format!(
                        "expected USERAUTH_SUCCESS, got message {}",
                        frame.number
                    ));
                    abort_auth_protocol(connection, &mut writer, "unexpected authentication reply")
                        .await;
                    return Err(error);
                }
            }
        }

        send_service(&mut writer, CONNECTION_SERVICE).await?;
        expect_service_accept(connection, &mut reader, &mut writer, CONNECTION_SERVICE).await?;
        Ok((reader, writer))
    }
}

/// Server-side public-key authentication and service transition.
pub struct UserAuthServer {
    pub authorized_keys: AuthorizedKeys,
    pub expected_username: Option<String>,
}

impl UserAuthServer {
    pub async fn authenticate(
        &self,
        connection: &quinn::Connection,
        mut reader: FramedReader<quinn::RecvStream>,
        mut writer: FramedWriter<quinn::SendStream>,
    ) -> Result<(
        String,
        FramedReader<quinn::RecvStream>,
        FramedWriter<quinn::SendStream>,
    )> {
        if self.expected_username.is_none() {
            send_disconnect(
                connection,
                &mut writer,
                2,
                "server authentication policy has no configured user",
            )
            .await?;
            return Err(Error::Auth(
                "server authentication requires an explicit username".into(),
            ));
        }
        expect_service_request(connection, &mut reader, &mut writer, USERAUTH_SERVICE).await?;

        let mut attempts = 0;
        let username = loop {
            attempts += 1;
            if attempts > MAX_AUTH_ATTEMPTS {
                send_disconnect(
                    connection,
                    &mut writer,
                    5,
                    "too many authentication attempts",
                )
                .await?;
                return Err(Error::Auth("too many authentication attempts".into()));
            }
            let frame = next_auth_control_frame(connection, &mut reader, &mut writer).await?;
            if frame.number != MSG_USERAUTH_REQUEST {
                send_failure(&mut writer).await?;
                continue;
            }
            let request = match AuthRequest::decode(&frame.payload) {
                Ok(request) => request,
                Err(_) => {
                    send_failure(&mut writer).await?;
                    continue;
                }
            };
            if !request.is_valid_service()
                || request.method != PUBLICKEY_METHOD
                || !valid_algorithm_name(&request.algorithm)
            {
                send_failure(&mut writer).await?;
                continue;
            }
            if request.user.is_empty()
                || request.user.len() > 256
                || self
                    .expected_username
                    .as_deref()
                    .is_some_and(|expected| expected != request.user)
            {
                send_failure(&mut writer).await?;
                continue;
            }
            let Some(key) = self
                .authorized_keys
                .lookup(&request.algorithm, &request.public_blob)
            else {
                send_failure(&mut writer).await?;
                continue;
            };
            if !request.has_signature {
                let mut payload = Encoder::new();
                payload.string(&request.algorithm)?;
                payload.bytes(&request.public_blob)?;
                send_frame(&mut writer, MSG_USERAUTH_PK_OK, payload.finish()).await?;
                continue;
            }
            let signature = match decode_canonical_signature(&request.signature) {
                Ok(signature) => signature,
                Err(_) => {
                    send_failure(&mut writer).await?;
                    continue;
                }
            };
            if signature.algorithm().as_str() != request.algorithm {
                send_failure(&mut writer).await?;
                continue;
            }
            let binding = exporter_binding(connection)?;
            let transcript = request.signed_transcript(&binding)?;
            if Verifier::verify(key, &transcript, &signature).is_err() {
                send_failure(&mut writer).await?;
                continue;
            }
            send_frame(&mut writer, MSG_USERAUTH_SUCCESS, Vec::new()).await?;
            break request.user;
        };

        expect_service_request(connection, &mut reader, &mut writer, CONNECTION_SERVICE).await?;
        Ok((username, reader, writer))
    }
}

#[derive(Clone, Debug)]
struct AuthRequest {
    user: String,
    service: String,
    method: String,
    has_signature: bool,
    algorithm: String,
    public_blob: Vec<u8>,
    signature: Vec<u8>,
}

impl AuthRequest {
    fn probe(user: &str, identity: &Identity) -> Self {
        Self {
            user: user.to_owned(),
            service: CONNECTION_SERVICE.to_owned(),
            method: PUBLICKEY_METHOD.to_owned(),
            has_signature: false,
            algorithm: identity.algorithm().to_owned(),
            public_blob: identity.public_blob().to_vec(),
            signature: Vec::new(),
        }
    }

    fn signed(user: &str, identity: &Identity, binding: &[u8; EXPORTER_LEN]) -> Result<Self> {
        let mut request = Self::probe(user, identity);
        request.has_signature = true;
        let transcript = request.signed_transcript(binding)?;
        request.signature = identity.sign(&transcript)?;
        Ok(request)
    }

    fn decode(payload: &[u8]) -> std::result::Result<Self, WireError> {
        let mut decoder = Decoder::new(payload);
        let user = decoder.string()?.to_owned();
        let service = decoder.string()?.to_owned();
        let method = decoder.string()?.to_owned();
        let has_signature = decoder.boolean()?;
        let algorithm = decoder.string()?.to_owned();
        let public_blob = decoder.bytes()?.to_vec();
        let signature = if has_signature {
            decoder.bytes()?.to_vec()
        } else {
            Vec::new()
        };
        decoder.finish()?;
        Ok(Self {
            user,
            service,
            method,
            has_signature,
            algorithm,
            public_blob,
            signature,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        encoder.string(&self.user)?;
        encoder.string(&self.service)?;
        encoder.string(&self.method)?;
        encoder.boolean(self.has_signature);
        encoder.string(&self.algorithm)?;
        encoder.bytes(&self.public_blob)?;
        if self.has_signature {
            encoder.bytes(&self.signature)?;
        }
        Ok(encoder.finish())
    }

    fn signed_transcript(&self, binding: &[u8; EXPORTER_LEN]) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        encoder.bytes(binding)?;
        encoder.u8(MSG_USERAUTH_REQUEST);
        encoder.string(&self.user)?;
        encoder.string(&self.service)?;
        encoder.string(&self.method)?;
        encoder.boolean(true);
        encoder.string(&self.algorithm)?;
        encoder.bytes(&self.public_blob)?;
        Ok(encoder.finish())
    }

    fn is_valid_service(&self) -> bool {
        self.service == CONNECTION_SERVICE
    }
}

fn auth_algorithm_for_key(key: &PublicKey) -> Result<String> {
    if !is_supported_public_key(key) {
        return Err(Error::UnsupportedAlgorithm(
            key.algorithm().as_str().to_string(),
        ));
    }
    let algorithm = match key.algorithm() {
        Algorithm::Rsa { .. } => "rsa-sha2-512",
        _ => return Ok(key.algorithm().as_str().to_owned()),
    };
    Ok(algorithm.to_owned())
}

fn is_supported_public_key(key: &PublicKey) -> bool {
    match key.algorithm() {
        Algorithm::Ed25519
        | Algorithm::Ecdsa { .. }
        | Algorithm::SkEd25519
        | Algorithm::SkEcdsaSha2NistP256 => true,
        Algorithm::Rsa { .. } => key
            .key_data()
            .rsa()
            .and_then(|rsa| rsa.n.as_positive_bytes())
            .is_some_and(|n| rsa_modulus_bits(n) >= 3072),
        _ => false,
    }
}

fn validate_identity_algorithm(key: &PublicKey, algorithm: &str) -> Result<()> {
    if !valid_algorithm_name(algorithm) {
        return Err(Error::UnsupportedAlgorithm(algorithm.to_owned()));
    }
    match key.algorithm() {
        Algorithm::Rsa { .. } if matches!(algorithm, "rsa-sha2-256" | "rsa-sha2-512") => Ok(()),
        Algorithm::Rsa { .. } => Err(Error::UnsupportedAlgorithm(algorithm.to_owned())),
        _ if key.algorithm().as_str() == algorithm => Ok(()),
        _ => Err(Error::UnsupportedAlgorithm(algorithm.to_owned())),
    }
}

fn rsa_modulus_bits(bytes: &[u8]) -> usize {
    bytes
        .first()
        .map_or(0, |first| bytes.len() * 8 - first.leading_zeros() as usize)
}

fn decode_canonical_signature(bytes: &[u8]) -> Result<Signature> {
    let signature = Signature::try_from(bytes)
        .map_err(|e| Error::Auth(format!("invalid authentication signature: {e}")))?;
    let canonical: Vec<u8> = signature
        .clone()
        .try_into()
        .map_err(|e: ssh_key::Error| Error::Auth(format!("cannot canonicalize signature: {e}")))?;
    if canonical != bytes {
        return Err(Error::Auth(
            "authentication signature has trailing bytes".into(),
        ));
    }
    Ok(signature)
}

async fn send_auth_request(
    writer: &mut FramedWriter<quinn::SendStream>,
    request: &AuthRequest,
) -> Result<()> {
    send_frame(writer, MSG_USERAUTH_REQUEST, request.encode()?).await
}

async fn send_service(writer: &mut FramedWriter<quinn::SendStream>, service: &str) -> Result<()> {
    let mut encoder = Encoder::new();
    encoder.string(service)?;
    send_frame(writer, MSG_SERVICE_REQUEST, encoder.finish()).await
}

async fn expect_service_accept(
    connection: &quinn::Connection,
    reader: &mut FramedReader<quinn::RecvStream>,
    writer: &mut FramedWriter<quinn::SendStream>,
    expected: &str,
) -> Result<()> {
    let frame = next_control_frame(connection, reader, writer).await?;
    match frame {
        Frame {
            number: MSG_SERVICE_ACCEPT,
            payload,
        } => {
            let mut decoder = Decoder::new(&payload);
            let service = match decoder.string() {
                Ok(service) => service,
                Err(error) => {
                    let error: Error = error.into();
                    abort_auth_protocol(connection, writer, "malformed SERVICE_ACCEPT").await;
                    return Err(error);
                }
            };
            if let Err(error) = decoder.finish() {
                let error: Error = error.into();
                abort_auth_protocol(connection, writer, "malformed SERVICE_ACCEPT").await;
                return Err(error);
            }
            if service != expected {
                let error =
                    Error::Protocol(format!("server accepted unexpected service {service}"));
                abort_auth_protocol(connection, writer, "unexpected service acceptance").await;
                return Err(error);
            }
            Ok(())
        }
        frame => {
            let error = Error::Protocol(format!("expected SERVICE_ACCEPT, got {}", frame.number));
            abort_auth_protocol(connection, writer, "unexpected service acceptance").await;
            Err(error)
        }
    }
}

async fn expect_service_request(
    connection: &quinn::Connection,
    reader: &mut FramedReader<quinn::RecvStream>,
    writer: &mut FramedWriter<quinn::SendStream>,
    expected: &str,
) -> Result<()> {
    let frame = next_auth_control_frame(connection, reader, writer).await?;
    match frame {
        Frame {
            number: MSG_SERVICE_REQUEST,
            payload,
        } => {
            let mut decoder = Decoder::new(&payload);
            let service = match decoder.string() {
                Ok(service) => service.to_owned(),
                Err(error) => {
                    let error: Error = error.into();
                    abort_auth_protocol(connection, writer, "malformed SERVICE_REQUEST").await;
                    return Err(error);
                }
            };
            if let Err(error) = decoder.finish() {
                let error: Error = error.into();
                abort_auth_protocol(connection, writer, "malformed SERVICE_REQUEST").await;
                return Err(error);
            }
            if service != expected {
                let error =
                    Error::Protocol(format!("client requested unexpected service {service}"));
                abort_auth_protocol(connection, writer, "unexpected service request").await;
                return Err(error);
            }
            let mut encoder = Encoder::new();
            encoder.string(expected)?;
            send_frame(writer, MSG_SERVICE_ACCEPT, encoder.finish()).await
        }
        frame => {
            let error = Error::Protocol(format!("expected SERVICE_REQUEST, got {}", frame.number));
            abort_auth_protocol(connection, writer, "unexpected service request").await;
            Err(error)
        }
    }
}

async fn send_failure(writer: &mut FramedWriter<quinn::SendStream>) -> Result<()> {
    let mut encoder = Encoder::new();
    encoder.string(PUBLICKEY_METHOD)?;
    encoder.boolean(false);
    send_frame(writer, MSG_USERAUTH_FAILURE, encoder.finish()).await
}

async fn send_disconnect(
    connection: &quinn::Connection,
    writer: &mut FramedWriter<quinn::SendStream>,
    reason: u32,
    description: &str,
) -> Result<()> {
    let mut encoder = Encoder::new();
    encoder.u32(reason);
    encoder.string(description)?;
    let result = send_frame(writer, MSG_DISCONNECT, encoder.finish()).await;
    let stopped = if result.is_ok() {
        let _ = writer.finish().await;
        Some(writer.inner().stopped())
    } else {
        None
    };
    if let Some(stopped) = stopped {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(250), stopped).await;
    }
    connection.close(reason.into(), b"FSH disconnect");
    result
}

fn decode_disconnect(payload: &[u8]) -> Result<String> {
    let mut decoder = Decoder::new(payload);
    let reason = decoder.u32().map_err(|error| {
        Error::RemoteDisconnect(format!("malformed disconnect reason: {error}"))
    })?;
    if !(1..=5).contains(&reason) {
        return Err(Error::RemoteDisconnect(format!(
            "malformed disconnect reason code {reason}"
        )));
    }
    let message = decoder
        .string()
        .map_err(|error| Error::RemoteDisconnect(format!("malformed disconnect message: {error}")))?
        .to_owned();
    decoder.finish().map_err(|error| {
        Error::RemoteDisconnect(format!("malformed disconnect payload: {error}"))
    })?;
    Ok(format!("peer disconnected ({reason}): {message}"))
}

fn validate_failure(payload: &[u8]) -> Result<()> {
    let mut decoder = Decoder::new(payload);
    if decoder.string()? != PUBLICKEY_METHOD {
        return Err(Error::Protocol(
            "USERAUTH_FAILURE advertised an unsupported method".into(),
        ));
    }
    if decoder.boolean()? {
        return Err(Error::Protocol(
            "partial authentication is not supported".into(),
        ));
    }
    decoder.finish()?;
    Ok(())
}

fn valid_algorithm_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.is_ascii()
        && !name
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b',')
        && matches!(
            name,
            "ssh-ed25519"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
                | "rsa-sha2-256"
                | "rsa-sha2-512"
        )
}

async fn next_control_frame(
    connection: &quinn::Connection,
    reader: &mut FramedReader<quinn::RecvStream>,
    writer: &mut FramedWriter<quinn::SendStream>,
) -> Result<Frame> {
    loop {
        let frame = match reader.next().await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                let error = Error::Protocol("control stream ended unexpectedly".into());
                abort_auth_protocol(connection, writer, "control stream ended unexpectedly").await;
                return Err(error);
            }
            Err(error) => {
                let error: Error = error.into();
                abort_auth_protocol(connection, writer, "malformed control frame").await;
                return Err(error);
            }
        };
        if frame.number == MSG_DISCONNECT {
            let result = decode_disconnect(&frame.payload);
            connection.close(0u32.into(), b"peer disconnected");
            return match result {
                Ok(message) => Err(Error::RemoteDisconnect(message)),
                Err(error) => Err(error),
            };
        }
        match consume_transport_info(&frame) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                abort_auth_protocol(connection, writer, "malformed transport message").await;
                return Err(error);
            }
        }
        if frame.number == MSG_UNIMPLEMENTED {
            if let Err(error) = validate_unimplemented(&frame.payload) {
                abort_auth_protocol(connection, writer, "malformed UNIMPLEMENTED message").await;
                return Err(error);
            }
            continue;
        }
        if frame.number >= 192 {
            continue;
        }
        if !matches!(
            frame.number,
            MSG_SERVICE_ACCEPT | MSG_USERAUTH_FAILURE | MSG_USERAUTH_PK_OK | MSG_USERAUTH_SUCCESS
        ) {
            send_unimplemented(writer, frame.number).await?;
            continue;
        }
        return Ok(frame);
    }
}

async fn next_auth_control_frame(
    connection: &quinn::Connection,
    reader: &mut FramedReader<quinn::RecvStream>,
    writer: &mut FramedWriter<quinn::SendStream>,
) -> Result<Frame> {
    loop {
        tokio::select! {
            frame = reader.next() => {
                let frame = match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        let error = Error::Protocol("control stream ended unexpectedly".into());
                        abort_auth_protocol(
                            connection,
                            writer,
                            "control stream ended unexpectedly",
                        )
                        .await;
                        return Err(error);
                    }
                    Err(error) => {
                        let error: Error = error.into();
                        abort_auth_protocol(connection, writer, "malformed control frame").await;
                        return Err(error);
                    }
                };
                if frame.number == MSG_DISCONNECT {
                    let result = decode_disconnect(&frame.payload);
                    connection.close(0u32.into(), b"peer disconnected");
                    return match result {
                        Ok(message) => Err(Error::RemoteDisconnect(message)),
                        Err(error) => Err(error),
                    };
                }
                match consume_transport_info(&frame) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => {
                        abort_auth_protocol(connection, writer, "malformed transport message").await;
                        return Err(error);
                    }
                }
                if frame.number == MSG_UNIMPLEMENTED {
                    if let Err(error) = validate_unimplemented(&frame.payload) {
                        abort_auth_protocol(connection, writer, "malformed UNIMPLEMENTED message")
                            .await;
                        return Err(error);
                    }
                    continue;
                }
                if frame.number >= 192 {
                    continue;
                }
                if !matches!(
                    frame.number,
                    MSG_SERVICE_REQUEST | MSG_USERAUTH_REQUEST | MSG_DISCONNECT
                ) {
                    send_unimplemented(writer, frame.number).await?;
                    continue;
                }
                return Ok(frame);
            }
            incoming = connection.accept_bi() => {
                let (mut send, mut recv) = incoming?;
                let _ = send.reset(quinn::VarInt::from_u32(1));
                let _ = recv.stop(quinn::VarInt::from_u32(1));
            }
            incoming = connection.accept_uni() => {
                let mut recv = incoming?;
                let _ = recv.stop(quinn::VarInt::from_u32(1));
            }
        }
    }
}

async fn abort_auth_protocol(
    connection: &quinn::Connection,
    writer: &mut FramedWriter<quinn::SendStream>,
    description: &str,
) {
    let _ = send_disconnect(connection, writer, 1, description).await;
}

async fn send_frame(
    writer: &mut FramedWriter<quinn::SendStream>,
    number: u8,
    payload: Vec<u8>,
) -> Result<()> {
    writer.send(number, &payload).await?;
    Ok(())
}

async fn send_unimplemented(
    writer: &mut FramedWriter<quinn::SendStream>,
    number: u8,
) -> Result<()> {
    send_frame(writer, MSG_UNIMPLEMENTED, vec![number]).await
}

fn consume_transport_info(frame: &Frame) -> Result<bool> {
    match frame.number {
        MSG_IGNORE => Ok(true),
        MSG_DEBUG => {
            let mut decoder = Decoder::new(&frame.payload);
            let _always_display = decoder.boolean()?;
            let _message = decoder.string()?;
            decoder.finish()?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn validate_unimplemented(payload: &[u8]) -> Result<()> {
    let mut decoder = Decoder::new(payload);
    let _ = decoder.u8()?;
    decoder.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServerIdentity, make_client_endpoint, make_server_endpoint};
    use std::{net::SocketAddr, time::Duration};
    use tokio::time::timeout;

    #[test]
    fn authorized_keys_accepts_ed25519_and_rejects_options() {
        let key = Identity::generate_ed25519(
            std::env::temp_dir().join(format!("fsh-test-{}", std::process::id())),
        )
        .unwrap();
        let line = key.public_key().to_openssh().unwrap();
        let keys = AuthorizedKeys::from_lines(&line).unwrap();
        assert!(!keys.is_empty());
        assert!(AuthorizedKeys::from_lines(&format!("command=x {line}")).is_err());
    }

    #[test]
    fn rsa_auth_signs_both_sha2_algorithms() {
        let mut rng = rand_core_06::OsRng;
        let private_key = PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None }).unwrap();
        let transcript = b"fsh authentication transcript";

        for algorithm in ["rsa-sha2-256", "rsa-sha2-512"] {
            let identity =
                Identity::from_private_key_with_algorithm(private_key.clone(), Some(algorithm))
                    .unwrap();
            let encoded = identity.sign(transcript).unwrap();
            let signature = decode_canonical_signature(&encoded).unwrap();
            assert_eq!(signature.algorithm().as_str(), algorithm);
            Verifier::verify(identity.public_key(), transcript, &signature).unwrap();
        }
    }

    #[test]
    fn rsa_modulus_size_does_not_round_up() {
        assert_eq!(rsa_modulus_bits(&[0x7f; 384]), 3071);
        assert_eq!(rsa_modulus_bits(&[0x80; 384]), 3072);
    }

    #[test]
    fn nested_signature_trailing_bytes_are_rejected() {
        let identity = Identity::generate_ed25519(
            std::env::temp_dir().join(format!("fsh-test-signature-{}", std::process::id())),
        )
        .unwrap();
        let mut encoded = identity.sign(b"transcript").unwrap();
        encoded.push(0);
        assert!(decode_canonical_signature(&encoded).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_auth_disconnect_is_terminal_and_has_no_reply() {
        let mut cases = Vec::new();

        let mut valid = Encoder::new();
        valid.u32(4);
        valid.string("server is shutting down").unwrap();
        cases.push(valid.finish());

        let mut invalid_reason = Encoder::new();
        invalid_reason.u32(0);
        invalid_reason.string("invalid reason").unwrap();
        cases.push(invalid_reason.finish());

        let mut trailing = Encoder::new();
        trailing.u32(1);
        trailing.string("trailing bytes").unwrap();
        let mut trailing = trailing.finish();
        trailing.push(0);
        cases.push(trailing);

        cases.push(vec![0, 0, 0, 1]);

        for payload in cases {
            run_client_auth_disconnect_case(payload).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_auth_replies_unimplemented_to_assigned_unknown_message() {
        let stem = format!(
            "fsh-auth-unknown-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let key_path = std::env::temp_dir().join(format!("{stem}.key"));
        let cert_path = std::env::temp_dir().join(format!("{stem}.cert"));
        let server_key_path = std::env::temp_dir().join(format!("{stem}.server-key"));
        let identity = Identity::generate_ed25519(&key_path).unwrap();
        let server_identity = ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport = make_server_endpoint(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            server_identity,
        )
        .unwrap();
        let server_address = server_transport.endpoint.local_addr().unwrap();
        let server_endpoint = server_transport.endpoint.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let mut reader = FramedReader::new(recv);
            let mut writer = FramedWriter::new(send);
            assert_eq!(
                reader.next().await.unwrap().unwrap().number,
                MSG_SERVICE_REQUEST
            );
            writer.send(53, &[]).await.unwrap();
            let mut service = Encoder::new();
            service.string(USERAUTH_SERVICE).unwrap();
            writer
                .send(MSG_SERVICE_ACCEPT, &service.finish())
                .await
                .unwrap();

            let unimplemented = timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(unimplemented.number, MSG_UNIMPLEMENTED);
            assert_eq!(unimplemented.payload, vec![53]);
            let probe = timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(probe.number, MSG_USERAUTH_REQUEST);

            let mut disconnect = Encoder::new();
            disconnect.u32(1);
            disconnect.string("test").unwrap();
            writer
                .send(MSG_DISCONNECT, &disconnect.finish())
                .await
                .unwrap();
            match timeout(Duration::from_secs(2), reader.next()).await {
                Ok(Ok(None)) | Ok(Err(_)) => Ok::<(), String>(()),
                Ok(Ok(Some(frame))) => Err(format!(
                    "client sent message {} after DISCONNECT",
                    frame.number
                )),
                Err(_) => Err("client did not close after DISCONNECT".into()),
            }
        });

        let client_transport = make_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_transport.identity.pin()),
        )
        .unwrap();
        let connection = client_transport
            .endpoint
            .connect(server_address, "fsh.local")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let result = auth
            .authenticate(
                &connection,
                FramedReader::new(recv),
                FramedWriter::new(send),
            )
            .await;
        assert!(matches!(result, Err(Error::RemoteDisconnect(_))));
        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        assert!(server_task.await.unwrap().is_ok());
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_auth_aborts_on_wrong_service_accept() {
        let stem = format!(
            "fsh-auth-service-error-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let key_path = std::env::temp_dir().join(format!("{stem}.key"));
        let cert_path = std::env::temp_dir().join(format!("{stem}.cert"));
        let server_key_path = std::env::temp_dir().join(format!("{stem}.server-key"));
        let identity = Identity::generate_ed25519(&key_path).unwrap();
        let server_identity = ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport = make_server_endpoint(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            server_identity,
        )
        .unwrap();
        let server_address = server_transport.endpoint.local_addr().unwrap();
        let server_endpoint = server_transport.endpoint.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let mut reader = FramedReader::new(recv);
            let mut writer = FramedWriter::new(send);
            assert_eq!(
                reader.next().await.unwrap().unwrap().number,
                MSG_SERVICE_REQUEST
            );
            let mut service = Encoder::new();
            service.string("wrong-service").unwrap();
            writer
                .send(MSG_SERVICE_ACCEPT, &service.finish())
                .await
                .unwrap();
            let disconnect = timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(disconnect.number, MSG_DISCONNECT);
            let mut decoder = Decoder::new(&disconnect.payload);
            assert_eq!(decoder.u32().unwrap(), 1);
            assert!(!decoder.string().unwrap().is_empty());
            decoder.finish().unwrap();
            match timeout(Duration::from_secs(2), reader.next()).await {
                Ok(Ok(None)) | Ok(Err(_)) => Ok::<(), String>(()),
                Ok(Ok(Some(frame))) => Err(format!(
                    "client sent message {} after DISCONNECT",
                    frame.number
                )),
                Err(_) => Err("client did not close after DISCONNECT".into()),
            }
        });

        let client_transport = make_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_transport.identity.pin()),
        )
        .unwrap();
        let connection = client_transport
            .endpoint
            .connect(server_address, "fsh.local")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let result = auth
            .authenticate(
                &connection,
                FramedReader::new(recv),
                FramedWriter::new(send),
            )
            .await;
        assert!(matches!(result, Err(Error::Protocol(_))));
        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        assert!(server_task.await.unwrap().is_ok());
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }

    async fn run_client_auth_disconnect_case(payload: Vec<u8>) {
        let stem = format!(
            "fsh-auth-disconnect-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let key_path = std::env::temp_dir().join(format!("{stem}.key"));
        let cert_path = std::env::temp_dir().join(format!("{stem}.cert"));
        let server_key_path = std::env::temp_dir().join(format!("{stem}.server-key"));
        let identity = Identity::generate_ed25519(&key_path).unwrap();
        let server_identity = ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport = make_server_endpoint(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            server_identity,
        )
        .unwrap();
        let server_address = server_transport.endpoint.local_addr().unwrap();
        let server_endpoint = server_transport.endpoint.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint
                .accept()
                .await
                .ok_or_else(|| "server endpoint closed".to_owned())?
                .await
                .map_err(|error| format!("server handshake failed: {error}"))?;
            let (send, recv) = connection
                .accept_bi()
                .await
                .map_err(|error| format!("control stream failed: {error}"))?;
            let mut reader = FramedReader::new(recv);
            let mut writer = FramedWriter::new(send);
            let frame = timeout(Duration::from_secs(2), reader.next())
                .await
                .map_err(|_| "client did not request userauth".to_owned())?
                .map_err(|error| format!("reading userauth request failed: {error}"))?
                .ok_or_else(|| "client closed before userauth request".to_owned())?;
            if frame.number != MSG_SERVICE_REQUEST {
                return Err(format!("expected SERVICE_REQUEST, got {}", frame.number));
            }
            writer
                .send(MSG_DISCONNECT, &payload)
                .await
                .map_err(|error| format!("sending disconnect failed: {error}"))?;
            match timeout(Duration::from_secs(2), reader.next())
                .await
                .map_err(|_| "client did not close after DISCONNECT".to_owned())?
            {
                Ok(Some(frame)) => Err(format!(
                    "client sent message {} after DISCONNECT",
                    frame.number
                )),
                Ok(None) | Err(_) => Ok(()),
            }
        });

        let client_transport = make_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_transport.identity.pin()),
        )
        .unwrap();
        let connection = client_transport
            .endpoint
            .connect(server_address, "fsh.local")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let result = auth
            .authenticate(
                &connection,
                FramedReader::new(recv),
                FramedWriter::new(send),
            )
            .await;
        assert!(matches!(result, Err(Error::RemoteDisconnect(_))));
        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        assert!(server_task.await.unwrap().is_ok());
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }
}
