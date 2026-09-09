use thiserror::Error;

/// Errors returned by the FSH protocol implementation.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("QUIC connection error: {0}")]
    Quic(#[from] quinn::ConnectionError),

    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("QUIC stream write error: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("QUIC stream read error: {0}")]
    Read(#[from] quinn::ReadError),

    #[error("TLS configuration error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("wire error: {0}")]
    Wire(#[from] crate::wire::WireError),

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("channel protocol error: {0}")]
    ChannelProtocol(String),

    #[error("peer disconnected: {0}")]
    RemoteDisconnect(String),

    #[error("host key pin mismatch for {host}: expected {expected}, got {actual}")]
    HostKeyMismatch {
        host: String,
        expected: String,
        actual: String,
    },

    #[error("host key for {host} is not trusted yet (pin {pin})")]
    HostKeyUnknown { host: String, pin: String },

    #[error("certificate does not contain a usable public-key pin")]
    InvalidCertificate,

    #[error("unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("command failed: {0}")]
    Command(String),
}

pub type Result<T> = std::result::Result<T, Error>;
