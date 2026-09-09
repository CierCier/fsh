//! A small, opinionated implementation of the FSH v0 protocol.
//!
//! The crate deliberately keeps the wire codec independent from the command
//! line applications.  This makes the framing, authentication transcript,
//! and transport policy usable by alternate clients and daemons.

mod auth;
mod connection;
mod error;
mod tls;
mod wire;

pub use auth::{AuthorizedKeys, Identity, UserAuthClient, UserAuthServer};
pub use connection::{ClientSession, Command, ServerSession, SessionConfig};
pub use error::{Error, Result};
pub use tls::{
    ClientTransport, KnownHosts, ServerIdentity, ServerTransport, SpkiPin, make_client_endpoint,
    make_server_endpoint,
};
pub use wire::{
    Decoder, Encoder, Frame, FramedReader, FramedWriter, MAX_FRAME_SIZE, MessageNumber,
};

/// The ALPN token for the v0 protocol.
pub const ALPN: &[u8] = b"fsh/1";

/// The exact TLS exporter label used to bind public-key authentication to a
/// particular QUIC connection.
pub const EXPORTER_LABEL: &[u8] = b"fsh-binding-v0";

/// The length of the exporter binding used in authentication signatures.
pub const EXPORTER_LEN: usize = 32;

/// Return the v0 TLS exporter binding for a connected QUIC session.
pub fn exporter_binding(connection: &quinn::Connection) -> Result<[u8; EXPORTER_LEN]> {
    let mut binding = [0u8; EXPORTER_LEN];
    connection
        .export_keying_material(&mut binding, EXPORTER_LABEL, &[])
        .map_err(|_| Error::Protocol("TLS exporter is unavailable".into()))?;
    Ok(binding)
}
