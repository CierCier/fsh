use std::{env, net::SocketAddr, path::PathBuf, process};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser};
use fsh_core::{
    AuthorizedKeys, FramedReader, FramedWriter, ServerIdentity, ServerSession, SessionConfig,
    SpkiPin, UserAuthServer, make_server_endpoint,
};
use tokio::sync::oneshot;

#[derive(Debug, Parser)]
#[command(name = "fshd", about = "Serve FSH/QUIC remote-execution sessions")]
struct Args {
    /// UDP address on which to listen.
    #[arg(
        long,
        env = "FSHD_LISTEN",
        default_value = "0.0.0.0:4433",
        value_name = "ADDR"
    )]
    listen: SocketAddr,

    /// TLS certificate file (DER or PEM). Must be supplied with --key.
    #[arg(long, env = "FSHD_CERT", value_name = "FILE")]
    cert: Option<PathBuf>,

    /// TLS private key file (DER or PEM). Must be supplied with --cert.
    #[arg(long, env = "FSHD_KEY", value_name = "FILE")]
    key: Option<PathBuf>,

    /// OpenSSH authorized_keys file.
    #[arg(long, env = "FSHD_AUTHORIZED_KEYS", value_name = "FILE")]
    authorized_keys: Option<PathBuf>,

    /// Restrict authentication to this user name.
    #[arg(long, env = "FSHD_USER", value_name = "USER")]
    user: Option<String>,

    /// Increase diagnostic output (-v, -vv).
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        eprintln!("fshd: {error:#}");
        process::exit(1);
    }
}

async fn run(args: Args) -> Result<()> {
    let configured_username = args
        .user
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--user or FSHD_USER is required"))?;
    validate_username(configured_username)?;

    let (identity, certificate_path, private_key_path, generated) =
        load_server_identity(args.cert, args.key)?;
    let authorized_keys_path = args
        .authorized_keys
        .unwrap_or_else(default_authorized_keys_path);
    let authorized_keys = AuthorizedKeys::from_file(&authorized_keys_path)
        .with_context(|| format!("loading authorized keys {}", authorized_keys_path.display()))?;
    if authorized_keys.is_empty() {
        eprintln!(
            "fshd: warning: {} contains no authorized keys",
            authorized_keys_path.display()
        );
    }

    let pin = identity.pin();
    let transport = make_server_endpoint(args.listen, identity)
        .with_context(|| format!("binding UDP listener {}", args.listen))?;
    let endpoint = transport.endpoint;
    let bound_address = endpoint
        .local_addr()
        .context("reading bound listener address")?;
    eprintln!("fshd: listening on {bound_address}");
    eprintln!("fshd: server host pin {}", display_pin(pin));
    if generated {
        eprintln!(
            "fshd: generated server identity at {} and {}",
            certificate_path.display(),
            private_key_path.display()
        );
    }

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            result = &mut shutdown => {
                result.context("waiting for Ctrl-C")?;
                eprintln!("fshd: shutting down");
                endpoint.close(0u32.into(), b"server shutting down");
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let authorized_keys = authorized_keys.clone();
                let expected_username = args.user.clone();
                let verbose = args.verbose;
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            let peer = connection.remote_address();
                            if verbose > 0 {
                                eprintln!("fshd: accepted connection from {peer}");
                            }
                            let result = async {
                                let (send, recv) = connection
                                    .accept_bi()
                                    .await
                                    .context("waiting for the control stream")?;
                                let control_stream = send.id();
                                if control_stream.index() != 0
                                    || control_stream.initiator() != quinn::Side::Client
                                    || control_stream.dir() != quinn::Dir::Bi
                                    || recv.id() != control_stream
                                {
                                    connection.close(
                                        1u32.into(),
                                        b"first bidirectional stream must be the control stream",
                                    );
                                    bail!("first bidirectional stream was not stream 0");
                                }

                                let auth = UserAuthServer {
                                    authorized_keys,
                                    expected_username,
                                };
                                let (stop_tx, stop_rx) = oneshot::channel();
                                let quarantine = tokio::spawn(quarantine_pre_auth_streams(
                                    connection.clone(),
                                    stop_rx,
                                ));
                                let auth_result = auth
                                    .authenticate(
                                        &connection,
                                        FramedReader::new(recv),
                                        FramedWriter::new(send),
                                    )
                                    .await;
                                let _ = stop_tx.send(());
                                let _ = quarantine.await;
                                let (username, reader, writer) = auth_result
                                    .context("authenticating client")?;
                                if verbose > 0 {
                                    eprintln!("fshd: authenticated {username} from {peer}");
                                }
                                ServerSession::new(connection, reader, writer, SessionConfig::default())
                                    .run()
                                    .await
                                    .context("running session")
                            }
                            .await;
                            if let Err(error) = result {
                                eprintln!("fshd: connection from {peer} failed: {error:#}");
                            }
                        }
                        Err(error) => eprintln!("fshd: QUIC handshake failed: {error}"),
                    }
                });
            }
        }
    }

    endpoint.wait_idle().await;
    Ok(())
}

async fn quarantine_pre_auth_streams(
    connection: quinn::Connection,
    mut stop: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop => break,
            incoming = connection.accept_bi() => {
                match incoming {
                    Ok((mut send, mut recv)) => {
                        let _ = send.reset(quinn::VarInt::from_u32(1));
                        let _ = recv.stop(quinn::VarInt::from_u32(1));
                    }
                    Err(_) => break,
                }
            }
            incoming = connection.accept_uni() => {
                match incoming {
                    Ok(mut recv) => {
                        let _ = recv.stop(quinn::VarInt::from_u32(1));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

fn load_server_identity(
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
) -> Result<(ServerIdentity, PathBuf, PathBuf, bool)> {
    let (certificate, private_key) = match (certificate, private_key) {
        (Some(certificate), Some(private_key)) => (certificate, private_key),
        (None, None) => (default_certificate_path(), default_private_key_path()),
        _ => bail!("--cert and --key must be supplied together"),
    };

    match (certificate.exists(), private_key.exists()) {
        (true, true) => Ok((
            ServerIdentity::load(&certificate, &private_key).with_context(|| {
                format!(
                    "loading server identity {} and {}",
                    certificate.display(),
                    private_key.display()
                )
            })?,
            certificate,
            private_key,
            false,
        )),
        (false, false) => Ok((
            ServerIdentity::generate(&certificate, &private_key).with_context(|| {
                format!(
                    "generating server identity {} and {}",
                    certificate.display(),
                    private_key.display()
                )
            })?,
            certificate,
            private_key,
            true,
        )),
        _ => bail!(
            "server identity is incomplete: {} and {} must either both exist or both be absent",
            certificate.display(),
            private_key.display()
        ),
    }
}

fn default_state_dir() -> PathBuf {
    if let Some(path) = env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(path).join("fsh");
    }
    home_dir()
        .map(|home| home.join(".local").join("state").join("fsh"))
        .unwrap_or_else(|| PathBuf::from(".fsh"))
}

fn default_certificate_path() -> PathBuf {
    default_state_dir().join("server-cert.der")
}

fn default_private_key_path() -> PathBuf {
    default_state_dir().join("server-key.der")
}

fn default_authorized_keys_path() -> PathBuf {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(path).join("fsh").join("authorized_keys");
    }
    home_dir()
        .map(|home| home.join(".config").join("fsh").join("authorized_keys"))
        .unwrap_or_else(|| PathBuf::from("authorized_keys"))
}

fn display_pin(pin: SpkiPin) -> String {
    let encoded = pin.encoded();
    if encoded.starts_with("FSH-SHA256:") {
        encoded
    } else {
        let encoded = encoded.strip_prefix("sha256/").unwrap_or(&encoded);
        format!("FSH-SHA256:{}", encoded.trim_end_matches('='))
    }
}

fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        bail!("--user must not be empty");
    }
    if username.len() > 256 {
        bail!("--user must be at most 256 bytes");
    }
    Ok(())
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}
