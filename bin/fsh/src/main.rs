use std::{
    env,
    io::{self, IsTerminal, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    process,
};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser};
use fsh_core::{
    ClientSession, ClientTransport, Command, ExitStatus, Identity, KnownHosts, SessionConfig,
    SpkiPin, UserAuthClient, make_client_endpoint, signal_number,
};

#[derive(Debug, Parser)]
#[command(name = "fsh", about = "Run a command over an FSH/QUIC connection")]
struct Args {
    /// Server host name or IP address.
    #[arg(value_name = "HOST")]
    host: String,

    /// Server UDP port.
    #[arg(short = 'p', long, default_value_t = 4433)]
    port: u16,

    /// Remote user name.
    #[arg(short = 'l', long, env = "FSH_USER", default_value_t = default_username())]
    user: String,

    /// OpenSSH private key used for public-key authentication.
    #[arg(short = 'i', long, env = "FSH_IDENTITY", value_name = "FILE")]
    identity: Option<PathBuf>,

    /// Passphrase for an encrypted identity (or set FSH_PASSPHRASE).
    #[arg(
        long,
        env = "FSH_PASSPHRASE",
        hide_env_values = true,
        value_name = "PASSPHRASE"
    )]
    passphrase: Option<String>,

    /// FSH host pin database.
    #[arg(long, env = "FSH_KNOWN_HOSTS", value_name = "FILE")]
    known_hosts: Option<PathBuf>,

    /// Trust and save a previously unseen server host pin without prompting.
    #[arg(long)]
    accept_new: bool,

    /// Command string to execute. Omit it to start a shell.
    #[arg(
        short = 'c',
        long,
        value_name = "COMMAND",
        conflicts_with = "command_args"
    )]
    command: Option<String>,

    /// Command and arguments to execute.
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        conflicts_with = "command"
    )]
    command_args: Vec<String>,

    /// Increase diagnostic output (-v, -vv).
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() {
    let exit_code = match run(Args::parse()).await {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("fsh: {error:#}");
            1
        }
    };
    process::exit(exit_code);
}

async fn run(args: Args) -> Result<i32> {
    let host = normalize_host(&args.host)?;
    if args.port == 0 {
        bail!("--port must not be zero");
    }
    validate_username(&args.user)?;
    let command = requested_command(&args);

    let identity_path = args.identity.unwrap_or_else(default_identity_path);
    let identity = Identity::load(&identity_path, args.passphrase.as_deref())
        .with_context(|| format!("loading identity {}", identity_path.display()))?;
    let known_hosts_path = args.known_hosts.unwrap_or_else(default_known_hosts_path);
    let mut known_hosts = KnownHosts::load(&known_hosts_path)
        .with_context(|| format!("loading known hosts {}", known_hosts_path.display()))?;

    let expected_pins = match known_hosts.pins(&host, args.port) {
        Some(pins) => pins.iter().copied().collect(),
        None => {
            let pin = probe_server_pin(&host, args.port).await?;
            accept_new_host(&host, args.port, pin, args.accept_new)?;
            known_hosts
                .insert(&host, args.port, pin)
                .with_context(|| format!("saving known hosts {}", known_hosts.path().display()))?;
            log_info(
                args.verbose,
                format_args!("saved host pin for {host}:{}", args.port),
            );
            vec![pin]
        }
    };

    // Keep the endpoint alive for the lifetime of its session.
    let (_transport, mut session) =
        connect_session(&host, args.port, &expected_pins, &args.user, &identity).await?;
    log_info(args.verbose, format_args!("authenticated as {}", args.user));

    let mut input = tokio::io::stdin();
    let mut output = tokio::io::stdout();
    let mut error_output = tokio::io::stderr();
    let status = session
        .exec(command, &mut input, &mut output, &mut error_output)
        .await
        .context("running remote command")?;

    exit_status_code(status)
}

async fn connect_session(
    host: &str,
    port: u16,
    expected_pins: &[SpkiPin],
    username: &str,
    identity: &Identity,
) -> Result<(ClientTransport, ClientSession)> {
    let addresses = resolve_addresses(host, port).await?;
    let mut failures = Vec::new();

    for remote in addresses {
        for expected_pin in expected_pins {
            let transport =
                match make_client_endpoint(client_bind_address(remote), Some(*expected_pin)) {
                    Ok(transport) => transport,
                    Err(error) => {
                        failures.push(format!("{remote}: creating client endpoint: {error}"));
                        continue;
                    }
                };
            let auth = UserAuthClient {
                username: username.to_owned(),
                identity: identity.clone(),
            };
            match ClientSession::connect(
                &transport.endpoint,
                remote,
                host,
                auth,
                SessionConfig::default(),
            )
            .await
            {
                Ok(session) => return Ok((transport, session)),
                Err(error) => failures.push(format!("{remote}: {error}")),
            }
        }
    }

    bail!(
        "could not connect to {host}:{port}: {}",
        failures.join("; ")
    )
}

async fn probe_server_pin(host: &str, port: u16) -> Result<SpkiPin> {
    let addresses = resolve_addresses(host, port).await?;
    let mut failures = Vec::new();

    for remote in addresses {
        let transport = match make_client_endpoint(client_bind_address(remote), None) {
            Ok(transport) => transport,
            Err(error) => {
                failures.push(format!("{remote}: creating client endpoint: {error}"));
                continue;
            }
        };
        let connecting = match transport.endpoint.connect(remote, host) {
            Ok(connecting) => connecting,
            Err(error) => {
                failures.push(format!("{remote}: {error}"));
                continue;
            }
        };
        match connecting.await {
            Ok(connection) => {
                let pin = transport.observed_pin().ok_or_else(|| {
                    anyhow::anyhow!("TLS completed without reporting a server host pin")
                })?;
                connection.close(0u32.into(), b"host pin verified");
                transport.endpoint.close(0u32.into(), b"host pin verified");
                return Ok(pin);
            }
            Err(error) => failures.push(format!("{remote}: {error}")),
        }
    }

    bail!(
        "could not establish TLS with {host}:{port}: {}",
        failures.join("; ")
    )
}

async fn resolve_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}:{port}"))?
        .collect();
    if addresses.is_empty() {
        bail!("no addresses found for {host}:{port}");
    }
    Ok(addresses)
}

fn accept_new_host(host: &str, port: u16, pin: SpkiPin, accept_new: bool) -> Result<()> {
    if accept_new {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        bail!(
            "host key for {host}:{port} is unknown; refusing to trust it non-interactively (use --accept-new after verifying its fingerprint)"
        );
    }

    eprintln!("The authenticity of host '{host}:{port}' cannot be established.");
    eprintln!("{}", display_pin(pin));
    eprint!("Trust this host and add it to known hosts? [yes/no] ");
    io::stderr().flush().context("flushing host trust prompt")?;

    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .context("reading host trust response")?;
    if response.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("host key for {host}:{port} was not accepted")
    }
}

fn requested_command(args: &Args) -> Command {
    match (&args.command, args.command_args.is_empty()) {
        (Some(command), _) => Command::Exec(command.clone()),
        (None, true) => Command::Shell,
        (None, false) => Command::Exec(
            args.command_args
                .iter()
                .map(|argument| shell_quote(argument))
                .collect::<Vec<_>>()
                .join(" "),
        ),
    }
}

fn shell_quote(argument: &str) -> String {
    if argument.is_empty() {
        "''".to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn exit_status_code(status: ExitStatus) -> Result<i32> {
    match status {
        ExitStatus::Code(code) => Ok(i32::try_from(code).unwrap_or(1)),
        ExitStatus::Signal {
            name,
            core_dumped: _,
            message: _,
        } => {
            if let Some(number) = signal_number(&name) {
                eprintln!("fsh: remote command terminated by signal {name}");
                Ok(128 + number)
            } else {
                eprintln!("fsh: remote command terminated by signal {name}");
                Ok(1)
            }
        }
    }
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

fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        bail!("host must not be empty");
    }
    Ok(host.to_owned())
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

fn client_bind_address(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

fn default_username() -> String {
    env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn default_identity_path() -> PathBuf {
    home_dir()
        .map(|home| home.join(".ssh").join("id_ed25519"))
        .unwrap_or_else(|| PathBuf::from("id_ed25519"))
}

fn default_known_hosts_path() -> PathBuf {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(path).join("fsh").join("known_hosts");
    }
    home_dir()
        .map(|home| home.join(".config").join("fsh").join("known_hosts"))
        .unwrap_or_else(|| PathBuf::from("fsh-known-hosts"))
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

fn log_info(verbose: u8, message: impl std::fmt::Display) {
    if verbose > 0 {
        eprintln!("fsh: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_maps_remote_codes_directly() {
        assert_eq!(exit_status_code(ExitStatus::Code(0)).unwrap(), 0);
        assert_eq!(exit_status_code(ExitStatus::Code(7)).unwrap(), 7);
    }

    #[test]
    fn exit_status_maps_known_signals_to_128_plus_number() {
        let status = ExitStatus::Signal {
            name: "XCPU".into(),
            core_dumped: false,
            message: String::new(),
        };
        assert_eq!(exit_status_code(status).unwrap(), 128 + 24);
    }

    #[test]
    fn exit_status_survives_unknown_signal_names() {
        // A peer that reports an unknown signal name must not crash the
        // client or fabricate a wrong exit status.
        let status = ExitStatus::Signal {
            name: "BOGUS".into(),
            core_dumped: false,
            message: String::new(),
        };
        assert_eq!(exit_status_code(status).unwrap(), 1);
    }
}
