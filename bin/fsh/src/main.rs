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
    ClientSession, ClientTransport, Command, ExitStatus, Identity, KnownHosts, PtyRequest,
    SessionConfig, SpkiPin, UserAuthClient, make_client_endpoint, signal_number,
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
    // Interactive terminal plus bare `fsh host` shell: attach a pty. Every
    // other combination (piped stdin, explicit command) keeps the existing
    // pipe behavior byte-identical.
    let status = if matches!(&command, Command::Shell) && io::stdin().is_terminal() {
        run_interactive_shell(&mut session, &mut input, &mut output, &mut error_output).await?
    } else {
        session
            .exec(command, &mut input, &mut output, &mut error_output)
            .await
            .context("running remote command")?
    };

    exit_status_code(status)
}

/// Run a shell attached to a server-side pty: raw local tty, `pty-req` with
/// the current `TERM`/winsize before the shell request, and `window-change`
/// updates on resize. A refused `pty-req` falls back to a pipe shell.
async fn run_interactive_shell(
    session: &mut ClientSession,
    input: &mut tokio::io::Stdin,
    stdout: &mut tokio::io::Stdout,
    stderr: &mut tokio::io::Stderr,
) -> Result<ExitStatus> {
    // Raw mode for the whole session; the guard restores termios on return.
    let _raw = enable_raw_mode();
    let term = client_term();
    let (cols, rows) = pty_size();
    let (resize_tx, resize_rx) = tokio::sync::mpsc::channel::<(u32, u32)>(8);
    // Resize poller: re-check the winsize each iteration (immediately, then
    // every second) and forward changes; exits when the session drops the
    // receiver or the session ends.
    let poller = tokio::spawn(async move {
        let mut last = (cols, rows);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if let Some(size) = terminal_winsize()
                && size != last
            {
                last = size;
                if resize_tx.send(size).await.is_err() {
                    break;
                }
            }
        }
    });
    let result = session
        .exec_pty(
            Command::Shell,
            PtyRequest { term, cols, rows },
            resize_rx,
            input,
            stdout,
            stderr,
        )
        .await;
    poller.abort();
    let _ = poller.await;
    match result {
        Ok(status) => Ok(status),
        Err(fsh_core::Error::Command(_)) => {
            // The server refused the pty: restore canonical mode first so the
            // fallback behaves exactly like the historical pipe shell.
            drop(_raw);
            eprintln!("fsh: server refused pty allocation; falling back to pipe");
            session
                .exec(Command::Shell, input, stdout, stderr)
                .await
                .context("running remote command")
        }
        Err(error) => Err(error).context("running remote command"),
    }

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

// Interactive-shell TTY support. Used only when stdin is a terminal and the
// request is `Command::Shell` (bare `fsh host`); pipe and explicit-command
// paths never call these.

/// Linux `struct termios` (glibc layout).
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

// Direct libc syscalls only (no TUI crate): raw mode needs TCGETS/TCSETS and
// resize polling needs TIOCGWINSZ, none of which `std` exposes.
unsafe extern "C" {
    fn ioctl(
        fd: std::os::raw::c_int,
        request: std::os::raw::c_ulong,
        ...
    ) -> std::os::raw::c_int;
}

const TCGETS: std::os::raw::c_ulong = 0x5401;
const TCSETS: std::os::raw::c_ulong = 0x5402;
const TIOCGWINSZ: std::os::raw::c_ulong = 0x5413;

/// Apply the `cfmakeraw` equivalent: no line buffering or echo, no
/// `ISIG`/`IXON` handling, 8-bit clean, `read` returns after 1 byte.
/// Signal generation stays off so bytes like `0x03` (Ctrl-C) travel to the
/// server pty, whose kernel delivers `SIGINT` to the remote foreground.
fn make_raw(termios: &mut Termios) {
    // iflag: INBRK | BRKINT | ISTRIP | ICRNL | IXON
    termios.c_iflag &= !(0x1 | 0x2 | 0x20 | 0x100 | 0x400);
    // oflag: OPOST
    termios.c_oflag &= !0x1;
    // cflag: clear CSIZE | PARENB, then set CS8
    termios.c_cflag &= !(0x30 | 0x100);
    termios.c_cflag |= 0x30;
    // lflag: ECHO | ICANON | IEXTEN | ISIG
    termios.c_lflag &= !(0x8 | 0x2 | 0x8000 | 0x100);
    // VMIN = 1, VTIME = 0
    termios.c_cc[6] = 1;
    termios.c_cc[5] = 0;
}

/// Restores the saved termios for every fd it changed when dropped.
struct RawGuard {
    saved: Vec<(std::os::raw::c_int, Termios)>,
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        for (fd, saved) in &self.saved {
            // Best effort: nothing useful to do with a failure while exiting.
            unsafe {
                ioctl(*fd, TCSETS, saved);
            }
        }
    }
}

/// Put stdin/stdout into raw mode wherever they are terminals. Fds that are
/// not terminals (pipes, redirects) are left untouched.
fn enable_raw_mode() -> Option<RawGuard> {
    let mut saved = Vec::new();
    for fd in [0, 1] {
        let mut current: Termios = unsafe { std::mem::zeroed() };
        // SAFETY: `TCGETS` only writes `struct termios` when `fd` is a
        // terminal; otherwise it fails and `current` stays untouched.
        if unsafe { ioctl(fd, TCGETS, &mut current) } != 0 {
            continue;
        }
        let mut raw = current;
        make_raw(&mut raw);
        // SAFETY: `raw` is a valid `struct termios` derived from this fd.
        if unsafe { ioctl(fd, TCSETS, &raw) } != 0 {
            continue;
        }
        saved.push((fd, current));
    }
    if saved.is_empty() {
        None
    } else {
        Some(RawGuard { saved })
    }
}

/// Current terminal size, clamped to the `pty-req` wire bounds. Prefers
/// stdin (the tty that gates interactive mode), falls back to stdout.
fn terminal_winsize() -> Option<(u32, u32)> {
    let mut size = Winsize::default();
    // SAFETY: `TIOCGWINSZ` only writes `struct winsize` on success.
    let ok = unsafe { ioctl(0, TIOCGWINSZ, &mut size) } == 0
        || unsafe { ioctl(1, TIOCGWINSZ, &mut size) } == 0;
    if !ok || (size.ws_col == 0 && size.ws_row == 0) {
        return None;
    }
    Some((clamp_dim(size.ws_col), clamp_dim(size.ws_row)))
}

fn clamp_dim(value: u16) -> u32 {
    (value as u32).clamp(1, 1024)
}

fn pty_size() -> (u32, u32) {
    terminal_winsize().unwrap_or((80, 24))
}

fn client_term() -> String {
    sanitize_term(&env::var("TERM").unwrap_or_default())
}

/// Clamp `TERM` to the wire contract: 1-64 printable ASCII chars, defaulting
/// to `xterm-256color` when nothing usable remains.
fn sanitize_term(value: &str) -> String {
    let term: String = value
        .bytes()
        .filter(|byte| (0x20..=0x7E).contains(byte))
        .take(64)
        .map(char::from)
        .collect();
    if term.is_empty() {
        String::from("xterm-256color")
    } else {
        term
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

    #[test]
    fn term_defaults_when_empty_or_unusable() {
        assert_eq!(sanitize_term(""), "xterm-256color");
        assert_eq!(sanitize_term("\u{0}\u{1b}[31m"), "[31m");
        assert_eq!(sanitize_term("xterm-256color"), "xterm-256color");
    }

    #[test]
    fn term_truncates_to_wire_limit() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_term(&long), "a".repeat(64));
    }

    #[test]
    fn winsize_dims_stay_in_wire_bounds() {
        assert_eq!(clamp_dim(0), 1);
        assert_eq!(clamp_dim(80), 80);
        assert_eq!(clamp_dim(5000), 1024);
    }

    #[test]
    fn make_raw_clears_canonical_mode_and_echo() {
        let mut termios: Termios = unsafe { std::mem::zeroed() };
        termios.c_iflag = 0xffff;
        termios.c_oflag = 0xffff;
        termios.c_cflag = 0xffff;
        termios.c_lflag = 0xffff;
        make_raw(&mut termios);
        // ICANON | ECHO | ISIG | IEXTEN cleared.
        assert_eq!(termios.c_lflag & (0x2 | 0x8 | 0x100 | 0x8000), 0);
        // OPOST cleared; CS8 set.
        assert_eq!(termios.c_oflag & 0x1, 0);
        assert_eq!(termios.c_cflag & 0x30, 0x30);
        assert_eq!(termios.c_cc[6], 1);
        assert_eq!(termios.c_cc[5], 0);
    }

}
