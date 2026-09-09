use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    pin::Pin,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command as TokioCommand,
    sync::{Mutex, mpsc, oneshot},
    task::JoinSet,
};

use crate::auth::UserAuthClient;
use crate::wire::{Decoder, Encoder, Frame, FramedReader, FramedWriter, MAX_FRAME_SIZE, WireError};
use crate::{Error, Result};

pub const MSG_GLOBAL_REQUEST: u8 = 80;
pub const MSG_REQUEST_SUCCESS: u8 = 81;
pub const MSG_REQUEST_FAILURE: u8 = 82;
pub const MSG_CHANNEL_OPEN: u8 = 90;
pub const MSG_CHANNEL_OPEN_CONFIRM: u8 = 91;
pub const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const MSG_CHANNEL_DATA: u8 = 94;
pub const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const MSG_CHANNEL_EOF: u8 = 96;
pub const MSG_CHANNEL_CLOSE: u8 = 97;
pub const MSG_CHANNEL_REQUEST: u8 = 98;
pub const MSG_CHANNEL_SUCCESS: u8 = 99;
pub const MSG_CHANNEL_FAILURE: u8 = 100;

const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_UNIMPLEMENTED: u8 = 3;
const MSG_DEBUG: u8 = 4;
const STDERR_TYPE: u32 = 1;
const MAX_CHANNELS: usize = 64;
const MAX_COMMAND_BYTES: usize = 16_384;
const MAX_SIGNAL_BYTES: usize = 16;
const MAX_PENDING_SIGNALS: usize = 16;
const MAX_SUBSYSTEM_BYTES: usize = 64;
const CLOSE_DRAIN_GRACE: Duration = Duration::from_millis(100);
const PREOPEN_HANDOFF_QUIET: Duration = Duration::from_millis(2);
const DISCONNECT_DELIVERY_GRACE: Duration = Duration::from_millis(250);
const MAX_PENDING_CHANNEL_REQUESTS: usize = 16;

type ControlWriter = Arc<Mutex<FramedWriter<quinn::SendStream>>>;
type IncomingChannelStream = (quinn::SendStream, quinn::RecvStream);
type ChannelStream = (quinn::SendStream, FramedReader<quinn::RecvStream>);

struct PendingGlobalGuard {
    pending: Arc<AtomicBool>,
    connection: quinn::Connection,
    completed: bool,
}

impl PendingGlobalGuard {
    fn complete(&mut self) {
        self.pending.store(false, Ordering::Release);
        self.completed = true;
    }
}

impl Drop for PendingGlobalGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.connection
                .close(1u32.into(), b"global request cancelled");
        }
        self.pending.store(false, Ordering::Release);
    }
}

struct ActiveChannelGuard {
    active: Arc<AtomicBool>,
    connection: quinn::Connection,
    released: bool,
}

impl ActiveChannelGuard {
    fn release(&mut self) {
        self.active.store(false, Ordering::Release);
        self.released = true;
    }
}

impl Drop for ActiveChannelGuard {
    fn drop(&mut self) {
        if !self.released {
            self.active.store(false, Ordering::Release);
            self.connection
                .close(1u32.into(), b"client channel task cancelled");
        }
    }
}

struct ClientControlReader {
    frames: Mutex<mpsc::Receiver<std::result::Result<Frame, WireError>>>,
}

#[derive(Clone, Copy)]
struct CleanupPolicy {
    input_done: bool,
    deliver_data: bool,
}

impl ClientControlReader {
    async fn next(&self) -> std::result::Result<Option<Frame>, WireError> {
        self.frames.lock().await.recv().await.transpose()
    }
}

/// Runtime limits used by both client and daemon.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub max_channels: usize,
    pub close_timeout: Duration,
    pub request_timeout: Duration,
    pub max_command_bytes: usize,
    /// Shell program for `shell` requests. When unset the daemon resolves the
    /// login shell of the account it runs as.
    pub login_shell: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_channels: MAX_CHANNELS,
            close_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_command_bytes: MAX_COMMAND_BYTES,
            login_shell: None,
        }
    }
}

/// A command binding for a session channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Exec(String),
    Shell,
}

/// The terminal state reported by a remote session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitStatus {
    Code(u32),
    Signal {
        name: String,
        core_dumped: bool,
        message: String,
    },
}

/// An authenticated client-side FSH connection.
pub struct ClientSession {
    connection: quinn::Connection,
    control_reader: ClientControlReader,
    control_writer: ControlWriter,
    dispatcher: tokio::task::JoinHandle<()>,
    active_channel: Arc<AtomicBool>,
    config: SessionConfig,
    closed_channels: HashSet<u32>,
    pending_global: Arc<AtomicBool>,
}

impl ClientSession {
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        remote: SocketAddr,
        server_name: &str,
        auth: UserAuthClient,
        config: SessionConfig,
    ) -> Result<Self> {
        let connection = endpoint.connect(remote, server_name)?.await?;
        let (send, recv) = connection.open_bi().await?;
        let stream_id = send.id();
        if stream_id.index() != 0
            || stream_id.initiator() != quinn::Side::Client
            || stream_id.dir() != quinn::Dir::Bi
            || recv.id() != stream_id
        {
            connection.close(1u32.into(), b"invalid control stream");
            return Err(Error::Protocol(
                "first bidirectional stream is not control stream".into(),
            ));
        }
        let reader = FramedReader::new(recv);
        let writer = FramedWriter::new(send);
        let (reader, writer) = auth.authenticate(&connection, reader, writer).await?;
        let control_writer = Arc::new(Mutex::new(writer));
        let active_channel = Arc::new(AtomicBool::new(false));
        let pending_global = Arc::new(AtomicBool::new(false));
        let (control_reader, dispatcher) = spawn_client_dispatcher(
            connection.clone(),
            reader,
            Arc::clone(&control_writer),
            Arc::clone(&active_channel),
            Arc::clone(&pending_global),
        );
        Ok(Self {
            connection,
            control_reader,
            control_writer,
            dispatcher,
            active_channel,
            config,
            closed_channels: HashSet::new(),
            pending_global,
        })
    }

    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    async fn abort_protocol(&self, description: &str) {
        if self.connection.close_reason().is_none() {
            let _ = send_disconnect(&self.connection, &self.control_writer, description).await;
        }
    }

    async fn abort_protocol_before(&self, deadline: tokio::time::Instant, description: &str) {
        if self.connection.close_reason().is_none() {
            let _ = tokio::time::timeout_at(
                deadline,
                send_disconnect(&self.connection, &self.control_writer, description),
            )
            .await;
            self.connection
                .close(1u32.into(), b"connection protocol error");
        }
    }

    /// Send the v0 keepalive request. Global requests are stop-and-wait: this
    /// method does not return until its single reply has been consumed.
    pub async fn keepalive(&mut self) -> Result<bool> {
        if self.pending_global.swap(true, Ordering::AcqRel) {
            return Err(Error::Protocol("global request already outstanding".into()));
        }
        let mut pending = PendingGlobalGuard {
            pending: Arc::clone(&self.pending_global),
            connection: self.connection.clone(),
            completed: false,
        };
        let deadline = tokio::time::Instant::now() + self.config.request_timeout;
        let send_result = tokio::time::timeout_at(
            deadline,
            send_control(
                &self.control_writer,
                MSG_GLOBAL_REQUEST,
                encode_global_request("keepalive@fsh.dev", true),
            ),
        )
        .await;
        match send_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.abort_protocol_before(deadline, "global request write failed")
                    .await;
                return Err(error);
            }
            Err(_) => {
                self.abort_protocol_before(deadline, "global request timed out")
                    .await;
                return Err(Error::Protocol("global request timed out".into()));
            }
        }
        let result = tokio::time::timeout_at(deadline, async {
            loop {
                let frame = match self.control_reader.next().await {
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        return Err(Error::Protocol(
                            "control stream closed during keepalive".into(),
                        ));
                    }
                    Err(error) => {
                        return Err(error.into());
                    }
                };
                match frame.number {
                    MSG_DISCONNECT => {
                        return Err(received_disconnect(&self.connection, &frame.payload));
                    }
                    MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => {
                        self.consume_global_reply(frame.number, &frame.payload)?;
                        return Ok(frame.number == MSG_REQUEST_SUCCESS);
                    }
                    MSG_GLOBAL_REQUEST => {
                        self.handle_global_request(&frame.payload).await?;
                    }
                    MSG_UNIMPLEMENTED => {
                        validate_unimplemented(&frame.payload)?;
                        return Err(Error::Protocol(
                            "server did not accept the keepalive request".into(),
                        ));
                    }
                    number if number >= 192 => {}
                    number => {
                        send_unimplemented(&self.control_writer, number).await?;
                    }
                }
            }
        })
        .await;
        match result {
            Ok(result) => match result {
                Ok(result) => {
                    pending.complete();
                    Ok(result)
                }
                Err(error) => {
                    if matches!(error, Error::RemoteDisconnect(_)) {
                        self.connection.close(0u32.into(), b"peer disconnected");
                    } else {
                        self.abort_protocol_before(deadline, "keepalive protocol error")
                            .await;
                    }
                    Err(error)
                }
            },
            Err(_) => {
                self.abort_protocol_before(deadline, "global request timed out")
                    .await;
                Err(Error::Protocol("global request timed out".into()))
            }
        }
    }

    /// Execute one session channel. The API is deliberately sequential on a
    /// client session; the daemon still permits independent concurrent channels.
    pub async fn exec<R, W, E>(
        &mut self,
        command: Command,
        input: &mut R,
        stdout: &mut W,
        stderr: &mut E,
    ) -> Result<ExitStatus>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
        E: AsyncWrite + Unpin,
    {
        let result = self.exec_inner(command, input, stdout, stderr).await;
        if matches!(&result, Err(Error::Protocol(_)) | Err(Error::Wire(_))) {
            self.abort_protocol("connection protocol error").await;
        }
        result
    }

    async fn exec_inner<R, W, E>(
        &mut self,
        command: Command,
        input: &mut R,
        stdout: &mut W,
        stderr: &mut E,
    ) -> Result<ExitStatus>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
        E: AsyncWrite + Unpin,
    {
        let (data_send, data_recv) = self.connection.open_bi().await?;
        let stream_id = data_send.id();
        if stream_id.index() == 0
            || stream_id.index() > u32::MAX as u64
            || stream_id.initiator() != quinn::Side::Client
            || stream_id.dir() != quinn::Dir::Bi
        {
            return Err(Error::Protocol("invalid client channel stream id".into()));
        }
        let channel_id = stream_id.index() as u32;
        let mut active = self.begin_channel_activity()?;
        let mut data_writer = FramedWriter::new(data_send);
        let mut data_reader = FramedReader::new(data_recv);

        send_control(
            &self.control_writer,
            MSG_CHANNEL_OPEN,
            encode_open(channel_id),
        )
        .await?;
        if let Err(error) = self.await_open(channel_id).await {
            active.release();
            reset_stream(data_writer.into_inner(), data_reader.into_inner());
            self.closed_channels.insert(channel_id);
            return Err(error);
        }

        // Quinn does not make an incoming bidirectional stream visible to the
        // peer until its opener has written or finished it.  An empty DATA
        // message is a legal, no-op stdin message and activates the stream
        // without violating the post-confirmation data rule.
        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_data(channel_id, &[])?)
            .await?;
        send_control(
            &self.control_writer,
            MSG_CHANNEL_REQUEST,
            encode_channel_request(channel_id, &command)?,
        )
        .await?;
        if let Err(error) = self.await_channel_success(channel_id).await {
            if matches!(error, Error::Command(_)) {
                // CHANNEL_FAILURE rejects the binding, not the already-open
                // channel stream. Close it through the normal EOF/FIN path;
                // RESET_STREAM is reserved for an open failure or abort.
                let cleanup = self
                    .close_rejected_request(
                        channel_id,
                        data_writer,
                        data_reader,
                        stdout,
                        stderr,
                        CleanupPolicy {
                            input_done: false,
                            deliver_data: true,
                        },
                    )
                    .await;
                cleanup?;
                active.release();
            } else {
                // Confirmation has already created a channel. A timeout or
                // malformed reply cannot satisfy the channel drain
                // preconditions, so abort the connection rather than
                // resetting an active stream while data may still be in
                // flight.
                self.abort_protocol("channel request failed").await;
                self.connection
                    .close(1u32.into(), b"channel request failed");
                drop(data_writer.into_inner());
                drop(data_reader.into_inner());
            }
            self.closed_channels.insert(channel_id);
            return Err(error);
        }

        let mut input_done = false;
        let mut output_fin = false;
        let mut peer_close = false;
        let mut peer_eof = false;
        let mut local_close = false;
        let mut exit_status = None;
        let mut close_deadline: Option<Pin<Box<tokio::time::Sleep>>> = None;
        let mut input_buffer = vec![0u8; 16 * 1024];

        loop {
            // A command can finish while the caller still has stdin open
            // (for example, `exec true` from an interactive terminal). Once
            // the remote side has delivered its complete result, no input is
            // useful and the channel must still be drained and closed.
            if !input_done && (output_fin && exit_status.is_some() || peer_close) {
                if !peer_close {
                    send_control(
                        &self.control_writer,
                        MSG_CHANNEL_EOF,
                        encode_channel_id(channel_id),
                    )
                    .await?;
                }
                data_writer.finish().await?;
                input_done = true;
            }
            if !local_close && input_done && output_fin && (exit_status.is_some() || peer_close) {
                send_control(
                    &self.control_writer,
                    MSG_CHANNEL_CLOSE,
                    encode_channel_id(channel_id),
                )
                .await?;
                local_close = true;
                close_deadline = Some(Box::pin(tokio::time::sleep(self.config.close_timeout)));
            }
            if local_close && peer_close && output_fin {
                break;
            }

            tokio::select! {
                result = input.read(&mut input_buffer), if !input_done => {
                    let length = result?;
                    if length == 0 {
                        send_control(&self.control_writer, MSG_CHANNEL_EOF, encode_channel_id(channel_id)).await?;
                        data_writer.finish().await?;
                        input_done = true;
                    } else {
                        let payload = encode_channel_data(channel_id, &input_buffer[..length])?;
                        data_writer.send(MSG_CHANNEL_DATA, &payload).await?;
                    }
                }
                frame = data_reader.next(), if !output_fin => {
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(error) => {
                            let _ = tokio::time::timeout(
                                self.config.close_timeout,
                                data_reader.drain_to_end(),
                            )
                            .await;
                            let channel_error = Error::ChannelProtocol(format!(
                                "malformed channel data: {error}"
                            ));
                            let _ = self
                                .close_rejected_request(
                                    channel_id,
                                    data_writer,
                                    data_reader,
                                    stdout,
                                    stderr,
                                    CleanupPolicy {
                                        input_done,
                                        deliver_data: false,
                                    },
                                )
                                .await;
                            self.closed_channels.insert(channel_id);
                            return Err(channel_error);
                        }
                    };
                    match frame {
                        Some(frame) => {
                            if let Err(error) =
                                handle_client_data_frame(channel_id, frame, stdout, stderr).await
                            {
                                // Treat malformed peer data as a channel abort,
                                // but still order our EOF/FIN before CLOSE and
                                // drain the peer's final close when possible.
                                let _ = self
                                    .close_rejected_request(
                                        channel_id,
                                        data_writer,
                                        data_reader,
                                        stdout,
                                        stderr,
                                        CleanupPolicy {
                                            input_done,
                                            deliver_data: false,
                                        },
                                    )
                                    .await;
                                self.closed_channels.insert(channel_id);
                                return Err(error);
                            }
                            if let Some(deadline) = close_deadline.as_mut() {
                                deadline
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + self.config.close_timeout);
                            }
                        }
                        None => {
                            output_fin = true;
                            if exit_status.is_none() && close_deadline.is_none() {
                                close_deadline = Some(Box::pin(tokio::time::sleep(
                                    self.config.close_timeout,
                                )));
                            }
                        }
                    }
                }
                frame = self.control_reader.next(), if !peer_close => {
                    let frame = match frame {
                        Ok(Some(frame)) => frame,
                        Ok(None) => return Err(Error::Protocol("control stream closed during channel".into())),
                        Err(error) => return Err(error.into()),
                    };
                    if consume_transport_info(&frame)? {
                        continue;
                    }
                    match frame.number {
                        MSG_CHANNEL_EOF => {
                            if decode_channel_id(&frame.payload)? != channel_id {
                                return Err(Error::Protocol("CHANNEL_EOF references another channel".into()));
                            }
                            if peer_eof {
                                return Err(Error::Protocol("duplicate CHANNEL_EOF".into()));
                            }
                            peer_eof = true;
                            if close_deadline.is_none() {
                                close_deadline = Some(Box::pin(tokio::time::sleep(self.config.close_timeout)));
                            }
                        }
                        MSG_CHANNEL_CLOSE => {
                            let id = decode_channel_id(&frame.payload)?;
                            if id != channel_id && self.closed_channels.contains(&id) {
                                continue;
                            }
                            if id != channel_id {
                                return Err(Error::Protocol(
                                    "CHANNEL_CLOSE references another channel".into(),
                                ));
                            }
                            peer_close = true;
                            if close_deadline.is_none() {
                                close_deadline = Some(Box::pin(tokio::time::sleep(
                                    self.config.close_timeout,
                                )));
                            }
                        }
                        MSG_CHANNEL_REQUEST => {
                            let status = decode_exit_notification(channel_id, &frame.payload)?
                                .ok_or_else(|| {
                                    Error::Protocol(
                                        "unexpected channel request from server".into(),
                                    )
                                })?;
                            if exit_status.replace(status).is_some() {
                                return Err(Error::Protocol("duplicate exit notification".into()));
                            }
                            if close_deadline.is_none() {
                                close_deadline = Some(Box::pin(tokio::time::sleep(
                                    self.config.close_timeout,
                                )));
                            }
                        }
                        MSG_CHANNEL_OPEN_CONFIRM | MSG_CHANNEL_OPEN_FAILURE => {
                            return Err(Error::Protocol(
                                "unexpected channel open reply during channel".into(),
                            ));
                        }
                        MSG_CHANNEL_SUCCESS | MSG_CHANNEL_FAILURE => {
                            return Err(Error::Protocol(
                                "unexpected channel request reply during channel".into(),
                            ));
                        }
                        MSG_GLOBAL_REQUEST => self.handle_global_request(&frame.payload).await?,
                        MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => {
                            self.consume_global_reply(frame.number, &frame.payload)?;
                        }
                        MSG_UNIMPLEMENTED => {
                            validate_unimplemented(&frame.payload)?;
                        }
                        MSG_DISCONNECT => {
                            return Err(received_disconnect(&self.connection, &frame.payload));
                        }
                        number if number >= 192 => {}
                        number if number <= 191 => send_unimplemented(&self.control_writer, number).await?,
                        _ => {}
                    }
                }
                _ = async {
                    if let Some(deadline) = close_deadline.as_mut() {
                        deadline.as_mut().await;
                    }
                }, if close_deadline.is_some() && !(local_close && peer_close && output_fin) => {
                    if !input_done {
                        let _ = send_control(
                            &self.control_writer,
                            MSG_CHANNEL_EOF,
                            encode_channel_id(channel_id),
                        )
                        .await;
                        let _ = data_writer.finish().await;
                    }
                    self.connection
                        .close(1u32.into(), b"channel drain timed out");
                    drop(data_writer.into_inner());
                    drop(data_reader.into_inner());
                    self.closed_channels.insert(channel_id);
                    return Err(Error::Protocol("channel close timed out".into()));
                }
            }
        }

        let mut recv = data_reader.into_inner();
        let _ = recv.stop(quinn::VarInt::from_u32(0));
        let mut send = data_writer.into_inner();
        let _ = send.reset(quinn::VarInt::from_u32(0));
        stdout.flush().await?;
        stderr.flush().await?;
        self.closed_channels.insert(channel_id);
        let result = exit_status
            .ok_or_else(|| Error::Protocol("channel closed without exit notification".into()));
        active.release();
        result
    }

    fn begin_channel_activity(&self) -> Result<ActiveChannelGuard> {
        if self.active_channel.swap(true, Ordering::AcqRel) {
            return Err(Error::Protocol("another client channel is active".into()));
        }
        Ok(ActiveChannelGuard {
            active: Arc::clone(&self.active_channel),
            connection: self.connection.clone(),
            released: false,
        })
    }

    async fn close_rejected_request<W, E>(
        &mut self,
        channel_id: u32,
        mut data_writer: FramedWriter<quinn::SendStream>,
        mut data_reader: FramedReader<quinn::RecvStream>,
        stdout: &mut W,
        stderr: &mut E,
        policy: CleanupPolicy,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
        E: AsyncWrite + Unpin,
    {
        if !policy.input_done {
            let _ = send_control(
                &self.control_writer,
                MSG_CHANNEL_EOF,
                encode_channel_id(channel_id),
            )
            .await;
            let _ = data_writer.finish().await;
        }

        let deadline = tokio::time::sleep(self.config.close_timeout);
        tokio::pin!(deadline);
        let mut peer_close = false;
        let mut peer_fin = false;
        let mut local_close = false;
        let mut control_abort = false;
        let mut terminal_error = None;
        while !(peer_close && peer_fin) {
            if peer_fin && !local_close {
                match send_control(
                    &self.control_writer,
                    MSG_CHANNEL_CLOSE,
                    encode_channel_id(channel_id),
                )
                .await
                {
                    Ok(()) => local_close = true,
                    Err(error) => {
                        terminal_error = Some(error);
                        control_abort = true;
                        break;
                    }
                }
            }
            tokio::select! {
                _ = &mut deadline => break,
                frame = data_reader.next(), if !peer_fin => {
                    match frame {
                        Ok(Some(frame)) => {
                            if policy.deliver_data
                                && let Err(error) =
                                    handle_client_data_frame(channel_id, frame, stdout, stderr).await
                                && terminal_error.is_none()
                            {
                                terminal_error = Some(error);
                            }
                        }
                        Ok(None) => peer_fin = true,
                        Err(error) => {
                            terminal_error = Some(Error::ChannelProtocol(format!(
                                "malformed channel data: {error}"
                            )));
                            peer_fin = tokio::time::timeout(
                                self.config.close_timeout,
                                data_reader.drain_to_end(),
                            )
                            .await
                            .is_ok_and(|result| result.is_ok());
                            break;
                        }
                    }
                }
                frame = self.control_reader.next(), if !peer_close => {
                    match frame {
                        Ok(Some(frame)) if frame.number == MSG_DISCONNECT => {
                            terminal_error = Some(received_disconnect(&self.connection, &frame.payload));
                            control_abort = true;
                            break;
                        }
                        Ok(Some(frame)) if frame.number == MSG_CHANNEL_CLOSE => {
                            match decode_channel_id(&frame.payload) {
                                Ok(id) if id == channel_id => peer_close = true,
                                Ok(_) => {}
                                Err(error) => {
                                    terminal_error = Some(error);
                                    control_abort = true;
                                    break;
                                }
                            }
                        }
                        Ok(Some(frame)) => {
                            match consume_transport_info(&frame) {
                                Ok(true) => continue,
                                Ok(false) => {}
                                Err(error) => {
                                    terminal_error = Some(error);
                                    control_abort = true;
                                    break;
                                }
                            }
                            match frame.number {
                                MSG_GLOBAL_REQUEST => {
                                    if let Err(error) = self.handle_global_request(&frame.payload).await {
                                        terminal_error = Some(error);
                                        control_abort = true;
                                        break;
                                    }
                                }
                                MSG_CHANNEL_REQUEST => {
                                    let _ = decode_exit_notification(channel_id, &frame.payload);
                                }
                                MSG_UNIMPLEMENTED => {
                                    if let Err(error) = validate_unimplemented(&frame.payload) {
                                        terminal_error = Some(error);
                                        control_abort = true;
                                        break;
                                    }
                                }
                                number if number >= 192 => {}
                                number => {
                                    if let Err(error) = send_unimplemented(&self.control_writer, number).await {
                                        terminal_error = Some(error);
                                        control_abort = true;
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            terminal_error = Some(Error::Protocol("control stream closed during channel cleanup".into()));
                            control_abort = true;
                            break;
                        }
                        Err(error) => {
                            terminal_error = Some(error.into());
                            control_abort = true;
                            break;
                        }
                    }
                }
            }
        }

        if peer_fin && !local_close && !control_abort {
            if let Err(error) = send_control(
                &self.control_writer,
                MSG_CHANNEL_CLOSE,
                encode_channel_id(channel_id),
            )
            .await
            {
                terminal_error = Some(error);
                control_abort = true;
            } else {
                local_close = true;
            }
        }

        if control_abort {
            self.connection
                .close(1u32.into(), b"channel cleanup aborted");
            reset_stream(data_writer.into_inner(), data_reader.into_inner());
        } else if peer_close && peer_fin && local_close {
            let mut recv = data_reader.into_inner();
            let _ = recv.stop(quinn::VarInt::from_u32(0));
        } else if matches!(&terminal_error, Some(Error::ChannelProtocol(_))) {
            reset_stream(data_writer.into_inner(), data_reader.into_inner());
        } else {
            // A timeout cannot be repaired with a channel CLOSE: the peer FIN
            // precondition is still unknown. Tear down the connection instead
            // of truncating a potentially in-flight final DATA frame.
            self.connection
                .close(1u32.into(), b"channel drain timed out");
            reset_stream(data_writer.into_inner(), data_reader.into_inner());
        }

        terminal_error.map_or(Ok(()), Err)
    }

    async fn await_open(&mut self, channel_id: u32) -> Result<()> {
        let deadline = tokio::time::sleep(self.config.request_timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => return Err(Error::Protocol("channel open timed out".into())),
                frame = self.control_reader.next() => {
                    let frame = frame?.ok_or_else(|| Error::Protocol("control stream ended while opening channel".into()))?;
                    if consume_transport_info(&frame)? {
                        continue;
                    }
                    match frame.number {
                        MSG_CHANNEL_OPEN_CONFIRM if decode_channel_id(&frame.payload)? == channel_id => return Ok(()),
                        MSG_CHANNEL_OPEN_FAILURE => {
                            let (id, message) = decode_open_failure(&frame.payload)?;
                            if id == channel_id {
                                return Err(Error::Command(message));
                            }
                            return Err(Error::Protocol("channel open failure references another channel".into()));
                        }
                        MSG_GLOBAL_REQUEST => self.handle_global_request(&frame.payload).await?,
                        MSG_CHANNEL_REQUEST => {
                            let _ = decode_exit_notification(channel_id, &frame.payload)?
                                .ok_or_else(|| Error::Protocol("unexpected channel request while opening channel".into()))?;
                            return Err(Error::Protocol("exit notification arrived before channel request success".into()));
                        }
                        MSG_CHANNEL_OPEN_CONFIRM => return Err(Error::Protocol("reply references another channel".into())),
                        MSG_DISCONNECT => {
                            return Err(received_disconnect(&self.connection, &frame.payload));
                        }
                        MSG_CHANNEL_CLOSE => {
                            let id = decode_channel_id(&frame.payload)?;
                            if !self.closed_channels.contains(&id) {
                                return Err(Error::Protocol(
                                    "CHANNEL_CLOSE references an unknown channel".into(),
                                ));
                            }
                        }
                        MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => {
                            self.consume_global_reply(frame.number, &frame.payload)?;
                        }
                        MSG_UNIMPLEMENTED => validate_unimplemented(&frame.payload)?,
                        number if number >= 192 => {},
                        number => send_unimplemented(&self.control_writer, number).await?,
                    }
                }
            }
        }
    }

    async fn await_channel_success(&mut self, channel_id: u32) -> Result<()> {
        let deadline = tokio::time::sleep(self.config.request_timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => return Err(Error::Protocol("channel request timed out".into())),
                frame = self.control_reader.next() => {
                    let frame = frame?.ok_or_else(|| Error::Protocol("control stream ended while requesting channel".into()))?;
                    if consume_transport_info(&frame)? {
                        continue;
                    }
                    match frame.number {
                        MSG_CHANNEL_SUCCESS if decode_channel_id(&frame.payload)? == channel_id => return Ok(()),
                        MSG_CHANNEL_FAILURE if decode_channel_id(&frame.payload)? == channel_id => return Err(Error::Command("remote rejected channel request".into())),
                        MSG_DISCONNECT => {
                            return Err(received_disconnect(&self.connection, &frame.payload));
                        }
                        MSG_CHANNEL_CLOSE if decode_channel_id(&frame.payload)? == channel_id => {
                            return Err(Error::Protocol("channel closed while requesting channel".into()));
                        }
                        MSG_CHANNEL_CLOSE => {
                            let id = decode_channel_id(&frame.payload)?;
                            if !self.closed_channels.contains(&id) {
                                return Err(Error::Protocol(
                                    "CHANNEL_CLOSE references an unknown channel".into(),
                                ));
                            }
                        }
                        MSG_CHANNEL_REQUEST => {
                            let _ = decode_exit_notification(channel_id, &frame.payload)?
                                .ok_or_else(|| Error::Protocol("unexpected channel request while requesting channel".into()))?;
                            return Err(Error::Protocol("exit notification arrived before channel request success".into()));
                        }
                        MSG_GLOBAL_REQUEST => self.handle_global_request(&frame.payload).await?,
                        MSG_CHANNEL_SUCCESS | MSG_CHANNEL_FAILURE => return Err(Error::Protocol("reply references another channel".into())),
                        MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => {
                            self.consume_global_reply(frame.number, &frame.payload)?;
                        }
                        MSG_UNIMPLEMENTED => validate_unimplemented(&frame.payload)?,
                        number if number >= 192 => {},
                        number => send_unimplemented(&self.control_writer, number).await?,
                    }
                }
            }
        }
    }

    fn consume_global_reply(&mut self, _number: u8, payload: &[u8]) -> Result<()> {
        if !self.pending_global.load(Ordering::Acquire) {
            return Err(Error::Protocol("unsolicited global request reply".into()));
        }
        if !payload.is_empty() {
            return Err(Error::Protocol(
                "global request reply has trailing data".into(),
            ));
        }
        Ok(())
    }

    async fn handle_global_request(&self, payload: &[u8]) -> Result<()> {
        let mut decoder = Decoder::new(payload);
        let name = decoder.string()?;
        let want_reply = decoder.boolean()?;
        let keepalive = name == "keepalive@fsh.dev";
        decoder.finish()?;
        if want_reply {
            let number = if keepalive {
                MSG_REQUEST_SUCCESS
            } else {
                MSG_REQUEST_FAILURE
            };
            send_control(&self.control_writer, number, Vec::new()).await?;
        }
        Ok(())
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.dispatcher.abort();
    }
}

fn spawn_client_dispatcher(
    connection: quinn::Connection,
    mut reader: FramedReader<quinn::RecvStream>,
    writer: ControlWriter,
    active_channel: Arc<AtomicBool>,
    pending_global: Arc<AtomicBool>,
) -> (ClientControlReader, tokio::task::JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel(256);
    let dispatcher = tokio::spawn(async move {
        loop {
            tokio::select! {
                frame = reader.next() => {
                    match frame {
                        Ok(Some(frame)) => {
                            match consume_transport_info(&frame) {
                                Ok(true) => continue,
                                Ok(false) => {}
                                Err(_) => {
                                    let _ = send_disconnect(
                                        &connection,
                                        &writer,
                                        "malformed transport message",
                                    )
                                    .await;
                                    let _ = sender
                                        .send(Err(WireError::Malformed("malformed transport message")))
                                        .await;
                                    break;
                                }
                            }
                            if frame.number == MSG_GLOBAL_REQUEST {
                                if handle_server_global_request(&writer, &frame.payload).await.is_err() {
                                    let _ = send_disconnect(
                                        &connection,
                                        &writer,
                                        "malformed global request",
                                    )
                                    .await;
                                    let _ = sender
                                        .send(Err(WireError::Malformed("malformed global request")))
                                        .await;
                                    break;
                                }
                                continue;
                            }
                            if frame.number == MSG_DISCONNECT {
                                if sender.send(Ok(frame)).await.is_err() {
                                    break;
                                }
                                connection.close(0u32.into(), b"peer disconnected");
                                break;
                            }
                            if frame.number >= 192 {
                                continue;
                            }
                            if matches!(
                                frame.number,
                                MSG_CHANNEL_OPEN
                                    | MSG_CHANNEL_DATA
                                    | MSG_CHANNEL_EXTENDED_DATA
                            ) {
                                let _ = send_disconnect(
                                    &connection,
                                    &writer,
                                    "server sent a client-only channel message",
                                )
                                .await;
                                let _ = sender
                                    .send(Err(WireError::Malformed(
                                        "server sent a client-only channel message",
                                    )))
                                    .await;
                                break;
                            }
                            if matches!(frame.number, MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE)
                                && !pending_global.load(Ordering::Acquire)
                            {
                                let _ = send_disconnect(
                                    &connection,
                                    &writer,
                                    "unsolicited global request reply",
                                )
                                .await;
                                let _ = sender
                                    .send(Err(WireError::Malformed(
                                        "unsolicited global request reply",
                                    )))
                                    .await;
                                break;
                            }
                            if !is_client_control_message(frame.number) {
                                if send_unimplemented(&writer, frame.number).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                            if !active_channel.load(Ordering::Acquire)
                                && !matches!(
                                    frame.number,
                                    MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE
                                ) {
                                let _ = send_disconnect(
                                    &connection,
                                    &writer,
                                    "server sent channel control while idle",
                                )
                                .await;
                                let _ = sender
                                    .send(Err(WireError::Malformed(
                                        "server sent channel control while idle",
                                    )))
                                    .await;
                                break;
                            }
                            if sender.send(Ok(frame)).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => {
                            let _ = send_disconnect(
                                &connection,
                                &writer,
                                "control stream closed",
                            )
                            .await;
                            let _ = sender
                                .send(Err(WireError::Malformed("control stream closed")))
                                .await;
                            connection.close(1u32.into(), b"control stream ended");
                            break;
                        }
                        Err(error) => {
                            let _ = send_disconnect(
                                &connection,
                                &writer,
                                "malformed control stream",
                            )
                            .await;
                            let _ = sender.send(Err(error)).await;
                            connection.close(1u32.into(), b"malformed control stream");
                            break;
                        }
                    }
                }
                incoming = connection.accept_bi() => {
                    match incoming {
                        Ok((send, recv)) => {
                            reset_stream(send, recv);
                            let _ = send_disconnect(
                                &connection,
                                &writer,
                                "server opened a bidirectional channel stream",
                            )
                            .await;
                            let _ = sender
                                .send(Err(WireError::Malformed(
                                    "server opened a bidirectional channel stream",
                                )))
                                .await;
                        }
                        Err(_) => break,
                    }
                    break;
                }
                incoming = connection.accept_uni() => {
                    match incoming {
                        Ok(mut recv) => {
                            let _ = recv.stop(quinn::VarInt::from_u32(1));
                            let _ = send_disconnect(
                                &connection,
                                &writer,
                                "server opened a unidirectional stream",
                            )
                            .await;
                            let _ = sender
                                .send(Err(WireError::Malformed(
                                    "server opened a unidirectional stream",
                                )))
                                .await;
                        }
                        Err(_) => break,
                    }
                    break;
                }
            }
        }
    });
    (
        ClientControlReader {
            frames: Mutex::new(receiver),
        },
        dispatcher,
    )
}

/// A server-side authenticated session. Every client-created channel owns its
/// own QUIC stream and worker; control messages remain serialized on stream 0.
pub struct ServerSession {
    connection: quinn::Connection,
    control_reader: FramedReader<quinn::RecvStream>,
    control_writer: ControlWriter,
    config: SessionConfig,
}

impl ServerSession {
    pub fn new(
        connection: quinn::Connection,
        reader: FramedReader<quinn::RecvStream>,
        writer: FramedWriter<quinn::SendStream>,
        config: SessionConfig,
    ) -> Self {
        Self {
            connection,
            control_reader: reader,
            control_writer: Arc::new(Mutex::new(writer)),
            config,
        }
    }

    async fn handle_incoming_bi(
        &self,
        incoming: std::result::Result<IncomingChannelStream, quinn::ConnectionError>,
        channels: &mut HashMap<u32, ServerChannel>,
        seen: &HashSet<u32>,
        preopen: &mut HashMap<u32, PreopenState>,
        events_tx: &mpsc::UnboundedSender<WorkerEvent>,
    ) -> Result<()> {
        let (send, recv) = incoming?;
        let stream_id = send.id();
        let id = stream_id.index();
        if stream_id.initiator() != quinn::Side::Client
            || stream_id.dir() != quinn::Dir::Bi
            || id == 0
            || id > u32::MAX as u64
        {
            reset_stream(send, recv);
            return Ok(());
        }
        let id = id as u32;
        if preopen.contains_key(&id) {
            reset_stream(send, recv);
        } else if let Some(state) = channels.get_mut(&id) {
            if state.stream.is_some()
                || state.activation_handle.is_some()
                || state.worker_handle.is_some()
            {
                reset_stream(send, recv);
            } else {
                state.activation_handle = Some(start_channel_activation(
                    id,
                    send,
                    recv,
                    events_tx,
                    self.config.request_timeout,
                ));
                state.stream_deadline =
                    Some(tokio::time::Instant::now() + self.config.request_timeout);
            }
        } else if seen.contains(&id) {
            // An OPEN_FAILURE, an expired channel, or a completed channel
            // leaves a tombstone. A late stream for that id is an orphan and
            // must not become a new pre-open entry.
            reset_stream(send, recv);
        } else {
            // Do not probe an unknown stream inline. A peer can create a
            // stream before sending any bytes, and waiting for its first byte
            // here would stop control messages, worker events, and deadlines
            // for the whole session. The probe owns the stream until OPEN is
            // processed, and either discards pre-OPEN input or hands the
            // untouched stream to channel activation.
            if channels.len() + preopen.len() >= self.config.max_channels {
                reset_stream(send, recv);
                return Err(Error::Protocol("too many pre-open channel streams".into()));
            }
            let (command_tx, command_rx) = oneshot::channel();
            let handle = start_preopen_quarantine(id, send, recv, command_rx, events_tx);
            preopen.insert(
                id,
                PreopenState {
                    command_tx: Some(command_tx),
                    handle: Some(handle),
                    deadline: tokio::time::Instant::now() + self.config.request_timeout,
                },
            );
        }
        Ok(())
    }

    pub async fn run(mut self) -> Result<()> {
        let mut channels = HashMap::<u32, ServerChannel>::new();
        let mut seen = HashSet::<u32>::new();
        let mut preopen = HashMap::<u32, PreopenState>::new();
        let mut preopen_fin = HashSet::<u32>::new();
        let mut closed = HashSet::<u32>::new();
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let result = async {
            loop {
            let next_deadline = channels
                .values()
                .flat_map(|state| [state.stream_deadline, state.close_deadline])
                .flatten()
                .chain(preopen.values().map(|state| state.deadline))
                .min();
            tokio::select! {
                biased;
                incoming = self.connection.accept_bi() => {
                    self.handle_incoming_bi(
                        incoming,
                        &mut channels,
                        &seen,
                        &mut preopen,
                        &events_tx,
                    )
                    .await?;
                }
                frame = self.control_reader.next() => {
                    let frame = frame?.ok_or_else(|| Error::Protocol("control stream closed".into()))?;
                    if consume_transport_info(&frame)? {
                        continue;
                    }
                    match frame.number {
                        MSG_CHANNEL_OPEN => {
                            let (id, kind) = decode_open(&frame.payload)?;
                            if let Some(mut preopen_state) = preopen.remove(&id) {
                                seen.insert(id);
                                if let Some(command_tx) = preopen_state.command_tx.take() {
                                    let accepted = kind == "session"
                                        && channels.len() < self.config.max_channels;
                                    if accepted {
                                        if command_tx.send(PreopenCommand::Activate).is_ok() {
                                            let mut state = ServerChannel::new(
                                                id,
                                                self.config.request_timeout,
                                            );
                                            state.activation_handle = preopen_state.handle.take();
                                            channels.insert(id, state);
                                        } else {
                                            // The quarantine actor observed
                                            // FIN before it could transition;
                                            // this is the silent FIN-before-OPEN
                                            // case, not an open failure.
                                            preopen_fin.insert(id);
                                        }
                                    } else {
                                        let _ = command_tx.send(PreopenCommand::Reject);
                                        closed.insert(id);
                                        send_open_failure(
                                            &self.control_writer,
                                            id,
                                            if kind == "session" { 4 } else { 3 },
                                            "channel is unavailable",
                                        )
                                        .await?;
                                    }
                                }
                                continue;
                            }
                            if preopen_fin.contains(&id) {
                                // A stream that reached FIN before OPEN never
                                // became a channel and gets no response, even
                                // if its OPEN is delivered later.
                                seen.insert(id);
                                continue;
                            }
                            let already_seen = seen.contains(&id);
                            if id == 0
                                || kind != "session"
                                || already_seen
                                || channels.len() >= self.config.max_channels
                            {
                                if id != 0 {
                                    // Rejected channel numbers are consumed
                                    // just like accepted ones; ids are never
                                    // reusable within a connection.
                                    seen.insert(id);
                                    closed.insert(id);
                                }
                                send_open_failure(&self.control_writer, id, if kind == "session" { 4 } else { 3 }, "channel is unavailable").await?;
                                continue;
                            }
                            seen.insert(id);
                            let mut state = ServerChannel::new(id, self.config.request_timeout);
                            send_control(&self.control_writer, MSG_CHANNEL_OPEN_CONFIRM, encode_channel_id(id)).await?;
                            maybe_start_worker(&mut state, &self.config, &self.control_writer, &events_tx)
                                .await?;
                            channels.insert(id, state);
                        }
                        MSG_CHANNEL_REQUEST => {
                            let request = decode_channel_request(&frame.payload)?;
                            let id = request.channel_id;
                            if let Some(state) = channels.get_mut(&id) {
                                if state.peer_close || state.local_close {
                                    return Err(Error::Protocol(
                                        "channel request arrived after CHANNEL_CLOSE".into(),
                                    ));
                                }
                                if state.worker_failed {
                                    if request.want_reply {
                                        send_control(
                                            &self.control_writer,
                                            MSG_CHANNEL_FAILURE,
                                            encode_channel_id(id),
                                        )
                                        .await?;
                                    }
                                } else if state.activation_handle.is_some()
                                    || (state.stream.is_none() && state.worker_handle.is_none())
                                {
                                    if state.pending_requests.len() >= MAX_PENDING_CHANNEL_REQUESTS {
                                        if request.want_reply {
                                            send_control(
                                                &self.control_writer,
                                                MSG_CHANNEL_FAILURE,
                                                encode_channel_id(id),
                                            )
                                            .await?;
                                        }
                                    } else {
                                        state.pending_requests.push_back(request);
                                    }
                                } else {
                                    handle_server_channel_request(
                                        state,
                                        request,
                                        &self.control_writer,
                                        self.config.max_command_bytes.min(MAX_COMMAND_BYTES),
                                    )
                                    .await?;
                                    maybe_start_worker(state, &self.config, &self.control_writer, &events_tx)
                                        .await?;
                                }
                            } else if request.want_reply {
                                send_control(&self.control_writer, MSG_CHANNEL_FAILURE, encode_channel_id(id)).await?;
                            }
                        }
                        MSG_CHANNEL_EOF => {
                            let id = decode_channel_id(&frame.payload)?;
                            let (input_eof_tx, start_orphan) = if let Some(state) = channels.get_mut(&id) {
                                if state.peer_close {
                                    return Err(Error::Protocol(
                                        "CHANNEL_EOF arrived after CHANNEL_CLOSE".into(),
                                    ));
                                }
                                if state.peer_eof {
                                    return Err(Error::Protocol("duplicate CHANNEL_EOF".into()));
                                }
                                state.peer_eof = true;
                                (
                                    state.worker_tx.clone(),
                                    state.worker_handle.is_none()
                                        && state.command.is_none()
                                        && state.stream.is_some(),
                                )
                            } else {
                                return Err(Error::Protocol("CHANNEL_EOF references an unknown channel".into()));
                            };
                            if let Some(tx) = input_eof_tx {
                                let _ = tx.send(WorkerCommand::ControlEof).await;
                            }
                            if start_orphan && let Some(state) = channels.get_mut(&id) {
                                start_orphan_drain(state, &events_tx, &self.control_writer);
                            }
                            let should_close = channels.get(&id).is_some_and(|state| {
                                can_send_channel_close(state)
                            });
                            if should_close {
                                send_control(&self.control_writer, MSG_CHANNEL_CLOSE, encode_channel_id(id)).await?;
                                if let Some(state) = channels.get_mut(&id) {
                                    mark_local_close(state, self.config.close_timeout);
                                }
                            }
                        }
                        MSG_CHANNEL_CLOSE => {
                            let id = decode_channel_id(&frame.payload)?;
                            let should_close;
                            if let Some(state) = channels.get_mut(&id) {
                                if state.peer_close {
                                    continue;
                                }
                                state.peer_close = true;
                                if state.close_deadline.is_none() {
                                    state.close_deadline =
                                        Some(tokio::time::Instant::now() + self.config.close_timeout);
                                }
                                if !state.local_close
                                    && state.worker_handle.is_none()
                                    && state.stream.is_some()
                                {
                                    start_orphan_drain(state, &events_tx, &self.control_writer);
                                }
                                if let Some(tx) = &state.worker_tx {
                                    let _ = tx.send(WorkerCommand::Close).await;
                                }
                                should_close = can_send_channel_close(state);
                            } else if closed.contains(&id) {
                                // A duplicate CLOSE can arrive after the
                                // channel tombstone has been released.
                                continue;
                            } else {
                                return Err(Error::Protocol("CHANNEL_CLOSE references an unknown channel".into()));
                            }
                            if should_close {
                                send_control(&self.control_writer, MSG_CHANNEL_CLOSE, encode_channel_id(id)).await?;
                                if let Some(state) = channels.get_mut(&id) {
                                    mark_local_close(state, self.config.close_timeout);
                                }
                            }
                            if channels.get(&id).is_some_and(channel_is_drained) {
                                channels.remove(&id);
                                closed.insert(id);
                            }
                        }
                        MSG_GLOBAL_REQUEST => handle_server_global_request(&self.control_writer, &frame.payload).await?,
                        MSG_DISCONNECT => {
                            return Err(Error::RemoteDisconnect(decode_disconnect(&frame.payload)?));
                        }
                        MSG_UNIMPLEMENTED => {
                            validate_unimplemented(&frame.payload)?;
                        }
                        MSG_CHANNEL_OPEN_CONFIRM | MSG_CHANNEL_OPEN_FAILURE | MSG_CHANNEL_SUCCESS | MSG_CHANNEL_FAILURE => {
                            return Err(Error::Protocol("client sent a server-only control message".into()));
                        }
                        number if number >= 192 => {}
                        number => send_unimplemented(&self.control_writer, number).await?,
                    }
                }
                incoming = self.connection.accept_uni() => {
                    let mut recv = incoming?;
                    let _ = recv.stop(quinn::VarInt::from_u32(1));
                }
                event = events_rx.recv() => {
                    if let Some(event) = event {
                        match event {
                            WorkerEvent::PreopenFin { id } => {
                                if let Some(state) = preopen.remove(&id) {
                                    drop(state);
                                    preopen_fin.insert(id);
                                    seen.insert(id);
                                } else if let Some(state) = channels.get(&id)
                                    && state.stream.is_none()
                                    && state.activation_handle.is_some()
                                {
                                    channels.remove(&id);
                                    closed.insert(id);
                                }
                            }
                            WorkerEvent::PreopenReady { id, stream } => {
                                let pending = channels.get_mut(&id).is_some_and(|state| {
                                    state.stream.is_none() && state.activation_handle.is_some()
                                });
                                if pending {
                                    if let Some(state) = channels.get_mut(&id) {
                                        state.activation_handle.take();
                                        let (send, recv) = stream;
                                        // The quarantine consumed the pre-OPEN
                                        // activation bytes. Handoff must not
                                        // wait for another DATA frame: the
                                        // client sends its command only after
                                        // receiving OPEN_CONFIRM.
                                        state.stream =
                                            Some((send, FramedReader::new(recv)));
                                        state.stream_deadline = Some(
                                            tokio::time::Instant::now()
                                                + self.config.request_timeout,
                                        );
                                    }
                                    send_control(
                                        &self.control_writer,
                                        MSG_CHANNEL_OPEN_CONFIRM,
                                        encode_channel_id(id),
                                    )
                                    .await?;
                                    if let Some(state) = channels.get_mut(&id) {
                                        drain_pending_channel_requests(
                                            state,
                                            &self.control_writer,
                                            self.config.max_command_bytes.min(MAX_COMMAND_BYTES),
                                        )
                                        .await?;
                                        maybe_start_worker(state, &self.config, &self.control_writer, &events_tx)
                                            .await?;
                                    }
                                } else {
                                    let (send, reader) = stream;
                                    reset_stream(send, reader);
                                }
                            }
                            WorkerEvent::Activated {
                                id,
                                stream,
                                initial_data,
                                peer_fin,
                            } => {
                                if let Some(state) = channels.get_mut(&id) {
                                    state.activation_handle.take();
                                    state.stream = Some(stream);
                                    state.pending_data.push_back(initial_data);
                                    state.peer_fin |= peer_fin;
                                    state.stream_deadline = Some(
                                        tokio::time::Instant::now() + self.config.request_timeout,
                                    );
                                    let should_start_orphan = if state.peer_close {
                                        state.pending_requests.clear();
                                        true
                                    } else {
                                        drain_pending_channel_requests(
                                            state,
                                            &self.control_writer,
                                            self.config.max_command_bytes.min(MAX_COMMAND_BYTES),
                                        )
                                        .await?;
                                        state.command.is_none()
                                            && (state.peer_eof || state.peer_fin)
                                    };
                                    if should_start_orphan {
                                        start_orphan_drain(
                                            state,
                                            &events_tx,
                                            &self.control_writer,
                                        );
                                    } else {
                                        maybe_start_worker(state, &self.config, &self.control_writer, &events_tx)
                                            .await?;
                                    }
                                } else {
                                    let (send, reader) = stream;
                                    reset_stream(send, reader.into_inner());
                                }
                            }
                            WorkerEvent::ActivationFailed { id, send, reader } => {
                                if let Some(state) = channels.get_mut(&id) {
                                    state.activation_handle.take();
                                    state.worker_failed = true;
                                    let pending_replies = state
                                        .pending_requests
                                        .drain(..)
                                        .filter(|request| request.want_reply)
                                        .count();
                                    state.close_deadline = Some(
                                        tokio::time::Instant::now() + self.config.close_timeout,
                                    );
                                    for _ in 0..pending_replies {
                                        send_control(
                                            &self.control_writer,
                                            MSG_CHANNEL_FAILURE,
                                            encode_channel_id(id),
                                        )
                                        .await?;
                                    }
                                    start_rejected_channel_drain(
                                        state,
                                        &events_tx,
                                        &self.control_writer,
                                        self.config.close_timeout,
                                        send,
                                        reader,
                                    );
                                } else {
                                    reset_stream(send, reader.into_inner());
                                }
                            }
                            WorkerEvent::InputProgress { id } => {
                                let _ = id;
                            }
                            WorkerEvent::Finished {
                                id,
                                failed,
                                peer_fin,
                                local_fin,
                            } => {
                                let mut should_close = false;
                                if let Some(state) = channels.get_mut(&id) {
                                    state.worker_finished = true;
                                    state.worker_failed = failed;
                                    state.peer_fin |= peer_fin;
                                    state.local_fin |= local_fin;
                                    state.worker_handle.take();
                                    state.worker_tx.take();
                                    if failed && !peer_fin {
                                        state.close_deadline.get_or_insert(
                                            tokio::time::Instant::now() + self.config.close_timeout,
                                        );
                                    }
                                    should_close = can_send_channel_close(state);
                                }
                                if should_close {
                                    send_control(
                                        &self.control_writer,
                                        MSG_CHANNEL_CLOSE,
                                        encode_channel_id(id),
                                    )
                                    .await?;
                                    if let Some(state) = channels.get_mut(&id) {
                                        mark_local_close(state, self.config.close_timeout);
                                    }
                                }
                                if channels.get(&id).is_some_and(channel_is_drained) {
                                    channels.remove(&id);
                                    closed.insert(id);
                                }
                            }
                        }
                    }
                }
                _ = async {
                    if let Some(deadline) = next_deadline {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if next_deadline.is_some() => {
                    let now = tokio::time::Instant::now();
                    let expired_unattached = channels
                        .iter()
                        .filter_map(|(&id, state)| {
                            (state.stream.is_none()
                                && state.worker_handle.is_none()
                                && state
                                    .stream_deadline
                                    .is_some_and(|deadline| deadline <= now))
                            .then_some(id)
                        })
                        .collect::<Vec<_>>();
                    let expired_preopen = preopen
                        .iter()
                        .filter_map(|(&id, state)| (state.deadline <= now).then_some(id))
                        .collect::<Vec<_>>();
                    for id in expired_preopen {
                        preopen.remove(&id);
                        seen.insert(id);
                    }
                    for id in expired_unattached {
                        channels.remove(&id);
                        closed.insert(id);
                    }
                    let expired_unrequested = channels
                        .iter()
                        .filter_map(|(&id, state)| {
                            (state.stream.is_some()
                                && state.worker_handle.is_none()
                                && state.command.is_none()
                                && state.stream_deadline.is_some_and(|deadline| deadline <= now))
                            .then_some(id)
                        })
                        .collect::<Vec<_>>();
                    for id in expired_unrequested {
                        if let Some(state) = channels.get_mut(&id) {
                            start_orphan_drain(state, &events_tx, &self.control_writer);
                            state.close_deadline =
                                Some(tokio::time::Instant::now() + self.config.close_timeout);
                        }
                    }
                    let expired_channels = channels
                        .iter()
                        .filter_map(|(&id, state)| {
                            (!channel_is_drained(state)
                                && (state
                                    .stream_deadline
                                    .is_some_and(|deadline| deadline <= now)
                                    || state
                                        .close_deadline
                                        .is_some_and(|deadline| deadline <= now)))
                            .then_some(id)
                        })
                        .collect::<Vec<_>>();
                    for id in expired_channels {
                        channels.remove(&id);
                        closed.insert(id);
                    }
                }
                }
            }
        }
        .await;

        let result = match result {
            Err(error) if is_transport_shutdown(&error) => Ok(()),
            Err(Error::RemoteDisconnect(_)) => {
                self.connection.close(0u32.into(), b"peer disconnected");
                Ok(())
            }
            result => result,
        };

        if let Err(error) = &result {
            if matches!(error, Error::RemoteDisconnect(_)) {
                self.connection.close(0u32.into(), b"peer disconnected");
            } else {
                let _ = send_disconnect(
                    &self.connection,
                    &self.control_writer,
                    "connection protocol error",
                )
                .await;
            }
            tracing::debug!(error = %error, "closing FSH session after protocol error");
        }
        // Dropping each channel runs transport/process cleanup, including
        // when the control stream fails while workers are active.
        channels.clear();
        result
    }
}

struct ServerChannel {
    id: u32,
    stream: Option<ChannelStream>,
    activation_handle: Option<tokio::task::JoinHandle<()>>,
    pending_data: VecDeque<Vec<u8>>,
    command: Option<Command>,
    pending_requests: VecDeque<ChannelRequest>,
    worker_tx: Option<mpsc::Sender<WorkerCommand>>,
    worker_handle: Option<tokio::task::JoinHandle<()>>,
    worker_finished: bool,
    worker_failed: bool,
    local_fin: bool,
    local_close: bool,
    peer_close: bool,
    peer_eof: bool,
    peer_fin: bool,
    stream_deadline: Option<tokio::time::Instant>,
    close_deadline: Option<tokio::time::Instant>,
    pending_signals: Vec<String>,
}

struct PreopenState {
    command_tx: Option<oneshot::Sender<PreopenCommand>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    deadline: tokio::time::Instant,
}

impl Drop for PreopenState {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

impl ServerChannel {
    fn new(id: u32, stream_timeout: Duration) -> Self {
        Self {
            id,
            stream: None,
            activation_handle: None,
            pending_data: VecDeque::new(),
            command: None,
            pending_requests: VecDeque::new(),
            worker_tx: None,
            worker_handle: None,
            worker_finished: false,
            worker_failed: false,
            local_fin: false,
            local_close: false,
            peer_close: false,
            peer_eof: false,
            peer_fin: false,
            stream_deadline: Some(tokio::time::Instant::now() + stream_timeout),
            close_deadline: None,
            pending_signals: Vec::new(),
        }
    }
}

fn mark_local_close(state: &mut ServerChannel, timeout: Duration) {
    state.local_close = true;
    state.stream_deadline = None;
    state.close_deadline = Some(tokio::time::Instant::now() + timeout);
}

impl Drop for ServerChannel {
    fn drop(&mut self) {
        if let Some(handle) = self.activation_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.worker_handle.take() {
            handle.abort();
        }
        if let Some((mut send, reader)) = self.stream.take() {
            let _ = send.reset(quinn::VarInt::from_u32(1));
            let mut recv = reader.into_inner();
            let _ = recv.stop(quinn::VarInt::from_u32(1));
        }
    }
}

#[derive(Debug)]
enum WorkerCommand {
    Signal(String),
    ControlEof,
    Close,
}

enum WorkerEvent {
    PreopenFin {
        id: u32,
    },
    PreopenReady {
        id: u32,
        stream: IncomingChannelStream,
    },
    Activated {
        id: u32,
        stream: ChannelStream,
        initial_data: Vec<u8>,
        peer_fin: bool,
    },
    ActivationFailed {
        id: u32,
        send: quinn::SendStream,
        reader: FramedReader<quinn::RecvStream>,
    },
    InputProgress {
        id: u32,
    },
    Finished {
        id: u32,
        failed: bool,
        peer_fin: bool,
        local_fin: bool,
    },
}

fn can_send_channel_close(state: &ServerChannel) -> bool {
    !state.local_close && state.worker_finished && state.local_fin && state.peer_fin
}

fn channel_is_drained(state: &ServerChannel) -> bool {
    state.local_close
        && state.peer_close
        && state.worker_handle.is_none()
        && state.local_fin
        && state.peer_fin
}

struct PreopenStream {
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
}

impl PreopenStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send: Some(send),
            recv: Some(recv),
        }
    }

    fn into_stream(mut self) -> IncomingChannelStream {
        (
            self.send.take().expect("pre-open send stream exists"),
            self.recv.take().expect("pre-open receive stream exists"),
        )
    }
}

enum PreopenCommand {
    Activate,
    Reject,
}

impl Drop for PreopenStream {
    fn drop(&mut self) {
        if let Some(mut send) = self.send.take() {
            let _ = send.reset(quinn::VarInt::from_u32(1));
        }
        if let Some(mut recv) = self.recv.take() {
            let _ = recv.stop(quinn::VarInt::from_u32(1));
        }
    }
}

fn start_preopen_quarantine(
    channel_id: u32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    mut command_rx: oneshot::Receiver<PreopenCommand>,
    events: &mpsc::UnboundedSender<WorkerEvent>,
) -> tokio::task::JoinHandle<()> {
    let events = events.clone();
    tokio::spawn(async move {
        let mut stream = PreopenStream::new(send, recv);
        let mut scratch = [0u8; 8192];
        loop {
            let decision = {
                let recv = stream
                    .recv
                    .as_mut()
                    .expect("pre-open receive stream exists");
                tokio::select! {
                    biased;
                    command = &mut command_rx => match command {
                        Ok(PreopenCommand::Activate) => PreopenDecision::Activate,
                        Ok(PreopenCommand::Reject) | Err(_) => PreopenDecision::Reject,
                    },
                    read = recv.read(&mut scratch) => {
                        match read {
                            Ok(None) | Ok(Some(0)) | Err(_) => PreopenDecision::Fin,
                            Ok(Some(_)) => PreopenDecision::Data,
                        }
                    }
                }
            };

            match decision {
                PreopenDecision::Data => {
                    // Every byte consumed before Activate is deliberately
                    // discarded. The raw read avoids FramedReader buffering
                    // a partial pre-open frame for later activation.
                    continue;
                }
                PreopenDecision::Fin => {
                    let _ = events.send(WorkerEvent::PreopenFin { id: channel_id });
                    return;
                }
                PreopenDecision::Ready => unreachable!(),
                PreopenDecision::Reject => return,
                PreopenDecision::Activate => {
                    let mut quiet = Box::pin(tokio::time::sleep(PREOPEN_HANDOFF_QUIET));
                    loop {
                        let handoff = {
                            let recv = stream
                                .recv
                                .as_mut()
                                .expect("pre-open receive stream exists");
                            tokio::select! {
                                biased;
                                read = recv.read(&mut scratch) => {
                                    match read {
                                        Ok(None) | Ok(Some(0)) | Err(_) => PreopenDecision::Fin,
                                        Ok(Some(_)) => PreopenDecision::Data,
                                    }
                                }
                                _ = &mut quiet => PreopenDecision::Ready,
                            }
                        };
                        match handoff {
                            PreopenDecision::Data => quiet
                                .as_mut()
                                .reset(tokio::time::Instant::now() + PREOPEN_HANDOFF_QUIET),
                            PreopenDecision::Fin => {
                                let _ = events.send(WorkerEvent::PreopenFin { id: channel_id });
                                return;
                            }
                            PreopenDecision::Ready => {
                                let _ = events.send(WorkerEvent::PreopenReady {
                                    id: channel_id,
                                    stream: stream.into_stream(),
                                });
                                return;
                            }
                            PreopenDecision::Activate | PreopenDecision::Reject => unreachable!(),
                        }
                    }
                }
            }
        }
    })
}

enum PreopenDecision {
    Data,
    Fin,
    Activate,
    Ready,
    Reject,
}

fn start_channel_activation(
    channel_id: u32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    events: &mpsc::UnboundedSender<WorkerEvent>,
    timeout_duration: Duration,
) -> tokio::task::JoinHandle<()> {
    let events = events.clone();
    tokio::spawn(run_channel_activation(
        channel_id,
        send,
        recv,
        events,
        timeout_duration,
    ))
}

async fn run_channel_activation(
    channel_id: u32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    events: mpsc::UnboundedSender<WorkerEvent>,
    timeout_duration: Duration,
) {
    let mut reader = FramedReader::new(recv);
    let activation = tokio::time::timeout(timeout_duration, reader.next()).await;
    let event = match activation {
        Ok(Ok(Some(frame))) => match decode_client_channel_data(channel_id, &frame) {
            Ok(data) => WorkerEvent::Activated {
                id: channel_id,
                stream: (send, reader),
                initial_data: data,
                peer_fin: false,
            },
            Err(_) => WorkerEvent::ActivationFailed {
                id: channel_id,
                send,
                reader,
            },
        },
        Ok(Ok(None)) => WorkerEvent::Activated {
            id: channel_id,
            stream: (send, reader),
            initial_data: Vec::new(),
            peer_fin: true,
        },
        Ok(Err(_)) | Err(_) => WorkerEvent::ActivationFailed {
            id: channel_id,
            send,
            reader,
        },
    };
    let _ = events.send(event);
}

async fn maybe_start_worker(
    state: &mut ServerChannel,
    config: &SessionConfig,
    control_writer: &ControlWriter,
    events: &mpsc::UnboundedSender<WorkerEvent>,
) -> Result<()> {
    if state.worker_handle.is_some()
        || state.stream.is_none()
        || state.command.is_none()
        || state.peer_close
        || state.local_close
    {
        return Ok(());
    }
    let command = state.command.clone().expect("command checked");
    let (send, recv) = state.stream.take().expect("stream checked");
    let initial_data = state.pending_data.drain(..).collect::<Vec<_>>();
    state.stream_deadline = None;
    let (worker_tx, worker_rx) = mpsc::channel(64);
    let id = state.id;
    let writer = Arc::clone(control_writer);
    for signal in state.pending_signals.drain(..) {
        let _ = worker_tx.try_send(WorkerCommand::Signal(signal));
    }
    if state.peer_eof {
        let _ = worker_tx.try_send(WorkerCommand::ControlEof);
    }
    state.worker_tx = Some(worker_tx);
    let events = events.clone();
    let login_shell = config.login_shell.clone();
    let close_timeout = config.close_timeout;
    state.worker_handle = Some(tokio::spawn(async move {
        let result = run_channel_worker(
            id,
            command,
            send,
            recv,
            initial_data,
            writer,
            worker_rx,
            events.clone(),
            login_shell,
            close_timeout,
        )
        .await;
        let (failed, peer_fin, local_fin) = match result {
            Ok(outcome) => (outcome.failed, outcome.peer_fin, outcome.local_fin),
            Err(_) => (true, false, false),
        };
        let _ = events.send(WorkerEvent::Finished {
            id,
            failed,
            peer_fin,
            local_fin,
        });
    }));
    Ok(())
}

fn start_orphan_drain(
    state: &mut ServerChannel,
    events: &mpsc::UnboundedSender<WorkerEvent>,
    control_writer: &ControlWriter,
) {
    let Some((send, mut reader)) = state.stream.take() else {
        return;
    };
    state.stream_deadline = None;
    let id = state.id;
    let events = events.clone();
    let control_writer = Arc::clone(control_writer);
    state.worker_handle = Some(tokio::spawn(async move {
        let mut clean = send_control(&control_writer, MSG_CHANNEL_EOF, encode_channel_id(id))
            .await
            .is_ok();
        loop {
            match reader.next().await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {
                    clean = false;
                    break;
                }
            }
        }
        let mut writer = FramedWriter::new(send);
        if writer.finish().await.is_err() {
            clean = false;
        }
        let _ = events.send(WorkerEvent::Finished {
            id,
            failed: !clean,
            peer_fin: clean,
            local_fin: clean,
        });
    }));
}

fn start_rejected_channel_drain(
    state: &mut ServerChannel,
    events: &mpsc::UnboundedSender<WorkerEvent>,
    control_writer: &ControlWriter,
    timeout_duration: Duration,
    send: quinn::SendStream,
    reader: FramedReader<quinn::RecvStream>,
) {
    state.stream_deadline = None;
    let id = state.id;
    let events = events.clone();
    let control_writer = Arc::clone(control_writer);
    state.worker_handle = Some(tokio::spawn(async move {
        let mut clean = send_control(&control_writer, MSG_CHANNEL_EOF, encode_channel_id(id))
            .await
            .is_ok();
        let peer_fin = if clean {
            drain_raw_until_fin(reader.into_inner(), timeout_duration).await
        } else {
            false
        };
        let mut writer = FramedWriter::new(send);
        let local_fin = writer.finish().await.is_ok();
        clean &= local_fin;
        let _ = events.send(WorkerEvent::Finished {
            id,
            failed: true,
            peer_fin,
            local_fin: clean,
        });
    }));
}

async fn drain_pending_channel_requests(
    state: &mut ServerChannel,
    writer: &ControlWriter,
    max_command_bytes: usize,
) -> Result<()> {
    while let Some(request) = state.pending_requests.pop_front() {
        handle_server_channel_request(state, request, writer, max_command_bytes).await?;
    }
    Ok(())
}

async fn handle_server_channel_request(
    state: &mut ServerChannel,
    request: ChannelRequest,
    writer: &ControlWriter,
    max_command_bytes: usize,
) -> Result<()> {
    let mut success = false;
    match request.kind {
        ChannelRequestKind::Unknown => {}
        ChannelRequestKind::Exec(command) => {
            let accepted = state.command.is_none()
                && command.len() <= max_command_bytes
                && !command.as_bytes().contains(&0)
                && shell_words::split(&command).is_ok_and(|parts| !parts.is_empty());
            if accepted {
                state.command = Some(Command::Exec(command));
                success = request.want_reply;
            }
        }
        ChannelRequestKind::Shell => {
            if state.command.is_none() {
                state.command = Some(Command::Shell);
                success = request.want_reply;
            }
        }
        ChannelRequestKind::Subsystem(name) => {
            let _ = name;
        }
        ChannelRequestKind::Pty { valid } => {
            let _ = valid;
        }
        ChannelRequestKind::Signal(signal) => {
            if valid_signal(&signal) {
                if let Some(tx) = &state.worker_tx {
                    let _ = tx.send(WorkerCommand::Signal(signal)).await;
                } else {
                    if state.pending_signals.len() < MAX_PENDING_SIGNALS {
                        state.pending_signals.push(signal);
                    }
                }
            }
        }
        ChannelRequestKind::WindowChange { valid } => {
            let _ = valid;
        }
        ChannelRequestKind::ExitStatus | ChannelRequestKind::ExitSignal => {}
    }
    if request.want_reply {
        send_control(
            writer,
            if success {
                MSG_CHANNEL_SUCCESS
            } else {
                MSG_CHANNEL_FAILURE
            },
            encode_channel_id(state.id),
        )
        .await?;
    }
    Ok(())
}

struct WorkerOutcome {
    failed: bool,
    peer_fin: bool,
    local_fin: bool,
}

#[allow(clippy::too_many_arguments)]
async fn run_channel_worker(
    channel_id: u32,
    command: Command,
    send: quinn::SendStream,
    recv: FramedReader<quinn::RecvStream>,
    initial_data: Vec<Vec<u8>>,
    control_writer: ControlWriter,
    mut commands: mpsc::Receiver<WorkerCommand>,
    events: mpsc::UnboundedSender<WorkerEvent>,
    login_shell: Option<String>,
    close_timeout: Duration,
) -> Result<WorkerOutcome> {
    let mut process = match spawn_process(&command, login_shell.as_deref()) {
        Ok(process) => process,
        Err(_error) => {
            // A rejected command still owns an accepted channel stream. Make
            // the terminal notification and FIN precede the control CLOSE
            // that the session loop emits for this worker failure.
            let mut exit = Encoder::new();
            exit.u32(channel_id);
            exit.string("exit-status")?;
            exit.boolean(false);
            exit.u32(127);
            let _ = send_control(&control_writer, MSG_CHANNEL_REQUEST, exit.finish()).await;
            let _ = send_control(
                &control_writer,
                MSG_CHANNEL_EOF,
                encode_channel_id(channel_id),
            )
            .await;
            let mut output_writer = FramedWriter::new(send);
            let local_fin = output_writer.finish().await.is_ok();
            let peer_fin = drain_input_until_fin(recv, close_timeout).await;
            return Ok(WorkerOutcome {
                failed: true,
                peer_fin,
                local_fin,
            });
        }
    };
    let process_id = process
        .id()
        .ok_or_else(|| Error::Command("child has no process id".into()))?;
    let mut process_guard = ProcessGroupGuard::new(process_id);
    let mut stdin = process.stdin.take();
    let stdout = process
        .stdout
        .take()
        .ok_or_else(|| Error::Command("missing stdout pipe".into()))?;
    let stderr = process
        .stderr
        .take()
        .ok_or_else(|| Error::Command("missing stderr pipe".into()))?;
    let mut output_writer = FramedWriter::new(send);
    let (io_tx, mut io_rx) = mpsc::channel::<WorkerIo>(64);
    let mut tasks = JoinSet::new();
    tasks.spawn(read_channel_input(
        channel_id,
        recv,
        initial_data,
        close_timeout,
        io_tx.clone(),
    ));
    tasks.spawn(read_output(stdout, StreamKind::Stdout, io_tx.clone()));
    tasks.spawn(read_output(stderr, StreamKind::Stderr, io_tx));

    let mut wait = Box::pin(process.wait());
    let mut process_status = None;
    let mut input_done = false;
    let mut input_fin = false;
    let mut output_done = 0u8;
    let mut sent_exit = false;
    let mut closing = false;
    let mut protocol_error = false;
    let mut control_eof_deadline = None;
    let mut io_closed = false;
    let mut close_requested = false;
    let mut close_kill_deadline = None;

    loop {
        if (closing && process_status.is_some() && output_done == 2)
            || (!closing && output_done == 2 && process_status.is_some())
        {
            break;
        }
        tokio::select! {
            _ = async {
                if let Some(deadline) = close_kill_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if close_kill_deadline.is_some() && !closing && process_status.is_none() => {
                closing = true;
                close_kill_deadline = None;
                drop(wait);
                send_process_signal(process_id, "KILL");
                wait = Box::pin(process.wait());
            }
            _ = async {
                if let Some(deadline) = control_eof_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if control_eof_deadline.is_some() && !input_done => {
                protocol_error = true;
                closing = true;
                if process_status.is_none() {
                    drop(wait);
                    send_process_signal(process_id, "KILL");
                    wait = Box::pin(process.wait());
                }
            }
                    status = &mut wait, if process_status.is_none() => {
                process_status = Some(status.map_err(|e| Error::Command(format!("wait failed: {e}")))?);
                // The command's process group owns the session.  Once the
                // leader exits, terminate any descendants before releasing
                // the guard so background jobs cannot outlive the channel.
                send_process_signal(process_id, "KILL");
                process_guard.disarm();
            }
            command = commands.recv() => {
                match command {
                    Some(WorkerCommand::Signal(signal)) => { send_process_signal(process_id, &signal); }
                    Some(WorkerCommand::ControlEof) => {
                        if !input_done {
                            control_eof_deadline = Some(
                                tokio::time::Instant::now() + close_timeout,
                            );
                        }
                    }
                    Some(WorkerCommand::Close) => {
                        close_requested = true;
                        if process_status.is_none() {
                            close_kill_deadline = Some(
                                tokio::time::Instant::now() + CLOSE_DRAIN_GRACE,
                            );
                        }
                    }
                    None => {}
                }
            }
            event = io_rx.recv(), if !io_closed => {
                match event {
                    Some(WorkerIo::Input(data)) => {
                        if let Some(pipe) = stdin.as_mut() {
                            if pipe.write_all(&data).await.is_err() {
                                stdin.take();
                            } else {
                                let _ = events.send(WorkerEvent::InputProgress { id: channel_id });
                                if control_eof_deadline.is_some() {
                                    control_eof_deadline = Some(
                                        tokio::time::Instant::now() + close_timeout,
                                    );
                                }
                            }
                        }
                    }
                    Some(WorkerIo::InputDone { clean, fin }) => {
                        stdin.take();
                        input_done = clean;
                        input_fin = fin;
                        if clean {
                            control_eof_deadline = None;
                            if close_requested && process_status.is_none() {
                                close_kill_deadline = Some(
                                    tokio::time::Instant::now() + CLOSE_DRAIN_GRACE,
                                );
                            }
                        }
                        if !clean {
                            protocol_error = true;
                            closing = true;
                            if process_status.is_none() {
                                drop(wait);
                                send_process_signal(process_id, "KILL");
                                wait = Box::pin(process.wait());
                            }
                        }
                    }
                    Some(WorkerIo::Output(kind, data)) if !protocol_error => {
                        let mut encoder = Encoder::new();
                        encoder.u32(channel_id);
                        if kind == StreamKind::Stderr {
                            encoder.u32(STDERR_TYPE);
                        }
                        encoder.bytes(&data)?;
                        output_writer.send(if kind == StreamKind::Stderr { MSG_CHANNEL_EXTENDED_DATA } else { MSG_CHANNEL_DATA }, &encoder.finish()).await?;
                    }
                    Some(WorkerIo::Output(_, _)) => {}
                    Some(WorkerIo::OutputDone) => {
                        output_done = output_done.saturating_add(1);
                    }
                    Some(WorkerIo::ProtocolError) => {
                        protocol_error = true;
                        closing = true;
                        if process_status.is_none() {
                            drop(wait);
                            send_process_signal(process_id, "KILL");
                            wait = Box::pin(process.wait());
                        }
                    }
                    None => {
                        io_closed = true;
                    }
                }
            }
        }
        if !closing
            && !sent_exit
            && let Some(status) = process_status.as_ref()
        {
            send_exit_notification(&control_writer, channel_id, status).await?;
            sent_exit = true;
        }
    }

    if !sent_exit && let Some(status) = process_status.as_ref() {
        send_exit_notification(&control_writer, channel_id, status).await?;
    }
    send_control(
        &control_writer,
        MSG_CHANNEL_EOF,
        encode_channel_id(channel_id),
    )
    .await?;
    let local_fin = output_writer.finish().await.is_ok();

    // Output can finish before the peer has observed the exit notification
    // and sent its stdin FIN.  Keep the input reader alive for the drain
    // window, but never leave a half-closed channel waiting forever.
    if !input_done {
        let deadline_at = tokio::time::Instant::now() + close_timeout;
        let deadline = tokio::time::sleep_until(deadline_at);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    protocol_error = true;
                    break;
                }
                command = commands.recv() => {
                    match command {
                        Some(WorkerCommand::ControlEof) => {}
                        Some(WorkerCommand::Close) => {}
                        Some(WorkerCommand::Signal(_)) | None => {}
                    }
                }
                event = io_rx.recv() => {
                    match event {
                        Some(WorkerIo::Input(data)) => {
                            let mut delivered = false;
                            if let Some(pipe) = stdin.as_mut() {
                                if pipe.write_all(&data).await.is_err() {
                                    stdin.take();
                                } else {
                                    delivered = true;
                                    let _ = events.send(WorkerEvent::InputProgress { id: channel_id });
                                }
                            }
                            if delivered {
                                if control_eof_deadline.is_some() {
                                    control_eof_deadline = Some(
                                        tokio::time::Instant::now() + close_timeout,
                                    );
                                }
                                deadline
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + close_timeout);
                            }
                        }
                        Some(WorkerIo::InputDone { clean, fin }) => {
                            stdin.take();
                            input_fin = fin;
                            if !clean {
                                protocol_error = true;
                            }
                            break;
                        }
                        Some(WorkerIo::ProtocolError) => {
                            protocol_error = true;
                        }
                        Some(WorkerIo::Output(_, _)) | Some(WorkerIo::OutputDone) => {}
                        None => {
                            protocol_error = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if protocol_error {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        return Ok(WorkerOutcome {
            failed: true,
            peer_fin: input_fin,
            local_fin,
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(WorkerOutcome {
        failed: closing && !close_requested,
        peer_fin: input_fin,
        local_fin,
    })
}

async fn drain_input_until_fin(
    mut reader: FramedReader<quinn::RecvStream>,
    timeout_duration: Duration,
) -> bool {
    tokio::time::timeout(timeout_duration, async {
        loop {
            match reader.next().await {
                Ok(Some(_)) => {}
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn drain_raw_until_fin<R>(mut reader: R, timeout_duration: Duration) -> bool
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(timeout_duration, async {
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

struct ProcessGroupGuard {
    pid: u32,
    armed: bool,
}

impl ProcessGroupGuard {
    fn new(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            send_process_signal(self.pid, "KILL");
        }
    }
}

/// The passwd entry of the account the daemon runs as. The MVP serves a
/// single configured user, so the account's own login shell is the shell
/// that `shell` requests must start.
struct Account {
    name: String,
    home: String,
    shell: String,
}

#[cfg(unix)]
fn account_info() -> Option<Account> {
    use std::ffi::CStr;

    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    // getpwuid_r needs scratch space for the strings it points into.
    let mut buffer = vec![0u8; 8192];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(entry.pw_name) }.to_str().ok()?;
    let home = unsafe { CStr::from_ptr(entry.pw_dir) }.to_str().ok()?;
    let shell = unsafe { CStr::from_ptr(entry.pw_shell) }.to_str().ok()?;
    if name.is_empty() || home.is_empty() {
        return None;
    }
    Some(Account {
        name: name.to_owned(),
        home: home.to_owned(),
        shell: if shell.is_empty() {
            "/bin/sh".to_owned()
        } else {
            shell.to_owned()
        },
    })
}

#[cfg(not(unix))]
fn account_info() -> Option<Account> {
    None
}

/// Resolve the program to run for a `shell` request: the daemon account's
/// login shell, overridable through `SessionConfig::login_shell`, falling
/// back to `/bin/sh`.
fn resolve_shell(login_shell: Option<&str>) -> String {
    if let Some(shell) = login_shell {
        return shell.to_owned();
    }
    account_info()
        .map(|account| account.shell)
        .unwrap_or_else(|| "/bin/sh".to_owned())
}

fn spawn_process(command: &Command, login_shell: Option<&str>) -> Result<tokio::process::Child> {
    let account = account_info();
    let mut process = match command {
        Command::Exec(command) => {
            let words = shell_words::split(command)
                .map_err(|e| Error::Command(format!("invalid command quoting: {e}")))?;
            if words.is_empty() {
                return Err(Error::Command("empty command".into()));
            }
            let mut process = TokioCommand::new(&words[0]);
            process.args(&words[1..]);
            process
        }
        Command::Shell => {
            // The connection contract starts the account's default shell.
            // Without a pty the shell reads commands from the channel pipe,
            // so no interactive flag is passed.
            let shell = resolve_shell(login_shell);
            TokioCommand::new(shell)
        }
    };
    process.env_clear();
    process.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    if let Some(account) = account {
        let shell = resolve_shell(login_shell);
        process.env("HOME", &account.home);
        process.env("SHELL", shell);
        process.env("USER", &account.name);
        process.env("LOGNAME", &account.name);
        process.env("PWD", &account.home);
    }
    #[cfg(unix)]
    process.process_group(0);
    process.kill_on_drop(true);
    process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Command(format!("cannot start command: {e}")))
}

fn send_process_signal(pid: u32, name: &str) {
    #[cfg(unix)]
    {
        let Some(signal) = signal_number(name) else {
            return;
        };
        // process_group(0) creates a group whose id is the child pid.
        unsafe {
            libc::kill(-(pid as libc::pid_t), signal);
        }
    }
}

async fn send_exit_notification(
    writer: &ControlWriter,
    channel_id: u32,
    status: &std::process::ExitStatus,
) -> Result<()> {
    let payload = encode_exit_notification(channel_id, status)?;
    send_control(writer, MSG_CHANNEL_REQUEST, payload).await
}

fn encode_exit_notification(channel_id: u32, status: &std::process::ExitStatus) -> Result<Vec<u8>> {
    let status = *status;
    let mut encoder = Encoder::new();
    encoder.u32(channel_id);
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal()
            && let Some(name) = signal_name(signal)
        {
            encoder.string("exit-signal")?;
            encoder.boolean(false);
            encoder.string(name)?;
            encoder.boolean(status.core_dumped());
            encoder.string("process terminated by signal")?;
            encoder.string("")?;
            return Ok(encoder.finish());
        }
        // An unrecognized signal number must not be misreported as TERM.
        // Report the conventional 128+n exit status so the client still
        // surfaces the true termination cause.
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let code = status
            .code()
            .or_else(|| status.signal().map(|signal| 128 + signal))
            .unwrap_or(1);
        encoder.string("exit-status")?;
        encoder.boolean(false);
        encoder.u32(code as u32);
    }
    #[cfg(not(unix))]
    {
        encoder.string("exit-status")?;
        encoder.boolean(false);
        encoder.u32(status.code().unwrap_or(1) as u32);
    }
    Ok(encoder.finish())
}

#[cfg(unix)]
fn signal_name(signal: i32) -> Option<&'static str> {
    Some(match signal {
        libc::SIGHUP => "HUP",
        libc::SIGINT => "INT",
        libc::SIGQUIT => "QUIT",
        libc::SIGILL => "ILL",
        libc::SIGTRAP => "TRAP",
        libc::SIGABRT => "ABRT",
        libc::SIGBUS => "BUS",
        libc::SIGFPE => "FPE",
        libc::SIGKILL => "KILL",
        libc::SIGUSR1 => "USR1",
        libc::SIGSEGV => "SEGV",
        libc::SIGUSR2 => "USR2",
        libc::SIGPIPE => "PIPE",
        libc::SIGALRM => "ALRM",
        libc::SIGTERM => "TERM",
        #[cfg(target_os = "linux")]
        libc::SIGSTKFLT => "STKFLT",
        libc::SIGCHLD => "CHLD",
        libc::SIGCONT => "CONT",
        libc::SIGSTOP => "STOP",
        libc::SIGTSTP => "TSTP",
        libc::SIGTTIN => "TTIN",
        libc::SIGTTOU => "TTOU",
        libc::SIGURG => "URG",
        libc::SIGXCPU => "XCPU",
        libc::SIGXFSZ => "XFSZ",
        libc::SIGVTALRM => "VTALRM",
        libc::SIGPROF => "PROF",
        libc::SIGWINCH => "WINCH",
        libc::SIGIO => "IO",
        #[cfg(target_os = "linux")]
        libc::SIGPWR => "PWR",
        libc::SIGSYS => "SYS",
        _ => return None,
    })
}

/// Map an SSH-style signal name (no `SIG` prefix) to its number. Shared by
/// the daemon, which sends signals, and the client, which reports
/// `128 + number` for a signaled remote command.
pub fn signal_number(name: &str) -> Option<i32> {
    #[cfg(unix)]
    {
        Some(match name {
            "HUP" => libc::SIGHUP,
            "INT" => libc::SIGINT,
            "QUIT" => libc::SIGQUIT,
            "ILL" => libc::SIGILL,
            "TRAP" => libc::SIGTRAP,
            "ABRT" => libc::SIGABRT,
            "BUS" => libc::SIGBUS,
            "FPE" => libc::SIGFPE,
            "KILL" => libc::SIGKILL,
            "USR1" => libc::SIGUSR1,
            "SEGV" => libc::SIGSEGV,
            "USR2" => libc::SIGUSR2,
            "PIPE" => libc::SIGPIPE,
            "ALRM" => libc::SIGALRM,
            "TERM" => libc::SIGTERM,
            #[cfg(target_os = "linux")]
            "STKFLT" => libc::SIGSTKFLT,
            "CHLD" => libc::SIGCHLD,
            "CONT" => libc::SIGCONT,
            "STOP" => libc::SIGSTOP,
            "TSTP" => libc::SIGTSTP,
            "TTIN" => libc::SIGTTIN,
            "TTOU" => libc::SIGTTOU,
            "URG" => libc::SIGURG,
            "XCPU" => libc::SIGXCPU,
            "XFSZ" => libc::SIGXFSZ,
            "VTALRM" => libc::SIGVTALRM,
            "PROF" => libc::SIGPROF,
            "WINCH" => libc::SIGWINCH,
            "IO" => libc::SIGIO,
            #[cfg(target_os = "linux")]
            "PWR" => libc::SIGPWR,
            "SYS" => libc::SIGSYS,
            _ => return None,
        })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum StreamKind {
    Stdout,
    Stderr,
}

enum WorkerIo {
    Input(Vec<u8>),
    InputDone { clean: bool, fin: bool },
    Output(StreamKind, Vec<u8>),
    OutputDone,
    ProtocolError,
}

async fn read_channel_input(
    channel_id: u32,
    mut input_reader: FramedReader<quinn::RecvStream>,
    initial_data: Vec<Vec<u8>>,
    timeout_duration: Duration,
    sender: mpsc::Sender<WorkerIo>,
) {
    let mut clean_eof = false;
    let mut protocol_error = false;
    for data in initial_data {
        if sender.send(WorkerIo::Input(data)).await.is_err() {
            return;
        }
    }
    loop {
        match input_reader.next().await {
            Ok(Some(frame)) if frame.number == MSG_CHANNEL_DATA => {
                let mut decoder = Decoder::new(&frame.payload);
                let id = match decoder.u32() {
                    Ok(id) => id,
                    Err(_) => {
                        if !protocol_error {
                            let _ = sender.send(WorkerIo::ProtocolError).await;
                        }
                        protocol_error = true;
                        continue;
                    }
                };
                let data = match decoder.bytes() {
                    Ok(data) => data.to_vec(),
                    Err(_) => {
                        if !protocol_error {
                            let _ = sender.send(WorkerIo::ProtocolError).await;
                        }
                        protocol_error = true;
                        continue;
                    }
                };
                if id != channel_id || decoder.finish().is_err() {
                    if !protocol_error {
                        let _ = sender.send(WorkerIo::ProtocolError).await;
                    }
                    protocol_error = true;
                    continue;
                }
                if !protocol_error && sender.send(WorkerIo::Input(data)).await.is_err() {
                    break;
                }
            }
            Ok(Some(_)) => {
                if !protocol_error {
                    let _ = sender.send(WorkerIo::ProtocolError).await;
                }
                protocol_error = true;
            }
            Ok(None) => {
                clean_eof = true;
                break;
            }
            Err(_) => {
                if !protocol_error {
                    let _ = sender.send(WorkerIo::ProtocolError).await;
                }
                protocol_error = true;
                clean_eof = tokio::time::timeout(timeout_duration, input_reader.drain_to_end())
                    .await
                    .is_ok_and(|result| result.is_ok());
                break;
            }
        }
    }
    let _ = sender
        .send(WorkerIo::InputDone {
            clean: clean_eof && !protocol_error,
            fin: clean_eof,
        })
        .await;
}

async fn read_output<R>(mut reader: R, kind: StreamKind, sender: mpsc::Sender<WorkerIo>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut buffer = vec![0u8; MAX_FRAME_SIZE as usize / 2];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(length) => {
                if sender
                    .send(WorkerIo::Output(kind, buffer[..length].to_vec()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(_) => break,
        }
    }
    let _ = sender.send(WorkerIo::OutputDone).await;
}

#[derive(Debug)]
struct ChannelRequest {
    channel_id: u32,
    want_reply: bool,
    kind: ChannelRequestKind,
}

#[derive(Debug)]
enum ChannelRequestKind {
    Unknown,
    Exec(String),
    Shell,
    Subsystem(String),
    Pty { valid: bool },
    Signal(String),
    WindowChange { valid: bool },
    ExitStatus,
    ExitSignal,
}

fn decode_channel_request(payload: &[u8]) -> Result<ChannelRequest> {
    let mut decoder = Decoder::new(payload);
    let channel_id = decoder.u32()?;
    let kind = decoder.string()?.to_owned();
    let want_reply = decoder.boolean()?;
    let request = match kind.as_str() {
        "exec" => ChannelRequestKind::Exec(decoder.string()?.to_owned()),
        "shell" => ChannelRequestKind::Shell,
        "subsystem" => ChannelRequestKind::Subsystem({
            let name = decoder.string()?.to_owned();
            if name.len() > MAX_SUBSYSTEM_BYTES {
                return Err(Error::Protocol("subsystem name is too long".into()));
            }
            name
        }),
        "pty-req" => {
            let term = decoder.string()?;
            let cols = decoder.u32()?;
            let rows = decoder.u32()?;
            let width = decoder.u32()?;
            let height = decoder.u32()?;
            let modes = decoder.bytes()?;
            ChannelRequestKind::Pty {
                valid: !term.is_empty()
                    && term.len() <= 64
                    && term
                        .as_bytes()
                        .iter()
                        .all(|byte| (0x20..=0x7e).contains(byte))
                    && cols > 0
                    && cols <= 1024
                    && rows > 0
                    && rows <= 1024
                    && width <= 8192
                    && height <= 8192
                    && modes.is_empty(),
            }
        }
        "signal" => ChannelRequestKind::Signal(decoder.string()?.to_owned()),
        "window-change" => {
            let cols = decoder.u32()?;
            let rows = decoder.u32()?;
            let width = decoder.u32()?;
            let height = decoder.u32()?;
            ChannelRequestKind::WindowChange {
                valid: cols > 0
                    && cols <= 1024
                    && rows > 0
                    && rows <= 1024
                    && width <= 8192
                    && height <= 8192,
            }
        }
        "exit-status" => {
            let _ = decoder.u32()?;
            ChannelRequestKind::ExitStatus
        }
        "exit-signal" => {
            let _ = decoder.string()?;
            let _ = decoder.boolean()?;
            let _ = decoder.string()?;
            let _ = decoder.string()?;
            ChannelRequestKind::ExitSignal
        }
        _ => ChannelRequestKind::Unknown,
    };
    if !matches!(request, ChannelRequestKind::Unknown) {
        decoder.finish()?;
    }
    Ok(ChannelRequest {
        channel_id,
        want_reply,
        kind: request,
    })
}

fn encode_channel_request(channel_id: u32, command: &Command) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.u32(channel_id);
    match command {
        Command::Exec(command) => {
            encoder.string("exec")?;
            encoder.boolean(true);
            encoder.string(command)?;
        }
        Command::Shell => {
            encoder.string("shell")?;
            encoder.boolean(true);
        }
    }
    Ok(encoder.finish())
}

fn decode_exit_notification(channel_id: u32, payload: &[u8]) -> Result<Option<ExitStatus>> {
    let request = decode_channel_request(payload)?;
    if request.channel_id != channel_id || request.want_reply {
        return Ok(None);
    }
    match request.kind {
        ChannelRequestKind::ExitStatus => {
            let mut decoder = Decoder::new(payload);
            let _ = decoder.u32()?;
            let _ = decoder.string()?;
            let _ = decoder.boolean()?;
            let code = decoder.u32()?;
            decoder.finish()?;
            Ok(Some(ExitStatus::Code(code)))
        }
        ChannelRequestKind::ExitSignal => {
            let mut decoder = Decoder::new(payload);
            let _ = decoder.u32()?;
            let _ = decoder.string()?;
            let _ = decoder.boolean()?;
            let name = decoder.string()?.to_owned();
            let core = decoder.boolean()?;
            let message = decoder.string()?.to_owned();
            let _ = decoder.string()?;
            decoder.finish()?;
            Ok(Some(ExitStatus::Signal {
                name,
                core_dumped: core,
                message,
            }))
        }
        _ => Ok(None),
    }
}

async fn handle_client_data_frame<W, E>(
    channel_id: u32,
    frame: Frame,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let mut decoder = Decoder::new(&frame.payload);
    let id = match decoder.u32() {
        Ok(id) => id,
        Err(_) => return Err(Error::ChannelProtocol("malformed channel data".into())),
    };
    if id != channel_id {
        return Err(Error::ChannelProtocol(
            "channel data id does not match stream".into(),
        ));
    }
    match frame.number {
        MSG_CHANNEL_DATA => {
            let data = match decoder.bytes() {
                Ok(data) => data,
                Err(_) => return Err(Error::ChannelProtocol("malformed channel data".into())),
            };
            if decoder.finish().is_err() {
                return Err(Error::ChannelProtocol(
                    "channel data has trailing bytes".into(),
                ));
            }
            stdout.write_all(data).await?;
        }
        MSG_CHANNEL_EXTENDED_DATA => {
            if decoder.u32().ok() != Some(STDERR_TYPE) {
                return Err(Error::ChannelProtocol("unknown extended data type".into()));
            }
            let data = match decoder.bytes() {
                Ok(data) => data,
                Err(_) => return Err(Error::ChannelProtocol("malformed extended data".into())),
            };
            if decoder.finish().is_err() {
                return Err(Error::ChannelProtocol(
                    "extended data has trailing bytes".into(),
                ));
            }
            stderr.write_all(data).await?;
        }
        _ => {
            return Err(Error::ChannelProtocol(
                "invalid channel data message".into(),
            ));
        }
    }
    Ok(())
}

fn decode_open(payload: &[u8]) -> Result<(u32, String)> {
    let mut decoder = Decoder::new(payload);
    let kind = decoder.string()?.to_owned();
    let id = decoder.u32()?;
    decoder.finish()?;
    Ok((id, kind))
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
    let description = decoder.string().map_err(|error| {
        Error::RemoteDisconnect(format!("malformed disconnect message: {error}"))
    })?;
    decoder.finish().map_err(|error| {
        Error::RemoteDisconnect(format!("malformed disconnect payload: {error}"))
    })?;
    Ok(format!("peer disconnected ({reason}): {description}"))
}

fn received_disconnect(connection: &quinn::Connection, payload: &[u8]) -> Error {
    let result = decode_disconnect(payload);
    connection.close(0u32.into(), b"peer disconnected");
    match result {
        Ok(message) => Error::RemoteDisconnect(message),
        Err(error) => error,
    }
}

fn encode_open(channel_id: u32) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.string("session").expect("static string");
    encoder.u32(channel_id);
    encoder.finish()
}

fn encode_global_request(name: &str, want_reply: bool) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder
        .string(name)
        .expect("request name length checked by caller");
    encoder.boolean(want_reply);
    encoder.finish()
}

fn is_client_control_message(number: u8) -> bool {
    matches!(
        number,
        MSG_UNIMPLEMENTED
            | MSG_REQUEST_SUCCESS
            | MSG_REQUEST_FAILURE
            | MSG_CHANNEL_OPEN_CONFIRM
            | MSG_CHANNEL_OPEN_FAILURE
            | MSG_CHANNEL_EOF
            | MSG_CHANNEL_CLOSE
            | MSG_CHANNEL_REQUEST
            | MSG_CHANNEL_SUCCESS
            | MSG_CHANNEL_FAILURE
            | crate::auth::MSG_SERVICE_REQUEST
            | crate::auth::MSG_SERVICE_ACCEPT
            | crate::auth::MSG_USERAUTH_REQUEST
            | crate::auth::MSG_USERAUTH_FAILURE
            | crate::auth::MSG_USERAUTH_SUCCESS
            | crate::auth::MSG_USERAUTH_PK_OK
    )
}

fn encode_channel_id(channel_id: u32) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.u32(channel_id);
    encoder.finish()
}

fn encode_channel_data(channel_id: u32, data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.u32(channel_id);
    encoder.bytes(data)?;
    Ok(encoder.finish())
}

fn decode_client_channel_data(channel_id: u32, frame: &Frame) -> Result<Vec<u8>> {
    if frame.number != MSG_CHANNEL_DATA {
        return Err(Error::ChannelProtocol(
            "channel activation must begin with CHANNEL_DATA".into(),
        ));
    }
    let mut decoder = Decoder::new(&frame.payload);
    let id = decoder
        .u32()
        .map_err(|_| Error::ChannelProtocol("malformed channel data".into()))?;
    if id != channel_id {
        return Err(Error::ChannelProtocol(
            "channel data id does not match stream".into(),
        ));
    }
    let data = decoder
        .bytes()
        .map_err(|_| Error::ChannelProtocol("malformed channel data".into()))?
        .to_vec();
    decoder
        .finish()
        .map_err(|_| Error::ChannelProtocol("channel data has trailing bytes".into()))?;
    Ok(data)
}

fn decode_channel_id(payload: &[u8]) -> Result<u32> {
    let mut decoder = Decoder::new(payload);
    let id = decoder.u32()?;
    decoder.finish()?;
    Ok(id)
}

fn decode_open_failure(payload: &[u8]) -> Result<(u32, String)> {
    let mut decoder = Decoder::new(payload);
    let id = decoder.u32()?;
    let reason = decoder.u32()?;
    let description = decoder.string()?.to_owned();
    let _ = decoder.string()?;
    decoder.finish()?;
    Ok((id, format!("channel rejected ({reason}): {description}")))
}

async fn send_open_failure(
    writer: &ControlWriter,
    id: u32,
    reason: u32,
    description: &str,
) -> Result<()> {
    let mut encoder = Encoder::new();
    encoder.u32(id);
    encoder.u32(reason);
    encoder.string(description)?;
    encoder.string("")?;
    send_control(writer, MSG_CHANNEL_OPEN_FAILURE, encoder.finish()).await
}

async fn send_control(writer: &ControlWriter, number: u8, payload: Vec<u8>) -> Result<()> {
    let mut writer = writer.lock().await;
    writer.send(number, &payload).await?;
    Ok(())
}

/// IGNORE and DEBUG are defined transport messages, not unknown control
/// messages. They are consumed without generating a reply.
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

async fn send_unimplemented(writer: &ControlWriter, number: u8) -> Result<()> {
    let mut encoder = Encoder::new();
    encoder.u8(number);
    send_control(writer, MSG_UNIMPLEMENTED, encoder.finish()).await
}

async fn send_disconnect(
    connection: &quinn::Connection,
    writer: &ControlWriter,
    description: &str,
) -> Result<()> {
    let mut encoder = Encoder::new();
    encoder.u32(1);
    encoder.string(description)?;
    let (result, stopped) = {
        let mut writer = writer.lock().await;
        let result = writer.send(MSG_DISCONNECT, &encoder.finish()).await;
        let stopped = if result.is_ok() {
            let _ = writer.finish().await;
            Some(writer.inner().stopped())
        } else {
            None
        };
        (result.map_err(Error::from), stopped)
    };
    if let Some(stopped) = stopped {
        let _ = tokio::time::timeout(DISCONNECT_DELIVERY_GRACE, stopped).await;
    }
    connection.close(1u32.into(), b"connection protocol error");
    result
}

async fn handle_server_global_request(writer: &ControlWriter, payload: &[u8]) -> Result<()> {
    let mut decoder = Decoder::new(payload);
    let name = decoder.string()?;
    let want_reply = decoder.boolean()?;
    let keepalive = name == "keepalive@fsh.dev";
    decoder.finish()?;
    if want_reply {
        send_control(
            writer,
            if keepalive {
                MSG_REQUEST_SUCCESS
            } else {
                MSG_REQUEST_FAILURE
            },
            Vec::new(),
        )
        .await?;
    }
    Ok(())
}

fn reset_stream(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let _ = send.reset(quinn::VarInt::from_u32(1));
    let _ = recv.stop(quinn::VarInt::from_u32(1));
}

fn is_transport_shutdown(error: &Error) -> bool {
    match error {
        Error::Quic(error) => matches!(
            error,
            quinn::ConnectionError::LocallyClosed
                | quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_)
        ),
        Error::Read(error) => matches!(
            error,
            quinn::ReadError::ConnectionLost(_) | quinn::ReadError::ClosedStream
        ),
        Error::Wire(crate::wire::WireError::Io(error)) => error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<quinn::ReadError>())
            .is_some_and(|cause| {
                matches!(
                    cause,
                    quinn::ReadError::ConnectionLost(_) | quinn::ReadError::ClosedStream
                )
            }),
        _ => false,
    }
}

fn valid_signal(name: &str) -> bool {
    name.len() <= MAX_SIGNAL_BYTES && name.is_ascii() && signal_number(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorizedKeys, Identity, UserAuthClient, UserAuthServer, make_client_endpoint,
        make_server_endpoint,
    };
    use std::{path::PathBuf, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    #[test]
    fn channel_open_uses_stream_index_as_id() {
        assert_eq!(encode_channel_id(7), vec![0, 0, 0, 7]);
        let (id, kind) = decode_open(&encode_open(7)).unwrap();
        assert_eq!(id, 7);
        assert_eq!(kind, "session");
    }

    #[test]
    fn exec_request_is_strict_and_round_trips() {
        let payload = encode_channel_request(1, &Command::Exec("printf hello".into())).unwrap();
        let request = decode_channel_request(&payload).unwrap();
        assert!(
            matches!(request.kind, ChannelRequestKind::Exec(command) if command == "printf hello")
        );
        assert!(request.want_reply);
    }

    #[test]
    fn channel_data_has_an_explicit_empty_string() {
        assert_eq!(
            encode_channel_data(1, &[]).unwrap(),
            vec![0, 0, 0, 1, 0, 0, 0, 0]
        );
    }

    #[test]
    fn disconnect_grammar_has_no_language_field() {
        let mut encoder = Encoder::new();
        encoder.u32(1);
        encoder.string("protocol error").unwrap();
        let payload = encoder.finish();
        assert_eq!(
            decode_disconnect(&payload).unwrap(),
            "peer disconnected (1): protocol error"
        );

        let mut legacy = payload;
        let mut language = Encoder::new();
        language.string("en").unwrap();
        legacy.extend_from_slice(&language.finish());
        assert!(decode_disconnect(&legacy).is_err());
    }

    #[test]
    fn malformed_disconnect_is_terminal_without_protocol_reply() {
        let mut encoder = Encoder::new();
        encoder.u32(0);
        encoder.string("invalid reason").unwrap();
        assert!(matches!(
            decode_disconnect(&encoder.finish()),
            Err(Error::RemoteDisconnect(_))
        ));
    }

    #[test]
    fn signal_tables_round_trip_every_standard_signal() {
        for signal in 1..=31 {
            if let Some(name) = signal_name(signal) {
                assert_eq!(signal_number(name), Some(signal), "signal {name}");
            }
        }
        // The previously misreported signals keep their own names now.
        assert_eq!(signal_name(libc::SIGXCPU), Some("XCPU"));
        assert_eq!(signal_number("XCPU"), Some(libc::SIGXCPU));
        assert_eq!(signal_name(libc::SIGXFSZ), Some("XFSZ"));
        // Unrecognized numbers stay unrecognized instead of degrading to TERM.
        assert_eq!(signal_name(64), None);
        assert_eq!(signal_number("NOTASIGNAL"), None);

        // Linux-only signals must stay covered without breaking other Unix
        // targets, where libc does not define them.
        #[cfg(target_os = "linux")]
        {
            assert_eq!(signal_name(libc::SIGSTKFLT), Some("STKFLT"));
            assert_eq!(signal_number("STKFLT"), Some(libc::SIGSTKFLT));
            assert_eq!(signal_name(libc::SIGPWR), Some("PWR"));
            assert_eq!(signal_number("PWR"), Some(libc::SIGPWR));
        }
    }

    #[test]
    fn unknown_signal_numbers_report_numeric_exit_status() {
        use std::os::unix::process::ExitStatusExt;

        // A recognized signal keeps the exit-signal report with its true name.
        let known = encode_exit_notification(7, &std::process::ExitStatus::from_raw(libc::SIGXCPU))
            .unwrap();
        let mut decoder = Decoder::new(&known);
        assert_eq!(decoder.u32().unwrap(), 7);
        assert_eq!(decoder.string().unwrap(), "exit-signal");
        assert!(!decoder.boolean().unwrap());
        assert_eq!(decoder.string().unwrap(), "XCPU");
        assert!(!decoder.boolean().unwrap());
        assert_eq!(decoder.string().unwrap(), "process terminated by signal");
        assert_eq!(decoder.string().unwrap(), "");
        decoder.finish().unwrap();

        // An unrecognized signal number must not be misreported as TERM; it
        // degrades to the conventional 128+n exit status.
        let unknown = encode_exit_notification(7, &std::process::ExitStatus::from_raw(64)).unwrap();
        let mut decoder = Decoder::new(&unknown);
        assert_eq!(decoder.u32().unwrap(), 7);
        assert_eq!(decoder.string().unwrap(), "exit-status");
        assert!(!decoder.boolean().unwrap());
        assert_eq!(decoder.u32().unwrap(), 128 + 64);
        decoder.finish().unwrap();
    }

    struct RawSession {
        client_transport: crate::ClientTransport,
        server_transport: crate::ServerTransport,
        connection: quinn::Connection,
        control_reader: FramedReader<quinn::RecvStream>,
        control_writer: FramedWriter<quinn::SendStream>,
        server_task: tokio::task::JoinHandle<Result<()>>,
        cleanup: Vec<PathBuf>,
    }

    impl RawSession {
        async fn start(config: SessionConfig) -> Self {
            let stem = format!(
                "fsh-lifecycle-{}-{}",
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
            let authorized =
                AuthorizedKeys::from_lines(&identity.public_key().to_openssh().unwrap()).unwrap();
            let server_identity =
                crate::ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
            let server_transport =
                make_server_endpoint("127.0.0.1:0".parse().unwrap(), server_identity).unwrap();
            let server_address = server_transport.endpoint.local_addr().unwrap();
            let server_endpoint = server_transport.endpoint.clone();
            let server_task = tokio::spawn(async move {
                let connection = server_endpoint.accept().await.unwrap().await.unwrap();
                let (send, recv) = connection.accept_bi().await.unwrap();
                let auth = UserAuthServer {
                    authorized_keys: authorized,
                    expected_username: Some("alice".into()),
                };
                let (_, reader, writer) = auth
                    .authenticate(
                        &connection,
                        FramedReader::new(recv),
                        FramedWriter::new(send),
                    )
                    .await
                    .unwrap();
                ServerSession::new(connection, reader, writer, config)
                    .run()
                    .await
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
            let (control_reader, control_writer) = auth
                .authenticate(
                    &connection,
                    FramedReader::new(recv),
                    FramedWriter::new(send),
                )
                .await
                .unwrap();
            Self {
                client_transport,
                server_transport,
                connection,
                control_reader,
                control_writer,
                server_task,
                cleanup: vec![key_path, cert_path, server_key_path],
            }
        }

        async fn open_channel(
            &mut self,
            command: &str,
        ) -> (
            FramedWriter<quinn::SendStream>,
            FramedReader<quinn::RecvStream>,
            u32,
        ) {
            let (send, recv) = self.connection.open_bi().await.unwrap();
            let id = send.id().index() as u32;
            let mut data_writer = FramedWriter::new(send);
            let data_reader = FramedReader::new(recv);
            self.control_writer
                .send(MSG_CHANNEL_OPEN, &encode_open(id))
                .await
                .unwrap();
            let frame = self.control_reader.next().await.unwrap().unwrap();
            assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);
            assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
            data_writer
                .send(MSG_CHANNEL_DATA, &encode_channel_data(id, &[]).unwrap())
                .await
                .unwrap();
            self.control_writer
                .send(
                    MSG_CHANNEL_REQUEST,
                    &encode_channel_request(id, &Command::Exec(command.into())).unwrap(),
                )
                .await
                .unwrap();
            let frame = self.control_reader.next().await.unwrap().unwrap();
            assert_eq!(frame.number, MSG_CHANNEL_SUCCESS);
            assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
            (data_writer, data_reader, id)
        }

        async fn wait_for_close(&mut self, id: u32) {
            loop {
                let frame = timeout(Duration::from_secs(2), self.control_reader.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                if frame.number == MSG_CHANNEL_CLOSE {
                    assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                    return;
                }
            }
        }

        async fn shutdown(self) -> Result<()> {
            self.connection.close(0u32.into(), b"test complete");
            self.client_transport
                .endpoint
                .close(0u32.into(), b"test complete");
            self.server_transport
                .endpoint
                .close(0u32.into(), b"test complete");
            let mut server_task = self.server_task;
            let result = match timeout(Duration::from_secs(2), &mut server_task).await {
                Ok(Ok(result)) => result,
                Ok(Err(error)) => Err(Error::Protocol(format!("server task join failed: {error}"))),
                Err(_) => {
                    server_task.abort();
                    let _ = timeout(Duration::from_secs(1), server_task).await;
                    Err(Error::Protocol("server task shutdown timed out".into()))
                }
            };
            for path in self.cleanup {
                let _ = std::fs::remove_file(path);
            }
            result
        }
    }

    fn live_pid(pid: i32) -> bool {
        let path = format!("/proc/{pid}/stat");
        let Ok(stat) = std::fs::read_to_string(path) else {
            return false;
        };
        stat.rsplit_once(") ")
            .and_then(|(_, rest)| rest.chars().next())
            .is_some_and(|state| state != 'Z')
    }

    async fn wait_for_pids_to_exit(pids: &[i32]) {
        timeout(Duration::from_secs(2), async {
            loop {
                if pids.iter().all(|pid| !live_pid(*pid)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_for_pid_file(path: &std::path::Path) -> Vec<i32> {
        timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(path) {
                    let pids = contents
                        .split_whitespace()
                        .map(|pid| pid.parse().unwrap())
                        .collect::<Vec<i32>>();
                    if !pids.is_empty() {
                        return pids;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_info_messages_do_not_trigger_unimplemented() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        session
            .control_writer
            .send(MSG_IGNORE, b"opaque transport padding")
            .await
            .unwrap();
        let mut debug = Encoder::new();
        debug.boolean(false);
        debug.string("diagnostic").unwrap();
        session
            .control_writer
            .send(MSG_DEBUG, &debug.finish())
            .await
            .unwrap();

        let (mut data_writer, _data_reader, id) = session.open_channel("true").await;
        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        data_writer.finish().await.unwrap();
        session.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_eof_does_not_replace_peer_fin() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (mut data_writer, mut data_reader, id) = session.open_channel("cat").await;
        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();

        let mut got_exit = false;
        let mut got_eof = false;
        let mut output_fin = false;
        let mut got_close = false;
        match timeout(Duration::from_millis(100), session.control_reader.next()).await {
            Err(_) => {}
            Ok(Ok(Some(frame))) => match frame.number {
                MSG_CHANNEL_REQUEST => {
                    assert!(
                        decode_exit_notification(id, &frame.payload)
                            .unwrap()
                            .is_some()
                    );
                    got_exit = true;
                }
                MSG_CHANNEL_EOF => {
                    assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                    got_eof = true;
                }
                MSG_CHANNEL_CLOSE => panic!("server closed before peer FIN"),
                other => panic!("unexpected control message {other}"),
            },
            Ok(other) => panic!("control stream ended before peer FIN: {other:?}"),
        }
        data_writer.finish().await.unwrap();

        while !(got_exit && got_eof && output_fin) {
            tokio::select! {
                frame = session.control_reader.next() => {
                    let frame = frame.unwrap().unwrap();
                    match frame.number {
                        MSG_CHANNEL_REQUEST => {
                            assert!(decode_exit_notification(id, &frame.payload).unwrap().is_some());
                            got_exit = true;
                        }
                        MSG_CHANNEL_EOF => {
                            assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                            got_eof = true;
                        }
                        MSG_CHANNEL_CLOSE => got_close = true,
                        other => panic!("unexpected control message {other}"),
                    }
                }
                frame = data_reader.next(), if !output_fin => {
                    let frame = frame.unwrap();
                    output_fin = frame.is_none();
                }
            }
        }
        if !got_close {
            session.wait_for_close(id).await;
        }
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closed_output_pipes_still_emit_exit_status() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (mut data_writer, mut data_reader, id) = session
            .open_channel("sh -c 'exec 1>&- 2>&-; sleep 0.2'")
            .await;

        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        data_writer.finish().await.unwrap();

        let mut got_exit = false;
        let mut got_eof = false;
        let mut output_fin = false;
        let mut got_close = false;
        timeout(Duration::from_secs(2), async {
            while !(got_exit && got_eof && output_fin) {
                tokio::select! {
                    frame = session.control_reader.next() => {
                        let frame = frame.unwrap().unwrap();
                        match frame.number {
                            MSG_CHANNEL_REQUEST => {
                                assert!(decode_exit_notification(id, &frame.payload).unwrap().is_some());
                                got_exit = true;
                            }
                            MSG_CHANNEL_EOF => {
                                assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                                got_eof = true;
                            }
                            MSG_CHANNEL_CLOSE => got_close = true,
                            other => panic!("unexpected control message {other}"),
                        }
                    }
                    frame = data_reader.next(), if !output_fin => {
                        assert!(frame.unwrap().is_none(), "command unexpectedly produced output");
                        output_fin = true;
                    }
                }
            }
        })
        .await
        .unwrap();

        if !got_close {
            session.wait_for_close(id).await;
        }
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn data_sent_after_control_eof_is_drained_before_input_fin() {
        let config = SessionConfig {
            close_timeout: Duration::from_millis(120),
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let (mut data_writer, mut data_reader, id) = session.open_channel("cat").await;

        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        // Let the independent control stream reach the daemon before the
        // channel stream carries the final DATA frame.
        tokio::time::sleep(Duration::from_millis(80)).await;
        data_writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(id, b"delayed-").unwrap(),
            )
            .await
            .unwrap();
        // Continued valid input extends the idle drain window; a fixed
        // deadline would terminate this channel before the second frame.
        tokio::time::sleep(Duration::from_millis(80)).await;
        data_writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(id, b"input").unwrap(),
            )
            .await
            .unwrap();
        data_writer.finish().await.unwrap();

        let mut output = Vec::new();
        while let Some(frame) = timeout(Duration::from_secs(2), data_reader.next())
            .await
            .unwrap()
            .unwrap()
        {
            assert_eq!(frame.number, MSG_CHANNEL_DATA);
            let mut decoder = Decoder::new(&frame.payload);
            assert_eq!(decoder.u32().unwrap(), id);
            output.extend_from_slice(decoder.bytes().unwrap());
            decoder.finish().unwrap();
        }
        assert_eq!(output, b"delayed-input");

        session.wait_for_close(id).await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_before_stream_fin_still_drains_channel_data() {
        let config = SessionConfig {
            max_channels: 1,
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let (mut data_writer, mut data_reader, id) =
            session.open_channel("sh -c 'printf ready; cat'").await;

        let frame = timeout(Duration::from_secs(2), data_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_DATA);
        let mut decoder = Decoder::new(&frame.payload);
        assert_eq!(decoder.u32().unwrap(), id);
        assert_eq!(decoder.bytes().unwrap(), b"ready");
        decoder.finish().unwrap();

        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        data_writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(id, b"close-race").unwrap(),
            )
            .await
            .unwrap();
        data_writer.finish().await.unwrap();

        let mut output = Vec::new();
        while let Some(frame) = timeout(Duration::from_secs(2), data_reader.next())
            .await
            .unwrap()
            .unwrap()
        {
            assert_eq!(frame.number, MSG_CHANNEL_DATA);
            let mut decoder = Decoder::new(&frame.payload);
            assert_eq!(decoder.u32().unwrap(), id);
            output.extend_from_slice(decoder.bytes().unwrap());
            decoder.finish().unwrap();
        }
        assert_eq!(output, b"close-race");

        session.wait_for_close(id).await;

        // The peer CLOSE arrived before the worker observed FIN. The channel
        // must still be released when the worker completes, not at timeout.
        let (mut next_writer, mut next_reader, next_id) = session.open_channel("true").await;
        assert_ne!(next_id, id);
        next_writer.finish().await.unwrap();
        timeout(Duration::from_secs(2), async {
            while next_reader.next().await.unwrap().is_some() {}
        })
        .await
        .unwrap();
        session.wait_for_close(next_id).await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(next_id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unattached_channel_is_expired() {
        let config = SessionConfig {
            max_channels: 1,
            request_timeout: Duration::from_millis(100),
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let first_id = 1;
        // Reserve the first client stream id without sending stream data; the
        // control-only channel must expire independently of stream allocation.
        let (_orphan_send, _orphan_recv) = session.connection.open_bi().await.unwrap();
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(first_id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);
        assert_eq!(decode_channel_id(&frame.payload).unwrap(), first_id);

        tokio::time::sleep(Duration::from_millis(150)).await;

        // The expired channel has no attached stream, so the server cannot
        // satisfy the peer-FIN precondition for CHANNEL_CLOSE. It releases
        // the active slot without sending a premature close; ids remain
        // tombstoned and cannot be reused.
        let second_id = 2;
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(second_id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);
        assert_eq!(decode_channel_id(&frame.payload).unwrap(), second_id);
        assert_ne!(second_id, first_id);
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn activated_channel_without_request_is_drained_and_released() {
        let config = SessionConfig {
            max_channels: 1,
            request_timeout: Duration::from_millis(100),
            close_timeout: Duration::from_millis(200),
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let (send, _recv) = session.connection.open_bi().await.unwrap();
        let first_id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(first_id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);
        data_writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(first_id, &[]).unwrap(),
            )
            .await
            .unwrap();
        data_writer.finish().await.unwrap();

        let mut server_close = false;
        while !server_close {
            let frame = timeout(Duration::from_secs(2), session.control_reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            match frame.number {
                MSG_CHANNEL_EOF => {
                    assert_eq!(decode_channel_id(&frame.payload).unwrap(), first_id);
                }
                MSG_CHANNEL_CLOSE => {
                    assert_eq!(decode_channel_id(&frame.payload).unwrap(), first_id);
                    server_close = true;
                }
                other => panic!("unexpected message while draining abandoned channel: {other}"),
            }
        }
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(first_id))
            .await
            .unwrap();

        let (send, _recv) = session.connection.open_bi().await.unwrap();
        let second_id = send.id().index() as u32;
        assert_ne!(first_id, second_id);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(second_id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);
        assert_eq!(decode_channel_id(&frame.payload).unwrap(), second_id);
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_request_waits_for_stream_activation() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (send, recv) = session.connection.open_bi().await.unwrap();
        let id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        let mut data_reader = FramedReader::new(recv);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);

        // The control request may race ahead of accept_bi(), but it must not
        // be accepted until the peer has activated its channel stream.
        session
            .control_writer
            .send(
                MSG_CHANNEL_REQUEST,
                &encode_channel_request(id, &Command::Exec("true".into())).unwrap(),
            )
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(50), session.control_reader.next())
                .await
                .is_err()
        );

        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_data(id, &[]).unwrap())
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_SUCCESS);
        assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);

        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        data_writer.finish().await.unwrap();
        let mut server_close = false;
        while !server_close {
            let frame = timeout(Duration::from_secs(2), session.control_reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if frame.number == MSG_CHANNEL_CLOSE {
                assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                server_close = true;
            }
        }
        while data_reader.next().await.unwrap().is_some() {}
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_activation_frame_is_not_accepted_as_ready() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (send, recv) = session.connection.open_bi().await.unwrap();
        let id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        let mut data_reader = FramedReader::new(recv);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);

        let mut encoded = Vec::new();
        Frame::new(MSG_CHANNEL_DATA, encode_channel_data(id, &[]).unwrap())
            .unwrap()
            .encode(&mut encoded)
            .unwrap();
        let mut raw_send = data_writer.into_inner();
        raw_send.write_all(&encoded[..7]).await.unwrap();
        data_writer = FramedWriter::new(raw_send);

        session
            .control_writer
            .send(
                MSG_CHANNEL_REQUEST,
                &encode_channel_request(id, &Command::Exec("true".into())).unwrap(),
            )
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(80), session.control_reader.next())
                .await
                .is_err(),
            "partial framing must not activate a channel"
        );

        let mut raw_send = data_writer.into_inner();
        raw_send.write_all(&encoded[7..]).await.unwrap();
        data_writer = FramedWriter::new(raw_send);
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_SUCCESS);
        assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);

        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        data_writer.finish().await.unwrap();
        while data_reader.next().await.unwrap().is_some() {}
        let mut got_close = false;
        while !got_close {
            let frame = timeout(Duration::from_secs(2), session.control_reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            got_close = frame.number == MSG_CHANNEL_CLOSE;
        }
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn activation_preserves_the_first_valid_data_frame() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (send, recv) = session.connection.open_bi().await.unwrap();
        let id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        let mut data_reader = FramedReader::new(recv);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);

        data_writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(id, b"prefix-").unwrap(),
            )
            .await
            .unwrap();
        session
            .control_writer
            .send(
                MSG_CHANNEL_REQUEST,
                &encode_channel_request(id, &Command::Exec("cat".into())).unwrap(),
            )
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_SUCCESS);

        data_writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(id, b"suffix").unwrap(),
            )
            .await
            .unwrap();
        data_writer.finish().await.unwrap();
        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();

        let mut output = Vec::new();
        while let Some(frame) = timeout(Duration::from_secs(2), data_reader.next())
            .await
            .unwrap()
            .unwrap()
        {
            assert_eq!(frame.number, MSG_CHANNEL_DATA);
            let mut decoder = Decoder::new(&frame.payload);
            assert_eq!(decoder.u32().unwrap(), id);
            output.extend_from_slice(decoder.bytes().unwrap());
            decoder.finish().unwrap();
        }
        assert_eq!(output, b"prefix-suffix");

        let mut got_close = false;
        while !got_close {
            let frame = timeout(Duration::from_secs(2), session.control_reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            got_close = frame.number == MSG_CHANNEL_CLOSE;
        }
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_activation_is_channel_local_and_does_not_start_a_worker() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (send, recv) = session.connection.open_bi().await.unwrap();
        let id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        let mut data_reader = FramedReader::new(recv);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);

        data_writer
            .send(
                MSG_CHANNEL_EXTENDED_DATA,
                &encode_channel_data(id, b"not valid client input").unwrap(),
            )
            .await
            .unwrap();
        data_writer.finish().await.unwrap();
        session
            .control_writer
            .send(
                MSG_CHANNEL_REQUEST,
                &encode_channel_request(id, &Command::Exec("echo must-not-run".into())).unwrap(),
            )
            .await
            .unwrap();

        let mut got_eof = false;
        let mut got_close = false;
        while !got_close {
            let frame = timeout(Duration::from_secs(2), session.control_reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            match frame.number {
                MSG_CHANNEL_EOF => {
                    assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                    got_eof = true;
                }
                MSG_CHANNEL_FAILURE => {
                    assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                }
                MSG_CHANNEL_CLOSE => {
                    assert!(got_eof);
                    assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                    got_close = true;
                }
                MSG_CHANNEL_SUCCESS => panic!("invalid activation started a worker"),
                MSG_DISCONNECT => panic!("invalid channel data closed the connection"),
                other => panic!("unexpected invalid-activation message {other}"),
            }
        }
        assert!(data_reader.next().await.unwrap().is_none());
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();

        // A malformed channel must not poison unrelated channels.
        let (mut next_writer, mut next_reader, next_id) = session.open_channel("true").await;
        next_writer.finish().await.unwrap();
        while next_reader.next().await.unwrap().is_some() {}
        session.wait_for_close(next_id).await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(next_id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejected_channel_id_cannot_be_reopened() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let id = 1;
        let mut unsupported = Encoder::new();
        unsupported.string("forwarded-tcpip").unwrap();
        unsupported.u32(id);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &unsupported.finish())
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_FAILURE);
        assert_eq!(decode_open_failure(&frame.payload).unwrap().0, id);

        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_FAILURE);
        assert_eq!(decode_open_failure(&frame.payload).unwrap().0, id);
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_stream_for_rejected_channel_is_reset() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let id = 1;
        let mut unsupported = Encoder::new();
        unsupported.string("forwarded-tcpip").unwrap();
        unsupported.u32(id);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &unsupported.finish())
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_FAILURE);

        let (send, recv) = session.connection.open_bi().await.unwrap();
        assert_eq!(send.id().index() as u32, id);
        let mut writer = FramedWriter::new(send);
        let mut reader = FramedReader::new(recv);
        let _ = writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(id, b"orphan").unwrap(),
            )
            .await;
        assert!(
            timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .is_err()
        );
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_preopen_frame_does_not_stall_control_processing() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (mut data_send, data_recv) = session.connection.open_bi().await.unwrap();
        let id = data_send.id().index() as u32;
        data_send.write_all(&[0]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);

        // The prefix was discarded before OPEN. A fresh activation frame and
        // the following stdin must still decode normally.
        let mut data_writer = FramedWriter::new(data_send);
        let mut data_reader = FramedReader::new(data_recv);
        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_data(id, &[]).unwrap())
            .await
            .unwrap();
        session
            .control_writer
            .send(
                MSG_CHANNEL_REQUEST,
                &encode_channel_request(id, &Command::Exec("cat".into())).unwrap(),
            )
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_SUCCESS);
        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_data(id, b"kept").unwrap())
            .await
            .unwrap();
        data_writer.finish().await.unwrap();

        let mut output = Vec::new();
        while let Some(frame) = timeout(Duration::from_secs(2), data_reader.next())
            .await
            .unwrap()
            .unwrap()
        {
            assert_eq!(frame.number, MSG_CHANNEL_DATA);
            let mut decoder = Decoder::new(&frame.payload);
            assert_eq!(decoder.u32().unwrap(), id);
            output.extend_from_slice(decoder.bytes().unwrap());
            decoder.finish().unwrap();
        }
        assert_eq!(output, b"kept");
        session.wait_for_close(id).await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_preopen_stream_does_not_stall_later_control_or_channels() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (_empty_send, _empty_recv) = session.connection.open_bi().await.unwrap();
        tokio::task::yield_now().await;

        // The first stream remains completely idle. A synchronous probe in
        // the session loop would prevent this control request and all later
        // channel processing from making progress.
        session
            .control_writer
            .send(
                MSG_GLOBAL_REQUEST,
                &encode_global_request("keepalive@fsh.dev", true),
            )
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(1), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_REQUEST_SUCCESS);

        let (mut data_writer, mut data_reader, id) = session.open_channel("printf later").await;
        data_writer.finish().await.unwrap();
        while data_reader.next().await.unwrap().is_some() {}
        session.wait_for_close(id).await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn preopen_data_is_discarded_and_open_activates() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (send, recv) = session.connection.open_bi().await.unwrap();
        let id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        let mut data_reader = FramedReader::new(recv);
        data_writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(id, b"must-be-discarded").unwrap(),
            )
            .await
            .unwrap();
        // Let the server observe the stream before OPEN. This makes the
        // pre-OPEN discard boundary deterministic rather than depending on
        // cross-stream QUIC scheduling.
        tokio::time::sleep(Duration::from_millis(50)).await;

        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_CONFIRM);
        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_data(id, &[]).unwrap())
            .await
            .unwrap();
        session
            .control_writer
            .send(
                MSG_CHANNEL_REQUEST,
                &encode_channel_request(id, &Command::Exec("cat".into())).unwrap(),
            )
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_SUCCESS);
        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_data(id, b"kept").unwrap())
            .await
            .unwrap();
        data_writer.finish().await.unwrap();
        let mut output = Vec::new();
        while let Some(frame) = timeout(Duration::from_secs(2), data_reader.next())
            .await
            .unwrap()
            .unwrap()
        {
            assert_eq!(frame.number, MSG_CHANNEL_DATA);
            let mut decoder = Decoder::new(&frame.payload);
            assert_eq!(decoder.u32().unwrap(), id);
            output.extend_from_slice(decoder.bytes().unwrap());
            decoder.finish().unwrap();
        }
        assert_eq!(output, b"kept");
        session.wait_for_close(id).await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn preopen_data_for_unknown_type_uses_type_failure_reason() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (send, recv) = session.connection.open_bi().await.unwrap();
        let id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        let _data_reader = FramedReader::new(recv);
        data_writer
            .send(
                MSG_CHANNEL_DATA,
                &encode_channel_data(id, b"must-be-discarded").unwrap(),
            )
            .await
            .unwrap();
        tokio::task::yield_now().await;

        let mut unsupported = Encoder::new();
        unsupported.string("forwarded-tcpip").unwrap();
        unsupported.u32(id);
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &unsupported.finish())
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let (failure_id, message) = decode_open_failure(&frame.payload).unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_OPEN_FAILURE);
        assert_eq!(failure_id, id);
        assert!(message.contains("channel rejected (3)"));
        drop(data_writer);
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fin_before_open_has_no_channel_response() {
        let config = SessionConfig {
            request_timeout: Duration::from_millis(50),
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let (send, recv) = session.connection.open_bi().await.unwrap();
        let id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        let _data_reader = FramedReader::new(recv);
        data_writer.finish().await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), session.control_reader.next())
                .await
                .is_err()
        );
        let (mut next_writer, mut next_reader, next_id) = session.open_channel("true").await;
        assert_ne!(next_id, id);
        next_writer.finish().await.unwrap();
        while next_reader.next().await.unwrap().is_some() {}
        session.wait_for_close(next_id).await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(next_id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejected_command_closes_an_accepted_channel() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (send, recv) = session.connection.open_bi().await.unwrap();
        let id = send.id().index() as u32;
        let mut data_writer = FramedWriter::new(send);
        let mut data_reader = FramedReader::new(recv);

        session
            .control_writer
            .send(MSG_CHANNEL_OPEN, &encode_open(id))
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), session.control_reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .number,
            MSG_CHANNEL_OPEN_CONFIRM
        );
        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_data(id, &[]).unwrap())
            .await
            .unwrap();
        session
            .control_writer
            .send(
                MSG_CHANNEL_REQUEST,
                &encode_channel_request(id, &Command::Exec(String::new())).unwrap(),
            )
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_CHANNEL_FAILURE);

        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        let _ = data_writer.finish().await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();

        let mut peer_fin = false;
        let mut peer_close = false;
        timeout(Duration::from_secs(2), async {
            while !(peer_fin && peer_close) {
                tokio::select! {
                    frame = data_reader.next(), if !peer_fin => {
                        peer_fin = match frame {
                            Ok(frame) => frame.is_none(),
                            Err(_) => true,
                        };
                    }
                    frame = session.control_reader.next(), if !peer_close => {
                        let frame = frame.unwrap().unwrap();
                        if frame.number == MSG_CHANNEL_CLOSE {
                            assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                            peer_close = true;
                        }
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_data_with_close_before_fin_waits_for_peer_fin() {
        let config = SessionConfig {
            close_timeout: Duration::from_millis(300),
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let (mut data_writer, mut data_reader, id) = session.open_channel("cat").await;

        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_id(id))
            .await
            .unwrap();
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();

        // The malformed DATA and peer CLOSE do not waive the peer-FIN
        // precondition. The server may finish the process and emit EOF while
        // the input stream is still open, but it must not send CHANNEL_CLOSE.
        let mut early_frames = Vec::new();
        let early_result = timeout(Duration::from_millis(120), async {
            loop {
                let frame = session.control_reader.next().await.unwrap().unwrap();
                assert_ne!(frame.number, MSG_CHANNEL_CLOSE);
                assert_ne!(frame.number, MSG_DISCONNECT);
                early_frames.push(frame);
            }
        })
        .await;
        assert!(early_result.is_err(), "server closed before peer FIN");

        data_writer.finish().await.unwrap();
        let mut got_exit = early_frames
            .iter()
            .any(|frame| frame.number == MSG_CHANNEL_REQUEST);
        let mut got_eof = early_frames
            .iter()
            .any(|frame| frame.number == MSG_CHANNEL_EOF);
        let mut got_close = false;
        let mut output_fin = false;
        timeout(Duration::from_secs(2), async {
            while !(got_close && output_fin) {
                tokio::select! {
                    frame = session.control_reader.next(), if !got_close => {
                        let frame = frame.unwrap().unwrap();
                        match frame.number {
                            MSG_CHANNEL_REQUEST => {
                                assert!(decode_exit_notification(id, &frame.payload).unwrap().is_some());
                                got_exit = true;
                            }
                            MSG_CHANNEL_EOF => {
                                assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                                got_eof = true;
                            }
                            MSG_CHANNEL_CLOSE => {
                                assert!(got_exit && got_eof);
                                assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                                got_close = true;
                            }
                            MSG_DISCONNECT => panic!("channel drain became a connection failure"),
                            other => panic!("unexpected control message {other}"),
                        }
                    }
                    frame = data_reader.next(), if !output_fin => {
                        assert!(frame.unwrap().is_none(), "malformed input produced output");
                        output_fin = true;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(got_exit && got_eof && got_close && output_fin);
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_failure_without_peer_fin_is_channel_local() {
        let config = SessionConfig {
            close_timeout: Duration::from_millis(100),
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let (mut data_writer, mut data_reader, id) = session.open_channel("cat").await;
        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();

        timeout(Duration::from_millis(250), async {
            loop {
                match session.control_reader.next().await {
                    Ok(Some(frame)) => match frame.number {
                        MSG_CHANNEL_REQUEST | MSG_CHANNEL_EOF => {}
                        MSG_CHANNEL_CLOSE => {
                            panic!("server closed without observing peer FIN")
                        }
                        MSG_DISCONNECT => panic!("channel failure became a connection failure"),
                        other => panic!("unexpected control message {other}"),
                    },
                    Ok(None) | Err(_) => panic!("control session ended during channel cleanup"),
                }
            }
        })
        .await
        .expect_err("server emitted a terminal connection event before peer FIN");

        data_writer.finish().await.unwrap();
        let _ = timeout(Duration::from_secs(1), data_reader.next()).await;
        if let Ok(Ok(Some(frame))) =
            timeout(Duration::from_millis(250), session.control_reader.next()).await
        {
            match frame.number {
                MSG_CHANNEL_REQUEST | MSG_CHANNEL_EOF => {}
                MSG_CHANNEL_CLOSE => {
                    assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                    session
                        .control_writer
                        .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
                        .await
                        .unwrap();
                }
                MSG_DISCONNECT => panic!("channel failure became a connection failure"),
                other => panic!("unexpected control message {other}"),
            }
        }
        // A malformed channel must not poison the connection's global
        // request domain; the next channel/global message remains usable.
        session
            .control_writer
            .send(
                MSG_GLOBAL_REQUEST,
                &encode_global_request("keepalive@fsh.dev", true),
            )
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.number, MSG_REQUEST_SUCCESS);
        assert!(frame.payload.is_empty());
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_request_after_close_is_a_connection_error() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (mut data_writer, _data_reader, id) = session.open_channel("cat").await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        session
            .control_writer
            .send(
                MSG_CHANNEL_REQUEST,
                &encode_channel_request(id, &Command::Exec("echo should-not-run".into())).unwrap(),
            )
            .await
            .unwrap();

        let mut saw_disconnect = false;
        timeout(Duration::from_secs(2), async {
            while !saw_disconnect {
                match session.control_reader.next().await {
                    Ok(Some(frame)) => {
                        assert_ne!(
                            frame.number, MSG_CHANNEL_SUCCESS,
                            "request after CLOSE was acknowledged"
                        );
                        saw_disconnect = frame.number == MSG_DISCONNECT;
                    }
                    Ok(None) | Err(_) => saw_disconnect = true,
                }
            }
        })
        .await
        .unwrap();
        let _ = data_writer.finish().await;
        assert!(session.shutdown().await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_failure_finishes_output_before_channel_close() {
        let config = SessionConfig {
            close_timeout: Duration::from_millis(300),
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let (mut data_writer, mut data_reader, id) = session
            .open_channel("fsh-command-that-does-not-exist")
            .await;
        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        data_writer.finish().await.unwrap();

        let mut output_fin = false;
        let mut peer_close = false;
        timeout(Duration::from_secs(2), async {
            while !(output_fin && peer_close) {
                tokio::select! {
                    frame = data_reader.next(), if !output_fin => {
                        assert!(frame.unwrap().is_none(), "spawn failure produced output");
                        output_fin = true;
                    }
                    frame = session.control_reader.next(), if !peer_close => {
                        let frame = frame.unwrap().unwrap();
                        if frame.number == MSG_CHANNEL_CLOSE {
                            assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                            peer_close = true;
                        }
                    }
                }
            }
        })
        .await
        .unwrap();
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_close_kills_a_stalled_input_worker_without_fin() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (mut data_writer, mut data_reader, id) = session.open_channel("cat").await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();

        let mut output_fin = false;
        timeout(Duration::from_secs(2), async {
            while !output_fin {
                tokio::select! {
                    frame = data_reader.next(), if !output_fin => {
                        output_fin = match frame {
                            Ok(frame) => frame.is_none(),
                            Err(_) => true,
                        };
                    }
                    frame = session.control_reader.next() => {
                        let frame = frame.unwrap().unwrap();
                        assert_ne!(frame.number, MSG_CHANNEL_CLOSE, "CLOSE preceded peer FIN");
                    }
                }
            }
        })
        .await
        .unwrap();
        data_writer.finish().await.unwrap();
        session.wait_for_close(id).await;
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_eof_without_stream_fin_has_bounded_cleanup() {
        let pid_path = std::env::temp_dir().join(format!(
            "fsh-eof-timeout-{}-{}.pids",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = format!(
            "sh -c 'sleep 60 & child=$!; printf \"%s %s\" \"$$\" \"$child\" > {}; wait'",
            pid_path.display()
        );
        let config = SessionConfig {
            close_timeout: Duration::from_millis(150),
            ..SessionConfig::default()
        };
        let mut session = RawSession::start(config).await;
        let (mut data_writer, mut data_reader, id) = session.open_channel(&command).await;
        let pids = wait_for_pid_file(&pid_path).await;

        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        let mut output_fin = false;
        timeout(Duration::from_secs(2), async {
            while !output_fin {
                tokio::select! {
                    frame = data_reader.next(), if !output_fin => {
                        output_fin = frame.unwrap().is_none();
                    }
                    frame = session.control_reader.next() => {
                        let frame = frame.unwrap().unwrap();
                        assert_ne!(frame.number, MSG_CHANNEL_CLOSE, "CLOSE preceded peer FIN");
                    }
                }
            }
        })
        .await
        .unwrap();
        data_writer.finish().await.unwrap();
        session.wait_for_close(id).await;
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while data_reader.next().await.unwrap().is_some() {}
        })
        .await
        .unwrap();
        assert!(session.shutdown().await.is_ok());
        wait_for_pids_to_exit(&pids).await;
        let _ = std::fs::remove_file(pid_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn early_channel_close_kills_the_whole_process_group() {
        let pid_path = std::env::temp_dir().join(format!(
            "fsh-process-group-{}-{}.pids",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = format!(
            "sh -c 'sleep 60 & child=$!; printf \"%s %s\" \"$$\" \"$child\" > {}; wait'",
            pid_path.display()
        );
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (mut data_writer, mut data_reader, id) = session.open_channel(&command).await;
        let pids = wait_for_pid_file(&pid_path).await;

        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        data_writer.finish().await.unwrap();
        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        session.wait_for_close(id).await;
        timeout(Duration::from_secs(2), async {
            while data_reader.next().await.unwrap().is_some() {}
        })
        .await
        .unwrap();
        assert!(session.shutdown().await.is_ok());
        wait_for_pids_to_exit(&pids).await;
        let _ = std::fs::remove_file(pid_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_control_frame_cleans_up_active_worker() {
        let pid_path = std::env::temp_dir().join(format!(
            "fsh-malformed-worker-{}-{}.pid",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = format!(
            "sh -c 'printf \"%s\" \"$$\" > {}; sleep 60'",
            pid_path.display()
        );
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (_data_writer, _data_reader, id) = session.open_channel(&command).await;
        let pids = wait_for_pid_file(&pid_path).await;
        let mut malformed = encode_channel_id(id);
        malformed.push(0);
        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &malformed)
            .await
            .unwrap();
        if let Ok(Some(frame)) = timeout(Duration::from_secs(2), session.control_reader.next())
            .await
            .unwrap()
        {
            assert_eq!(frame.number, MSG_DISCONNECT);
        }
        assert!(session.shutdown().await.is_err());
        wait_for_pids_to_exit(&pids).await;
        let _ = std::fs::remove_file(pid_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_channel_data_has_terminal_sequence_before_close() {
        let mut session = RawSession::start(SessionConfig::default()).await;
        let (mut data_writer, mut data_reader, id) = session.open_channel("cat").await;
        data_writer
            .send(MSG_CHANNEL_DATA, &encode_channel_id(id))
            .await
            .unwrap();
        session
            .control_writer
            .send(MSG_CHANNEL_EOF, &encode_channel_id(id))
            .await
            .unwrap();
        data_writer.finish().await.unwrap();

        let mut got_exit = false;
        let mut got_eof = false;
        let mut output_fin = false;
        let mut got_close = false;
        timeout(Duration::from_secs(2), async {
            // Control and channel data use independent QUIC streams, so the
            // peer may observe CLOSE before the output FIN even though the
            // sender issued FIN first. Keep draining both until both terminal
            // events have arrived.
            while !(got_close && output_fin) {
                tokio::select! {
                    frame = session.control_reader.next() => {
                        let frame = frame.unwrap().unwrap();
                        match frame.number {
                            MSG_CHANNEL_REQUEST => {
                                assert!(decode_exit_notification(id, &frame.payload).unwrap().is_some());
                                assert!(!got_close);
                                got_exit = true;
                            }
                            MSG_CHANNEL_EOF => {
                                assert!(got_exit);
                                assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                                got_eof = true;
                            }
                            MSG_CHANNEL_CLOSE => {
                                assert!(got_eof);
                                assert_eq!(decode_channel_id(&frame.payload).unwrap(), id);
                                got_close = true;
                            }
                            other => panic!("unexpected control message {other}"),
                        }
                    }
                    frame = data_reader.next(), if !output_fin => {
                        let frame = frame.unwrap();
                        assert!(frame.is_none(), "malformed input produced output");
                        output_fin = true;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(
            got_exit && got_eof && output_fin,
            "got_exit={got_exit} got_eof={got_eof} output_fin={output_fin}"
        );

        session
            .control_writer
            .send(MSG_CHANNEL_CLOSE, &encode_channel_id(id))
            .await
            .unwrap();
        assert!(session.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_aborts_after_oversized_control_frame() {
        let stem = format!(
            "fsh-oversized-control-{}-{}",
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
        let authorized =
            AuthorizedKeys::from_lines(&identity.public_key().to_openssh().unwrap()).unwrap();
        let server_identity =
            crate::ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport =
            make_server_endpoint("127.0.0.1:0".parse().unwrap(), server_identity).unwrap();
        let server_address = server_transport.endpoint.local_addr().unwrap();
        let server_endpoint = server_transport.endpoint.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let auth = UserAuthServer {
                authorized_keys: authorized,
                expected_username: Some("alice".into()),
            };
            let (_, mut reader, writer) = auth
                .authenticate(
                    &connection,
                    FramedReader::new(recv),
                    FramedWriter::new(send),
                )
                .await
                .unwrap();
            let request = timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(request.number, MSG_GLOBAL_REQUEST);

            let mut raw = writer.into_inner();
            raw.write_all(&(MAX_FRAME_SIZE + 1).to_be_bytes())
                .await
                .unwrap();
            raw.flush().await.unwrap();

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
                Ok(Ok(None)) | Ok(Err(_)) => {}
                Ok(Ok(Some(frame))) => panic!(
                    "client sent message {} after protocol disconnect",
                    frame.number
                ),
                Err(_) => panic!("client did not close after protocol disconnect"),
            }
        });

        let client_transport = make_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_transport.identity.pin()),
        )
        .unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let mut client = ClientSession::connect(
            &client_transport.endpoint,
            server_address,
            "fsh.local",
            auth,
            SessionConfig::default(),
        )
        .await
        .unwrap();
        let result = client.keepalive().await;
        assert!(
            matches!(
                result,
                Err(Error::Wire(crate::wire::WireError::FrameTooLarge(_)))
            ),
            "{result:?}"
        );

        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_task.await.unwrap();
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_keepalive_closes_connection_and_clears_correlation() {
        let stem = format!(
            "fsh-cancelled-keepalive-{}-{}",
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
        let authorized =
            AuthorizedKeys::from_lines(&identity.public_key().to_openssh().unwrap()).unwrap();
        let server_identity =
            crate::ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport =
            make_server_endpoint("127.0.0.1:0".parse().unwrap(), server_identity).unwrap();
        let server_address = server_transport.endpoint.local_addr().unwrap();
        let server_endpoint = server_transport.endpoint.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let auth = UserAuthServer {
                authorized_keys: authorized,
                expected_username: Some("alice".into()),
            };
            let (_, mut reader, _writer) = auth
                .authenticate(
                    &connection,
                    FramedReader::new(recv),
                    FramedWriter::new(send),
                )
                .await
                .unwrap();
            let request = timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(request.number, MSG_GLOBAL_REQUEST);
            let mut decoder = Decoder::new(&request.payload);
            assert_eq!(decoder.string().unwrap(), "keepalive@fsh.dev");
            assert!(decoder.boolean().unwrap());
            decoder.finish().unwrap();
            match timeout(Duration::from_secs(2), reader.next()).await {
                Ok(Ok(Some(frame))) => panic!(
                    "canceled client sent message {} after its request was canceled",
                    frame.number
                ),
                Ok(Ok(None)) | Ok(Err(_)) => {}
                Err(_) => panic!("canceled client connection remained open"),
            }
        });

        let client_transport = make_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_transport.identity.pin()),
        )
        .unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let mut client = ClientSession::connect(
            &client_transport.endpoint,
            server_address,
            "fsh.local",
            auth,
            SessionConfig {
                request_timeout: Duration::from_secs(2),
                ..SessionConfig::default()
            },
        )
        .await
        .unwrap();
        assert!(
            timeout(Duration::from_millis(25), client.keepalive())
                .await
                .is_err()
        );

        let next = timeout(Duration::from_secs(1), client.keepalive())
            .await
            .unwrap()
            .unwrap_err();
        assert!(!matches!(
            next,
            Error::Protocol(message) if message == "global request already outstanding"
        ));

        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_task.await.unwrap();
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_client_dispatcher_answers_server_keepalive() {
        let stem = format!(
            "fsh-idle-dispatcher-{}-{}",
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
        let authorized =
            AuthorizedKeys::from_lines(&identity.public_key().to_openssh().unwrap()).unwrap();
        let server_identity =
            crate::ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport =
            make_server_endpoint("127.0.0.1:0".parse().unwrap(), server_identity).unwrap();
        let server_address = server_transport.endpoint.local_addr().unwrap();
        let server_endpoint = server_transport.endpoint.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let auth = UserAuthServer {
                authorized_keys: authorized,
                expected_username: Some("alice".into()),
            };
            let (_, mut reader, mut writer) = auth
                .authenticate(
                    &connection,
                    FramedReader::new(recv),
                    FramedWriter::new(send),
                )
                .await
                .unwrap();
            writer
                .send(
                    MSG_GLOBAL_REQUEST,
                    &encode_global_request("keepalive@fsh.dev", true),
                )
                .await
                .unwrap();
            let reply = timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(reply.number, MSG_REQUEST_SUCCESS);
            assert!(reply.payload.is_empty());
        });

        let client_transport = make_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_transport.identity.pin()),
        )
        .unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let client = ClientSession::connect(
            &client_transport.endpoint,
            server_address,
            "fsh.local",
            auth,
            SessionConfig::default(),
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        client.connection().close(0u32.into(), b"test complete");
        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_dispatcher_rejects_server_initiated_streams() {
        let stem = format!(
            "fsh-server-stream-{}-{}",
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
        let authorized =
            AuthorizedKeys::from_lines(&identity.public_key().to_openssh().unwrap()).unwrap();
        let server_identity =
            crate::ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport =
            make_server_endpoint("127.0.0.1:0".parse().unwrap(), server_identity).unwrap();
        let server_address = server_transport.endpoint.local_addr().unwrap();
        let server_endpoint = server_transport.endpoint.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let auth = UserAuthServer {
                authorized_keys: authorized,
                expected_username: Some("alice".into()),
            };
            let (_, mut reader, _writer) = auth
                .authenticate(
                    &connection,
                    FramedReader::new(recv),
                    FramedWriter::new(send),
                )
                .await
                .unwrap();
            let (mut bogus_send, mut bogus_recv) = connection.open_bi().await.unwrap();
            bogus_send.finish().unwrap();
            let frame = timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(frame.number, MSG_DISCONNECT);
            let _ = bogus_recv.stop(quinn::VarInt::from_u32(1));
        });

        let client_transport = make_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_transport.identity.pin()),
        )
        .unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let client = ClientSession::connect(
            &client_transport.endpoint,
            server_address,
            "fsh.local",
            auth,
            SessionConfig::default(),
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        client.connection().close(0u32.into(), b"test complete");
        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shell_request_runs_the_configured_login_shell() {
        let config = SessionConfig {
            login_shell: Some("/bin/sh".into()),
            ..SessionConfig::default()
        };
        let key_path = std::env::temp_dir().join(format!(
            "fsh-shell-test-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cert_path = key_path.with_extension("cert");
        let server_key_path = key_path.with_extension("server-key");
        let identity = Identity::generate_ed25519(&key_path).unwrap();
        let authorized =
            AuthorizedKeys::from_lines(&identity.public_key().to_openssh().unwrap()).unwrap();
        let server_identity =
            crate::ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport =
            make_server_endpoint("127.0.0.1:0".parse().unwrap(), server_identity).unwrap();
        let server_pin = server_transport.identity.pin();
        let server_endpoint = server_transport.endpoint.clone();
        let server_address = server_endpoint.local_addr().unwrap();
        let server_config = config.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let auth = UserAuthServer {
                authorized_keys: authorized,
                expected_username: Some("alice".into()),
            };
            let (_, reader, writer) = auth
                .authenticate(
                    &connection,
                    FramedReader::new(recv),
                    FramedWriter::new(send),
                )
                .await
                .unwrap();
            ServerSession::new(connection, reader, writer, server_config)
                .run()
                .await
        });

        let client_transport =
            make_client_endpoint("127.0.0.1:0".parse().unwrap(), Some(server_pin)).unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let mut client = ClientSession::connect(
            &client_transport.endpoint,
            server_address,
            "fsh.local",
            auth,
            config,
        )
        .await
        .unwrap();
        // The client reads `input`; feed it through the peer half, like a
        // live terminal pipe, and keep that half open so the drain path for
        // still-open stdin is exercised.
        let (mut input, mut input_writer) = tokio::io::duplex(1024);
        input_writer
            .write_all(b"printf shell-marker\nexit\n")
            .await
            .unwrap();
        let (mut stdout_reader, mut stdout_writer) = tokio::io::duplex(1024);
        let (mut stderr_reader, mut stderr_writer) = tokio::io::duplex(1024);
        let status_result = client
            .exec(
                Command::Shell,
                &mut input,
                &mut stdout_writer,
                &mut stderr_writer,
            )
            .await;
        drop(stdout_writer);
        drop(stderr_writer);
        let mut stdout = Vec::new();
        stdout_reader.read_to_end(&mut stdout).await.unwrap();
        let mut stderr = Vec::new();
        stderr_reader.read_to_end(&mut stderr).await.unwrap();
        client.connection().close(0u32.into(), b"test complete");
        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        let server_result = server_task.await.unwrap();
        assert!(
            server_result.is_ok(),
            "server session failed: {server_result:?}"
        );
        assert_eq!(status_result.unwrap(), ExitStatus::Code(0));
        assert_eq!(stdout, b"shell-marker");
        assert_eq!(stderr, Vec::<u8>::new());
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_exec_round_trip_over_quic() {
        let key_path = std::env::temp_dir().join(format!(
            "fsh-test-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cert_path = key_path.with_extension("cert");
        let server_key_path = key_path.with_extension("server-key");
        let identity = Identity::generate_ed25519(&key_path).unwrap();
        let authorized =
            AuthorizedKeys::from_lines(&identity.public_key().to_openssh().unwrap()).unwrap();
        let server_identity =
            crate::ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport =
            make_server_endpoint("127.0.0.1:0".parse().unwrap(), server_identity).unwrap();
        let server_pin = server_transport.identity.pin();
        let server_endpoint = server_transport.endpoint.clone();
        let server_address = server_endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            assert_eq!(send.id().index(), 0);
            let auth = UserAuthServer {
                authorized_keys: authorized,
                expected_username: Some("alice".into()),
            };
            let (_, reader, writer) = auth
                .authenticate(
                    &connection,
                    FramedReader::new(recv),
                    FramedWriter::new(send),
                )
                .await
                .unwrap();
            ServerSession::new(connection, reader, writer, SessionConfig::default())
                .run()
                .await
        });

        let client_transport =
            make_client_endpoint("127.0.0.1:0".parse().unwrap(), Some(server_pin)).unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity: identity.clone(),
        };
        let mut client = ClientSession::connect(
            &client_transport.endpoint,
            server_address,
            "fsh.local",
            auth,
            SessionConfig::default(),
        )
        .await
        .unwrap();
        assert!(client.keepalive().await.unwrap());
        // Keep stdin open to exercise the command-completion drain path:
        // non-interactive commands must not wait forever for terminal input.
        let (mut input, _input_writer) = tokio::io::duplex(1024);
        let (mut stdout_reader, mut stdout_writer) = tokio::io::duplex(1024);
        let (mut stderr_reader, mut stderr_writer) = tokio::io::duplex(1024);
        let status_result = client
            .exec(
                Command::Exec("sh -c 'printf hello; printf oops >&2'".into()),
                &mut input,
                &mut stdout_writer,
                &mut stderr_writer,
            )
            .await;
        drop(stdout_writer);
        drop(stderr_writer);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        stdout_reader.read_to_end(&mut stdout).await.unwrap();
        stderr_reader.read_to_end(&mut stderr).await.unwrap();
        client.connection().close(0u32.into(), b"test complete");
        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        let server_result = server_task.await.unwrap();
        assert!(
            server_result.is_ok(),
            "server session failed: {server_result:?}"
        );
        let status = status_result.unwrap();
        assert_eq!(status, ExitStatus::Code(0));
        assert_eq!(stdout, b"hello");
        assert_eq!(stderr, b"oops");
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_connection_disconnect_is_terminal_and_has_no_reply() {
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
            run_authenticated_connection_disconnect_case(payload).await;
        }
    }

    async fn run_authenticated_connection_disconnect_case(payload: Vec<u8>) {
        let stem = format!(
            "fsh-connection-disconnect-{}-{}",
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
        let authorized =
            AuthorizedKeys::from_lines(&identity.public_key().to_openssh().unwrap()).unwrap();
        let server_identity =
            crate::ServerIdentity::generate(&cert_path, &server_key_path).unwrap();
        let server_transport =
            make_server_endpoint("127.0.0.1:0".parse().unwrap(), server_identity).unwrap();
        let server_address = server_transport.endpoint.local_addr().unwrap();
        let server_endpoint = server_transport.endpoint.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let auth = UserAuthServer {
                authorized_keys: authorized,
                expected_username: Some("alice".into()),
            };
            let (_, mut reader, mut writer) = auth
                .authenticate(
                    &connection,
                    FramedReader::new(recv),
                    FramedWriter::new(send),
                )
                .await
                .unwrap();
            let request = timeout(Duration::from_secs(2), reader.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(request.number, MSG_GLOBAL_REQUEST);
            let mut decoder = Decoder::new(&request.payload);
            assert_eq!(decoder.string().unwrap(), "keepalive@fsh.dev");
            assert!(decoder.boolean().unwrap());
            decoder.finish().unwrap();
            writer.send(MSG_DISCONNECT, &payload).await.unwrap();

            match timeout(Duration::from_secs(2), reader.next()).await {
                Ok(Ok(Some(frame))) => panic!(
                    "client sent message {} after receiving DISCONNECT",
                    frame.number
                ),
                Ok(Ok(None)) | Ok(Err(_)) => {}
                Err(_) => panic!("client did not close after receiving DISCONNECT"),
            }
        });

        let client_transport = make_client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_transport.identity.pin()),
        )
        .unwrap();
        let auth = UserAuthClient {
            username: "alice".into(),
            identity,
        };
        let mut client = ClientSession::connect(
            &client_transport.endpoint,
            server_address,
            "fsh.local",
            auth,
            SessionConfig::default(),
        )
        .await
        .unwrap();
        let result = client.keepalive().await;
        assert!(
            matches!(result, Err(Error::RemoteDisconnect(_))),
            "{result:?}"
        );
        client_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_transport
            .endpoint
            .close(0u32.into(), b"test complete");
        server_task.await.unwrap();
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(server_key_path);
    }
}
