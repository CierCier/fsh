use std::{fmt, io};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest legal value of the FSH length field. The value includes the
/// message-number byte and excludes the four-byte length field itself.
pub const MAX_FRAME_SIZE: u32 = 35_000;

/// Maximum size of a single SSH-style string used by the implementation.
pub const MAX_STRING_SIZE: usize = 16 * 1024 * 1024;

/// Message-number registry represented as a typed constant namespace.
pub trait MessageNumber {
    const NUMBER: u8;
}

/// One length-delimited FSH message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub number: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(number: u8, payload: Vec<u8>) -> Result<Self, WireError> {
        let length = payload
            .len()
            .checked_add(1)
            .ok_or(WireError::LengthOverflow)?;
        if length == 0 || length > MAX_FRAME_SIZE as usize {
            return Err(WireError::FrameTooLarge(length));
        }
        Ok(Self { number, payload })
    }

    pub fn encode(&self, output: &mut Vec<u8>) -> Result<(), WireError> {
        let length = self
            .payload
            .len()
            .checked_add(1)
            .ok_or(WireError::LengthOverflow)?;
        if length == 0 || length > MAX_FRAME_SIZE as usize {
            return Err(WireError::FrameTooLarge(length));
        }
        output.extend_from_slice(&(length as u32).to_be_bytes());
        output.push(self.number);
        output.extend_from_slice(&self.payload);
        Ok(())
    }
}

/// Framing and field-level decoding failures.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("zero-length FSH frame")]
    ZeroLengthFrame,
    #[error("FSH frame length {0} exceeds the {MAX_FRAME_SIZE}-byte limit")]
    FrameTooLarge(usize),
    #[error("FSH frame length is not representable")]
    LengthOverflow,
    #[error("truncated FSH frame")]
    Truncated,
    #[error("invalid boolean value {0}")]
    InvalidBoolean(u8),
    #[error("invalid UTF-8 string")]
    InvalidUtf8,
    #[error("string length {0} exceeds the implementation limit")]
    StringTooLarge(usize),
    #[error("malformed field: {0}")]
    Malformed(&'static str),
    #[error("trailing bytes after message payload")]
    TrailingBytes,
}

/// Read FSH frames from a QUIC stream or any Tokio byte stream.
pub struct FramedReader<R> {
    inner: R,
    buffered: Vec<u8>,
}

impl<R> FramedReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffered: Vec::new(),
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    /// Read the next frame. A clean stream FIN before another frame is
    /// represented as `Ok(None)`; a partial prefix or payload is an error.
    pub async fn next(&mut self) -> Result<Option<Frame>, WireError> {
        let mut scratch = [0u8; 8192];
        loop {
            if self.buffered.len() >= 4 {
                let length = u32::from_be_bytes(
                    self.buffered[..4]
                        .try_into()
                        .expect("four-byte frame prefix"),
                ) as usize;
                if length == 0 {
                    return Err(WireError::ZeroLengthFrame);
                }
                if length > MAX_FRAME_SIZE as usize {
                    return Err(WireError::FrameTooLarge(length));
                }
                let total = 4 + length;
                if self.buffered.len() >= total {
                    let body = self.buffered[4..total].to_vec();
                    self.buffered.drain(..total);
                    return Ok(Some(Frame {
                        number: body[0],
                        payload: body[1..].to_vec(),
                    }));
                }
            }

            let read = self.inner.read(&mut scratch).await?;
            if read == 0 {
                return if self.buffered.is_empty() {
                    Ok(None)
                } else {
                    Err(WireError::Truncated)
                };
            }
            self.buffered.extend_from_slice(&scratch[..read]);
        }
    }

    /// Discard the remainder of a stream after a framing error. The buffered
    /// bytes are already known to be unusable, but the transport FIN still
    /// matters to channel drain accounting.
    pub async fn drain_to_end(&mut self) -> Result<(), WireError> {
        self.buffered.clear();
        let mut scratch = [0u8; 8192];
        loop {
            let read = self.inner.read(&mut scratch).await?;
            if read == 0 {
                return Ok(());
            }
        }
    }
}

/// Encode FSH frames to a QUIC stream or any Tokio byte stream.
pub struct FramedWriter<W> {
    inner: W,
}

impl<W> FramedWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub(crate) fn inner(&self) -> &W {
        &self.inner
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    pub async fn send(&mut self, number: u8, payload: &[u8]) -> Result<(), WireError> {
        let length = payload
            .len()
            .checked_add(1)
            .ok_or(WireError::LengthOverflow)?;
        if length == 0 || length > MAX_FRAME_SIZE as usize {
            return Err(WireError::FrameTooLarge(length));
        }
        let mut frame = Vec::with_capacity(length + 4);
        frame.extend_from_slice(&(length as u32).to_be_bytes());
        frame.push(number);
        frame.extend_from_slice(payload);
        self.inner.write_all(&frame).await?;
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<(), WireError> {
        self.inner.shutdown().await?;
        Ok(())
    }
}

/// SSH/RFC4251 primitive encoder.
#[derive(Default, Debug, Clone)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn bytes(&mut self, value: &[u8]) -> Result<(), WireError> {
        let len = u32::try_from(value.len()).map_err(|_| WireError::StringTooLarge(value.len()))?;
        if value.len() > MAX_STRING_SIZE {
            return Err(WireError::StringTooLarge(value.len()));
        }
        self.u32(len);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub fn string(&mut self, value: &str) -> Result<(), WireError> {
        self.bytes(value.as_bytes())
    }

    pub fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// SSH/RFC4251 primitive decoder with bounded strings and strict booleans.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        let value = *self.bytes.get(self.offset).ok_or(WireError::Truncated)?;
        self.offset += 1;
        Ok(value)
    }

    pub fn boolean(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(WireError::InvalidBoolean(value)),
        }
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let end = self.offset.checked_add(4).ok_or(WireError::Truncated)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireError::Truncated)?;
        self.offset = end;
        Ok(u32::from_be_bytes(bytes.try_into().expect("four bytes")))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let length = self.u32()? as usize;
        if length > MAX_STRING_SIZE {
            return Err(WireError::StringTooLarge(length));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WireError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    pub fn string(&mut self) -> Result<&'a str, WireError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| WireError::InvalidUtf8)
    }

    pub fn raw(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WireError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    pub fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    pub fn finish(self) -> Result<(), WireError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

impl fmt::Debug for FramedReader<quinn::RecvStream> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramedReader").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn frame_round_trip_and_fragmentation() {
        let mut encoder = Encoder::new();
        encoder.u32(7);
        encoder.string("hello").unwrap();
        let payload = encoder.finish();
        let frame = Frame::new(90, payload.clone()).unwrap();
        let mut encoded = Vec::new();
        frame.encode(&mut encoded).unwrap();
        assert_eq!(encoded.len(), payload.len() + 5);
    }

    #[tokio::test]
    async fn reader_handles_multiple_frames_and_clean_fin() {
        let (tx, rx) = duplex(2);
        let task = tokio::spawn(async move {
            let mut writer = FramedWriter::new(tx);
            writer.send(1, b"a").await.unwrap();
            writer.send(2, b"bc").await.unwrap();
            writer.finish().await.unwrap();
        });
        let mut reader = FramedReader::new(rx);
        assert_eq!(
            reader.next().await.unwrap(),
            Some(Frame::new(1, b"a".to_vec()).unwrap())
        );
        assert_eq!(
            reader.next().await.unwrap(),
            Some(Frame::new(2, b"bc".to_vec()).unwrap())
        );
        assert_eq!(reader.next().await.unwrap(), None);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn reader_retains_a_partial_frame_across_cancellation() {
        let (mut tx, rx) = duplex(64);
        let mut reader = FramedReader::new(rx);
        tx.write_all(&[0, 0, 0, 2]).await.unwrap();

        tokio::select! {
            biased;
            result = reader.next() => panic!("partial frame unexpectedly completed: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        tx.write_all(&[7, b'x']).await.unwrap();
        assert_eq!(
            reader.next().await.unwrap(),
            Some(Frame::new(7, vec![b'x']).unwrap())
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_boolean_and_trailing_bytes() {
        let mut decoder = Decoder::new(&[2]);
        assert!(matches!(
            decoder.boolean(),
            Err(WireError::InvalidBoolean(2))
        ));
        let decoder = Decoder::new(&[1]);
        assert!(matches!(decoder.finish(), Err(WireError::TrailingBytes)));
    }
}
