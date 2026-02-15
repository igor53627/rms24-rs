use crate::online::OnlineError;
use crate::online_framing::{read_frame, write_frame};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

/// Trait for sending and receiving bincode-serialized messages over a framed stream.
pub trait Transport {
    /// Serialize and send a value.
    fn send<T: Serialize>(&mut self, value: &T) -> Result<(), OnlineError>;
    /// Receive and deserialize a value.
    fn recv<T: DeserializeOwned>(&mut self) -> Result<T, OnlineError>;
}

/// [`Transport`] implementation backed by a length-framed `Read + Write` stream.
pub struct FramedIo<RW> {
    inner: RW,
}

impl<RW> FramedIo<RW> {
    /// Wrap a stream.
    pub fn new(inner: RW) -> Self {
        Self { inner }
    }

    /// Unwrap the inner stream.
    pub fn into_inner(self) -> RW {
        self.inner
    }
}

impl<RW: Read + Write> Transport for FramedIo<RW> {
    fn send<T: Serialize>(&mut self, value: &T) -> Result<(), OnlineError> {
        let bytes = bincode::serialize(value).map_err(|e| {
            log::debug!("transport serialize error: {}", e);
            OnlineError::Encode
        })?;
        write_frame(&mut self.inner, &bytes).map_err(|e| {
            log::debug!("transport write error: {}", e);
            OnlineError::Encode
        })
    }

    fn recv<T: DeserializeOwned>(&mut self) -> Result<T, OnlineError> {
        let bytes = read_frame(&mut self.inner).map_err(|e| {
            log::debug!("transport read error: {}", e);
            OnlineError::Decode
        })?;
        bincode::deserialize(&bytes).map_err(|e| {
            log::debug!("transport deserialize error: {}", e);
            OnlineError::Decode
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::online::{Mode, RunConfig};
    use std::io::Cursor;

    #[test]
    fn test_framed_send_recv_roundtrip() {
        let cfg = RunConfig { mode: Mode::Rms24, lambda: 80, entry_size: 40 };
        let mut io = FramedIo::new(Cursor::new(Vec::new()));
        io.send(&cfg).unwrap();
        let inner = io.into_inner().into_inner();
        let mut io = FramedIo::new(Cursor::new(inner));
        let decoded: RunConfig = io.recv().unwrap();
        assert_eq!(cfg, decoded);
    }
}
