use crate::online::OnlineError;
use crate::online_framing::{read_frame, write_frame};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

pub trait Transport {
    fn send<T: Serialize>(&mut self, value: &T) -> Result<(), OnlineError>;
    fn recv<T: DeserializeOwned>(&mut self) -> Result<T, OnlineError>;
}

pub struct FramedIo<RW> {
    inner: RW,
}

impl<RW> FramedIo<RW> {
    pub fn new(inner: RW) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> RW {
        self.inner
    }
}

impl<RW: Read + Write> Transport for FramedIo<RW> {
    fn send<T: Serialize>(&mut self, value: &T) -> Result<(), OnlineError> {
        let bytes = bincode::serialize(value).map_err(|_| OnlineError::Encode)?;
        write_frame(&mut self.inner, &bytes).map_err(|_| OnlineError::Encode)
    }

    fn recv<T: DeserializeOwned>(&mut self) -> Result<T, OnlineError> {
        let bytes = read_frame(&mut self.inner).map_err(|_| OnlineError::Decode)?;
        bincode::deserialize(&bytes).map_err(|_| OnlineError::Decode)
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
