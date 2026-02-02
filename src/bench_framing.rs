use std::io::{self, Read, Write};

pub fn write_frame<W: Write>(mut w: W, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)
}

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

pub fn read_frame<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME_SIZE || len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame size {} exceeds maximum {}", len, MAX_FRAME_SIZE),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let payload = vec![1u8, 2, 3, 4];
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let out = read_frame(&mut cursor).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn test_frame_rejects_oversized_len() {
        let mut buf = Vec::new();
        let len = u32::MAX;
        buf.extend_from_slice(&len.to_le_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
