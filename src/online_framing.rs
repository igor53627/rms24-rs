use std::io::{self, Read, Write};

pub fn write_frame<W: Write>(mut writer: W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)
}

pub fn read_frame<R: Read>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_frame_roundtrip() {
        let mut buf = Cursor::new(Vec::new());
        write_frame(&mut buf, b"hello").unwrap();
        buf.set_position(0);
        let out = read_frame(&mut buf).unwrap();
        assert_eq!(out, b"hello");
    }
}
