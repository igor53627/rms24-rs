use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Rms24,
    KeywordPir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunConfig {
    pub mode: Mode,
    pub lambda: u32,
    pub entry_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Query {
    Rms24 { id: u64, subset: Vec<(u32, u32)> },
    KeywordPir { id: u64, keyword: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Rms24 { id: u64, parity: Vec<u8> },
    KeywordPir { id: u64, payload: Vec<u8> },
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Decode,
    Encode,
    Protocol,
    Unsupported,
    Server,
}

#[derive(Debug, thiserror::Error)]
pub enum OnlineError {
    #[error("decode error")]
    Decode,
    #[error("encode error")]
    Encode,
    #[error("protocol mismatch")]
    Protocol,
    #[error("unsupported mode")]
    Unsupported,
    #[error("server error: {0}")]
    Server(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_config_roundtrip() {
        let cfg = RunConfig {
            mode: Mode::Rms24,
            lambda: 80,
            entry_size: 40,
        };
        let bytes = bincode::serialize(&cfg).unwrap();
        let decoded: RunConfig = bincode::deserialize(&bytes).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn test_query_roundtrip_rms24() {
        let q = Query::Rms24 {
            id: 7,
            subset: vec![(1, 2), (3, 4)],
        };
        let bytes = bincode::serialize(&q).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(q, decoded);
    }

    #[test]
    fn test_query_roundtrip_keywordpir() {
        let q = Query::KeywordPir {
            id: 9,
            keyword: b"alice".to_vec(),
        };
        let bytes = bincode::serialize(&q).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(q, decoded);
    }

    #[test]
    fn test_reply_roundtrip_error() {
        let r = Reply::Error {
            code: ErrorCode::Protocol,
            message: "bad mode".into(),
        };
        let bytes = bincode::serialize(&r).unwrap();
        let decoded: Reply = bincode::deserialize(&bytes).unwrap();
        assert_eq!(r, decoded);
    }
}
