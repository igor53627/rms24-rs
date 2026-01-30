use crate::online::{Mode, OnlineError, Query, Reply};

pub struct ClientCore {
    mode: Mode,
}

impl ClientCore {
    pub fn new(mode: Mode) -> Self {
        Self { mode }
    }

    pub fn build_rms24_query(&self, id: u64, subset: Vec<(u32, u32)>) -> Result<Query, OnlineError> {
        if self.mode != Mode::Rms24 {
            return Err(OnlineError::Protocol);
        }
        Ok(Query::Rms24 { id, subset })
    }

    pub fn build_keywordpir_query(&self, id: u64, keyword: Vec<u8>) -> Result<Query, OnlineError> {
        if self.mode != Mode::KeywordPir {
            return Err(OnlineError::Protocol);
        }
        Ok(Query::KeywordPir { id, keyword })
    }

    pub fn expect_rms24_reply(&self, reply: Reply) -> Result<Vec<u8>, OnlineError> {
        match reply {
            Reply::Rms24 { parity, .. } => Ok(parity),
            Reply::Error { .. } => Err(OnlineError::Server("server error".into())),
            _ => Err(OnlineError::Protocol),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::online::{Mode, Query, Reply};

    #[test]
    fn test_build_rms24_query() {
        let client = ClientCore::new(Mode::Rms24);
        let q = client.build_rms24_query(7, vec![(0, 1)]).unwrap();
        assert_eq!(q, Query::Rms24 { id: 7, subset: vec![(0, 1)] });
    }

    #[test]
    fn test_build_keywordpir_query() {
        let client = ClientCore::new(Mode::KeywordPir);
        let q = client.build_keywordpir_query(9, b"alice".to_vec()).unwrap();
        assert_eq!(q, Query::KeywordPir { id: 9, keyword: b"alice".to_vec() });
    }

    #[test]
    fn test_parse_rms24_reply() {
        let client = ClientCore::new(Mode::Rms24);
        let reply = Reply::Rms24 { id: 1, parity: vec![1, 2] };
        let parity = client.expect_rms24_reply(reply).unwrap();
        assert_eq!(parity, vec![1, 2]);
    }
}
