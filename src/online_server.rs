use crate::messages::Query as RmsQuery;
use crate::online::{Mode, OnlineError, Query, Reply, RunConfig};
use crate::server::{Db, Server};
use std::sync::Arc;

/// Handler for keyword PIR queries on the server side.
pub trait KeywordPirHandler: Send + Sync {
    /// Answer a keyword PIR query, returning the payload bytes.
    fn answer(&self, keyword: &[u8]) -> Result<Vec<u8>, OnlineError>;
}

/// Server-side query dispatcher for both RMS24 and keyword PIR modes.
pub struct ServerCore<D: Db> {
    server: Server<D>,
    keyword_handler: Option<Arc<dyn KeywordPirHandler>>,
}

impl<D: Db> ServerCore<D> {
    /// Create a server core wrapping an RMS24 server.
    pub fn new(server: Server<D>) -> Self {
        Self { server, keyword_handler: None }
    }

    /// Attach a keyword PIR handler.
    pub fn with_keyword_handler(mut self, handler: Arc<dyn KeywordPirHandler>) -> Self {
        self.keyword_handler = Some(handler);
        self
    }

    /// Dispatch a query to the appropriate handler based on the run config mode.
    pub fn handle_query(&self, cfg: &RunConfig, query: Query) -> Result<Reply, OnlineError> {
        match (cfg.mode, query) {
            (Mode::Rms24, Query::Rms24 { id, subset }) => {
                let rms_query = RmsQuery { id, subset };
                let reply = self.server.answer(&rms_query).map_err(|e| {
                    log::warn!("rms24 query id={} failed: {}", id, e);
                    OnlineError::Server(e.to_string())
                })?;
                Ok(Reply::Rms24 { id: reply.id, parity: reply.parity })
            }
            (Mode::KeywordPir, Query::KeywordPir { id, keyword }) => {
                let handler = self.keyword_handler.as_ref().ok_or_else(|| {
                    log::warn!("keywordpir query id={} rejected: no handler configured", id);
                    OnlineError::Unsupported
                })?;
                let payload = handler.answer(&keyword)?;
                Ok(Reply::KeywordPir { id, payload })
            }
            _ => {
                log::warn!("protocol mismatch: mode={:?}", cfg.mode);
                Err(OnlineError::Protocol)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::online::{Mode, Query, Reply, RunConfig};
    use crate::server::{InMemoryDb, Server};
    use std::sync::Arc;

    struct FakeKeywordPir;

    impl KeywordPirHandler for FakeKeywordPir {
        fn answer(&self, keyword: &[u8]) -> Result<Vec<u8>, OnlineError> {
            Ok(keyword.to_vec())
        }
    }

    #[test]
    fn test_handle_rms24_query() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4, 5, 6, 7, 8], 4).unwrap();
        let server = Server::new(db, 2).unwrap();
        let core = ServerCore::new(server);
        let cfg = RunConfig { mode: Mode::Rms24, lambda: 2, entry_size: 4 };
        let query = Query::Rms24 { id: 1, subset: vec![(0, 0), (0, 1)] };
        let reply = core.handle_query(&cfg, query).unwrap();
        assert_eq!(reply, Reply::Rms24 { id: 1, parity: vec![1 ^ 5, 2 ^ 6, 3 ^ 7, 4 ^ 8] });
    }

    #[test]
    fn test_handle_keywordpir_query() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 2).unwrap();
        let server = Server::new(db, 2).unwrap();
        let core = ServerCore::new(server).with_keyword_handler(Arc::new(FakeKeywordPir));
        let cfg = RunConfig { mode: Mode::KeywordPir, lambda: 2, entry_size: 2 };
        let query = Query::KeywordPir { id: 9, keyword: b"alice".to_vec() };
        let reply = core.handle_query(&cfg, query).unwrap();
        assert_eq!(reply, Reply::KeywordPir { id: 9, payload: b"alice".to_vec() });
    }

    #[test]
    fn test_handle_mismatched_mode() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 2).unwrap();
        let server = Server::new(db, 2).unwrap();
        let core = ServerCore::new(server);
        let cfg = RunConfig { mode: Mode::Rms24, lambda: 2, entry_size: 2 };
        let query = Query::KeywordPir { id: 9, keyword: b"alice".to_vec() };
        let err = core.handle_query(&cfg, query).unwrap_err();
        assert!(matches!(err, OnlineError::Protocol));
    }
}
