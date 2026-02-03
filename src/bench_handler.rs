//! Benchmark request handler that adapts bench frames to RMS24 server queries.
//!
//! Converts benchmark queries into RMS24 messages and enforces batch size limits.

use crate::bench_proto::{BatchReply, BatchRequest, ClientFrame, Query, Reply, ServerFrame};
use crate::messages::Query as RmsQuery;
use crate::server::{Db, Server};

/// Route a client frame to single or batch handling with a batch-size limit.
pub fn handle_client_frame<D: Db>(
    server: &Server<D>,
    frame: ClientFrame,
    max_batch: usize,
) -> ServerFrame {
    match frame {
        ClientFrame::Query(query) => handle_single(server, query),
        ClientFrame::BatchRequest(batch) => handle_batch(server, batch, max_batch),
    }
}

/// Handle a single benchmark query by delegating to the RMS24 server.
fn handle_single<D: Db>(server: &Server<D>, query: Query) -> ServerFrame {
    match query {
        Query::Rms24 { id, subset } => {
            let rms_query = RmsQuery { id, subset };
            match server.answer(&rms_query) {
                Ok(reply) => ServerFrame::Reply(Reply::Rms24 {
                    id: reply.id,
                    parity: reply.parity,
                }),
                Err(err) => ServerFrame::Reply(Reply::Error {
                    id: rms_query.id,
                    message: err.to_string(),
                }),
            }
        }
        Query::KeywordPir { id, subsets } => {
            if subsets.is_empty() || subsets.iter().any(|subset| subset.is_empty()) {
                return ServerFrame::Reply(Reply::Error {
                    id,
                    message: "keywordpir subsets must be non-empty".to_string(),
                });
            }
            let mut parities = Vec::with_capacity(subsets.len());
            for subset in subsets {
                let rms_query = RmsQuery { id, subset };
                let reply = match server.answer(&rms_query) {
                    Ok(reply) => reply,
                    Err(err) => {
                        return ServerFrame::Reply(Reply::Error {
                            id: rms_query.id,
                            message: err.to_string(),
                        })
                    }
                };
                parities.push(reply.parity);
            }
            ServerFrame::Reply(Reply::KeywordPir { id, parities })
        }
    }
}

/// Handle a batch of queries, rejecting batches larger than max_batch.
fn handle_batch<D: Db>(server: &Server<D>, batch: BatchRequest, max_batch: usize) -> ServerFrame {
    if batch.queries.len() > max_batch {
        return ServerFrame::Error {
            message: format!("batch too large: {}", batch.queries.len()),
        };
    }
    let mut replies = Vec::with_capacity(batch.queries.len());
    for query in batch.queries {
        let reply = match query {
            Query::Rms24 { id, subset } => {
                let rms_query = RmsQuery { id, subset };
                match server.answer(&rms_query) {
                    Ok(reply) => Reply::Rms24 {
                        id: reply.id,
                        parity: reply.parity,
                    },
                    Err(err) => Reply::Error {
                        id: rms_query.id,
                        message: err.to_string(),
                    },
                }
            }
            Query::KeywordPir { id, subsets } => {
                if subsets.is_empty() || subsets.iter().any(|subset| subset.is_empty()) {
                    Reply::Error {
                        id,
                        message: "keywordpir subsets must be non-empty".to_string(),
                    }
                } else {
                    let mut parities = Vec::with_capacity(subsets.len());
                    let mut err_out = None;
                    for subset in subsets {
                        let rms_query = RmsQuery { id, subset };
                        match server.answer(&rms_query) {
                            Ok(reply) => parities.push(reply.parity),
                            Err(err) => {
                                err_out = Some(err);
                                break;
                            }
                        }
                    }
                    match err_out {
                        Some(err) => Reply::Error {
                            id,
                            message: err.to_string(),
                        },
                        None => Reply::KeywordPir { id, parities },
                    }
                }
            }
        };
        replies.push(reply);
    }
    ServerFrame::BatchReply(BatchReply { replies })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::InMemoryDb;

    #[test]
    fn test_batch_reply_order_and_error() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 1).unwrap();
        let server = Server::new(db, 2).unwrap();

        let ok_id = 1;
        let bad_id = 2;
        let ok = Query::Rms24 { id: ok_id, subset: vec![(0, 0)] };
        let bad = Query::Rms24 { id: bad_id, subset: vec![(9, 0)] };
        let frame = ClientFrame::BatchRequest(BatchRequest { queries: vec![ok.clone(), bad.clone()] });
        let out = handle_client_frame(&server, frame, 8);

        match out {
            ServerFrame::BatchReply(batch) => {
                assert_eq!(batch.replies.len(), 2);
                match &batch.replies[0] {
                    Reply::Rms24 { id, parity } => {
                        assert_eq!(*id, ok_id);
                        assert_eq!(parity, &vec![1]);
                    }
                    _ => panic!("expected ok reply"),
                }
                match &batch.replies[1] {
                    Reply::Error { id, message } => {
                        assert_eq!(*id, bad_id);
                        assert!(message.contains("subset"));
                    }
                    _ => panic!("expected error reply"),
                }
            }
            _ => panic!("expected batch reply"),
        }
    }

    #[test]
    fn test_batch_size_enforced() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 1).unwrap();
        let server = Server::new(db, 2).unwrap();
        let frame = ClientFrame::BatchRequest(BatchRequest {
            queries: vec![
                Query::Rms24 { id: 1, subset: vec![(0, 0)] },
                Query::Rms24 { id: 2, subset: vec![(0, 1)] },
            ],
        });
        let out = handle_client_frame(&server, frame, 1);
        match out {
            ServerFrame::Error { message } => assert!(message.contains("batch too large")),
            _ => panic!("expected error frame"),
        }
    }

    #[test]
    fn test_handle_keywordpir_query() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 2).unwrap();
        let server = Server::new(db, 2).unwrap();
        let query = Query::KeywordPir {
            id: 9,
            subsets: vec![vec![(0, 0)], vec![(0, 1)]],
        };
        let out = handle_client_frame(&server, ClientFrame::Query(query), 8);
        match out {
            ServerFrame::Reply(Reply::KeywordPir { id, parities }) => {
                assert_eq!(id, 9);
                assert_eq!(parities, vec![vec![1, 2], vec![3, 4]]);
            }
            _ => panic!("expected keywordpir reply"),
        }
    }

    #[test]
    fn test_handle_keywordpir_empty_subsets_error() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 2).unwrap();
        let server = Server::new(db, 2).unwrap();
        let query = Query::KeywordPir { id: 9, subsets: Vec::new() };
        let out = handle_client_frame(&server, ClientFrame::Query(query), 8);
        match out {
            ServerFrame::Reply(Reply::Error { message, .. }) => {
                assert!(message.contains("keywordpir subsets"));
            }
            _ => panic!("expected error reply"),
        }
    }

    #[test]
    fn test_batch_keywordpir_queries() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 2).unwrap();
        let server = Server::new(db, 2).unwrap();
        let ok = Query::KeywordPir {
            id: 1,
            subsets: vec![vec![(0, 0)], vec![(0, 1)]],
        };
        let bad = Query::KeywordPir {
            id: 2,
            subsets: vec![Vec::new()],
        };
        let frame = ClientFrame::BatchRequest(BatchRequest {
            queries: vec![ok, bad],
        });
        let out = handle_client_frame(&server, frame, 8);

        match out {
            ServerFrame::BatchReply(batch) => {
                assert_eq!(batch.replies.len(), 2);
                match &batch.replies[0] {
                    Reply::KeywordPir { id, parities } => {
                        assert_eq!(*id, 1);
                        assert_eq!(parities, &vec![vec![1, 2], vec![3, 4]]);
                    }
                    _ => panic!("expected keywordpir reply"),
                }
                match &batch.replies[1] {
                    Reply::Error { id, message } => {
                        assert_eq!(*id, 2);
                        assert!(message.contains("keywordpir subsets"));
                    }
                    _ => panic!("expected error reply"),
                }
            }
            _ => panic!("expected batch reply"),
        }
    }
}
