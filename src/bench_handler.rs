use crate::bench_proto::{BatchReply, BatchRequest, ClientFrame, Query, Reply, ServerFrame};
use crate::messages::Query as RmsQuery;
use crate::server::{Db, Server};

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

fn handle_single<D: Db>(server: &Server<D>, query: Query) -> ServerFrame {
    let rms_query = RmsQuery { id: query.id, subset: query.subset };
    match server.answer(&rms_query) {
        Ok(reply) => ServerFrame::Reply(Reply::Ok { id: reply.id, parity: reply.parity }),
        Err(err) => ServerFrame::Reply(Reply::Error {
            id: rms_query.id,
            message: err.to_string(),
        }),
    }
}

fn handle_batch<D: Db>(server: &Server<D>, batch: BatchRequest, max_batch: usize) -> ServerFrame {
    if batch.queries.len() > max_batch {
        return ServerFrame::Error {
            message: format!("batch too large: {}", batch.queries.len()),
        };
    }
    let mut replies = Vec::with_capacity(batch.queries.len());
    for query in batch.queries {
        let rms_query = RmsQuery { id: query.id, subset: query.subset };
        let reply = match server.answer(&rms_query) {
            Ok(reply) => Reply::Ok { id: reply.id, parity: reply.parity },
            Err(err) => Reply::Error {
                id: rms_query.id,
                message: err.to_string(),
            },
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

        let ok = Query { id: 1, subset: vec![(0, 0)] };
        let bad = Query { id: 2, subset: vec![(9, 0)] };
        let frame = ClientFrame::BatchRequest(BatchRequest { queries: vec![ok.clone(), bad.clone()] });
        let out = handle_client_frame(&server, frame, 8);

        match out {
            ServerFrame::BatchReply(batch) => {
                assert_eq!(batch.replies.len(), 2);
                match &batch.replies[0] {
                    Reply::Ok { id, parity } => {
                        assert_eq!(*id, ok.id);
                        assert_eq!(parity, &vec![1]);
                    }
                    _ => panic!("expected ok reply"),
                }
                match &batch.replies[1] {
                    Reply::Error { id, message } => {
                        assert_eq!(*id, bad.id);
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
                Query { id: 1, subset: vec![(0, 0)] },
                Query { id: 2, subset: vec![(0, 1)] },
            ],
        });
        let out = handle_client_frame(&server, frame, 1);
        match out {
            ServerFrame::Error { message } => assert!(message.contains("batch too large")),
            _ => panic!("expected error frame"),
        }
    }
}
