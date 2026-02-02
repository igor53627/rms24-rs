use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Mode {
    Rms24,
    KeywordPir,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunConfig {
    pub dataset_id: String,
    pub mode: Mode,
    pub query_count: u64,
    pub threads: u32,
    pub seed: u64,
    pub batch_size: u32,
    pub max_batch_queries: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Query {
    pub id: u64,
    pub subset: Vec<(u32, u32)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Reply {
    Ok { id: u64, parity: Vec<u8> },
    Error { id: u64, message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchRequest {
    pub queries: Vec<Query>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchReply {
    pub replies: Vec<Reply>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientFrame {
    Query(Query),
    BatchRequest(BatchRequest),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServerFrame {
    Reply(Reply),
    BatchReply(BatchReply),
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bincode_roundtrip() {
        let cfg = RunConfig {
            dataset_id: "slice-1m".to_string(),
            mode: Mode::Rms24,
            query_count: 1000,
            threads: 1,
            seed: 42,
            batch_size: 1,
            max_batch_queries: 1,
        };
        let bytes = bincode::serialize(&cfg).unwrap();
        let decoded: RunConfig = bincode::deserialize(&bytes).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn test_query_subset_roundtrip() {
        let query = Query { id: 7, subset: vec![(1, 2), (3, 4)] };
        let bytes = bincode::serialize(&query).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(query, decoded);
    }

    #[test]
    fn test_batch_request_roundtrip() {
        let batch = BatchRequest {
            queries: vec![Query { id: 1, subset: vec![(0, 0)] }],
        };
        let frame = ClientFrame::BatchRequest(batch);
        let bytes = bincode::serialize(&frame).unwrap();
        let decoded: ClientFrame = bincode::deserialize(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_batch_reply_roundtrip() {
        let batch = BatchReply {
            replies: vec![Reply::Ok { id: 2, parity: vec![9, 9] }],
        };
        let frame = ServerFrame::BatchReply(batch);
        let bytes = bincode::serialize(&frame).unwrap();
        let decoded: ServerFrame = bincode::deserialize(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }
}
