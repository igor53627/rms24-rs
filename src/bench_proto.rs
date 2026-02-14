//! Benchmark protocol types shared by rms24_client and rms24_server.
//!
//! These types are bincode-serialized and framed by bench_framing.
//! They model per-query and batch requests/replies for the benchmark harness.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Benchmark mode for the harness (RMS24 or KeywordPIR).
/// Used to select client/server logic for serialized frames.
pub enum Mode {
    Rms24,
    KeywordPir,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Benchmark run parameters communicated between client and server.
/// All fields must be consistent with the dataset and CLI options.
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
/// A benchmark query for RMS24 or KeywordPIR.
pub enum Query {
    /// RMS24 subset query.
    Rms24 { id: u64, subset: Vec<(u32, u32)> },
    /// KeywordPIR query with multiple RMS24 subsets.
    KeywordPir {
        id: u64,
        subsets: Vec<Vec<(u32, u32)>>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Benchmark reply payload (success or error) for a query id.
pub enum Reply {
    /// RMS24 reply parity bytes.
    Rms24 { id: u64, parity: Vec<u8> },
    /// KeywordPIR reply parity bytes per subset.
    KeywordPir { id: u64, parities: Vec<Vec<u8>> },
    /// Error reply with message.
    Error { id: u64, message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Batch of queries sent in a single client frame.
pub struct BatchRequest {
    pub queries: Vec<Query>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Batch of replies returned in a single server frame.
pub struct BatchReply {
    pub replies: Vec<Reply>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Client-to-server frame: single query or batch request.
pub enum ClientFrame {
    Query(Query),
    BatchRequest(BatchRequest),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Server-to-client frame: single reply, batch reply, or protocol error.
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
    fn test_query_rms24_roundtrip() {
        let query = Query::Rms24 {
            id: 7,
            subset: vec![(1, 2), (3, 4)],
        };
        let bytes = bincode::serialize(&query).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(query, decoded);
    }

    #[test]
    fn test_query_keywordpir_roundtrip() {
        let query = Query::KeywordPir {
            id: 9,
            subsets: vec![vec![(0, 1), (2, 3)]],
        };
        let bytes = bincode::serialize(&query).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(query, decoded);
    }

    #[test]
    fn test_batch_request_roundtrip() {
        let batch = BatchRequest {
            queries: vec![Query::Rms24 {
                id: 1,
                subset: vec![(0, 0)],
            }],
        };
        let frame = ClientFrame::BatchRequest(batch);
        let bytes = bincode::serialize(&frame).unwrap();
        let decoded: ClientFrame = bincode::deserialize(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_batch_reply_roundtrip() {
        let batch = BatchReply {
            replies: vec![Reply::Rms24 {
                id: 2,
                parity: vec![9, 9],
            }],
        };
        let frame = ServerFrame::BatchReply(batch);
        let bytes = bincode::serialize(&frame).unwrap();
        let decoded: ServerFrame = bincode::deserialize(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }
}
