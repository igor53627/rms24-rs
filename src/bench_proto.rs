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
    pub threads: usize,
    pub seed: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Query {
    pub id: u64,
    pub subset: Vec<(u32, u32)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reply {
    pub id: u64,
    pub parity: Vec<u8>,
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
        };
        let bytes = bincode::serialize(&cfg).unwrap();
        let decoded: RunConfig = bincode::deserialize(&bytes).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn test_query_subset_roundtrip() {
        let query = Query {
            id: 7,
            subset: vec![(1, 2), (3, 4)],
        };
        let bytes = bincode::serialize(&query).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(query, decoded);
    }
}
