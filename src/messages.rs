use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u64,
    pub subset: Vec<(u32, u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub id: u64,
    pub parity: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub index: u64,
    pub old_entry: Vec<u8>,
    pub new_entry: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_reply_round_trip_fields() {
        let q = Query { id: 7, subset: vec![(1, 2), (3, 4)] };
        let r = Reply { id: 7, parity: vec![1, 2, 3] };
        assert_eq!(q.id, 7);
        assert_eq!(r.id, 7);
        assert_eq!(q.subset.len(), 2);
    }
}
