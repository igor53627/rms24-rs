use thiserror::Error;

/// RMS24 query containing a subset of (block, offset) pairs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u64,
    pub subset: Vec<(u32, u32)>,
}

/// Server reply containing the XOR parity of the queried subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub id: u64,
    pub parity: Vec<u8>,
}

/// Database update with old and new entry values for a given index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub index: u64,
    pub old_entry: Vec<u8>,
    pub new_entry: Vec<u8>,
}

/// Errors returned by the server when processing queries or updates.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("subset out of range")]
    SubsetOutOfRange,
    #[error("entry size mismatch")]
    EntrySizeMismatch,
    #[error("db error: {0}")]
    DbError(String),
}

/// Errors encountered on the client side during queries or hint management.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid index")]
    InvalidIndex,
    #[error("no available hint contains target")]
    NoValidHint,
    #[error("reply parity length mismatch")]
    ParityLengthMismatch,
    #[error("verification failed")]
    VerificationFailed,
    #[error("serialization error: {0}")]
    SerializationError(String),
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

    #[test]
    fn test_server_error_variants_exist() {
        let err = ServerError::SubsetOutOfRange;
        assert!(matches!(err, ServerError::SubsetOutOfRange));
    }

    #[test]
    fn test_client_error_variants_exist() {
        let err = ClientError::InvalidIndex;
        assert!(matches!(err, ClientError::InvalidIndex));
    }
}
