use crate::hints::xor_bytes_inplace;
use crate::messages::{Query, Reply, ServerError, Update};

pub trait Db {
    fn num_entries(&self) -> u64;
    fn entry_size(&self) -> usize;
    fn entry(&self, index: u64) -> Result<Vec<u8>, ServerError>;
    fn update(&mut self, index: u64, entry: &[u8]) -> Result<(), ServerError>;
}

#[derive(Debug)]
pub struct InMemoryDb {
    entry_size: usize,
    entries: Vec<u8>,
}

impl InMemoryDb {
    pub fn new(entries: Vec<u8>, entry_size: usize) -> Result<Self, ServerError> {
        if entry_size == 0 || entries.len() % entry_size != 0 {
            return Err(ServerError::EntrySizeMismatch);
        }
        Ok(Self { entry_size, entries })
    }
}

impl Db for InMemoryDb {
    fn num_entries(&self) -> u64 {
        (self.entries.len() / self.entry_size) as u64
    }

    fn entry_size(&self) -> usize {
        self.entry_size
    }

    fn entry(&self, index: u64) -> Result<Vec<u8>, ServerError> {
        if index >= self.num_entries() {
            return Err(ServerError::SubsetOutOfRange);
        }
        let start = index as usize * self.entry_size;
        Ok(self.entries[start..start + self.entry_size].to_vec())
    }

    fn update(&mut self, index: u64, entry: &[u8]) -> Result<(), ServerError> {
        if entry.len() != self.entry_size {
            return Err(ServerError::EntrySizeMismatch);
        }
        if index >= self.num_entries() {
            return Err(ServerError::SubsetOutOfRange);
        }
        let start = index as usize * self.entry_size;
        self.entries[start..start + self.entry_size].copy_from_slice(entry);
        Ok(())
    }
}

pub struct Server<D: Db> {
    db: D,
    block_size: u64,
    max_subset_len: usize,
}

impl<D: Db> Server<D> {
    pub fn new(db: D, block_size: u64) -> Result<Self, ServerError> {
        if block_size == 0 {
            return Err(ServerError::SubsetOutOfRange);
        }
        let num_entries = db.num_entries();
        let num_blocks = num_entries.saturating_add(block_size - 1) / block_size;
        let max_subset_len = num_blocks.saturating_add(1);
        let max_subset_len = usize::try_from(max_subset_len).unwrap_or(usize::MAX);
        Ok(Self { db, block_size, max_subset_len })
    }

    pub fn answer(&self, query: &Query) -> Result<Reply, ServerError> {
        if query.subset.len() > self.max_subset_len {
            return Err(ServerError::SubsetOutOfRange);
        }
        let mut parity = vec![0u8; self.db.entry_size()];
        for (block, offset) in &query.subset {
            let offset_u64 = *offset as u64;
            if offset_u64 >= self.block_size {
                return Err(ServerError::SubsetOutOfRange);
            }
            let index = (u64::from(*block))
                .checked_mul(self.block_size)
                .and_then(|base| base.checked_add(offset_u64))
                .ok_or(ServerError::SubsetOutOfRange)?;
            let entry = self.db.entry(index)?;
            if entry.len() != parity.len() {
                return Err(ServerError::EntrySizeMismatch);
            }
            xor_bytes_inplace(&mut parity, &entry);
        }
        Ok(Reply { id: query.id, parity })
    }

    pub fn apply_update(&mut self, update: &Update) -> Result<(), ServerError> {
        self.db.update(update.index, &update.new_entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Query;

    #[test]
    fn test_server_parity_simple() {
        let entry_size = 4;
        let block_size = 2;
        let db = InMemoryDb::new(vec![1, 2, 3, 4, 5, 6, 7, 8], entry_size).unwrap();
        let server = Server::new(db, block_size).unwrap();
        let query = Query { id: 1, subset: vec![(0, 0), (0, 1)] };
        let reply = server.answer(&query).unwrap();
        // parity of entry0 ^ entry1
        assert_eq!(reply.parity, vec![1 ^ 5, 2 ^ 6, 3 ^ 7, 4 ^ 8]);
    }

    #[test]
    fn test_in_memory_db_entry_size_mismatch() {
        match InMemoryDb::new(vec![1, 2, 3], 4) {
            Err(err) => assert!(matches!(err, ServerError::EntrySizeMismatch)),
            Ok(_) => panic!("expected entry size mismatch"),
        }
    }

    #[test]
    fn test_server_answer_out_of_range() {
        let entry_size = 4;
        let block_size = 1;
        let db = InMemoryDb::new(vec![1, 2, 3, 4], entry_size).unwrap();
        let server = Server::new(db, block_size).unwrap();
        let query = Query { id: 1, subset: vec![(1, 0)] };
        let err = server.answer(&query).unwrap_err();
        assert!(matches!(err, ServerError::SubsetOutOfRange));
    }

    #[test]
    fn test_server_new_block_size_zero() {
        let entry_size = 1;
        let db = InMemoryDb::new(vec![1], entry_size).unwrap();
        match Server::new(db, 0) {
            Err(err) => assert!(matches!(err, ServerError::SubsetOutOfRange)),
            Ok(_) => panic!("expected block_size validation error"),
        }
    }

    #[test]
    fn test_server_answer_subset_too_large() {
        let entry_size = 1;
        let block_size = 2;
        let db = InMemoryDb::new(vec![1, 2, 3, 4], entry_size).unwrap();
        let server = Server::new(db, block_size).unwrap();
        let query = Query { id: 1, subset: vec![(0, 0), (0, 1), (1, 0), (1, 1)] };
        let err = server.answer(&query).unwrap_err();
        assert!(matches!(err, ServerError::SubsetOutOfRange));
    }

    #[test]
    fn test_server_answer_offset_out_of_range() {
        let entry_size = 1;
        let block_size = 2;
        let db = InMemoryDb::new(vec![1, 2, 3, 4], entry_size).unwrap();
        let server = Server::new(db, block_size).unwrap();
        let query = Query { id: 1, subset: vec![(0, 2)] };
        let err = server.answer(&query).unwrap_err();
        assert!(matches!(err, ServerError::SubsetOutOfRange));
    }

    #[test]
    fn test_server_answer_index_overflow() {
        let entry_size = 1;
        let block_size = u64::MAX;
        let db = InMemoryDb::new(vec![1], entry_size).unwrap();
        let server = Server::new(db, block_size).unwrap();
        let query = Query { id: 1, subset: vec![(2, 0)] };
        let err = server.answer(&query).unwrap_err();
        assert!(matches!(err, ServerError::SubsetOutOfRange));
    }
}
