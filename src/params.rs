//! RMS24 parameters.

use serde::{Deserialize, Serialize};

/// Entry size: 32B value + 8B TAG fingerprint
pub const ENTRY_SIZE: usize = 40;

/// Parameters for RMS24 PIR scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    /// Total number of database entries.
    pub num_entries: u64,
    /// Size of each entry in bytes.
    pub entry_size: usize,
    /// Security parameter (lambda). Controls hint count per block.
    pub security_param: u32,
    /// Number of entries per block (approximately sqrt(num_entries)).
    pub block_size: u64,
    /// Number of blocks (always even).
    pub num_blocks: u64,
    /// Number of regular (queryable) hints.
    pub num_reg_hints: u64,
    /// Number of backup hints for replenishment.
    pub num_backup_hints: u64,
}

impl Params {
    /// Create parameters from database size, entry size, and security parameter.
    ///
    /// Derives block_size as ceil(sqrt(num_entries)), rounds num_blocks to even,
    /// and sets hint counts to lambda * block_size.
    pub fn new(num_entries: u64, entry_size: usize, security_param: u32) -> Self {
        let block_size = (num_entries as f64).sqrt().ceil() as u64;
        let mut num_blocks = num_entries.div_ceil(block_size);
        if num_blocks % 2 == 1 {
            num_blocks += 1; // Must be even
        }
        let num_reg_hints = security_param as u64 * block_size;
        let num_backup_hints = num_reg_hints;

        Self {
            num_entries,
            entry_size,
            security_param,
            block_size,
            num_blocks,
            num_reg_hints,
            num_backup_hints,
        }
    }

    /// Return the block number containing the given entry index.
    pub fn block_of(&self, index: u64) -> u64 {
        index / self.block_size
    }

    /// Return the offset of the entry within its block.
    pub fn offset_in_block(&self, index: u64) -> u64 {
        index % self.block_size
    }

    /// Total hint count (regular + backup).
    pub fn total_hints(&self) -> u64 {
        self.num_reg_hints + self.num_backup_hints
    }
}
