//! RMS24 Client with hint generation.

use crate::hints::{find_median_cutoff, xor_bytes_inplace, HintState, HintSubset};
use crate::messages::ClientError;
use crate::params::Params;
use crate::prf::Prf;
use bincode::Options;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub struct Client {
    pub params: Params,
    pub prf: Prf,
    pub hints: HintState,
}

impl Client {
    pub fn new(params: Params) -> Self {
        Self::with_prf(params, Prf::random())
    }

    pub fn with_prf(params: Params, prf: Prf) -> Self {
        let hints = HintState::new(
            params.num_reg_hints as usize,
            params.num_backup_hints as usize,
            params.entry_size,
        );
        Self { params, prf, hints }
    }

    /// Generate precomputed subsets for GPU hint generation.
    ///
    /// Phase 1 only: computes cutoffs and subset membership.
    /// Does NOT stream database or compute parities.
    /// Uses rayon for parallel processing across hints.
    pub fn generate_subsets(&self) -> Vec<HintSubset> {
        self.generate_subsets_range(0, (self.params.num_reg_hints + self.params.num_backup_hints) as usize)
    }

    /// Generate precomputed subsets for a specific hint range.
    ///
    /// For distributed GPU generation: each GPU handles [hint_start, hint_end).
    pub fn generate_subsets_range(&self, hint_start: usize, hint_end: usize) -> Vec<HintSubset> {
        let p = &self.params;
        let num_reg = p.num_reg_hints as usize;
        let num_blocks = p.num_blocks as u32;
        let block_size = p.block_size as u64;

        (hint_start..hint_end)
            .into_par_iter()
            .map_init(
                || (
                    Vec::with_capacity(num_blocks as usize), 
                    Vec::with_capacity(num_blocks as usize),
                    Vec::with_capacity(num_blocks as usize * 64),
                    Vec::with_capacity(num_blocks as usize * 64)
                ),
                |(select_values, offset_values, select_bytes, offset_bytes), hint_idx| {
                    self.prf.fill_select_and_offset_reused(
                        hint_idx as u32, 
                        num_blocks, 
                        select_values, 
                        offset_values,
                        select_bytes,
                        offset_bytes
                    );
                    let cutoff = find_median_cutoff(select_values);

                    let mut subset = HintSubset::new();
                    subset.is_regular = hint_idx < num_reg;

                    if cutoff == 0 {
                        return subset;
                    }

                    let mut high_blocks = Vec::new();
                    for block in 0..num_blocks {
                        let offset = (offset_values[block as usize] % block_size) as u32;
                        if select_values[block as usize] < cutoff {
                            subset.blocks.push(block);
                            subset.offsets.push(offset);
                        } else {
                            high_blocks.push((block, offset));
                        }
                    }

                    if hint_idx < num_reg && !high_blocks.is_empty() {
                        let mut rng = rand::thread_rng();
                        let idx = rng.gen_range(0..high_blocks.len());
                        subset.extra_block = high_blocks[idx].0;
                        subset.extra_offset = rng.gen_range(0..block_size as u32);
                    }

                    subset
                }
            )
            .collect()
    }

    /// Generate hints from database bytes.
    ///
    /// Database layout: num_entries * entry_size bytes, row-major.
    pub fn generate_hints(&mut self, db: &[u8]) {
        let p = &self.params;
        let num_total = (p.num_reg_hints + p.num_backup_hints) as usize;
        let num_reg = p.num_reg_hints as usize;
        let num_blocks = p.num_blocks as u32;
        let block_size = p.block_size as u64;

        // Reset hint state
        self.hints = HintState::new(num_reg, p.num_backup_hints as usize, p.entry_size);

        // Phase 1: Build skeleton (cutoffs and extras)
        let mut rng = rand::thread_rng();
        for hint_idx in 0..num_total {
            let mut select_values = self.prf.select_vector(hint_idx as u32, num_blocks);
            self.hints.cutoffs[hint_idx] = find_median_cutoff(&mut select_values);

            if hint_idx < num_reg && self.hints.cutoffs[hint_idx] != 0 {
                // Pick random block from high subset
                loop {
                    let block: u32 = rng.gen_range(0..num_blocks);
                    if self.prf.select(hint_idx as u32, block) >= self.hints.cutoffs[hint_idx] {
                        self.hints.extra_blocks[hint_idx] = block;
                        self.hints.extra_offsets[hint_idx] = rng.gen_range(0..block_size as u32);
                        break;
                    }
                }
            }
        }

        // Phase 2: Stream database and accumulate parities
        for block in 0..num_blocks {
            let block_start = block as u64 * block_size;

            for hint_idx in 0..num_total {
                let cutoff = self.hints.cutoffs[hint_idx];
                if cutoff == 0 {
                    continue;
                }

                let select_value = self.prf.select(hint_idx as u32, block);
                let picked_offset = (self.prf.offset(hint_idx as u32, block) % block_size) as u64;
                let entry_idx = block_start + picked_offset;

                if entry_idx >= p.num_entries {
                    continue;
                }

                let entry_start = (entry_idx as usize) * p.entry_size;
                let entry = &db[entry_start..entry_start + p.entry_size];
                let is_selected = select_value < cutoff;

                if hint_idx < num_reg {
                    if is_selected {
                        xor_bytes_inplace(&mut self.hints.parities[hint_idx], entry);
                    } else if block == self.hints.extra_blocks[hint_idx] {
                        let extra_idx = block_start + self.hints.extra_offsets[hint_idx] as u64;
                        if extra_idx < p.num_entries {
                            let extra_start = (extra_idx as usize) * p.entry_size;
                            let extra_entry = &db[extra_start..extra_start + p.entry_size];
                            xor_bytes_inplace(&mut self.hints.parities[hint_idx], extra_entry);
                        }
                    }
                } else {
                    let backup_idx = hint_idx - num_reg;
                    if is_selected {
                        xor_bytes_inplace(&mut self.hints.parities[hint_idx], entry);
                    } else {
                        xor_bytes_inplace(&mut self.hints.backup_parities_high[backup_idx], entry);
                    }
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct OnlineClient {
    pub params: Params,
    pub prf: Prf,
    pub hints: HintState,
    pub available_hints: Vec<usize>,
    pub rng: ChaCha20Rng,
    pub next_query_id: u64,
}

impl OnlineClient {
    pub fn new(params: Params, prf: Prf, seed: u64) -> Self {
        let hints = HintState::new(
            params.num_reg_hints as usize,
            params.num_backup_hints as usize,
            params.entry_size,
        );
        let available_hints = (0..params.num_reg_hints as usize).collect();
        Self {
            params,
            prf,
            hints,
            available_hints,
            rng: ChaCha20Rng::seed_from_u64(seed),
            next_query_id: 0,
        }
    }

    pub fn serialize_state(&self) -> Result<Vec<u8>, ClientError> {
        Self::bincode_options()
            .serialize(self)
            .map_err(|e| ClientError::SerializationError(e.to_string()))
    }

    pub fn deserialize_state(bytes: &[u8]) -> Result<Self, ClientError> {
        let options = Self::bincode_options().with_limit(bytes.len() as u64);
        let client: Self = options
            .deserialize(bytes)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        client.validate_state()?;
        Ok(client)
    }

    pub fn next_query_id(&mut self) -> u64 {
        let id = self.next_query_id;
        self.next_query_id += 1;
        id
    }

    fn bincode_options() -> impl Options {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
    }

    fn validate_state(&self) -> Result<(), ClientError> {
        if self.params.entry_size == 0 {
            return Err(ClientError::SerializationError(
                "entry_size must be greater than 0".to_string(),
            ));
        }

        let num_reg = self.params.num_reg_hints as usize;
        let num_backup = self.params.num_backup_hints as usize;
        let total = num_reg + num_backup;
        let hints = &self.hints;

        if hints.cutoffs.len() != total
            || hints.extra_blocks.len() != total
            || hints.extra_offsets.len() != total
            || hints.parities.len() != total
            || hints.flips.len() != total
        {
            return Err(ClientError::SerializationError(
                "hint vector length mismatch".to_string(),
            ));
        }

        if hints.backup_parities_high.len() != num_backup {
            return Err(ClientError::SerializationError(
                "backup parity length mismatch".to_string(),
            ));
        }

        let entry_size = self.params.entry_size;
        if hints.parities.iter().any(|p| p.len() != entry_size) {
            return Err(ClientError::SerializationError(
                "parity length mismatch".to_string(),
            ));
        }
        if hints
            .backup_parities_high
            .iter()
            .any(|p| p.len() != entry_size)
        {
            return Err(ClientError::SerializationError(
                "backup parity length mismatch".to_string(),
            ));
        }

        let mut seen = HashSet::new();
        for &hint in &self.available_hints {
            if hint >= num_reg {
                return Err(ClientError::SerializationError(
                    "available hint out of range".to_string(),
                ));
            }
            if !seen.insert(hint) {
                return Err(ClientError::SerializationError(
                    "duplicate available hint".to_string(),
                ));
            }
        }

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_generate_hints_basic() {
        let params = Params::new(100, 40, 2);
        let mut client = Client::new(params);
        let db: Vec<u8> = vec![0u8; 100 * 40];
        client.generate_hints(&db);
        assert!(client.hints.cutoffs.iter().any(|&c| c > 0));
    }

    #[test]
    fn test_generate_hints_nonzero_db() {
        let params = Params::new(64, 40, 2);
        let mut client = Client::new(params);
        let mut db = vec![0u8; 64 * 40];
        for i in 0..64 {
            db[i * 40] = i as u8;
        }
        client.generate_hints(&db);
        // At least some parities should be non-zero
        let any_nonzero = client.hints.parities.iter().any(|p| p.iter().any(|&b| b != 0));
        assert!(any_nonzero);
    }

    #[test]
    fn test_hint_coverage() {
        let params = Params::new(100, 40, 8);
        let mut client = Client::new(params.clone());
        let db = vec![0xFFu8; 100 * 40];
        client.generate_hints(&db);
        
        // Most hints should be valid (cutoff > 0)
        let valid_count = client.hints.cutoffs.iter().filter(|&&c| c > 0).count();
        assert!(valid_count > 0, "Should have valid hints");
    }

    #[test]
    fn test_generate_subsets_basic() {
        let params = Params::new(100, 40, 2);
        let client = Client::new(params.clone());
        let subsets = client.generate_subsets();

        let num_total = (params.num_reg_hints + params.num_backup_hints) as usize;
        let num_reg = params.num_reg_hints as usize;
        let num_blocks = params.num_blocks as usize;

        assert_eq!(subsets.len(), num_total);

        for (i, subset) in subsets.iter().enumerate() {
            if subset.blocks.is_empty() {
                continue;
            }

            let subset_size = subset.blocks.len();
            let expected_half = num_blocks / 2;
            let lower = expected_half * 80 / 100;
            let upper = expected_half * 120 / 100;
            assert!(
                subset_size >= lower && subset_size <= upper,
                "Subset {} has {} blocks, expected ~{} (within 20%)",
                i,
                subset_size,
                expected_half
            );

            if i < num_reg && subset.extra_block != u32::MAX {
                assert!(
                    !subset.blocks.contains(&subset.extra_block),
                    "Extra block {} should be in high subset (not in low)",
                    subset.extra_block
                );
            }
        }
    }

    #[test]
    fn test_client_state_roundtrip() {
        let params = Params::new(16, 40, 2);
        let mut client = OnlineClient::new(params, Prf::random(), 1234u64);
        let data = client.serialize_state().unwrap();
        let mut client2 = OnlineClient::deserialize_state(&data).unwrap();
        assert_eq!(client.prf.key(), client2.prf.key());
        let r1 = client.rng.next_u64();
        let r2 = client2.rng.next_u64();
        assert_eq!(r1, r2);
        let id1 = client.next_query_id();
        let id2 = client2.next_query_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_client_state_invalid_available_hints() {
        let params = Params::new(16, 40, 2);
        let mut client = OnlineClient::new(params, Prf::random(), 1234u64);
        let num_reg = client.params.num_reg_hints as usize;
        client.available_hints.push(num_reg + 1);
        let data = client.serialize_state().unwrap();
        let result = OnlineClient::deserialize_state(&data);
        assert!(matches!(result, Err(ClientError::SerializationError(_))));
    }

}
