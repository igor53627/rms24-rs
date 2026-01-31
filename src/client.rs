//! RMS24 Client with hint generation.

use crate::hints::{find_median_cutoff, xor_bytes_inplace, HintState, HintSubset};
use crate::messages::ClientError;
use crate::updates::replenish_from_backup;
use crate::params::Params;
use crate::prf::Prf;
use bincode::Options;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;

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
        let total_hints = num_total as u64;
        let total_blocks = num_blocks as u64;

        // Reset hint state
        self.hints = HintState::new(num_reg, p.num_backup_hints as usize, p.entry_size);

        // Phase 1: Build skeleton (cutoffs and extras)
        let mut rng = rand::thread_rng();
        let phase1_start = Instant::now();
        let log_every_hint = std::cmp::max(1, (total_hints + 99) / 100);
        let mut next_hint_log = log_every_hint;
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

            let done = (hint_idx + 1) as u64;
            if done >= next_hint_log || done == total_hints {
                let elapsed = phase1_start.elapsed().as_secs_f64();
                let rate = done as f64 / elapsed;
                let eta = if rate > 0.0 {
                    (total_hints.saturating_sub(done)) as f64 / rate
                } else {
                    0.0
                };
                let pct = done as f64 * 100.0 / total_hints.max(1) as f64;
                println!(
                    "progress phase=phase1 pct={:.1} elapsed_s={:.0} eta_s={:.0}",
                    pct, elapsed, eta
                );
                if done >= next_hint_log {
                    next_hint_log += log_every_hint;
                }
            }
        }

        // Phase 2: Stream database and accumulate parities
        let phase2_start = Instant::now();
        let log_every_block = std::cmp::max(1, (total_blocks + 99) / 100);
        let mut next_block_log = log_every_block;
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

            let done = (block + 1) as u64;
            if done >= next_block_log || done == total_blocks {
                let elapsed = phase2_start.elapsed().as_secs_f64();
                let rate = done as f64 / elapsed;
                let eta = if rate > 0.0 {
                    (total_blocks.saturating_sub(done)) as f64 / rate
                } else {
                    0.0
                };
                let pct = done as f64 * 100.0 / total_blocks.max(1) as f64;
                println!(
                    "progress phase=phase2 pct={:.1} elapsed_s={:.0} eta_s={:.0}",
                    pct, elapsed, eta
                );
                if done >= next_block_log {
                    next_block_log += log_every_block;
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
    pub hint_prf_ids: Vec<u32>,
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
        let total = (params.num_reg_hints + params.num_backup_hints) as usize;
        let hint_prf_ids = (0..total).map(|id| id as u32).collect();
        Self {
            params,
            prf,
            hints,
            hint_prf_ids,
            available_hints,
            rng: ChaCha20Rng::seed_from_u64(seed),
            next_query_id: 0,
        }
    }

    pub fn generate_hints(&mut self, db: &[u8]) -> Result<(), ClientError> {
        let mut offline = Client::with_prf(self.params.clone(), self.prf.clone());
        offline.generate_hints(db);
        self.hints = offline.hints;
        self.available_hints = (0..self.params.num_reg_hints as usize).collect();
        Ok(())
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

    fn hint_covers(&self, hint_id: usize, target_block: u32, target_offset: u32) -> bool {
        let cutoff = self.hints.cutoffs[hint_id];
        if cutoff == 0 {
            return false;
        }
        let prf_id = self.hint_prf_ids[hint_id];
        let select = self.prf.select(prf_id, target_block);
        let offset = (self.prf.offset(prf_id, target_block) % self.params.block_size) as u32;
        let flipped = self.hints.flips[hint_id];
        let is_selected = if flipped { select >= cutoff } else { select < cutoff };
        if is_selected && offset == target_offset {
            return true;
        }
        let extra_block = self.hints.extra_blocks[hint_id];
        let extra_offset = self.hints.extra_offsets[hint_id];
        extra_block == target_block && extra_offset == target_offset
    }

    pub fn build_network_queries(
        &mut self,
        index: u64,
    ) -> Result<(crate::messages::Query, crate::messages::Query, usize), ClientError> {
        if index >= self.params.num_entries {
            return Err(ClientError::InvalidIndex);
        }

        let target_block = self.params.block_of(index) as u32;
        let target_offset = self.params.offset_in_block(index) as u32;

        let mut candidates = Vec::new();
        for &hint_id in &self.available_hints {
            if self.hint_covers(hint_id, target_block, target_offset) {
                candidates.push(hint_id);
            }
        }

        if candidates.is_empty() {
            return Err(ClientError::NoValidHint);
        }

        let id = self.next_query_id();
        let candidate_idx = self.rng.gen_range(0..candidates.len());
        let real_hint = candidates.swap_remove(candidate_idx);
        let mut real_subset = self.build_subset_for_hint(real_hint);
        if let Some(pos) = real_subset
            .iter()
            .position(|(block, offset)| *block == target_block && *offset == target_offset)
        {
            real_subset.swap_remove(pos);
        }

        let dummy_hint = self.available_hints[self.rng.gen_range(0..self.available_hints.len())];
        let dummy_subset = self.build_subset_for_hint(dummy_hint);

        let real_query = crate::messages::Query {
            id,
            subset: real_subset,
        };
        let dummy_query = crate::messages::Query {
            id,
            subset: dummy_subset,
        };

        Ok((real_query, dummy_query, real_hint))
    }

    pub fn build_coverage_index(&self) -> Vec<Vec<u32>> {
        let num_entries = self.params.num_entries as usize;
        let num_reg = self.params.num_reg_hints as usize;
        let mut coverage = vec![Vec::new(); num_entries];
        let block_size = self.params.block_size;

        for hint_id in 0..num_reg {
            let subset = self.build_subset_for_hint(hint_id);
            for (block, offset) in subset {
                let idx = (block as u64) * block_size + (offset as u64);
                if idx < self.params.num_entries {
                    coverage[idx as usize].push(hint_id as u32);
                }
            }
        }
        coverage
    }

    pub fn build_network_queries_with_coverage(
        &mut self,
        index: u64,
        coverage: &[Vec<u32>],
    ) -> Result<(crate::messages::Query, crate::messages::Query, usize), ClientError> {
        if index >= self.params.num_entries {
            return Err(ClientError::InvalidIndex);
        }
        let target_block = self.params.block_of(index) as u32;
        let target_offset = self.params.offset_in_block(index) as u32;

        let mut candidates: Vec<usize> = coverage[index as usize]
            .iter()
            .copied()
            .map(|id| id as usize)
            .collect();

        if candidates.is_empty() {
            return self.build_network_queries(index);
        }

        let candidate_idx = self.rng.gen_range(0..candidates.len());
        let real_hint = candidates.swap_remove(candidate_idx);
        let mut real_subset = self.build_subset_for_hint(real_hint);
        if let Some(pos) = real_subset
            .iter()
            .position(|(block, offset)| *block == target_block && *offset == target_offset)
        {
            real_subset.swap_remove(pos);
        }

        let dummy_hint = self.available_hints[self.rng.gen_range(0..self.available_hints.len())];
        let dummy_subset = self.build_subset_for_hint(dummy_hint);

        let id = self.next_query_id();
        let real_query = crate::messages::Query {
            id,
            subset: real_subset,
        };
        let dummy_query = crate::messages::Query {
            id,
            subset: dummy_subset,
        };

        Ok((real_query, dummy_query, real_hint))
    }

    pub fn consume_network_reply(
        &mut self,
        index: u64,
        real_hint: usize,
        mut parity: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        if parity.len() != self.params.entry_size {
            return Err(ClientError::ParityLengthMismatch);
        }

        let hint_parity = &self.hints.parities[real_hint];
        if parity.len() != hint_parity.len() {
            return Err(ClientError::ParityLengthMismatch);
        }
        xor_bytes_inplace(&mut parity, hint_parity);

        if let Some(pos) = self.available_hints.iter().position(|&hint| hint == real_hint) {
            self.available_hints.swap_remove(pos);
        }
        self.replenish_hint(real_hint, index, &parity)?;
        self.available_hints.push(real_hint);

        Ok(parity)
    }

    pub fn decode_reply_static(
        &self,
        real_hint: usize,
        mut parity: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        let hint_parity = &self.hints.parities[real_hint];
        if parity.len() != hint_parity.len() {
            return Err(ClientError::ParityLengthMismatch);
        }
        xor_bytes_inplace(&mut parity, hint_parity);
        Ok(parity)
    }

    fn build_subset_for_hint(&self, hint_id: usize) -> Vec<(u32, u32)> {
        let cutoff = self.hints.cutoffs[hint_id];
        if cutoff == 0 {
            return Vec::new();
        }

        let mut subset = Vec::new();
        let num_blocks = self.params.num_blocks as u32;
        let block_size = self.params.block_size;
        let num_entries = self.params.num_entries;
        let flipped = self.hints.flips[hint_id];
        let prf_id = self.hint_prf_ids[hint_id];

        let mut push_if_in_range = |block: u32, offset: u32| {
            let offset_u64 = offset as u64;
            if offset_u64 >= block_size {
                return;
            }
            let entry_idx = (block as u64)
                .checked_mul(block_size)
                .and_then(|base| base.checked_add(offset_u64));
            if let Some(idx) = entry_idx {
                if idx < num_entries {
                    subset.push((block, offset));
                }
            }
        };

        for block in 0..num_blocks {
            let select = self.prf.select(prf_id, block);
            let offset = (self.prf.offset(prf_id, block) % block_size) as u32;
            let is_selected = if flipped { select >= cutoff } else { select < cutoff };
            if is_selected {
                push_if_in_range(block, offset);
            }
        }

        let extra_block = self.hints.extra_blocks[hint_id];
        if extra_block != u32::MAX {
            let extra_offset = self.hints.extra_offsets[hint_id];
            push_if_in_range(extra_block, extra_offset);
        }

        subset
    }

    pub fn query<D: crate::server::Db>(
        &mut self,
        server: &crate::server::Server<D>,
        index: u64,
    ) -> Result<Vec<u8>, ClientError> {
        if index >= self.params.num_entries {
            return Err(ClientError::InvalidIndex);
        }

        let target_block = self.params.block_of(index) as u32;
        let target_offset = self.params.offset_in_block(index) as u32;

        let mut candidates = Vec::new();
        for &hint_id in &self.available_hints {
            let subset = self.build_subset_for_hint(hint_id);
            if subset
                .iter()
                .any(|(block, offset)| *block == target_block && *offset == target_offset)
            {
                candidates.push((hint_id, subset));
            }
        }

        if candidates.is_empty() {
            return Err(ClientError::NoValidHint);
        }

        let id = self.next_query_id();
        let candidate_idx = self.rng.gen_range(0..candidates.len());
        let (real_hint, mut real_subset) = candidates.swap_remove(candidate_idx);
        if let Some(pos) = real_subset
            .iter()
            .position(|(block, offset)| *block == target_block && *offset == target_offset)
        {
            real_subset.swap_remove(pos);
        }

        let dummy_hint = self.available_hints[self.rng.gen_range(0..self.available_hints.len())];
        let dummy_subset = self.build_subset_for_hint(dummy_hint);

        let real_query = crate::messages::Query {
            id,
            subset: real_subset,
        };
        let dummy_query = crate::messages::Query {
            id,
            subset: dummy_subset,
        };

        let real_reply = server
            .answer(&real_query)
            .map_err(|_| ClientError::VerificationFailed)?;
        let _dummy_reply = server
            .answer(&dummy_query)
            .map_err(|_| ClientError::VerificationFailed)?;

        let mut result = real_reply.parity;
        let hint_parity = &self.hints.parities[real_hint];
        if result.len() != hint_parity.len() {
            return Err(ClientError::ParityLengthMismatch);
        }
        xor_bytes_inplace(&mut result, hint_parity);

        if let Some(pos) = self.available_hints.iter().position(|&hint| hint == real_hint) {
            self.available_hints.swap_remove(pos);
        }
        self.replenish_hint(real_hint, index, &result)?;
        self.available_hints.push(real_hint);

        Ok(result)
    }

    pub fn apply_update(&mut self, update: &crate::messages::Update) -> Result<(), ClientError> {
        if update.index >= self.params.num_entries {
            return Err(ClientError::InvalidIndex);
        }
        if update.old_entry.len() != self.params.entry_size
            || update.new_entry.len() != self.params.entry_size
        {
            return Err(ClientError::ParityLengthMismatch);
        }

        let num_reg = self.params.num_reg_hints as usize;
        let num_total = (self.params.num_reg_hints + self.params.num_backup_hints) as usize;
        let block = self.params.block_of(update.index) as u32;
        let offset = self.params.offset_in_block(update.index) as u32;

        for hint_id in 0..num_total {
            let cutoff = self.hints.cutoffs[hint_id];
            if cutoff == 0 {
                continue;
            }
            let prf_id = self.hint_prf_ids[hint_id];

            let select = self.prf.select(prf_id, block);
            let picked_offset =
                (self.prf.offset(prf_id, block) % self.params.block_size) as u32;
            let matches_selected = picked_offset == offset;

            if hint_id < num_reg {
                let flipped = self.hints.flips[hint_id];
                let is_selected = if flipped { select >= cutoff } else { select < cutoff };
                let extra_block = self.hints.extra_blocks[hint_id];
                let extra_offset = self.hints.extra_offsets[hint_id];
                let matches_extra = extra_block == block && extra_offset == offset;
                if (matches_selected && is_selected) || matches_extra {
                    xor_bytes_inplace(&mut self.hints.parities[hint_id], &update.old_entry);
                    xor_bytes_inplace(&mut self.hints.parities[hint_id], &update.new_entry);
                }
            } else {
                if !matches_selected {
                    continue;
                }
                let backup_idx = hint_id - num_reg;
                if select < cutoff {
                    xor_bytes_inplace(&mut self.hints.parities[hint_id], &update.old_entry);
                    xor_bytes_inplace(&mut self.hints.parities[hint_id], &update.new_entry);
                } else {
                    xor_bytes_inplace(
                        &mut self.hints.backup_parities_high[backup_idx],
                        &update.old_entry,
                    );
                    xor_bytes_inplace(
                        &mut self.hints.backup_parities_high[backup_idx],
                        &update.new_entry,
                    );
                }
            }
        }

        Ok(())
    }

    fn replenish_hint(
        &mut self,
        consumed_hint: usize,
        target_index: u64,
        target_entry: &[u8],
    ) -> Result<(), ClientError> {
        let num_reg = self.params.num_reg_hints as usize;
        let num_backup = self.params.num_backup_hints as usize;
        if num_backup == 0 {
            return Ok(());
        }
        let total = num_reg + num_backup;
        let backup_hint = self.hints.next_backup_idx;
        if backup_hint < num_reg || backup_hint >= total {
            return Err(ClientError::VerificationFailed);
        }
        let backup_prf_id = self.hint_prf_ids[backup_hint];

        let replenish = replenish_from_backup(
            &self.params,
            &self.prf,
            &self.hints,
            backup_hint,
            backup_prf_id,
            target_index,
            target_entry,
        )
        .ok_or(ClientError::VerificationFailed)?;

        let target_block = self.params.block_of(target_index) as u32;
        let target_offset = self.params.offset_in_block(target_index) as u32;
        self.hints.cutoffs[consumed_hint] = replenish.cutoff;
        self.hints.flips[consumed_hint] = replenish.flip;
        self.hints.extra_blocks[consumed_hint] = target_block;
        self.hints.extra_offsets[consumed_hint] = target_offset;
        self.hints.parities[consumed_hint] = replenish.parity;
        self.hint_prf_ids[consumed_hint] = backup_prf_id;

        self.hints.cutoffs[backup_hint] = 0;
        let next = if backup_hint + 1 < total {
            backup_hint + 1
        } else {
            num_reg
        };
        self.hints.next_backup_idx = next;

        Ok(())
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
            || self.hint_prf_ids.len() != total
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
        if self
            .hint_prf_ids
            .iter()
            .any(|&id| id as usize >= total)
        {
            return Err(ClientError::SerializationError(
                "hint prf id out of range".to_string(),
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

    #[test]
    fn test_query_round_trip_basic() {
        let params = Params::new(16, 4, 2);
        let db = (0..(16 * 4)).map(|i| i as u8).collect::<Vec<u8>>();
        let prf = Prf::random();
        let mut offline = Client::with_prf(params.clone(), prf.clone());
        offline.generate_hints(&db);
        let mut client = OnlineClient::new(params.clone(), prf, 42);
        client.hints = offline.hints.clone();
        let server = crate::server::Server::new(
            crate::server::InMemoryDb::new(db, 4).unwrap(),
            params.block_size,
        )
        .unwrap();

        let mut index = None;
        for &hint_id in &client.available_hints {
            let subset = client.build_subset_for_hint(hint_id);
            if let Some((block, offset)) = subset.first().copied() {
                let candidate = (block as u64) * params.block_size + (offset as u64);
                if candidate < params.num_entries {
                    index = Some(candidate);
                    break;
                }
            }
        }
        let index = index.expect("expected at least one hint to cover an entry");
        let result = client.query(&server, index).unwrap();
        let expected = vec![
            (index * 4) as u8,
            (index * 4 + 1) as u8,
            (index * 4 + 2) as u8,
            (index * 4 + 3) as u8,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_online_client_build_and_consume_network_query() {
        let params = Params::new(16, 4, 4);
        let prf = Prf::random();
        let mut client = OnlineClient::new(params.clone(), prf, 1);

        let db = vec![7u8; (params.num_entries as usize) * params.entry_size];
        client.generate_hints(&db).unwrap();

        let (real_query, dummy_query, real_hint) = client.build_network_queries(3).unwrap();
        assert_eq!(real_query.id, dummy_query.id);
        assert!(!real_query.subset.is_empty());

        let parity = vec![0u8; params.entry_size];
        let _ = client.consume_network_reply(3, real_hint, parity).unwrap();
    }

    #[test]
    fn test_hint_covers_matches_subset() {
        let params = Params::new(64, 4, 4);
        let prf = Prf::random();
        let mut client = OnlineClient::new(params.clone(), prf, 1);
        let db = vec![7u8; (params.num_entries as usize) * params.entry_size];
        client.generate_hints(&db).unwrap();

        let mut found = None;
        for hint_id in 0..client.available_hints.len() {
            let subset = client.build_subset_for_hint(hint_id);
            if let Some((block, offset)) = subset.first().copied() {
                found = Some((hint_id, block, offset));
                break;
            }
        }
        let (hint_id, block, offset) = found.expect("expected non-empty subset");
        assert!(client.hint_covers(hint_id, block, offset));
    }

    #[test]
    fn test_build_coverage_index_contains_hint() {
        let params = Params::new(64, 4, 4);
        let prf = Prf::random();
        let mut client = OnlineClient::new(params.clone(), prf, 1);
        let db = vec![7u8; (params.num_entries as usize) * params.entry_size];
        client.generate_hints(&db).unwrap();

        let coverage = client.build_coverage_index();
        let num_reg = params.num_reg_hints as usize;

        for hint_id in 0..num_reg {
            let subset = client.build_subset_for_hint(hint_id);
            for (block, offset) in subset {
                let idx = (block as u64) * params.block_size + offset as u64;
                assert!(coverage[idx as usize].contains(&(hint_id as u32)));
            }
        }
    }

    #[test]
    fn test_network_queries_with_coverage_selects_hint() {
        let params = Params::new(64, 4, 4);
        let prf = Prf::random();
        let mut client = OnlineClient::new(params.clone(), prf, 1);
        let db = vec![7u8; (params.num_entries as usize) * params.entry_size];
        client.generate_hints(&db).unwrap();
        let coverage = client.build_coverage_index();

        let index = 3u64;
        let (real_query, _dummy_query, real_hint) =
            client.build_network_queries_with_coverage(index, &coverage).unwrap();

        assert!(coverage[index as usize].contains(&(real_hint as u32)));
        assert_eq!(real_query.id, real_query.id);
    }

    #[test]
    fn test_decode_reply_static() {
        let params = Params::new(16, 4, 2);
        let prf = Prf::random();
        let mut client = OnlineClient::new(params.clone(), prf, 1);
        let db = vec![0u8; (params.num_entries as usize) * params.entry_size];
        client.generate_hints(&db).unwrap();

        let real_hint = 0;
        let parity = vec![0u8; params.entry_size];
        let decoded = client.decode_reply_static(real_hint, parity).unwrap();
        assert_eq!(decoded.len(), params.entry_size);
    }

    #[test]
    fn test_build_subset_skips_out_of_range_entries() {
        let params = Params::new(5, 1, 1);
        let mut client = OnlineClient::new(params.clone(), Prf::random(), 0);
        let hint_id = 0;
        client.hints.cutoffs[hint_id] = u32::MAX;
        client.hints.flips[hint_id] = false;
        client.hints.extra_blocks[hint_id] = 1;
        client.hints.extra_offsets[hint_id] = 2;

        let subset = client.build_subset_for_hint(hint_id);
        assert!(subset.iter().all(|(block, offset)| {
            let idx = (*block as u64) * params.block_size + (*offset as u64);
            idx < params.num_entries
        }));
    }

    #[test]
    fn test_hint_consumed_after_query() {
        let params = Params::new(16, 4, 2);
        let db = vec![0u8; (params.num_entries as usize) * params.entry_size];
        let prf = Prf::random();
        let mut offline = Client::with_prf(params.clone(), prf.clone());
        offline.generate_hints(&db);
        let mut client = OnlineClient::new(params.clone(), prf, 42);
        client.hints = offline.hints.clone();
        let server = crate::server::Server::new(
            crate::server::InMemoryDb::new(db, params.entry_size).unwrap(),
            params.block_size,
        )
        .unwrap();

        let mut index = None;
        for &hint_id in &client.available_hints {
            let subset = client.build_subset_for_hint(hint_id);
            if let Some((block, offset)) = subset.first().copied() {
                let candidate = (block as u64) * params.block_size + (offset as u64);
                if candidate < params.num_entries {
                    index = Some(candidate);
                    break;
                }
            }
        }
        let index = index.expect("expected at least one hint to cover an entry");
        let before_len = client.available_hints.len();
        let before_backup_idx = client.hints.next_backup_idx;
        let _ = client.query(&server, index).unwrap();
        assert_eq!(client.available_hints.len(), before_len);
        let num_reg = params.num_reg_hints as usize;
        let num_backup = params.num_backup_hints as usize;
        let total = num_reg + num_backup;
        let expected = if before_backup_idx + 1 < total {
            before_backup_idx + 1
        } else {
            num_reg
        };
        assert_eq!(client.hints.next_backup_idx, expected);
    }

    #[test]
    fn test_point_update_round_trip() {
        let params = Params::new(8, 4, 2);
        let db = vec![0u8; (params.num_entries as usize) * params.entry_size];
        let prf = Prf::random();
        let mut offline = Client::with_prf(params.clone(), prf.clone());
        offline.generate_hints(&db);
        let mut client = OnlineClient::new(params.clone(), prf, 1);
        client.hints = offline.hints.clone();
        let mut server = crate::server::Server::new(
            crate::server::InMemoryDb::new(db, params.entry_size).unwrap(),
            params.block_size,
        )
        .unwrap();

        let mut index = None;
        for &hint_id in &client.available_hints {
            let subset = client.build_subset_for_hint(hint_id);
            if let Some((block, offset)) = subset.first().copied() {
                let candidate = (block as u64) * params.block_size + (offset as u64);
                if candidate < params.num_entries {
                    index = Some(candidate);
                    break;
                }
            }
        }
        let index = index.expect("expected at least one hint to cover an entry");
        let old_entry = vec![0u8; params.entry_size];
        let new_entry = vec![9u8; params.entry_size];
        let update = crate::messages::Update {
            index,
            old_entry,
            new_entry: new_entry.clone(),
        };
        server.apply_update(&update).unwrap();
        client.apply_update(&update).unwrap();

        let got = client.query(&server, index).unwrap();
        assert_eq!(got, new_entry);
    }

    #[test]
    fn test_apply_update_handles_extra_entry_collision() {
        let params = Params::new(16, 4, 1);
        let prf = Prf::new([7u8; 32]);
        let mut client = OnlineClient::new(params.clone(), prf, 0);
        let total = (params.num_reg_hints + params.num_backup_hints) as usize;

        client.hints.cutoffs = vec![0; total];
        client.hints.parities = vec![vec![0u8; params.entry_size]; total];
        client.hints.flips = vec![false; total];
        client.hints.extra_blocks = vec![u32::MAX; total];
        client.hints.extra_offsets = vec![0; total];

        let cutoff = u32::MAX / 2;
        client.hints.cutoffs[0] = cutoff;

        let prf_id = client.hint_prf_ids[0];
        let num_blocks = params.num_blocks as u32;
        let block_size = params.block_size;
        let mut chosen = None;
        for block in 0..num_blocks {
            let select = client.prf.select(prf_id, block);
            if select >= cutoff {
                let offset = (client.prf.offset(prf_id, block) % block_size) as u32;
                let index = (block as u64) * block_size + (offset as u64);
                if index < params.num_entries {
                    chosen = Some((block, offset, index));
                    break;
                }
            }
        }
        let (block, offset, index) = chosen.expect("expected a high-subset block");
        client.hints.extra_blocks[0] = block;
        client.hints.extra_offsets[0] = offset;

        let old_entry = vec![1u8; params.entry_size];
        let new_entry = vec![9u8; params.entry_size];
        let update = crate::messages::Update {
            index,
            old_entry: old_entry.clone(),
            new_entry: new_entry.clone(),
        };

        client.apply_update(&update).unwrap();

        let mut expected = vec![0u8; params.entry_size];
        xor_bytes_inplace(&mut expected, &old_entry);
        xor_bytes_inplace(&mut expected, &new_entry);
        assert_eq!(client.hints.parities[0], expected);
    }
}
