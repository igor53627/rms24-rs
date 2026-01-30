//! Hint replenish helpers.

use crate::hints::{xor_bytes_inplace, HintState};
use crate::params::Params;
use crate::prf::Prf;

pub struct ReplenishResult {
    pub cutoff: u32,
    pub flip: bool,
    pub parity: Vec<u8>,
}

pub fn replenish_from_backup(
    params: &Params,
    prf: &Prf,
    hints: &HintState,
    backup_hint: usize,
    backup_prf_id: u32,
    target_index: u64,
    target_entry: &[u8],
) -> Option<ReplenishResult> {
    if target_entry.len() != params.entry_size {
        return None;
    }

    let cutoff = *hints.cutoffs.get(backup_hint)?;
    if cutoff == 0 {
        return None;
    }

    let target_block = params.block_of(target_index) as u32;
    let select = prf.select(backup_prf_id, target_block);
    let target_in_low = select < cutoff;

    let num_reg = params.num_reg_hints as usize;
    let backup_idx = backup_hint.checked_sub(num_reg)?;
    let mut parity = if target_in_low {
        hints.backup_parities_high.get(backup_idx)?.clone()
    } else {
        hints.parities.get(backup_hint)?.clone()
    };
    xor_bytes_inplace(&mut parity, target_entry);

    Some(ReplenishResult {
        cutoff,
        flip: target_in_low,
        parity,
    })
}
