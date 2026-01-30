use rms24::{OnlineClient, Params, Prf};
use rms24::client::Client;
use rms24::schema40::Tag;
use rms24::server::{InMemoryDb, Server};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

const ACCOUNT_MAP_RECORD_SIZE: usize = 24;
const STORAGE_MAP_RECORD_SIZE: usize = 56;
const ACCOUNT_KEY_SIZE: usize = 20;
const STORAGE_KEY_SIZE: usize = 52;
// Plinko v3 account entry layout: balance(16) + nonce(4) + code_id(4) + tag(8) + pad(8).
// Plinko v3 storage entry layout: value(32) + tag(8).
const ACCOUNT_TAG_OFFSET: usize = 24;
const STORAGE_TAG_OFFSET: usize = 32;
const TARGETS_PER_KIND: usize = 3;
const CANDIDATE_MULTIPLIER: usize = 4;

#[derive(Clone, Debug)]
struct MappingTarget {
    index: u64,
    key: Vec<u8>,
    tag_offset: usize,
}

#[test]
fn test_real_slice_optional() {
    let data_dir = match std::env::var("RMS24_DATA_DIR").ok() {
        Some(dir) => dir,
        None => return,
    };

    let base = PathBuf::from(data_dir);
    let db_path = base.join("database.bin");
    let acc_map_path = base.join("account-mapping.bin");
    let sto_map_path = base.join("storage-mapping.bin");
    let db = match fs::read(&db_path) {
        Ok(data) => data,
        Err(_) => return,
    };
    let acc_map = match fs::read(&acc_map_path) {
        Ok(data) => data,
        Err(_) => return,
    };
    let sto_map = match fs::read(&sto_map_path) {
        Ok(data) => data,
        Err(_) => return,
    };

    let entry_size = 40usize;
    if db.len() % entry_size != 0 {
        return;
    }
    if acc_map.len() % ACCOUNT_MAP_RECORD_SIZE != 0 {
        return;
    }
    if sto_map.len() % STORAGE_MAP_RECORD_SIZE != 0 {
        return;
    }

    let num_entries = (db.len() / entry_size) as u64;
    let acc_count = (acc_map.len() / ACCOUNT_MAP_RECORD_SIZE) as u64;
    let sto_count = (sto_map.len() / STORAGE_MAP_RECORD_SIZE) as u64;
    if acc_count + sto_count > num_entries {
        return;
    }

    let params = Params::new(num_entries, entry_size, 2);
    let prf = Prf::random();
    let mut offline = Client::with_prf(params.clone(), prf.clone());
    offline.generate_hints(&db);
    let mut client = OnlineClient::new(params.clone(), prf.clone(), 1);
    client.hints = offline.hints.clone();

    let db_handle = match InMemoryDb::new(db.clone(), entry_size) {
        Ok(handle) => handle,
        Err(_) => return,
    };
    let server = match Server::new(db_handle, params.block_size) {
        Ok(server) => server,
        Err(_) => return,
    };

    let (account_targets, storage_targets) = collect_targets(
        &client,
        &acc_map,
        &sto_map,
        num_entries,
        acc_count,
        sto_count,
        TARGETS_PER_KIND,
    );

    assert!(!account_targets.is_empty(), "no account targets found");
    assert!(!storage_targets.is_empty(), "no storage targets found");

    let mut targets = Vec::new();
    targets.extend(account_targets);
    targets.extend(storage_targets);

    for target in targets {
        let mut query_client = OnlineClient::new(params.clone(), prf.clone(), 1);
        query_client.hints = offline.hints.clone();
        let got = query_client.query(&server, target.index).unwrap();
        let start = target.index as usize * entry_size;
        let expected = db[start..start + entry_size].to_vec();
        assert_eq!(got, expected);
        let tag = tag_for_key(&target.key);
        let tag_end = target.tag_offset + tag.0.len();
        assert_eq!(&got[target.tag_offset..tag_end], &tag.0);
    }
}

#[test]
fn test_real_slice_sequential_optional() {
    let data_dir = match std::env::var("RMS24_DATA_DIR").ok() {
        Some(dir) => dir,
        None => return,
    };

    let base = PathBuf::from(data_dir);
    let db_path = base.join("database.bin");
    let acc_map_path = base.join("account-mapping.bin");
    let sto_map_path = base.join("storage-mapping.bin");
    let db = match fs::read(&db_path) {
        Ok(data) => data,
        Err(_) => return,
    };
    let acc_map = match fs::read(&acc_map_path) {
        Ok(data) => data,
        Err(_) => return,
    };
    let sto_map = match fs::read(&sto_map_path) {
        Ok(data) => data,
        Err(_) => return,
    };

    let entry_size = 40usize;
    if db.len() % entry_size != 0 {
        return;
    }
    if acc_map.len() % ACCOUNT_MAP_RECORD_SIZE != 0 {
        return;
    }
    if sto_map.len() % STORAGE_MAP_RECORD_SIZE != 0 {
        return;
    }

    let num_entries = (db.len() / entry_size) as u64;
    let acc_count = (acc_map.len() / ACCOUNT_MAP_RECORD_SIZE) as u64;
    let sto_count = (sto_map.len() / STORAGE_MAP_RECORD_SIZE) as u64;
    if acc_count + sto_count > num_entries {
        return;
    }

    let params = Params::new(num_entries, entry_size, 2);
    let prf = Prf::random();
    let mut offline = Client::with_prf(params.clone(), prf.clone());
    offline.generate_hints(&db);
    let mut client = OnlineClient::new(params.clone(), prf.clone(), 1);
    client.hints = offline.hints.clone();

    let db_handle = match InMemoryDb::new(db.clone(), entry_size) {
        Ok(handle) => handle,
        Err(_) => return,
    };
    let server = match Server::new(db_handle, params.block_size) {
        Ok(server) => server,
        Err(_) => return,
    };

    let total_rounds = TARGETS_PER_KIND * 2;
    for round in 0..total_rounds {
        let (account_targets, storage_targets) = collect_targets(
            &client,
            &acc_map,
            &sto_map,
            num_entries,
            acc_count,
            sto_count,
            1,
        );
        let target = if round % 2 == 0 {
            account_targets
                .into_iter()
                .next()
                .or_else(|| storage_targets.into_iter().next())
        } else {
            storage_targets
                .into_iter()
                .next()
                .or_else(|| account_targets.into_iter().next())
        };
        let target = match target {
            Some(target) => target,
            None => return,
        };

        let (target_block, target_offset) = (
            params.block_of(target.index) as u32,
            params.offset_in_block(target.index) as u32,
        );
        let candidates_before = count_candidate_hints(
            &client,
            target_block,
            target_offset,
        );
        let got = client.query(&server, target.index).unwrap();
        let start = target.index as usize * entry_size;
        let expected = db[start..start + entry_size].to_vec();
        if got != expected {
            let mut fresh_client = OnlineClient::new(params.clone(), prf.clone(), 1);
            fresh_client.hints = offline.hints.clone();
            let fresh = fresh_client.query(&server, target.index).unwrap();
            let fresh_matches = fresh == expected;
            panic!(
                "sequential query mismatch at index {} (block {}, offset {}): candidates_before={}, fresh_matches_expected={}",
                target.index,
                target_block,
                target_offset,
                candidates_before,
                fresh_matches
            );
        }
        let tag = tag_for_key(&target.key);
        let tag_end = target.tag_offset + tag.0.len();
        assert_eq!(&got[target.tag_offset..tag_end], &tag.0);
    }
}

fn collect_candidate_indices(
    client: &OnlineClient,
    num_entries: u64,
    acc_count: u64,
    sto_count: u64,
) -> (HashSet<u64>, HashSet<u64>) {
    let mut account_candidates = HashSet::new();
    let mut storage_candidates = HashSet::new();
    let num_blocks = client.params.num_blocks as u32;
    let block_size = client.params.block_size;
    let storage_end = acc_count + sto_count;
    let target_per_kind = TARGETS_PER_KIND * CANDIDATE_MULTIPLIER;

    for &hint_id in &client.available_hints {
        let cutoff = client.hints.cutoffs[hint_id];
        if cutoff == 0 {
            continue;
        }
        let flipped = client.hints.flips[hint_id];
        let prf_id = client.hint_prf_ids[hint_id];

        for block in 0..num_blocks {
            let select = client.prf.select(prf_id, block);
            let offset = (client.prf.offset(prf_id, block) % block_size) as u32;
            let is_selected = if flipped { select >= cutoff } else { select < cutoff };
            if !is_selected {
                continue;
            }
            let idx = (block as u64) * block_size + (offset as u64);
            if idx >= num_entries {
                continue;
            }
            if idx < acc_count {
                account_candidates.insert(idx);
            } else if idx < storage_end {
                storage_candidates.insert(idx);
            }
            if account_candidates.len() >= target_per_kind
                && storage_candidates.len() >= target_per_kind
            {
                return (account_candidates, storage_candidates);
            }
        }
    }

    (account_candidates, storage_candidates)
}

fn extract_mapping_targets(
    map: &[u8],
    record_size: usize,
    key_size: usize,
    index_offset: usize,
    tag_offset: usize,
    candidates: &HashSet<u64>,
    limit: usize,
) -> Vec<MappingTarget> {
    let mut targets = Vec::new();
    if candidates.is_empty() {
        return targets;
    }

    for record in map.chunks(record_size) {
        if record.len() != record_size {
            break;
        }
        let index = u32::from_le_bytes([
            record[index_offset],
            record[index_offset + 1],
            record[index_offset + 2],
            record[index_offset + 3],
        ]) as u64;
        if !candidates.contains(&index) {
            continue;
        }
        let mut key = vec![0u8; key_size];
        key.copy_from_slice(&record[..key_size]);
        targets.push(MappingTarget {
            index,
            key,
            tag_offset,
        });
        if targets.len() >= limit {
            break;
        }
    }

    targets
}

fn count_candidate_hints(client: &OnlineClient, block: u32, offset: u32) -> usize {
    let mut count = 0;
    let block_size = client.params.block_size;
    for &hint_id in &client.available_hints {
        let cutoff = client.hints.cutoffs[hint_id];
        if cutoff == 0 {
            continue;
        }
        let prf_id = client.hint_prf_ids[hint_id];
        let select = client.prf.select(prf_id, block);
        let picked_offset = (client.prf.offset(prf_id, block) % block_size) as u32;
        let flipped = client.hints.flips[hint_id];
        let is_selected = if flipped { select >= cutoff } else { select < cutoff };
        let matches_selected = is_selected && picked_offset == offset;
        let matches_extra = client.hints.extra_blocks[hint_id] == block
            && client.hints.extra_offsets[hint_id] == offset;
        if matches_selected || matches_extra {
            count += 1;
        }
    }
    count
}

fn tag_for_key(key: &[u8]) -> Tag {
    match key.len() {
        ACCOUNT_KEY_SIZE => {
            let mut address = [0u8; ACCOUNT_KEY_SIZE];
            address.copy_from_slice(key);
            Tag::from_address(&address)
        }
        STORAGE_KEY_SIZE => {
            let mut address = [0u8; ACCOUNT_KEY_SIZE];
            let mut slot = [0u8; 32];
            address.copy_from_slice(&key[..ACCOUNT_KEY_SIZE]);
            slot.copy_from_slice(&key[ACCOUNT_KEY_SIZE..]);
            Tag::from_address_slot(&address, &slot)
        }
        _ => panic!("unexpected key size {}", key.len()),
    }
}

fn collect_targets(
    client: &OnlineClient,
    acc_map: &[u8],
    sto_map: &[u8],
    num_entries: u64,
    acc_count: u64,
    sto_count: u64,
    limit: usize,
) -> (Vec<MappingTarget>, Vec<MappingTarget>) {
    let (account_candidates, storage_candidates) =
        collect_candidate_indices(client, num_entries, acc_count, sto_count);
    let account_targets = extract_mapping_targets(
        acc_map,
        ACCOUNT_MAP_RECORD_SIZE,
        ACCOUNT_KEY_SIZE,
        ACCOUNT_KEY_SIZE,
        ACCOUNT_TAG_OFFSET,
        &account_candidates,
        limit,
    );
    let storage_targets = extract_mapping_targets(
        sto_map,
        STORAGE_MAP_RECORD_SIZE,
        STORAGE_KEY_SIZE,
        STORAGE_KEY_SIZE,
        STORAGE_TAG_OFFSET,
        &storage_candidates,
        limit,
    );
    (account_targets, storage_targets)
}
