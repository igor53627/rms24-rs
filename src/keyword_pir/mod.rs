use crate::schema40::{Tag, ENTRY_SIZE, TAG_SIZE};
use std::hash::Hash;

impl Hash for Tag {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[derive(Clone, Debug)]
pub struct MappingRecord {
    pub key: Vec<u8>,
    pub index: u64,
}

pub fn parse_mapping_record(record: &[u8], key_size: usize) -> Option<MappingRecord> {
    if record.len() < key_size + 4 {
        return None;
    }
    let mut key = vec![0u8; key_size];
    key.copy_from_slice(&record[..key_size]);
    let index = u32::from_le_bytes(record[key_size..key_size + 4].try_into().ok()?) as u64;
    Some(MappingRecord { key, index })
}

pub fn tag_for_key(key: &[u8]) -> Option<Tag> {
    match key.len() {
        20 => {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(key);
            Some(Tag::from_address(&addr))
        }
        52 => {
            let mut addr = [0u8; 20];
            let mut slot = [0u8; 32];
            addr.copy_from_slice(&key[..20]);
            slot.copy_from_slice(&key[20..]);
            Some(Tag::from_address_slot(&addr, &slot))
        }
        _ => None,
    }
}

pub fn tag_from_entry(key_len: usize, entry: &[u8; ENTRY_SIZE]) -> Option<Tag> {
    match key_len {
        20 => {
            let mut tag = [0u8; TAG_SIZE];
            tag.copy_from_slice(&entry[24..32]);
            Some(Tag(tag))
        }
        52 => {
            let mut tag = [0u8; TAG_SIZE];
            tag.copy_from_slice(&entry[32..40]);
            Some(Tag(tag))
        }
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct CuckooConfig {
    pub num_buckets: usize,
    pub bucket_size: usize,
    pub num_hashes: usize,
    pub max_kicks: usize,
    pub seed: u64,
}

impl CuckooConfig {
    pub fn new(
        num_buckets: usize,
        bucket_size: usize,
        num_hashes: usize,
        max_kicks: usize,
        seed: u64,
    ) -> Self {
        Self {
            num_buckets,
            bucket_size,
            num_hashes,
            max_kicks,
            seed,
        }
    }
}

pub fn cuckoo_positions(key: &[u8], cfg: &CuckooConfig) -> Vec<usize> {
    (0..cfg.num_hashes)
        .map(|i| hash_with_seed(key, cfg.seed.wrapping_add(i as u64)) % cfg.num_buckets)
        .collect()
}

fn hash_with_seed(key: &[u8], seed: u64) -> usize {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(key);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes) as usize
}

fn hash_key(key: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

#[derive(Clone, Debug)]
pub struct CuckooSlot {
    pub key_hash: [u8; 32],
    pub value: [u8; 40],
}

#[derive(Clone, Debug)]
pub struct CuckooTable {
    cfg: CuckooConfig,
    slots: Vec<Option<CuckooSlot>>,
}

impl CuckooTable {
    pub fn new(cfg: CuckooConfig) -> Self {
        let total = cfg.num_buckets * cfg.bucket_size;
        Self {
            cfg,
            slots: vec![None; total],
        }
    }

    pub fn insert(&mut self, key: &[u8], value: [u8; 40]) -> Result<(), String> {
        let key_hash = hash_key(key);
        let slot = CuckooSlot { key_hash, value };
        let positions = cuckoo_positions(&key_hash, &self.cfg);
        for &bucket in &positions {
            for i in 0..self.cfg.bucket_size {
                let idx = bucket * self.cfg.bucket_size + i;
                if self.slots[idx].is_none() {
                    self.slots[idx] = Some(slot);
                    return Ok(());
                }
            }
        }
        let mut cur_slot = slot;
        let mut cur_bucket = positions[0];
        for kick in 0..self.cfg.max_kicks {
            let idx = cur_bucket * self.cfg.bucket_size + (kick % self.cfg.bucket_size);
            let evicted = self.slots[idx].replace(cur_slot);
            let evicted = match evicted {
                Some(evicted) => evicted,
                None => return Ok(()),
            };
            cur_slot = evicted;
            let evicted_positions = cuckoo_positions(&cur_slot.key_hash, &self.cfg);
            cur_bucket = evicted_positions[0];
            for i in 0..self.cfg.bucket_size {
                let cand = cur_bucket * self.cfg.bucket_size + i;
                if self.slots[cand].is_none() {
                    self.slots[cand] = Some(cur_slot);
                    return Ok(());
                }
            }
        }
        Err("cuckoo insertion failed".into())
    }

    pub fn find_candidate(&self, key: &[u8]) -> Option<[u8; 40]> {
        let key_hash = hash_key(key);
        let positions = cuckoo_positions(&key_hash, &self.cfg);
        for &bucket in &positions {
            for i in 0..self.cfg.bucket_size {
                let idx = bucket * self.cfg.bucket_size + i;
                if let Some(slot) = &self.slots[idx] {
                    if slot.key_hash == key_hash {
                        return Some(slot.value);
                    }
                }
            }
        }
        None
    }

    pub fn to_entry_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.slots.len() * ENTRY_SIZE];
        for (idx, slot) in self.slots.iter().enumerate() {
            if let Some(slot) = slot {
                let offset = idx * ENTRY_SIZE;
                out[offset..offset + ENTRY_SIZE].copy_from_slice(&slot.value);
            }
        }
        out
    }

    pub fn to_collision_bytes(&self) -> Vec<u8> {
        const COLLISION_ENTRY_SIZE: usize = 72;
        let mut out = vec![0u8; self.slots.len() * COLLISION_ENTRY_SIZE];
        for (idx, slot) in self.slots.iter().enumerate() {
            if let Some(slot) = slot {
                let offset = idx * COLLISION_ENTRY_SIZE;
                out[offset..offset + 32].copy_from_slice(&slot.key_hash);
                out[offset + 32..offset + COLLISION_ENTRY_SIZE].copy_from_slice(&slot.value);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mapping_record_account() {
        let mut record = vec![0u8; 24];
        record[..20].copy_from_slice(&[0x11u8; 20]);
        record[20..24].copy_from_slice(&42u32.to_le_bytes());
        let parsed = parse_mapping_record(&record, 20).unwrap();
        assert_eq!(parsed.index, 42);
        assert_eq!(parsed.key.len(), 20);
    }

    #[test]
    fn test_parse_mapping_record_storage() {
        let mut record = vec![0u8; 56];
        record[..52].copy_from_slice(&[0x22u8; 52]);
        record[52..56].copy_from_slice(&7u32.to_le_bytes());
        let parsed = parse_mapping_record(&record, 52).unwrap();
        assert_eq!(parsed.index, 7);
        assert_eq!(parsed.key.len(), 52);
    }

    #[test]
    fn test_tag_for_key_account_vs_storage() {
        let account_key = [0xABu8; 20];
        let storage_key = [0xCDu8; 52];
        let account_tag = tag_for_key(&account_key).unwrap();
        let storage_tag = tag_for_key(&storage_key).unwrap();
        assert_ne!(account_tag.0, storage_tag.0);
    }

    #[test]
    fn test_cuckoo_positions_deterministic() {
        let key = vec![0x55u8; 20];
        let cfg = CuckooConfig::new(16, 2, 2, 32, 123);
        let a = cuckoo_positions(&key, &cfg);
        let b = cuckoo_positions(&key, &cfg);
        assert_eq!(a, b);
    }

    #[test]
    fn test_cuckoo_insert_and_lookup() {
        let cfg = CuckooConfig::new(8, 2, 2, 32, 7);
        let mut table = CuckooTable::new(cfg);
        let key = vec![0x11u8; 20];
        let value = [0xAAu8; 40];
        table.insert(&key, value).unwrap();
        let got = table.find_candidate(&key).unwrap();
        assert_eq!(got, value);
    }
}
