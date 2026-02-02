use crate::messages::{Query, Reply};
use crate::schema40::{Tag, ENTRY_SIZE, TAG_SIZE};
use crate::OnlineClient;
use std::collections::HashSet;
use std::hash::Hash;

// schema40 layout: account tag after balance(16) + nonce(4) + code_id(4)
const ACCOUNT_TAG_OFFSET: usize = 24;
// schema40 layout: storage tag after value(32)
const STORAGE_TAG_OFFSET: usize = 32;

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
            tag.copy_from_slice(&entry[ACCOUNT_TAG_OFFSET..ACCOUNT_TAG_OFFSET + TAG_SIZE]);
            Some(Tag(tag))
        }
        52 => {
            let mut tag = [0u8; TAG_SIZE];
            tag.copy_from_slice(&entry[STORAGE_TAG_OFFSET..STORAGE_TAG_OFFSET + TAG_SIZE]);
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
            let start = kick % evicted_positions.len();
            for offset in 0..evicted_positions.len() {
                let bucket = evicted_positions[(start + offset) % evicted_positions.len()];
                for i in 0..self.cfg.bucket_size {
                    let cand = bucket * self.cfg.bucket_size + i;
                    if self.slots[cand].is_none() {
                        self.slots[cand] = Some(cur_slot);
                        return Ok(());
                    }
                }
            }
            cur_bucket = evicted_positions[start];
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

const COLLISION_ENTRY_SIZE: usize = 72;

#[derive(Clone, Debug)]
pub struct KeywordPirParams {
    pub cfg: CuckooConfig,
    pub entry_size: usize,
}

pub struct KeywordPirClient {
    params: KeywordPirParams,
    collision_tags: HashSet<Tag>,
    collision_table: Option<Vec<u8>>,
}

impl KeywordPirClient {
    pub fn new(params: KeywordPirParams) -> Self {
        Self {
            params,
            collision_tags: HashSet::new(),
            collision_table: None,
        }
    }

    pub fn set_collision_tags(&mut self, tags: Vec<Tag>) {
        self.collision_tags = tags.into_iter().collect();
    }

    pub fn set_collision_table(&mut self, table: Vec<u8>) {
        self.collision_table = Some(table);
    }

    pub fn positions_for_key(&self, key: &[u8]) -> Vec<usize> {
        let key_hash = hash_key(key);
        let buckets = cuckoo_positions(&key_hash, &self.params.cfg);
        let mut positions = Vec::with_capacity(buckets.len() * self.params.cfg.bucket_size);
        for bucket in buckets {
            for i in 0..self.params.cfg.bucket_size {
                positions.push(bucket * self.params.cfg.bucket_size + i);
            }
        }
        positions
    }

    pub fn query_local(&self, key: &[u8], table: &CuckooTable) -> Result<[u8; 40], String> {
        self.ensure_entry_size()?;
        let expected_tag = self.expected_tag(key)?;
        if self.collision_tags.contains(&expected_tag) {
            let collision_table = self
                .collision_table
                .as_ref()
                .ok_or_else(|| "collision table missing".to_string())?;
            return self.query_collision(key, collision_table);
        }

        let key_hash = hash_key(key);
        let positions = self.positions_for_key(key);
        for pos in positions.iter().copied() {
            if let Some(slot) = table.slots.get(pos).and_then(|slot| slot.as_ref()) {
                if slot.key_hash == key_hash {
                    if self.entry_tag_matches(key, &slot.value)? {
                        return Ok(slot.value);
                    }
                }
            }
        }

        for pos in positions {
            if let Some(slot) = table.slots.get(pos).and_then(|slot| slot.as_ref()) {
                if self.entry_tag_matches(key, &slot.value)? {
                    return Ok(slot.value);
                }
            }
        }

        Err("no matching entry found".into())
    }

    pub fn query_network(
        &mut self,
        key: &[u8],
        online: &mut OnlineClient,
        mut sender: impl FnMut(Query) -> Reply,
    ) -> Result<[u8; 40], String> {
        self.ensure_entry_size()?;
        if online.params.entry_size != self.params.entry_size {
            return Err("online entry size mismatch".into());
        }
        let expected_tag = self.expected_tag(key)?;
        if self.collision_tags.contains(&expected_tag) {
            let collision_table = self
                .collision_table
                .as_ref()
                .ok_or_else(|| "collision table missing".to_string())?;
            return self.query_collision(key, collision_table);
        }

        let positions = self.positions_for_key(key);
        for pos in positions {
            let (real_query, dummy_query, real_hint) =
                online.build_network_queries(pos as u64).map_err(|e| e.to_string())?;
            let real_reply = sender(Query {
                id: real_query.id,
                subset: real_query.subset,
            });
            let _ = sender(Query {
                id: dummy_query.id,
                subset: dummy_query.subset,
            });

            let entry = online
                .consume_network_reply(pos as u64, real_hint, real_reply.parity)
                .map_err(|e| e.to_string())?;
            let entry: [u8; ENTRY_SIZE] =
                entry.try_into().map_err(|_| "entry size mismatch".to_string())?;

            if self.entry_tag_matches(key, &entry)? {
                return Ok(entry);
            }
        }

        Err("no matching entry found".into())
    }

    fn query_collision(&self, key: &[u8], collision_table: &[u8]) -> Result<[u8; 40], String> {
        self.ensure_entry_size()?;
        if collision_table.len() % COLLISION_ENTRY_SIZE != 0 {
            return Err("collision table size mismatch".into());
        }
        if self.params.cfg.bucket_size == 0 {
            return Err("bucket_size must be >0".into());
        }
        let slots = collision_table.len() / COLLISION_ENTRY_SIZE;
        if slots % self.params.cfg.bucket_size != 0 {
            return Err("collision table bucket alignment mismatch".into());
        }
        let num_buckets = slots / self.params.cfg.bucket_size;
        if num_buckets == 0 {
            return Err("collision num_buckets must be >0".into());
        }
        let collision_cfg = CuckooConfig::new(
            num_buckets,
            self.params.cfg.bucket_size,
            self.params.cfg.num_hashes,
            self.params.cfg.max_kicks,
            self.params.cfg.seed,
        );
        let key_hash = hash_key(key);
        let buckets = cuckoo_positions(&key_hash, &collision_cfg);
        for bucket in buckets {
            for i in 0..self.params.cfg.bucket_size {
                let idx = bucket * self.params.cfg.bucket_size + i;
                if idx >= slots {
                    continue;
                }
                let offset = idx * COLLISION_ENTRY_SIZE;
                let slot_hash: [u8; 32] = collision_table[offset..offset + 32]
                    .try_into()
                    .map_err(|_| "collision entry truncated".to_string())?;
                if slot_hash == key_hash {
                    let mut entry = [0u8; ENTRY_SIZE];
                    entry.copy_from_slice(
                        &collision_table[offset + 32..offset + COLLISION_ENTRY_SIZE],
                    );
                    return Ok(entry);
                }
            }
        }
        Err("collision entry not found".into())
    }

    fn expected_tag(&self, key: &[u8]) -> Result<Tag, String> {
        tag_for_key(key).ok_or_else(|| "invalid key length for tag".to_string())
    }

    fn entry_tag_matches(&self, key: &[u8], entry: &[u8; ENTRY_SIZE]) -> Result<bool, String> {
        let expected = self.expected_tag(key)?;
        let actual = tag_from_entry(key.len(), entry)
            .ok_or_else(|| "invalid key length for entry tag".to_string())?;
        Ok(expected == actual)
    }

    fn ensure_entry_size(&self) -> Result<(), String> {
        if self.params.entry_size != ENTRY_SIZE {
            return Err("entry_size mismatch".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_with_tag_for_key(key: &[u8]) -> [u8; ENTRY_SIZE] {
        let mut entry = [0u8; ENTRY_SIZE];
        let tag = tag_for_key(key).expect("valid key length");
        match key.len() {
            20 => entry[ACCOUNT_TAG_OFFSET..ACCOUNT_TAG_OFFSET + TAG_SIZE].copy_from_slice(tag.as_bytes()),
            52 => entry[STORAGE_TAG_OFFSET..STORAGE_TAG_OFFSET + TAG_SIZE].copy_from_slice(tag.as_bytes()),
            _ => panic!("unsupported key length"),
        }
        entry
    }

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

    #[test]
    fn test_keywordpir_query_returns_matching_tag() {
        let cfg = CuckooConfig::new(8, 2, 2, 32, 1);
        let key = vec![0x11u8; 20];
        let entry = entry_with_tag_for_key(&key);
        let mut table = CuckooTable::new(cfg.clone());
        table.insert(&key, entry).unwrap();
        let params = KeywordPirParams { cfg, entry_size: 40 };
        let client = KeywordPirClient::new(params);
        let got = client.query_local(&key, &table).unwrap();
        assert_eq!(got, entry);
    }

    #[test]
    fn test_keywordpir_query_requires_tag_match() {
        let cfg = CuckooConfig::new(8, 2, 2, 32, 1);
        let key = vec![0x11u8; 20];
        let mut entry = entry_with_tag_for_key(&key);
        entry[24] ^= 0xFF;
        let mut table = CuckooTable::new(cfg.clone());
        table.insert(&key, entry).unwrap();
        let params = KeywordPirParams { cfg, entry_size: 40 };
        let client = KeywordPirClient::new(params);
        assert!(client.query_local(&key, &table).is_err());
    }

    #[test]
    fn test_keywordpir_query_uses_collision_table() {
        let cfg = CuckooConfig::new(8, 2, 2, 32, 1);
        let collision_cfg = CuckooConfig::new(4, 2, 2, 32, 1);
        let key = vec![0x11u8; 20];
        let entry = entry_with_tag_for_key(&key);
        let mut collision_table = CuckooTable::new(collision_cfg);
        collision_table.insert(&key, entry).unwrap();

        let mut client = KeywordPirClient::new(KeywordPirParams { cfg: cfg.clone(), entry_size: 40 });
        let tag = tag_for_key(&key).unwrap();
        client.set_collision_tags(vec![tag]);
        client.set_collision_table(collision_table.to_collision_bytes());

        let table = CuckooTable::new(cfg);
        let got = client.query_local(&key, &table).unwrap();
        assert_eq!(got, entry);
    }

    #[test]
    fn test_keywordpir_query_collision_empty_table_errors() {
        let cfg = CuckooConfig::new(8, 2, 2, 32, 1);
        let key = vec![0x11u8; 20];
        let mut client = KeywordPirClient::new(KeywordPirParams { cfg: cfg.clone(), entry_size: 40 });
        let tag = tag_for_key(&key).unwrap();
        client.set_collision_tags(vec![tag]);
        client.set_collision_table(Vec::new());

        let table = CuckooTable::new(cfg);
        assert!(client.query_local(&key, &table).is_err());
    }
}
