use sha3::{Digest, Keccak256};

pub const ENTRY_SIZE: usize = 40;
pub const BALANCE_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 4;
pub const CODE_ID_SIZE: usize = 4;
pub const TAG_SIZE: usize = 8;
pub const ACCOUNT_PADDING_SIZE: usize = 8;
pub const STORAGE_VALUE_SIZE: usize = 32;
pub const STORAGE_PADDING_SIZE: usize = 0;
pub const CODE_ID_NONE: u32 = 0;

/// 8-byte fingerprint derived from an Ethereum address (or address+slot).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tag(pub [u8; TAG_SIZE]);

impl Tag {
    /// Compute tag from a 20-byte Ethereum address using Keccak256.
    pub fn from_address(address: &[u8; 20]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(address);
        let digest = hasher.finalize();
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&digest[..TAG_SIZE]);
        Tag(tag)
    }

    /// Compute tag from an address and 32-byte storage slot key.
    pub fn from_address_slot(address: &[u8; 20], slot_key: &[u8; 32]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(address);
        hasher.update(slot_key);
        let digest = hasher.finalize();
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&digest[..TAG_SIZE]);
        Tag(tag)
    }

    /// Return the tag bytes.
    pub fn as_bytes(&self) -> &[u8; TAG_SIZE] {
        &self.0
    }
}

/// Compact identifier for a contract's bytecode hash (0 = EOA).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CodeId(pub u32);

impl CodeId {
    /// Wrap a raw u32 into a [`CodeId`].
    pub fn new(id: u32) -> Self {
        CodeId(id)
    }

    /// Returns true if this is the EOA sentinel (no code).
    pub fn is_eoa(&self) -> bool {
        self.0 == CODE_ID_NONE
    }

    /// Return the raw u32 value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Serialize to little-endian bytes.
    pub fn to_le_bytes(&self) -> [u8; CODE_ID_SIZE] {
        self.0.to_le_bytes()
    }

    /// Deserialize from little-endian bytes.
    pub fn from_le_bytes(bytes: [u8; CODE_ID_SIZE]) -> Self {
        CodeId(u32::from_le_bytes(bytes))
    }
}

/// 40-byte account entry: balance(16) + nonce(4) + code_id(4) + tag(8) + padding(8).
#[derive(Clone, Copy, Debug)]
pub struct AccountEntry40 {
    pub balance: [u8; BALANCE_SIZE],
    pub nonce: u32,
    pub code_id: CodeId,
    pub tag: Tag,
    pub _padding: [u8; ACCOUNT_PADDING_SIZE],
}

impl AccountEntry40 {
    /// Create an account entry, truncating balance to 16 bytes and nonce to u32.
    pub fn new(balance_256: &[u8; 32], nonce: u64, code_id: CodeId, address: &[u8; 20]) -> Self {
        let mut balance = [0u8; BALANCE_SIZE];
        balance.copy_from_slice(&balance_256[..BALANCE_SIZE]);
        let nonce_u32 = if nonce > u32::MAX as u64 {
            u32::MAX
        } else {
            nonce as u32
        };
        Self {
            balance,
            nonce: nonce_u32,
            code_id,
            tag: Tag::from_address(address),
            _padding: [0u8; ACCOUNT_PADDING_SIZE],
        }
    }

    /// Serialize to a 40-byte array.
    pub fn to_bytes(&self) -> [u8; ENTRY_SIZE] {
        let mut bytes = [0u8; ENTRY_SIZE];
        bytes[0..16].copy_from_slice(&self.balance);
        bytes[16..20].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.code_id.to_le_bytes());
        bytes[24..32].copy_from_slice(self.tag.as_bytes());
        bytes
    }

    /// Deserialize from a 40-byte array.
    pub fn from_bytes(bytes: &[u8; ENTRY_SIZE]) -> Self {
        let mut balance = [0u8; BALANCE_SIZE];
        balance.copy_from_slice(&bytes[0..16]);
        let nonce = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let mut code_id_bytes = [0u8; CODE_ID_SIZE];
        code_id_bytes.copy_from_slice(&bytes[20..24]);
        let code_id = CodeId::from_le_bytes(code_id_bytes);
        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(&bytes[24..32]);
        let tag = Tag(tag_bytes);
        Self {
            balance,
            nonce,
            code_id,
            tag,
            _padding: [0u8; ACCOUNT_PADDING_SIZE],
        }
    }

    /// Return the nonce as u64.
    pub fn nonce_u64(&self) -> u64 {
        self.nonce as u64
    }
}

/// 40-byte storage entry: value(32) + tag(8).
#[derive(Clone, Copy, Debug, Default)]
pub struct StorageEntry40 {
    pub value: [u8; STORAGE_VALUE_SIZE],
    pub tag: Tag,
}

impl StorageEntry40 {
    /// Create a storage entry from a 32-byte value, address, and slot key.
    pub fn new(value: &[u8; 32], address: &[u8; 20], slot_key: &[u8; 32]) -> Self {
        Self {
            value: *value,
            tag: Tag::from_address_slot(address, slot_key),
        }
    }

    /// Serialize to a 40-byte array.
    pub fn to_bytes(&self) -> [u8; ENTRY_SIZE] {
        let mut bytes = [0u8; ENTRY_SIZE];
        bytes[0..32].copy_from_slice(&self.value);
        bytes[32..40].copy_from_slice(self.tag.as_bytes());
        bytes
    }

    /// Deserialize from a 40-byte array.
    pub fn from_bytes(bytes: &[u8; ENTRY_SIZE]) -> Self {
        let mut value = [0u8; STORAGE_VALUE_SIZE];
        value.copy_from_slice(&bytes[0..32]);
        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(&bytes[32..40]);
        Self {
            value,
            tag: Tag(tag_bytes),
        }
    }
}

/// Bidirectional mapping between bytecode hashes and compact [`CodeId`]s.
#[derive(Debug, Default)]
pub struct CodeStore {
    hashes: Vec<[u8; 32]>,
    hash_to_id: std::collections::HashMap<[u8; 32], CodeId>,
}

impl CodeStore {
    /// Create an empty code store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the [`CodeId`] for a bytecode hash, inserting if new. `None` or zero hash returns EOA.
    pub fn get_or_insert(&mut self, hash: Option<&[u8; 32]>) -> CodeId {
        let hash = match hash {
            Some(h) if *h != [0u8; 32] => h,
            _ => return CodeId(CODE_ID_NONE),
        };
        if let Some(&id) = self.hash_to_id.get(hash) {
            return id;
        }
        let next_len = self.hashes.len() + 1;
        if next_len >= u32::MAX as usize {
            panic!("CodeStore exhausted: reached maximum of 4B unique bytecodes");
        }
        let id = CodeId(next_len as u32);
        self.hashes.push(*hash);
        self.hash_to_id.insert(*hash, id);
        id
    }

    /// Look up the bytecode hash for a [`CodeId`]. Returns `None` for EOA.
    pub fn get(&self, id: CodeId) -> Option<&[u8; 32]> {
        if id.is_eoa() {
            return None;
        }
        self.hashes.get((id.0 - 1) as usize)
    }

    /// Return the number of stored bytecode hashes.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Returns true if no bytecode hashes are stored.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Serialize the code store to bytes (4-byte count + 32-byte hashes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.hashes.len() * 32);
        bytes.extend_from_slice(&(self.hashes.len() as u32).to_le_bytes());
        for hash in &self.hashes {
            bytes.extend_from_slice(hash);
        }
        bytes
    }

    /// Deserialize a code store from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("Code store too short".to_string());
        }
        let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let expected = 4 + count * 32;
        if bytes.len() != expected {
            return Err(format!(
                "Code store size mismatch: expected {}, got {}",
                expected,
                bytes.len()
            ));
        }
        let mut store = Self::new();
        for i in 0..count {
            let offset = 4 + i * 32;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[offset..offset + 32]);
            store.hashes.push(hash);
            store
                .hash_to_id
                .insert(hash, CodeId((i + 1) as u32));
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_sizes() {
        assert_eq!(ENTRY_SIZE, 40);
        assert_eq!(
            BALANCE_SIZE + NONCE_SIZE + CODE_ID_SIZE + TAG_SIZE + ACCOUNT_PADDING_SIZE,
            ENTRY_SIZE
        );
        assert_eq!(STORAGE_VALUE_SIZE + TAG_SIZE + STORAGE_PADDING_SIZE, ENTRY_SIZE);
    }

    #[test]
    fn test_tag_deterministic() {
        let address = [0x12u8; 20];
        let tag1 = Tag::from_address(&address);
        let tag2 = Tag::from_address(&address);
        assert_eq!(tag1, tag2);

        let slot = [0x34u8; 32];
        let tag3 = Tag::from_address_slot(&address, &slot);
        let tag4 = Tag::from_address_slot(&address, &slot);
        assert_eq!(tag3, tag4);

        let other_address = [0x56u8; 20];
        let tag5 = Tag::from_address(&other_address);
        assert_ne!(tag1, tag5);
    }

    #[test]
    fn test_code_id_roundtrip() {
        let id = CodeId::new(42);
        assert_eq!(CodeId::from_le_bytes(id.to_le_bytes()), id);
        assert!(!id.is_eoa());
        assert!(CodeId::new(CODE_ID_NONE).is_eoa());
    }

    #[test]
    fn test_account_entry_roundtrip() {
        let balance = [0x42u8; 32];
        let nonce = 12345u64;
        let address = [0xABu8; 20];
        let code_id = CodeId::new(999);

        let entry = AccountEntry40::new(&balance, nonce, code_id, &address);
        let bytes = entry.to_bytes();
        let recovered = AccountEntry40::from_bytes(&bytes);

        assert_eq!(entry.balance, recovered.balance);
        assert_eq!(entry.nonce, recovered.nonce);
        assert_eq!(entry.code_id, recovered.code_id);
        assert_eq!(entry.tag, recovered.tag);
    }

    #[test]
    fn test_balance_truncation() {
        let balance_large = [0xFFu8; 32];
        let entry = AccountEntry40::new(&balance_large, 0, CodeId(0), &[0u8; 20]);
        assert_eq!(&entry.balance[..], &[0xFFu8; 16]);
    }

    #[test]
    fn test_nonce_truncation() {
        let address = [0u8; 20];
        let balance = [0u8; 32];
        let entry = AccountEntry40::new(&balance, u64::MAX, CodeId(0), &address);
        assert_eq!(entry.nonce, u32::MAX);
    }

    #[test]
    fn test_storage_entry_roundtrip() {
        let value = [0x77u8; 32];
        let address = [0xABu8; 20];
        let slot_key = [0xCDu8; 32];

        let entry = StorageEntry40::new(&value, &address, &slot_key);
        let bytes = entry.to_bytes();
        let recovered = StorageEntry40::from_bytes(&bytes);

        assert_eq!(entry.value, recovered.value);
        assert_eq!(entry.tag, recovered.tag);
    }

    #[test]
    fn test_storage_no_padding() {
        let entry = StorageEntry40::default();
        let bytes = entry.to_bytes();
        assert_eq!(&bytes[0..32], &[0u8; 32]);
        assert_eq!(&bytes[32..40], &[0u8; 8]);
    }

    #[test]
    fn test_code_store_basic() {
        let mut store = CodeStore::new();
        assert_eq!(store.get_or_insert(None), CodeId(0));
        assert_eq!(store.get_or_insert(Some(&[0u8; 32])), CodeId(0));

        let hash1 = [0x11u8; 32];
        let id1 = store.get_or_insert(Some(&hash1));
        assert_eq!(id1, CodeId(1));
        assert_eq!(store.get(CodeId(1)), Some(&hash1));

        let hash2 = [0x22u8; 32];
        let id2 = store.get_or_insert(Some(&hash2));
        assert_eq!(id2, CodeId(2));
        assert_eq!(store.get(CodeId(2)), Some(&hash2));

        assert_eq!(store.get(CodeId(0)), None);
        assert_eq!(store.get(CodeId(999)), None);
    }

    #[test]
    fn test_code_store_serialization() {
        let mut store = CodeStore::new();
        store.get_or_insert(Some(&[0x11u8; 32]));
        store.get_or_insert(Some(&[0x22u8; 32]));

        let bytes = store.to_bytes();
        let recovered = CodeStore::from_bytes(&bytes).unwrap();

        assert_eq!(store.len(), recovered.len());
        assert_eq!(store.get(CodeId(1)), recovered.get(CodeId(1)));
        assert_eq!(store.get(CodeId(2)), recovered.get(CodeId(2)));
    }
}
