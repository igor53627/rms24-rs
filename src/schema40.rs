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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tag(pub [u8; TAG_SIZE]);

impl Tag {
    pub fn from_address(address: &[u8; 20]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(address);
        let digest = hasher.finalize();
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&digest[..TAG_SIZE]);
        Tag(tag)
    }

    pub fn from_address_slot(address: &[u8; 20], slot_key: &[u8; 32]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(address);
        hasher.update(slot_key);
        let digest = hasher.finalize();
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&digest[..TAG_SIZE]);
        Tag(tag)
    }

    pub fn as_bytes(&self) -> &[u8; TAG_SIZE] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CodeId(pub u32);

impl CodeId {
    pub fn new(id: u32) -> Self {
        CodeId(id)
    }

    pub fn is_eoa(&self) -> bool {
        self.0 == CODE_ID_NONE
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn to_le_bytes(&self) -> [u8; CODE_ID_SIZE] {
        self.0.to_le_bytes()
    }

    pub fn from_le_bytes(bytes: [u8; CODE_ID_SIZE]) -> Self {
        CodeId(u32::from_le_bytes(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountEntry40 {
    pub value: [u8; 32],
    pub tag: Tag,
}

impl AccountEntry40 {
    pub fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.value);
        out[32..].copy_from_slice(&self.tag.0);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 40 {
            return None;
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes[..32]);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&bytes[32..]);
        Some(Self { value, tag: Tag(tag) })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageEntry40 {
    pub value: [u8; 32],
    pub tag: Tag,
}

impl StorageEntry40 {
    pub fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.value);
        out[32..].copy_from_slice(&self.tag.0);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 40 {
            return None;
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes[..32]);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&bytes[32..]);
        Some(Self { value, tag: Tag(tag) })
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
    fn test_account_entry_encode_decode() {
        let value = [0xAAu8; 32];
        let tag = Tag([0xBBu8; 8]);
        let entry = AccountEntry40 { value, tag };
        let bytes = entry.encode();
        assert_eq!(bytes.len(), 40);
        let decoded = AccountEntry40::decode(&bytes).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.tag.0, tag.0);
    }

    #[test]
    fn test_storage_entry_encode_decode() {
        let value = [0xCCu8; 32];
        let tag = Tag([0xDDu8; 8]);
        let entry = StorageEntry40 { value, tag };
        let bytes = entry.encode();
        assert_eq!(bytes.len(), 40);
        let decoded = StorageEntry40::decode(&bytes).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.tag.0, tag.0);
    }
}
