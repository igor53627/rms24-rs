use sha3::{Digest, Keccak256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag(pub [u8; 8]);

impl Tag {
    pub fn from_key(key: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(key);
        let digest = hasher.finalize();
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&digest[..8]);
        Tag(tag)
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
    fn test_tag_keccak() {
        let key = [0x11u8; 20];
        let tag = Tag::from_key(&key);
        let mut hasher = Keccak256::new();
        hasher.update(&key);
        let digest = hasher.finalize();
        let mut expected = [0u8; 8];
        expected.copy_from_slice(&digest[..8]);
        assert_eq!(tag.0, expected);
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
