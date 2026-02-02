use crate::schema40::Tag;

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
}
