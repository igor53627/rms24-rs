use clap::Parser;
use memmap2::Mmap;
use rms24::keyword_pir::{
    parse_mapping_record, tag_for_key, tag_from_entry, CuckooConfig, CuckooTable,
};
use rms24::schema40::{Tag, ENTRY_SIZE, TAG_SIZE};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

const COLLISION_ENTRY_SIZE: usize = 72;
const BUCKET_SLACK: f64 = 1.15;
const MAX_BUILD_ATTEMPTS: usize = 5;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    db: String,
    #[arg(long)]
    account_mapping: String,
    #[arg(long)]
    storage_mapping: String,
    #[arg(long)]
    out: String,
    #[arg(long, default_value = "2")]
    bucket_size: usize,
    #[arg(long, default_value = "2")]
    num_hashes: usize,
    #[arg(long, default_value = "32")]
    max_kicks: usize,
    #[arg(long, default_value = "1")]
    seed: u64,
}

struct EntryRecord {
    key: Vec<u8>,
    #[allow(dead_code)]
    index: u64,
    entry: [u8; ENTRY_SIZE],
    tag: Tag,
}

fn buckets_for_entries(count: usize, bucket_size: usize) -> usize {
    (count + bucket_size - 1) / bucket_size
}

fn build_cuckoo_with_retries(
    entries: &[EntryRecord],
    base_cfg: &CuckooConfig,
    slack: f64,
    max_attempts: usize,
    bump_seed: bool,
) -> Result<(CuckooTable, CuckooConfig), String> {
    if entries.is_empty() {
        return Err("no entries".into());
    }
    if slack <= 1.0 {
        return Err("slack must be >1".into());
    }
    if max_attempts == 0 {
        return Err("max_attempts must be >0".into());
    }
    let base_buckets = base_cfg.num_buckets;
    for attempt in 0..max_attempts {
        let factor = slack.powi(attempt as i32);
        let num_buckets = ((base_buckets as f64) * factor).ceil() as usize;
        let seed = if bump_seed {
            base_cfg.seed + attempt as u64
        } else {
            base_cfg.seed
        };
        let cfg = CuckooConfig::new(
            num_buckets,
            base_cfg.bucket_size,
            base_cfg.num_hashes,
            base_cfg.max_kicks,
            seed,
        );
        let mut table = CuckooTable::new(cfg.clone());
        let mut ok = true;
        for record in entries {
            if table.insert(&record.key, record.entry).is_err() {
                ok = false;
                break;
            }
        }
        if ok {
            return Ok((table, cfg));
        }
    }
    Err(format!("cuckoo build failed after {max_attempts} attempts"))
}

fn read_mapping_entries(
    path: &str,
    key_size: usize,
    db: &[u8],
) -> Result<Vec<EntryRecord>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len() as usize;
    let record_size = key_size + 4;
    if record_size == 0 || len % record_size != 0 {
        return Err(format!("mapping file {path} has invalid length").into());
    }
    let count = len / record_size;
    let num_entries = db.len() / ENTRY_SIZE;

    let mut reader = BufReader::new(file);
    let mut buf = vec![0u8; record_size];
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        reader.read_exact(&mut buf)?;
        let record = parse_mapping_record(&buf, key_size)
            .ok_or("mapping record shorter than expected")?;
        let index = record.index as usize;
        if index >= num_entries {
            return Err(format!("mapping index {index} out of range").into());
        }
        let offset = index * ENTRY_SIZE;
        let mut entry = [0u8; ENTRY_SIZE];
        entry.copy_from_slice(&db[offset..offset + ENTRY_SIZE]);

        let tag = tag_for_key(&record.key).ok_or("invalid key length for tag")?;
        let entry_tag = tag_from_entry(record.key.len(), &entry)
            .ok_or("invalid key length for entry tag")?;
        if tag != entry_tag {
            return Err(format!("tag mismatch for mapping index {index}").into());
        }

        out.push(EntryRecord {
            key: record.key,
            index: record.index,
            entry,
            tag,
        });
    }

    Ok(out)
}

fn write_metadata(
    out_dir: &Path,
    entry_size: usize,
    num_entries: usize,
    bucket_size: usize,
    num_buckets: usize,
    num_hashes: usize,
    max_kicks: usize,
    seed: u64,
    collision_entry_size: usize,
    collision_count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Serialize)]
    struct Metadata {
        entry_size: usize,
        num_entries: usize,
        bucket_size: usize,
        num_buckets: usize,
        num_hashes: usize,
        max_kicks: usize,
        seed: u64,
        collision_entry_size: usize,
        collision_count: usize,
    }

    let metadata = Metadata {
        entry_size,
        num_entries,
        bucket_size,
        num_buckets,
        num_hashes,
        max_kicks,
        seed,
        collision_entry_size,
        collision_count,
    };
    let json = serde_json::to_string_pretty(&metadata)?;
    fs::write(out_dir.join("keywordpir-metadata.json"), json)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.bucket_size == 0 {
        return Err("bucket_size must be >0".into());
    }
    if args.num_hashes == 0 {
        return Err("num_hashes must be >0".into());
    }

    let db_file = File::open(&args.db)?;
    let db = unsafe { Mmap::map(&db_file)? };
    if db.is_empty() {
        return Err("db must contain at least one entry".into());
    }
    if db.len() % ENTRY_SIZE != 0 {
        return Err("db length must be multiple of entry size".into());
    }

    let mut entries = read_mapping_entries(&args.account_mapping, 20, &db)?;
    entries.extend(read_mapping_entries(&args.storage_mapping, 52, &db)?);
    if entries.is_empty() {
        return Err("no mapping entries found".into());
    }

    let num_entries = entries.len();
    let num_buckets = buckets_for_entries(num_entries, args.bucket_size);
    if num_buckets == 0 {
        return Err("num_buckets must be >0".into());
    }

    let base_cfg = CuckooConfig::new(
        num_buckets,
        args.bucket_size,
        args.num_hashes,
        args.max_kicks,
        args.seed,
    );
    let (table, final_cfg) = build_cuckoo_with_retries(
        &entries,
        &base_cfg,
        BUCKET_SLACK,
        MAX_BUILD_ATTEMPTS,
        true,
    )?;

    let out_dir = Path::new(&args.out);
    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("keywordpir-db.bin"), table.to_entry_bytes())?;

    let mut tag_map: HashMap<Tag, Vec<Vec<u8>>> = HashMap::new();
    for record in &entries {
        tag_map.entry(record.tag).or_default().push(record.key.clone());
    }
    let mut collision_tags: Vec<Tag> = tag_map
        .iter()
        .filter(|(_, keys)| keys.len() > 1)
        .map(|(tag, _)| *tag)
        .collect();
    collision_tags.sort_by(|a, b| a.0.cmp(&b.0));
    let collision_set: HashSet<Tag> = collision_tags.iter().copied().collect();

    let collision_entries: Vec<EntryRecord> = entries
        .iter()
        .filter(|record| collision_set.contains(&record.tag))
        .map(|record| EntryRecord {
            key: record.key.clone(),
            index: record.index,
            entry: record.entry,
            tag: record.tag,
        })
        .collect();
    let collision_count = collision_entries.len();
    if collision_count > 0 {
        let collision_buckets = buckets_for_entries(collision_count, args.bucket_size);
        if collision_buckets == 0 {
            return Err("collision num_buckets must be >0".into());
        }
        let collision_base_cfg = CuckooConfig::new(
            collision_buckets,
            args.bucket_size,
            args.num_hashes,
            args.max_kicks,
            final_cfg.seed,
        );
        let (collision_table, _) = build_cuckoo_with_retries(
            &collision_entries,
            &collision_base_cfg,
            BUCKET_SLACK,
            MAX_BUILD_ATTEMPTS,
            false,
        )?;
        fs::write(
            out_dir.join("keywordpir-collision-db.bin"),
            collision_table.to_collision_bytes(),
        )?;
    }

    let mut tags_bytes = Vec::with_capacity(collision_tags.len() * TAG_SIZE);
    for tag in &collision_tags {
        tags_bytes.extend_from_slice(tag.as_bytes());
    }
    fs::write(out_dir.join("keywordpir-collision-tags.bin"), tags_bytes)?;

    write_metadata(
        out_dir,
        ENTRY_SIZE,
        num_entries,
        final_cfg.bucket_size,
        final_cfg.num_buckets,
        final_cfg.num_hashes,
        final_cfg.max_kicks,
        final_cfg.seed,
        COLLISION_ENTRY_SIZE,
        collision_count,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rms24::keyword_pir::cuckoo_positions;

    fn entry_record_for_key(key: Vec<u8>) -> EntryRecord {
        let tag = tag_for_key(&key).expect("valid key length");
        let mut entry = [0u8; ENTRY_SIZE];
        match key.len() {
            20 => entry[24..32].copy_from_slice(tag.as_bytes()),
            52 => entry[32..40].copy_from_slice(tag.as_bytes()),
            _ => panic!("unsupported key length"),
        }
        EntryRecord {
            key,
            entry,
            tag,
            index: 0,
        }
    }

    fn hash_key_for_test(key: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..]);
        out
    }

    fn find_keys_with_distinct_buckets(seed: u64) -> (Vec<u8>, Vec<u8>) {
        let cfg = CuckooConfig::new(2, 1, 1, 1, seed);
        for a in 0u8..=255 {
            let key_a = vec![a; 20];
            let hash_a = hash_key_for_test(&key_a);
            let bucket_a = cuckoo_positions(&hash_a, &cfg)[0];
            for b in 0u8..=255 {
                if b == a {
                    continue;
                }
                let key_b = vec![b; 20];
                let hash_b = hash_key_for_test(&key_b);
                let bucket_b = cuckoo_positions(&hash_b, &cfg)[0];
                if bucket_a != bucket_b {
                    return (key_a, key_b);
                }
            }
        }
        panic!("no keys found with distinct buckets");
    }

    #[test]
    fn test_build_cuckoo_retries_and_bumps_seed() {
        let (key_a, key_b) = find_keys_with_distinct_buckets(8);
        let entries = vec![
            entry_record_for_key(key_a),
            entry_record_for_key(key_b),
        ];
        let base = CuckooConfig::new(1, 1, 1, 1, 7);
        let (table, cfg) = build_cuckoo_with_retries(&entries, &base, 2.0, 2, true).unwrap();
        assert!(cfg.num_buckets >= 2);
        assert_eq!(cfg.seed, 8);
        for record in &entries {
            assert!(table.find_candidate(&record.key).is_some());
        }
    }

    #[test]
    fn test_build_cuckoo_retries_without_seed_bump() {
        let (key_a, key_b) = find_keys_with_distinct_buckets(9);
        let entries = vec![entry_record_for_key(key_a), entry_record_for_key(key_b)];
        let base = CuckooConfig::new(1, 1, 1, 1, 9);
        let (_, cfg) = build_cuckoo_with_retries(&entries, &base, 2.0, 2, false).unwrap();
        assert!(cfg.num_buckets >= 2);
        assert_eq!(cfg.seed, 9);
    }

    #[test]
    fn test_parse_args() {
        let args = Args::parse_from([
            "rms24_keywordpir_build",
            "--db",
            "db.bin",
            "--account-mapping",
            "acc.bin",
            "--storage-mapping",
            "sto.bin",
            "--out",
            "out",
        ]);
        assert_eq!(args.db, "db.bin");
        assert_eq!(args.out, "out");
    }
}
