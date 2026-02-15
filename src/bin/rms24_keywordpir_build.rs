use clap::Parser;
use memmap2::Mmap;
use rms24::keyword_pir::{
    parse_mapping_record, tag_for_key, tag_from_entry, CuckooConfig, CuckooTable,
};
use rms24::schema40::{Tag, ENTRY_SIZE};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

const COLLISION_ENTRY_SIZE: usize = 72;
const TARGET_LOAD_PERCENT: u128 = 90;

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

#[derive(serde::Serialize)]
struct KeywordPirMetadataFile {
    entry_size: u64,
    num_entries: u64,
    bucket_size: u64,
    num_buckets: u64,
    num_hashes: u64,
    max_kicks: u64,
    seed: u64,
    collision_entry_size: u64,
    collision_count: u64,
    collision_num_buckets: u64,
}

fn buckets_for_entries(count: usize, bucket_size: usize) -> usize {
    if count == 0 || bucket_size == 0 {
        return 0;
    }
    let count_u128 = count as u128;
    let bucket_u128 = bucket_size as u128;
    let target_entries =
        (count_u128 * 100 + (TARGET_LOAD_PERCENT - 1)) / TARGET_LOAD_PERCENT;
    let buckets = (target_entries + bucket_u128 - 1) / bucket_u128;
    usize::try_from(buckets).unwrap_or(usize::MAX)
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
    collision_num_buckets: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = KeywordPirMetadataFile {
        entry_size: entry_size as u64,
        num_entries: num_entries as u64,
        bucket_size: bucket_size as u64,
        num_buckets: num_buckets as u64,
        num_hashes: num_hashes as u64,
        max_kicks: max_kicks as u64,
        seed,
        collision_entry_size: collision_entry_size as u64,
        collision_count: collision_count as u64,
        collision_num_buckets: collision_num_buckets as u64,
    };
    let mut contents = serde_json::to_string_pretty(&metadata)?;
    contents.push('\n');
    fs::write(out_dir.join("keywordpir-metadata.json"), contents)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
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

    let cfg = CuckooConfig::new(
        num_buckets,
        args.bucket_size,
        args.num_hashes,
        args.max_kicks,
        args.seed,
    );
    let mut table = CuckooTable::new(cfg.clone());
    for record in &entries {
        table.insert(&record.key, record.entry)?;
    }

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

    let collision_count = entries
        .iter()
        .filter(|record| collision_set.contains(&record.tag))
        .count();
    let collision_buckets = if collision_count > 0 {
        let buckets = buckets_for_entries(collision_count, args.bucket_size);
        if buckets == 0 {
            return Err("collision num_buckets must be >0".into());
        }
        buckets
    } else {
        0
    };
    if collision_count > 0 {
        let collision_cfg = CuckooConfig::new(
            collision_buckets,
            args.bucket_size,
            args.num_hashes,
            args.max_kicks,
            args.seed,
        );
        let mut collision_table = CuckooTable::new(collision_cfg);
        for record in entries.iter().filter(|record| collision_set.contains(&record.tag)) {
            collision_table.insert(&record.key, record.entry)?;
        }
        fs::write(
            out_dir.join("keywordpir-collision-db.bin"),
            collision_table.to_collision_bytes(),
        )?;
    }

    let mut tags_bytes = Vec::with_capacity(collision_tags.len() * 8);
    for tag in &collision_tags {
        tags_bytes.extend_from_slice(tag.as_bytes());
    }
    fs::write(out_dir.join("keywordpir-collision-tags.bin"), tags_bytes)?;

    write_metadata(
        out_dir,
        ENTRY_SIZE,
        num_entries,
        args.bucket_size,
        num_buckets,
        args.num_hashes,
        args.max_kicks,
        args.seed,
        COLLISION_ENTRY_SIZE,
        collision_count,
        collision_buckets,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_write_metadata_includes_collision_num_buckets() {
        let mut out_dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        out_dir.push(format!(
            "keywordpir_meta_test_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&out_dir).unwrap();
        write_metadata(
            &out_dir,
            ENTRY_SIZE,
            4,
            2,
            2,
            2,
            8,
            1,
            COLLISION_ENTRY_SIZE,
            3,
            2,
        )
        .unwrap();
        let contents = fs::read_to_string(out_dir.join("keywordpir-metadata.json")).unwrap();
        assert!(contents.contains("\"collision_num_buckets\": 2"));
        let _ = fs::remove_file(out_dir.join("keywordpir-metadata.json"));
        let _ = fs::remove_dir(&out_dir);
    }

    #[test]
    fn test_buckets_for_entries_adds_slack() {
        let buckets = buckets_for_entries(10, 2);
        assert_eq!(buckets, 6);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_buckets_for_entries_large_count_precision() {
        let count = (1usize << 53) + 1;
        let buckets = buckets_for_entries(count, 2);
        let expected = 5003999585967219usize;
        assert_eq!(buckets, expected);
    }
}
