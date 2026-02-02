use clap::Parser;
use rms24::bench_framing::{read_frame, write_frame};
use rms24::bench_proto::{BatchRequest, ClientFrame, Mode, Query, Reply, RunConfig, ServerFrame};
use rms24::bench_timing::TimingCounters;
use rms24::client::OnlineClient;
use rms24::keyword_pir::{parse_mapping_record, CuckooConfig, KeywordPirClient, KeywordPirParams};
use rms24::params::Params;
use rms24::prf::Prf;
use rms24::schema40::{Tag, TAG_SIZE};
use sha3::{Digest, Sha3_256};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

const DEFAULT_TCP_TIMEOUT_SECS: u64 = 60;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    db: String,
    #[arg(long, default_value = "40")]
    entry_size: usize,
    #[arg(long, default_value = "80")]
    lambda: u32,
    #[arg(long, default_value = "127.0.0.1:4000")]
    server: String,
    #[arg(long, default_value = "1000")]
    query_count: u64,
    #[arg(long, default_value = "1")]
    threads: usize,
    #[arg(long, default_value = "0")]
    seed: u64,
    #[arg(long, default_value = "rms24")]
    mode: String,
    #[arg(long)]
    coverage_index: bool,
    #[arg(long)]
    state: Option<String>,
    #[arg(long)]
    timing: bool,
    #[arg(long, default_value = "1000")]
    timing_every: u64,
    #[arg(long, default_value = "1")]
    batch_size: usize,
    #[arg(long)]
    keywordpir_metadata: Option<String>,
    #[arg(long)]
    account_mapping: Option<String>,
    #[arg(long)]
    storage_mapping: Option<String>,
    #[arg(long)]
    collision_tags: Option<String>,
    #[arg(long)]
    collision_server: Option<String>,
}

fn prf_from_seed(seed: u64) -> Prf {
    let mut hasher = Sha3_256::new();
    hasher.update(seed.to_le_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    Prf::new(key)
}

fn params_match(a: &Params, b: &Params) -> bool {
    a.num_entries == b.num_entries
        && a.entry_size == b.entry_size
        && a.security_param == b.security_param
}

fn params_from_db(
    db: &[u8],
    entry_size: usize,
    lambda: u32,
) -> Result<(Params, usize), Box<dyn std::error::Error>> {
    if entry_size == 0 {
        return Err("entry_size must be >0".into());
    }
    if db.is_empty() {
        return Err("db must contain at least one entry".into());
    }
    if db.len() % entry_size != 0 {
        return Err("entry_size must divide db length".into());
    }
    let num_entries = db.len() / entry_size;
    Ok((Params::new(num_entries as u64, entry_size, lambda), num_entries))
}

struct KeywordPirMetadata {
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

fn parse_keywordpir_metadata(
    path: &Path,
) -> Result<KeywordPirMetadata, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let mut entry_size = None;
    let mut num_entries = None;
    let mut bucket_size = None;
    let mut num_buckets = None;
    let mut num_hashes = None;
    let mut max_kicks = None;
    let mut seed = None;
    let mut collision_entry_size = None;
    let mut collision_count = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if !line.starts_with('"') {
            continue;
        }
        let line = line.trim_end_matches(',');
        let mut parts = line.splitn(2, ':');
        let key = parts
            .next()
            .ok_or("keywordpir metadata missing key")?
            .trim()
            .trim_matches('"');
        let value_str = parts
            .next()
            .ok_or("keywordpir metadata missing value")?
            .trim()
            .trim_end_matches(',');
        let value: u64 = value_str
            .parse()
            .map_err(|_| format!("keywordpir metadata invalid value for {key}"))?;
        match key {
            "entry_size" => entry_size = Some(value),
            "num_entries" => num_entries = Some(value),
            "bucket_size" => bucket_size = Some(value),
            "num_buckets" => num_buckets = Some(value),
            "num_hashes" => num_hashes = Some(value),
            "max_kicks" => max_kicks = Some(value),
            "seed" => seed = Some(value),
            "collision_entry_size" => collision_entry_size = Some(value),
            "collision_count" => collision_count = Some(value),
            _ => {}
        }
    }

    let entry_size = entry_size.ok_or("keywordpir metadata missing entry_size")?;
    let num_entries = num_entries.ok_or("keywordpir metadata missing num_entries")?;
    let bucket_size = bucket_size.ok_or("keywordpir metadata missing bucket_size")?;
    let num_buckets = num_buckets.ok_or("keywordpir metadata missing num_buckets")?;
    let num_hashes = num_hashes.ok_or("keywordpir metadata missing num_hashes")?;
    let max_kicks = max_kicks.ok_or("keywordpir metadata missing max_kicks")?;
    let seed = seed.ok_or("keywordpir metadata missing seed")?;
    let collision_entry_size =
        collision_entry_size.ok_or("keywordpir metadata missing collision_entry_size")?;
    let collision_count =
        collision_count.ok_or("keywordpir metadata missing collision_count")?;

    let entry_size = usize::try_from(entry_size)
        .map_err(|_| "keywordpir metadata entry_size too large")?;
    let num_entries = usize::try_from(num_entries)
        .map_err(|_| "keywordpir metadata num_entries too large")?;
    let bucket_size = usize::try_from(bucket_size)
        .map_err(|_| "keywordpir metadata bucket_size too large")?;
    let num_buckets = usize::try_from(num_buckets)
        .map_err(|_| "keywordpir metadata num_buckets too large")?;
    let num_hashes = usize::try_from(num_hashes)
        .map_err(|_| "keywordpir metadata num_hashes too large")?;
    let max_kicks = usize::try_from(max_kicks)
        .map_err(|_| "keywordpir metadata max_kicks too large")?;
    let collision_entry_size = usize::try_from(collision_entry_size)
        .map_err(|_| "keywordpir metadata collision_entry_size too large")?;
    let collision_count = usize::try_from(collision_count)
        .map_err(|_| "keywordpir metadata collision_count too large")?;

    Ok(KeywordPirMetadata {
        entry_size,
        num_entries,
        bucket_size,
        num_buckets,
        num_hashes,
        max_kicks,
        seed,
        collision_entry_size,
        collision_count,
    })
}

fn read_mapping_keys(
    path: &Path,
    key_size: usize,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len() as usize;
    let record_size = key_size + 4;
    if record_size == 0 || len % record_size != 0 {
        return Err(format!("mapping file {} has invalid length", path.display()).into());
    }
    let count = len / record_size;

    let mut reader = BufReader::new(file);
    let mut buf = vec![0u8; record_size];
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        reader.read_exact(&mut buf)?;
        let record = parse_mapping_record(&buf, key_size)
            .ok_or("mapping record shorter than expected")?;
        out.push(record.key);
    }
    Ok(out)
}

fn read_collision_tags(path: &Path) -> Result<Vec<Tag>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() % TAG_SIZE != 0 {
        return Err("collision tags length must be multiple of tag size".into());
    }
    let mut tags = Vec::with_capacity(bytes.len() / TAG_SIZE);
    for chunk in bytes.chunks_exact(TAG_SIZE) {
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(chunk);
        tags.push(Tag(tag));
    }
    Ok(tags)
}

fn ensure_collision_server(
    tags: &[Tag],
    collision_server: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !tags.is_empty() && collision_server.is_none() {
        return Err("collision-server required when collision-tags are non-empty".into());
    }
    Ok(())
}

fn build_round_robin_keys(
    account_keys: &[Vec<u8>],
    storage_keys: &[Vec<u8>],
    count: u64,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    if account_keys.is_empty() && storage_keys.is_empty() {
        return Err("no mapping keys found".into());
    }
    let total = usize::try_from(count).map_err(|_| "query_count must fit in usize")?;
    let mut out = Vec::with_capacity(total);
    let mut account_idx = 0usize;
    let mut storage_idx = 0usize;
    let mut use_account = true;
    for _ in 0..count {
        let next_is_account = if account_keys.is_empty() {
            false
        } else if storage_keys.is_empty() {
            true
        } else {
            use_account
        };
        if next_is_account {
            let key = account_keys[account_idx % account_keys.len()].clone();
            account_idx += 1;
            out.push(key);
        } else {
            let key = storage_keys[storage_idx % storage_keys.len()].clone();
            storage_idx += 1;
            out.push(key);
        }
        use_account = !use_account;
    }
    Ok(out)
}

fn coverage_enabled(args: &Args) -> bool {
    if args.coverage_index {
        return true;
    }
    match std::env::var("RMS24_COVERAGE_INDEX") {
        Ok(val) => matches!(val.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

fn connect_with_timeouts(addr: &str, timeout: Duration) -> io::Result<TcpStream> {
    let mut last_err = None;
    let addrs = addr
        .to_socket_addrs()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "failed to resolve socket addresses"))?;
    for socket_addr in addrs {
        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(err) => {
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "failed to resolve socket addresses")
    }))
}

fn load_cached_client(
    path: &Path,
    params: &Params,
    expected_prf: Option<&[u8; 32]>,
) -> Option<OnlineClient> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                eprintln!("state_cache=read_error path={} err={}", path.display(), err);
            }
            return None;
        }
    };
    let client = match OnlineClient::deserialize_state(&bytes) {
        Ok(client) => client,
        Err(err) => {
            eprintln!(
                "state_cache=deserialize_error path={} err={}",
                path.display(),
                err
            );
            return None;
        }
    };
    if !params_match(&client.params, params) {
        eprintln!("state_cache=param_mismatch path={}", path.display());
        return None;
    }
    if let Some(expected_prf) = expected_prf {
        if client.prf.key() != expected_prf {
            eprintln!("state_cache=prf_mismatch path={}", path.display());
            return None;
        }
    } else {
        eprintln!("state_cache=skip_prf_check path={}", path.display());
    }
    Some(client)
}

fn save_cached_client(client: &OnlineClient, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    let data = client.serialize_state()?;
    std::fs::write(&tmp_path, data)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn load_or_generate_client(
    db: &[u8],
    params: Params,
    seed: u64,
    state_path: Option<&Path>,
) -> Result<OnlineClient, Box<dyn std::error::Error>> {
    let prf = if seed == 0 { Prf::random() } else { prf_from_seed(seed) };
    let expected_prf = if seed == 0 { None } else { Some(*prf.key()) };
    if let Some(path) = state_path {
        if let Some(client) = load_cached_client(path, &params, expected_prf.as_ref()) {
            println!("state_cache=hit path={}", path.display());
            return Ok(client);
        }
    }

    let mut client = OnlineClient::new(params, prf, seed);
    println!("state_cache=miss");
    client.generate_hints(db)?;
    if let Some(path) = state_path {
        if let Err(err) = save_cached_client(&client, path) {
            eprintln!("state_cache=save_error path={} err={}", path.display(), err);
        } else {
            println!("state_cache=saved path={}", path.display());
        }
    }
    Ok(client)
}

struct PendingItem {
    query: Query,
    kind: PendingKind,
}

enum PendingKind {
    Real { index: u64, hint: usize },
    Dummy,
}

fn flush_batch(
    stream: &mut TcpStream,
    pending: &mut Vec<PendingItem>,
    batch_size: usize,
    client: &mut OnlineClient,
    coverage: &Option<Vec<Vec<u32>>>,
    record: &mut impl FnMut(&str, u64),
) -> Result<(), Box<dyn std::error::Error>> {
    let take = batch_size.min(pending.len());
    if take == 0 {
        return Ok(());
    }
    let batch: Vec<PendingItem> = pending.drain(0..take).collect();
    let queries: Vec<Query> = batch.iter().map(|p| p.query.clone()).collect();
    let frame = if queries.len() == 1 {
        ClientFrame::Query(queries[0].clone())
    } else {
        ClientFrame::BatchRequest(BatchRequest { queries })
    };

    let serialize_start = Instant::now();
    let bytes = bincode::serialize(&frame)?;
    record("serialize", serialize_start.elapsed().as_micros() as u64);
    let write_start = Instant::now();
    write_frame(&mut *stream, &bytes)?;
    record("write_frame", write_start.elapsed().as_micros() as u64);
    let read_start = Instant::now();
    let reply_bytes = read_frame(&mut *stream)?;
    record("read_frame", read_start.elapsed().as_micros() as u64);
    let deserialize_start = Instant::now();
    let reply_frame: ServerFrame = bincode::deserialize(&reply_bytes)?;
    record("deserialize", deserialize_start.elapsed().as_micros() as u64);

    let replies = match reply_frame {
        ServerFrame::Reply(reply) => vec![reply],
        ServerFrame::BatchReply(batch) => batch.replies,
        ServerFrame::Error { message } => return Err(message.into()),
    };
    if replies.len() != batch.len() {
        return Err(format!(
            "batch reply count {} does not match request count {}",
            replies.len(),
            batch.len()
        )
        .into());
    }

    for (item, reply) in batch.into_iter().zip(replies.into_iter()) {
        match (item.kind, reply) {
            (PendingKind::Real { index, hint }, Reply::Ok { parity, .. }) => {
                let decode_start = Instant::now();
                if let Some(_) = coverage {
                    let _ = client.decode_reply_static(hint, parity)?;
                } else {
                    let _ = client.consume_network_reply(index, hint, parity)?;
                }
                record("decode", decode_start.elapsed().as_micros() as u64);
            }
            (_, Reply::Ok { .. }) => {}
            (_, Reply::Error { message, .. }) => return Err(message.into()),
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let batch_size = args.batch_size.max(1);
    let mode = match args.mode.as_str() {
        "keywordpir" => Mode::KeywordPir,
        _ => Mode::Rms24,
    };
    let is_keywordpir = matches!(mode, Mode::KeywordPir);
    let keywordpir_metadata = if is_keywordpir {
        let path = args
            .keywordpir_metadata
            .as_deref()
            .ok_or("keywordpir-metadata required for keywordpir mode")?;
        let metadata = parse_keywordpir_metadata(Path::new(path))?;
        if metadata.entry_size != args.entry_size {
            return Err(format!(
                "keywordpir metadata entry_size {} does not match --entry-size {}",
                metadata.entry_size, args.entry_size
            )
            .into());
        }
        Some(metadata)
    } else {
        None
    };
    let db = std::fs::read(&args.db)?;
    let (params, num_entries) = params_from_db(&db, args.entry_size, args.lambda)?;
    let state_path = args.state.as_deref().map(Path::new);
    let mut client = load_or_generate_client(&db, params.clone(), args.seed, state_path)?;
    let coverage_enabled = coverage_enabled(&args);
    let coverage = if coverage_enabled {
        Some(client.build_coverage_index())
    } else {
        None
    };

    let threads = u32::try_from(args.threads)
        .map_err(|_| "threads must fit in u32")?;
    let batch_size_u32 =
        u32::try_from(batch_size).map_err(|_| "batch_size must fit in u32")?;

    let cfg = RunConfig {
        dataset_id: "unknown".to_string(),
        mode,
        query_count: args.query_count,
        threads,
        seed: args.seed,
        batch_size: batch_size_u32,
        max_batch_queries: batch_size_u32,
    };

    let mut keyword_client: Option<KeywordPirClient> = None;
    let mut keyword_keys: Vec<Vec<u8>> = Vec::new();
    if let Some(metadata) = keywordpir_metadata {
        if metadata.collision_entry_size == 0 {
            return Err("keywordpir metadata collision_entry_size must be >0".into());
        }
        let expected_entries = metadata
            .num_buckets
            .checked_mul(metadata.bucket_size)
            .ok_or("keywordpir metadata table size overflow")?;
        if expected_entries != num_entries {
            return Err(format!(
                "keywordpir metadata table size {} does not match db entries {}",
                expected_entries, num_entries
            )
            .into());
        }

        let account_path = args
            .account_mapping
            .as_deref()
            .ok_or("account-mapping required for keywordpir mode")?;
        let storage_path = args
            .storage_mapping
            .as_deref()
            .ok_or("storage-mapping required for keywordpir mode")?;
        let account_keys = read_mapping_keys(Path::new(account_path), 20)?;
        let storage_keys = read_mapping_keys(Path::new(storage_path), 52)?;
        let mapping_count = account_keys.len() + storage_keys.len();
        if mapping_count != metadata.num_entries {
            return Err(format!(
                "keywordpir metadata num_entries {} does not match mapping entries {}",
                metadata.num_entries, mapping_count
            )
            .into());
        }
        keyword_keys = build_round_robin_keys(&account_keys, &storage_keys, args.query_count)?;

        let cfg = CuckooConfig::new(
            metadata.num_buckets,
            metadata.bucket_size,
            metadata.num_hashes,
            metadata.max_kicks,
            metadata.seed,
        );
        let mut kp_client =
            KeywordPirClient::new(KeywordPirParams { cfg, entry_size: metadata.entry_size });
        if let Some(path) = args.collision_tags.as_deref() {
            let tags = read_collision_tags(Path::new(path))?;
            ensure_collision_server(&tags, args.collision_server.as_deref())?;
            if tags.len() > metadata.collision_count {
                return Err(format!(
                    "collision tags count {} exceeds collision_count {}",
                    tags.len(),
                    metadata.collision_count
                )
                .into());
            }
            kp_client.set_collision_tags(tags);
        }
        keyword_client = Some(kp_client);
    }

    let timeout = Duration::from_secs(DEFAULT_TCP_TIMEOUT_SECS);
    let mut stream = connect_with_timeouts(&args.server, timeout)?;
    let cfg_bytes = bincode::serialize(&cfg)?;
    write_frame(&mut stream, &cfg_bytes)?;

    const PHASES: [&str; 6] = [
        "build_query",
        "serialize",
        "write_frame",
        "read_frame",
        "deserialize",
        "decode",
    ];
    let mut timing = args.timing.then(|| TimingCounters::new(args.timing_every));
    let mut record = |phase: &str, micros: u64| {
        if let Some(ref mut timing) = timing {
            timing.add(phase, micros);
            if timing.should_log(phase) {
                println!("{}", timing.summary_line(phase));
            }
        }
    };

    let start = Instant::now();
    let mut pending: Vec<PendingItem> = Vec::new();
    if is_keywordpir {
        let keyword_client = keyword_client.as_ref().ok_or("keywordpir client missing")?;
        for key in keyword_keys {
            let positions = keyword_client.positions_for_key(&key);
            for pos in positions {
                let idx = pos as u64;
                let build_start = Instant::now();
                let (real_query, dummy_query, real_hint) = match &coverage {
                    Some(coverage) => client.build_network_queries_with_coverage(idx, coverage)?,
                    None => client.build_network_queries(idx)?,
                };
                record("build_query", build_start.elapsed().as_micros() as u64);

                let real = Query { id: real_query.id, subset: real_query.subset };
                let dummy = Query { id: dummy_query.id, subset: dummy_query.subset };

                pending.push(PendingItem {
                    query: real,
                    kind: PendingKind::Real { index: idx, hint: real_hint },
                });
                pending.push(PendingItem {
                    query: dummy,
                    kind: PendingKind::Dummy,
                });

                if pending.len() >= batch_size {
                    flush_batch(
                        &mut stream,
                        &mut pending,
                        batch_size,
                        &mut client,
                        &coverage,
                        &mut record,
                    )?;
                }
            }
        }
    } else {
        for i in 0..args.query_count {
            let idx = (i % num_entries as u64) as u64;
            let build_start = Instant::now();
            let (real_query, dummy_query, real_hint) = match &coverage {
                Some(coverage) => client.build_network_queries_with_coverage(idx, coverage)?,
                None => client.build_network_queries(idx)?,
            };
            record("build_query", build_start.elapsed().as_micros() as u64);

            let real = Query { id: real_query.id, subset: real_query.subset };
            let dummy = Query { id: dummy_query.id, subset: dummy_query.subset };

            pending.push(PendingItem {
                query: real,
                kind: PendingKind::Real { index: idx, hint: real_hint },
            });
            pending.push(PendingItem {
                query: dummy,
                kind: PendingKind::Dummy,
            });

            if pending.len() >= batch_size {
                flush_batch(
                    &mut stream,
                    &mut pending,
                    batch_size,
                    &mut client,
                    &coverage,
                    &mut record,
                )?;
            }
        }
    }
    while !pending.is_empty() {
        flush_batch(
            &mut stream,
            &mut pending,
            batch_size,
            &mut client,
            &coverage,
            &mut record,
        )?;
    }
    let elapsed = start.elapsed();
    println!("elapsed_ms={}", elapsed.as_millis());
    if let Some(timing) = timing {
        for phase in PHASES {
            println!("{}", timing.summary_line(phase));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_parse_args() {
        let args = Args::parse_from([
            "rms24-client",
            "--db",
            "db.bin",
            "--entry-size",
            "40",
            "--lambda",
            "80",
            "--server",
            "127.0.0.1:4000",
            "--query-count",
            "1000",
            "--coverage-index",
        ]);
        assert_eq!(args.query_count, 1000);
        assert!(args.coverage_index);
    }

    #[test]
    fn test_parse_args_keywordpir_flags() {
        let args = Args::parse_from([
            "rms24-client",
            "--db",
            "keywordpir-db.bin",
            "--mode",
            "keywordpir",
            "--keywordpir-metadata",
            "meta.json",
            "--account-mapping",
            "acc.bin",
            "--storage-mapping",
            "sto.bin",
        ]);
        assert!(args.keywordpir_metadata.is_some());
        assert!(args.account_mapping.is_some());
    }

    #[test]
    fn test_collision_server_required_for_nonempty_tags() {
        let tags = vec![Tag([1u8; TAG_SIZE])];
        let err = ensure_collision_server(&tags, None).unwrap_err();
        assert!(err.to_string().contains("collision-server"));
        ensure_collision_server(&[], None).unwrap();
        ensure_collision_server(&tags, Some("127.0.0.1:4001")).unwrap();
    }

    #[test]
    fn test_coverage_env_enables_index() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("RMS24_COVERAGE_INDEX", "1");
        let args = Args::parse_from(["rms24-client", "--db", "db.bin"]);
        assert!(coverage_enabled(&args));
        std::env::remove_var("RMS24_COVERAGE_INDEX");
    }

    #[test]
    fn test_parse_args_state() {
        let args = Args::parse_from([
            "rms24-client",
            "--db",
            "db.bin",
            "--entry-size",
            "40",
            "--lambda",
            "80",
            "--state",
            "/tmp/state.bin",
        ]);
        assert_eq!(args.state.as_deref(), Some("/tmp/state.bin"));
    }

    #[test]
    fn test_parse_args_timing_flags() {
        let args = Args::parse_from([
            "rms24-client",
            "--db",
            "db.bin",
            "--timing",
            "--timing-every",
            "25",
        ]);
        assert!(args.timing);
        assert_eq!(args.timing_every, 25);
    }

    #[test]
    fn test_parse_args_batch_size() {
        let args = Args::parse_from([
            "rms24-client",
            "--db",
            "db.bin",
            "--batch-size",
            "8",
        ]);
        assert_eq!(args.batch_size, 8);
    }

    #[test]
    fn test_load_cached_state_uses_cache() {
        let params = Params::new(16, 4, 2);
        let prf = prf_from_seed(42);
        let mut client = OnlineClient::new(params.clone(), prf, 42);
        client.next_query_id = 7;
        let data = client.serialize_state().unwrap();

        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("rms24_state_test_{}_{}.bin", std::process::id(), nanos));
        std::fs::write(&path, data).unwrap();

        let db = vec![0u8; params.num_entries as usize * params.entry_size];
        let loaded =
            load_or_generate_client(&db, params.clone(), 42, Some(path.as_path())).unwrap();
        assert_eq!(loaded.next_query_id, 7);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_connect_with_timeouts_sets_read_write() {
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });

        let timeout = Duration::from_secs(60);
        let stream = connect_with_timeouts(&addr.to_string(), timeout).unwrap();
        assert_eq!(stream.read_timeout().unwrap(), Some(timeout));
        assert_eq!(stream.write_timeout().unwrap(), Some(timeout));

        let _ = handle.join();
    }

    #[test]
    fn test_connect_with_timeouts_invalid_address_message() {
        use std::time::Duration;

        let timeout = Duration::from_secs(1);
        let err = connect_with_timeouts("127.0.0.1", timeout).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err
            .to_string()
            .contains("failed to resolve socket addresses"));
    }

    #[test]
    fn test_params_from_db_rejects_zero_entry_size() {
        let db = vec![0u8; 10];
        let err = params_from_db(&db, 0, 80).unwrap_err();
        assert!(err.to_string().contains("entry_size"));
    }

    #[test]
    fn test_params_from_db_rejects_unaligned_db() {
        let db = vec![0u8; 5];
        let err = params_from_db(&db, 4, 80).unwrap_err();
        assert!(err.to_string().contains("entry_size"));
    }

    #[test]
    fn test_params_from_db_rejects_empty_db() {
        let db = vec![];
        let err = params_from_db(&db, 4, 80).unwrap_err();
        assert!(err.to_string().contains("db must contain"));
    }

    #[test]
    fn test_params_from_db_ok() {
        let db = vec![0u8; 8];
        let (params, num_entries) = params_from_db(&db, 4, 80).unwrap();
        assert_eq!(num_entries, 2);
        assert_eq!(params.num_entries, 2);
        assert_eq!(params.entry_size, 4);
    }
}
