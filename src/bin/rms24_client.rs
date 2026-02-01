use clap::Parser;
use rms24::bench_framing::{read_frame, write_frame};
use rms24::bench_proto::{Mode, Query, Reply, RunConfig};
use rms24::bench_timing::TimingCounters;
use rms24::client::OnlineClient;
use rms24::params::Params;
use rms24::prf::Prf;
use sha3::{Digest, Sha3_256};
use std::net::TcpStream;
use std::path::Path;
use std::time::Instant;

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

fn coverage_enabled(args: &Args) -> bool {
    if args.coverage_index {
        return true;
    }
    match std::env::var("RMS24_COVERAGE_INDEX") {
        Ok(val) => matches!(val.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let db = std::fs::read(&args.db)?;
    let num_entries = db.len() / args.entry_size;
    let params = Params::new(num_entries as u64, args.entry_size, args.lambda);
    let state_path = args.state.as_deref().map(Path::new);
    let mut client = load_or_generate_client(&db, params.clone(), args.seed, state_path)?;
    let coverage_enabled = coverage_enabled(&args);
    let coverage = if coverage_enabled {
        Some(client.build_coverage_index())
    } else {
        None
    };

    let mode = match args.mode.as_str() {
        "keywordpir" => Mode::KeywordPir,
        _ => Mode::Rms24,
    };

    let cfg = RunConfig {
        dataset_id: "unknown".to_string(),
        mode,
        query_count: args.query_count,
        threads: args.threads,
        seed: args.seed,
    };

    let mut stream = TcpStream::connect(&args.server)?;
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

        let serialize_start = Instant::now();
        let bytes = bincode::serialize(&real)?;
        record("serialize", serialize_start.elapsed().as_micros() as u64);
        let write_start = Instant::now();
        write_frame(&mut stream, &bytes)?;
        record("write_frame", write_start.elapsed().as_micros() as u64);
        let read_start = Instant::now();
        let reply_bytes = read_frame(&mut stream)?;
        record("read_frame", read_start.elapsed().as_micros() as u64);
        let deserialize_start = Instant::now();
        let reply: Reply = bincode::deserialize(&reply_bytes)?;
        record("deserialize", deserialize_start.elapsed().as_micros() as u64);

        let serialize_start = Instant::now();
        let bytes = bincode::serialize(&dummy)?;
        record("serialize", serialize_start.elapsed().as_micros() as u64);
        let write_start = Instant::now();
        write_frame(&mut stream, &bytes)?;
        record("write_frame", write_start.elapsed().as_micros() as u64);
        let read_start = Instant::now();
        let dummy_reply_bytes = read_frame(&mut stream)?;
        record("read_frame", read_start.elapsed().as_micros() as u64);
        let deserialize_start = Instant::now();
        let _dummy_reply: Reply = bincode::deserialize(&dummy_reply_bytes)?;
        record("deserialize", deserialize_start.elapsed().as_micros() as u64);

        let decode_start = Instant::now();
        if coverage_enabled {
            let _ = client.decode_reply_static(real_hint, reply.parity)?;
        } else {
            let _ = client.consume_network_reply(idx, real_hint, reply.parity)?;
        }
        record("decode", decode_start.elapsed().as_micros() as u64);
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
    fn test_coverage_env_enables_index() {
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
}
