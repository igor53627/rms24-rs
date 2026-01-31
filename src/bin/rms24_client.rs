use clap::Parser;
use rms24::bench_framing::{read_frame, write_frame};
use rms24::bench_proto::{Mode, Query, Reply, RunConfig};
use rms24::client::OnlineClient;
use rms24::params::Params;
use rms24::prf::Prf;
use sha3::{Digest, Sha3_256};
use std::net::TcpStream;
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
}

fn prf_from_seed(seed: u64) -> Prf {
    let mut hasher = Sha3_256::new();
    hasher.update(seed.to_le_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    Prf::new(key)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let db = std::fs::read(&args.db)?;
    let num_entries = db.len() / args.entry_size;
    let params = Params::new(num_entries as u64, args.entry_size, args.lambda);
    let prf = if args.seed == 0 { Prf::random() } else { prf_from_seed(args.seed) };

    let mut client = OnlineClient::new(params.clone(), prf, args.seed);
    client.generate_hints(&db)?;

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

    let start = Instant::now();
    for i in 0..args.query_count {
        let idx = (i % num_entries as u64) as u64;
        let (real_query, dummy_query, real_hint) = client.build_network_queries(idx)?;

        let real = Query { id: real_query.id, subset: real_query.subset };
        let dummy = Query { id: dummy_query.id, subset: dummy_query.subset };

        let bytes = bincode::serialize(&real)?;
        write_frame(&mut stream, &bytes)?;
        let reply_bytes = read_frame(&mut stream)?;
        let reply: Reply = bincode::deserialize(&reply_bytes)?;

        let bytes = bincode::serialize(&dummy)?;
        write_frame(&mut stream, &bytes)?;
        let _dummy_reply: Reply = bincode::deserialize(&read_frame(&mut stream)?)?;

        let _ = client.consume_network_reply(idx, real_hint, reply.parity)?;
    }
    let elapsed = start.elapsed();
    println!("elapsed_ms={}", elapsed.as_millis());
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
        ]);
        assert_eq!(args.query_count, 1000);
    }
}
