use clap::Parser;
use rms24::bench_framing::{read_frame, write_frame};
use rms24::bench_handler::handle_client_frame;
use rms24::bench_proto::{ClientFrame, RunConfig};
use rms24::bench_timing::TimingCounters;
use rms24::params::Params;
use rms24::server::{InMemoryDb, Server};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
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
    listen: String,
    #[arg(long)]
    timing: bool,
    #[arg(long, default_value = "1000")]
    timing_every: u64,
    #[arg(long, default_value = "1")]
    max_batch_queries: usize,
}

const TIMING_PHASES: [&str; 5] = [
    "read_frame",
    "deserialize",
    "answer",
    "serialize",
    "write_frame",
];

fn print_timing_summary(timing: &TimingCounters) {
    for phase in TIMING_PHASES {
        println!("{}", timing.summary_line(phase));
    }
}

fn parse_run_config(bytes: &[u8]) -> io::Result<RunConfig> {
    bincode::deserialize(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn parse_client_frame(bytes: &[u8]) -> io::Result<ClientFrame> {
    bincode::deserialize(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn handle_client(
    mut stream: TcpStream,
    server: Arc<Server<InMemoryDb>>,
    timing_enabled: bool,
    timing_every: u64,
    max_batch_queries: usize,
) -> io::Result<()> {
    let cfg_bytes = read_frame(&mut stream)?;
    let cfg: RunConfig = parse_run_config(&cfg_bytes)?;
    let max_batch = max_batch_queries.min(cfg.max_batch_queries as usize);

    let mut timing = timing_enabled.then(|| TimingCounters::new(timing_every));
    let mut record = |phase: &str, micros: u64| {
        if let Some(ref mut timing) = timing {
            timing.add(phase, micros);
            if timing.should_log(phase) {
                println!("{}", timing.summary_line(phase));
            }
        }
    };

    loop {
        let read_start = Instant::now();
        let msg = match read_frame(&mut stream) {
            Ok(msg) => {
                record("read_frame", read_start.elapsed().as_micros() as u64);
                msg
            }
            Err(err) => {
                if let Some(ref timing) = timing {
                    print_timing_summary(timing);
                }
                return Err(err);
            }
        };
        let deserialize_start = Instant::now();
        let frame: ClientFrame = parse_client_frame(&msg)?;
        record(
            "deserialize",
            deserialize_start.elapsed().as_micros() as u64,
        );
        let answer_start = Instant::now();
        let out = handle_client_frame(&server, frame, max_batch);
        record("answer", answer_start.elapsed().as_micros() as u64);
        let serialize_start = Instant::now();
        let out_bytes = match bincode::serialize(&out) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("failed to serialize response: {err}");
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };
        record("serialize", serialize_start.elapsed().as_micros() as u64);
        let write_start = Instant::now();
        write_frame(&mut stream, &out_bytes)?;
        record("write_frame", write_start.elapsed().as_micros() as u64);
    }
}

fn build_server(
    db_path: &str,
    entry_size: usize,
    lambda: u32,
) -> Result<Server<InMemoryDb>, Box<dyn std::error::Error>> {
    if entry_size == 0 {
        return Err("entry_size must be >0".into());
    }
    let db = std::fs::read(db_path)?;
    if db.len() % entry_size != 0 {
        return Err("entry_size must divide db length".into());
    }
    if db.is_empty() {
        return Err("db must contain at least one entry".into());
    }
    let num_entries = db.len() / entry_size;
    let params = Params::new(num_entries as u64, entry_size, lambda);
    let db = InMemoryDb::new(db, entry_size)?;
    let server = Server::new(db, params.block_size)?;
    Ok(server)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let server = build_server(&args.db, args.entry_size, args.lambda)?;
    let server = Arc::new(server);
    let timing_enabled = args.timing;
    let timing_every = args.timing_every;
    let max_batch_queries = args.max_batch_queries;

    let listener = TcpListener::bind(&args.listen)?;
    for stream in listener.incoming() {
        let server = Arc::clone(&server);
        thread::spawn(move || {
            if let Ok(stream) = stream {
                let _ = handle_client(
                    stream,
                    server,
                    timing_enabled,
                    timing_every,
                    max_batch_queries,
                );
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rms24::messages::Query as RmsQuery;

    #[test]
    fn test_parse_args() {
        let args = Args::parse_from([
            "rms24-server",
            "--db",
            "db.bin",
            "--entry-size",
            "40",
            "--lambda",
            "80",
            "--listen",
            "127.0.0.1:4000",
        ]);
        assert_eq!(args.entry_size, 40);
        assert_eq!(args.lambda, 80);
    }

    #[test]
    fn test_parse_args_timing_flags() {
        let args = Args::parse_from([
            "rms24-server",
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
    fn test_parse_args_batching() {
        let args = Args::parse_from([
            "rms24-server",
            "--db",
            "db.bin",
            "--max-batch-queries",
            "32",
        ]);
        assert_eq!(args.max_batch_queries, 32);
    }

    #[test]
    fn test_build_server_rejects_zero_entry_size() {
        let path = std::env::temp_dir().join("rms24_server_entry_size_zero.bin");
        std::fs::write(&path, vec![0u8; 16]).unwrap();

        let result = std::panic::catch_unwind(|| build_server(path.to_str().unwrap(), 0, 80));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_build_server_rejects_unaligned_db_len() {
        let path = std::env::temp_dir().join("rms24_server_unaligned.bin");
        std::fs::write(&path, vec![0u8; 5]).unwrap();

        let err = match build_server(path.to_str().unwrap(), 4, 80) {
            Ok(_) => panic!("expected error for unaligned db length"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("entry_size"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_build_server_rejects_empty_db() {
        let path = std::env::temp_dir().join("rms24_server_empty.bin");
        std::fs::write(&path, Vec::<u8>::new()).unwrap();

        let err = match build_server(path.to_str().unwrap(), 4, 80) {
            Ok(_) => panic!("expected error for empty db"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("db must contain"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_parse_run_config_invalid_bytes() {
        let err = parse_run_config(&[0xAA, 0xBB]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_parse_client_frame_invalid_bytes() {
        let err = parse_client_frame(&[0xCC, 0xDD]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_server_uses_params_block_size() {
        let entry_size = 1;
        let num_entries = 100usize;
        let db = vec![0u8; num_entries * entry_size];
        let path = std::env::temp_dir().join("rms24_server_blocksize_test.bin");
        std::fs::write(&path, &db).unwrap();

        let server = build_server(path.to_str().unwrap(), entry_size, 2).unwrap();
        let query = RmsQuery {
            id: 1,
            subset: vec![(0, 9)],
        };
        let reply = server.answer(&query).unwrap();
        assert_eq!(reply.parity.len(), entry_size);

        let _ = std::fs::remove_file(path);
    }
}
