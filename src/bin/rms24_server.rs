use clap::Parser;
use rms24::bench_framing::{read_frame, write_frame};
use rms24::bench_proto::{Query, Reply, RunConfig};
use rms24::messages::Query as RmsQuery;
use rms24::params::Params;
use rms24::server::{InMemoryDb, Server};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

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
}

fn handle_client(mut stream: TcpStream, server: Arc<Server<InMemoryDb>>) -> io::Result<()> {
    let cfg_bytes = read_frame(&mut stream)?;
    let _cfg: RunConfig = bincode::deserialize(&cfg_bytes).unwrap();

    loop {
        let msg = read_frame(&mut stream)?;
        let query: Query = bincode::deserialize(&msg).unwrap();
        let rms_query = RmsQuery { id: query.id, subset: query.subset };
        let reply = server.answer(&rms_query).unwrap();
        let out = Reply { id: reply.id, parity: reply.parity };
        let out_bytes = bincode::serialize(&out).unwrap();
        write_frame(&mut stream, &out_bytes)?;
    }
}

fn build_server(
    db_path: &str,
    entry_size: usize,
    lambda: u32,
) -> Result<Server<InMemoryDb>, Box<dyn std::error::Error>> {
    let db = std::fs::read(db_path)?;
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

    let listener = TcpListener::bind(&args.listen)?;
    for stream in listener.incoming() {
        let server = Arc::clone(&server);
        thread::spawn(move || {
            if let Ok(stream) = stream {
                let _ = handle_client(stream, server);
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
    fn test_server_uses_params_block_size() {
        let entry_size = 1;
        let num_entries = 100usize;
        let db = vec![0u8; num_entries * entry_size];
        let path = std::env::temp_dir().join("rms24_server_blocksize_test.bin");
        std::fs::write(&path, &db).unwrap();

        let server = build_server(path.to_str().unwrap(), entry_size, 2).unwrap();
        let query = RmsQuery { id: 1, subset: vec![(0, 9)] };
        let reply = server.answer(&query).unwrap();
        assert_eq!(reply.parity.len(), entry_size);

        let _ = std::fs::remove_file(path);
    }
}
