use clap::Parser;
use rms24::bench_framing::{read_frame, write_frame};
use rms24::bench_proto::{Query, Reply, RunConfig};
use rms24::messages::Query as RmsQuery;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let db = std::fs::read(&args.db)?;
    let db = InMemoryDb::new(db, args.entry_size)?;
    let server = Server::new(db, args.lambda as u64)?;
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
}
