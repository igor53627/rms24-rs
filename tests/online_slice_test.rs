use rms24::{OnlineClient, Params, Prf};
use rms24::client::Client;
use rms24::server::{InMemoryDb, Server};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_real_slice_optional() {
    let data_dir = match std::env::var("RMS24_DATA_DIR").ok() {
        Some(dir) => dir,
        None => return,
    };

    let base = PathBuf::from(data_dir);
    let db_path = base.join("database.bin");
    let db = match fs::read(&db_path) {
        Ok(data) => data,
        Err(_) => return,
    };

    let entry_size = 40usize;
    if db.len() % entry_size != 0 {
        return;
    }

    let num_entries = (db.len() / entry_size) as u64;
    let params = Params::new(num_entries, entry_size, 2);
    let prf = Prf::random();
    let mut offline = Client::with_prf(params.clone(), prf.clone());
    offline.generate_hints(&db);
    let mut client = OnlineClient::new(params.clone(), prf, 1);
    client.hints = offline.hints.clone();

    let db_handle = match InMemoryDb::new(db.clone(), entry_size) {
        Ok(handle) => handle,
        Err(_) => return,
    };
    let server = match Server::new(db_handle, params.block_size) {
        Ok(server) => server,
        Err(_) => return,
    };

    let indices = [0u64, 1u64, num_entries.saturating_sub(1)];
    for index in indices {
        if index >= num_entries {
            continue;
        }
        let got = client.query(&server, index).unwrap();
        let start = index as usize * entry_size;
        let expected = db[start..start + entry_size].to_vec();
        assert_eq!(got, expected);
    }
}
