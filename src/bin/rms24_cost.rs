use clap::Parser;
use rms24::cost::{estimate, CuckooParams};
use rms24::params::Params;

#[derive(Parser)]
#[command(about = "Estimate RMS24 PIR resource costs by component")]
struct Args {
    /// Number of database entries
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    num_entries: u64,

    /// Entry size in bytes
    #[arg(long, default_value = "40")]
    entry_size: usize,

    /// Security parameter (lambda)
    #[arg(long, default_value = "128")]
    lambda: u32,

    /// Cuckoo hash table buckets (enables KeywordPIR cost estimation)
    #[arg(long)]
    cuckoo_buckets: Option<u64>,

    /// Cuckoo bucket size
    #[arg(long, default_value = "2")]
    cuckoo_bucket_size: u64,

    /// Cuckoo number of hash functions
    #[arg(long, default_value = "2")]
    cuckoo_hashes: u64,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

fn main() {
    let args = Args::parse();

    let params = Params::new(args.num_entries, args.entry_size, args.lambda);

    let cuckoo = args.cuckoo_buckets.map(|buckets| CuckooParams {
        num_buckets: buckets,
        bucket_size: args.cuckoo_bucket_size,
        num_hashes: args.cuckoo_hashes,
    });

    let report = estimate(&params, cuckoo.as_ref());

    if args.json {
        print_json(&report);
    } else {
        print!("{}", report);
    }
}

fn print_json(report: &rms24::cost::CostReport) {
    let kp_json = if let Some(kp) = &report.keyword_pir {
        format!(
            r#", "keyword_pir": {{ "cuckoo_table_entries": {}, "cuckoo_expansion_factor": {:.4}, "queries_per_lookup": {}, "total_bandwidth_per_lookup_bytes": {} }}"#,
            kp.cuckoo_table_entries,
            kp.cuckoo_expansion_factor,
            kp.queries_per_lookup,
            kp.total_bandwidth_per_lookup_bytes,
        )
    } else {
        String::new()
    };

    println!(
        r#"{{ "num_entries": {}, "entry_size": {}, "security_param": {}, "block_size": {}, "num_blocks": {}, "total_hints": {}, "client_hint_storage_bytes": {}, "server_db_storage_bytes": {}, "offline_bandwidth_bytes": {}, "online_upload_bytes": {}, "online_download_bytes": {}, "online_query_bandwidth_bytes": {}, "server_xor_ops_per_query": {}{} }}"#,
        report.params.num_entries,
        report.params.entry_size,
        report.params.security_param,
        report.params.block_size,
        report.params.num_blocks,
        report.params.total_hints(),
        report.client_hint_storage_bytes,
        report.server_db_storage_bytes,
        report.offline_bandwidth_bytes,
        report.online_upload_bytes,
        report.online_download_bytes,
        report.online_query_bandwidth_bytes,
        report.server_xor_ops_per_query,
        kp_json,
    );
}
