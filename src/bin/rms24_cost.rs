use clap::Parser;
use rms24::cost::{estimate, CuckooParams};
use rms24::params::Params;
use serde::Serialize;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    validate_args(&args)?;

    let params = Params::new(args.num_entries, args.entry_size, args.lambda);

    let cuckoo = args.cuckoo_buckets.map(|buckets| CuckooParams {
        num_buckets: buckets,
        bucket_size: args.cuckoo_bucket_size,
        num_hashes: args.cuckoo_hashes,
    });

    let report = estimate(&params, cuckoo.as_ref());

    if args.json {
        print_json(&report)?;
    } else {
        print!("{}", report);
    }

    Ok(())
}

fn validate_args(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    if args.entry_size == 0 {
        return Err("entry_size must be > 0".into());
    }

    let entry_size = u64::try_from(args.entry_size).map_err(|_| "entry_size too large")?;
    let max_entries = u64::MAX / entry_size;
    if args.num_entries > max_entries {
        return Err(format!(
            "num_entries too large for entry_size {} (max {})",
            args.entry_size, max_entries
        )
        .into());
    }

    Ok(())
}

fn print_json(report: &rms24::cost::CostReport) -> Result<(), serde_json::Error> {
    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    struct JsonReport<'a> {
        num_entries: u64,
        entry_size: usize,
        security_param: u32,
        block_size: u64,
        num_blocks: u64,
        total_hints: u64,
        client_hint_storage_bytes: u64,
        server_db_storage_bytes: u64,
        offline_bandwidth_bytes: u64,
        online_upload_bytes: u64,
        online_download_bytes: u64,
        online_query_bandwidth_bytes: u64,
        server_xor_ops_per_query: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        keyword_pir: Option<&'a rms24::cost::KeywordPirCost>,
    }

    let json_report = JsonReport {
        num_entries: report.params.num_entries,
        entry_size: report.params.entry_size,
        security_param: report.params.security_param,
        block_size: report.params.block_size,
        num_blocks: report.params.num_blocks,
        total_hints: report.params.total_hints(),
        client_hint_storage_bytes: report.client_hint_storage_bytes,
        server_db_storage_bytes: report.server_db_storage_bytes,
        offline_bandwidth_bytes: report.offline_bandwidth_bytes,
        online_upload_bytes: report.online_upload_bytes,
        online_download_bytes: report.online_download_bytes,
        online_query_bandwidth_bytes: report.online_query_bandwidth_bytes,
        server_xor_ops_per_query: report.server_xor_ops_per_query,
        keyword_pir: report.keyword_pir.as_ref(),
    };

    println!("{}", serde_json::to_string_pretty(&json_report)?);
    Ok(())
}
