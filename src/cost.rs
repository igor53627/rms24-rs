//! Cost attribution estimator for RMS24 PIR protocol.
//!
//! Computes theoretical storage, bandwidth, and computation costs
//! broken down by component, given protocol parameters.

use crate::params::Params;

const CUTOFF_BYTES: u64 = std::mem::size_of::<u32>() as u64;
const EXTRA_BLOCK_BYTES: u64 = std::mem::size_of::<u32>() as u64;
const EXTRA_OFFSET_BYTES: u64 = std::mem::size_of::<u32>() as u64;
const FLIP_BYTES: u64 = std::mem::size_of::<u8>() as u64;
const PER_HINT_META_BYTES: u64 = CUTOFF_BYTES + EXTRA_BLOCK_BYTES + EXTRA_OFFSET_BYTES + FLIP_BYTES;
const QUERY_ELEMENT_BYTES: u64 = std::mem::size_of::<(u32, u32)>() as u64;
const EXTRA_QUERY_ELEMENTS_PER_HINT: u64 = 1;
const BYTES_PER_KIB: f64 = 1024.0;
const BYTES_PER_MIB: f64 = BYTES_PER_KIB * 1024.0;

fn checked_add(a: u64, b: u64, _ctx: &'static str) -> u64 {
    (u128::from(a) + u128::from(b)).min(u128::from(u64::MAX)) as u64
}

fn checked_mul(a: u64, b: u64, _ctx: &'static str) -> u64 {
    (u128::from(a) * u128::from(b)).min(u128::from(u64::MAX)) as u64
}

/// Per-component cost breakdown for the RMS24 PIR protocol.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CostReport {
    pub params: Params,
    pub client_hint_storage_bytes: u64,
    pub server_db_storage_bytes: u64,
    pub offline_bandwidth_bytes: u64,
    pub online_query_bandwidth_bytes: u64,
    pub online_upload_bytes: u64,
    pub online_download_bytes: u64,
    pub server_xor_ops_per_query: u64,
    pub keyword_pir: Option<KeywordPirCost>,
}

/// Cost overhead from KeywordPIR cuckoo hashing.
#[derive(Clone, Debug, serde::Serialize)]
pub struct KeywordPirCost {
    pub cuckoo_table_entries: u64,
    pub cuckoo_expansion_factor: f64,
    pub queries_per_lookup: u64,
    pub total_bandwidth_per_lookup_bytes: u64,
}

/// Optional cuckoo hashing parameters for KeywordPIR cost estimation.
#[derive(Clone, Debug)]
pub struct CuckooParams {
    pub num_buckets: u64,
    pub bucket_size: u64,
    pub num_hashes: u64,
}

/// Estimate costs for RMS24 PIR with the given parameters.
///
/// The `cuckoo` argument, when provided, adds KeywordPIR overhead estimation.
pub fn estimate(params: &Params, cuckoo: Option<&CuckooParams>) -> CostReport {
    let entry_size = params.entry_size as u64;
    let total_hints = params.total_hints();
    let num_backup = params.num_backup_hints;

    // Client hint storage:
    //   Per hint: cutoff(4) + extra_block(4) + extra_offset(4) + parity(entry_size) + flip(1)
    //   Plus backup hints store an additional high-parity: num_backup × entry_size
    let per_hint_bytes = checked_add(entry_size, PER_HINT_META_BYTES, "per-hint bytes overflow");
    let client_hint_storage_bytes = checked_add(
        checked_mul(total_hints, per_hint_bytes, "client hint bytes overflow"),
        checked_mul(num_backup, entry_size, "backup high parity bytes overflow"),
        "client hint bytes overflow",
    );

    // Server DB storage: num_entries × entry_size
    let server_db_storage_bytes =
        checked_mul(params.num_entries, entry_size, "server DB bytes overflow");

    // Offline bandwidth: full DB scan during hint generation
    let offline_bandwidth_bytes = checked_mul(
        params.num_entries,
        entry_size,
        "offline bandwidth bytes overflow",
    );

    // Expected subset size: approximately num_blocks / 2 (median split)
    // Each regular hint also adds one extra entry.
    let subset_size = params.num_blocks / 2;
    let subset_elements_per_query = checked_add(
        subset_size,
        EXTRA_QUERY_ELEMENTS_PER_HINT,
        "subset element count overflow",
    );

    // Online upload per query: 2 queries (real + dummy), each sends subset as Vec<(u32, u32)>
    let online_upload_bytes = checked_mul(
        checked_mul(
            2,
            subset_elements_per_query,
            "online upload subset count overflow",
        ),
        QUERY_ELEMENT_BYTES,
        "online upload bytes overflow",
    );

    // Online download per query: 2 parity replies, each entry_size bytes
    let online_download_bytes = checked_mul(2, entry_size, "online download bytes overflow");

    // Total online bandwidth
    let online_query_bandwidth_bytes = checked_add(
        online_upload_bytes,
        online_download_bytes,
        "online query bandwidth overflow",
    );

    // Server XOR operations per query: 2 queries × subset_size entries × entry_size bytes XORed
    let server_xor_ops_per_query = checked_mul(
        checked_mul(
            2,
            subset_elements_per_query,
            "server xor subset count overflow",
        ),
        entry_size,
        "server xor operation bytes overflow",
    );

    // KeywordPIR overhead
    let keyword_pir = cuckoo.map(|c| {
        let cuckoo_table_entries = checked_mul(
            c.num_buckets,
            c.bucket_size,
            "keywordpir cuckoo table size overflow",
        );
        let cuckoo_expansion_factor = if params.num_entries > 0 {
            cuckoo_table_entries as f64 / params.num_entries as f64
        } else {
            0.0
        };
        // Each lookup checks num_hashes buckets × bucket_size positions
        let queries_per_lookup = checked_mul(
            c.num_hashes,
            c.bucket_size,
            "keywordpir queries-per-lookup overflow",
        );
        // Each position requires a full PIR query (upload + download)
        let per_query = online_query_bandwidth_bytes;
        let total_bandwidth_per_lookup_bytes = checked_mul(
            queries_per_lookup,
            per_query,
            "keywordpir bandwidth per lookup overflow",
        );

        KeywordPirCost {
            cuckoo_table_entries,
            cuckoo_expansion_factor,
            queries_per_lookup,
            total_bandwidth_per_lookup_bytes,
        }
    });

    CostReport {
        params: params.clone(),
        client_hint_storage_bytes,
        server_db_storage_bytes,
        offline_bandwidth_bytes,
        online_query_bandwidth_bytes,
        online_upload_bytes,
        online_download_bytes,
        server_xor_ops_per_query,
        keyword_pir,
    }
}

impl std::fmt::Display for CostReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== RMS24 Cost Report ===")?;
        writeln!(f, "Parameters:")?;
        writeln!(f, "  num_entries:      {}", self.params.num_entries)?;
        writeln!(f, "  entry_size:       {} B", self.params.entry_size)?;
        writeln!(f, "  security_param:   {}", self.params.security_param)?;
        writeln!(f, "  block_size:       {}", self.params.block_size)?;
        writeln!(f, "  num_blocks:       {}", self.params.num_blocks)?;
        writeln!(f, "  total_hints:      {}", self.params.total_hints())?;
        writeln!(f)?;
        writeln!(f, "Storage:")?;
        writeln!(
            f,
            "  client hints:     {} ({:.2} MiB)",
            self.client_hint_storage_bytes,
            self.client_hint_storage_bytes as f64 / BYTES_PER_MIB
        )?;
        writeln!(
            f,
            "  server DB:        {} ({:.2} MiB)",
            self.server_db_storage_bytes,
            self.server_db_storage_bytes as f64 / BYTES_PER_MIB
        )?;
        writeln!(f)?;
        writeln!(f, "Bandwidth:")?;
        writeln!(
            f,
            "  offline (hint gen): {} ({:.2} MiB)",
            self.offline_bandwidth_bytes,
            self.offline_bandwidth_bytes as f64 / BYTES_PER_MIB
        )?;
        writeln!(
            f,
            "  online upload/q:    {} ({:.2} KiB)",
            self.online_upload_bytes,
            self.online_upload_bytes as f64 / BYTES_PER_KIB
        )?;
        writeln!(
            f,
            "  online download/q:  {} ({:.2} KiB)",
            self.online_download_bytes,
            self.online_download_bytes as f64 / BYTES_PER_KIB
        )?;
        writeln!(
            f,
            "  online total/q:     {} ({:.2} KiB)",
            self.online_query_bandwidth_bytes,
            self.online_query_bandwidth_bytes as f64 / BYTES_PER_KIB
        )?;
        writeln!(f)?;
        writeln!(f, "Computation:")?;
        writeln!(
            f,
            "  server XOR ops/q:   {} ({:.2} KiB)",
            self.server_xor_ops_per_query,
            self.server_xor_ops_per_query as f64 / BYTES_PER_KIB
        )?;

        if let Some(kp) = &self.keyword_pir {
            writeln!(f)?;
            writeln!(f, "KeywordPIR:")?;
            writeln!(f, "  cuckoo entries:     {}", kp.cuckoo_table_entries)?;
            writeln!(
                f,
                "  expansion factor:   {:.2}x",
                kp.cuckoo_expansion_factor
            )?;
            writeln!(f, "  queries/lookup:     {}", kp.queries_per_lookup)?;
            writeln!(
                f,
                "  bandwidth/lookup:   {} ({:.2} KiB)",
                kp.total_bandwidth_per_lookup_bytes,
                kp.total_bandwidth_per_lookup_bytes as f64 / BYTES_PER_KIB
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_estimate() {
        let params = Params::new(10_000, 40, 128);
        let report = estimate(&params, None);

        assert_eq!(report.server_db_storage_bytes, 10_000 * 40);
        assert_eq!(report.offline_bandwidth_bytes, 10_000 * 40);
        assert!(report.keyword_pir.is_none());
    }

    #[test]
    fn test_client_hint_storage() {
        let params = Params::new(10_000, 40, 128);
        let report = estimate(&params, None);

        let total_hints = params.total_hints();
        let per_hint = PER_HINT_META_BYTES + 40; // cutoff + extra_block + extra_offset + parity + flip
        let expected = total_hints * per_hint + params.num_backup_hints * 40;
        assert_eq!(report.client_hint_storage_bytes, expected);
    }

    #[test]
    fn test_online_bandwidth() {
        let params = Params::new(10_000, 40, 128);
        let report = estimate(&params, None);

        let subset_size = params.num_blocks / 2;
        assert_eq!(
            report.online_upload_bytes,
            2 * (subset_size + EXTRA_QUERY_ELEMENTS_PER_HINT) * QUERY_ELEMENT_BYTES
        );
        assert_eq!(report.online_download_bytes, 2 * 40);
        assert_eq!(
            report.online_query_bandwidth_bytes,
            report.online_upload_bytes + report.online_download_bytes
        );
    }

    #[test]
    fn test_server_xor_ops() {
        let params = Params::new(10_000, 40, 128);
        let report = estimate(&params, None);

        let subset_size = params.num_blocks / 2;
        assert_eq!(
            report.server_xor_ops_per_query,
            2 * (subset_size + EXTRA_QUERY_ELEMENTS_PER_HINT) * 40
        );
    }

    #[test]
    fn test_keyword_pir_cost() {
        let params = Params::new(10_000, 40, 128);
        let cuckoo = CuckooParams {
            num_buckets: 8192,
            bucket_size: 2,
            num_hashes: 2,
        };
        let report = estimate(&params, Some(&cuckoo));

        let kp = report.keyword_pir.as_ref().unwrap();
        assert_eq!(kp.cuckoo_table_entries, 8192 * 2);
        assert_eq!(kp.queries_per_lookup, 2 * 2);
        assert!(kp.cuckoo_expansion_factor > 1.0);
        assert_eq!(
            kp.total_bandwidth_per_lookup_bytes,
            kp.queries_per_lookup * report.online_query_bandwidth_bytes
        );
    }

    #[test]
    fn test_small_db() {
        let params = Params::new(100, 40, 40);
        let report = estimate(&params, None);

        assert_eq!(report.server_db_storage_bytes, 100 * 40);
        assert!(report.client_hint_storage_bytes > 0);
        assert!(report.online_upload_bytes > 0);
    }

    #[test]
    fn test_single_entry() {
        let params = Params::new(1, 40, 1);
        let report = estimate(&params, None);

        assert_eq!(report.server_db_storage_bytes, 1 * 40);
        assert_eq!(report.offline_bandwidth_bytes, 1 * 40);
    }

    #[test]
    fn test_keyword_pir_large_expansion() {
        let params = Params::new(100, 40, 40);
        let cuckoo = CuckooParams {
            num_buckets: 1000,
            bucket_size: 2,
            num_hashes: 2,
        };
        let report = estimate(&params, Some(&cuckoo));
        let kp = report.keyword_pir.as_ref().unwrap();
        assert_eq!(kp.cuckoo_table_entries, 2000);
        assert!((kp.cuckoo_expansion_factor - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_display_does_not_panic() {
        let params = Params::new(10_000, 40, 128);
        let cuckoo = CuckooParams {
            num_buckets: 8192,
            bucket_size: 2,
            num_hashes: 2,
        };
        let report = estimate(&params, Some(&cuckoo));
        let output = format!("{}", report);
        assert!(output.contains("RMS24 Cost Report"));
        assert!(output.contains("KeywordPIR"));
    }
}
