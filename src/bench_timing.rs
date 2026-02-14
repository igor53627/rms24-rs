use std::collections::HashMap;

#[derive(Default)]
pub struct TimingCounters {
    counts: HashMap<String, u64>,
    totals_us: HashMap<String, u64>,
    log_every: u64,
}

impl TimingCounters {
    pub fn new(log_every: u64) -> Self {
        Self {
            counts: HashMap::new(),
            totals_us: HashMap::new(),
            log_every,
        }
    }

    pub fn add(&mut self, phase: &str, micros: u64) {
        *self.counts.entry(phase.to_string()).or_insert(0) += 1;
        *self.totals_us.entry(phase.to_string()).or_insert(0) += micros;
    }

    pub fn summary_line(&self, phase: &str) -> String {
        let count = *self.counts.get(phase).unwrap_or(&0);
        let total = *self.totals_us.get(phase).unwrap_or(&0);
        let avg = if count == 0 { 0 } else { total / count };
        format!(
            "timing phase={} count={} total_us={} avg_us={}",
            phase, count, total, avg
        )
    }

    pub fn should_log(&self, phase: &str) -> bool {
        let count = *self.counts.get(phase).unwrap_or(&0);
        self.log_every > 0 && count > 0 && count.is_multiple_of(self.log_every)
    }
}
