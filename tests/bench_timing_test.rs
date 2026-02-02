use rms24::bench_timing::TimingCounters;

#[test]
fn test_timing_summary_format() {
    let mut t = TimingCounters::new(2);
    t.add("serialize", 1500);
    t.add("serialize", 500);
    let line = t.summary_line("serialize");
    assert!(line.contains("phase=serialize"));
    assert!(line.contains("count=2"));
    assert!(line.contains("total_us=2000"));
}

#[test]
fn test_timing_helper_smoke() {
    let mut t = rms24::bench_timing::TimingCounters::new(1);
    t.add("read", 10);
    assert!(t.summary_line("read").contains("count=1"));
}

#[test]
fn test_should_log_skips_zero_count() {
    let t = TimingCounters::new(2);
    assert!(!t.should_log("phase"));
}
