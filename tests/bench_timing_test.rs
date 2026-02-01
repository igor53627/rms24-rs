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
