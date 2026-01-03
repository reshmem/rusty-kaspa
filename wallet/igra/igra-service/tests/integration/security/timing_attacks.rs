use std::time::Instant;
use subtle::ConstantTimeEq;

fn mean(values: &[u128]) -> f64 {
    values.iter().map(|&v| v as f64).sum::<f64>() / values.len() as f64
}

fn stddev(values: &[u128], mean: f64) -> f64 {
    let variance = values
        .iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

#[test]
fn test_constant_time_hash_comparison() {
    let hash1 = [0u8; 32];
    let hash2_match = [0u8; 32];
    let hash2_differ_early = [255u8; 32];
    let mut hash2_differ_late = [0u8; 32];
    hash2_differ_late[31] = 1;

    for _ in 0..1000 {
        let _ = bool::from(hash1.ct_eq(&hash2_match));
        let _ = bool::from(hash1.ct_eq(&hash2_differ_early));
        let _ = bool::from(hash1.ct_eq(&hash2_differ_late));
    }

    let mut match_times = Vec::with_capacity(5000);
    let mut differ_early_times = Vec::with_capacity(5000);
    let mut differ_late_times = Vec::with_capacity(5000);

    for _ in 0..5000 {
        let start = Instant::now();
        let _ = bool::from(hash1.ct_eq(&hash2_match));
        match_times.push(start.elapsed().as_nanos());
    }
    for _ in 0..5000 {
        let start = Instant::now();
        let _ = bool::from(hash1.ct_eq(&hash2_differ_early));
        differ_early_times.push(start.elapsed().as_nanos());
    }
    for _ in 0..5000 {
        let start = Instant::now();
        let _ = bool::from(hash1.ct_eq(&hash2_differ_late));
        differ_late_times.push(start.elapsed().as_nanos());
    }

    let match_mean = mean(&match_times);
    let early_mean = mean(&differ_early_times);
    let late_mean = mean(&differ_late_times);

    let match_stddev = stddev(&match_times, match_mean);
    let early_stddev = stddev(&differ_early_times, early_mean);
    let late_stddev = stddev(&differ_late_times, late_mean);

    println!(
        "Match: mean={:.2}ns stddev={:.2}ns | Early diff: mean={:.2}ns stddev={:.2}ns | Late diff: mean={:.2}ns stddev={:.2}ns",
        match_mean, match_stddev, early_mean, early_stddev, late_mean, late_stddev
    );

    let early_diff_pct = ((match_mean - early_mean).abs() / match_mean) * 100.0;
    let late_diff_pct = ((match_mean - late_mean).abs() / match_mean) * 100.0;
    let early_vs_late_pct = ((early_mean - late_mean).abs() / early_mean) * 100.0;

    assert!(
        early_diff_pct < 25.0,
        "early byte timing difference: {:.2}%",
        early_diff_pct
    );
    assert!(
        late_diff_pct < 25.0,
        "late byte timing difference: {:.2}%",
        late_diff_pct
    );
    assert!(
        early_vs_late_pct < 25.0,
        "early vs late timing difference: {:.2}%",
        early_vs_late_pct
    );
}
