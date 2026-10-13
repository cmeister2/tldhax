//! Representative offline assessment throughput benchmark.

use std::hint::black_box;
use std::time::Instant;
use tldhax::Registry;

/// Measure a small mixed corpus with explanations enabled.
fn main() {
    if cfg!(debug_assertions) || std::env::args().any(|arg| arg == "--test") {
        return;
    }
    let registry = Registry::new();
    let candidates = [
        "sunflower.com",
        "sunflower.co.uk",
        "bücher.de",
        "icann.com",
        "_bad.com",
        "sunflower.zzz",
    ];
    let iterations = 100_000;
    let started = Instant::now();
    for _ in 0..iterations {
        for domain in candidates {
            let _ = black_box(registry.assess(black_box(domain), None));
        }
    }
    let count = iterations * candidates.len();
    println!(
        "{count} assessments in {:?}: {:.0} assessments/second",
        started.elapsed(),
        count as f64 / started.elapsed().as_secs_f64()
    );
}
