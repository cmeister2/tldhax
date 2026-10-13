//! Per-request latency and separately instrumented allocation baseline.

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::hint::black_box;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use tldhax::Registry;

/// Count allocation requests only during the untimed second pass.
struct CountingAllocator;
/// Enable request counting only during the separate allocation measurement pass.
static COUNTING: AtomicBool = AtomicBool::new(false);
/// Allocation and reallocation request count for the current corpus case.
static CALLS: AtomicUsize = AtomicUsize::new(0);
/// Requested bytes across allocations and reallocations for the current corpus case.
static BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            CALLS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            CALLS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(size, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
}

/// System allocator wrapper that counts requests while instrumentation is enabled.
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Read an unsigned environment setting, falling back to its default when absent.
fn setting(name: &str, default: usize) -> usize {
    std::env::var(name)
        .map(|value| {
            value
                .parse::<usize>()
                .expect("benchmark setting must be an integer")
        })
        .unwrap_or(default)
}

/// Select the nearest-rank percentile from a sorted, nonempty nanosecond sample.
fn percentile(sorted: &[u64], percent: usize) -> u64 {
    sorted[(sorted.len() * percent).div_ceil(100) - 1]
}

/// Emit release lookup latency and allocation measurements with corpus and build metadata.
fn main() {
    // `cargo test --all-targets` verifies compilation, without measuring debug builds.
    if cfg!(debug_assertions) || std::env::args().any(|argument| argument == "--test") {
        return;
    }
    let dataset_hash = std::env::var("TLDHAX_DATASET_SHA256")
        .expect("set TLDHAX_DATASET_SHA256 to the audit corpus_sha256");
    let corpus_hash = std::env::var("TLDHAX_CORPUS_SHA256")
        .expect("set TLDHAX_CORPUS_SHA256 to SHA-256 of benches/domains.txt");
    let samples = setting("TLDHAX_BENCH_SAMPLES", 10_000);
    let warmup = setting("TLDHAX_BENCH_WARMUP", 1_000);
    assert!(samples >= 100, "at least 100 samples are required for p99");
    let corpus = include_str!("domains.txt")
        .lines()
        .map(|line| {
            line.split_once('\t')
                .expect("case must contain tag and domain")
        })
        .collect::<Vec<_>>();
    let registry = Registry::new();
    let started = Instant::now();
    let first_result = black_box(registry.check(black_box(corpus[0].1)));
    let first_call_ns = started.elapsed().as_nanos() as u64;
    drop(first_result);
    for _ in 0..warmup {
        for (_, domain) in &corpus {
            black_box(registry.check(black_box(domain)));
        }
    }
    let mut timings = (0..corpus.len())
        .map(|_| Vec::with_capacity(samples))
        .collect::<Vec<Vec<u64>>>();
    for cycle in 0..samples {
        // Rotate the leading case to avoid always giving one class the same position.
        for offset in 0..corpus.len() {
            let index = (cycle + offset) % corpus.len();
            let started = Instant::now();
            let result = black_box(registry.check(black_box(corpus[index].1)));
            timings[index].push(started.elapsed().as_nanos() as u64);
            drop(result);
        }
    }
    let cases = corpus.iter().enumerate().map(|(index, (tag, domain))| {
        timings[index].sort_unstable();
        CALLS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
        COUNTING.store(true, Ordering::Relaxed);
        for _ in 0..samples {
            black_box(registry.check(black_box(domain)));
        }
        COUNTING.store(false, Ordering::Relaxed);
        serde_json::json!({
            "case": tag, "domain": domain,
            "status": registry.check(domain).status.as_str(),
            "p50_ns": percentile(&timings[index], 50),
            "p99_ns": percentile(&timings[index], 99),
            "min_ns": timings[index][0],
            "max_ns": timings[index][samples - 1],
            "allocation_requests_per_check": CALLS.load(Ordering::Relaxed) as f64 / samples as f64,
            "requested_bytes_per_check": BYTES.load(Ordering::Relaxed) as f64 / samples as f64,
        })
    }).collect::<Vec<_>>();
    let cpu = fs::read_to_string("/proc/cpuinfo").ok().and_then(|text| {
        text.lines()
            .find(|line| line.starts_with("model name"))
            .and_then(|line| line.split_once(':'))
            .map(|(_, value)| value.trim().to_owned())
    });
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    let executable_bytes = std::env::current_exe()
        .ok()
        .and_then(|path| fs::metadata(path).ok())
        .map(|metadata| metadata.len());
    let report = serde_json::json!({
        "report_schema": 1, "api": "Registry.check (legacy detailed)",
        "dataset_sha256": dataset_hash, "corpus_sha256": corpus_hash,
        "revision": revision, "cpu": cpu,
        "architecture": std::env::consts::ARCH, "os": std::env::consts::OS,
        "rustc": rustc, "debug_assertions": cfg!(debug_assertions),
        "rustflags": option_env!("RUSTFLAGS").unwrap_or(""),
        "cargo_encoded_rustflags": option_env!("CARGO_ENCODED_RUSTFLAGS").unwrap_or(""),
        "samples_per_case": samples, "warmup_per_case": warmup,
        "first_call_ns": first_call_ns, "first_call_domain": corpus[0].1,
        "measurement": "Individual monotonic-clock calls; result destruction excluded. Allocation counters enabled only in a separate untimed pass; allocator instrumentation branches remain during timings.",
        "allocation_metric": "alloc/realloc requests and requested sizes; excludes deallocation and is not peak/live memory",
        "compiled_rules": tldhax::TLD_RULES.len(),
        "rule_struct_payload_bytes": tldhax::TLD_RULES.len() * std::mem::size_of::<tldhax::TldRule>(),
        "size_metric": "struct payload lower bound excludes PHF, strings, shared data and Unicode dependencies; executable size is separate",
        "executable_bytes": executable_bytes, "cases": cases,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
}
