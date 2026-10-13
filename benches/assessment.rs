//! Release per-call compact latency and untimed allocation instrumentation.
#![allow(clippy::missing_docs_in_private_items)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use tldhax::{profile::RegistrantProfile, Registry};

struct Counter;
static COUNT: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNT.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNT.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(size, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Counter = Counter;

struct Case {
    tag: &'static str,
    domain: &'static str,
    profile: Option<RegistrantProfile>,
    preparation_ns: Option<u64>,
    include_private: bool,
}

fn setting(key: &str, default: usize) -> usize {
    std::env::var(key)
        .map(|value| value.parse().expect("integer benchmark setting"))
        .unwrap_or(default)
}

fn quantile(sorted: &[u64], percent: usize) -> u64 {
    sorted[(sorted.len() * percent).div_ceil(100) - 1]
}

fn command(program: &str, arguments: &[&str]) -> Option<String> {
    std::process::Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    if cfg!(debug_assertions) || std::env::args().any(|argument| argument == "--test") {
        return;
    }
    let samples = setting("TLDHAX_BENCH_SAMPLES", 10_000);
    let warmup = setting("TLDHAX_BENCH_WARMUP", 1_000);
    assert!(samples >= 100, "p99 requires at least 100 samples");
    let corpus_hash = std::env::var("TLDHAX_CORPUS_SHA256")
        .expect("set SHA-256 of benches/assessment_domains.txt");
    assert!(corpus_hash.len() == 64 && corpus_hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let registry = Registry::new();
    let started = Instant::now();
    let first = black_box(registry.assess(black_box("sunflower.com"), None));
    let first_call_ns = started.elapsed().as_nanos() as u64;
    drop(first);
    let cases = include_str!("assessment_domains.txt")
        .lines()
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 3, "tag, domain, JSON profile required");
            let started = Instant::now();
            let profile = (fields[2] != "null").then(|| {
                registry
                    .prepare_registrant(fields[2])
                    .expect("synthetic benchmark profile")
            });
            let preparation_ns = profile
                .as_ref()
                .map(|_| started.elapsed().as_nanos() as u64);
            Case {
                tag: fields[0],
                domain: fields[1],
                profile,
                preparation_ns,
                include_private: fields[0] == "private_classification",
            }
        })
        .collect::<Vec<_>>();
    for _ in 0..warmup {
        for case in &cases {
            black_box(registry.assess_with_private(
                black_box(case.domain),
                case.profile.as_ref(),
                case.include_private,
            ));
        }
    }
    let mut timings = cases
        .iter()
        .map(|_| Vec::with_capacity(samples))
        .collect::<Vec<Vec<u64>>>();
    for cycle in 0..samples {
        for offset in 0..cases.len() {
            let index = (cycle + offset) % cases.len();
            let case = &cases[index];
            let started = Instant::now();
            let result = black_box(registry.assess_with_private(
                black_box(case.domain),
                case.profile.as_ref(),
                case.include_private,
            ));
            timings[index].push(started.elapsed().as_nanos() as u64);
            drop(result);
        }
    }
    let reports = cases.iter().enumerate().map(|(index, case)| {
        timings[index].sort_unstable();
        ALLOCS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
        COUNT.store(true, Ordering::Relaxed);
        for _ in 0..samples { black_box(registry.assess_with_private(black_box(case.domain), case.profile.as_ref(), case.include_private)); }
        COUNT.store(false, Ordering::Relaxed);
        let result = registry.assess_with_private(case.domain, case.profile.as_ref(), case.include_private);
        serde_json::json!({
            "case":case.tag, "domain":case.domain, "prepared_profile":case.profile.is_some(),
            "include_private":case.include_private,
            "private_suffix":result.private.and_then(|route|result.route_suffix(route)),
            "profile_preparation_ns":case.preparation_ns,
            "name_validity":result.name_validity.as_str(), "status":result.summary.as_str(),
            "policy_coverage":result.policy_coverage.as_str(), "eligibility":result.eligibility.as_str(),
            "p50_ns":quantile(&timings[index],50), "p99_ns":quantile(&timings[index],99),
            "min_ns":timings[index][0], "max_ns":timings[index][samples-1],
            "allocation_requests_per_call":ALLOCS.load(Ordering::Relaxed) as f64 / samples as f64,
            "requested_bytes_per_call":BYTES.load(Ordering::Relaxed) as f64 / samples as f64,
        })
    }).collect::<Vec<_>>();
    let dataset = registry.dataset();
    let payload = std::mem::size_of_val(dataset.namespaces)
        + std::mem::size_of_val(dataset.rules)
        + std::mem::size_of_val(dataset.sources)
        + std::mem::size_of_val(dataset.assertions);
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("model name"))
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_owned())
        });
    let report = serde_json::json!({
        "report_schema":2, "api":"Registry.assess_with_private (compact)", "dataset_version":dataset.version,
        "evaluation_date":dataset.evaluation_date, "inventory_date":dataset.inventory_date,
        "normalization_profile":dataset.normalization_profile, "corpus_sha256":corpus_hash,
        "revision":command("git", &["rev-parse","HEAD"]), "cpu":cpu,
        "rustc":command("rustc", &["--version"]), "architecture":std::env::consts::ARCH, "os":std::env::consts::OS,
        "debug_assertions":cfg!(debug_assertions), "rustflags":option_env!("RUSTFLAGS").unwrap_or(""),
        "cargo_encoded_rustflags":option_env!("CARGO_ENCODED_RUSTFLAGS").unwrap_or(""),
        "samples_per_case":samples, "warmup_per_case":warmup, "first_call_ns":first_call_ns,
        "first_call_domain":"sunflower.com", "compiled_rules":dataset.rules.len(),
        "first_call_api":"Registry.assess",
        "published_namespaces":dataset.namespaces.len(), "policy_evidence_struct_payload_bytes":payload,
        "size_metric":"Namespace/rule/source/assertion struct payload lower bound; excludes strings, predicate children, other tables, routing and Unicode dependencies",
        "executable_bytes":std::env::current_exe().ok().and_then(|path|std::fs::metadata(path).ok()).map(|metadata|metadata.len()),
        "measurement":"Rotated individual monotonic-clock calls through return exclude result destruction. Allocations measured in a separate untimed pass; instrumentation branches remain during timing. First call precedes profile preparation; prepared profile parsing is timed separately.",
        "allocation_metric":"alloc/realloc requests and requested sizes, not peak/live memory",
        "cases":reports,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize benchmark")
    );
}
