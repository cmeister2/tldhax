# tldhax

Offline domain registration checks. The existing Python Registry/check/info/stats API and CLI remain available.

The Rust engine evaluates direct name and declared-profile requirements and returns yes/no/unknown with reasons. Unsupported policy remains unknown; retained legacy rule files supply inventory without automatically approving registration. The following interface PR adds public Python profile assessment and batches.

    from tldhax import Registry
    registry = Registry()
    result = registry.check("sunflower.com")
    print(result.status, result.reasons)

Build and test with pip install .[dev], cargo test --all-targets and pytest.
