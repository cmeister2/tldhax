# tldhax

Offline domain registrability against direct name and declared-profile requirements.

The Rust core returns yes, no or unknown, with actionable reasons. Registration availability and transaction approval belong to the caller. Unsupported policies and missing declarations remain unknown.

    use tldhax::Registry;
    let registry = Registry::new();
    let result = registry.assess("sunflower.com", None).unwrap();
    println!("{}", result.decision.as_str());
    for reason in result.reasons { println!("{}", reason.message); }

This review boundary contains the Rust implementation. Python and CLI interfaces are added in the following interface PR.
