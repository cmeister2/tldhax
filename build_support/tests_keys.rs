//! Calendar, canonical identity and pinned-date applicability fixtures.

use super::{keys, schema};

#[test]
fn calendar_validation_checks_leap_years_and_exact_spelling() {
    for valid in ["2024-02-29", "2000-02-29", "2026-10-12", "0001-01-01"] {
        assert!(keys::date(valid).is_ok(), "{valid}");
    }
    for invalid in [
        "1900-02-29",
        "2026-02-29",
        "2026-04-31",
        "2026-13-01",
        "0000-01-01",
        "2026-00-01",
        "2026-01-00",
        "2026-1-01",
        "2026-01-01 ",
    ] {
        assert!(keys::date(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn authored_keys_share_registration_normalization() {
    assert_eq!(keys::selector("É.FIXTURE.").unwrap(), "xn--9ca.fixture");
    assert_eq!(keys::selector("*.É.fixture").unwrap(), "*.xn--9ca.fixture");
    assert_eq!(keys::selector("l·l.fixture").unwrap(), "xn--ll-0ea.fixture");
    for invalid in [
        "!city.fixture",
        "x.*.fixture",
        "a·b.fixture",
        "a..fixture",
        "ab--cd",
    ] {
        assert!(keys::selector(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn stable_record_ids_are_unique_and_machine_safe() {
    assert!(keys::unique(&["rule.one", "rule-two"], |id| id, "rule").is_ok());
    for invalid in [vec![""], vec!["é"], vec!["one", "one"], vec!["two words"]] {
        assert!(keys::unique(&invalid, |id| id, "rule").is_err());
    }
}

#[test]
fn explicit_current_attestation_and_exclusive_end_control_activation() {
    let today = "2026-10-12";
    assert_eq!(
        keys::temporal(None, None, None, today).unwrap(),
        Some("applicability_unknown")
    );
    assert_eq!(
        keys::temporal(None, Some(today), None, today).unwrap(),
        None
    );
    assert_eq!(
        keys::temporal(Some("2027-02-09"), None, None, today).unwrap(),
        Some("future_effective")
    );
    assert_eq!(
        keys::temporal(Some("2020-01-01"), None, Some(today), today).unwrap(),
        Some("no_longer_effective")
    );
    assert!(keys::temporal(Some(today), None, Some(today), today).is_err());
    assert!(keys::temporal(Some(today), Some("2026-10-11"), None, today).is_err());
}

#[test]
fn future_and_expired_reviews_cannot_approve_current_policy() {
    let mut assertion: schema::Assertion = serde_json::from_str(
        r#"{
        "id":"fixture.rule","source_id":"fixture.source","locator":"clause 1",
        "operation":"new_registration","namespaces":["fixture"],"forms":[1],
        "input_class":"any","family":"length","effect":"require","knowledge":"reviewed",
        "interpretation":"synthetic","reviewer":"fixture","reviewed_on":"2026-10-12",
        "review_due":"2027-10-12","effective_from":"2020-01-01"
    }"#,
    )
    .unwrap();
    assert!(
        keys::assertion_status(&assertion, "2026-10-12")
            .unwrap()
            .active
    );
    assertion.reviewed_on = "2026-10-13".into();
    assert_eq!(
        keys::assertion_status(&assertion, "2026-10-12")
            .unwrap()
            .reason
            .as_deref(),
        Some("future_review")
    );
    assertion.reviewed_on = "2026-01-01".into();
    assertion.review_due = "2026-10-11".into();
    let expired = keys::assertion_status(&assertion, "2026-10-12").unwrap();
    assert!(!expired.active);
    assert_eq!(expired.knowledge, schema::Knowledge::Unknown);
    assertion.effective_from = Some("2027-02-09".into());
    assertion.knowledge = schema::Knowledge::Conflicting;
    assert_eq!(
        keys::assertion_status(&assertion, "2026-10-12")
            .unwrap()
            .reason
            .as_deref(),
        Some("future_effective")
    );
}
