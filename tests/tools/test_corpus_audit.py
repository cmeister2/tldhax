"""Exercise authoring audit semantics independently of the full live corpus."""

from pathlib import Path

import pytest
from tools.corpus_audit import audit, canonical_key, fingerprint


def test_audit_preserves_selectors_and_does_not_claim_review(tmp_path: Path) -> None:
    """URLs and empty explicit values are presence metrics, not policy proof."""
    (tmp_path / "fixture.toml").write_text(
        """[[domains]]
tld = "食狮.com.cn"
registerable = "yes"
banned = []
[domains.sources]
registerable = "https://example.org/delegation"
[[domains]]
tld = "xn--85x722f.com.cn"
[[domains]]
tld = "*.ck"
[[domains]]
tld = "!www.ck"
[[domains]]
tld = "www.ck"
[[domains]]
tld = "www.ck"
""",
        encoding="utf-8",
    )
    report = audit(tmp_path)
    assert report["inventory"]["raw_entries"] == 6
    assert report["inventory"]["distinct_raw_keys"] == 5
    assert report["inventory"]["distinct_canonical_selector_keys"] == 4
    assert report["canonical_collisions"] == {
        "xn--85x722f.com.cn": ["xn--85x722f.com.cn", "食狮.com.cn"]
    }
    assert report["inventory"]["wildcards"] == 1
    assert report["inventory"]["exceptions"] == 1
    assert report["field_presence"]["banned"] == {"explicit": 1, "source_link": 0}
    assert report["evidence_assessment"]["reviewed_policy_coverage"] is None
    assert "www.ck" in report["duplicate_raw_keys"]
    assert audit(tmp_path) == report


def test_hash_tracks_paths_and_exact_content(tmp_path: Path) -> None:
    """Whitespace and authoring filenames affect the reproducible snapshot ID."""
    path = tmp_path / "a.toml"
    path.write_text('[[domains]]\ntld = "com"\n', encoding="utf-8")
    original = fingerprint(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert fingerprint(tmp_path) != original
    changed = fingerprint(tmp_path)
    path.rename(tmp_path / "b.toml")
    assert fingerprint(tmp_path) != changed


def test_invalid_selector_is_reported_and_bad_document_fails(tmp_path: Path) -> None:
    """Mapping errors cannot erase entries; malformed documents fail the audit."""
    path = tmp_path / "bad.toml"
    path.write_text('[[domains]]\ntld = "_invalid.com"\n', encoding="utf-8")
    report = audit(tmp_path)
    assert report["inventory"]["raw_entries"] == 1
    assert report["invalid_selector_keys"][0]["raw"] == "_invalid.com"
    path.write_text("[[domains]]\ntld = [\n", encoding="utf-8")
    with pytest.raises(ValueError):
        audit(tmp_path)


def test_nontransitional_idna_and_marker_identity() -> None:
    """Sharp-s stays distinct from ss; exception and literal keys stay distinct."""
    assert canonical_key("faß.de") == "xn--fa-hia.de"
    assert canonical_key("WWW.CK") == "www.ck"
    assert canonical_key("!www.ck") != canonical_key("www.ck")
