"""Release benchmark contract guards; no synthetic timing claims or provider calls."""

from pathlib import Path

import pytest
from tools.release_benchmark import ascii_domains, checkout_hash, corpus, require_api


def test_corpus_preserves_unicode_and_explicit_negative_profile(tmp_path: Path) -> None:
    """The authored workload distinguishes an omitted profile from false facts."""
    source = tmp_path / "cases.txt"
    source.write_text(
        'idn\tbücher.de\tnull\nnegative\tvanity.me.uk\t{"resident":false}\n',
        encoding="utf-8",
    )
    assert corpus(source) == [
        ("idn", "bücher.de", None),
        ("negative", "vanity.me.uk", {"resident": False}),
    ]


@pytest.mark.parametrize(
    "value",
    [
        "",
        "tag\tdomain\n",
        "tag\tdomain\ttrue\n",
        "tag\tdomain\tnull\ntag\tother\tnull\n",
    ],
)
def test_corrupt_corpus_cannot_silently_change_the_workload(
    tmp_path: Path, value: str
) -> None:
    """Missing cases, field corruption and duplicate identities fail explicitly."""
    source = tmp_path / "cases.txt"
    source.write_text(value, encoding="utf-8")
    with pytest.raises(ValueError):
        corpus(source)


def test_old_api_fails_instead_of_substituting_a_loop_for_batch() -> None:
    """A legacy registry cannot produce a misleading release performance report."""
    with pytest.raises(RuntimeError, match="Registry.assess"):
        require_api(object())


def test_ascii_batch_excludes_both_idn_spellings_and_profile_preparation() -> None:
    """An all-ASCII A-label spelling still exercises internationalised-name work."""
    assert ascii_domains(
        [
            ("plain", "vanity.com", None),
            ("ulabel", "bücher.de", None),
            ("alabel", "XN--BCHER-KVA.de", None),
            ("idn_suffix", "vanity.xn--fiqs8s", None),
            ("profile", "vanity.me.uk", {"resident": False}),
        ]
    ) == ["vanity.com"]


def test_checkout_fingerprint_tracks_policy_bytes_and_excludes_hidden_input(
    tmp_path: Path,
) -> None:
    """Source identity includes authoring content and never reads developer secrets."""
    for name in ("Cargo.toml", "Cargo.lock", "build.rs"):
        (tmp_path / name).write_text("fixture", encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "fixture.toml").write_text("version=1", encoding="utf-8")
    (tmp_path / ".env").write_text("private-fixture", encoding="utf-8")
    before = checkout_hash(tmp_path)
    (tmp_path / ".env").write_text("changed-private-fixture", encoding="utf-8")
    assert checkout_hash(tmp_path) == before
    (rules / "fixture.toml").write_text("version=2", encoding="utf-8")
    assert checkout_hash(tmp_path) != before
