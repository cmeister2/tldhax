"""Recorded response shapes and fake HTTP only; no environment or network."""

import pytest
from tools.oracle.config import load_credentials
from tools.oracle.models import canonical_name


def test_environment_precedence_and_no_implicit_file(tmp_path, monkeypatch):
    """Environment precedence and no implicit file."""
    (tmp_path / ".env").write_text(
        "NAMECOM_USERNAME=local\nNAMECOM_API_TOKEN=filetoken\n"
    )
    monkeypatch.chdir(tmp_path)
    assert load_credentials(environ={}) == []
    credentials = load_credentials(
        tmp_path / ".env", {"NAMECOM_API_TOKEN": "envtoken"}
    )[0]
    assert credentials.username == "local" and credentials.token == "envtoken"
    assert "envtoken" not in repr(credentials) and "local" not in repr(credentials)
    with pytest.raises(ValueError, match="requires"):
        load_credentials(environ={"NAMECOM_USERNAME": "partial"})


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("BÜCHER.com.", "xn--bcher-kva.com"),
        ("faß.de", "xn--fa-hia.de"),
        ("_bad.com", None),
        ("a..com", None),
        (" a.com", None),
        ("bad.com..", None),
    ],
)
def test_strict_identity(name, expected):
    """Strict identity."""
    assert canonical_name(name) == expected


@pytest.mark.parametrize(
    "metadata",
    [
        {"namespace": []},
        {"stratum": []},
        {"evidence_ids": "not-a-list"},
        {"evidence_ids": [1]},
        {"offline_validity": []},
    ],
)
def test_invalid_candidate_metadata_is_rejected_before_dispatch(metadata):
    """Optional profile-free research metadata must have its documented types."""
    from tools.oracle.models import Candidate

    with pytest.raises(ValueError):
        Candidate("a.com", **metadata)


def test_redact_full_basic_value_before_short_overlapping_secrets():
    """Remove encoded credentials wholly before a short token can fragment the match."""
    import base64

    from tools.oracle.models import Redactor

    username, token = "user", "d"
    encoded = base64.b64encode(f"{username}:{token}".encode()).decode()
    assert encoded.startswith(token)
    assert Redactor((token, username), (username, token)).clean(encoded) == "[REDACTED]"
