"""Git checkout must preserve the bytes used by authoritative fingerprints."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def test_autocrlf_checkout_preserves_hashed_inputs(tmp_path: Path) -> None:
    """Exercise real checkout conversion, including a CRLF upstream snapshot."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is required to test checkout byte preservation")
    repository = tmp_path / "source"
    repository.mkdir()
    env = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }

    def run(*args: str) -> None:
        subprocess.run(
            [git, *args],
            cwd=repository,
            env=env,
            check=True,
            capture_output=True,
            timeout=30,
        )

    run("init", "--quiet")
    attributes = Path(__file__).resolve().parents[2] / ".gitattributes"
    shutil.copyfile(attributes, repository / ".gitattributes")
    originals = {
        "data/root/pinned.txt": b"PINNED\nSOURCE\n",
        "data/special-use/upstream.csv": b"Name,Reference\r\nexample,[RFC2606]\r\n",
        "rules/namespaces/fixture.toml": b"schema_version=2\n",
        "evidence/sources.toml": b"schema_version=2\n",
    }
    for name, content in {**originals, "ordinary.rs": b"// ordinary text\n"}.items():
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    run("-c", "core.autocrlf=false", "add", ".")
    run(
        "-c",
        "user.name=Checkout fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "--no-gpg-sign",
        "-m",
        "Synthetic byte-preservation fixture",
    )
    checkout = tmp_path / "checkout"
    run("-c", "core.autocrlf=true", "clone", "--quiet", str(repository), str(checkout))
    # The control proves conversion ran, rather than inheriting a disabled config.
    assert (checkout / "ordinary.rs").read_bytes() == b"// ordinary text\r\n"
    for name, content in originals.items():
        assert (checkout / name).read_bytes() == content, name
