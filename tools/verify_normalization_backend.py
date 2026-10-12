"""Verify a real offline downstream consumer and refuse an older IDNA backend."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

PROBE = """use subject::normalization::{normalize, NORMALIZATION_PROFILE};
fn main() {
    let unicode = normalize("bücher.com").unwrap();
    let ascii = normalize("XN--BCHER-KVA.COM").unwrap();
    assert_eq!(unicode.ascii(), "xn--bcher-kva.com");
    assert_eq!(unicode.ascii(), ascii.ascii());
    assert_eq!(ascii.unicode().unwrap(), "bücher.com");
    assert!(normalize("l·l.com").is_ok());
    assert!(normalize("a·b.com").is_err());
    assert!(normalize("xn--ab-0ea.com").is_err());
    println!("{NORMALIZATION_PROFILE}");
}
"""


def run(
    root: Path, library: Path, package: str, old_backend: bool
) -> subprocess.CompletedProcess[str]:
    """Create a consumer outside the library; its lockfile resolves independently."""
    (root / "src").mkdir(parents=True)
    manifest = (
        '[package]\nname = "backend_contract_consumer"\nversion = "0.0.0"\nedition = "2021"\n'
        f"[dependencies]\nsubject = {{ package = {json.dumps(package)}, path = {json.dumps(str(library))} }}\n"
    )
    if old_backend:
        manifest += 'idna_adapter = "=1.2.1"\n'
    (root / "Cargo.toml").write_text(manifest, encoding="utf-8")
    (root / "src/main.rs").write_text(PROBE, encoding="utf-8")
    command = "generate-lockfile" if old_backend else "run"
    return subprocess.run(
        ["cargo", command, "--offline", "--manifest-path", str(root / "Cargo.toml")],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> None:
    """Require successful real behavior and an actual resolver conflict."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("--package", default="tldhax")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="tldhax-backend-") as directory:
        root = Path(directory)
        positive = run(root / "compatible", args.library.resolve(), args.package, False)
        if positive.returncode:
            raise RuntimeError(positive.stderr)
        negative = run(root / "old-backend", args.library.resolve(), args.package, True)
        if (
            negative.returncode == 0
            or "failed to select a version for `idna_adapter`" not in negative.stderr
        ):
            raise RuntimeError(
                "the downstream adapter constraint was not refused by Cargo"
            )
        print(positive.stdout.strip())
        print(
            "Real downstream U/A equivalence and ContextO checks passed; older adapter refused."
        )


if __name__ == "__main__":
    main()
