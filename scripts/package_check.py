"""Verify source archives and installed wheels through repeatable offline builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib


def required_paths(root: Path) -> set[str]:
    """Discover actual compiler inputs rather than a stale hardcoded sample."""
    required = {
        "Cargo.toml",
        "Cargo.lock",
        "pyproject.toml",
        "build.rs",
        "LICENSE",
        "README.md",
        "data/manifest.json",
        "data/NOTICES.md",
        "data/psl/LICENSE",
    }
    manifest = json.loads((root / "data/manifest.json").read_text(encoding="utf-8"))
    required.update(
        row["path"] for group in ("inputs", "outputs") for row in manifest[group]
    )
    for directory, pattern in [
        ("src", "*.rs"),
        ("build_support", "*.rs"),
        ("rules", "*.toml"),
        ("evidence", "*.toml"),
        ("tests/compiler", "*.toml"),
        ("data/idn", "*"),
    ]:
        required.update(
            p.relative_to(root).as_posix()
            for p in (root / directory).rglob(pattern)
            if p.is_file()
        )
    source_path = root / "evidence/sources.toml"
    if source_path.exists():
        sources = tomllib.loads(source_path.read_text(encoding="utf-8"))["sources"]
        required.update(s["snapshot_path"] for s in sources if "snapshot_path" in s)
    for path in required:
        relative = PurePosixPath(path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe compiler input path")
        if not (root / path).is_file():
            raise ValueError("required package input missing: " + path)
    return required


def source_archive(archive: Path, root: Path) -> dict[str, bytes]:
    """Verify every packaged build input against the source tree's exact bytes."""
    files = {}
    prefix = None
    with tarfile.open(archive, "r:gz") as package:
        for entry in package:
            path = PurePosixPath(entry.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or entry.issym()
                or entry.islnk()
            ):
                raise ValueError("unsafe source archive entry")
            if not entry.isfile():
                continue
            if len(path.parts) < 2:
                raise ValueError("source archive needs one containing directory")
            prefix = prefix or path.parts[0]
            if path.parts[0] != prefix:
                raise ValueError("multiple source archive roots")
            name = PurePosixPath(*path.parts[1:]).as_posix()
            if name in files:
                raise ValueError("duplicate source archive member")
            stream = package.extractfile(entry)
            if stream is None:
                raise ValueError("unreadable source archive member")
            files[name] = stream.read()
    for name in sorted(required_paths(root)):
        if name not in files:
            raise ValueError("source archive omitted compiler input: " + name)
        # Cargo rewrites Cargo.toml; all actual source/data bytes remain exact.
        if name != "Cargo.toml" and files[name] != (root / name).read_bytes():
            raise ValueError("source archive changed compiler input: " + name)
    original_manifest = files.get("Cargo.toml.orig", files["Cargo.toml"])
    if original_manifest != (root / "Cargo.toml").read_bytes():
        raise ValueError("source archive changed original Cargo manifest")
    return files


def wheel_archive(archive: Path, root: Path) -> None:
    """Require native tables and redistribution notices, without raw runtime data."""
    with zipfile.ZipFile(archive) as wheel:
        names = wheel.namelist()
        if not any(
            "tldhax/_native" in name and name.endswith((".so", ".pyd"))
            for name in names
        ):
            raise ValueError("wheel omitted native extension")
        for required in ("data/psl/LICENSE", "data/NOTICES.md"):
            content = (root / required).read_bytes()
            if not any(
                wheel.read(name) == content
                for name in names
                if name.endswith(Path(required).name)
            ):
                raise ValueError("wheel omitted redistribution notice: " + required)
        if any(name.endswith("data/root/inventory.json") for name in names):
            raise ValueError("wheel includes unnecessary raw inventory inputs")


def command(args: list[str], cwd: Path, env: dict[str, str]) -> str:
    """Run a bounded build step, surfacing captured diagnostics on failure."""
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=900,
    )
    if result.returncode:
        raise RuntimeError(
            "package command failed: " + " ".join(args) + "\n" + result.stdout
        )
    return result.stdout


def probe(wheel: Path, directory: Path, root: Path, env: dict[str, str]) -> dict:
    """Install into an isolated environment and test from outside the checkout."""
    wheel_archive(wheel, root)
    venv.EnvBuilder(with_pip=True).create(directory)
    executable = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    command(
        [
            str(executable),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        directory,
        env,
    )
    output = command(
        [str(executable), "-I", str(root / "scripts/wheel_probe.py")], directory, env
    )
    return json.loads(output)


def check(root: Path, working: Path, maturin: str) -> dict:
    """Compare a checkout wheel to the same build from its unpacked source archive."""
    working.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.update(
        CARGO_NET_OFFLINE="true",
        CARGO_TARGET_DIR=str(working / "target"),
        PIP_NO_INDEX="1",
    )
    artifacts = working / "artifacts"
    command([maturin, "sdist", "--out", str(artifacts)], root, env)
    archive = next(artifacts.glob("*.tar.gz"))
    files = source_archive(archive, root)
    unpacked = working / "unpacked"
    unpacked.mkdir()
    for name, content in files.items():
        target = unpacked / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    outcomes = []
    for index, tree in enumerate((root, unpacked)):
        output = working / f"wheel-{index}"
        command(
            [
                maturin,
                "build",
                "--offline",
                "--locked",
                "--interpreter",
                sys.executable,
                "--out",
                str(output),
            ],
            tree,
            env,
        )
        wheel = next(output.glob("*.whl"))
        outcomes.append(probe(wheel, working / f"installed-{index}", root, env))
    if outcomes[0] != outcomes[1]:
        raise ValueError(
            "installed checkout/sdist evaluations or dataset fingerprints differ"
        )
    return {
        "schema_version": 1,
        "installed_result": outcomes[0],
        "sdist_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    }


def main() -> int:
    """Create local artifacts only; all build/install steps use offline mode."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--work-directory", type=Path)
    parser.add_argument("--maturin", default=shutil.which("maturin"))
    args = parser.parse_args()
    if not args.maturin:
        parser.error("maturin must already be installed")
    try:
        if args.work_directory:
            report = check(
                args.root.resolve(), args.work_directory.resolve(), args.maturin
            )
        else:
            with tempfile.TemporaryDirectory(prefix="tldhax-package-") as temporary:
                report = check(
                    args.root.resolve(), Path(temporary) / "check", args.maturin
                )
        print(json.dumps(report, indent=2, sort_keys=True))
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
