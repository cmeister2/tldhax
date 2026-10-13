"""Archive integrity failures independent of Cargo's include implementation."""

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest
from scripts.package_check import required_paths, source_archive, wheel_archive


def package_tree(root: Path) -> Path:
    """Minimal real input graph including modules, IDN and retained evidence."""
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "pyproject.toml",
        "build.rs",
        "LICENSE",
        "README.md",
        "data/NOTICES.md",
        "data/psl/LICENSE",
        "src/lib.rs",
        "build_support/inventory.rs",
        "rules/namespaces/fixture.toml",
        "tests/compiler/authoring.toml",
        "data/root/raw.txt",
        "data/root/inventory.json",
        "data/idn/fixture.xml",
        "evidence/snapshot.txt",
    ]:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture:" + name, encoding="utf-8")
    (root / "data/manifest.json").write_text(
        json.dumps(
            {
                "inputs": [{"path": "data/root/raw.txt"}],
                "outputs": [{"path": "data/root/inventory.json"}],
            }
        ),
        encoding="utf-8",
    )
    (root / "evidence/sources.toml").write_text(
        '[[sources]]\nsnapshot_path="evidence/snapshot.txt"\n', encoding="utf-8"
    )
    return root


def tar_archive(
    root: Path, archive: Path, *, omitted: str | None = None, changed: str | None = None
) -> None:
    """Create fixtures without using the package selection code being tested."""
    with tarfile.open(archive, "w:gz") as package:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            name = path.relative_to(root).as_posix()
            if name == omitted:
                continue
            content = b"tampered" if name == changed else path.read_bytes()
            info = tarfile.TarInfo("tldhax-0.0.0/" + name)
            info.size = len(content)
            package.addfile(info, io.BytesIO(content))


def test_archive_requires_inventory_evidence_namespace_idn_and_compiler_modules(
    tmp_path: Path,
) -> None:
    """Catch actual missing compiler inputs and altered archived evidence."""
    tree = package_tree(tmp_path / "root")
    required = required_paths(tree)
    assert {
        "build_support/inventory.rs",
        "evidence/snapshot.txt",
        "rules/namespaces/fixture.toml",
        "data/idn/fixture.xml",
    } <= required
    archive = tmp_path / "complete.tar.gz"
    tar_archive(tree, archive)
    assert (
        source_archive(archive, tree)["data/root/raw.txt"]
        == (tree / "data/root/raw.txt").read_bytes()
    )
    for omitted in (
        "build_support/inventory.rs",
        "evidence/snapshot.txt",
        "data/root/raw.txt",
    ):
        tar_archive(tree, archive, omitted=omitted)
        with pytest.raises(ValueError, match="omitted compiler input"):
            source_archive(archive, tree)
    tar_archive(tree, archive, changed="data/root/inventory.json")
    with pytest.raises(ValueError, match="changed compiler input"):
        source_archive(archive, tree)


def test_archive_rejects_path_traversal_before_extraction(tmp_path: Path) -> None:
    """Reject unsafe archives before creating any extracted paths."""
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        info = tarfile.TarInfo("root/../../outside")
        package.addfile(info, io.BytesIO(b""))
    with pytest.raises(ValueError, match="unsafe"):
        source_archive(archive, tmp_path)


def test_wheel_contains_native_data_and_exact_third_party_notice_bytes(
    tmp_path: Path,
) -> None:
    """Require license notices alongside compiled tables in binary wheels."""
    tree = package_tree(tmp_path / "root")
    wheel = tmp_path / "fixture.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("tldhax/_native.test.so", b"fixture native")
        archive.writestr(
            "tldhax.data/data/psl/LICENSE", (tree / "data/psl/LICENSE").read_bytes()
        )
    with pytest.raises(ValueError, match="NOTICES"):
        wheel_archive(wheel, tree)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(
            "tldhax.data/data/NOTICES.md", (tree / "data/NOTICES.md").read_bytes()
        )
    wheel_archive(wheel, tree)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("data/root/inventory.json", b"raw source")
    with pytest.raises(ValueError, match="unnecessary raw"):
        wheel_archive(wheel, tree)
