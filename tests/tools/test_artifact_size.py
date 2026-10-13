"""Section measurement distinguishes constant payload, metadata and RELRO."""

import struct
from pathlib import Path

from tools.artifact_size import inspect


def elf_fixture(path: Path, protected: bool) -> None:
    """Write a small ELF64 image with independent section and segment flags."""
    strings = b"\0.rodata\0.data.rel.ro\0.debug_info\0.shstrtab\0"
    sections = b"\0" * 64
    for name, flags, address, offset, size in [
        (".rodata", 2, 0x1000, 440, 16),
        (".data.rel.ro", 3, 0x2000, 456, 32),
        (".debug_info", 0, 0, 488, 64),
        (".shstrtab", 0, 0, 552, len(strings)),
    ]:
        sections += struct.pack(
            "<IIQQQQIIQQ",
            strings.index(name.encode()),
            1,
            flags,
            address,
            offset,
            size,
            0,
            0,
            1,
            0,
        )
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1]) + bytes(9),
        3,
        62,
        1,
        0,
        64,
        120,
        0,
        64,
        56,
        1,
        64,
        5,
        4,
    )
    segment = struct.pack(
        "<IIQQQQQQ",
        0x6474E552,
        4,
        456,
        0x2000 if protected else 0x3000,
        0,
        32,
        32,
        1,
    )
    path.write_bytes(header + segment + sections + bytes(112) + strings)


def test_section_payload_excludes_debug_and_checks_actual_relro(tmp_path: Path) -> None:
    """Writable pointer tables count as candidate constants only with clear metadata."""
    artifact = tmp_path / "fixture.so"
    for protected in [True, False]:
        elf_fixture(artifact, protected)
        report = inspect(artifact)
        assert report["constant_candidate_sections"] == {
            ".rodata": 16,
            ".data.rel.ro": 32,
        }
        assert report["constant_candidate_section_bytes"] == 48
        assert report["allocated_section_bytes"] == 48
        assert report["debug_section_bytes"] == 64
        assert report["total_file_bytes"] > 48 + 64
        assert report["data_rel_ro_inside_gnu_relro"] is protected
