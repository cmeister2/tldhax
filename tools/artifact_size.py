#!/usr/bin/env python3
"""Measure ELF64 artifact sections without loading or executing the library.

Section bytes describe linked artifact contents, not RSS or TLD-only payload.
The candidate constant sections contain tables from all linked dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


def inspect(path: Path) -> dict[str, Any]:
    """Report a linked ELF64 file without importing or executing its library."""
    data = path.read_bytes()
    if len(data) < 64 or data[:5] != b"\x7fELF\x02" or data[5] not in (1, 2):
        raise ValueError(f"{path}: expected ELF64")
    endian = "<" if data[5] == 1 else ">"
    header = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data)
    _, _, machine, _, _, phoff, shoff, _, _, phsize, phcount, shsize, shcount, names = (
        header
    )
    if not shcount or names >= shcount or shsize != 64 or phsize != 56:
        raise ValueError(f"{path}: unsupported extended or malformed ELF header")
    if shoff + shsize * shcount > len(data) or phoff + phsize * phcount > len(data):
        raise ValueError(f"{path}: truncated ELF tables")
    raw_sections = [
        struct.unpack_from(endian + "IIQQQQIIQQ", data, shoff + i * shsize)
        for i in range(shcount)
    ]
    name_section = raw_sections[names]
    strings = data[name_section[4] : name_section[4] + name_section[5]]
    sections = []
    for raw in raw_sections[1:]:
        name_start, section_type, flags, address, offset, size, *_ = raw
        name_end = strings.find(b"\0", name_start)
        if name_end < 0:
            raise ValueError(f"{path}: malformed section name")
        sections.append(
            {
                "name": strings[name_start:name_end].decode("ascii"),
                "bytes": size,
                "file_bytes": 0 if section_type == 8 else size,
                "address": address,
                "offset": offset,
                "allocated": bool(flags & 2),
                "writable": bool(flags & 1),
                "executable": bool(flags & 4),
            }
        )
    programs = [
        struct.unpack_from(endian + "IIQQQQQQ", data, phoff + i * phsize)
        for i in range(phcount)
    ]
    relro = [p for p in programs if p[0] == 0x6474E552]
    by_name = {s["name"]: s for s in sections}
    payload = {
        name: by_name.get(name, {}).get("bytes", 0)
        for name in (".rodata", ".data.rel.ro")
    }
    relro_section = by_name.get(".data.rel.ro")
    protected = False
    if relro_section is not None:
        start = relro_section["address"]
        end = start + relro_section["bytes"]
        protected = any(p[3] <= start and end <= p[3] + p[6] for p in relro)
    return {
        "artifact": str(path.resolve()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "elf_machine": machine,
        "total_file_bytes": len(data),
        "constant_candidate_sections": payload,
        "constant_candidate_section_bytes": sum(payload.values()),
        "data_rel_ro_inside_gnu_relro": protected,
        "allocated_section_bytes": sum(s["bytes"] for s in sections if s["allocated"]),
        "allocated_readonly_noncode_section_bytes": sum(
            s["bytes"]
            for s in sections
            if s["allocated"] and not s["writable"] and not s["executable"]
        ),
        "allocated_code_section_bytes": sum(
            s["bytes"] for s in sections if s["allocated"] and s["executable"]
        ),
        "debug_section_bytes": sum(
            s["bytes"] for s in sections if s["name"].startswith(".debug")
        ),
        "symbol_string_table_bytes": sum(
            by_name.get(n, {}).get("bytes", 0)
            for n in (".symtab", ".strtab", ".shstrtab")
        ),
        "dynamic_relocation_bytes": sum(
            by_name.get(n, {}).get("bytes", 0) for n in (".rela.dyn", ".rela.plt")
        ),
        "pt_load_memsz_bytes": sum(p[6] for p in programs if p[0] == 1),
        "sections": sections,
    }


def main() -> None:
    """Print artifact section measurements and descriptive deltas as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    reports = [inspect(path) for path in args.artifacts]
    baseline = reports[0]
    for report in reports[1:]:
        report["delta_from_first_artifact"] = {
            key: report[key] - baseline[key]
            for key in (
                "total_file_bytes",
                "constant_candidate_section_bytes",
                "allocated_section_bytes",
                "allocated_code_section_bytes",
                "debug_section_bytes",
                "dynamic_relocation_bytes",
            )
        }
    print(
        json.dumps(
            {
                "schema": 1,
                "measurement": "Linked ELF section payload, not RSS, heap, or TLD-only data. "
                "rodata + data.rel.ro includes dependencies and codegen changes. "
                "RELRO protects pointers after load-time relocations.",
                "artifacts": reports,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
