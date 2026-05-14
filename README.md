# tldhax

`tldhax` is a Rust library with Python bindings for checking whether a candidate domain could be registerable under its effective TLD.

The project compiles curated TLD rule data from `rules/*.toml` into the binary at build time. Rule coverage is bootstrapped from the ICANN section of the Public Suffix List, while concrete registration policy remains explicit and source-backed.

## Highlights

- Rust core with PyO3 Python bindings.
- Build-time TOML validation and code generation.
- CLI for `check`, `info`, and `stats`.
- Checked-in ICANN PSL coverage plus grouped Spec 13 brand TLD rules.

## Development

```bash
cargo test
maturin develop
pytest
```

## Bootstrap Data

The repository already includes checked-in rule data under `rules/*.toml`.

That data includes:

- ICANN Public Suffix List coverage represented as minimal `[[domains]]` entries
- grouped ICANN Spec 13 brand TLD rules in `rules/_brand.toml`
- curated rule entries where registration policy is explicitly tracked and sourced