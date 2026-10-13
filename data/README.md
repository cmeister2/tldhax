# Pinned inventories

Run these commands from the repository root with the development dependencies
installed (`idna` is required). Normal library builds use packaged snapshots and
perform no network requests.

```sh
python -m scripts.data --verify
python -m scripts.data --reconcile
python -m scripts.data --fetch /tmp/tldhax-next \
  --evaluation-date 2026-10-12 --retrieved-on 2026-10-12
python -m scripts.data --diff /path/to/previous-checkout --report /tmp/tld-diff.json
```

`--verify` recomputes raw source hashes, upstream versions, the dataset version,
and every generated artifact. It rejects missing inputs and stale output bytes.
`--reconcile` validates local sources before regenerating outputs and is byte
idempotent. A new dataset needs both dates; changed raw inputs need an explicit
`--retrieved-on`. Unchanged inputs retain their original retrieval date.

`--fetch` uses bounded HTTPS requests, byte limits and transient retries. Its
destination must be new. It validates each response and the complete derived
dataset before exposing the staging directory. Review source changes and the
deterministic diff before copying approved snapshots into the repository.
The PSL publisher asks clients to fetch no more than once per day:
[download guidance](https://publicsuffix.org/list/).

`manifest.json` has schema version 2, an explicit evaluation date, and a dataset
version consisting of that date plus a hash of raw source identities/hashes.
Each `inputs` entry records `source_id`, `path`, `url`, original-byte `sha256`,
`retrieved_on`, and `upstream_version`. `unversioned` means that the source does
not publish a version identifier; its content hash remains authoritative.
Each `outputs` entry records the generated `path` and `sha256`.

| Generated artifact | Contract |
| --- | --- |
| `root/inventory.json` | Every pinned active ASCII TLD, IANA type/manager/delegation URL, optional ICANN contract metadata, source IDs, unknown policy state |
| `psl/rules.json` | Original rule text, canonical ASCII suffix, ICANN/PRIVATE section, exact/wildcard/exception kind |
| `special-use/names.json` | Canonical designation, descendant scope, deprecation flag, governing RFC IDs |
| `reserved/sets.json` | Separate category IDs, canonical labels, original scope/exception description and references; applicability requires review |
| `research-queue.json` | Every active root and discovered ICANN selector grouped by IANA manager, with an explicit research disposition |

The root database includes inactive/unassigned entries; the generated root
inventory contains only roots in the pinned active list. PRIVATE PSL rules are
preserved as metadata and do not become registry namespace research tasks.
PSL exceptions remain routing exceptions rather than registration namespaces.

Delegation, PSL membership, shared manager identity and Spec 13 metadata do not
approve a registration policy. Imported reservations retain distinct categories
and exceptions; they do not automatically apply to a TLD or namespace. Reviewed
assertions and their evidence must supply those decisions. Registrar availability
and purchases are outside these tools.

See [snapshot notices](NOTICES.md) and the [PSL license](psl/LICENSE).
