# Third-party notices

## Public Suffix List

`data/snapshots/public_suffix_list.dat` is an unmodified snapshot of the
[Public Suffix List](https://publicsuffix.org/list/), maintained by the Public
Suffix List community. The list is made available under the Mozilla Public
License, version 2.0 (`MPL-2.0`).

The complete license text distributed with the snapshot is available at
`data/snapshots/LICENSE.publicsuffix`. Snapshot provenance, including its
upstream commit and content hash, is recorded in `data/manifest.toml`.

The upstream project is available at
<https://github.com/publicsuffix/list>. The Public Suffix List is separate from
the MIT-licensed tldhax source code; inclusion here does not relicense it under
the tldhax license.

## IANA Special-Use Domain Names registry

`data/snapshots/special-use-domain.csv` is a snapshot of IANA's Special-Use
Domain Names protocol registry. IANA and the IETF state that the protocol
registry data linked directly from IANA's protocol-registry index is dedicated
under the Creative Commons CC0 1.0 Universal dedication (`CC0-1.0`).

The applicable statement is available at
<https://www.iana.org/help/licensing-terms>, and the registry appears in the
protocol-registry index at <https://www.iana.org/protocols>.

## Other IANA and ICANN data

The files `tlds-alpha-by-domain.txt`, `root-zone-database.html`,
and `icann-gtlds.json` are pinned snapshots of factual namespace and
registry-agreement data published by IANA or ICANN. Their exact source URLs,
retrieval metadata, and content hashes are recorded in `data/manifest.toml`.

The manifest deliberately records their SPDX status as `NOASSERTION` and links
to the applicable ICANN terms. The tldhax MIT license does not purport to
relicense those snapshots. Redistribution rights for these snapshot payloads
must be resolved before publishing a distribution that contains them.
