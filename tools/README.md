# Registrar oracle for development

`registrar_oracle.py` records non-purchasing registrar checks to investigate
policy gaps and contradictions. It is separate from the offline library and
ordinary `tldhax` CLI. Registrar availability and prices are not library verdicts.
The tool never purchases, renews, transfers or changes DNS.

The oracle supports Name.com and Gandi through separate adapters. Each adapter
owns its endpoints, authentication, batch limits and native response parsing.
The shared [`Provider`](oracle/providers.py) handles HTTP errors and sanitized
observations; the dispatcher, quotas, retries and SQLite history work across
providers. Adding a registrar does not require changing those shared components.

## Accounts and credentials

Name.com's
[reseller documentation](https://cs.name.com/hc/en-us/articles/205934767-Name-com-Reseller-Program)
states that API use is free. Create an account and generate separate production
or test tokens through the [API settings workflow](https://www.name.com/api-resources).
The adapter uses the current
[Core `domains:checkAvailability` endpoint](https://docs.name.com/api/v1/reference/domains/check-availability),
with HTTP Basic authentication and `purchaseType="registration"`.

Install optional developer dependencies:

```sh
python -m pip install -e '.[oracle]'
```

Use the empty keys in [.env.example](../.env.example) to create an ignored local
credential file:

```dotenv
NAMECOM_USERNAME=
NAMECOM_API_TOKEN=
GANDI_PAT=
```

Only an explicit `--env-file` is loaded; the tool does not search parent folders
for `.env`. Process environment takes precedence over that file, and dotenv
interpolation is disabled. Credentials and encoded Basic authentication values
are redacted from retained provider response fields and diagnostics.

`--environment` is mandatory. Production uses `api.name.com`; sandbox uses
`api.dev.name.com`. Supply the sandbox token and documented `-test` username
explicitly; switching the flag does not convert credentials. Sandbox observations
remain separately identified and cannot establish current production policy.

Gandi is optional for an existing account eligible to create a PAT. If its UI
requires a product before token creation, leave `GANDI_PAT` empty; a purchase is
not needed for this project's validation workflow. The adapter calls only
[GET domain availability](https://api.gandi.net/docs/domains/#get-domain-availability)
for the `create` process using Bearer authentication. Follow
[Gandi's PAT resource/permission guidance](https://docs.gandi.net/en/managing_an_organization/organizations/personal_access_token.html)
for the account's available access; DNS editing, registration and billing write
rights are not required by this tool. A permission failure pauses that provider
and is reported separately from candidate validity.

## Explicit probes

```sh
python tools/registrar_oracle.py \
  --environment production --env-file .env \
  --name 'ß.com' --name '_bad.com' \
  --dataset-version YOUR_COMPILED_DATASET_VERSION \
  --store /tmp/tldhax-oracle.sqlite
```

Supply the complete `dataset_version` from `Registry().dataset_info()` for the
offline release being compared. This command makes live requests; it is not part
of library installation, normal lookup or automated tests.

For multiple probes, use `--input candidates.jsonl`. Each record contains only
the candidate and optional public comparison metadata:

```json
{"name":"ß.com","namespace":"com","stratum":"idn-boundary","offline_validity":"invalid","evidence_ids":["com.idn-no-sharp-s"]}
{"name":"_bad.com","namespace":"com","stratum":"syntax-negative"}
```

`offline_validity` accepts `valid`, `invalid`, `conditional` or `unknown`.
Candidate names contain 1–4,096 UTF-8 bytes. Do not put registrant profiles or
credentials in probe records. Raw negative probes are transmitted as supplied;
strict equivalent A-/U-label identities can be deduplicated. If a provider strips
an underscore or otherwise changes the name, the response is **inconclusive**
for the original candidate. Missing or duplicate identities are also retained
as findings rather than attributed to a different domain.

## Interpreting responses

| Signal | Meaning |
| --- | --- |
| `accepted` | A matching registrar response accepted this registration check at the recorded time. It is a consistency signal, not complete registry-policy proof. |
| `explicitly_invalid` / `explicitly_restricted` | A documented provider status gives a concrete reason to investigate. It does not automatically become an offline rule. |
| `inconclusive` | Taken/unavailable, unknown status, unsupported service, changed identity, transport failure or other ambiguous response. |

Name.com `purchasable=true` for a matching registration response gives an accepted
signal; `false` and free-text reasons remain inconclusive. Gandi's documented
`error_invalid` is an explicit invalid signal; documented restriction states are
separate. An already registered or unavailable domain is **not evidence of an
invalid name**. Prices and premium classifications do not establish validity.

Output separates `observations`, policy-review `findings`, and `tool_errors`.
Observations retain provider/API version, environment, query context, requested
and returned identity, native status/reason, timestamp and dataset version.
Provider disagreement and acceptance contradicting an evidenced offline denial
create review findings. Only primary registry-policy review can promote a new
rule or declare a policy family complete.

## Quotas, fallback and resume

The dispatcher uses supported namespace coverage, provider weights, cooldowns
and per-run budgets. It batches within provider limits, retries transient failures
with bounded backoff, respects `Retry-After`, pauses authentication failures and
can fall back to another configured provider. A stratified sample is cross-checked
only where another usable provider exists; a one-provider run explicitly reports
that cross-checking is unavailable.

Defaults are conservative local settings: one request per second, 30 requests
per minute, concurrency one, at most 30 unique candidates per provider and two
retries. They are not claims about a provider's advertised allowance. An optional
credential-free `--config` JSON can narrow coverage and set explicit quotas:

```json
{
  "namecom": {
    "namespaces": ["com", "net", "de"],
    "quota_group": "namecom-account",
    "windows": [{"requests": 1, "seconds": 1}, {"requests": 30, "seconds": 60}],
    "concurrency": 1,
    "weight": 1,
    "max_candidates": 30,
    "retries": 2
  }
}
```

Use a shared `quota_group` for an account or source-IP limit. Separate tokens do
not create additional quota. SQLite retains request windows/cooldowns, attempts
and sanitized observations across runs. Eligible cached observations are reused
for the same identity/API/environment within `--max-age` (default one day).
Reused output preserves the response timestamp and records the currently
compared dataset version; the stored original observation remains unchanged.
`--refresh` bypasses observation reuse without resetting quota history.
`--cross-check-rate` defaults to `0.1`; unknown capability and failed requests do
not count as corroboration.

Tests under `tests/oracle/` use fake HTTP and clocks. They cover identity changes,
known/unknown statuses, secret redaction, retry/cooldown, authentication pause,
durable quotas, resume, fallback and cross-check evidence without live calls.
