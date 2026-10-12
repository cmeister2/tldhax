# Registrar oracle

The offline library evaluates static domain-name policy. This optional Python
tool gathers registrar observations for development and evidence review.
It uses non-purchasing check endpoints. Availability, prices and premium
designations do not become library validity rules.

Install dependencies and create a local credential file using the empty
placeholders in [.env.example](../.env.example):

```sh
python -m pip install -e '.[oracle]'
python tools/registrar_oracle.py \
  --environment production --env-file .env \
  --dataset-version YOUR_DATASET_VERSION \
  --store /tmp/tldhax-oracle.sqlite --name example.com
```

Name.com needs `NAMECOM_USERNAME` and `NAMECOM_API_TOKEN`. Its production Core
check endpoint has been exercised with this project. A sandbox account uses
its separately supplied sandbox username and credentials; do not reuse a
production observation as sandbox evidence. File credentials load only with
`--env-file`; process environment values take precedence. Keep credentials
out of tracked files, input suites, configuration and reports.

Gandi is optional and uses `GANDI_PAT` from an existing eligible account. Its
token-creation flow may require an existing product; no purchase is needed
for this project's Name.com setup. The adapter uses only `GET /v5/domain/check`
with `processes=create`.

Use `--input probes.jsonl` for a suite. Each UTF-8 JSON line can contain `name`,
`namespace`, `stratum`, `offline_validity` (`valid`, `invalid`, `conditional`,
or `unknown`) and `evidence_ids`. These last fields describe a supplied offline
comparison; they do not approve the underlying assertions. Malformed name
probes retain their raw identity. A provider returning a different name yields
an inconclusive finding, as observed when Name.com removed an underscore.

By default each provider has a budget of 30 unique names per run, one request
per second, 30 requests per minute, concurrency one, two retries and a 10%
stratified cross-check sample. These are conservative local defaults. Configure
documented account limits and coverage with credential-free `--config` JSON:

```json
{"namecom": {"windows": [{"requests": 1, "seconds": 1}],
             "max_candidates": 30, "weight": 1, "concurrency": 1}}
```

Providers support `quota_group` for shared account/source-IP limits and
`namespaces` for explicitly configured coverage. Credentials do not create
independent quota pools. Reuse the same SQLite store for runs sharing an
account/IP: reservations, cooldowns and interrupted attempts persist there.
Independent stores cannot coordinate their quotas. Provider headers can slow
the tool but cannot increase configured local limits.

Fresh completed observations are reused for 24 hours by default; `--max-age`
changes this and `--refresh` requests new observations. Cache identity includes
the requested name, provider/API, environment and check context. A current
dataset can be compared with an existing observation while preserving its
observation timestamp and append-only stored history.

JSON output separates observations, research findings and tool errors.
Authentication failures pause the provider. Server/quota failures have bounded
retries and fallback. Cross-checking is `unavailable` with one provider and
is complete only when every selected candidate has usable observations from
two providers. Provider disagreements never rewrite a static policy.

Official contracts: [Name.com check](https://docs.name.com/api/v1/reference/domains/check-availability)
and [Gandi check](https://api.gandi.net/docs/domains/#get-domain-availability).
Offline parser, scheduler and credential tests live in `tests/oracle`.
