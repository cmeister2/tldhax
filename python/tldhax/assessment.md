# Registration decision API

`Registry.assess(domain, registrant=None)` returns `yes`, `no` or `unknown` with
structured `Reason(code, message)` explanations. It evaluates supported static
name and applicant requirements against declared facts. Availability and
transaction approval remain the registering application's responsibility.

The result exposes `decision`, `canonical_domain`, `namespace`, `reasons` and
`missing_profile_fields`. `status` aliases `decision`, and `to_dict()` returns the
same five fields as JSON-compatible objects. Reasons explain concrete failures
or unresolved conditions directly; no separate detail mode or evidence lookup is
required.

`prepare_registrant(mapping)` validates a reusable opaque profile.
`prepare_registrant_json(text)` also rejects duplicate keys. Missing fields remain
distinct from `false` and empty sets. A passing alternative does not request
missing declarations for unused alternatives. `profile_schema()` describes
accepted types and constrained values. Profile values are excluded from
representations, result reasons and validation errors.

`assess_many(domains, registrant=None)` prepares one mapping once and evaluates
at most 10,000 candidates in input order with the GIL released. Malformed names
return `no`; malformed profiles and exceeded implementation limits raise input
errors. `check(domain)` is a thin adapter returning `status` and reason strings.

`dataset_version()` and `supported_namespaces()` expose small release metadata.
An authored namespace can retain explicit unsupported IDN, form or policy
conditions; its presence is not a promise that every candidate receives `yes`.
