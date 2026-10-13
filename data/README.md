# Runtime policy inputs

The build compiles these checked-in files into immutable Rust tables. It makes
no network requests and does not require downloaded documents or a manifest.

- `roots.txt`: delegated root identities; presence does not establish permission.
- `psl/icann.dat`: ICANN-section exact, wildcard and exception selectors used to
  find namespace boundaries. Private hosting boundaries are excluded.
- `special-use.json`: designated names and descendant scope.
- `reserved/sets.json`: exact shared label sets referenced by direct policies.
- `../rules/namespaces/`: supported registration forms, name/profile requirements,
  explanations and known limitations.
- `../rules/profiles/`: typed profile fields and adopted IDN tables.

Update the relevant file in an ordinary PR, with passing and failing examples
for policy changes. Source URLs or short interpretation notes can live beside
rules. Unsupported namespaces and forms remain unknown.

See [redistribution notices](NOTICES.md) and the [PSL license](psl/LICENSE).
