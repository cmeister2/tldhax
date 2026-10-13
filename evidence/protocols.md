# Protocol evidence and the selected input contract

These are source-only records in `sources.toml`. They support built-in protocol
findings and the selected normalization contract; they do not establish a
registry's registration forms, openness, repertoire or applicant policy. The
original publication bytes were privately acquired and SHA-256 fingerprinted.
No publication body is packaged.

| Source ID | Precise locator | Supported interpretation |
| --- | --- | --- |
| `rfc-1035` | §2.3.4; §3.1 | A DNS label is at most 63 octets. The complete wire name is at most 255 octets, including every label length byte and the root's zero byte. Measure encoded A-label bytes, not Unicode character count. |
| `rfc-1035` | §2.3.1; §2.3.3; §3.1 | Preferred host syntax uses letters, digits and interior hyphens; ASCII case is insignificant. General DNS labels can contain other octet values, so this is not evidence that every DNS owner name uses host syntax. |
| `rfc-1123` | §2.1, first paragraph | Host names may start with a digit as well as a letter, updating the older leading-letter restriction. |
| `rfc-5890` | §2.3.1; §2.3.2.1; §2.3.2.4 | LDH labels exclude edge hyphens. R-LDH labels have hyphens in positions three and four. Non-`xn--` R-LDH labels are not valid IDNA labels; a syntactic `xn--` prefix alone does not establish a valid A-label. Valid A-/U-label equivalence requires IDNA validation and conversion. |
| `rfc-5891` | §4.2.2; §4.2.3.1–4.2.3.4 | Registration rejects disallowed/unassigned characters, invalid hyphen placements, leading combining marks, unsatisfied ContextJ/ContextO rules and failed Bidi requirements. §4.2.3.3 requires positive confirmation of each applicable contextual rule. |
| `rfc-5892` | §2; Appendix A.3–A.9 | The derived-property framework distinguishes PVALID, contextual, disallowed and unassigned characters. The ContextO conditions below are registration requirements, independent of a registry repertoire. |
| `uts46-rev33` | §2.3; §3, clause C2; §3.1; §4; §4.1; §4.2 | The selected nontransitional processing maps case/compatibility forms, applies NFC, recognizes equivalent dot separators, validates A-labels and honors explicit STD3, hyphen, Bidi and joiner settings. ContextO registration checks are an additional requirement from RFC 5891/5892. |
| `rfc-3172` | §2; §2.1; §3; §7 | `.arpa` serves Internet infrastructure protocol namespaces, with specific creation/delegation through the IETF/IAB/IANA process. Ordinary generic host naming is outside that intended purpose. |

Direct sources: [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.txt),
[RFC 1123](https://www.rfc-editor.org/rfc/rfc1123.txt),
[RFC 5890](https://www.rfc-editor.org/rfc/rfc5890.txt),
[RFC 5891](https://www.rfc-editor.org/rfc/rfc5891.txt),
[RFC 5892](https://www.rfc-editor.org/rfc/rfc5892.txt),
[RFC 3172](https://www.rfc-editor.org/rfc/rfc3172.txt), and
[UTS 46 revision 33](https://www.unicode.org/reports/tr46/tr46-33.html).

## ContextO locators

| Code point | RFC 5892 locator | Required context |
| --- | --- | --- |
| U+00B7 middle dot | Appendix A.3 | Immediately between two lowercase U+006C letters. |
| U+0375 Greek lower numeral sign | Appendix A.4 | Followed by a character whose Script is Greek. |
| U+05F3 Hebrew geresh | Appendix A.5 | Preceded by a character whose Script is Hebrew. |
| U+05F4 Hebrew gershayim | Appendix A.6 | Preceded by a character whose Script is Hebrew. |
| U+30FB Katakana middle dot | Appendix A.7 | The label includes another character with Hiragana, Katakana or Han Script. |
| U+0660–U+0669 Arabic-Indic digits | Appendix A.8 | The label contains no U+06F0–U+06F9 digits. |
| U+06F0–U+06F9 extended Arabic-Indic digits | Appendix A.9 | The label contains no U+0660–U+0669 digits. |

The runtime's `Hyphens::Check` is intentional: plain `ab--cd` fails this selected
strict IDNA/UTS 46 contract before a suffix-specific reservation rule. It is not
reported as a `.us` rule failure or as a universal prohibition on arbitrary DNS
owner names. A valid `xn--` A-label is decoded and validated as its U-label.

Revision 33 is an immutable Unicode 16.0.0 publication dated 2024-08-30; the
`idna` 1.1.0 bundled conformance fixture identifies Unicode 16.0.0. This evidence
does not establish that the separate locked ICU backend uses exactly that data
version. The release must record the selected profile and backend versions.
The moving latest UTS 46 URL identifies revision 36 / Unicode 18.0.0 on the
review date; it is not substituted silently for this pinned source.

## `.arpa` boundary

RFC 3172 §2 supports an infrastructure access classification and explains why
ordinary public vanity registration is not its purpose. It does not provide an
exhaustive registration-form inventory or prove that every descendant is an
invalid domain name. §3 explicitly delegates policy for each protocol namespace
to its governing specification. §4 describes valid reverse-address and ENUM
names; its historical example list is not a current exhaustive inventory.

Retain `Infrastructure` context and the governing reference. Keep unexplored
forms/access exceptions unknown, and consult each applicable descendant's
governing RFC or reviewed policy. Do not synthesize a blanket name-invalid rule
or a complete empty-form declaration from infrastructure classification alone.
