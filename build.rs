//! Compile legacy TOML rule summaries into immutable lookup tables.


use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Legacy authored registration-access state deserialized from a rule record.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
enum RegisterableToml {
    /// Legacy evidence describes an openly registerable namespace.
    Yes,
    /// Legacy evidence describes a non-registerable namespace.
    No,
    /// Legacy evidence describes registration with additional restrictions.
    Restricted,
}

/// Legacy authored reason explaining a non-registerable namespace.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
enum ReasonToml {
    /// Registration is limited by a brand namespace policy.
    BrandTld,
    /// The namespace serves Internet infrastructure.
    Infrastructure,
    /// The namespace serves governmental use.
    Government,
    /// The namespace is retired from registration.
    Retired,
}

/// Label representation used by the legacy authored length limits.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
enum LengthBasisToml {
    /// Measure the ASCII label representation.
    Ascii,
    /// Measure the Unicode label representation.
    Unicode,
}

/// Legacy authored character-set category.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
enum CharsetToml {
    /// Legacy policy describes ASCII labels.
    Ascii,
    /// Legacy policy describes internationalized labels.
    Idn,
}

/// Legacy TOML suffix entry with optional policy claims and per-field source links.
///
/// An entry without policy claims contributes discovery only.
#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct DomainEntryToml {
    /// Authored suffix identity checked against the root implied by the filename.
    tld: String,
    /// Optional registration-access claim; absence permits discovery-only entries.
    registerable: Option<RegisterableToml>,
    /// Optional explanation allowed only when registration is unavailable.
    reason: Option<ReasonToml>,
    /// Optional descriptive context retained in the compiled rule.
    note: Option<String>,
    /// Published conditions allowed only for restricted registration.
    restrictions: Vec<String>,
    /// Optional minimum label length; the compiler defaults to one when omitted.
    min_length: Option<u8>,
    /// Optional maximum label length; the compiler defaults to sixty-three when omitted.
    max_length: Option<u8>,
    /// Optional length representation; the compiler defaults to ASCII when omitted.
    length_basis: Option<LengthBasisToml>,
    /// Finite authored label patterns retained by the legacy runtime rule.
    banned: Vec<String>,
    /// Optional character-set category; the compiler defaults to ASCII when omitted.
    charset: Option<CharsetToml>,
    /// Optional authored IDN character repertoire; requires an IDN character-set category.
    idn_chars: Option<String>,
    /// Source links keyed by each explicitly authored policy field.
    sources: BTreeMap<String, String>,
}

/// TOML container for one or more legacy suffix entries.
#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RuleFileToml {
    /// Legacy suffix entries; empty files are rejected by the build.
    domains: Vec<DomainEntryToml>,
}

/// Validated legacy summary with explicit defaults and static runtime enum expressions.
#[derive(Debug)]
struct CompiledDomainEntry {
    /// Authored suffix identity checked against the root implied by the filename.
    tld: String,
    /// Static runtime registration-access enum expression selected during validation.
    registerable: &'static str,
    /// Optional static runtime reason expression for unavailable registration.
    reason: Option<&'static str>,
    /// Optional descriptive context retained in the compiled rule.
    note: Option<String>,
    /// Published conditions allowed only for restricted registration.
    restrictions: Vec<String>,
    /// Validated minimum label length, including the legacy default when omitted.
    min_length: u8,
    /// Validated maximum label length, including the legacy default when omitted.
    max_length: u8,
    /// Static runtime length-representation enum expression.
    length_basis: &'static str,
    /// Finite authored label patterns retained by the legacy runtime rule.
    banned: Vec<String>,
    /// Static runtime character-set enum expression.
    charset: &'static str,
    /// Retained IDN character repertoire, empty when no repertoire was authored.
    idn_chars: String,
    /// Source links keyed by each explicitly authored policy field.
    sources: BTreeMap<String, String>,
}

/// Compile every packaged artifact into Cargo’s output directory.
///
/// # Panics
/// Panics when Cargo omits `OUT_DIR`, packaged evidence fails validation, or an
/// output artifact cannot be written.
fn main() {
    let rules_dir = Path::new("rules");
    println!("cargo:rerun-if-changed={}", rules_dir.display());

    let mut compiled_entries = Vec::new();
    let mut known_suffixes = BTreeSet::new();

    let mut files = fs::read_dir(rules_dir)
        .expect("failed to read rules directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("toml"))
        .collect::<Vec<_>>();
    files.sort();

    for path in files {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let parsed: RuleFileToml = toml::from_str(&text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_else(|| panic!("invalid rule filename {}", path.display()));

        if parsed.domains.is_empty() {
            panic!("{} must contain at least one [[domains]] entry", path.display());
        }

        for entry in parsed.domains {
            let tld = entry.tld.clone();
            if let Some(compiled) = validate_domain_entry(&path, stem, entry) {
                compiled_entries.push(compiled);
            }
            known_suffixes.insert(tld);
        }
    }

    compiled_entries.sort_by(|left, right| left.tld.cmp(&right.tld));

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is not set"));
    let destination = out_dir.join("generated_rules.rs");
    let mut output = fs::File::create(&destination)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", destination.display()));

    writeln!(output, "use crate::types::{{Charset, LengthBasis, Reason, Registerable, TldRule}};")
        .expect("failed to write generated prelude");

    let mut rule_map = phf_codegen::Map::new();
    for entry in &compiled_entries {
        rule_map.entry(&entry.tld, &render_tld_rule(entry));
    }

    writeln!(output, "/// Validated legacy rule summaries indexed by their authored suffix identities.\npub static TLD_RULES: phf::Map<&'static str, TldRule> = {};
", rule_map.build()).expect("failed to write TLD_RULES map");

    let mut suffix_set = phf_codegen::Set::new();
    for suffix in &known_suffixes {
        suffix_set.entry(suffix);
    }

    writeln!(output, "/// All authored suffix identities, including discovery-only entries without policy claims.\npub static KNOWN_SUFFIXES: phf::Set<&'static str> = {};
", suffix_set.build()).expect("failed to write KNOWN_SUFFIXES set");
    writeln!(output, "/// Number of unique suffix identities in the compiled discovery set.\npub const TOTAL_KNOWN_SUFFIXES: usize = {};", known_suffixes.len())
        .expect("failed to write suffix count");
}

/// Require each suffix root to match the rule filename unless its stem begins with an underscore.
///
/// # Panics
/// Panics when a suffix root disagrees with the non-exempt rule filename.
fn validate_root_alignment(path: &Path, stem: &str, suffix: &str) {
    if stem.starts_with('_') {
        return;
    }

    let normalized = suffix
        .trim_start_matches("!.")
        .trim_start_matches('!')
        .trim_start_matches("*.");
    let root = normalized.rsplit('.').next().unwrap_or(normalized);
    if root != stem {
        panic!(
            "{} contains suffix '{}' whose root '{}' does not match filename '{}'",
            path.display(),
            suffix,
            root,
            stem,
        );
    }
}

/// Validate an authored legacy entry and apply legacy defaults to a complete summary.
///
/// # Panics
/// Panics for mismatched root identity, policy fields without an access claim,
/// missing per-field sources, invalid length bounds, or reason, restriction and
/// IDN fields inconsistent with the selected access or character-set category.
fn validate_domain_entry(path: &Path, stem: &str, entry: DomainEntryToml) -> Option<CompiledDomainEntry> {
    validate_root_alignment(path, stem, &entry.tld);

    let has_min_length = entry.min_length.is_some();
    let has_max_length = entry.max_length.is_some();
    let has_length_basis = entry.length_basis.is_some();
    let has_charset = entry.charset.is_some();
    let has_idn_chars = entry.idn_chars.as_ref().is_some_and(|value| !value.is_empty());
    let has_policy_fields = entry.reason.is_some()
        || entry.note.is_some()
        || !entry.restrictions.is_empty()
        || has_min_length
        || has_max_length
        || has_length_basis
        || !entry.banned.is_empty()
        || has_charset
        || has_idn_chars
        || !entry.sources.is_empty();

    let Some(registerable) = entry.registerable.clone() else {
        if has_policy_fields {
            panic!(
                "{}: domain '{}' omits registerable but still sets rule fields",
                path.display(),
                entry.tld,
            );
        }
        return None;
    };

    if !entry.sources.contains_key("registerable") {
        panic!(
            "{}: domain '{}' is missing sources.registerable",
            path.display(),
            entry.tld,
        );
    }

    let min_length = entry.min_length.unwrap_or(1);
    let max_length = entry.max_length.unwrap_or(63);
    if min_length == 0 || min_length > max_length {
        panic!(
            "{}: domain '{}' has invalid min/max length {}-{}",
            path.display(),
            entry.tld,
            min_length,
            max_length,
        );
    }

    let length_basis = entry.length_basis.clone().unwrap_or(LengthBasisToml::Ascii);
    let charset = entry.charset.clone().unwrap_or(CharsetToml::Ascii);
    let idn_chars = entry.idn_chars.clone().unwrap_or_default();

    if !idn_chars.is_empty() && !matches!(charset, CharsetToml::Idn) {
        panic!(
            "{}: domain '{}' sets idn_chars without charset = 'idn'",
            path.display(),
            entry.tld,
        );
    }

    if entry.reason.is_some() && !matches!(registerable, RegisterableToml::No) {
        panic!(
            "{}: domain '{}' sets reason but is not registerable = 'no'",
            path.display(),
            entry.tld,
        );
    }

    if !entry.restrictions.is_empty() && !matches!(registerable, RegisterableToml::Restricted) {
        panic!(
            "{}: domain '{}' sets restrictions but is not registerable = 'restricted'",
            path.display(),
            entry.tld,
        );
    }

    require_source_if_present(path, &entry, entry.reason.is_some(), "reason");
    require_source_if_present(path, &entry, entry.note.is_some(), "note");
    require_source_if_present(path, &entry, !entry.restrictions.is_empty(), "restrictions");
    require_source_if_present(path, &entry, has_min_length, "min_length");
    require_source_if_present(path, &entry, has_max_length, "max_length");
    require_source_if_present(path, &entry, has_length_basis, "length_basis");
    require_source_if_present(path, &entry, !entry.banned.is_empty(), "banned");
    require_source_if_present(path, &entry, has_charset, "charset");
    require_source_if_present(path, &entry, has_idn_chars, "idn_chars");

    Some(CompiledDomainEntry {
        tld: entry.tld,
        registerable: match registerable {
            RegisterableToml::Yes => "Registerable::Yes",
            RegisterableToml::No => "Registerable::No",
            RegisterableToml::Restricted => "Registerable::Restricted",
        },
        reason: entry.reason.map(|reason| match reason {
            ReasonToml::BrandTld => "Reason::BrandTld",
            ReasonToml::Infrastructure => "Reason::Infrastructure",
            ReasonToml::Government => "Reason::Government",
            ReasonToml::Retired => "Reason::Retired",
        }),
        note: entry.note,
        restrictions: entry.restrictions,
        min_length,
        max_length,
        length_basis: match length_basis {
            LengthBasisToml::Ascii => "LengthBasis::Ascii",
            LengthBasisToml::Unicode => "LengthBasis::Unicode",
        },
        banned: entry.banned,
        charset: match charset {
            CharsetToml::Ascii => "Charset::Ascii",
            CharsetToml::Idn => "Charset::Idn",
        },
        idn_chars,
        sources: entry.sources,
    })
}

/// Require a matching source link for an explicitly authored policy field.
///
/// # Panics
/// Panics if the field is present but its source key is absent.
fn require_source_if_present(path: &Path, entry: &DomainEntryToml, condition: bool, source_key: &str) {
    if condition && !entry.sources.contains_key(source_key) {
        panic!(
            "{}: domain '{}' is missing sources.{}",
            path.display(),
            entry.tld,
            source_key,
        );
    }
}

/// Render one validated summary as a static runtime rule expression.
fn render_tld_rule(entry: &CompiledDomainEntry) -> String {
    format!(
        "TldRule {{ tld: {tld}, registerable: {registerable}, reason: {reason}, note: {note}, restrictions: {restrictions}, min_length: {min_length}, max_length: {max_length}, length_basis: {length_basis}, banned: {banned}, charset: {charset}, idn_chars: {idn_chars}, sources: {sources} }}",
        tld = render_string(&entry.tld),
        registerable = entry.registerable,
        reason = entry
            .reason
            .map(|value| format!("Some({value})"))
            .unwrap_or_else(|| "None".to_string()),
        note = entry
            .note
            .as_ref()
            .map(|value| format!("Some({})", render_string(value)))
            .unwrap_or_else(|| "None".to_string()),
        restrictions = render_string_slice(&entry.restrictions),
        min_length = entry.min_length,
        max_length = entry.max_length,
        length_basis = entry.length_basis,
        banned = render_string_slice(&entry.banned),
        charset = entry.charset,
        idn_chars = render_string(&entry.idn_chars),
        sources = render_sources(&entry.sources),
    )
}

/// Escape an exact string value as a Rust literal.
fn render_string(value: &str) -> String {
    format!("{value:?}")
}

/// Render a static slice preserving the authored string order.
fn render_string_slice(values: &[String]) -> String {
    let rendered = values
        .iter()
        .map(|value| render_string(value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{rendered}]")
}

/// Render source key/link pairs in deterministic map-key order.
fn render_sources(values: &BTreeMap<String, String>) -> String {
    let rendered = values
        .iter()
        .map(|(field, source)| format!("({}, {})", render_string(field), render_string(source)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{rendered}]")
}