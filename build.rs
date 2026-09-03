//! Deterministic compiler for the pinned namespace and policy catalog.

#![allow(clippy::missing_docs_in_private_items, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_SCHEMA: u32 = 1;
const POLICY_SCHEMA: u32 = 2;
const REQUIRED_SNAPSHOTS: &[(&str, &str)] = &[
    ("psl", "public_suffix_list"),
    ("iana_tlds", "current_root_tld_list"),
    ("iana_root_db", "root_zone_database"),
    ("icann_gtlds", "gtld_registry_agreements"),
    ("iana_special_use", "special_use_domain_names"),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    generated_at: String,
    snapshots: Vec<Snapshot>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    id: String,
    kind: String,
    path: String,
    url: String,
    retrieved_at: String,
    upstream_version: Option<String>,
    upstream_commit: Option<String>,
    upstream_updated_at: Option<String>,
    http_last_modified: Option<String>,
    http_etag: Option<String>,
    sha256: String,
    parser_version: String,
    content_type: String,
    license_spdx: String,
    license_name: String,
    license_url: String,
    license_path: Option<String>,
    license_source_url: Option<String>,
    license_retrieved_at: Option<String>,
    license_http_etag: Option<String>,
    license_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcesFile {
    schema_version: u32,
    sources: Vec<SourceRecord>,
    evidence: Vec<EvidenceRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRecord {
    id: String,
    kind: String,
    publisher_role: String,
    publisher: String,
    url: String,
    retrieved_at: String,
    sha256: String,
    review_after: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRecord {
    id: String,
    source: String,
    locator: String,
    predicates: Vec<String>,
    scope: EvidenceScope,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceScope {
    #[serde(default)]
    products: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilesFile {
    schema_version: u32,
    profiles: Vec<ProfileRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRecord {
    id: String,
    extends: Option<String>,
    offering_state: Option<ClaimRecord>,
    public_access: Option<ClaimRecord>,
    application_channel: Option<ClaimRecord>,
    eligibility: Option<EligibilityRecord>,
    label_policy: Option<LabelPolicyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRecord {
    status: Option<String>,
    value: Option<String>,
    #[serde(default)]
    evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct EligibilityRecord {
    mode: String,
    requirements: Vec<RequirementRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementRecord {
    id: String,
    kind: String,
    value: String,
    explanation: String,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelPolicyRecord {
    id: String,
    completeness: String,
    completeness_evidence: Vec<String>,
    length: Option<LengthRecord>,
    idn_support: Option<ClaimRecord>,
    idn_profile: Option<IdnProfileRecord>,
    reserved_status: String,
    reserved_set_evidence: Vec<String>,
    #[serde(default)]
    reserved_labels: Vec<ReservedLabelRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LengthRecord {
    minimum: u16,
    maximum: u16,
    unit: String,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdnProfileRecord {
    id: String,
    version: String,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservedLabelRecord {
    label: String,
    disposition: String,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct FlatProfile {
    id: String,
    extends: Option<String>,
    offering_state: Option<ClaimRecord>,
    public_access: Option<ClaimRecord>,
    application_channel: Option<ClaimRecord>,
    eligibility: Option<EligibilityRecord>,
    label_policy: Option<LabelPolicyRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductsFile {
    schema_version: u32,
    products: Vec<ProductRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductRecord {
    id: String,
    operator: String,
    profile: String,
    selectors: Vec<SelectorRecord>,
    #[serde(default)]
    designations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorRecord {
    kind: String,
    suffix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IcannGtlds {
    #[serde(rename = "gTLDs")]
    gtlds: Vec<IcannGtld>,
    #[serde(rename = "updatedOn")]
    updated_on: String,
    version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IcannGtld {
    #[serde(rename = "applicationId")]
    application_id: Option<String>,
    #[serde(rename = "contractTerminated")]
    contract_terminated: bool,
    #[serde(rename = "dateOfContractSignature")]
    date_of_contract_signature: Option<String>,
    #[serde(rename = "delegationDate")]
    delegation_date: Option<String>,
    #[serde(rename = "gTLD")]
    gtld: String,
    #[serde(rename = "registryClassDomainNameList")]
    registry_class_domain_name_list: Option<Vec<String>>,
    #[serde(rename = "registryOperator")]
    registry_operator: Option<String>,
    #[serde(rename = "registryOperatorCountryCode")]
    registry_operator_country_code: Option<String>,
    #[serde(rename = "removalDate")]
    removal_date: Option<String>,
    specification13: Option<bool>,
    #[serde(rename = "thirdOrLowerLevelRegistration")]
    third_or_lower_level_registration: Option<bool>,
    #[serde(rename = "uLabel")]
    u_label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKindCode {
    IanaCurrentRoot,
    IanaRootDatabase,
    PublicSuffixList,
    RegistryAgreement,
    RegistryPolicy,
    GovernmentPolicy,
    SpecialUseRegistry,
    StandardsDocument,
    RegistryIdnTable,
    IanaIdnTable,
    Secondary,
}

#[derive(Debug, Clone)]
struct RootMetadata {
    raw_type: String,
    manager: String,
}

#[derive(Debug, Clone)]
struct CompiledSuffixRule {
    labels: String,
    kind: &'static str,
    section: &'static str,
    role: &'static str,
}

#[derive(Debug, Clone)]
struct GeneratedProduct {
    id: String,
    operator: String,
    profile_id: String,
    designations: Vec<String>,
}

fn main() {
    for path in [
        "data/manifest.toml",
        "data/policy/sources.toml",
        "data/policy/profiles.toml",
        "data/policy/products.toml",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    let manifest: Manifest = read_toml("data/manifest.toml");
    validate_schema(
        "data/manifest.toml",
        manifest.schema_version,
        MANIFEST_SCHEMA,
    );
    let catalog_view = validate_timestamp("manifest.generated_at", &manifest.generated_at);
    let snapshots = validate_snapshots(&manifest, &catalog_view);

    let sources_file: SourcesFile = read_toml("data/policy/sources.toml");
    validate_schema(
        "data/policy/sources.toml",
        sources_file.schema_version,
        POLICY_SCHEMA,
    );
    let source_index = validate_sources(&sources_file.sources, &catalog_view);
    let evidence_index = validate_evidence(&sources_file.evidence, &source_index);

    let profiles_file: ProfilesFile = read_toml("data/policy/profiles.toml");
    validate_schema(
        "data/policy/profiles.toml",
        profiles_file.schema_version,
        POLICY_SCHEMA,
    );
    let flat_profiles = flatten_profiles(&profiles_file.profiles);
    validate_profiles(
        &flat_profiles,
        &evidence_index,
        &source_index,
        catalog_view.utc_day(),
    );

    let products_file: ProductsFile = read_toml("data/policy/products.toml");
    validate_schema(
        "data/policy/products.toml",
        products_file.schema_version,
        POLICY_SCHEMA,
    );

    let current_roots = parse_current_roots(snapshot_path(&snapshots, "iana_tlds"));
    let root_metadata = parse_root_database(snapshot_path(&snapshots, "iana_root_db"));
    let (psl_exact, psl_wildcard, psl_exception) = parse_psl(snapshot_path(&snapshots, "psl"));
    let special_use = parse_special_use(snapshot_path(&snapshots, "iana_special_use"));
    let active_spec13 = parse_active_spec13(snapshot_path(&snapshots, "icann_gtlds"));
    validate_root_metadata(&current_roots, &root_metadata);

    let (mut products, mut exact_selectors, one_below_selectors) = validate_products(
        &products_file.products,
        &flat_profiles,
        &evidence_index,
        &source_index,
        &psl_exception,
        &current_roots,
        &special_use,
    );
    add_active_spec13_products(
        &mut products,
        &mut exact_selectors,
        &active_spec13,
        &current_roots,
    );

    let generated = generate(
        &snapshots,
        &sources_file.evidence,
        &source_index,
        &current_roots,
        &root_metadata,
        &active_spec13,
        &psl_exact,
        &psl_wildcard,
        &psl_exception,
        &special_use,
        &flat_profiles,
        &products,
        &exact_selectors,
        &one_below_selectors,
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is not set"));
    let destination = out_dir.join("generated_catalog.rs");
    let mut file = fs::File::create(&destination)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", destination.display()));
    file.write_all(generated.as_bytes())
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", destination.display()));
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &str) -> T {
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
    toml::from_str(&text).unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
}

fn validate_schema(path: &str, actual: u32, expected: u32) {
    assert_eq!(
        actual, expected,
        "{path} uses schema {actual}; expected {expected}"
    );
}

fn validate_snapshots(
    manifest: &Manifest,
    catalog_view: &ParsedTimestamp,
) -> BTreeMap<String, Snapshot> {
    let mut result = BTreeMap::new();
    for snapshot in &manifest.snapshots {
        validate_id("snapshot", &snapshot.id);
        assert!(
            result
                .insert(snapshot.id.clone(), snapshot.clone())
                .is_none(),
            "duplicate snapshot id '{}'",
            snapshot.id
        );
        assert_https(&format!("snapshot '{}'.url", snapshot.id), &snapshot.url);
        assert_https(
            &format!("snapshot '{}'.license_url", snapshot.id),
            &snapshot.license_url,
        );
        let retrieved_at = validate_timestamp(
            &format!("snapshot '{}'.retrieved_at", snapshot.id),
            &snapshot.retrieved_at,
        );
        assert!(
            !retrieved_at.is_after(catalog_view),
            "snapshot '{}' was retrieved after manifest generation",
            snapshot.id
        );
        validate_hash(
            &format!("snapshot '{}'.sha256", snapshot.id),
            &snapshot.sha256,
        );
        assert!(
            !snapshot.parser_version.trim().is_empty(),
            "snapshot '{}' has no parser_version",
            snapshot.id
        );
        assert!(
            !snapshot.content_type.trim().is_empty(),
            "snapshot '{}' has no content_type",
            snapshot.id
        );
        assert!(
            !snapshot.license_spdx.trim().is_empty(),
            "snapshot '{}' has no license_spdx",
            snapshot.id
        );
        assert!(
            !snapshot.license_name.trim().is_empty(),
            "snapshot '{}' has no license_name",
            snapshot.id
        );
        let _optional_http_metadata = (
            &snapshot.upstream_version,
            &snapshot.upstream_commit,
            &snapshot.http_etag,
        );
        for (field, timestamp) in [
            ("upstream_updated_at", &snapshot.upstream_updated_at),
            ("http_last_modified", &snapshot.http_last_modified),
        ] {
            if let Some(timestamp) = timestamp {
                let timestamp =
                    validate_timestamp(&format!("snapshot '{}'.{field}", snapshot.id), timestamp);
                assert!(
                    !timestamp.is_after(&retrieved_at),
                    "snapshot '{}' {field} is after its retrieval time",
                    snapshot.id
                );
            }
        }

        let path = safe_repository_path(&snapshot.path);
        println!("cargo:rerun-if-changed={}", path.display());
        let payload = fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        assert_eq!(
            sha256(&payload),
            snapshot.sha256,
            "snapshot '{}' hash mismatch",
            snapshot.id
        );

        if let Some(license_path) = &snapshot.license_path {
            let expected = snapshot.license_sha256.as_ref().unwrap_or_else(|| {
                panic!(
                    "snapshot '{}' has license_path without license_sha256",
                    snapshot.id
                )
            });
            validate_hash(
                &format!("snapshot '{}'.license_sha256", snapshot.id),
                expected,
            );
            let license_path = safe_repository_path(license_path);
            println!("cargo:rerun-if-changed={}", license_path.display());
            let payload = fs::read(&license_path).unwrap_or_else(|error| {
                panic!("failed to read {}: {error}", license_path.display())
            });
            assert_eq!(
                sha256(&payload),
                *expected,
                "snapshot '{}' license hash mismatch",
                snapshot.id
            );
            assert!(
                snapshot
                    .license_source_url
                    .as_deref()
                    .is_some_and(|value| value.starts_with("https://")),
                "snapshot '{}' has no HTTPS license source URL",
                snapshot.id
            );
            let license_retrieved_at = validate_timestamp(
                &format!("snapshot '{}'.license_retrieved_at", snapshot.id),
                snapshot.license_retrieved_at.as_deref().unwrap_or_else(|| {
                    panic!("snapshot '{}' has no license_retrieved_at", snapshot.id)
                }),
            );
            assert!(
                !license_retrieved_at.is_after(catalog_view),
                "snapshot '{}' license was retrieved after manifest generation",
                snapshot.id
            );
        } else {
            assert!(
                snapshot.license_sha256.is_none()
                    && snapshot.license_source_url.is_none()
                    && snapshot.license_retrieved_at.is_none()
                    && snapshot.license_http_etag.is_none(),
                "snapshot '{}' has partial license-file provenance",
                snapshot.id
            );
        }
    }

    for (id, expected_kind) in REQUIRED_SNAPSHOTS {
        let snapshot = result
            .get(*id)
            .unwrap_or_else(|| panic!("required snapshot '{id}' is missing"));
        assert_eq!(
            &snapshot.kind, expected_kind,
            "snapshot '{id}' has the wrong kind"
        );
    }
    result
}

fn safe_repository_path(value: &str) -> PathBuf {
    let path = Path::new(value);
    assert!(
        !path.is_absolute(),
        "repository data path must be relative: {value}"
    );
    assert!(
        path.components()
            .all(|part| matches!(part, Component::Normal(_))),
        "repository data path contains unsafe components: {value}"
    );
    path.to_path_buf()
}

fn snapshot_path<'a>(snapshots: &'a BTreeMap<String, Snapshot>, id: &str) -> &'a Path {
    Path::new(
        &snapshots
            .get(id)
            .unwrap_or_else(|| panic!("missing snapshot '{id}'"))
            .path,
    )
}

fn validate_sources<'a>(
    sources: &'a [SourceRecord],
    catalog_view: &ParsedTimestamp,
) -> BTreeMap<String, &'a SourceRecord> {
    let mut result = BTreeMap::new();
    for source in sources {
        validate_id("source", &source.id);
        assert!(
            result.insert(source.id.clone(), source).is_none(),
            "duplicate source id '{}'",
            source.id
        );
        source_kind(&source.kind);
        assert!(
            !source.publisher_role.trim().is_empty(),
            "source '{}' has no publisher_role",
            source.id
        );
        assert!(
            !source.publisher.trim().is_empty(),
            "source '{}' has no publisher",
            source.id
        );
        assert_https(&format!("source '{}'.url", source.id), &source.url);
        let retrieved_at = validate_timestamp(
            &format!("source '{}'.retrieved_at", source.id),
            &source.retrieved_at,
        );
        assert!(
            !retrieved_at.is_after(catalog_view),
            "source '{}' was retrieved after catalog generation",
            source.id
        );
        validate_hash(&format!("source '{}'.sha256", source.id), &source.sha256);
        let review_after = validate_date(
            &format!("source '{}'.review_after", source.id),
            &source.review_after,
        );
        assert!(
            review_after >= retrieved_at.utc_day(),
            "source '{}' has review_after before its retrieval date",
            source.id
        );
    }
    result
}

fn validate_evidence<'a>(
    evidence: &'a [EvidenceRecord],
    sources: &BTreeMap<String, &'a SourceRecord>,
) -> BTreeMap<String, &'a EvidenceRecord> {
    let mut result = BTreeMap::new();
    for item in evidence {
        validate_id("evidence", &item.id);
        assert!(
            result.insert(item.id.clone(), item).is_none(),
            "duplicate evidence id '{}'",
            item.id
        );
        let source = sources.get(&item.source).unwrap_or_else(|| {
            panic!(
                "evidence '{}' refers to unknown source '{}'",
                item.id, item.source
            )
        });
        assert!(
            !item.locator.trim().is_empty(),
            "evidence '{}' has no document locator",
            item.id
        );
        assert!(
            !item.predicates.is_empty(),
            "evidence '{}' has no predicates",
            item.id
        );
        assert!(
            !item.scope.products.is_empty(),
            "evidence '{}' has no product scope",
            item.id
        );
        let mut predicates = BTreeSet::new();
        for predicate in &item.predicates {
            assert!(
                predicates.insert(predicate),
                "evidence '{}' repeats predicate '{predicate}'",
                item.id
            );
            assert!(
                source_can_prove(source_kind(&source.kind), predicate),
                "source '{}' of kind '{}' cannot establish predicate '{}' for evidence '{}'",
                source.id,
                source.kind,
                predicate,
                item.id
            );
        }
        let mut products = BTreeSet::new();
        for product in &item.scope.products {
            validate_id("scoped product", product);
            assert!(
                products.insert(product),
                "evidence '{}' repeats scoped product '{product}'",
                item.id
            );
        }
    }
    result
}

fn source_can_prove(kind: SourceKindCode, predicate: &str) -> bool {
    match kind {
        SourceKindCode::IanaCurrentRoot => predicate == "root_state",
        SourceKindCode::IanaRootDatabase => matches!(predicate, "root_metadata" | "operator"),
        SourceKindCode::PublicSuffixList => predicate == "suffix_topology",
        SourceKindCode::RegistryAgreement => {
            matches!(predicate, "designation" | "contract_lifecycle")
        }
        SourceKindCode::RegistryPolicy | SourceKindCode::GovernmentPolicy => matches!(
            predicate,
            "offering_state"
                | "public_access"
                | "application_channel"
                | "eligibility"
                | "label_policy"
                | "label_length"
                | "idn_support"
                | "reserved_labels"
        ),
        SourceKindCode::SpecialUseRegistry => predicate == "special_use",
        SourceKindCode::StandardsDocument => {
            matches!(
                predicate,
                "offering_state" | "public_access" | "special_use"
            )
        }
        SourceKindCode::RegistryIdnTable | SourceKindCode::IanaIdnTable => {
            matches!(predicate, "idn_support" | "idn_profile")
        }
        SourceKindCode::Secondary => false,
    }
}

fn source_kind(value: &str) -> SourceKindCode {
    match value {
        "iana_current_root" | "current_root_tld_list" => SourceKindCode::IanaCurrentRoot,
        "iana_root_database" | "root_zone_database" => SourceKindCode::IanaRootDatabase,
        "public_suffix_list" => SourceKindCode::PublicSuffixList,
        "registry_agreement" | "gtld_registry_agreements" => SourceKindCode::RegistryAgreement,
        "registry_policy" => SourceKindCode::RegistryPolicy,
        "government_policy" => SourceKindCode::GovernmentPolicy,
        "special_use_registry" | "special_use_domain_names" => SourceKindCode::SpecialUseRegistry,
        "standards_document" => SourceKindCode::StandardsDocument,
        "registry_idn_table" => SourceKindCode::RegistryIdnTable,
        "iana_idn_table" => SourceKindCode::IanaIdnTable,
        "secondary" => SourceKindCode::Secondary,
        _ => panic!("unknown source kind '{value}'"),
    }
}

fn flatten_profiles(profiles: &[ProfileRecord]) -> BTreeMap<String, FlatProfile> {
    let mut records = BTreeMap::new();
    for profile in profiles {
        validate_id("profile", &profile.id);
        assert!(
            records
                .insert(profile.id.clone(), profile.clone())
                .is_none(),
            "duplicate profile id '{}'",
            profile.id
        );
    }
    let mut cache = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    for id in records.keys() {
        resolve_profile(id, &records, &mut cache, &mut visiting);
    }
    cache
}

fn resolve_profile(
    id: &str,
    records: &BTreeMap<String, ProfileRecord>,
    cache: &mut BTreeMap<String, FlatProfile>,
    visiting: &mut BTreeSet<String>,
) -> FlatProfile {
    if let Some(profile) = cache.get(id) {
        return profile.clone();
    }
    assert!(
        visiting.insert(id.to_string()),
        "profile inheritance cycle includes '{id}'"
    );
    let authored = records
        .get(id)
        .unwrap_or_else(|| panic!("unknown inherited profile '{id}'"));
    let mut flat = if let Some(parent) = &authored.extends {
        resolve_profile(parent, records, cache, visiting)
    } else {
        FlatProfile::default()
    };
    flat.id.clone_from(&authored.id);
    flat.extends.clone_from(&authored.extends);
    if authored.offering_state.is_some() {
        flat.offering_state.clone_from(&authored.offering_state);
    }
    if authored.public_access.is_some() {
        flat.public_access.clone_from(&authored.public_access);
    }
    if authored.application_channel.is_some() {
        flat.application_channel
            .clone_from(&authored.application_channel);
    }
    if authored.eligibility.is_some() {
        flat.eligibility.clone_from(&authored.eligibility);
    }
    if authored.label_policy.is_some() {
        flat.label_policy.clone_from(&authored.label_policy);
    }
    visiting.remove(id);
    cache.insert(id.to_string(), flat.clone());
    flat
}

fn validate_profiles(
    profiles: &BTreeMap<String, FlatProfile>,
    evidence: &BTreeMap<String, &EvidenceRecord>,
    sources: &BTreeMap<String, &SourceRecord>,
    catalog_view_day: i64,
) {
    let mut requirements_by_id = BTreeMap::new();
    let mut label_policies_by_id = BTreeMap::new();
    let mut idn_profiles_by_id = BTreeMap::new();
    for profile in profiles.values() {
        validate_claim(
            profile,
            "offering_state",
            profile.offering_state.as_ref(),
            &[
                "accepting",
                "paused",
                "renewal_only",
                "not_launched",
                "closed",
            ],
            evidence,
            sources,
            catalog_view_day,
        );
        validate_claim(
            profile,
            "public_access",
            profile.public_access.as_ref(),
            &["open", "conditional", "controlled_group", "unavailable"],
            evidence,
            sources,
            catalog_view_day,
        );
        validate_claim(
            profile,
            "application_channel",
            profile.application_channel.as_ref(),
            &[
                "registrar",
                "registry_direct",
                "approval_workflow",
                "delegated_authority",
                "internal",
            ],
            evidence,
            sources,
            catalog_view_day,
        );
        match verified_claim_value(profile.public_access.as_ref()) {
            Some(value @ ("open" | "unavailable")) => assert!(
                profile.eligibility.is_none(),
                "profile '{}' has verified {} public access but also carries eligibility rules",
                profile.id,
                value
            ),
            Some("conditional" | "controlled_group") => assert!(
                profile.eligibility.is_some(),
                "profile '{}' has verified gated public access without eligibility rules",
                profile.id
            ),
            Some(_) | None => {}
        }
        if let Some(expression) = &profile.eligibility {
            assert!(
                matches!(expression.mode.as_str(), "all" | "any"),
                "profile '{}' has invalid eligibility mode '{}'",
                profile.id,
                expression.mode
            );
            assert!(
                !expression.requirements.is_empty(),
                "profile '{}' has an empty eligibility expression",
                profile.id
            );
            for requirement in &expression.requirements {
                validate_id("eligibility requirement", &requirement.id);
                if let Some(previous) =
                    requirements_by_id.insert(requirement.id.clone(), requirement.clone())
                {
                    assert_eq!(
                        previous, *requirement,
                        "eligibility requirement id '{}' has conflicting definitions",
                        requirement.id
                    );
                }
                eligibility_kind(&requirement.kind);
                assert!(
                    !requirement.value.trim().is_empty(),
                    "requirement '{}' has no value",
                    requirement.id
                );
                assert!(
                    !requirement.explanation.trim().is_empty(),
                    "requirement '{}' has no explanation",
                    requirement.id
                );
                assert!(
                    !requirement.evidence.is_empty(),
                    "requirement '{}' has no evidence",
                    requirement.id
                );
                validate_evidence_references(
                    &profile.id,
                    "eligibility",
                    &requirement.evidence,
                    evidence,
                    sources,
                    claim_is_verified(profile.public_access.as_ref()),
                    catalog_view_day,
                );
            }
        }
        if let Some(policy) = &profile.label_policy {
            validate_id("label policy", &policy.id);
            if let Some(previous) = label_policies_by_id.insert(policy.id.clone(), policy.clone()) {
                assert_eq!(
                    previous, *policy,
                    "label policy id '{}' has conflicting definitions",
                    policy.id
                );
            }
            validate_status_evidence(
                profile,
                "label_policy",
                &policy.completeness,
                &policy.completeness_evidence,
                evidence,
                sources,
                catalog_view_day,
            );
            validate_status_evidence(
                profile,
                "reserved_labels",
                &policy.reserved_status,
                &policy.reserved_set_evidence,
                evidence,
                sources,
                catalog_view_day,
            );
            if let Some(length) = &policy.length {
                assert!(
                    length.minimum > 0 && length.minimum <= length.maximum,
                    "label policy '{}' has invalid length range",
                    policy.id
                );
                assert!(
                    !length.evidence.is_empty(),
                    "label policy '{}' has a length constraint without evidence",
                    policy.id
                );
                length_unit(&length.unit);
                validate_evidence_references(
                    &profile.id,
                    "label_length",
                    &length.evidence,
                    evidence,
                    sources,
                    true,
                    catalog_view_day,
                );
            }
            validate_claim(
                profile,
                "idn_support",
                policy.idn_support.as_ref(),
                &["supported", "unsupported"],
                evidence,
                sources,
                catalog_view_day,
            );
            if let Some(idn_profile) = &policy.idn_profile {
                validate_id("IDN profile", &idn_profile.id);
                if let Some(previous) =
                    idn_profiles_by_id.insert(idn_profile.id.clone(), idn_profile.clone())
                {
                    assert_eq!(
                        previous, *idn_profile,
                        "IDN profile id '{}' has conflicting definitions",
                        idn_profile.id
                    );
                }
                assert!(
                    !idn_profile.version.trim().is_empty(),
                    "IDN profile '{}' has no version",
                    idn_profile.id
                );
                assert!(
                    !idn_profile.evidence.is_empty(),
                    "IDN profile '{}' has no evidence",
                    idn_profile.id
                );
                validate_evidence_references(
                    &profile.id,
                    "idn_profile",
                    &idn_profile.evidence,
                    evidence,
                    sources,
                    claim_is_verified(policy.idn_support.as_ref()),
                    catalog_view_day,
                );
                assert_eq!(
                    policy
                        .idn_support
                        .as_ref()
                        .and_then(|claim| claim.value.as_deref()),
                    Some("supported"),
                    "label policy '{}' has an IDN profile without supported IDN status",
                    policy.id
                );
            }
            let mut labels = BTreeSet::new();
            for reserved in &policy.reserved_labels {
                let label = canonical_name(
                    &reserved.label,
                    &format!("reserved label in '{}'", policy.id),
                );
                assert!(
                    !label.contains('.'),
                    "reserved label '{}' in '{}' is not one label",
                    reserved.label,
                    policy.id
                );
                assert!(
                    labels.insert(label),
                    "label policy '{}' repeats reserved label '{}'",
                    policy.id,
                    reserved.label
                );
                reserved_disposition(&reserved.disposition);
                assert!(
                    !reserved.evidence.is_empty(),
                    "reserved label '{}' in '{}' has no evidence",
                    reserved.label,
                    policy.id
                );
                validate_evidence_references(
                    &profile.id,
                    "reserved_labels",
                    &reserved.evidence,
                    evidence,
                    sources,
                    policy.reserved_status == "verified",
                    catalog_view_day,
                );
            }
        }
    }
}

fn validate_status_evidence(
    profile: &FlatProfile,
    predicate: &str,
    status: &str,
    evidence_ids: &[String],
    evidence: &BTreeMap<String, &EvidenceRecord>,
    sources: &BTreeMap<String, &SourceRecord>,
    catalog_view_day: i64,
) {
    claim_status(status);
    match status {
        "verified" | "stale" => assert!(
            !evidence_ids.is_empty(),
            "profile '{}' {predicate} {status} status has no evidence",
            profile.id
        ),
        "conflicting" => assert!(
            evidence_ids.len() >= 2,
            "profile '{}' conflicting {predicate} status needs at least two evidence records",
            profile.id
        ),
        "unknown" => {}
        _ => unreachable!("claim status was validated"),
    }
    validate_evidence_references(
        &profile.id,
        predicate,
        evidence_ids,
        evidence,
        sources,
        status == "verified",
        catalog_view_day,
    );
}

fn validate_claim(
    profile: &FlatProfile,
    predicate: &str,
    claim: Option<&ClaimRecord>,
    allowed_values: &[&str],
    evidence: &BTreeMap<String, &EvidenceRecord>,
    sources: &BTreeMap<String, &SourceRecord>,
    catalog_view_day: i64,
) {
    let Some(claim) = claim else { return };
    let status = claim.status.as_deref().unwrap_or(if claim.value.is_some() {
        "verified"
    } else {
        "unknown"
    });
    claim_status(status);
    match status {
        "verified" | "stale" => {
            let value = claim.value.as_deref().unwrap_or_else(|| {
                panic!(
                    "profile '{}' {predicate} {status} claim has no value",
                    profile.id
                )
            });
            assert!(
                allowed_values.contains(&value),
                "profile '{}' has invalid {predicate} value '{value}'",
                profile.id
            );
            assert!(
                !claim.evidence.is_empty(),
                "profile '{}' {predicate} {status} claim has no evidence",
                profile.id
            );
        }
        "conflicting" => {
            assert!(
                claim.value.is_none(),
                "profile '{}' conflicting {predicate} claim must not choose a value",
                profile.id
            );
            assert!(
                claim.evidence.len() >= 2,
                "profile '{}' conflicting {predicate} claim needs at least two evidence records",
                profile.id
            );
        }
        "unknown" => assert!(
            claim.value.is_none(),
            "profile '{}' unknown {predicate} claim must not have a value",
            profile.id
        ),
        _ => unreachable!(),
    }
    validate_evidence_references(
        &profile.id,
        predicate,
        &claim.evidence,
        evidence,
        sources,
        status == "verified",
        catalog_view_day,
    );
}

fn claim_is_verified(claim: Option<&ClaimRecord>) -> bool {
    let Some(claim) = claim else { return false };
    claim.status.as_deref().unwrap_or(if claim.value.is_some() {
        "verified"
    } else {
        "unknown"
    }) == "verified"
}

fn verified_claim_value(claim: Option<&ClaimRecord>) -> Option<&str> {
    let claim = claim?;
    let status = claim.status.as_deref().unwrap_or(if claim.value.is_some() {
        "verified"
    } else {
        "unknown"
    });
    (status == "verified")
        .then_some(claim.value.as_deref())
        .flatten()
}

fn validate_evidence_references(
    profile: &str,
    predicate: &str,
    ids: &[String],
    evidence: &BTreeMap<String, &EvidenceRecord>,
    sources: &BTreeMap<String, &SourceRecord>,
    require_current: bool,
    catalog_view_day: i64,
) {
    let mut unique = BTreeSet::new();
    for id in ids {
        assert!(
            unique.insert(id),
            "profile '{profile}' repeats evidence '{id}' for {predicate}"
        );
        let item = evidence
            .get(id)
            .unwrap_or_else(|| panic!("profile '{profile}' refers to unknown evidence '{id}'"));
        assert!(
            item.predicates
                .iter()
                .any(|candidate| candidate == predicate),
            "evidence '{id}' is not scoped to predicate '{predicate}'"
        );
        let source = sources
            .get(&item.source)
            .expect("evidence source was validated");
        assert!(
            source_can_prove(source_kind(&source.kind), predicate),
            "source '{}' cannot prove {predicate}",
            source.id
        );
        if require_current {
            let review_after = validate_date(
                &format!("source '{}'.review_after", source.id),
                &source.review_after,
            );
            assert!(
                review_after >= catalog_view_day,
                "profile '{profile}' active {predicate} depends on expired evidence '{id}' \
                 from source '{}' (review_after {}); refresh the source or mark the dependent \
                 claim stale, unknown, or conflicting",
                source.id,
                source.review_after
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_products(
    authored: &[ProductRecord],
    profiles: &BTreeMap<String, FlatProfile>,
    evidence: &BTreeMap<String, &EvidenceRecord>,
    sources: &BTreeMap<String, &SourceRecord>,
    exception_rules: &BTreeMap<String, CompiledSuffixRule>,
    roots: &BTreeSet<String>,
    special_use: &BTreeSet<String>,
) -> (
    BTreeMap<String, GeneratedProduct>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
) {
    let mut products = BTreeMap::new();
    let mut exact = BTreeMap::new();
    let mut one_below = BTreeMap::new();
    for product in authored {
        validate_id("product", &product.id);
        validate_id("operator", &product.operator);
        let profile = profiles.get(&product.profile).unwrap_or_else(|| {
            panic!(
                "product '{}' refers to unknown profile '{}'",
                product.id, product.profile
            )
        });
        assert!(
            !product.selectors.is_empty(),
            "product '{}' has no selectors",
            product.id
        );
        for designation in &product.designations {
            designation_variant(designation);
        }
        for (predicate, evidence_id) in profile_evidence(profile) {
            let item = evidence
                .get(evidence_id)
                .expect("profile evidence was validated");
            assert!(
                item.scope.products.iter().any(|id| id == &product.id),
                "evidence '{}' for {} is not scoped to product '{}'",
                item.id,
                predicate,
                product.id
            );
            let source = sources
                .get(&item.source)
                .expect("evidence source was validated");
            assert!(
                source_can_prove(source_kind(&source.kind), predicate),
                "source '{}' cannot prove {}",
                source.id,
                predicate
            );
        }
        for selector in &product.selectors {
            let suffix =
                canonical_name(&selector.suffix, &format!("selector for '{}'", product.id));
            validate_runtime_dns_name(&suffix, &format!("product '{}' selector", product.id));
            assert!(
                selector_namespace_is_known(&suffix, roots, special_use),
                "product '{}' selector '{}' is not anchored in a current or special-use namespace",
                product.id,
                suffix
            );
            assert!(
                !exception_rules.contains_key(&suffix),
                "product '{}' selector '{}' is a raw PSL exception, not an allocation boundary",
                product.id,
                suffix
            );
            let (destination, required_prefix_length) = match selector.kind.as_str() {
                "exact" => (&mut exact, 2),
                "one_label_below" => (&mut one_below, 4),
                other => panic!(
                    "product '{}' has unknown selector kind '{other}'",
                    product.id
                ),
            };
            assert!(
                suffix.len() + required_prefix_length <= 253,
                "product '{}' selector '{}' leaves no DNS space for a registrable candidate",
                product.id,
                suffix
            );
            if let Some(previous) = destination.insert(suffix.clone(), product.id.clone()) {
                panic!(
                    "same-rank selector ambiguity for '{suffix}': products '{previous}' and '{}'",
                    product.id
                );
            }
        }
        let compiled = GeneratedProduct {
            id: product.id.clone(),
            operator: product.operator.clone(),
            profile_id: product.profile.clone(),
            designations: product.designations.clone(),
        };
        assert!(
            products.insert(product.id.clone(), compiled).is_none(),
            "duplicate product id '{}'",
            product.id
        );
    }

    for item in evidence.values() {
        for product in &item.scope.products {
            assert!(
                products.contains_key(product),
                "evidence '{}' is scoped to unknown product '{product}'",
                item.id
            );
        }
    }
    (products, exact, one_below)
}

fn profile_evidence(profile: &FlatProfile) -> Vec<(&'static str, &str)> {
    let mut result = Vec::new();
    for (predicate, claim) in [
        ("offering_state", profile.offering_state.as_ref()),
        ("public_access", profile.public_access.as_ref()),
        ("application_channel", profile.application_channel.as_ref()),
    ] {
        if let Some(claim) = claim {
            result.extend(claim.evidence.iter().map(|id| (predicate, id.as_str())));
        }
    }
    if let Some(eligibility) = &profile.eligibility {
        for requirement in &eligibility.requirements {
            result.extend(
                requirement
                    .evidence
                    .iter()
                    .map(|id| ("eligibility", id.as_str())),
            );
        }
    }
    if let Some(policy) = &profile.label_policy {
        result.extend(
            policy
                .completeness_evidence
                .iter()
                .map(|id| ("label_policy", id.as_str())),
        );
        if let Some(length) = &policy.length {
            result.extend(
                length
                    .evidence
                    .iter()
                    .map(|id| ("label_length", id.as_str())),
            );
        }
        if let Some(claim) = &policy.idn_support {
            result.extend(claim.evidence.iter().map(|id| ("idn_support", id.as_str())));
        }
        if let Some(idn) = &policy.idn_profile {
            result.extend(idn.evidence.iter().map(|id| ("idn_profile", id.as_str())));
        }
        for reserved in &policy.reserved_labels {
            result.extend(
                reserved
                    .evidence
                    .iter()
                    .map(|id| ("reserved_labels", id.as_str())),
            );
        }
        result.extend(
            policy
                .reserved_set_evidence
                .iter()
                .map(|id| ("reserved_labels", id.as_str())),
        );
    }
    result
}

fn selector_namespace_is_known(
    value: &str,
    roots: &BTreeSet<String>,
    special: &BTreeSet<String>,
) -> bool {
    let root = value.rsplit('.').next().expect("selector has labels");
    roots.contains(root) || special.contains(root) || special.contains(value)
}

fn validate_runtime_dns_name(value: &str, context: &str) {
    assert!(
        value.len() <= 253,
        "{context} '{value}' exceeds the runtime DNS name limit"
    );
    for label in value.split('.') {
        assert!(
            label.len() <= 63,
            "{context} '{value}' contains a label longer than the runtime DNS limit"
        );
        assert!(
            !label.starts_with('-') && !label.ends_with('-'),
            "{context} '{value}' contains a label with an invalid edge hyphen"
        );
        assert!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "{context} '{value}' contains characters rejected by the runtime DNS validator"
        );
    }
}

fn parse_current_roots(path: &Path) -> BTreeSet<String> {
    let text = read_text(path);
    let mut lines = text.lines();
    let header = lines.next().unwrap_or_default();
    assert!(
        header.starts_with("# Version "),
        "{} has an invalid IANA TLD header",
        path.display()
    );
    let mut roots = BTreeSet::new();
    for line in lines.map(str::trim).filter(|line| !line.is_empty()) {
        let label = canonical_name(line, "IANA current root label");
        assert!(
            !label.contains('.'),
            "IANA current root entry '{line}' is not one label"
        );
        assert!(
            roots.insert(label),
            "IANA current root list repeats '{line}'"
        );
    }
    assert!(
        roots.len() >= 1_000 && roots.contains("arpa") && roots.contains("com"),
        "IANA current root list failed sanity checks"
    );
    roots
}

fn parse_root_database(path: &Path) -> BTreeMap<String, RootMetadata> {
    let text = read_text(path);
    let row_re = Regex::new(r"(?s)<tr>(.*?)</tr>").expect("valid row regex");
    // Visible IDN labels contain bidi marks and entities. IANA's per-record
    // URL contains the canonical A-label and is therefore the safe key.
    let label_re =
        Regex::new(r#"href="/domains/root/db/([a-z0-9-]+)\.html""#).expect("valid label regex");
    let cell_re = Regex::new(r"(?s)<td[^>]*>(.*?)</td>").expect("valid cell regex");
    let tag_re = Regex::new(r"(?s)<[^>]+>").expect("valid tag regex");
    let mut result = BTreeMap::new();
    for row in row_re.captures_iter(&text) {
        let body = &row[1];
        let Some(label_capture) = label_re.captures(body) else {
            continue;
        };
        let cells = cell_re
            .captures_iter(body)
            .map(|capture| html_text(&tag_re, &capture[1]))
            .collect::<Vec<_>>();
        assert!(
            cells.len() >= 3,
            "root database row for '{}' has fewer than three cells",
            &label_capture[1]
        );
        let label = canonical_name(&label_capture[1], "IANA root database label");
        let metadata = RootMetadata {
            raw_type: cells[1].clone(),
            manager: cells[2].clone(),
        };
        assert!(
            result.insert(label.clone(), metadata).is_none(),
            "IANA root database repeats '{label}'"
        );
    }
    assert!(
        result.len() >= 1_500,
        "IANA root database parser found only {} rows",
        result.len()
    );
    result
}

fn html_text(tag_re: &Regex, value: &str) -> String {
    let stripped = tag_re.replace_all(value, " ");
    stripped
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_root_metadata(roots: &BTreeSet<String>, metadata: &BTreeMap<String, RootMetadata>) {
    for root in roots {
        let record = metadata.get(root).unwrap_or_else(|| {
            panic!("current root '{root}' is missing from the pinned IANA root database")
        });
        root_family(&record.raw_type);
        assert_ne!(
            record.manager, "Not assigned",
            "current root '{root}' has no assigned manager in the root database"
        );
    }
}

fn parse_psl(
    path: &Path,
) -> (
    BTreeMap<String, CompiledSuffixRule>,
    BTreeMap<String, CompiledSuffixRule>,
    BTreeMap<String, CompiledSuffixRule>,
) {
    let text = read_text(path);
    let mut section = None;
    let mut exact = BTreeMap::new();
    let mut wildcard = BTreeMap::new();
    let mut exception = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        match line {
            "// ===BEGIN ICANN DOMAINS===" => {
                section = Some(("PslSection::Icann", "SuffixRole::RegistryBoundary"));
                continue;
            }
            "// ===END ICANN DOMAINS===" => {
                section = None;
                continue;
            }
            "// ===BEGIN PRIVATE DOMAINS===" => {
                section = Some(("PslSection::Private", "SuffixRole::PrivateServiceBoundary"));
                continue;
            }
            "// ===END PRIVATE DOMAINS===" => {
                section = None;
                continue;
            }
            _ => {}
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let (section, role) =
            section.unwrap_or_else(|| panic!("PSL rule outside a recognized section: '{line}'"));
        let (kind, unmarked, destination) = if let Some(value) = line.strip_prefix('!') {
            ("SuffixRuleKind::Exception", value, &mut exception)
        } else if let Some(value) = line.strip_prefix("*.") {
            ("SuffixRuleKind::Wildcard", value, &mut wildcard)
        } else {
            ("SuffixRuleKind::Exact", line, &mut exact)
        };
        let labels = canonical_name(unmarked, "PSL rule");
        let compiled = CompiledSuffixRule {
            labels: labels.clone(),
            kind,
            section,
            role,
        };
        if let Some(previous) = destination.insert(labels.clone(), compiled.clone()) {
            assert!(
                previous.kind == compiled.kind && previous.section == compiled.section,
                "canonical PSL collision for '{labels}'"
            );
        }
    }
    assert!(
        exact.len() + wildcard.len() + exception.len() >= 5_000,
        "PSL parser found too few rules"
    );
    (exact, wildcard, exception)
}

fn parse_special_use(path: &Path) -> BTreeSet<String> {
    let mut reader = csv::Reader::from_path(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let headers = reader
        .headers()
        .unwrap_or_else(|error| panic!("invalid {} header: {error}", path.display()));
    assert_eq!(
        headers.iter().collect::<Vec<_>>(),
        vec!["Name", "Reference"],
        "unexpected special-use CSV header"
    );
    let mut result = BTreeSet::new();
    for row in reader.records() {
        let row = row.unwrap_or_else(|error| panic!("invalid {} row: {error}", path.display()));
        let raw = row.get(0).expect("Name column").trim();
        let raw = raw
            .strip_suffix(" (DEPRECATED)")
            .unwrap_or(raw)
            .trim_end_matches('.');
        let name = canonical_name(raw, "IANA special-use name");
        assert!(
            result.insert(name.clone()),
            "special-use registry repeats '{name}'"
        );
        assert!(
            !row.get(1).unwrap_or_default().trim().is_empty(),
            "special-use name '{name}' has no reference"
        );
    }
    assert!(
        result.contains("test") && result.contains("example.com") && result.contains("onion"),
        "special-use registry failed sanity checks"
    );
    result
}

fn parse_active_spec13(path: &Path) -> BTreeMap<String, String> {
    let text = read_text(path);
    let parsed: IcannGtlds = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
    assert_eq!(parsed.version, 2, "unsupported ICANN gTLD dataset version");
    validate_timestamp("ICANN gTLD updatedOn", &parsed.updated_on);
    assert!(
        parsed.gtlds.len() >= 1_000,
        "ICANN gTLD dataset is unexpectedly short"
    );
    let mut result = BTreeMap::new();
    for record in parsed.gtlds {
        let _provenance_fields = (
            &record.application_id,
            &record.date_of_contract_signature,
            &record.registry_class_domain_name_list,
            &record.registry_operator_country_code,
            &record.third_or_lower_level_registration,
            &record.u_label,
        );
        if record.specification13 != Some(true)
            || record.contract_terminated
            || record.delegation_date.is_none()
            || record.removal_date.is_some()
        {
            continue;
        }
        let label = canonical_name(&record.gtld, "ICANN gTLD label");
        assert!(
            !label.contains('.'),
            "ICANN gTLD '{}' is not one label",
            record.gtld
        );
        let operator = record
            .registry_operator
            .unwrap_or_else(|| panic!("active Specification 13 gTLD '{label}' has no operator"));
        assert!(
            result.insert(label.clone(), operator).is_none(),
            "ICANN dataset repeats active Specification 13 gTLD '{label}'"
        );
    }
    assert!(
        result.len() >= 300,
        "ICANN dataset yielded only {} active Specification 13 gTLDs",
        result.len()
    );
    result
}

fn add_active_spec13_products(
    products: &mut BTreeMap<String, GeneratedProduct>,
    exact: &mut BTreeMap<String, String>,
    spec13: &BTreeMap<String, String>,
    roots: &BTreeSet<String>,
) {
    for (label, operator) in spec13 {
        assert!(
            roots.contains(label),
            "active Specification 13 gTLD '{label}' is absent from current IANA roots"
        );
        if exact.contains_key(label) {
            continue;
        }
        let id = format!("icann-spec13-{label}");
        let product = GeneratedProduct {
            id: id.clone(),
            operator: slug_id(operator),
            profile_id: "icann-active-spec13-baseline-v1".to_string(),
            designations: vec!["brand_spec13".to_string()],
        };
        assert!(
            products.insert(id.clone(), product).is_none(),
            "generated Specification 13 product id collision '{id}'"
        );
        assert!(
            exact.insert(label.clone(), id).is_none(),
            "generated Specification 13 selector collision '{label}'"
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn generate(
    snapshots: &BTreeMap<String, Snapshot>,
    evidence: &[EvidenceRecord],
    source_index: &BTreeMap<String, &SourceRecord>,
    roots: &BTreeSet<String>,
    root_metadata: &BTreeMap<String, RootMetadata>,
    spec13: &BTreeMap<String, String>,
    psl_exact: &BTreeMap<String, CompiledSuffixRule>,
    psl_wildcard: &BTreeMap<String, CompiledSuffixRule>,
    psl_exception: &BTreeMap<String, CompiledSuffixRule>,
    special_use: &BTreeSet<String>,
    profiles: &BTreeMap<String, FlatProfile>,
    products: &BTreeMap<String, GeneratedProduct>,
    exact_selectors: &BTreeMap<String, String>,
    one_below_selectors: &BTreeMap<String, String>,
) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "// @generated by build.rs from pinned schema-v2 data; do not edit."
    )
    .unwrap();
    writeln!(out, "use crate::types::*;\n").unwrap();

    render_evidence_map(&mut out, snapshots, evidence, source_index);
    render_root_map(&mut out, roots, root_metadata, spec13, special_use);
    render_suffix_map(&mut out, "PSL_EXACT", psl_exact);
    render_suffix_map(&mut out, "PSL_WILDCARD", psl_wildcard);
    render_suffix_map(&mut out, "PSL_EXCEPTION", psl_exception);
    render_special_use(&mut out, special_use);
    render_profiles(&mut out, profiles);
    render_products(&mut out, products, profiles);
    render_string_map(&mut out, "PRODUCT_BY_SUFFIX", exact_selectors);
    render_string_map(&mut out, "PRODUCT_ONE_LABEL_BELOW", one_below_selectors);

    writeln!(
        out,
        "pub const CURRENT_ROOT_EVIDENCE: &str = \"iana_tlds\";"
    )
    .unwrap();
    writeln!(
        out,
        "pub const SPECIAL_USE_EVIDENCE: &str = \"iana_special_use\";"
    )
    .unwrap();
    out
}

fn render_evidence_map(
    out: &mut String,
    snapshots: &BTreeMap<String, Snapshot>,
    evidence: &[EvidenceRecord],
    source_index: &BTreeMap<String, &SourceRecord>,
) {
    let mut map = phf_codegen::Map::new();
    for snapshot in snapshots.values() {
        let kind_code = source_kind(&snapshot.kind);
        let kind = source_kind_variant(kind_code);
        let publisher = match kind_code {
            SourceKindCode::PublicSuffixList => "Public Suffix List maintainers",
            SourceKindCode::RegistryAgreement => "ICANN",
            _ => "Internet Assigned Numbers Authority",
        };
        let value = format!(
            "Evidence {{ id: {:?}, kind: {kind}, publisher: {:?}, url: {:?}, locator: {:?}, retrieved_at: {:?}, sha256: {:?}, review_after: None }}",
            snapshot.id,
            publisher,
            snapshot.url,
            snapshot.parser_version,
            snapshot.retrieved_at,
            snapshot.sha256
        );
        map.entry(snapshot.id.as_str(), &value);
    }
    for item in evidence {
        assert!(
            !snapshots.contains_key(&item.id),
            "evidence id '{}' collides with snapshot evidence",
            item.id
        );
        let source = source_index
            .get(&item.source)
            .expect("evidence source was validated");
        let kind = source_kind_variant(source_kind(&source.kind));
        let value = format!(
            "Evidence {{ id: {:?}, kind: {kind}, publisher: {:?}, url: {:?}, locator: {:?}, retrieved_at: {:?}, sha256: {:?}, review_after: Some({:?}) }}",
            item.id,
            source.publisher,
            source.url,
            item.locator,
            source.retrieved_at,
            source.sha256,
            source.review_after
        );
        map.entry(item.id.as_str(), &value);
    }
    writeln!(
        out,
        "pub static EVIDENCE: phf::Map<&'static str, Evidence> = {};\n",
        map.build()
    )
    .unwrap();
}

fn render_root_map(
    out: &mut String,
    roots: &BTreeSet<String>,
    metadata: &BTreeMap<String, RootMetadata>,
    spec13: &BTreeMap<String, String>,
    special_use: &BTreeSet<String>,
) {
    let mut map = phf_codegen::Map::new();
    for root in roots {
        let record = metadata.get(root).expect("root metadata validated");
        let unicode = unicode_display(root);
        let mut designations = Vec::new();
        if spec13.contains_key(root) {
            designations.push("Designation::BrandSpec13");
        }
        if root.starts_with("xn--") {
            designations.push("Designation::IdnTld");
        }
        let operator = format!("iana-manager-{}", slug_id(&record.manager));
        let value = format!(
            "RootTld {{ ascii_label: {root:?}, unicode_label: {}, raw_iana_type: Some({:?}), family: Some({}), state: Claim::verified(RootState::Delegated, &[\"iana_tlds\"]), operator_ids: &[{operator:?}], designations: &[{}] }}",
            option_string(unicode.as_deref()),
            record.raw_type,
            root_family(&record.raw_type),
            designations.join(", ")
        );
        map.entry(root.as_str(), &value);
    }
    let special_roots = special_root_labels(special_use, roots);
    for root in &special_roots {
        let unicode = unicode_display(root);
        let value = format!(
            "RootTld {{ ascii_label: {root:?}, unicode_label: {}, raw_iana_type: None, family: None, state: Claim::verified(RootState::SpecialUse, &[\"iana_special_use\"]), operator_ids: &[], designations: &[] }}",
            option_string(unicode.as_deref())
        );
        map.entry(root.as_str(), &value);
    }
    writeln!(
        out,
        "pub static ROOT_TLDS: phf::Map<&'static str, RootTld> = {};\n",
        map.build()
    )
    .unwrap();
}

fn special_root_labels(special: &BTreeSet<String>, roots: &BTreeSet<String>) -> BTreeSet<String> {
    special
        .iter()
        .filter(|name| !name.contains('.') && !roots.contains(*name))
        .cloned()
        .collect()
}

fn render_suffix_map(out: &mut String, name: &str, rules: &BTreeMap<String, CompiledSuffixRule>) {
    let mut map = phf_codegen::Map::new();
    for (key, rule) in rules {
        let value = format!(
            "SuffixRule {{ labels: {:?}, kind: {}, section: {}, role: {}, evidence: \"psl\" }}",
            rule.labels, rule.kind, rule.section, rule.role
        );
        map.entry(key.as_str(), &value);
    }
    writeln!(
        out,
        "pub static {name}: phf::Map<&'static str, SuffixRule> = {};\n",
        map.build()
    )
    .unwrap();
}

fn render_special_use(out: &mut String, names: &BTreeSet<String>) {
    let mut set = phf_codegen::Set::new();
    for name in names {
        set.entry(name);
    }
    writeln!(
        out,
        "pub static SPECIAL_USE_NAMES: phf::Set<&'static str> = {};\n",
        set.build()
    )
    .unwrap();
}

fn render_profiles(out: &mut String, profiles: &BTreeMap<String, FlatProfile>) {
    for (index, profile) in profiles.values().enumerate() {
        render_profile_support(out, index, profile);
    }
    let spec13_index = profiles.len();
    writeln!(
        out,
        "static PROFILE_{spec13_index}_VALUE: PolicyProfile = PolicyProfile {{ id: \"icann-active-spec13-baseline-v1\", extends: None, offering_state: Claim::unknown(), public_access: Claim::unknown(), application_channel: Claim::unknown(), eligibility: None, label_policy: None }};"
    )
    .unwrap();

    let mut map = phf_codegen::Map::new();
    for (index, profile) in profiles.values().enumerate() {
        map.entry(profile.id.as_str(), &format!("PROFILE_{index}_VALUE"));
    }
    map.entry(
        "icann-active-spec13-baseline-v1",
        &format!("PROFILE_{spec13_index}_VALUE"),
    );
    writeln!(
        out,
        "pub static POLICY_PROFILES: phf::Map<&'static str, PolicyProfile> = {};\n",
        map.build()
    )
    .unwrap();
}

fn render_profile_support(out: &mut String, index: usize, profile: &FlatProfile) {
    let eligibility_ref = if let Some(eligibility) = &profile.eligibility {
        for (requirement_index, requirement) in eligibility.requirements.iter().enumerate() {
            writeln!(
                out,
                "static PROFILE_{index}_REQUIREMENT_{requirement_index}: EligibilityRequirement = EligibilityRequirement {{ id: {:?}, kind: {}, value: {:?}, explanation: {:?}, evidence: {} }};",
                requirement.id,
                eligibility_kind(&requirement.kind),
                requirement.value,
                requirement.explanation,
                string_slice(&requirement.evidence)
            )
            .unwrap();
        }
        let children = eligibility
            .requirements
            .iter()
            .enumerate()
            .map(|(requirement_index, _)| {
                format!("EligibilityExpression::Requirement(&PROFILE_{index}_REQUIREMENT_{requirement_index})")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let mode = if eligibility.mode == "all" {
            "All"
        } else {
            "Any"
        };
        writeln!(out, "static PROFILE_{index}_ELIGIBILITY: EligibilityExpression = EligibilityExpression::{mode}(&[{children}]);").unwrap();
        format!("Some(&PROFILE_{index}_ELIGIBILITY)")
    } else {
        "None".to_string()
    };

    let label_policy_ref = if let Some(policy) = &profile.label_policy {
        if let Some(idn) = &policy.idn_profile {
            writeln!(
                out,
                "static PROFILE_{index}_IDN: IdnProfile = IdnProfile {{ id: {:?}, version: {:?}, evidence: {} }};",
                idn.id,
                idn.version,
                string_slice(&idn.evidence)
            )
            .unwrap();
        }
        for (reserved_index, reserved) in policy.reserved_labels.iter().enumerate() {
            writeln!(
                out,
                "static PROFILE_{index}_RESERVED_{reserved_index}: ReservedLabel = ReservedLabel {{ label: {:?}, disposition: {}, evidence: {} }};",
                canonical_name(&reserved.label, "reserved label"),
                reserved_disposition(&reserved.disposition),
                string_slice(&reserved.evidence)
            )
            .unwrap();
        }
        let reserved = (0..policy.reserved_labels.len())
            .map(|reserved_index| format!("PROFILE_{index}_RESERVED_{reserved_index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let (length, length_evidence) = policy.length.as_ref().map_or_else(
            || ("None".to_string(), "&[]".to_string()),
            |length| {
                (
                    format!(
                        "Some(LengthConstraint {{ minimum: {}, maximum: {}, unit: {} }})",
                        length.minimum,
                        length.maximum,
                        length_unit(&length.unit)
                    ),
                    string_slice(&length.evidence),
                )
            },
        );
        let idn_profile = if policy.idn_profile.is_some() {
            format!("Some(&PROFILE_{index}_IDN)")
        } else {
            "None".to_string()
        };
        writeln!(
            out,
            "static PROFILE_{index}_LABEL_POLICY: LabelPolicy = LabelPolicy {{ id: {:?}, completeness: {}, completeness_evidence: {}, length: {length}, length_evidence: {length_evidence}, idn_support: {}, idn_profile: {idn_profile}, reserved_status: {}, reserved_set_evidence: {}, reserved_labels: &[{reserved}] }};",
            policy.id,
            claim_status(&policy.completeness),
            string_slice(&policy.completeness_evidence),
            render_claim(policy.idn_support.as_ref(), idn_support_variant),
            claim_status(&policy.reserved_status),
            string_slice(&policy.reserved_set_evidence)
        )
        .unwrap();
        format!("Some(&PROFILE_{index}_LABEL_POLICY)")
    } else {
        "None".to_string()
    };

    writeln!(
        out,
        "static PROFILE_{index}_VALUE: PolicyProfile = PolicyProfile {{ id: {:?}, extends: {}, offering_state: {}, public_access: {}, application_channel: {}, eligibility: {eligibility_ref}, label_policy: {label_policy_ref} }};",
        profile.id,
        option_string(profile.extends.as_deref()),
        render_claim(profile.offering_state.as_ref(), offering_variant),
        render_claim(profile.public_access.as_ref(), access_variant),
        render_claim(profile.application_channel.as_ref(), channel_variant)
    )
    .unwrap();
}

fn render_products(
    out: &mut String,
    products: &BTreeMap<String, GeneratedProduct>,
    profiles: &BTreeMap<String, FlatProfile>,
) {
    let profile_indexes = profiles
        .keys()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let spec13_index = profiles.len();
    let mut map = phf_codegen::Map::new();
    for product in products.values() {
        let profile_index = if product.profile_id == "icann-active-spec13-baseline-v1" {
            spec13_index
        } else {
            *profile_indexes
                .get(product.profile_id.as_str())
                .unwrap_or_else(|| panic!("product '{}' has missing compiled profile", product.id))
        };
        let designations = product
            .designations
            .iter()
            .map(|value| designation_variant(value))
            .collect::<Vec<_>>()
            .join(", ");
        let value = format!(
            "RegistrationProduct {{ id: {:?}, operator_id: {:?}, offering_state: PROFILE_{profile_index}_VALUE.offering_state, public_access: PROFILE_{profile_index}_VALUE.public_access, application_channel: PROFILE_{profile_index}_VALUE.application_channel, eligibility: PROFILE_{profile_index}_VALUE.eligibility, label_policy: PROFILE_{profile_index}_VALUE.label_policy, designations: &[{designations}] }}",
            product.id,
            product.operator
        );
        map.entry(product.id.as_str(), &value);
    }
    writeln!(
        out,
        "pub static REGISTRATION_PRODUCTS: phf::Map<&'static str, RegistrationProduct> = {};\n",
        map.build()
    )
    .unwrap();
}

fn render_string_map(out: &mut String, name: &str, values: &BTreeMap<String, String>) {
    let mut map = phf_codegen::Map::new();
    for (key, value) in values {
        map.entry(key.as_str(), &format!("{value:?}"));
    }
    writeln!(
        out,
        "pub static {name}: phf::Map<&'static str, &'static str> = {};\n",
        map.build()
    )
    .unwrap();
}

fn render_claim<T>(claim: Option<&ClaimRecord>, variant: T) -> String
where
    T: Fn(&str) -> &'static str,
{
    let Some(claim) = claim else {
        return "Claim::unknown()".to_string();
    };
    let status = claim.status.as_deref().unwrap_or(if claim.value.is_some() {
        "verified"
    } else {
        "unknown"
    });
    let evidence = string_slice(&claim.evidence);
    match status {
        "verified" => format!(
            "Claim::verified({}, {evidence})",
            variant(claim.value.as_deref().expect("validated claim value"))
        ),
        "stale" => format!(
            "Claim::stale({}, {evidence})",
            variant(claim.value.as_deref().expect("validated claim value"))
        ),
        "conflicting" => format!("Claim::conflicting({evidence})"),
        "unknown" if claim.evidence.is_empty() => "Claim::unknown()".to_string(),
        "unknown" => {
            format!("Claim {{ status: ClaimStatus::Unknown, value: None, evidence: {evidence} }}")
        }
        _ => unreachable!("claim status was validated"),
    }
}

fn canonical_name(value: &str, context: &str) -> String {
    let trimmed = value.trim().trim_matches('.');
    assert!(!trimmed.is_empty(), "{context} is empty");
    let ascii = idna::domain_to_ascii(trimmed)
        .unwrap_or_else(|error| panic!("{context} '{value}' is invalid IDNA: {error:?}"))
        .to_ascii_lowercase();
    assert!(
        !ascii.split('.').any(str::is_empty),
        "{context} '{value}' contains an empty label"
    );
    ascii
}

fn unicode_display(ascii: &str) -> Option<String> {
    let (unicode, result) = idna::domain_to_unicode(ascii);
    if result.is_ok() && unicode != ascii {
        Some(unicode)
    } else {
        None
    }
}

fn slug_id(value: &str) -> String {
    let mut result = String::new();
    let mut separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !result.is_empty() {
                result.push('-');
            }
            result.push(character.to_ascii_lowercase());
            separator = false;
        } else {
            separator = true;
        }
    }
    let trimmed = result.trim_matches('-');
    if trimmed.is_empty() {
        "unknown-operator".to_string()
    } else {
        trimmed.to_string()
    }
}

fn root_family(raw: &str) -> &'static str {
    match raw {
        "country-code" => "RootFamily::CountryCode",
        "generic" | "generic-restricted" | "sponsored" => "RootFamily::Generic",
        "infrastructure" => "RootFamily::Infrastructure",
        "test" => "RootFamily::Test",
        other => panic!("unknown IANA root type '{other}'"),
    }
}

fn offering_variant(value: &str) -> &'static str {
    match value {
        "accepting" => "OfferingState::Accepting",
        "paused" => "OfferingState::Paused",
        "renewal_only" => "OfferingState::RenewalOnly",
        "not_launched" => "OfferingState::NotLaunched",
        "closed" => "OfferingState::Closed",
        _ => panic!("invalid offering state '{value}'"),
    }
}

fn access_variant(value: &str) -> &'static str {
    match value {
        "open" => "PublicAccess::Open",
        "conditional" => "PublicAccess::Conditional",
        "controlled_group" => "PublicAccess::ControlledGroup",
        "unavailable" => "PublicAccess::Unavailable",
        _ => panic!("invalid public access '{value}'"),
    }
}

fn channel_variant(value: &str) -> &'static str {
    match value {
        "registrar" => "ApplicationChannel::Registrar",
        "registry_direct" => "ApplicationChannel::RegistryDirect",
        "approval_workflow" => "ApplicationChannel::ApprovalWorkflow",
        "delegated_authority" => "ApplicationChannel::DelegatedAuthority",
        "internal" => "ApplicationChannel::Internal",
        _ => panic!("invalid application channel '{value}'"),
    }
}

fn idn_support_variant(value: &str) -> &'static str {
    match value {
        "supported" => "IdnSupport::Supported",
        "unsupported" => "IdnSupport::Unsupported",
        _ => panic!("invalid IDN support '{value}'"),
    }
}

fn eligibility_kind(value: &str) -> &'static str {
    match value {
        "residence" => "EligibilityKind::Residence",
        "citizenship" => "EligibilityKind::Citizenship",
        "legal_presence" => "EligibilityKind::LegalPresence",
        "entity_type" => "EligibilityKind::EntityType",
        "regulated_sector_credential" => "EligibilityKind::RegulatedSectorCredential",
        "community_membership" => "EligibilityKind::CommunityMembership",
        "naming_entitlement" => "EligibilityKind::NamingEntitlement",
        "intended_use" => "EligibilityKind::IntendedUse",
        "authority_approval" => "EligibilityKind::AuthorityApproval",
        _ => panic!("invalid eligibility kind '{value}'"),
    }
}

fn claim_status(value: &str) -> &'static str {
    match value {
        "verified" => "ClaimStatus::Verified",
        "unknown" => "ClaimStatus::Unknown",
        "stale" => "ClaimStatus::Stale",
        "conflicting" => "ClaimStatus::Conflicting",
        _ => panic!("invalid claim status '{value}'"),
    }
}

fn length_unit(value: &str) -> &'static str {
    match value {
        "a_label_octets" => "LengthUnit::ALabelOctets",
        "unicode_code_points" => "LengthUnit::UnicodeCodePoints",
        "grapheme_clusters" => "LengthUnit::GraphemeClusters",
        _ => panic!("invalid length unit '{value}'"),
    }
}

fn reserved_disposition(value: &str) -> &'static str {
    match value {
        "prohibited" => "ReservedDisposition::Prohibited",
        "held" => "ReservedDisposition::Held",
        "premium" => "ReservedDisposition::Premium",
        "special_allocation" => "ReservedDisposition::SpecialAllocation",
        _ => panic!("invalid reserved disposition '{value}'"),
    }
}

fn designation_variant(value: &str) -> &'static str {
    match value {
        "brand_spec13" => "Designation::BrandSpec13",
        "community_spec12" => "Designation::CommunitySpec12",
        "geographic" => "Designation::Geographic",
        "sponsored_legacy" => "Designation::SponsoredLegacy",
        "non_sponsored" => "Designation::NonSponsored",
        "exclusive_use" => "Designation::ExclusiveUse",
        "idn_tld" => "Designation::IdnTld",
        _ => panic!("invalid designation '{value}'"),
    }
}

fn source_kind_variant(kind: SourceKindCode) -> &'static str {
    match kind {
        SourceKindCode::IanaCurrentRoot => "SourceKind::IanaCurrentRoot",
        SourceKindCode::IanaRootDatabase => "SourceKind::IanaRootDatabase",
        SourceKindCode::PublicSuffixList => "SourceKind::PublicSuffixList",
        SourceKindCode::RegistryAgreement => "SourceKind::RegistryAgreement",
        SourceKindCode::RegistryPolicy => "SourceKind::RegistryPolicy",
        SourceKindCode::GovernmentPolicy => "SourceKind::GovernmentPolicy",
        SourceKindCode::SpecialUseRegistry => "SourceKind::SpecialUseRegistry",
        SourceKindCode::StandardsDocument => "SourceKind::StandardsDocument",
        SourceKindCode::RegistryIdnTable => "SourceKind::RegistryIdnTable",
        SourceKindCode::IanaIdnTable => "SourceKind::IanaIdnTable",
        SourceKindCode::Secondary => "SourceKind::Secondary",
    }
}

fn option_string(value: Option<&str>) -> String {
    value.map_or_else(|| "None".to_string(), |value| format!("Some({value:?})"))
}

fn string_slice(values: &[String]) -> String {
    format!(
        "&[{}]",
        values
            .iter()
            .map(|value| format!("{value:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn validate_hash(context: &str, value: &str) {
    assert!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{context} is not a lowercase SHA-256 digest"
    );
}

fn validate_id(context: &str, value: &str) {
    assert!(
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            }),
        "{context} id '{value}' must use lowercase ASCII letters, digits, hyphens, and underscores"
    );
}

#[derive(Debug)]
struct ParsedTimestamp {
    whole_seconds: i64,
    fraction: String,
}

impl ParsedTimestamp {
    fn is_after(&self, other: &Self) -> bool {
        if self.whole_seconds != other.whole_seconds {
            return self.whole_seconds > other.whole_seconds;
        }
        let width = self.fraction.len().max(other.fraction.len());
        for index in 0..width {
            let left = self.fraction.as_bytes().get(index).copied().unwrap_or(b'0');
            let right = other
                .fraction
                .as_bytes()
                .get(index)
                .copied()
                .unwrap_or(b'0');
            if left != right {
                return left > right;
            }
        }
        false
    }

    fn utc_day(&self) -> i64 {
        self.whole_seconds.div_euclid(86_400)
    }
}

fn validate_timestamp(context: &str, value: &str) -> ParsedTimestamp {
    let Some((date, time_with_offset)) = value.split_once('T') else {
        panic!("{context} is not an RFC 3339 timestamp: '{value}'");
    };
    let date = parse_date(context, date);

    let (time, offset) = if let Some(time) = time_with_offset.strip_suffix('Z') {
        (time, None)
    } else {
        let offset_index = time_with_offset
            .char_indices()
            .rev()
            .find_map(|(index, character)| matches!(character, '+' | '-').then_some(index))
            .unwrap_or_else(|| panic!("{context} is not an RFC 3339 timestamp: '{value}'"));
        let (time, offset) = time_with_offset.split_at(offset_index);
        (time, Some(offset))
    };

    let mut time_parts = time.split(':');
    let hour = parse_decimal(context, time_parts.next(), value);
    let minute = parse_decimal(context, time_parts.next(), value);
    let second_part = time_parts
        .next()
        .unwrap_or_else(|| panic!("{context} is not an RFC 3339 timestamp: '{value}'"));
    assert!(
        time_parts.next().is_none() && hour <= 23 && minute <= 59,
        "{context} is not an RFC 3339 timestamp: '{value}'"
    );
    let (second, fraction) = second_part
        .split_once('.')
        .map_or((second_part, None), |(whole, fraction)| {
            (whole, Some(fraction))
        });
    let second = parse_decimal(context, Some(second), value);
    assert!(
        (second <= 59 || (second == 60 && minute == 59))
            && fraction.is_none_or(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
            }),
        "{context} is not an RFC 3339 timestamp: '{value}'"
    );

    let offset_seconds = if let Some(offset) = offset {
        let (offset_hour, offset_minute) = match offset.as_bytes() {
            [b'+' | b'-', _, _, b':', _, _] => (&offset[1..3], &offset[4..6]),
            // ICANN's gTLD feed uses the otherwise ISO-8601-compatible +0000 form.
            [b'+' | b'-', _, _, _, _] => (&offset[1..3], &offset[3..5]),
            _ => panic!("{context} is not an RFC 3339 timestamp: '{value}'"),
        };
        let offset_hour = parse_decimal(context, Some(offset_hour), value);
        let offset_minute = parse_decimal(context, Some(offset_minute), value);
        assert!(
            offset_hour <= 23
                && offset_minute <= 59
                && !(offset.starts_with('-') && offset_hour == 0 && offset_minute == 0),
            "{context} is not an RFC 3339 timestamp: '{value}'"
        );
        let seconds = i64::from(offset_hour * 3_600 + offset_minute * 60);
        if offset.starts_with('-') {
            -seconds
        } else {
            seconds
        }
    } else {
        0
    };

    ParsedTimestamp {
        whole_seconds: date * 86_400 + i64::from(hour * 3_600 + minute * 60 + second)
            - offset_seconds,
        fraction: fraction.unwrap_or_default().to_string(),
    }
}

fn validate_date(context: &str, value: &str) -> i64 {
    parse_date(context, value)
}

fn parse_date(context: &str, value: &str) -> i64 {
    assert!(
        value.len() == 10
            && value.as_bytes().get(4) == Some(&b'-')
            && value.as_bytes().get(7) == Some(&b'-')
            && value
                .bytes()
                .enumerate()
                .all(|(index, byte)| { index == 4 || index == 7 || byte.is_ascii_digit() }),
        "{context} is not an ISO date: '{value}'"
    );
    let year = value[..4]
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("{context} is not an ISO date: '{value}'"));
    let month = value[5..7]
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("{context} is not an ISO date: '{value}'"));
    let day = value[8..10]
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("{context} is not an ISO date: '{value}'"));
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    assert!(
        year != 0 && day != 0 && day <= days_in_month,
        "{context} is not an ISO date: '{value}'"
    );
    let preceding_years = i64::from(year - 1);
    let days_before_year =
        365 * preceding_years + preceding_years / 4 - preceding_years / 100 + preceding_years / 400;
    let days_before_month = match month {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => unreachable!("month was validated"),
    } + i64::from(leap_year && month > 2);
    days_before_year + days_before_month + i64::from(day - 1)
}

fn parse_decimal(context: &str, value: Option<&str>, timestamp: &str) -> u32 {
    let value =
        value.unwrap_or_else(|| panic!("{context} is not an RFC 3339 timestamp: '{timestamp}'"));
    assert!(
        value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_digit()),
        "{context} is not an RFC 3339 timestamp: '{timestamp}'"
    );
    value
        .parse()
        .unwrap_or_else(|_| panic!("{context} is not an RFC 3339 timestamp: '{timestamp}'"))
}

fn assert_https(context: &str, value: &str) {
    assert!(
        value.starts_with("https://"),
        "{context} must use HTTPS: '{value}'"
    );
}
