use std::{error::Error, fmt, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    QualificationRecordV2,
    authority::{parse_qualification_record_v2, sha256_hex},
    validate_qualification_evidence_v2,
};

const PACKAGE_PROVENANCE_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/package-provenance-v1.json"
));
const PROMOTION_MANIFEST_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/promotion-manifest.json"
));

#[derive(Debug)]
pub enum PromotionValidationError {
    Qualification(crate::PolicyAuthorityError),
    EvidenceParse(crate::EvidenceParseError),
    Json {
        artifact: &'static str,
        source: serde_json::Error,
    },
    Invalid {
        artifact: &'static str,
        field: &'static str,
    },
    Mismatch(&'static str),
}

impl fmt::Display for PromotionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Qualification(error) => write!(formatter, "qualification rejected: {error}"),
            Self::EvidenceParse(error) => write!(formatter, "evidence rejected: {error}"),
            Self::Json { artifact, source } => write!(formatter, "invalid {artifact}: {source}"),
            Self::Invalid { artifact, field } => {
                write!(formatter, "invalid {artifact} field: {field}")
            }
            Self::Mismatch(field) => write!(formatter, "promotion identity mismatch: {field}"),
        }
    }
}

impl Error for PromotionValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Qualification(error) => Some(error),
            Self::EvidenceParse(error) => Some(error),
            Self::Json { source, .. } => Some(source),
            Self::Invalid { .. } | Self::Mismatch(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizedQualificationEvidenceV1 {
    schema_version: u32,
    qualification_record_sha256: String,
    record_status: String,
    stage: String,
    outcome: String,
    final_firmware_auto_confirmed: bool,
    workload_stopped: bool,
    service_stopped: bool,
    compatibility: SanitizedCompatibilityV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizedCompatibilityV1 {
    hardware: SanitizedHardwareV1,
    kernel: SanitizedKernelV1,
    module: SanitizedModuleV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizedHardwareV1 {
    product_name: String,
    board_name: String,
    bios_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizedKernelV1 {
    release: String,
    package: String,
    source_commit: String,
    image_sha256: String,
    image_signer_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizedModuleV1 {
    name: String,
    sha256: String,
    signer_fingerprint: String,
    provenance: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionManifestV1 {
    schema_version: u32,
    qualification_record_sha256: String,
    controller: ControllerPromotionV1,
    policy: PolicyPromotionV1,
    kernel: KernelPromotionV1,
    packages: PackagePromotionV1,
    sanitized_evidence_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerPromotionV1 {
    package_sha256: String,
    signature_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPromotionV1 {
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelPromotionV1 {
    release: String,
    image_sha256: String,
    image_signer_fingerprint: String,
    module_sha256: String,
    module_signer_fingerprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackagePromotionV1 {
    provenance_sha256: String,
    manifest_signature_sha256: String,
    manifest_signer_fingerprint: String,
    artifacts: Vec<PackageArtifactV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageArtifactV1 {
    name: String,
    version: String,
    architecture: String,
    sha256: String,
}

pub fn sanitize_qualification_evidence_v1(
    qualification_record_source: &str,
    evidence_source: &str,
    authorized_evidence_path: &Path,
) -> Result<String, PromotionValidationError> {
    validate_qualification_evidence_v2(
        qualification_record_source,
        evidence_source,
        authorized_evidence_path,
    )
    .map_err(PromotionValidationError::Qualification)?;
    let record = parse_qualification_record_v2(qualification_record_source)
        .map_err(PromotionValidationError::Qualification)?;
    let evidence = crate::parse_evidence_v2(evidence_source)
        .map_err(PromotionValidationError::EvidenceParse)?;
    let summary = sanitized_summary(qualification_record_source.as_bytes(), &record, &evidence);
    let mut rendered = serde_json::to_string_pretty(&summary).map_err(|source| {
        PromotionValidationError::Json {
            artifact: "sanitized evidence",
            source,
        }
    })?;
    rendered.push('\n');
    Ok(rendered)
}

pub struct PromotionInputs<'a> {
    pub manifest_source: &'a str,
    pub qualification_record_source: &'a str,
    pub evidence_source: &'a str,
    pub authorized_evidence_path: &'a Path,
    pub sanitized_evidence_source: &'a str,
    pub protected_policy: &'a [u8],
    pub package_provenance_source: &'a [u8],
    pub controller_package: &'a [u8],
    pub controller_signature: &'a [u8],
    pub package_manifest_signature: &'a [u8],
}

pub fn validate_promotion_manifest_v1(
    inputs: PromotionInputs<'_>,
) -> Result<(), PromotionValidationError> {
    let PromotionInputs {
        manifest_source,
        qualification_record_source,
        evidence_source,
        authorized_evidence_path,
        sanitized_evidence_source,
        protected_policy,
        package_provenance_source,
        controller_package,
        controller_signature,
        package_manifest_signature,
    } = inputs;
    validate_qualification_evidence_v2(
        qualification_record_source,
        evidence_source,
        authorized_evidence_path,
    )
    .map_err(PromotionValidationError::Qualification)?;
    let record = parse_qualification_record_v2(qualification_record_source)
        .map_err(PromotionValidationError::Qualification)?;
    let evidence = crate::parse_evidence_v2(evidence_source)
        .map_err(PromotionValidationError::EvidenceParse)?;
    let expected_summary =
        sanitized_summary(qualification_record_source.as_bytes(), &record, &evidence);
    let actual_summary: SanitizedQualificationEvidenceV1 =
        serde_json::from_str(sanitized_evidence_source).map_err(|source| {
            PromotionValidationError::Json {
                artifact: "sanitized evidence",
                source,
            }
        })?;
    require_equal("sanitized evidence", &expected_summary, &actual_summary)?;

    let manifest_value: Value =
        serde_json::from_str(manifest_source).map_err(|source| PromotionValidationError::Json {
            artifact: "promotion manifest",
            source,
        })?;
    validate_schema(
        "promotion manifest",
        PROMOTION_MANIFEST_SCHEMA,
        &manifest_value,
    )?;
    let manifest: PromotionManifestV1 =
        serde_json::from_value(manifest_value).map_err(|source| {
            PromotionValidationError::Json {
                artifact: "promotion manifest",
                source,
            }
        })?;
    if manifest.schema_version != 1 {
        return Err(PromotionValidationError::Invalid {
            artifact: "promotion manifest",
            field: "schema_version",
        });
    }
    require_hash(
        "qualification_record_sha256",
        &manifest.qualification_record_sha256,
        qualification_record_source.as_bytes(),
    )?;
    require_hash(
        "controller.package_sha256",
        &manifest.controller.package_sha256,
        controller_package,
    )?;
    require_hash(
        "controller.signature_sha256",
        &manifest.controller.signature_sha256,
        controller_signature,
    )?;
    require_hash("policy.sha256", &manifest.policy.sha256, protected_policy)?;
    require_equal(
        "policy.qualification_record",
        &record.protected_policy_sha256(),
        &manifest.policy.sha256.as_str(),
    )?;
    require_hash(
        "packages.provenance_sha256",
        &manifest.packages.provenance_sha256,
        package_provenance_source,
    )?;
    require_hash(
        "packages.manifest_signature_sha256",
        &manifest.packages.manifest_signature_sha256,
        package_manifest_signature,
    )?;
    require_hash(
        "sanitized_evidence_sha256",
        &manifest.sanitized_evidence_sha256,
        sanitized_evidence_source.as_bytes(),
    )?;

    let provenance: Value =
        serde_json::from_slice(package_provenance_source).map_err(|source| {
            PromotionValidationError::Json {
                artifact: "package provenance",
                source,
            }
        })?;
    validate_schema("package provenance", PACKAGE_PROVENANCE_SCHEMA, &provenance)?;
    validate_provenance_identity(&provenance)?;
    let compatibility = record.compatibility();
    require_json_string(
        "package provenance kernel.release",
        &provenance["kernel"]["release"],
        &compatibility.kernel.release,
    )?;
    require_json_string(
        "package provenance build.source_commit",
        &provenance["build"]["source_commit"],
        &compatibility.kernel.source_commit,
    )?;
    if !is_sha256(&manifest.packages.manifest_signer_fingerprint) {
        return Err(PromotionValidationError::Invalid {
            artifact: "promotion manifest",
            field: "packages.manifest_signer_fingerprint",
        });
    }
    require_json_string(
        "package provenance kernel.package",
        &provenance["kernel"]["package"],
        &compatibility.kernel.package,
    )?;
    require_json_string(
        "package provenance kernel.image_sha256",
        &provenance["kernel"]["image_sha256"],
        &compatibility.kernel.image_sha256,
    )?;
    require_json_string(
        "package provenance kernel.image_signer_fingerprint",
        &provenance["kernel"]["image_signer_fingerprint"],
        &compatibility.kernel.image_signer_fingerprint,
    )?;
    let acer_module = provenance["modules"]
        .as_array()
        .and_then(|modules| modules.iter().find(|module| module["name"] == "acer_wmi"))
        .ok_or(PromotionValidationError::Invalid {
            artifact: "package provenance",
            field: "modules.acer_wmi",
        })?;
    for (field, expected) in [
        ("sha256", compatibility.module.sha256.as_str()),
        (
            "signer_fingerprint",
            compatibility.module.signer_fingerprint.as_str(),
        ),
        ("vermagic", compatibility.module.vermagic.as_str()),
    ] {
        require_json_string("package provenance acer_wmi", &acer_module[field], expected)?;
    }

    for (field, expected, actual) in [
        (
            "kernel.release",
            compatibility.kernel.release.as_str(),
            manifest.kernel.release.as_str(),
        ),
        (
            "kernel.image_sha256",
            compatibility.kernel.image_sha256.as_str(),
            manifest.kernel.image_sha256.as_str(),
        ),
        (
            "kernel.image_signer_fingerprint",
            compatibility.kernel.image_signer_fingerprint.as_str(),
            manifest.kernel.image_signer_fingerprint.as_str(),
        ),
        (
            "kernel.module_sha256",
            compatibility.module.sha256.as_str(),
            manifest.kernel.module_sha256.as_str(),
        ),
        (
            "kernel.module_signer_fingerprint",
            compatibility.module.signer_fingerprint.as_str(),
            manifest.kernel.module_signer_fingerprint.as_str(),
        ),
    ] {
        require_equal(field, &expected, &actual)?;
    }
    require_json_string(
        "packages.manifest_signer_fingerprint",
        &provenance["build"]["package_manifest_signer_fingerprint"],
        &manifest.packages.manifest_signer_fingerprint,
    )?;
    let provenance_packages: Vec<PackageArtifactV1> =
        serde_json::from_value(provenance["packages"].clone()).map_err(|source| {
            PromotionValidationError::Json {
                artifact: "package provenance packages",
                source,
            }
        })?;
    validate_package_artifacts(&provenance_packages)?;
    validate_package_artifacts(&manifest.packages.artifacts)?;
    require_equal(
        "packages.artifacts",
        &provenance_packages,
        &manifest.packages.artifacts,
    )?;
    Ok(())
}

fn validate_schema(
    artifact: &'static str,
    schema_source: &str,
    instance: &Value,
) -> Result<(), PromotionValidationError> {
    let schema: Value =
        serde_json::from_str(schema_source).expect("embedded repository schema must be valid JSON");
    let validator = jsonschema::validator_for(&schema)
        .expect("embedded repository schema must compile successfully");
    if validator.is_valid(instance) {
        Ok(())
    } else {
        Err(PromotionValidationError::Invalid {
            artifact,
            field: "schema",
        })
    }
}

fn validate_package_artifacts(
    packages: &[PackageArtifactV1],
) -> Result<(), PromotionValidationError> {
    if packages.is_empty() {
        return Err(PromotionValidationError::Invalid {
            artifact: "package artifacts",
            field: "empty",
        });
    }
    let mut names = std::collections::BTreeSet::new();
    for package in packages {
        if package.name.is_empty()
            || package.version.is_empty()
            || package.architecture.is_empty()
            || !is_sha256(&package.sha256)
        {
            return Err(PromotionValidationError::Invalid {
                artifact: "package artifacts",
                field: "identity",
            });
        }
        if !names.insert(&package.name) {
            return Err(PromotionValidationError::Invalid {
                artifact: "package artifacts",
                field: "duplicate name",
            });
        }
    }
    Ok(())
}

fn sanitized_summary(
    qualification_record: &[u8],
    record: &QualificationRecordV2,
    evidence: &crate::EvidenceRecord,
) -> SanitizedQualificationEvidenceV1 {
    let compatibility = record.compatibility();
    SanitizedQualificationEvidenceV1 {
        schema_version: 1,
        qualification_record_sha256: sha256_hex(qualification_record),
        record_status: "complete".into(),
        stage: evidence.stage.clone(),
        outcome: "passed".into(),
        final_firmware_auto_confirmed: evidence.outcome.final_firmware_auto_confirmed,
        workload_stopped: true,
        service_stopped: true,
        compatibility: SanitizedCompatibilityV1 {
            hardware: SanitizedHardwareV1 {
                product_name: compatibility.hardware.dmi_product_name.clone(),
                board_name: compatibility.hardware.dmi_board_name.clone(),
                bios_version: compatibility.hardware.bios_version.clone(),
            },
            kernel: SanitizedKernelV1 {
                release: compatibility.kernel.release.clone(),
                package: compatibility.kernel.package.clone(),
                source_commit: compatibility.kernel.source_commit.clone(),
                image_sha256: compatibility.kernel.image_sha256.clone(),
                image_signer_fingerprint: compatibility.kernel.image_signer_fingerprint.clone(),
            },
            module: SanitizedModuleV1 {
                name: compatibility.module.name.clone(),
                sha256: compatibility.module.sha256.clone(),
                signer_fingerprint: compatibility.module.signer_fingerprint.clone(),
                provenance: match compatibility.module.provenance {
                    crate::ModuleProvenance::InTree => "in-tree".into(),
                    crate::ModuleProvenance::External => "external".into(),
                },
            },
        },
    }
}

fn validate_provenance_identity(provenance: &Value) -> Result<(), PromotionValidationError> {
    let object = provenance
        .as_object()
        .ok_or(PromotionValidationError::Invalid {
            artifact: "package provenance",
            field: "root",
        })?;
    for required in [
        "schema_version",
        "candidate",
        "build",
        "kernel",
        "modules",
        "packages",
    ] {
        if !object.contains_key(required) {
            return Err(PromotionValidationError::Invalid {
                artifact: "package provenance",
                field: required,
            });
        }
    }
    if provenance["schema_version"] != 1
        || !provenance["candidate"].is_string()
        || !provenance["build"].is_object()
        || !provenance["kernel"].is_object()
        || !provenance["modules"].is_array()
        || !provenance["packages"].is_array()
        || provenance["packages"].as_array().is_some_and(Vec::is_empty)
    {
        return Err(PromotionValidationError::Invalid {
            artifact: "package provenance",
            field: "shape",
        });
    }
    Ok(())
}

fn require_json_string(
    field: &'static str,
    value: &Value,
    expected: &str,
) -> Result<(), PromotionValidationError> {
    match value.as_str() {
        Some(actual) => require_equal(field, &expected, &actual),
        None => Err(PromotionValidationError::Invalid {
            artifact: "package provenance",
            field,
        }),
    }
}

fn require_hash(
    field: &'static str,
    expected: &str,
    content: &[u8],
) -> Result<(), PromotionValidationError> {
    if !is_sha256(expected) {
        return Err(PromotionValidationError::Invalid {
            artifact: "promotion manifest",
            field,
        });
    }
    require_equal(field, &expected, &sha256_hex(content).as_str())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_equal<T: PartialEq>(
    field: &'static str,
    expected: &T,
    actual: &T,
) -> Result<(), PromotionValidationError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PromotionValidationError::Mismatch(field))
    }
}
