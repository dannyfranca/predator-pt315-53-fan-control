use std::{error::Error, fmt};

use serde::{Deserialize, Deserializer, de};
use sha2::{Digest, Sha256};

use crate::{
    AcerHwmonDevice, BoundedFileAccess, Clock, CompatibilityAdmissionError,
    CompatibilityDeclarationV1, CompatibilityObservation, ConfigV1, ConfigValidationError,
    ControllerOwnership, EnvelopeValidationError, FirmwareAutoRestorationError,
    QualificationEnvelopeIdentityV1, RuntimeLockAccess, TachometerCalibrationError,
    ValidatedConfig, admit_compatibility,
    compatibility::validate_declaration,
    tachometer::{QualifiedTachometerCalibrations, TachometerCalibrationConfig},
    validate_against_protected_envelope, validate_config_v1,
};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedPolicyManifestV2 {
    #[serde(deserialize_with = "deserialize_policy_schema_version")]
    schema_version: u32,
    qualification_id: String,
    policy_version: String,
    compatibility: CompatibilityDeclarationV1,
    calibration: TachometerCalibrationConfig,
    protected: ConfigV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationRecordV1 {
    #[serde(deserialize_with = "deserialize_schema_version")]
    schema_version: u32,
    qualification_id: String,
    policy_version: String,
    protected_policy_sha256: String,
    compatibility: CompatibilityDeclarationV1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedPolicyAuthority {
    ownership_id: u64,
    qualification_id: String,
    policy_version: String,
    protected_policy_sha256: String,
    compatibility: CompatibilityDeclarationV1,
    calibration: QualifiedTachometerCalibrations,
    protected: ValidatedConfig,
}

#[derive(Debug, Clone, PartialEq)]
struct ValidatedPolicyAuthority {
    qualification_id: String,
    policy_version: String,
    protected_policy_sha256: String,
    compatibility: CompatibilityDeclarationV1,
    calibration: QualifiedTachometerCalibrations,
    protected: ValidatedConfig,
}

impl ValidatedPolicyAuthority {
    fn bind_to_ownership(self, ownership_id: u64) -> AdmittedPolicyAuthority {
        AdmittedPolicyAuthority {
            ownership_id,
            qualification_id: self.qualification_id,
            policy_version: self.policy_version,
            protected_policy_sha256: self.protected_policy_sha256,
            compatibility: self.compatibility,
            calibration: self.calibration,
            protected: self.protected,
        }
    }
}

impl AdmittedPolicyAuthority {
    pub(crate) const fn belongs_to_ownership(&self, ownership_id: u64) -> bool {
        self.ownership_id == ownership_id
    }

    pub fn qualification_id(&self) -> &str {
        &self.qualification_id
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    pub fn protected_policy_sha256(&self) -> &str {
        &self.protected_policy_sha256
    }

    /// Returns the exact envelope identity retained from this admitted authority.
    pub fn evidence_identity(&self) -> QualificationEnvelopeIdentityV1 {
        QualificationEnvelopeIdentityV1 {
            qualification_record_schema_version: 1,
            qualification_id: self.qualification_id.clone(),
            policy_version: self.policy_version.clone(),
            protected_policy_sha256: self.protected_policy_sha256.clone(),
            compatibility: self.compatibility.clone(),
        }
    }

    pub fn validate_candidate(
        &self,
        candidate: &ValidatedConfig,
    ) -> Result<(), EnvelopeValidationError> {
        validate_against_protected_envelope(candidate, &self.protected)
    }

    pub(crate) fn tachometer_calibrations(&self) -> QualifiedTachometerCalibrations {
        self.calibration.clone()
    }
}

#[derive(Debug)]
pub enum PolicyAuthorityAdmissionError {
    Rejected(PolicyAuthorityError),
    RestorationFailed {
        reason: PolicyAuthorityError,
        restoration: FirmwareAutoRestorationError,
    },
}

impl PolicyAuthorityAdmissionError {
    pub const fn reason(&self) -> &PolicyAuthorityError {
        match self {
            Self::Rejected(reason) | Self::RestorationFailed { reason, .. } => reason,
        }
    }
}

impl fmt::Display for PolicyAuthorityAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(reason) => write!(formatter, "authority rejected: {reason}"),
            Self::RestorationFailed {
                reason,
                restoration,
            } => write!(
                formatter,
                "authority rejected ({reason}); Firmware Auto restoration failed: {restoration}"
            ),
        }
    }
}

impl Error for PolicyAuthorityAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rejected(reason) | Self::RestorationFailed { reason, .. } => Some(reason),
        }
    }
}

#[derive(Debug)]
pub enum PolicyAuthorityError {
    FirmwareAutoUnconfirmed,
    ProtectedPolicyParse(toml::de::Error),
    QualificationRecordParse(serde_json::Error),
    InvalidIdentity {
        artifact: &'static str,
        field: &'static str,
    },
    InvalidCompatibility {
        artifact: &'static str,
        field: &'static str,
    },
    InvalidProtectedPolicy(ConfigValidationError),
    InvalidTachometerCalibration(TachometerCalibrationError),
    CompatibilityAdmission(CompatibilityAdmissionError),
    Mismatch {
        field: &'static str,
    },
}

impl fmt::Display for PolicyAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirmwareAutoUnconfirmed => {
                formatter.write_str("Firmware Auto was not confirmed before policy admission")
            }
            Self::ProtectedPolicyParse(error) => write!(formatter, "protected policy: {error}"),
            Self::QualificationRecordParse(error) => {
                write!(formatter, "qualification record: {error}")
            }
            Self::InvalidIdentity { artifact, field } => {
                write!(formatter, "invalid {artifact} identity at {field}")
            }
            Self::InvalidCompatibility { artifact, field } => {
                write!(formatter, "invalid {artifact} compatibility at {field}")
            }
            Self::InvalidProtectedPolicy(error) => {
                write!(formatter, "invalid protected policy: {error}")
            }
            Self::InvalidTachometerCalibration(error) => {
                write!(formatter, "invalid tachometer calibration: {error}")
            }
            Self::CompatibilityAdmission(error) => {
                write!(formatter, "current compatibility: {error}")
            }
            Self::Mismatch { field } => write!(formatter, "authority mismatch at {field}"),
        }
    }
}

impl Error for PolicyAuthorityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProtectedPolicyParse(error) => Some(error),
            Self::QualificationRecordParse(error) => Some(error),
            Self::InvalidProtectedPolicy(error) => Some(error),
            Self::InvalidTachometerCalibration(error) => Some(error),
            Self::CompatibilityAdmission(error) => Some(error),
            Self::FirmwareAutoUnconfirmed
            | Self::InvalidIdentity { .. }
            | Self::InvalidCompatibility { .. }
            | Self::Mismatch { .. } => None,
        }
    }
}

fn parse_protected_policy_v2(
    source: &str,
) -> Result<ProtectedPolicyManifestV2, PolicyAuthorityError> {
    let manifest = toml::from_str(source).map_err(PolicyAuthorityError::ProtectedPolicyParse)?;
    validate_manifest_identity(&manifest)?;
    Ok(manifest)
}

fn parse_qualification_record_v1(
    source: &str,
) -> Result<QualificationRecordV1, PolicyAuthorityError> {
    let record =
        serde_json::from_str(source).map_err(PolicyAuthorityError::QualificationRecordParse)?;
    validate_record_identity(&record)?;
    Ok(record)
}

pub fn admit_policy_authority<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    protected_policy_source: &str,
    qualification_record_source: &str,
    compatibility_observations: &[CompatibilityObservation],
) -> Result<AdmittedPolicyAuthority, PolicyAuthorityAdmissionError>
where
    P: BoundedFileAccess + Clock + RuntimeLockAccess + ?Sized,
{
    let result = if ownership.refresh_firmware_auto_confirmation(device) {
        validate_policy_authority(
            protected_policy_source,
            qualification_record_source,
            compatibility_observations,
        )
        .map(|authority| authority.bind_to_ownership(ownership.ownership_id()))
    } else {
        Err(PolicyAuthorityError::FirmwareAutoUnconfirmed)
    };
    match result {
        Ok(authority) => Ok(authority),
        Err(reason) => match ownership.restore_firmware_auto(device) {
            Ok(()) => Err(PolicyAuthorityAdmissionError::Rejected(reason)),
            Err(restoration) => Err(PolicyAuthorityAdmissionError::RestorationFailed {
                reason,
                restoration,
            }),
        },
    }
}

/// Validates the protected policy and qualification record without acquiring ownership or
/// changing fan state.
pub(crate) fn validate_policy_authority_sources(
    protected_policy_source: &str,
    qualification_record_source: &str,
    compatibility_observations: &[CompatibilityObservation],
) -> Result<(), PolicyAuthorityError> {
    validate_policy_authority(
        protected_policy_source,
        qualification_record_source,
        compatibility_observations,
    )
    .map(|_| ())
}

fn validate_policy_authority(
    protected_policy_source: &str,
    qualification_record_source: &str,
    compatibility_observations: &[CompatibilityObservation],
) -> Result<ValidatedPolicyAuthority, PolicyAuthorityError> {
    let manifest = parse_protected_policy_v2(protected_policy_source)?;
    let record = parse_qualification_record_v1(qualification_record_source)?;

    require_equal(
        "qualification_id",
        &manifest.qualification_id,
        &record.qualification_id,
    )?;
    require_equal(
        "policy_version",
        &manifest.policy_version,
        &record.policy_version,
    )?;
    require_equal(
        "compatibility",
        &manifest.compatibility,
        &record.compatibility,
    )?;
    admit_compatibility(&manifest.compatibility, compatibility_observations)
        .map_err(PolicyAuthorityError::CompatibilityAdmission)?;

    let protected_policy_sha256 = sha256_hex(protected_policy_source.as_bytes());
    require_equal(
        "protected_policy_sha256",
        &protected_policy_sha256,
        &record.protected_policy_sha256,
    )?;

    let protected = validate_config_v1(manifest.protected)
        .map_err(PolicyAuthorityError::InvalidProtectedPolicy)?;
    let calibration = manifest
        .calibration
        .qualify(&protected)
        .map_err(PolicyAuthorityError::InvalidTachometerCalibration)?;

    Ok(ValidatedPolicyAuthority {
        qualification_id: manifest.qualification_id,
        policy_version: manifest.policy_version,
        protected_policy_sha256,
        compatibility: manifest.compatibility,
        calibration,
        protected,
    })
}

fn validate_manifest_identity(
    manifest: &ProtectedPolicyManifestV2,
) -> Result<(), PolicyAuthorityError> {
    if manifest.schema_version != 2 {
        return Err(PolicyAuthorityError::InvalidIdentity {
            artifact: "protected policy",
            field: "schema_version",
        });
    }
    validate_identifier(
        "protected policy",
        "qualification_id",
        &manifest.qualification_id,
    )?;
    validate_identifier(
        "protected policy",
        "policy_version",
        &manifest.policy_version,
    )?;
    validate_compatibility("protected policy", &manifest.compatibility)
}

fn validate_record_identity(record: &QualificationRecordV1) -> Result<(), PolicyAuthorityError> {
    if record.schema_version != 1 {
        return Err(PolicyAuthorityError::InvalidIdentity {
            artifact: "qualification record",
            field: "schema_version",
        });
    }
    validate_identifier(
        "qualification record",
        "qualification_id",
        &record.qualification_id,
    )?;
    validate_identifier(
        "qualification record",
        "policy_version",
        &record.policy_version,
    )?;
    if !is_lower_hex(&record.protected_policy_sha256, 64) {
        return Err(PolicyAuthorityError::InvalidIdentity {
            artifact: "qualification record",
            field: "protected_policy_sha256",
        });
    }
    validate_compatibility("qualification record", &record.compatibility)
}

fn validate_compatibility(
    artifact: &'static str,
    compatibility: &CompatibilityDeclarationV1,
) -> Result<(), PolicyAuthorityError> {
    validate_declaration(compatibility).map_err(|error| match error {
        crate::CompatibilityDeclarationError::Unsafe { field, .. } => {
            PolicyAuthorityError::InvalidCompatibility { artifact, field }
        }
        crate::CompatibilityDeclarationError::Parse(_) => {
            unreachable!("validating a parsed compatibility declaration cannot parse")
        }
    })
}

fn validate_identifier(
    artifact: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), PolicyAuthorityError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PolicyAuthorityError::InvalidIdentity { artifact, field });
    }
    Ok(())
}

fn require_equal<T: PartialEq>(
    field: &'static str,
    expected: &T,
    actual: &T,
) -> Result<(), PolicyAuthorityError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PolicyAuthorityError::Mismatch { field })
    }
}

fn sha256_hex(source: &[u8]) -> String {
    format!("{:x}", Sha256::digest(source))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = i64::deserialize(deserializer)?;
    if version == 1 {
        Ok(1)
    } else {
        Err(de::Error::custom("schema_version must be 1"))
    }
}

fn deserialize_policy_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = i64::deserialize(deserializer)?;
    if version == 2 {
        Ok(2)
    } else {
        Err(de::Error::custom(
            "schema_version must be 2; V1 manifests require requalification with tachometer calibration",
        ))
    }
}
