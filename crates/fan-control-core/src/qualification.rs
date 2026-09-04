use std::{error::Error, fmt, fs, path::Path};

use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};

use crate::{
    CompatibilityDeclarationV1, EVIDENCE_SCHEMA_VERSION_V2, EvidenceRecordStatus,
    EvidenceTimestamp, EvidenceWriteError, RunOutcomeStatus, StoppedProcess,
    SupervisedEndurancePlan, SupervisedEndurancePlanError, SupervisedEnduranceReport,
    endurance::{
        endurance_thermal_envelope, supervised_endurance_is_complete,
        validate_endurance_thermal_limits_against_baselines, validate_qualification_plan,
    },
    evidence::{
        validate_root_owned_output_destination, write_root_owned_evidence_atomically,
        write_root_owned_json_atomically,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRecordV2 {
    #[serde(deserialize_with = "deserialize_qualification_schema_version")]
    pub(crate) schema_version: u32,
    pub(crate) qualification_id: String,
    pub(crate) policy_version: String,
    pub(crate) protected_policy_sha256: String,
    pub(crate) compatibility: CompatibilityDeclarationV1,
    pub(crate) supervised_endurance: SupervisedEnduranceAuthorizationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisedEnduranceAuthorizationV1 {
    #[serde(deserialize_with = "deserialize_endurance_authorization_schema_version")]
    pub(crate) schema_version: u32,
    pub(crate) evidence_sha256: String,
    pub(crate) evidence_path: String,
    pub(crate) evidence_schema_version: u32,
    pub(crate) stage: String,
    pub(crate) record_status: EvidenceRecordStatus,
    pub(crate) outcome: RunOutcomeStatus,
    pub(crate) final_firmware_auto_confirmed: bool,
    pub(crate) workload_stopped: bool,
    pub(crate) service_stopped: bool,
    pub(crate) completed_at: EvidenceTimestamp,
}

impl QualificationRecordV2 {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
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

    pub fn compatibility(&self) -> &CompatibilityDeclarationV1 {
        &self.compatibility
    }

    pub fn supervised_endurance(&self) -> &SupervisedEnduranceAuthorizationV1 {
        &self.supervised_endurance
    }
}

impl SupervisedEnduranceAuthorizationV1 {
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }
}

#[derive(Debug)]
pub enum QualificationAuthorizationError {
    InvalidPlan(SupervisedEndurancePlanError),
    EnduranceNotAccepted,
    PublicationCancelled,
    Write(EvidenceWriteError),
}

impl fmt::Display for QualificationAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(error) => {
                write!(formatter, "qualification envelope rejected: {error}")
            }
            Self::EnduranceNotAccepted => {
                formatter.write_str("supervised endurance evidence is not complete and passing")
            }
            Self::PublicationCancelled => {
                formatter.write_str("authorization publication was cancelled before commit")
            }
            Self::Write(error) => write!(
                formatter,
                "cannot publish root-owned qualification record: {error}"
            ),
        }
    }
}

impl Error for QualificationAuthorizationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPlan(error) => Some(error),
            Self::Write(error) => Some(error),
            Self::EnduranceNotAccepted | Self::PublicationCancelled => None,
        }
    }
}

pub fn write_qualification_record_after_endurance(
    destination: &Path,
    evidence_path: &Path,
    plan: &SupervisedEndurancePlan<'_>,
    report: &SupervisedEnduranceReport,
) -> Result<QualificationRecordV2, QualificationAuthorizationError> {
    write_qualification_record_after_endurance_with_guard(
        destination,
        evidence_path,
        plan,
        report,
        || true,
    )
}

pub fn write_qualification_record_after_endurance_with_guard(
    destination: &Path,
    evidence_path: &Path,
    plan: &SupervisedEndurancePlan<'_>,
    report: &SupervisedEnduranceReport,
    commit: impl FnOnce() -> bool,
) -> Result<QualificationRecordV2, QualificationAuthorizationError> {
    let envelope =
        validate_qualification_plan(plan).map_err(QualificationAuthorizationError::InvalidPlan)?;
    report.record().validate().map_err(|error| {
        QualificationAuthorizationError::InvalidPlan(
            SupervisedEndurancePlanError::InvalidGeneratedEvidence(error),
        )
    })?;
    if !report.accepted()
        || report.record().qualification_envelope != envelope
        || report.record().prerequisite_binding_sha256.as_deref()
            != Some(plan.prerequisite_binding_sha256.as_str())
        || !supervised_endurance_is_complete(report.record())
    {
        return Err(QualificationAuthorizationError::EnduranceNotAccepted);
    }
    if report.record().endurance_thermal_envelope.as_ref()
        != Some(
            &endurance_thermal_envelope(plan.baselines)
                .map_err(QualificationAuthorizationError::InvalidPlan)?,
        )
    {
        return Err(QualificationAuthorizationError::EnduranceNotAccepted);
    }
    validate_endurance_thermal_limits_against_baselines(
        report
            .record()
            .thermal_summary
            .as_ref()
            .expect("complete endurance has a summary"),
        &report.record().samples,
        plan.baselines,
    )
    .map_err(QualificationAuthorizationError::InvalidPlan)?;

    if !evidence_path.is_absolute() {
        return Err(QualificationAuthorizationError::EnduranceNotAccepted);
    }
    validate_root_owned_output_destination(evidence_path)
        .map_err(QualificationAuthorizationError::Write)?;
    validate_root_owned_output_destination(destination)
        .map_err(QualificationAuthorizationError::Write)?;
    let mut evidence_payload = serde_json::to_vec_pretty(report.record())
        .expect("validated endurance evidence serializes");
    evidence_payload.push(b'\n');
    let evidence_sha256 = format!("{:x}", Sha256::digest(&evidence_payload));
    let qualification = QualificationRecordV2 {
        schema_version: 2,
        qualification_id: envelope.qualification_id,
        policy_version: envelope.policy_version,
        protected_policy_sha256: envelope.protected_policy_sha256,
        compatibility: envelope.compatibility,
        supervised_endurance: SupervisedEnduranceAuthorizationV1 {
            schema_version: 1,
            evidence_sha256,
            evidence_path: evidence_path.to_string_lossy().into_owned(),
            evidence_schema_version: EVIDENCE_SCHEMA_VERSION_V2,
            stage: "supervised-endurance".into(),
            record_status: report.record().record_status,
            outcome: report.record().outcome.status,
            final_firmware_auto_confirmed: report.record().outcome.final_firmware_auto_confirmed,
            workload_stopped: matches!(
                report.record().process_stops.first(),
                Some(stop) if stop.process == StoppedProcess::Workload && !stop.running
            ),
            service_stopped: matches!(
                report.record().process_stops.get(1),
                Some(stop) if stop.process == StoppedProcess::Service && !stop.running
            ),
            completed_at: report.record().completed_at,
        },
    };
    write_root_owned_evidence_atomically(evidence_path, report.record())
        .map_err(QualificationAuthorizationError::Write)?;
    if !commit() {
        fs::remove_file(evidence_path).map_err(|source| {
            QualificationAuthorizationError::Write(EvidenceWriteError::Published {
                operation: "remove cancelled endurance evidence",
                source,
            })
        })?;
        fs::File::open(
            evidence_path
                .parent()
                .ok_or(QualificationAuthorizationError::EnduranceNotAccepted)?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(|source| {
            QualificationAuthorizationError::Write(EvidenceWriteError::Published {
                operation: "sync cancelled endurance evidence directory",
                source,
            })
        })?;
        return Err(QualificationAuthorizationError::PublicationCancelled);
    }
    write_root_owned_json_atomically(destination, &qualification)
        .map_err(QualificationAuthorizationError::Write)?;
    Ok(qualification)
}

fn deserialize_qualification_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version == 2 {
        Ok(version)
    } else {
        Err(de::Error::custom("schema_version must be 2"))
    }
}

fn deserialize_endurance_authorization_schema_version<'de, D>(
    deserializer: D,
) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version == 1 {
        Ok(version)
    } else {
        Err(de::Error::custom(
            "supervised_endurance.schema_version must be 1",
        ))
    }
}
