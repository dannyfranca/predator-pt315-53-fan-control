use std::{
    error::Error,
    ffi::{CString, OsStr},
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser, ser::SerializeStruct};

use crate::{CompatibilityDeclarationV1, compatibility::validate_declaration};

pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "EvidenceRecordV1Wire")]
pub struct EvidenceRecordV1 {
    pub schema_version: u32,
    pub record_status: EvidenceRecordStatus,
    pub qualification_envelope: QualificationEnvelopeIdentityV1,
    pub stage: String,
    pub started_at: EvidenceTimestamp,
    pub completed_at: EvidenceTimestamp,
    pub workload: Option<WorkloadEvidence>,
    pub samples: Vec<TelemetrySampleEvidence>,
    pub commands: Vec<FanCommandEvidence>,
    pub readbacks: Vec<FanReadbackEvidence>,
    pub state_transitions: Vec<StateTransitionEvidence>,
    pub faults: Vec<FaultEvidence>,
    pub restoration_attempts: Vec<RestorationAttemptEvidence>,
    pub calibration: Vec<FanCalibrationEvidence>,
    pub thermal_summary: Option<ThermalSummaryEvidence>,
    pub outcome: RunOutcomeEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRecordV1Wire {
    #[serde(deserialize_with = "deserialize_schema_version")]
    schema_version: u32,
    record_status: EvidenceRecordStatus,
    qualification_envelope: QualificationEnvelopeIdentityV1,
    stage: String,
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
    #[serde(deserialize_with = "deserialize_required_option")]
    workload: Option<WorkloadEvidence>,
    samples: Vec<TelemetrySampleEvidence>,
    commands: Vec<FanCommandEvidence>,
    readbacks: Vec<FanReadbackEvidence>,
    state_transitions: Vec<StateTransitionEvidence>,
    faults: Vec<FaultEvidence>,
    restoration_attempts: Vec<RestorationAttemptEvidence>,
    calibration: Vec<FanCalibrationEvidence>,
    #[serde(deserialize_with = "deserialize_required_option")]
    thermal_summary: Option<ThermalSummaryEvidence>,
    outcome: RunOutcomeEvidence,
}

impl TryFrom<EvidenceRecordV1Wire> for EvidenceRecordV1 {
    type Error = EvidenceValidationError;

    fn try_from(wire: EvidenceRecordV1Wire) -> Result<Self, Self::Error> {
        let record = Self {
            schema_version: wire.schema_version,
            record_status: wire.record_status,
            qualification_envelope: wire.qualification_envelope,
            stage: wire.stage,
            started_at: wire.started_at,
            completed_at: wire.completed_at,
            workload: wire.workload,
            samples: wire.samples,
            commands: wire.commands,
            readbacks: wire.readbacks,
            state_transitions: wire.state_transitions,
            faults: wire.faults,
            restoration_attempts: wire.restoration_attempts,
            calibration: wire.calibration,
            thermal_summary: wire.thermal_summary,
            outcome: wire.outcome,
        };
        record.validate()?;
        Ok(record)
    }
}

impl Serialize for EvidenceRecordV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(ser::Error::custom)?;
        let mut record = serializer.serialize_struct("EvidenceRecordV1", 16)?;
        record.serialize_field("schema_version", &self.schema_version)?;
        record.serialize_field("record_status", &self.record_status)?;
        record.serialize_field("qualification_envelope", &self.qualification_envelope)?;
        record.serialize_field("stage", &self.stage)?;
        record.serialize_field("started_at", &self.started_at)?;
        record.serialize_field("completed_at", &self.completed_at)?;
        record.serialize_field("workload", &self.workload)?;
        record.serialize_field("samples", &self.samples)?;
        record.serialize_field("commands", &self.commands)?;
        record.serialize_field("readbacks", &self.readbacks)?;
        record.serialize_field("state_transitions", &self.state_transitions)?;
        record.serialize_field("faults", &self.faults)?;
        record.serialize_field("restoration_attempts", &self.restoration_attempts)?;
        record.serialize_field("calibration", &self.calibration)?;
        record.serialize_field("thermal_summary", &self.thermal_summary)?;
        record.serialize_field("outcome", &self.outcome)?;
        record.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRecordStatus {
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEnvelopeIdentityV1 {
    #[serde(
        serialize_with = "serialize_qualification_record_schema_version",
        deserialize_with = "deserialize_qualification_record_schema_version"
    )]
    pub qualification_record_schema_version: u32,
    pub qualification_id: String,
    pub policy_version: String,
    pub protected_policy_sha256: String,
    pub compatibility: CompatibilityDeclarationV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTimestamp {
    pub monotonic_millis: u64,
    pub wall_unix_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadEvidence {
    pub workload_id: String,
    pub command: Vec<String>,
    pub version: String,
    pub power_profile: EvidenceProfile,
    pub ambient_millicelsius: i32,
    pub starting_cpu_millicelsius: i32,
    pub starting_gpu_millicelsius: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySampleEvidence {
    pub timestamp: EvidenceTimestamp,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub cpu_millicelsius: Option<i32>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub gpu_millicelsius: Option<i32>,
    pub freshness: SampleFreshness,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub external_power: Option<EvidenceExternalPower>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub selected_profile: Option<EvidenceProfile>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub cpu_source_demand_basis_points: Option<u16>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub gpu_source_demand_basis_points: Option<u16>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub commanded_demand_basis_points: Option<u16>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub cpu_thermal_throttling: Option<bool>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub gpu_thermal_throttling: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SampleFreshness {
    Fresh,
    Stale,
    Invalid,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceExternalPower {
    Ac,
    Battery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceProfile {
    Ac,
    Battery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FanCommandEvidence {
    pub timestamp: EvidenceTimestamp,
    pub fan: EvidenceFan,
    pub field: FanControlField,
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FanReadbackEvidence {
    pub timestamp: EvidenceTimestamp,
    pub fan: EvidenceFan,
    pub field: FanReadbackField,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub value: Option<u32>,
    pub endpoint_identity: String,
    pub outcome: ObservationOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceFan {
    Cpu,
    Gpu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanControlField {
    Pwm,
    Enable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanReadbackField {
    Pwm,
    Enable,
    Rpm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationOutcome {
    Confirmed,
    Unexpected,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateTransitionEvidence {
    pub timestamp: EvidenceTimestamp,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultEvidence {
    pub timestamp: EvidenceTimestamp,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorationAttemptEvidence {
    pub timestamp: EvidenceTimestamp,
    pub fan: EvidenceFan,
    pub auto_write_succeeded: bool,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub enable_readback: Option<u32>,
    pub outcome: RestorationOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestorationOutcome {
    FirmwareAutoConfirmed,
    FirmwareAutoUnconfirmed,
    MaximumContainmentConfirmed,
    ContainmentFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FanCalibrationEvidence {
    pub fan: EvidenceFan,
    pub floor_basis_points: u16,
    pub response_deadline_millis: u64,
    pub anchors: Vec<RpmAnchorEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpmAnchorEvidence {
    pub duty_basis_points: u16,
    pub median_rpm: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThermalSummaryEvidence {
    pub cpu_peak_millicelsius: i32,
    pub gpu_peak_millicelsius: i32,
    pub cpu_p95_millicelsius: i32,
    pub gpu_p95_millicelsius: i32,
    pub cpu_final_slope_millicelsius_per_minute: i32,
    pub gpu_final_slope_millicelsius_per_minute: i32,
    pub kernel_faults: Vec<String>,
    pub nvidia_faults: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunOutcomeEvidence {
    pub status: RunOutcomeStatus,
    pub reason: String,
    pub another_passing_run_required: bool,
    pub final_firmware_auto_confirmed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunOutcomeStatus {
    Passed,
    Failed,
    NoGo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceValidationError {
    UnsupportedSchemaVersion,
    InvalidIdentity { field: &'static str },
    InvalidStage,
    InvalidTimeRange,
    EventOutsideRun { field: &'static str, index: usize },
    InvalidWorkload { field: &'static str },
    InvalidValue { field: &'static str, index: usize },
    InvalidState { field: &'static str, index: usize },
    InvalidFault { field: &'static str, index: usize },
}

impl fmt::Display for EvidenceValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion => {
                formatter.write_str("unsupported evidence schema version")
            }
            Self::InvalidIdentity { field } => {
                write!(formatter, "invalid qualification identity at {field}")
            }
            Self::InvalidStage => formatter.write_str("invalid qualification stage"),
            Self::InvalidTimeRange => {
                formatter.write_str("evidence monotonic time range is invalid")
            }
            Self::EventOutsideRun { field, index } => {
                write!(formatter, "{field}[{index}] is outside the run time range")
            }
            Self::InvalidWorkload { field } => write!(formatter, "invalid workload field {field}"),
            Self::InvalidValue { field, index } => {
                write!(formatter, "invalid value at {field}[{index}]")
            }
            Self::InvalidState { field, index } => {
                write!(formatter, "invalid state at {field}[{index}]")
            }
            Self::InvalidFault { field, index } => {
                write!(formatter, "invalid fault at {field}[{index}]")
            }
        }
    }
}

impl Error for EvidenceValidationError {}

#[derive(Debug)]
pub enum EvidenceParseError {
    Parse(serde_json::Error),
    Invalid(EvidenceValidationError),
}

impl fmt::Display for EvidenceParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "cannot parse evidence: {error}"),
            Self::Invalid(error) => write!(formatter, "invalid evidence: {error}"),
        }
    }
}

impl Error for EvidenceParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Invalid(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub enum EvidenceWriteError {
    Invalid(EvidenceValidationError),
    Serialize(serde_json::Error),
    InvalidDestination,
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Published {
        operation: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for EvidenceWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(formatter, "invalid evidence: {error}"),
            Self::Serialize(error) => write!(formatter, "cannot serialize evidence: {error}"),
            Self::InvalidDestination => {
                formatter.write_str("evidence destination must have a parent and file name")
            }
            Self::Io { operation, source } => write!(formatter, "cannot {operation}: {source}"),
            Self::Published { operation, source } => write!(
                formatter,
                "evidence was published, but cannot {operation}: {source}"
            ),
        }
    }
}

impl Error for EvidenceWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(error) => Some(error),
            Self::Serialize(error) => Some(error),
            Self::Io { source, .. } | Self::Published { source, .. } => Some(source),
            Self::InvalidDestination => None,
        }
    }
}

impl EvidenceWriteError {
    /// Whether the immutable destination became visible before this error.
    pub const fn destination_was_published(&self) -> bool {
        matches!(self, Self::Published { .. })
    }
}

impl EvidenceRecordV1 {
    pub fn validate(&self) -> Result<(), EvidenceValidationError> {
        if self.schema_version != EVIDENCE_SCHEMA_VERSION {
            return Err(EvidenceValidationError::UnsupportedSchemaVersion);
        }
        validate_identity(&self.qualification_envelope)?;
        if !is_identifier(&self.stage) {
            return Err(EvidenceValidationError::InvalidStage);
        }
        if self.started_at.monotonic_millis > self.completed_at.monotonic_millis {
            return Err(EvidenceValidationError::InvalidTimeRange);
        }
        if let Some(workload) = &self.workload {
            validate_workload(workload)?;
        }

        for (index, sample) in self.samples.iter().enumerate() {
            validate_timestamp(self, sample.timestamp, "samples", index)?;
            if matches!(sample.freshness, SampleFreshness::Fresh)
                && (sample.cpu_millicelsius.is_none()
                    || sample.gpu_millicelsius.is_none()
                    || sample.external_power.is_none()
                    || sample.selected_profile.is_none()
                    || sample.cpu_source_demand_basis_points.is_none()
                    || sample.gpu_source_demand_basis_points.is_none()
                    || sample.commanded_demand_basis_points.is_none()
                    || sample.cpu_thermal_throttling.is_none()
                    || sample.gpu_thermal_throttling.is_none())
            {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "samples.fresh",
                    index,
                });
            }
            for (field, value) in [
                (
                    "samples.cpu_source_demand_basis_points",
                    sample.cpu_source_demand_basis_points,
                ),
                (
                    "samples.gpu_source_demand_basis_points",
                    sample.gpu_source_demand_basis_points,
                ),
                (
                    "samples.commanded_demand_basis_points",
                    sample.commanded_demand_basis_points,
                ),
            ] {
                if value.is_some_and(|value| value > 10_000) {
                    return Err(EvidenceValidationError::InvalidValue { field, index });
                }
            }
        }
        for (index, command) in self.commands.iter().enumerate() {
            validate_timestamp(self, command.timestamp, "commands", index)?;
            let valid = match command.field {
                FanControlField::Pwm => command.value <= 255,
                FanControlField::Enable => command.value <= 2,
            };
            if !valid {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "commands.value",
                    index,
                });
            }
        }
        for (index, readback) in self.readbacks.iter().enumerate() {
            validate_timestamp(self, readback.timestamp, "readbacks", index)?;
            let outcome_matches_value = match readback.outcome {
                ObservationOutcome::Confirmed | ObservationOutcome::Unexpected => {
                    readback.value.is_some()
                }
                ObservationOutcome::Unreadable => readback.value.is_none(),
            };
            if !outcome_matches_value
                || readback.endpoint_identity.is_empty()
                || matches!(readback.field, FanReadbackField::Pwm)
                    && readback.value.is_some_and(|value| value > 255)
                || matches!(readback.field, FanReadbackField::Enable)
                    && readback.value.is_some_and(|value| value > 2)
            {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "readbacks",
                    index,
                });
            }
        }
        for (index, transition) in self.state_transitions.iter().enumerate() {
            validate_timestamp(self, transition.timestamp, "state_transitions", index)?;
            if !is_identifier(&transition.from) || !is_identifier(&transition.to) {
                return Err(EvidenceValidationError::InvalidState {
                    field: "state_transitions",
                    index,
                });
            }
        }
        for (index, fault) in self.faults.iter().enumerate() {
            validate_timestamp(self, fault.timestamp, "faults", index)?;
            if !is_identifier(&fault.code) || fault.detail.is_empty() {
                return Err(EvidenceValidationError::InvalidFault {
                    field: "faults",
                    index,
                });
            }
        }
        for (index, attempt) in self.restoration_attempts.iter().enumerate() {
            validate_timestamp(self, attempt.timestamp, "restoration_attempts", index)?;
            if attempt.enable_readback.is_some_and(|value| value > 2)
                || matches!(attempt.outcome, RestorationOutcome::FirmwareAutoConfirmed)
                    && attempt.enable_readback != Some(2)
                || matches!(attempt.outcome, RestorationOutcome::FirmwareAutoUnconfirmed)
                    && attempt.enable_readback == Some(2)
            {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "restoration_attempts.enable_readback",
                    index,
                });
            }
        }
        for (index, calibration) in self.calibration.iter().enumerate() {
            if calibration.floor_basis_points > 10_000
                || calibration.anchors.is_empty()
                || calibration
                    .anchors
                    .iter()
                    .any(|anchor| anchor.duty_basis_points > 10_000)
            {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "calibration",
                    index,
                });
            }
        }
        let final_restoration_is_complete = if self.commands.is_empty() {
            final_enable_readback_confirms_auto(self, EvidenceFan::Cpu)
                && final_enable_readback_confirms_auto(self, EvidenceFan::Gpu)
        } else {
            let mut commanded_fans = [EvidenceFan::Cpu, EvidenceFan::Gpu]
                .into_iter()
                .filter(|fan| self.commands.iter().any(|command| command.fan == *fan));
            if !commanded_fans
                .clone()
                .all(|fan| final_restoration_attempt_after_command(self, fan).is_some())
                || !final_state_follows_restoration(self)
            {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "outcome.restoration_evidence",
                    index: 0,
                });
            }
            commanded_fans.all(|fan| final_restoration_confirms_auto(self, fan))
                && final_state_confirms_auto(self)
        };
        if self.outcome.final_firmware_auto_confirmed != final_restoration_is_complete {
            return Err(EvidenceValidationError::InvalidValue {
                field: "outcome.final_firmware_auto_confirmed",
                index: 0,
            });
        }
        if matches!(self.outcome.status, RunOutcomeStatus::Passed)
            && (self.samples.is_empty()
                || self.readbacks.is_empty()
                || !self.outcome.final_firmware_auto_confirmed)
        {
            return Err(EvidenceValidationError::InvalidValue {
                field: "outcome.passed_evidence",
                index: 0,
            });
        }
        if matches!(self.outcome.status, RunOutcomeStatus::Passed) {
            let stage_evidence_is_complete = match self.stage.as_str() {
                "preflight" => {
                    self.workload.is_none()
                        && self.thermal_summary.is_none()
                        && self.commands.is_empty()
                        && self.state_transitions.is_empty()
                        && self.restoration_attempts.is_empty()
                        && self.calibration.is_empty()
                        && final_enable_readback_confirms_auto(self, EvidenceFan::Cpu)
                        && final_enable_readback_confirms_auto(self, EvidenceFan::Gpu)
                }
                "firmware-auto-baseline" => {
                    self.workload.is_some()
                        && self.thermal_summary.is_some()
                        && self.commands.is_empty()
                        && self.state_transitions.is_empty()
                        && self.restoration_attempts.is_empty()
                        && final_enable_readback_confirms_auto(self, EvidenceFan::Cpu)
                        && final_enable_readback_confirms_auto(self, EvidenceFan::Gpu)
                }
                _ => {
                    self.workload.is_some()
                        && self.thermal_summary.is_some()
                        && !self.commands.is_empty()
                        && !self.state_transitions.is_empty()
                        && !self.restoration_attempts.is_empty()
                        && final_restoration_confirms_auto(self, EvidenceFan::Cpu)
                        && final_restoration_confirms_auto(self, EvidenceFan::Gpu)
                        && final_state_confirms_auto(self)
                }
            };
            if !stage_evidence_is_complete {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "outcome.stage_evidence",
                    index: 0,
                });
            }
        }
        if self.outcome.reason.is_empty() {
            return Err(EvidenceValidationError::InvalidValue {
                field: "outcome.reason",
                index: 0,
            });
        }
        Ok(())
    }
}

pub fn parse_evidence_v1(source: &str) -> Result<EvidenceRecordV1, EvidenceParseError> {
    let record: EvidenceRecordV1 =
        serde_json::from_str(source).map_err(EvidenceParseError::Parse)?;
    record.validate().map_err(EvidenceParseError::Invalid)?;
    Ok(record)
}

/// Publishes one immutable evidence record only after all bytes are durable.
///
/// The record is built in an unnamed inode. The destination appears atomically only after the
/// complete inode has been synced, and an existing record is never replaced.
pub fn write_evidence_atomically(
    destination: &Path,
    record: &EvidenceRecordV1,
) -> Result<(), EvidenceWriteError> {
    write_evidence_with_observer(destination, record, |_| Ok(()))
}

fn write_evidence_with_observer(
    destination: &Path,
    record: &EvidenceRecordV1,
    observer: impl FnMut(PublicationStage) -> io::Result<()>,
) -> Result<(), EvidenceWriteError> {
    record.validate().map_err(EvidenceWriteError::Invalid)?;
    let mut payload = serde_json::to_vec_pretty(record).map_err(EvidenceWriteError::Serialize)?;
    payload.push(b'\n');

    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(EvidenceWriteError::InvalidDestination)?;
    let file_name = destination
        .file_name()
        .ok_or(EvidenceWriteError::InvalidDestination)?;
    let directory = open_directory(parent)?;
    let file = create_unnamed_file(&directory)?;
    publish_file(&directory, file_name, &payload, file, observer)
}

fn publish_file(
    directory: &File,
    destination_name: &OsStr,
    payload: &[u8],
    mut file: File,
    mut observer: impl FnMut(PublicationStage) -> io::Result<()>,
) -> Result<(), EvidenceWriteError> {
    file.write_all(payload)
        .map_err(|source| io_error("write temporary evidence", source))?;
    observe(&mut observer, PublicationStage::TemporaryWritten, false)?;
    file.sync_all()
        .map_err(|source| io_error("sync temporary evidence", source))?;
    observe(&mut observer, PublicationStage::TemporarySynced, false)?;

    link_open_file(directory, &file, destination_name)
        .map_err(|source| io_error("publish evidence", source))?;
    observe(&mut observer, PublicationStage::DestinationPublished, true)?;
    directory
        .sync_all()
        .map_err(|source| published_error("sync evidence directory", source))?;
    observe(&mut observer, PublicationStage::DirectorySynced, true)?;
    Ok(())
}

fn open_directory(parent: &Path) -> Result<File, EvidenceWriteError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|source| io_error("open evidence directory", source))
}

fn create_unnamed_file(directory: &File) -> Result<File, EvidenceWriteError> {
    let current_directory = CString::new(".").unwrap();
    // SAFETY: the name is NUL-terminated, `directory` remains open for the call, and ownership of
    // a successful descriptor is immediately transferred to `File`.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            current_directory.as_ptr(),
            libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor == -1 {
        Err(io_error(
            "create unnamed temporary evidence",
            io::Error::last_os_error(),
        ))
    } else {
        // SAFETY: `openat` returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn link_open_file(directory: &File, file: &File, destination_name: &OsStr) -> io::Result<()> {
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    let destination_name = c_string(destination_name)?;
    // SAFETY: the source and destination names are NUL-terminated, both descriptors remain open,
    // and AT_SYMLINK_FOLLOW makes the procfs descriptor link name resolve to the held inode.
    let result = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            directory.as_raw_fd(),
            destination_name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn c_string(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationStage {
    TemporaryWritten,
    TemporarySynced,
    DestinationPublished,
    DirectorySynced,
}

fn observe(
    observer: &mut impl FnMut(PublicationStage) -> io::Result<()>,
    stage: PublicationStage,
    published: bool,
) -> Result<(), EvidenceWriteError> {
    observer(stage).map_err(|source| {
        if published {
            published_error("complete publication checkpoint", source)
        } else {
            io_error("incomplete publication checkpoint", source)
        }
    })
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_version(deserializer, "schema_version")
}

fn deserialize_qualification_record_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_exact_version(deserializer, "qualification_record_schema_version")
}

fn serialize_qualification_record_schema_version<S>(
    version: &u32,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_exact_version(version, serializer, "qualification_record_schema_version")
}

fn serialize_exact_version<S>(version: &u32, serializer: S, field: &str) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *version == 1 {
        serializer.serialize_u32(1)
    } else {
        Err(ser::Error::custom(format_args!("{field} must be 1")))
    }
}

fn deserialize_exact_version<'de, D>(deserializer: D, field: &str) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version == 1 {
        Ok(version)
    } else {
        Err(de::Error::custom(format_args!("{field} must be 1")))
    }
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn validate_identity(
    identity: &QualificationEnvelopeIdentityV1,
) -> Result<(), EvidenceValidationError> {
    if identity.qualification_record_schema_version != 1 {
        return Err(EvidenceValidationError::InvalidIdentity {
            field: "qualification_record_schema_version",
        });
    }
    if !is_identifier(&identity.qualification_id) {
        return Err(EvidenceValidationError::InvalidIdentity {
            field: "qualification_id",
        });
    }
    if !is_identifier(&identity.policy_version) {
        return Err(EvidenceValidationError::InvalidIdentity {
            field: "policy_version",
        });
    }
    if !is_lower_hex(&identity.protected_policy_sha256, 64) {
        return Err(EvidenceValidationError::InvalidIdentity {
            field: "protected_policy_sha256",
        });
    }
    validate_declaration(&identity.compatibility).map_err(|_| {
        EvidenceValidationError::InvalidIdentity {
            field: "compatibility",
        }
    })
}

fn validate_workload(workload: &WorkloadEvidence) -> Result<(), EvidenceValidationError> {
    if !is_identifier(&workload.workload_id) {
        return Err(EvidenceValidationError::InvalidWorkload {
            field: "workload_id",
        });
    }
    if workload.command.is_empty() || workload.command.iter().any(|part| part.is_empty()) {
        return Err(EvidenceValidationError::InvalidWorkload { field: "command" });
    }
    if !is_identifier(&workload.version) {
        return Err(EvidenceValidationError::InvalidWorkload { field: "version" });
    }
    Ok(())
}

fn final_enable_readback_confirms_auto(record: &EvidenceRecordV1, fan: EvidenceFan) -> bool {
    record
        .readbacks
        .iter()
        .filter(|readback| readback.fan == fan && readback.field == FanReadbackField::Enable)
        .max_by_key(|readback| readback.timestamp.monotonic_millis)
        .is_some_and(|readback| {
            readback.value == Some(2) && readback.outcome == ObservationOutcome::Confirmed
        })
}

fn final_restoration_confirms_auto(record: &EvidenceRecordV1, fan: EvidenceFan) -> bool {
    final_restoration_attempt_after_command(record, fan).is_some_and(|attempt| {
        attempt.enable_readback == Some(2)
            && attempt.outcome == RestorationOutcome::FirmwareAutoConfirmed
    })
}

fn final_restoration_attempt_after_command(
    record: &EvidenceRecordV1,
    fan: EvidenceFan,
) -> Option<&RestorationAttemptEvidence> {
    let latest_command_millis = record
        .commands
        .iter()
        .filter(|command| command.fan == fan)
        .map(|command| command.timestamp.monotonic_millis)
        .max();
    let attempt = record
        .restoration_attempts
        .iter()
        .filter(|attempt| attempt.fan == fan)
        .max_by_key(|attempt| attempt.timestamp.monotonic_millis)?;
    latest_command_millis
        .is_none_or(|command_millis| attempt.timestamp.monotonic_millis > command_millis)
        .then_some(attempt)
}

fn final_state_follows_restoration(record: &EvidenceRecordV1) -> bool {
    let latest_restoration_millis = record
        .restoration_attempts
        .iter()
        .map(|attempt| attempt.timestamp.monotonic_millis)
        .max();
    record
        .state_transitions
        .iter()
        .max_by_key(|transition| transition.timestamp.monotonic_millis)
        .is_some_and(|transition| {
            latest_restoration_millis.is_none_or(|restoration_millis| {
                transition.timestamp.monotonic_millis >= restoration_millis
            })
        })
}

fn final_state_confirms_auto(record: &EvidenceRecordV1) -> bool {
    record
        .state_transitions
        .iter()
        .max_by_key(|transition| transition.timestamp.monotonic_millis)
        .is_some_and(|transition| {
            transition.to == "firmware-auto" && final_state_follows_restoration(record)
        })
}

fn validate_timestamp(
    record: &EvidenceRecordV1,
    timestamp: EvidenceTimestamp,
    field: &'static str,
    index: usize,
) -> Result<(), EvidenceValidationError> {
    if timestamp.monotonic_millis < record.started_at.monotonic_millis
        || timestamp.monotonic_millis > record.completed_at.monotonic_millis
    {
        Err(EvidenceValidationError::EventOutsideRun { field, index })
    } else {
        Ok(())
    }
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn io_error(operation: &'static str, source: io::Error) -> EvidenceWriteError {
    EvidenceWriteError::Io { operation, source }
}

fn published_error(operation: &'static str, source: io::Error) -> EvidenceWriteError {
    EvidenceWriteError::Published { operation, source }
}

#[cfg(test)]
mod tests {
    use std::{
        fs, io,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../qualification/evidence-example/evidence-v1.json"
    ));
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn every_interruption_boundary_has_unambiguous_destination_visibility() {
        for stage in [
            PublicationStage::TemporaryWritten,
            PublicationStage::TemporarySynced,
            PublicationStage::DestinationPublished,
            PublicationStage::DirectorySynced,
        ] {
            let directory = temporary_directory("boundary");
            fs::create_dir(&directory).unwrap();
            let destination = directory.join("run.json");
            let record = parse_evidence_v1(FIXTURE).unwrap();

            let error = write_evidence_with_observer(&destination, &record, |current| {
                if current == stage {
                    Err(io::Error::other("simulated interruption"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            let expected_visible = matches!(
                stage,
                PublicationStage::DestinationPublished | PublicationStage::DirectorySynced
            );

            assert_eq!(error.destination_was_published(), expected_visible);
            assert_eq!(destination.exists(), expected_visible);
            if expected_visible {
                assert_eq!(fs::read_to_string(&destination).unwrap(), FIXTURE);
            }
            assert_eq!(
                fs::read_dir(&directory)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().contains(".partial-"))
                    .count(),
                0
            );
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn temporary_inode_is_never_visible_in_the_evidence_directory() {
        let directory = temporary_directory("unnamed");
        fs::create_dir(&directory).unwrap();
        let destination = directory.join("run.json");
        let record = parse_evidence_v1(FIXTURE).unwrap();

        write_evidence_with_observer(&destination, &record, |stage| {
            if stage == PublicationStage::TemporarySynced {
                assert_eq!(fs::read_dir(&directory)?.count(), 0);
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(fs::read_to_string(&destination).unwrap(), FIXTURE);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "pt31553-evidence-unit-{label}-{}-{id}",
            std::process::id()
        ))
    }
}
