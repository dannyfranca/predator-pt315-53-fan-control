use std::{
    error::Error,
    ffi::{CString, OsStr},
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::Path,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser, ser::SerializeStruct};

use crate::{
    CompatibilityDeclarationV1,
    calibration::{
        calibration_response_deadline, canonical_calibration_anchor_duties,
        is_allowed_calibration_floor,
    },
    compatibility::validate_declaration,
};

pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const EVIDENCE_SCHEMA_VERSION_V2: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "EvidenceRecordWire")]
pub struct EvidenceRecord {
    pub schema_version: u32,
    pub record_status: EvidenceRecordStatus,
    pub qualification_envelope: QualificationEnvelopeIdentityV1,
    pub stage: String,
    pub started_at: EvidenceTimestamp,
    pub completed_at: EvidenceTimestamp,
    pub starting_conditions_captured_at: Option<EvidenceTimestamp>,
    pub workload_started_at: Option<EvidenceTimestamp>,
    pub baseline_binding_sha256: Option<String>,
    pub workload: Option<WorkloadEvidence>,
    pub samples: Vec<TelemetrySampleEvidence>,
    pub commands: Vec<FanCommandEvidence>,
    pub readbacks: Vec<FanReadbackEvidence>,
    pub state_transitions: Vec<StateTransitionEvidence>,
    pub faults: Vec<FaultEvidence>,
    pub restoration_attempts: Vec<RestorationAttemptEvidence>,
    pub process_stops: Vec<ProcessStopEvidence>,
    pub calibration: Vec<FanCalibrationEvidence>,
    pub thermal_summary: Option<ThermalSummaryEvidence>,
    pub endurance_thermal_envelope: Option<EnduranceThermalEnvelopeEvidence>,
    pub live_lifecycle_cases: Option<Vec<crate::LiveLifecycleCaseResult>>,
    pub outcome: RunOutcomeEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRecordWire {
    #[serde(deserialize_with = "deserialize_schema_version")]
    schema_version: u32,
    record_status: EvidenceRecordStatus,
    qualification_envelope: QualificationEnvelopeIdentityV1,
    stage: String,
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    starting_conditions_captured_at: Option<EvidenceTimestamp>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    workload_started_at: Option<EvidenceTimestamp>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    baseline_binding_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    workload: Option<WorkloadEvidence>,
    samples: Vec<TelemetrySampleEvidence>,
    commands: Vec<FanCommandEvidence>,
    readbacks: Vec<FanReadbackEvidence>,
    state_transitions: Vec<StateTransitionEvidence>,
    faults: Vec<FaultEvidence>,
    restoration_attempts: Vec<RestorationAttemptEvidence>,
    #[serde(default)]
    process_stops: Vec<ProcessStopEvidence>,
    calibration: Vec<FanCalibrationEvidence>,
    #[serde(deserialize_with = "deserialize_required_option")]
    thermal_summary: Option<ThermalSummaryEvidence>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    endurance_thermal_envelope: Option<EnduranceThermalEnvelopeEvidence>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    live_lifecycle_cases: Option<Vec<crate::LiveLifecycleCaseResult>>,
    outcome: RunOutcomeEvidence,
}

impl TryFrom<EvidenceRecordWire> for EvidenceRecord {
    type Error = EvidenceValidationError;

    fn try_from(wire: EvidenceRecordWire) -> Result<Self, Self::Error> {
        let record = Self {
            schema_version: wire.schema_version,
            record_status: wire.record_status,
            qualification_envelope: wire.qualification_envelope,
            stage: wire.stage,
            started_at: wire.started_at,
            completed_at: wire.completed_at,
            starting_conditions_captured_at: wire.starting_conditions_captured_at,
            workload_started_at: wire.workload_started_at,
            baseline_binding_sha256: wire.baseline_binding_sha256,
            workload: wire.workload,
            samples: wire.samples,
            commands: wire.commands,
            readbacks: wire.readbacks,
            state_transitions: wire.state_transitions,
            faults: wire.faults,
            restoration_attempts: wire.restoration_attempts,
            process_stops: wire.process_stops,
            calibration: wire.calibration,
            thermal_summary: wire.thermal_summary,
            endurance_thermal_envelope: wire.endurance_thermal_envelope,
            live_lifecycle_cases: wire.live_lifecycle_cases,
            outcome: wire.outcome,
        };
        record.validate()?;
        Ok(record)
    }
}

impl Serialize for EvidenceRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(ser::Error::custom)?;
        let mut record = serializer.serialize_struct(
            "EvidenceRecord",
            16 + usize::from(self.starting_conditions_captured_at.is_some())
                + usize::from(self.workload_started_at.is_some())
                + usize::from(self.baseline_binding_sha256.is_some())
                + usize::from(self.endurance_thermal_envelope.is_some())
                + usize::from(self.live_lifecycle_cases.is_some())
                + usize::from(!self.process_stops.is_empty()),
        )?;
        record.serialize_field("schema_version", &self.schema_version)?;
        record.serialize_field("record_status", &self.record_status)?;
        record.serialize_field("qualification_envelope", &self.qualification_envelope)?;
        record.serialize_field("stage", &self.stage)?;
        record.serialize_field("started_at", &self.started_at)?;
        record.serialize_field("completed_at", &self.completed_at)?;
        if let Some(starting_conditions_captured_at) = self.starting_conditions_captured_at {
            record.serialize_field(
                "starting_conditions_captured_at",
                &starting_conditions_captured_at,
            )?;
        }
        if let Some(workload_started_at) = self.workload_started_at {
            record.serialize_field("workload_started_at", &workload_started_at)?;
        }
        if let Some(baseline_binding_sha256) = &self.baseline_binding_sha256 {
            record.serialize_field("baseline_binding_sha256", baseline_binding_sha256)?;
        }
        record.serialize_field("workload", &self.workload)?;
        record.serialize_field("samples", &self.samples)?;
        record.serialize_field("commands", &self.commands)?;
        record.serialize_field("readbacks", &self.readbacks)?;
        record.serialize_field("state_transitions", &self.state_transitions)?;
        record.serialize_field("faults", &self.faults)?;
        record.serialize_field("restoration_attempts", &self.restoration_attempts)?;
        if !self.process_stops.is_empty() {
            record.serialize_field("process_stops", &self.process_stops)?;
        }
        record.serialize_field("calibration", &self.calibration)?;
        record.serialize_field("thermal_summary", &self.thermal_summary)?;
        if let Some(endurance_thermal_envelope) = &self.endurance_thermal_envelope {
            record.serialize_field("endurance_thermal_envelope", endurance_thermal_envelope)?;
        }
        if let Some(live_lifecycle_cases) = &self.live_lifecycle_cases {
            record.serialize_field("live_lifecycle_cases", live_lifecycle_cases)?;
        }
        record.serialize_field("outcome", &self.outcome)?;
        record.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRecordStatus {
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnduranceThermalEnvelopeEvidence {
    pub cpu_peak_limit_millicelsius: i32,
    pub gpu_peak_limit_millicelsius: i32,
    pub cpu_p95_limit_millicelsius: i32,
    pub gpu_p95_limit_millicelsius: i32,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_utilization_basis_points: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_utilization_basis_points: Option<u16>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub source_timestamp: Option<EvidenceTimestamp>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub fresh: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub boot_id: Option<String>,
    pub fan: EvidenceFan,
    pub field: FanReadbackField,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub value: Option<u32>,
    pub endpoint_identity: String,
    pub outcome: ObservationOutcome,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub phase: Option<FanReadbackPhase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanReadbackPhase {
    Initial,
    StartGate,
    WorkloadStarted,
    Sample,
    Final,
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
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub boot_id: Option<String>,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultEvidence {
    pub timestamp: EvidenceTimestamp,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub boot_id: Option<String>,
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
pub enum StoppedProcess {
    Workload,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStopEvidence {
    pub process: StoppedProcess,
    pub process_identity: String,
    pub requested_at: EvidenceTimestamp,
    pub confirmed_at: EvidenceTimestamp,
    pub running: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slowest_response_millis: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_checkpoint: Option<crate::CalibrationCheckpoint>,
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
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub system_stable: Option<bool>,
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
    IncompatibleSchemaField { field: &'static str },
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
            Self::IncompatibleSchemaField { field } => {
                write!(
                    formatter,
                    "{field} is incompatible with the evidence schema version"
                )
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

impl EvidenceRecord {
    pub fn validate(&self) -> Result<(), EvidenceValidationError> {
        if !matches!(
            self.schema_version,
            EVIDENCE_SCHEMA_VERSION | EVIDENCE_SCHEMA_VERSION_V2
        ) {
            return Err(EvidenceValidationError::UnsupportedSchemaVersion);
        }
        if self.schema_version == EVIDENCE_SCHEMA_VERSION {
            if self.starting_conditions_captured_at.is_some() {
                return Err(EvidenceValidationError::IncompatibleSchemaField {
                    field: "starting_conditions_captured_at",
                });
            }
            if self.workload_started_at.is_some() {
                return Err(EvidenceValidationError::IncompatibleSchemaField {
                    field: "workload_started_at",
                });
            }
            if self.baseline_binding_sha256.is_some() {
                return Err(EvidenceValidationError::IncompatibleSchemaField {
                    field: "baseline_binding_sha256",
                });
            }
            if self.live_lifecycle_cases.is_some() {
                return Err(EvidenceValidationError::IncompatibleSchemaField {
                    field: "live_lifecycle_cases",
                });
            }
            if self.readbacks.iter().any(|readback| {
                readback.phase.is_some()
                    || readback.source_timestamp.is_some()
                    || readback.fresh.is_some()
                    || readback.boot_id.is_some()
            }) {
                return Err(EvidenceValidationError::IncompatibleSchemaField {
                    field: "readbacks.v2_fields",
                });
            }
            if self
                .state_transitions
                .iter()
                .any(|transition| transition.boot_id.is_some())
            {
                return Err(EvidenceValidationError::IncompatibleSchemaField {
                    field: "state_transitions.boot_id",
                });
            }
            if self.faults.iter().any(|fault| fault.boot_id.is_some()) {
                return Err(EvidenceValidationError::IncompatibleSchemaField {
                    field: "faults.boot_id",
                });
            }
            if self
                .thermal_summary
                .as_ref()
                .is_some_and(|summary| summary.system_stable.is_some())
            {
                return Err(EvidenceValidationError::IncompatibleSchemaField {
                    field: "thermal_summary.system_stable",
                });
            }
        }
        validate_identity(&self.qualification_envelope)?;
        if !is_identifier(&self.stage) {
            return Err(EvidenceValidationError::InvalidStage);
        }
        match (
            self.schema_version,
            self.stage.as_str(),
            self.baseline_binding_sha256.as_deref(),
        ) {
            (EVIDENCE_SCHEMA_VERSION_V2, "matched-workload", Some(binding))
                if is_lower_hex(binding, 64) => {}
            (EVIDENCE_SCHEMA_VERSION_V2, "matched-workload", _) | (_, _, Some(_)) => {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "baseline_binding_sha256",
                    index: 0,
                });
            }
            (_, _, None) => {}
        }
        match (
            self.stage.as_str(),
            self.endurance_thermal_envelope.as_ref(),
        ) {
            ("supervised-endurance", Some(_))
                if self.schema_version == EVIDENCE_SCHEMA_VERSION_V2 => {}
            ("supervised-endurance", _) | (_, Some(_)) => {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "endurance_thermal_envelope",
                    index: 0,
                });
            }
            (_, None) => {}
        }
        match (self.stage.as_str(), self.live_lifecycle_cases.as_ref()) {
            ("live-lifecycle", Some(_))
                if self.schema_version == EVIDENCE_SCHEMA_VERSION_V2
                    && crate::live_lifecycle::live_lifecycle_cases_are_well_formed(self) => {}
            ("live-lifecycle", _) => {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "live_lifecycle_cases",
                    index: 0,
                });
            }
            (_, Some(_)) => {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "live_lifecycle_cases",
                    index: 0,
                });
            }
            (_, None) => {}
        }
        if self.stage == "live-lifecycle"
            && (self.starting_conditions_captured_at.is_some()
                || self.workload_started_at.is_some()
                || self.workload.is_some()
                || !self.samples.is_empty()
                || !self.commands.is_empty()
                || !self.restoration_attempts.is_empty()
                || !self.calibration.is_empty()
                || self.thermal_summary.is_some())
        {
            return Err(EvidenceValidationError::InvalidValue {
                field: "live_lifecycle_shape",
                index: 0,
            });
        }
        if self.started_at.monotonic_millis > self.completed_at.monotonic_millis {
            return Err(EvidenceValidationError::InvalidTimeRange);
        }
        if let Some(starting_conditions_captured_at) = self.starting_conditions_captured_at {
            validate_timestamp(
                self,
                starting_conditions_captured_at,
                "starting_conditions_captured_at",
                0,
            )?;
        }
        if let Some(workload_started_at) = self.workload_started_at {
            validate_timestamp(self, workload_started_at, "workload_started_at", 0)?;
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
                    "samples.cpu_utilization_basis_points",
                    sample.cpu_utilization_basis_points,
                ),
                (
                    "samples.gpu_utilization_basis_points",
                    sample.gpu_utilization_basis_points,
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
            validate_scoped_timestamp(
                self,
                readback.timestamp,
                readback.boot_id.as_deref(),
                "readbacks",
                index,
            )?;
            if let Some(source_timestamp) = readback.source_timestamp {
                validate_scoped_timestamp(
                    self,
                    source_timestamp,
                    readback.boot_id.as_deref(),
                    "readbacks.source_timestamp",
                    index,
                )?;
            }
            let outcome_matches_value = match readback.outcome {
                ObservationOutcome::Confirmed | ObservationOutcome::Unexpected => {
                    readback.value.is_some()
                }
                ObservationOutcome::Unreadable => readback.value.is_none(),
            };
            if !outcome_matches_value
                || readback.endpoint_identity.is_empty()
                || self.stage == "live-lifecycle"
                    && !crate::live_lifecycle::identity_has_nonblank_character(
                        &readback.endpoint_identity,
                    )
                || readback
                    .boot_id
                    .as_deref()
                    .is_some_and(|boot_id| !is_identifier(boot_id))
                || self.stage == "live-lifecycle"
                    && (readback.source_timestamp.is_none()
                        || readback.fresh.is_none()
                        || readback.phase.is_some())
                || self.stage != "live-lifecycle"
                    && (readback.source_timestamp.is_some()
                        || readback.fresh.is_some()
                        || readback.boot_id.is_some())
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
            validate_scoped_timestamp(
                self,
                transition.timestamp,
                transition.boot_id.as_deref(),
                "state_transitions",
                index,
            )?;
            if !is_identifier(&transition.from)
                || !is_identifier(&transition.to)
                || transition
                    .boot_id
                    .as_deref()
                    .is_some_and(|boot_id| !is_identifier(boot_id))
                || self.stage != "live-lifecycle" && transition.boot_id.is_some()
            {
                return Err(EvidenceValidationError::InvalidState {
                    field: "state_transitions",
                    index,
                });
            }
        }
        for (index, fault) in self.faults.iter().enumerate() {
            validate_scoped_timestamp(
                self,
                fault.timestamp,
                fault.boot_id.as_deref(),
                "faults",
                index,
            )?;
            if !is_identifier(&fault.code)
                || fault.detail.is_empty()
                || fault
                    .boot_id
                    .as_deref()
                    .is_some_and(|boot_id| !is_identifier(boot_id))
                || self.stage != "live-lifecycle" && fault.boot_id.is_some()
            {
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
                    && (attempt.enable_readback != Some(2) || !attempt.auto_write_succeeded)
            {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "restoration_attempts.enable_readback",
                    index,
                });
            }
        }
        if self.stage != "supervised-endurance" && !self.process_stops.is_empty() {
            return Err(EvidenceValidationError::InvalidValue {
                field: "process_stops",
                index: 0,
            });
        }
        for (index, process_stop) in self.process_stops.iter().enumerate() {
            validate_timestamp(self, process_stop.requested_at, "process_stops", index)?;
            validate_timestamp(self, process_stop.confirmed_at, "process_stops", index)?;
            if process_stop.process_identity.trim().is_empty()
                || process_stop.requested_at.monotonic_millis
                    > process_stop.confirmed_at.monotonic_millis
            {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "process_stops",
                    index,
                });
            }
        }
        let calibration_count_is_valid = match self.stage.as_str() {
            "fan-calibration" => self.calibration.len() == 1,
            "matched-workload" => {
                self.calibration.len() == 2
                    && [crate::EvidenceFan::Cpu, crate::EvidenceFan::Gpu]
                        .into_iter()
                        .all(|fan| {
                            self.calibration
                                .iter()
                                .filter(|calibration| calibration.fan == fan)
                                .count()
                                == 1
                        })
            }
            _ => self.calibration.is_empty(),
        };
        if self.schema_version == EVIDENCE_SCHEMA_VERSION_V2 && !calibration_count_is_valid {
            return Err(EvidenceValidationError::InvalidValue {
                field: "calibration",
                index: self.calibration.len(),
            });
        }
        if self.schema_version == EVIDENCE_SCHEMA_VERSION_V2
            && self.stage == "fan-calibration"
            && self.outcome.status != RunOutcomeStatus::Passed
        {
            return Err(EvidenceValidationError::InvalidValue {
                field: "outcome.status",
                index: 0,
            });
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
            if self.schema_version != EVIDENCE_SCHEMA_VERSION_V2 {
                if calibration.slowest_response_millis.is_some()
                    || calibration.protocol_checkpoint.is_some()
                {
                    return Err(EvidenceValidationError::InvalidValue {
                        field: "calibration",
                        index,
                    });
                }
                continue;
            }
            let anchors_are_ordered = calibration.anchors.windows(2).all(|anchors| {
                anchors[0].duty_basis_points < anchors[1].duty_basis_points
                    && anchors[0].median_rpm <= anchors[1].median_rpm
            });
            let canonical_anchor_duties =
                canonical_calibration_anchor_duties(calibration.floor_basis_points);
            let duties_match = calibration
                .anchors
                .iter()
                .map(|anchor| anchor.duty_basis_points)
                .eq(canonical_anchor_duties.iter().copied());
            let deadline_is_derived = calibration.slowest_response_millis.is_some_and(|slowest| {
                (1_000..=crate::MAXIMUM_CALIBRATION_RESPONSE_MILLIS).contains(&slowest)
                    && calibration.response_deadline_millis
                        == calibration_response_deadline(slowest)
            });
            let checkpoint_matches =
                calibration
                    .protocol_checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| {
                        let expected_fan = match calibration.fan {
                            EvidenceFan::Cpu => crate::Fan::Cpu,
                            EvidenceFan::Gpu => crate::Fan::Gpu,
                        };
                        let replay_matches = crate::ConservativeFanCalibration::resume(
                            expected_fan,
                            checkpoint.clone(),
                        )
                        .ok()
                        .and_then(|session| session.evidence().cloned())
                        .is_some_and(|derived| derived == *calibration);
                        replay_matches
                            && (self.stage == "matched-workload"
                                || calibration_checkpoint_is_bound_to_record(
                                    self,
                                    calibration.fan,
                                    checkpoint,
                                ))
                    });
            if !is_allowed_calibration_floor(calibration.floor_basis_points)
                || !deadline_is_derived
                || !checkpoint_matches
                || self.stage == "fan-calibration"
                    && !self
                        .commands
                        .iter()
                        .any(|command| command.fan == calibration.fan)
                || !duties_match
                || calibration
                    .anchors
                    .first()
                    .is_none_or(|anchor| anchor.duty_basis_points != calibration.floor_basis_points)
                || calibration
                    .anchors
                    .last()
                    .is_none_or(|anchor| anchor.duty_basis_points != 10_000)
                || calibration.anchors.iter().any(|anchor| {
                    anchor.duty_basis_points > 10_000
                        || !(crate::tachometer::MINIMUM_PLAUSIBLE_RPM
                            ..=crate::tachometer::MAXIMUM_PLAUSIBLE_RPM)
                            .contains(&anchor.median_rpm)
                })
                || !anchors_are_ordered
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
            let restoration_evidence_is_complete = commanded_fans
                .clone()
                .all(|fan| final_restoration_attempt_after_command(self, fan).is_some())
                && final_state_follows_restoration(self);
            if !restoration_evidence_is_complete
                && matches!(self.outcome.status, RunOutcomeStatus::Passed)
            {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "outcome.restoration_evidence",
                    index: 0,
                });
            }
            restoration_evidence_is_complete
                && commanded_fans.all(|fan| final_restoration_confirms_auto(self, fan))
                && final_state_confirms_auto(self)
        };
        if self.outcome.final_firmware_auto_confirmed != final_restoration_is_complete {
            return Err(EvidenceValidationError::InvalidValue {
                field: "outcome.final_firmware_auto_confirmed",
                index: 0,
            });
        }
        if matches!(self.outcome.status, RunOutcomeStatus::Passed)
            && ((!matches!(self.stage.as_str(), "preflight" | "live-lifecycle")
                && !self
                    .samples
                    .iter()
                    .any(|sample| sample.freshness == SampleFreshness::Fresh))
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
                "firmware-auto-baseline" => firmware_auto_baseline_is_complete(self),
                "matched-workload" if self.schema_version == EVIDENCE_SCHEMA_VERSION_V2 => {
                    crate::matched_workload::matched_workload_is_complete(self)
                }
                "live-lifecycle" if self.schema_version == EVIDENCE_SCHEMA_VERSION_V2 => {
                    crate::live_lifecycle::live_lifecycle_is_complete(self)
                }
                "supervised-endurance" if self.schema_version == EVIDENCE_SCHEMA_VERSION_V2 => {
                    crate::endurance::supervised_endurance_is_complete(self)
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

fn calibration_checkpoint_is_bound_to_record(
    record: &EvidenceRecord,
    selected_fan: EvidenceFan,
    checkpoint: &crate::CalibrationCheckpoint,
) -> bool {
    let Some((first_observation, last_observation)) = checkpoint.observed_time_bounds() else {
        return false;
    };
    if first_observation < record.started_at.monotonic_millis
        || last_observation > record.completed_at.monotonic_millis
    {
        return false;
    }

    let expected = checkpoint.command_expectations();
    let recorded: Vec<_> = record
        .commands
        .iter()
        .filter(|command| {
            command.fan == selected_fan
                && command.field == FanControlField::Pwm
                && (first_observation..=last_observation)
                    .contains(&command.timestamp.monotonic_millis)
        })
        .map(|command| (command.timestamp.monotonic_millis, command.value))
        .collect();
    let expected: Vec<_> = expected
        .iter()
        .map(|command| (command.monotonic_millis, u32::from(command.pwm_value)))
        .collect();
    if recorded != expected {
        return false;
    }

    record.commands.iter().all(|command| {
        let timestamp = command.timestamp.monotonic_millis;
        if timestamp < first_observation {
            return match command.field {
                FanControlField::Pwm => command.value == u32::from(u8::MAX),
                FanControlField::Enable => command.value == u32::from(CUSTOM_CONTROL_VALUE),
            };
        }
        if timestamp > last_observation {
            return match command.field {
                FanControlField::Pwm => command.value == u32::from(u8::MAX),
                FanControlField::Enable => command.value == u32::from(FIRMWARE_AUTO_VALUE),
            };
        }
        match (command.fan == selected_fan, command.field) {
            (true, FanControlField::Pwm) => true,
            (true, FanControlField::Enable) => command.value == u32::from(CUSTOM_CONTROL_VALUE),
            (false, FanControlField::Pwm) => command.value == u32::from(u8::MAX),
            (false, FanControlField::Enable) => command.value == u32::from(CUSTOM_CONTROL_VALUE),
        }
    })
}

const CUSTOM_CONTROL_VALUE: u8 = 1;
const FIRMWARE_AUTO_VALUE: u8 = 2;

fn firmware_auto_baseline_is_complete(record: &EvidenceRecord) -> bool {
    let Some(workload) = &record.workload else {
        return false;
    };
    let workload_conditions_are_safe = (-40_000..=80_000).contains(&workload.ambient_millicelsius)
        && (-40_000..95_000).contains(&workload.starting_cpu_millicelsius)
        && (-40_000..85_000).contains(&workload.starting_gpu_millicelsius);
    let samples_are_complete = record.samples.len() >= 2
        && record.samples.iter().all(|sample| {
            sample.freshness == SampleFreshness::Fresh
                && sample
                    .cpu_millicelsius
                    .is_some_and(|value| (-40_000..95_000).contains(&value))
                && sample
                    .gpu_millicelsius
                    .is_some_and(|value| (-40_000..85_000).contains(&value))
                && sample.external_power == Some(profile_power(workload.power_profile))
                && sample.selected_profile == Some(workload.power_profile)
                && sample.cpu_source_demand_basis_points.is_some()
                && sample.gpu_source_demand_basis_points.is_some()
                && sample.commanded_demand_basis_points.is_some()
                && sample.cpu_thermal_throttling == Some(false)
                && sample.gpu_thermal_throttling == Some(false)
        });
    let Some(workload_started_at) = record.workload_started_at else {
        return false;
    };
    let Some(starting_conditions_captured_at) = record.starting_conditions_captured_at else {
        return false;
    };
    let starting_conditions_precede_workload =
        starting_conditions_captured_at.monotonic_millis <= workload_started_at.monotonic_millis;
    let cadence_is_valid = record.samples.first().is_some_and(|sample| {
        let elapsed = sample
            .timestamp
            .monotonic_millis
            .saturating_sub(workload_started_at.monotonic_millis);
        (1_900..=2_100).contains(&elapsed)
    }) && record.samples.windows(2).all(|samples| {
        let delta = samples[1]
            .timestamp
            .monotonic_millis
            .saturating_sub(samples[0].timestamp.monotonic_millis);
        (1_900..=2_100).contains(&delta)
    });
    let readbacks_are_complete = record.readbacks.iter().all(|readback| {
        readback.field == FanReadbackField::Enable
            && readback.value == Some(2)
            && readback.outcome == ObservationOutcome::Confirmed
            && readback.phase.is_some()
    }) && [EvidenceFan::Cpu, EvidenceFan::Gpu]
        .into_iter()
        .all(|fan| baseline_readback_phases_are_complete(record, fan, workload_started_at));
    let summary_matches = record
        .thermal_summary
        .as_ref()
        .is_some_and(|summary| baseline_summary_matches(record, summary));

    workload_conditions_are_safe
        && samples_are_complete
        && starting_conditions_precede_workload
        && cadence_is_valid
        && readbacks_are_complete
        && summary_matches
        && record.faults.is_empty()
        && record.commands.is_empty()
        && record.state_transitions.is_empty()
        && record.restoration_attempts.is_empty()
        && record.calibration.is_empty()
        && final_enable_readback_confirms_auto(record, EvidenceFan::Cpu)
        && final_enable_readback_confirms_auto(record, EvidenceFan::Gpu)
}

fn baseline_readback_phases_are_complete(
    record: &EvidenceRecord,
    fan: EvidenceFan,
    workload_started_at: EvidenceTimestamp,
) -> bool {
    let Some(endpoint_identity) = record
        .readbacks
        .iter()
        .find(|readback| readback.fan == fan && readback.phase == Some(FanReadbackPhase::Initial))
        .map(|readback| readback.endpoint_identity.as_str())
    else {
        return false;
    };
    if !record
        .readbacks
        .iter()
        .filter(|readback| readback.fan == fan)
        .all(|readback| readback.endpoint_identity == endpoint_identity)
    {
        return false;
    }
    let unique_phase = |phase| {
        let mut matches = record
            .readbacks
            .iter()
            .filter(|readback| readback.fan == fan && readback.phase == Some(phase));
        let readback = matches.next()?;
        matches.next().is_none().then_some(readback)
    };
    let (Some(initial), Some(start_gate), Some(workload_started), Some(final_readback)) = (
        unique_phase(FanReadbackPhase::Initial),
        unique_phase(FanReadbackPhase::StartGate),
        unique_phase(FanReadbackPhase::WorkloadStarted),
        unique_phase(FanReadbackPhase::Final),
    ) else {
        return false;
    };
    record.started_at.monotonic_millis <= initial.timestamp.monotonic_millis
        && record
            .starting_conditions_captured_at
            .is_some_and(|starting_conditions_captured_at| {
                initial.timestamp.monotonic_millis
                    <= starting_conditions_captured_at.monotonic_millis
                    && starting_conditions_captured_at.monotonic_millis
                        <= start_gate.timestamp.monotonic_millis
            })
        && start_gate.timestamp.monotonic_millis <= workload_started_at.monotonic_millis
        && workload_started_at.monotonic_millis <= workload_started.timestamp.monotonic_millis
        && record.samples.first().is_some_and(|sample| {
            workload_started.timestamp.monotonic_millis <= sample.timestamp.monotonic_millis
        })
        && record.samples.iter().all(|sample| {
            record
                .readbacks
                .iter()
                .filter(|readback| {
                    let delay = readback
                        .timestamp
                        .monotonic_millis
                        .saturating_sub(sample.timestamp.monotonic_millis);
                    readback.fan == fan
                        && readback.phase == Some(FanReadbackPhase::Sample)
                        && readback.timestamp.monotonic_millis >= sample.timestamp.monotonic_millis
                        && delay <= 100
                })
                .count()
                == 1
        })
        && final_readback.timestamp == record.completed_at
        && record
            .readbacks
            .iter()
            .filter(|readback| readback.fan == fan)
            .count()
            == record.samples.len() + 4
}

fn profile_power(profile: EvidenceProfile) -> EvidenceExternalPower {
    match profile {
        EvidenceProfile::Ac => EvidenceExternalPower::Ac,
        EvidenceProfile::Battery => EvidenceExternalPower::Battery,
    }
}

fn baseline_summary_matches(record: &EvidenceRecord, summary: &ThermalSummaryEvidence) -> bool {
    summary == &summarize_thermal_evidence(&record.samples, true, Vec::new(), Vec::new())
}

pub(crate) fn summarize_thermal_evidence(
    samples: &[TelemetrySampleEvidence],
    system_stable: bool,
    kernel_faults: Vec<String>,
    nvidia_faults: Vec<String>,
) -> ThermalSummaryEvidence {
    let cpu = evidence_temperatures(samples, |sample| sample.cpu_millicelsius);
    let gpu = evidence_temperatures(samples, |sample| sample.gpu_millicelsius);
    ThermalSummaryEvidence {
        cpu_peak_millicelsius: cpu.iter().map(|(_, value)| *value).max().unwrap_or(0),
        gpu_peak_millicelsius: gpu.iter().map(|(_, value)| *value).max().unwrap_or(0),
        cpu_p95_millicelsius: evidence_percentile_95(&cpu),
        gpu_p95_millicelsius: evidence_percentile_95(&gpu),
        cpu_final_slope_millicelsius_per_minute: evidence_final_slope(&cpu),
        gpu_final_slope_millicelsius_per_minute: evidence_final_slope(&gpu),
        system_stable: Some(system_stable),
        kernel_faults,
        nvidia_faults,
    }
}

pub(crate) fn precise_final_thermal_slopes(samples: &[TelemetrySampleEvidence]) -> (f64, f64) {
    let cpu = evidence_temperatures(samples, |sample| sample.cpu_millicelsius);
    let gpu = evidence_temperatures(samples, |sample| sample.gpu_millicelsius);
    (
        evidence_final_slope_precise(&cpu),
        evidence_final_slope_precise(&gpu),
    )
}

fn evidence_temperatures(
    samples: &[TelemetrySampleEvidence],
    select: impl Fn(&TelemetrySampleEvidence) -> Option<i32>,
) -> Vec<(u64, i32)> {
    samples
        .iter()
        .filter_map(|sample| select(sample).map(|value| (sample.timestamp.monotonic_millis, value)))
        .collect()
}

fn evidence_percentile_95(values: &[(u64, i32)]) -> i32 {
    let mut values = values.iter().map(|(_, value)| *value).collect::<Vec<_>>();
    values.sort_unstable();
    let rank = (95 * values.len()).div_ceil(100);
    values.get(rank.saturating_sub(1)).copied().unwrap_or(0)
}

fn evidence_final_slope(values: &[(u64, i32)]) -> i32 {
    evidence_final_slope_precise(values).round() as i32
}

fn evidence_final_slope_precise(values: &[(u64, i32)]) -> f64 {
    const WINDOW_MILLIS: u64 = 5 * 60 * 1_000;
    let Some((last_millis, _)) = values.last() else {
        return 0.0;
    };
    let window_start = last_millis.saturating_sub(WINDOW_MILLIS);
    let values = values
        .iter()
        .filter(|(millis, _)| *millis >= window_start)
        .collect::<Vec<_>>();
    if values.len() < 2 {
        return 0.0;
    }
    let origin = values[0].0 as f64;
    let mean_x = values
        .iter()
        .map(|(millis, _)| (*millis as f64 - origin) / 60_000.0)
        .sum::<f64>()
        / values.len() as f64;
    let mean_y = values.iter().map(|(_, value)| *value as f64).sum::<f64>() / values.len() as f64;
    let numerator = values
        .iter()
        .map(|(millis, value)| {
            let x = (*millis as f64 - origin) / 60_000.0;
            (x - mean_x) * (*value as f64 - mean_y)
        })
        .sum::<f64>();
    let denominator = values
        .iter()
        .map(|(millis, _)| {
            let x = (*millis as f64 - origin) / 60_000.0;
            (x - mean_x).powi(2)
        })
        .sum::<f64>();
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

pub fn parse_evidence_v1(source: &str) -> Result<EvidenceRecord, EvidenceParseError> {
    let record: EvidenceRecord = serde_json::from_str(source).map_err(EvidenceParseError::Parse)?;
    if record.schema_version != EVIDENCE_SCHEMA_VERSION {
        return Err(EvidenceParseError::Invalid(
            EvidenceValidationError::UnsupportedSchemaVersion,
        ));
    }
    record.validate().map_err(EvidenceParseError::Invalid)?;
    Ok(record)
}

pub fn parse_evidence_v2(source: &str) -> Result<EvidenceRecord, EvidenceParseError> {
    let record: EvidenceRecord = serde_json::from_str(source).map_err(EvidenceParseError::Parse)?;
    if record.schema_version != EVIDENCE_SCHEMA_VERSION_V2 {
        return Err(EvidenceParseError::Invalid(
            EvidenceValidationError::UnsupportedSchemaVersion,
        ));
    }
    record.validate().map_err(EvidenceParseError::Invalid)?;
    Ok(record)
}

/// Publishes one immutable evidence record only after all bytes are durable.
///
/// The record is built in an unnamed inode. The destination appears atomically only after the
/// complete inode has been synced, and an existing record is never replaced.
pub fn write_evidence_atomically(
    destination: &Path,
    record: &EvidenceRecord,
) -> Result<(), EvidenceWriteError> {
    write_evidence_with_observer(destination, record, |_| Ok(()))
}

/// Rejects output locations that cannot safely hold root-owned authorization evidence.
pub fn validate_root_owned_output_destination(
    destination: &Path,
) -> Result<(), EvidenceWriteError> {
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    validate_owned_destination(destination, 0, unsafe { libc::geteuid() })
}

/// Publishes immutable evidence only through a protected root-owned directory chain.
pub fn write_root_owned_evidence_atomically(
    destination: &Path,
    record: &EvidenceRecord,
) -> Result<(), EvidenceWriteError> {
    record.validate().map_err(EvidenceWriteError::Invalid)?;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    write_owned_json_atomically(destination, record, 0, unsafe { libc::geteuid() })
}

pub(crate) fn write_root_owned_json_atomically<T: Serialize>(
    destination: &Path,
    value: &T,
) -> Result<(), EvidenceWriteError> {
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    write_owned_json_atomically(destination, value, 0, unsafe { libc::geteuid() })
}

fn write_owned_json_atomically<T: Serialize>(
    destination: &Path,
    value: &T,
    required_owner: u32,
    effective_user: u32,
) -> Result<(), EvidenceWriteError> {
    validate_owned_destination(destination, required_owner, effective_user)?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .expect("validated destination has a parent");
    let file_name = destination
        .file_name()
        .expect("validated destination has a file name");
    let directory = open_directory(parent)?;
    let mut payload = serde_json::to_vec_pretty(value).map_err(EvidenceWriteError::Serialize)?;
    payload.push(b'\n');
    let file = create_unnamed_file(&directory)?;
    publish_file(&directory, file_name, &payload, file, |_| Ok(()))
}

fn validate_owned_destination(
    destination: &Path,
    required_owner: u32,
    effective_user: u32,
) -> Result<(), EvidenceWriteError> {
    if effective_user != required_owner {
        return Err(io_error(
            "validate qualification record ownership",
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "effective user must own the qualification record",
            ),
        ));
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(EvidenceWriteError::InvalidDestination)?;
    let file_name = destination
        .file_name()
        .ok_or(EvidenceWriteError::InvalidDestination)?;
    if file_name.is_empty() {
        return Err(EvidenceWriteError::InvalidDestination);
    }
    validate_owned_ancestor_chain(parent, required_owner)?;
    let directory = open_directory(parent)?;
    let metadata = directory
        .metadata()
        .map_err(|source| io_error("inspect qualification record directory", source))?;
    if metadata.uid() != required_owner || metadata.permissions().mode() & 0o022 != 0 {
        return Err(io_error(
            "validate qualification record directory ownership",
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory must have the required owner and not be group/world writable",
            ),
        ));
    }
    match destination.symlink_metadata() {
        Ok(_) => Err(io_error(
            "validate output destination",
            io::Error::new(io::ErrorKind::AlreadyExists, "destination already exists"),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect output destination", error)),
    }
}

fn validate_owned_ancestor_chain(
    parent: &Path,
    required_owner: u32,
) -> Result<(), EvidenceWriteError> {
    if !parent.is_absolute() {
        return Err(EvidenceWriteError::InvalidDestination);
    }
    for ancestor in parent.ancestors() {
        let metadata = ancestor
            .symlink_metadata()
            .map_err(|source| io_error("inspect qualification record ancestor", source))?;
        let owner_is_trusted = metadata.uid() == 0 || metadata.uid() == required_owner;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !owner_is_trusted
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io_error(
                "validate qualification record ancestor ownership",
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "every ancestor must be a trusted-owner directory and not group/world writable",
                ),
            ));
        }
    }
    Ok(())
}

fn write_evidence_with_observer(
    destination: &Path,
    record: &EvidenceRecord,
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
    let version = u32::deserialize(deserializer)?;
    if matches!(
        version,
        EVIDENCE_SCHEMA_VERSION | EVIDENCE_SCHEMA_VERSION_V2
    ) {
        Ok(version)
    } else {
        Err(de::Error::custom("schema_version must be 1 or 2"))
    }
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

fn deserialize_present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub(crate) fn validate_identity(
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

pub(crate) fn validate_workload(
    workload: &WorkloadEvidence,
) -> Result<(), EvidenceValidationError> {
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

fn final_enable_readback_confirms_auto(record: &EvidenceRecord, fan: EvidenceFan) -> bool {
    let mut matching = record
        .readbacks
        .iter()
        .filter(|readback| readback.fan == fan && readback.field == FanReadbackField::Enable);
    let final_readback = if record.stage == "live-lifecycle" {
        matching.next_back()
    } else {
        matching.max_by_key(|readback| readback.timestamp.monotonic_millis)
    };
    final_readback.is_some_and(|readback| {
        readback.value == Some(2) && readback.outcome == ObservationOutcome::Confirmed
    })
}

fn final_restoration_confirms_auto(record: &EvidenceRecord, fan: EvidenceFan) -> bool {
    final_restoration_attempt_after_command(record, fan).is_some_and(|attempt| {
        attempt.auto_write_succeeded
            && attempt.enable_readback == Some(2)
            && attempt.outcome == RestorationOutcome::FirmwareAutoConfirmed
    })
}

fn final_restoration_attempt_after_command(
    record: &EvidenceRecord,
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

fn final_state_follows_restoration(record: &EvidenceRecord) -> bool {
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

fn final_state_confirms_auto(record: &EvidenceRecord) -> bool {
    record
        .state_transitions
        .iter()
        .max_by_key(|transition| transition.timestamp.monotonic_millis)
        .is_some_and(|transition| {
            transition.to == "firmware-auto" && final_state_follows_restoration(record)
        })
}

fn validate_timestamp(
    record: &EvidenceRecord,
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

fn validate_scoped_timestamp(
    record: &EvidenceRecord,
    timestamp: EvidenceTimestamp,
    boot_id: Option<&str>,
    field: &'static str,
    index: usize,
) -> Result<(), EvidenceValidationError> {
    let is_post_reboot = record.stage == "live-lifecycle"
        && boot_id.is_some()
        && boot_id == crate::live_lifecycle::post_reboot_boot_id(record);
    if is_post_reboot {
        if timestamp.wall_unix_millis < record.started_at.wall_unix_millis
            || timestamp.wall_unix_millis > record.completed_at.wall_unix_millis
        {
            Err(EvidenceValidationError::EventOutsideRun { field, index })
        } else {
            Ok(())
        }
    } else {
        validate_timestamp(record, timestamp, field, index)
    }
}

pub(crate) fn is_identifier(value: &str) -> bool {
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

    #[test]
    fn owned_json_publication_is_private_immutable_and_owner_confined() {
        // SAFETY: geteuid has no preconditions and does not mutate process state.
        let owner = unsafe { libc::geteuid() };
        let directory = trusted_temporary_directory("owned-json");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let destination = directory.join("qualification.json");
        let value = serde_json::json!({"schema_version": 1, "qualification_id": "test"});

        validate_owned_destination(&destination, owner, owner).unwrap();
        write_owned_json_atomically(&destination, &value, owner, owner).unwrap();
        let metadata = fs::metadata(&destination).unwrap();
        assert_eq!(metadata.uid(), owner);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&destination).unwrap())
                .unwrap(),
            value
        );
        assert!(write_owned_json_atomically(&destination, &value, owner, owner).is_err());

        let unsafe_ancestor = trusted_temporary_directory("unsafe-owned-json");
        let unsafe_directory = unsafe_ancestor.join("safe-child");
        fs::create_dir_all(&unsafe_directory).unwrap();
        fs::set_permissions(&unsafe_ancestor, fs::Permissions::from_mode(0o770)).unwrap();
        fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            validate_owned_destination(&unsafe_directory.join("endurance.json"), owner, owner,)
                .is_err()
        );
        assert!(
            write_owned_json_atomically(
                &unsafe_directory.join("qualification.json"),
                &value,
                owner,
                owner,
            )
            .is_err()
        );
        assert!(
            write_owned_json_atomically(
                &directory.join("wrong-owner.json"),
                &value,
                owner,
                owner.saturating_add(1),
            )
            .is_err()
        );

        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(unsafe_ancestor).unwrap();
    }

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "pt31553-evidence-unit-{label}-{}-{id}",
            std::process::id()
        ))
    }

    fn trusted_temporary_directory(label: &str) -> std::path::PathBuf {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "pt31553-owned-json-{label}-{}-{id}",
                std::process::id()
            ))
    }
}
