use std::{error::Error, fmt};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    EVIDENCE_SCHEMA_VERSION_V2, EvidenceExternalPower, EvidenceFan, EvidenceProfile,
    EvidenceRecord, EvidenceTimestamp, EvidenceValidationError, FanEndpointIdentitiesEvidence,
    FanReadbackEvidence, FanReadbackField, FaultEvidence, ObservationOutcome,
    QualificationEnvelopeIdentityV1, RunOutcomeEvidence, RunOutcomeStatus, StateTransitionEvidence,
    evidence::validate_identity,
};

pub const LIVE_RESTART_DELAY_MILLIS: u64 = 2_000;
pub const LIVE_START_LIMIT_BURST: u32 = 2;
pub const LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS: u64 = 5_000;
const UNVERIFIED_PRE_REBOOT_BOOT_ID: &str = "unverified-pre-reboot";
const UNVERIFIED_POST_REBOOT_BOOT_ID: &str = "unverified-post-reboot";

/// The complete ordered set of approved, non-destructive live lifecycle checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiveLifecycleCase {
    InvalidConfiguration,
    DuplicateProcess,
    NormalStopRestart,
    ProcessKillRecovery,
    WatchdogRecovery,
    AcToBatteryTransition,
    SuspendResume,
    Reboot,
}

impl LiveLifecycleCase {
    pub const ALL: [Self; 8] = [
        Self::InvalidConfiguration,
        Self::DuplicateProcess,
        Self::NormalStopRestart,
        Self::ProcessKillRecovery,
        Self::WatchdogRecovery,
        Self::AcToBatteryTransition,
        Self::SuspendResume,
        Self::Reboot,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid-configuration",
            Self::DuplicateProcess => "duplicate-process",
            Self::NormalStopRestart => "normal-stop-restart",
            Self::ProcessKillRecovery => "process-kill-recovery",
            Self::WatchdogRecovery => "watchdog-recovery",
            Self::AcToBatteryTransition => "ac-to-battery-transition",
            Self::SuspendResume => "suspend-resume",
            Self::Reboot => "reboot",
        }
    }

    /// Operator-facing action. The environment must return the typed observation for this case.
    pub const fn instruction(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => {
                "start with an intentionally invalid editable configuration and confirm rejection before Custom control"
            }
            Self::DuplicateProcess => {
                "start a second daemon and confirm duplicate ownership is rejected without displacing the owner"
            }
            Self::NormalStopRestart => {
                "stop normally, confirm both fans in Firmware Auto, then start a fresh daemon"
            }
            Self::ProcessKillRecovery => {
                "send SIGKILL to the daemon and confirm recovery reaches Firmware Auto before its bounded restart"
            }
            Self::WatchdogRecovery => {
                "exercise watchdog expiry and confirm recovery reaches Firmware Auto before its bounded restart"
            }
            Self::AcToBatteryTransition => {
                "disconnect AC normally and confirm battery power and the battery profile are selected"
            }
            Self::SuspendResume => {
                "request normal suspend only after both fans confirm Firmware Auto, then confirm a fresh daemon after resume"
            }
            Self::Reboot => {
                "request a normal reboot and confirm both fans in Firmware Auto before the new daemon arms"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DangerousLiveFaultInjection {
    RawWmiOrEcAccess,
    UnloadControllingModule,
    DisconnectFan,
    ForceKernelCrash,
    CutPower,
    InjectHardwareWriteFailure,
}

impl DangerousLiveFaultInjection {
    pub const ALL: [Self; 6] = [
        Self::RawWmiOrEcAccess,
        Self::UnloadControllingModule,
        Self::DisconnectFan,
        Self::ForceKernelCrash,
        Self::CutPower,
        Self::InjectHardwareWriteFailure,
    ];

    const fn id(self) -> &'static str {
        match self {
            Self::RawWmiOrEcAccess => "raw WMI/EC access",
            Self::UnloadControllingModule => "unloading the controlling module",
            Self::DisconnectFan => "disconnecting a fan",
            Self::ForceKernelCrash => "forcing a kernel crash",
            Self::CutPower => "cutting power",
            Self::InjectHardwareWriteFailure => "injecting a hardware-write failure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveLifecycleRequest {
    Approved(LiveLifecycleCase),
    Dangerous(DangerousLiveFaultInjection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveLifecycleRequestError {
    fault: DangerousLiveFaultInjection,
}

impl LiveLifecycleRequestError {
    pub const fn fault(&self) -> DangerousLiveFaultInjection {
        self.fault
    }
}

impl fmt::Display for LiveLifecycleRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} is refused on live hardware; exercise it only against the simulated backend",
            self.fault.id()
        )
    }
}

impl Error for LiveLifecycleRequestError {}

pub const fn classify_live_lifecycle_request(
    request: LiveLifecycleRequest,
) -> Result<LiveLifecycleCase, LiveLifecycleRequestError> {
    match request {
        LiveLifecycleRequest::Approved(case) => Ok(case),
        LiveLifecycleRequest::Dangerous(fault) => Err(LiveLifecycleRequestError { fault }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleFanAutoObservation {
    pub observed_at: EvidenceTimestamp,
    /// True only when the backend performed a new endpoint read for this request.
    pub fresh: bool,
    pub enable_readback: Option<u32>,
    pub endpoint_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleFanAutoPair {
    pub cpu: LiveLifecycleFanAutoObservation,
    pub gpu: LiveLifecycleFanAutoObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "case", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LiveLifecycleCaseObservation {
    InvalidConfiguration {
        observed_at: EvidenceTimestamp,
        fresh: bool,
        rejected_before_custom_control: bool,
    },
    DuplicateProcess {
        observed_at: EvidenceTimestamp,
        fresh: bool,
        duplicate_rejected: bool,
        original_owner_preserved: bool,
        original_process_identity: String,
        rejected_process_identity: String,
    },
    NormalStopRestart {
        clean_stop: bool,
        stopped_at: EvidenceTimestamp,
        auto_before_restart: LiveLifecycleFanAutoPair,
        restarted_at: EvidenceTimestamp,
        fresh_process: bool,
        process_identity_before: String,
        process_identity_after: String,
    },
    ProcessKillRecovery {
        sigkill_observed: bool,
        start_limit_reset_at: EvidenceTimestamp,
        killed_at: EvidenceTimestamp,
        auto_before_restart: LiveLifecycleFanAutoPair,
        restarted_at: EvidenceTimestamp,
        process_identity_before: String,
        process_identity_after: String,
        restart_delay_millis: u64,
        start_limit_burst: u32,
    },
    WatchdogRecovery {
        watchdog_expired: bool,
        start_limit_reset_at: EvidenceTimestamp,
        expired_at: EvidenceTimestamp,
        auto_before_restart: LiveLifecycleFanAutoPair,
        restarted_at: EvidenceTimestamp,
        process_identity_before: String,
        process_identity_after: String,
        restart_delay_millis: u64,
        start_limit_burst: u32,
    },
    AcToBatteryTransition {
        before: LiveLifecyclePowerObservation,
        after: LiveLifecyclePowerObservation,
        selected_profile_after: LiveLifecycleProfileObservation,
    },
    SuspendResume {
        auto_before_sleep: LiveLifecycleFanAutoPair,
        suspended_at: EvidenceTimestamp,
        suspend_completed: bool,
        resumed_at: EvidenceTimestamp,
        process_started_at: EvidenceTimestamp,
        process_identity_before: String,
        process_identity_after: String,
    },
    Reboot {
        reboot_completed: bool,
        boot_id_before: String,
        boot_id_after: String,
        post_boot_at: EvidenceTimestamp,
        auto_before_arm: Option<LiveLifecycleFanAutoPair>,
        armed_at: Option<EvidenceTimestamp>,
        controller_process_identity: Option<String>,
        restored_at: Option<EvidenceTimestamp>,
        auto_after_arm: Option<LiveLifecycleFanAutoPair>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleRebootContinuation {
    pub reboot_completed: bool,
    pub boot_id_before: String,
    pub boot_id_after: String,
    pub post_boot_at: EvidenceTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleRebootArmObservation {
    pub armed_at: EvidenceTimestamp,
    pub controller_process_identity: String,
}

/// Continuous physical-observer coverage for one live Custom-control action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleObserverAttestation {
    pub action: String,
    pub started_at: EvidenceTimestamp,
    pub completed_at: EvidenceTimestamp,
    /// Fresh checks made by the protected harness while the action remained live.
    pub checks: Vec<EvidenceTimestamp>,
}

/// A live operation plus the observer coverage collected during it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleObserved<T> {
    pub observation: T,
    pub observer_attestations: Vec<LiveLifecycleObserverAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecyclePowerObservation {
    pub observed_at: EvidenceTimestamp,
    pub fresh: bool,
    pub source: EvidenceExternalPower,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleProfileObservation {
    pub observed_at: EvidenceTimestamp,
    pub fresh: bool,
    pub profile: EvidenceProfile,
}

pub trait LiveLifecycleEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp;

    /// Returns the coordinator-observed identity of the currently running boot.
    fn current_boot_id(&mut self) -> Result<String, String>;

    /// Performs exactly the guided, non-destructive non-reboot case requested by the
    /// runner and returns a newly collected observation.
    ///
    /// A persisted outer coordinator must resume the reboot case after boot and provide
    /// distinct pre-boot and post-boot IDs. This core stage never initiates a reboot.
    fn run_case(
        &mut self,
        case: LiveLifecycleCase,
    ) -> Result<LiveLifecycleObserved<LiveLifecycleCaseObservation>, String>;

    /// Signal-safe containment after every non-reboot case, including harness failure.
    fn restore_after_case(
        &mut self,
        case: LiveLifecycleCase,
    ) -> Result<LiveLifecycleObserved<EvidenceTimestamp>, String>;

    /// Resumes the persisted reboot case without arming Custom control.
    fn resume_after_reboot(
        &mut self,
    ) -> Result<LiveLifecycleObserved<LiveLifecycleRebootContinuation>, String>;

    /// Arms the post-boot controller only after the runner independently confirms Auto.
    fn arm_after_reboot(
        &mut self,
    ) -> Result<LiveLifecycleObserved<LiveLifecycleRebootArmObservation>, String>;

    /// Stops the post-boot controller and restores firmware ownership before the terminal gate.
    fn restore_after_reboot(&mut self) -> Result<LiveLifecycleObserved<EvidenceTimestamp>, String>;

    /// Reads one fan's enable endpoint. The runner always calls this once for each fan.
    fn confirm_firmware_auto(
        &mut self,
        fan: EvidenceFan,
    ) -> Result<LiveLifecycleFanAutoObservation, String>;
}

#[derive(Debug)]
pub enum LiveLifecyclePlanError {
    InvalidEnvelope(EvidenceValidationError),
    InvalidCheckpoint(String),
    InvalidGeneratedEvidence(EvidenceValidationError),
}

impl fmt::Display for LiveLifecyclePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope(error) => {
                write!(formatter, "invalid qualification envelope: {error}")
            }
            Self::InvalidCheckpoint(error) => {
                write!(formatter, "invalid lifecycle checkpoint: {error}")
            }
            Self::InvalidGeneratedEvidence(error) => {
                write!(formatter, "invalid generated lifecycle evidence: {error}")
            }
        }
    }
}

impl Error for LiveLifecyclePlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEnvelope(error) | Self::InvalidGeneratedEvidence(error) => Some(error),
            Self::InvalidCheckpoint(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleCaseResult {
    case: LiveLifecycleCase,
    /// Case-local clock before the action. Reboot completion is in the new boot's clock domain.
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
    observation: Option<LiveLifecycleCaseObservation>,
    observer_attestations: Vec<LiveLifecycleObserverAttestation>,
    passed: bool,
    detail: String,
}

impl LiveLifecycleCaseResult {
    pub const fn case(&self) -> LiveLifecycleCase {
        self.case
    }

    pub const fn observation(&self) -> Option<&LiveLifecycleCaseObservation> {
        self.observation.as_ref()
    }

    pub fn observer_attestations(&self) -> &[LiveLifecycleObserverAttestation] {
        &self.observer_attestations
    }

    pub const fn started_at(&self) -> EvidenceTimestamp {
        self.started_at
    }

    pub const fn completed_at(&self) -> EvidenceTimestamp {
        self.completed_at
    }

    pub const fn passed(&self) -> bool {
        self.passed
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleReport {
    record: EvidenceRecord,
}

/// Protected state persisted by the production coordinator immediately before reboot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLifecycleCheckpoint {
    envelope: QualificationEnvelopeIdentityV1,
    prerequisite_binding_sha256: String,
    started_at: EvidenceTimestamp,
    last_event_at: EvidenceTimestamp,
    readbacks: Vec<FanReadbackEvidence>,
    transitions: Vec<StateTransitionEvidence>,
    faults: Vec<FaultEvidence>,
    cases: Vec<LiveLifecycleCaseResult>,
    expected_identities: Option<(String, String)>,
    final_auto_confirmed: bool,
    pre_reboot_boot_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveLifecycleCheckpointWire {
    envelope: QualificationEnvelopeIdentityV1,
    prerequisite_binding_sha256: String,
    started_at: EvidenceTimestamp,
    last_event_at: EvidenceTimestamp,
    readbacks: Vec<FanReadbackEvidence>,
    transitions: Vec<StateTransitionEvidence>,
    faults: Vec<FaultEvidence>,
    cases: Vec<LiveLifecycleCaseResult>,
    expected_identities: Option<(String, String)>,
    final_auto_confirmed: bool,
    pre_reboot_boot_id: String,
}

impl<'de> Deserialize<'de> for LiveLifecycleCheckpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LiveLifecycleCheckpointWire::deserialize(deserializer)?;
        let checkpoint = Self {
            envelope: wire.envelope,
            prerequisite_binding_sha256: wire.prerequisite_binding_sha256,
            started_at: wire.started_at,
            last_event_at: wire.last_event_at,
            readbacks: wire.readbacks,
            transitions: wire.transitions,
            faults: wire.faults,
            cases: wire.cases,
            expected_identities: wire.expected_identities,
            final_auto_confirmed: wire.final_auto_confirmed,
            pre_reboot_boot_id: wire.pre_reboot_boot_id,
        };
        checkpoint.validate().map_err(de::Error::custom)?;
        Ok(checkpoint)
    }
}

impl LiveLifecycleCheckpoint {
    pub const fn envelope(&self) -> &QualificationEnvelopeIdentityV1 {
        &self.envelope
    }

    pub fn prerequisite_binding_sha256(&self) -> &str {
        &self.prerequisite_binding_sha256
    }

    pub fn matches_completed_record_prefix(&self, record: &EvidenceRecord) -> bool {
        self.validate().is_ok()
            && self.envelope == record.qualification_envelope
            && record.prerequisite_binding_sha256.as_deref()
                == Some(self.prerequisite_binding_sha256.as_str())
            && self.started_at == record.started_at
            && record.readbacks.starts_with(&self.readbacks)
            && record.state_transitions.starts_with(&self.transitions)
            && record
                .live_lifecycle_cases
                .as_ref()
                .is_some_and(|cases| cases.starts_with(&self.cases))
    }

    pub const fn started_at(&self) -> EvidenceTimestamp {
        self.started_at
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_identity(&self.envelope).map_err(|error| error.to_string())?;
        if !crate::evidence::is_lower_hex(&self.prerequisite_binding_sha256, 64) {
            return Err("valid prerequisite binding required".into());
        }
        let expected = &LiveLifecycleCase::ALL[..LiveLifecycleCase::ALL.len() - 1];
        if self.cases.len() != expected.len()
            || self
                .cases
                .iter()
                .zip(expected)
                .any(|(result, expected)| result.case != *expected || !result.passed)
        {
            return Err("exact passing pre-reboot lifecycle prefix required".into());
        }
        if !self.faults.is_empty()
            || !self.final_auto_confirmed
            || !crate::evidence::is_identifier(&self.pre_reboot_boot_id)
            || self.expected_identities.as_ref().is_none_or(|(cpu, gpu)| {
                !identity_has_nonblank_character(cpu)
                    || !identity_has_nonblank_character(gpu)
                    || cpu == gpu
            })
        {
            return Err("fault-free Firmware Auto with distinct fan identities required".into());
        }
        let (expected_cpu, expected_gpu) =
            self.expected_identities.as_ref().expect("validated above");
        let final_gate_matches = self
            .readbacks
            .get(self.readbacks.len().saturating_sub(2)..)
            .is_some_and(|pair| match pair {
                [cpu, gpu] => {
                    cpu.fan == EvidenceFan::Cpu
                        && gpu.fan == EvidenceFan::Gpu
                        && cpu.endpoint_identity == *expected_cpu
                        && gpu.endpoint_identity == *expected_gpu
                }
                _ => false,
            });
        if !final_gate_matches
            || self.readbacks.iter().any(|readback| {
                readback.boot_id.as_deref() != Some(self.pre_reboot_boot_id.as_str())
            })
            || self.transitions.iter().any(|transition| {
                transition.boot_id.as_deref() != Some(self.pre_reboot_boot_id.as_str())
            })
        {
            return Err("checkpoint identities are not bound to its pre-reboot evidence".into());
        }
        if self
            .transitions
            .last()
            .map(|transition| transition.timestamp)
            != Some(self.last_event_at)
            || self.started_at.monotonic_millis > self.last_event_at.monotonic_millis
            || self.cases.windows(2).any(|pair| {
                pair[0].completed_at.monotonic_millis >= pair[1].started_at.monotonic_millis
            })
        {
            return Err("lifecycle timestamps are not ordered".into());
        }
        let mut partial = EvidenceRecord::complete_v2(
            self.envelope.clone(),
            "live-lifecycle",
            self.started_at,
            self.last_event_at,
            RunOutcomeEvidence {
                status: RunOutcomeStatus::Failed,
                reason: "reboot checkpoint is not authorization".into(),
                another_passing_run_required: true,
                final_firmware_auto_confirmed: true,
            },
        );
        partial.readbacks = self.readbacks.clone();
        partial.state_transitions = self.transitions.clone();
        partial.faults = self.faults.clone();
        partial.live_lifecycle_cases = Some(self.cases.clone());
        partial.prerequisite_binding_sha256 = Some(self.prerequisite_binding_sha256.clone());
        partial.validate().map_err(|error| error.to_string())?;
        Ok(())
    }
}

pub enum LiveLifecycleProgress {
    AwaitingReboot(Box<LiveLifecycleCheckpoint>),
    Complete(Box<LiveLifecycleReport>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveLifecycleReportWire {
    record: EvidenceRecord,
}

impl<'de> Deserialize<'de> for LiveLifecycleReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LiveLifecycleReportWire::deserialize(deserializer)?;
        if wire.record.schema_version != EVIDENCE_SCHEMA_VERSION_V2
            || wire.record.stage != "live-lifecycle"
            || wire.record.live_lifecycle_cases.is_none()
        {
            return Err(de::Error::custom(
                "live lifecycle report requires validated schema-v2 live-lifecycle evidence",
            ));
        }
        let report = Self {
            record: wire.record,
        };
        report.validate().map_err(de::Error::custom)?;
        Ok(report)
    }
}

impl LiveLifecycleReport {
    pub const fn record(&self) -> &EvidenceRecord {
        &self.record
    }

    pub fn cases(&self) -> &[LiveLifecycleCaseResult] {
        self.record
            .live_lifecycle_cases
            .as_deref()
            .expect("validated live lifecycle reports always contain cases")
    }

    pub const fn accepted(&self) -> bool {
        matches!(self.record.outcome.status, RunOutcomeStatus::Passed)
    }

    pub fn validate(&self) -> Result<(), EvidenceValidationError> {
        self.record.validate()
    }

    pub fn into_record(self) -> EvidenceRecord {
        self.record
    }
}

/// Runs the exact lifecycle prefix and returns before the operator reboots the host.
pub fn run_live_lifecycle_until_reboot<E>(
    environment: &mut E,
    envelope: &QualificationEnvelopeIdentityV1,
    prerequisite_binding_sha256: &str,
    prerequisite_fan_endpoints: &FanEndpointIdentitiesEvidence,
) -> Result<LiveLifecycleProgress, LiveLifecyclePlanError>
where
    E: LiveLifecycleEnvironment + ?Sized,
{
    validate_identity(envelope).map_err(LiveLifecyclePlanError::InvalidEnvelope)?;
    if !crate::evidence::is_lower_hex(prerequisite_binding_sha256, 64) {
        return Err(LiveLifecyclePlanError::InvalidCheckpoint(
            "valid prerequisite binding required".into(),
        ));
    }
    if !prerequisite_fan_endpoints.is_valid() {
        return Err(LiveLifecyclePlanError::InvalidCheckpoint(
            "valid prerequisite fan endpoint identities required".into(),
        ));
    }

    let pre_reboot_boot_id = environment.current_boot_id().map_err(|error| {
        LiveLifecyclePlanError::InvalidCheckpoint(format!(
            "cannot capture initial boot identity: {error}"
        ))
    })?;
    if !crate::evidence::is_identifier(&pre_reboot_boot_id) {
        return Err(LiveLifecyclePlanError::InvalidCheckpoint(
            "initial boot identity is invalid".into(),
        ));
    }
    let started_at = environment.timestamp();
    let mut state = LiveLifecycleCheckpoint {
        envelope: envelope.clone(),
        prerequisite_binding_sha256: prerequisite_binding_sha256.to_owned(),
        started_at,
        last_event_at: started_at,
        readbacks: Vec::new(),
        transitions: Vec::new(),
        faults: Vec::new(),
        cases: Vec::new(),
        expected_identities: Some((
            prerequisite_fan_endpoints.cpu_enable.clone(),
            prerequisite_fan_endpoints.gpu_enable.clone(),
        )),
        final_auto_confirmed: false,
        pre_reboot_boot_id,
    };
    let initial_gate = confirm_auto_gate(
        environment,
        started_at,
        state.expected_identities.as_ref(),
        Some(&state.pre_reboot_boot_id),
        false,
        &mut state.readbacks,
        &mut state.faults,
    );
    state.last_event_at = later_timestamp(state.last_event_at, initial_gate.completed_at);
    state.final_auto_confirmed = initial_gate.confirmed;
    if !initial_gate.confirmed {
        let cleanup_not_before = initial_gate.completed_at;
        let cleanup_result =
            environment.restore_after_case(LiveLifecycleCase::InvalidConfiguration);
        let cleanup_completed_at = environment.timestamp();
        match cleanup_result {
            Ok(restored)
                if restored.observation.monotonic_millis >= cleanup_not_before.monotonic_millis
                    && restored.observation.monotonic_millis
                        <= cleanup_completed_at.monotonic_millis
                    && restored.observation.wall_unix_millis
                        >= cleanup_not_before.wall_unix_millis
                    && restored.observation.wall_unix_millis
                        <= cleanup_completed_at.wall_unix_millis => {}
            Ok(_) => state.faults.push(FaultEvidence {
                timestamp: cleanup_completed_at,
                boot_id: Some(state.pre_reboot_boot_id.clone()),
                code: "initial-auto-recovery-failed".into(),
                detail: "initial Auto-gate recovery evidence was not fresh and ordered".into(),
            }),
            Err(error) => state.faults.push(FaultEvidence {
                timestamp: cleanup_completed_at,
                boot_id: Some(state.pre_reboot_boot_id.clone()),
                code: "initial-auto-recovery-failed".into(),
                detail: format!("cannot restore Firmware Auto after initial gate failure: {error}"),
            }),
        }
        state.last_event_at = later_timestamp(state.last_event_at, cleanup_completed_at);
        let recovery_gate = confirm_auto_gate(
            environment,
            state.last_event_at,
            state.expected_identities.as_ref(),
            Some(&state.pre_reboot_boot_id),
            false,
            &mut state.readbacks,
            &mut state.faults,
        );
        state.last_event_at = later_timestamp(state.last_event_at, recovery_gate.completed_at);
        state.final_auto_confirmed = recovery_gate.confirmed;
    }
    run_live_lifecycle_phase(environment, state, true)
}

/// Completes the reboot case after validating a protected pre-reboot checkpoint.
pub fn resume_live_lifecycle_qualification<E>(
    environment: &mut E,
    checkpoint: LiveLifecycleCheckpoint,
) -> Result<LiveLifecycleReport, LiveLifecyclePlanError>
where
    E: LiveLifecycleEnvironment + ?Sized,
{
    checkpoint
        .validate()
        .map_err(LiveLifecyclePlanError::InvalidCheckpoint)?;
    match run_live_lifecycle_phase(environment, checkpoint, false)? {
        LiveLifecycleProgress::Complete(report) => Ok(*report),
        LiveLifecycleProgress::AwaitingReboot(_) => unreachable!("resume phase cannot pause"),
    }
}

fn run_live_lifecycle_phase<E>(
    environment: &mut E,
    mut state: LiveLifecycleCheckpoint,
    pause_before_reboot: bool,
) -> Result<LiveLifecycleProgress, LiveLifecyclePlanError>
where
    E: LiveLifecycleEnvironment + ?Sized,
{
    let LiveLifecycleCheckpoint {
        ref envelope,
        ref prerequisite_binding_sha256,
        started_at,
        ref mut last_event_at,
        ref mut readbacks,
        ref mut transitions,
        ref mut faults,
        ref mut cases,
        ref mut expected_identities,
        ref mut final_auto_confirmed,
        ref pre_reboot_boot_id,
    } = state;

    if *final_auto_confirmed && faults.is_empty() {
        for case in LiveLifecycleCase::ALL.into_iter().skip(cases.len()) {
            if pause_before_reboot && case == LiveLifecycleCase::Reboot {
                let current_boot_id = environment.current_boot_id().map_err(|error| {
                    LiveLifecyclePlanError::InvalidCheckpoint(format!(
                        "cannot verify pre-reboot boot identity: {error}"
                    ))
                })?;
                if current_boot_id != *pre_reboot_boot_id {
                    return Err(LiveLifecyclePlanError::InvalidCheckpoint(
                        "boot identity changed during the pre-reboot lifecycle prefix".into(),
                    ));
                }
                let checkpoint = LiveLifecycleCheckpoint {
                    envelope: envelope.clone(),
                    prerequisite_binding_sha256: prerequisite_binding_sha256.clone(),
                    started_at,
                    last_event_at: *last_event_at,
                    readbacks: readbacks.clone(),
                    transitions: transitions.clone(),
                    faults: faults.clone(),
                    cases: cases.clone(),
                    expected_identities: expected_identities.clone(),
                    final_auto_confirmed: *final_auto_confirmed,
                    pre_reboot_boot_id: pre_reboot_boot_id.clone(),
                };
                checkpoint
                    .validate()
                    .map_err(LiveLifecyclePlanError::InvalidCheckpoint)?;
                return Ok(LiveLifecycleProgress::AwaitingReboot(Box::new(checkpoint)));
            }
            let requested_at = strictly_after_timestamp(environment.timestamp(), *last_event_at);
            transitions.push(StateTransitionEvidence {
                timestamp: requested_at,
                boot_id: Some(pre_reboot_boot_id.clone()),
                from: "firmware-auto".into(),
                to: case.id().into(),
            });

            let case_started_at = strictly_after_timestamp(environment.timestamp(), requested_at);
            let observation_result = if case == LiveLifecycleCase::Reboot {
                environment
                    .resume_after_reboot()
                    .map(|observed| LiveLifecycleObserved {
                        observation: LiveLifecycleCaseObservation::Reboot {
                            reboot_completed: observed.observation.reboot_completed,
                            boot_id_before: observed.observation.boot_id_before,
                            boot_id_after: observed.observation.boot_id_after,
                            post_boot_at: observed.observation.post_boot_at,
                            auto_before_arm: None,
                            armed_at: None,
                            controller_process_identity: None,
                            restored_at: None,
                            auto_after_arm: None,
                        },
                        observer_attestations: observed.observer_attestations,
                    })
            } else {
                environment.run_case(case)
            };
            let observed_completed_at = environment.timestamp();
            let mut case_completed_at = observed_completed_at;
            let mut observer_attestations = Vec::new();
            let (mut observation, mut observation_error) = match observation_result {
                Ok(observed) => {
                    observer_attestations = observed.observer_attestations;
                    let validation = if case == LiveLifecycleCase::Reboot {
                        environment.current_boot_id().and_then(|current_boot_id| {
                            validate_reboot_continuation(
                                &observed.observation,
                                case_started_at,
                                case_completed_at,
                                pre_reboot_boot_id,
                                &current_boot_id,
                            )
                        })
                    } else {
                        validate_case_observation(
                            case,
                            &observed.observation,
                            case_started_at,
                            case_completed_at,
                            expected_identities
                                .as_ref()
                                .expect("the initial gate established identities"),
                        )
                    };
                    (Some(observed.observation), validation.err())
                }
                Err(error) => (None, Some(format!("{} failed: {error}", case.id()))),
            };
            if case != LiveLifecycleCase::Reboot
                && case_completed_at.monotonic_millis <= case_started_at.monotonic_millis
            {
                observation_error = Some(format!(
                    "{} failed: monotonic clock did not advance across the case",
                    case.id()
                ));
            }

            let mut gate_not_before = observed_completed_at;
            if case != LiveLifecycleCase::Reboot {
                let cleanup_result = environment.restore_after_case(case);
                let cleanup_completed_at = environment.timestamp();
                match cleanup_result {
                    Ok(restored)
                        if restored.observation.monotonic_millis
                            >= observed_completed_at.monotonic_millis
                            && restored.observation.monotonic_millis
                                <= cleanup_completed_at.monotonic_millis
                            && restored.observation.wall_unix_millis
                                >= observed_completed_at.wall_unix_millis
                            && restored.observation.wall_unix_millis
                                <= cleanup_completed_at.wall_unix_millis =>
                    {
                        gate_not_before = restored.observation;
                        observer_attestations.extend(restored.observer_attestations);
                    }
                    Ok(_) => {
                        observation_error.get_or_insert_with(|| {
                            format!(
                                "{} failed: lifecycle cleanup evidence was not fresh and ordered",
                                case.id()
                            )
                        });
                        gate_not_before = cleanup_completed_at;
                    }
                    Err(error) => {
                        observation_error.get_or_insert_with(|| {
                            format!("{} failed: lifecycle cleanup failed: {error}", case.id())
                        });
                        gate_not_before = cleanup_completed_at;
                    }
                }
                gate_not_before = strictly_after_timestamp(gate_not_before, requested_at);
                case_completed_at = gate_not_before;
                if let Some(observation) = observation.as_ref()
                    && let Err(error) = validate_observer_attestations(
                        case,
                        &observer_attestations,
                        observation,
                        case_started_at,
                        case_completed_at,
                    )
                {
                    observation_error.get_or_insert(error);
                }
            }

            let mut gate_boot_id = Some(pre_reboot_boot_id.clone());
            if case == LiveLifecycleCase::Reboot {
                let (pre_boot_id, post_boot_id) = match observation.as_ref() {
                    Some(LiveLifecycleCaseObservation::Reboot {
                        boot_id_before,
                        boot_id_after,
                        ..
                    }) if reboot_boot_ids_are_valid(boot_id_before, boot_id_after) => {
                        (boot_id_before.as_str(), boot_id_after.as_str())
                    }
                    _ => (
                        UNVERIFIED_PRE_REBOOT_BOOT_ID,
                        UNVERIFIED_POST_REBOOT_BOOT_ID,
                    ),
                };
                for readback in readbacks.iter_mut() {
                    readback
                        .boot_id
                        .get_or_insert_with(|| pre_boot_id.to_owned());
                }
                for transition in transitions.iter_mut() {
                    transition
                        .boot_id
                        .get_or_insert_with(|| pre_boot_id.to_owned());
                }
                gate_boot_id = Some(post_boot_id.to_owned());
            }

            let gate = confirm_auto_gate(
                environment,
                gate_not_before,
                if case == LiveLifecycleCase::Reboot {
                    None
                } else {
                    expected_identities.as_ref()
                },
                gate_boot_id.as_deref(),
                case == LiveLifecycleCase::Reboot,
                readbacks,
                faults,
            );
            if case == LiveLifecycleCase::Reboot && observation_error.is_none() && gate.confirmed {
                let gate_pair = gate
                    .auto_pair
                    .clone()
                    .expect("a confirmed gate retains both observations");
                if let Some(rebound) = rebound_identities(&gate_pair, expected_identities.as_ref())
                {
                    match environment.arm_after_reboot() {
                        Ok(observed_arm) => {
                            let arm = observed_arm.observation;
                            observer_attestations.extend(observed_arm.observer_attestations);
                            let arm_completed_at = environment.timestamp();
                            let arm_is_ordered = arm.armed_at.monotonic_millis
                                > gate.completed_at.monotonic_millis
                                && arm.armed_at.monotonic_millis
                                    <= arm_completed_at.monotonic_millis
                                && identity_has_nonblank_character(
                                    &arm.controller_process_identity,
                                );
                            case_completed_at = arm_completed_at;
                            if arm_is_ordered {
                                if let Some(LiveLifecycleCaseObservation::Reboot {
                                    auto_before_arm,
                                    armed_at,
                                    controller_process_identity,
                                    ..
                                }) = observation.as_mut()
                                {
                                    *auto_before_arm = Some(gate_pair);
                                    *armed_at = Some(arm.armed_at);
                                    *controller_process_identity =
                                        Some(arm.controller_process_identity);
                                }
                                *expected_identities = Some(rebound);
                            } else {
                                observation_error = Some(
                                    "reboot failed: controller arming evidence was not fresh and ordered after the independent Auto gate"
                                        .into(),
                                );
                            }
                        }
                        Err(error) => {
                            case_completed_at = environment.timestamp();
                            observation_error =
                                Some(format!("reboot failed: cannot arm controller: {error}"));
                        }
                    }
                } else {
                    observation_error = Some(
                        "reboot failed: post-boot CPU/GPU endpoint identities were ambiguous or role-swapped"
                            .into(),
                    );
                }
            }
            if case == LiveLifecycleCase::Reboot && observation_error.is_none() && !gate.confirmed {
                observation_error = Some(
                    "reboot failed: independent post-boot Auto gate blocked controller arming"
                        .into(),
                );
            }
            if case == LiveLifecycleCase::Reboot {
                let restore_result = environment.restore_after_reboot();
                let restore_completed_at = environment.timestamp();
                let armed_at = observation
                    .as_ref()
                    .and_then(|observation| match observation {
                        LiveLifecycleCaseObservation::Reboot { armed_at, .. } => *armed_at,
                        _ => None,
                    });
                let restored_at = match restore_result {
                    Ok(observed_restore) => {
                        observer_attestations.extend(observed_restore.observer_attestations);
                        let restored = observed_restore.observation;
                        if restored.monotonic_millis <= restore_completed_at.monotonic_millis
                            && restored.wall_unix_millis <= restore_completed_at.wall_unix_millis
                            && armed_at.is_none_or(|armed| {
                                restored.monotonic_millis > armed.monotonic_millis
                                    && restored.wall_unix_millis > armed.wall_unix_millis
                            })
                        {
                            if let Some(LiveLifecycleCaseObservation::Reboot {
                                restored_at, ..
                            }) = observation.as_mut()
                            {
                                *restored_at = Some(restored);
                            }
                            restored
                        } else {
                            observation_error.get_or_insert_with(|| {
                                "reboot failed: post-arm restoration evidence was not fresh and ordered"
                                    .into()
                            });
                            restore_completed_at
                        }
                    }
                    Err(error) => {
                        observation_error.get_or_insert_with(|| {
                            format!("reboot failed: cannot restore after arming: {error}")
                        });
                        restore_completed_at
                    }
                };
                let terminal_gate = confirm_auto_gate(
                    environment,
                    restored_at,
                    gate.identities.as_ref(),
                    gate_boot_id.as_deref(),
                    true,
                    readbacks,
                    faults,
                );
                case_completed_at = terminal_gate.completed_at;
                if terminal_gate.confirmed {
                    if let Some(LiveLifecycleCaseObservation::Reboot { auto_after_arm, .. }) =
                        observation.as_mut()
                    {
                        *auto_after_arm = terminal_gate.auto_pair;
                    }
                } else {
                    observation_error.get_or_insert_with(|| {
                        "reboot failed: terminal Firmware Auto gate failed after post-boot arming"
                            .into()
                    });
                }
                *final_auto_confirmed = terminal_gate.confirmed;
                if let Some(observation) = observation.as_ref() {
                    if let Err(error) = validate_observer_attestations(
                        case,
                        &observer_attestations,
                        observation,
                        case_started_at,
                        case_completed_at,
                    ) {
                        observation_error.get_or_insert(error);
                    }
                }
            }
            if let Some(detail) = &observation_error {
                faults.push(FaultEvidence {
                    timestamp: gate.completed_at,
                    boot_id: gate_boot_id.clone(),
                    code: "live-lifecycle-case-failed".into(),
                    detail: detail.clone(),
                });
            }
            let restored_at = if case == LiveLifecycleCase::Reboot {
                environment.timestamp()
            } else {
                strictly_after_timestamp(environment.timestamp(), gate.completed_at)
            };
            *last_event_at = if case == LiveLifecycleCase::Reboot {
                strictly_after_timestamp(restored_at, *last_event_at)
            } else {
                later_timestamp(
                    *last_event_at,
                    later_timestamp(restored_at, gate.completed_at),
                )
            };
            if case != LiveLifecycleCase::Reboot {
                *final_auto_confirmed = gate.confirmed;
            }
            if gate.confirmed {
                *expected_identities = gate.identities;
            }
            transitions.push(StateTransitionEvidence {
                timestamp: restored_at,
                boot_id: gate_boot_id,
                from: case.id().into(),
                to: if *final_auto_confirmed {
                    "firmware-auto".into()
                } else {
                    "lifecycle-blocked".into()
                },
            });

            let passed = observation_error.is_none() && *final_auto_confirmed;
            let detail = observation_error.unwrap_or_else(|| {
                if *final_auto_confirmed {
                    format!("{} passed and both fans confirmed Firmware Auto", case.id())
                } else {
                    format!(
                        "{} ended without both fans confirmed in Firmware Auto",
                        case.id()
                    )
                }
            });
            cases.push(LiveLifecycleCaseResult {
                case,
                started_at: case_started_at,
                completed_at: case_completed_at,
                observation,
                observer_attestations,
                passed,
                detail,
            });
            if !passed {
                break;
            }
        }
    }

    let completed_at = normalize_timestamp(environment.timestamp(), *last_event_at);
    let accepted = cases.len() == LiveLifecycleCase::ALL.len()
        && cases.iter().all(LiveLifecycleCaseResult::passed)
        && *final_auto_confirmed
        && faults.is_empty();
    let reason = if accepted {
        "all approved live lifecycle cases passed with Firmware Auto between cases".into()
    } else {
        faults
            .first()
            .map(|fault| fault.detail.clone())
            .unwrap_or_else(|| {
                "live lifecycle qualification did not pass its initial Auto gate".into()
            })
    };
    let mut record = EvidenceRecord::complete_v2(
        envelope.clone(),
        "live-lifecycle",
        started_at,
        completed_at,
        RunOutcomeEvidence {
            status: if accepted {
                RunOutcomeStatus::Passed
            } else {
                RunOutcomeStatus::Failed
            },
            reason,
            another_passing_run_required: !accepted,
            final_firmware_auto_confirmed: *final_auto_confirmed,
        },
    );
    record.readbacks = readbacks.clone();
    record.state_transitions = transitions.clone();
    record.faults = faults.clone();
    record.live_lifecycle_cases = Some(cases.clone());
    record.prerequisite_binding_sha256 = Some(prerequisite_binding_sha256.clone());
    record
        .validate()
        .map_err(LiveLifecyclePlanError::InvalidGeneratedEvidence)?;
    let report = LiveLifecycleReport { record };
    report
        .validate()
        .map_err(LiveLifecyclePlanError::InvalidGeneratedEvidence)?;
    Ok(LiveLifecycleProgress::Complete(Box::new(report)))
}

struct AutoGate {
    completed_at: EvidenceTimestamp,
    identities: Option<(String, String)>,
    auto_pair: Option<LiveLifecycleFanAutoPair>,
    confirmed: bool,
}

#[derive(Clone, Copy)]
struct AutoGateContext<'a> {
    boot_id: Option<&'a str>,
    allow_clock_reset: bool,
}

fn confirm_auto_gate<E>(
    environment: &mut E,
    not_before: EvidenceTimestamp,
    expected_identities: Option<&(String, String)>,
    boot_id: Option<&str>,
    allow_clock_reset: bool,
    readbacks: &mut Vec<FanReadbackEvidence>,
    faults: &mut Vec<FaultEvidence>,
) -> AutoGate
where
    E: LiveLifecycleEnvironment + ?Sized,
{
    let context = AutoGateContext {
        boot_id,
        allow_clock_reset,
    };
    let cpu = confirm_one_fan(
        environment,
        EvidenceFan::Cpu,
        not_before,
        expected_identities.map(|identities| identities.0.as_str()),
        context,
        readbacks,
        faults,
    );
    let gpu_not_before = if allow_clock_reset {
        cpu.completed_at
    } else {
        later_timestamp(not_before, cpu.completed_at)
    };
    let gpu = confirm_one_fan(
        environment,
        EvidenceFan::Gpu,
        gpu_not_before,
        expected_identities.map(|identities| identities.1.as_str()),
        context,
        readbacks,
        faults,
    );
    let completed_at = later_timestamp(cpu.completed_at, gpu.completed_at);

    let mut detail = None;
    let identities = cpu
        .observation
        .as_ref()
        .zip(gpu.observation.as_ref())
        .map(|(cpu, gpu)| (cpu.endpoint_identity.clone(), gpu.endpoint_identity.clone()));
    let auto_pair = cpu
        .observation
        .as_ref()
        .zip(gpu.observation.as_ref())
        .map(|(cpu, gpu)| LiveLifecycleFanAutoPair {
            cpu: cpu.clone(),
            gpu: gpu.clone(),
        });
    let observations_confirmed = cpu
        .observation
        .as_ref()
        .is_some_and(|observation| observation.enable_readback == Some(2))
        && gpu
            .observation
            .as_ref()
            .is_some_and(|observation| observation.enable_readback == Some(2));

    if !cpu.valid || !gpu.valid || !observations_confirmed {
        detail = Some(
            "both CPU and GPU enable readbacks must independently equal Firmware Auto (2)"
                .to_owned(),
        );
    } else if let Some((cpu_identity, gpu_identity)) = &identities {
        if !identity_has_nonblank_character(cpu_identity)
            || !identity_has_nonblank_character(gpu_identity)
            || cpu_identity == gpu_identity
        {
            detail =
                Some("Firmware Auto readbacks require two distinct endpoint identities".into());
        } else if let Some((expected_cpu, expected_gpu)) = expected_identities {
            if cpu_identity != expected_cpu || gpu_identity != expected_gpu {
                detail =
                    Some("Firmware Auto endpoint identity changed between lifecycle cases".into());
            }
        }
    }

    if let Some(detail) = detail {
        for readback in readbacks.iter_mut().rev().take(2) {
            if readback.outcome == ObservationOutcome::Confirmed {
                readback.outcome = ObservationOutcome::Unexpected;
            }
        }
        faults.push(FaultEvidence {
            timestamp: completed_at,
            boot_id: boot_id.map(ToOwned::to_owned),
            code: "firmware-auto-unconfirmed".into(),
            detail,
        });
        AutoGate {
            completed_at,
            identities,
            auto_pair,
            confirmed: false,
        }
    } else {
        AutoGate {
            completed_at,
            identities,
            auto_pair,
            confirmed: true,
        }
    }
}

struct FanConfirmation {
    completed_at: EvidenceTimestamp,
    observation: Option<LiveLifecycleFanAutoObservation>,
    valid: bool,
}

fn confirm_one_fan<E>(
    environment: &mut E,
    fan: EvidenceFan,
    not_before: EvidenceTimestamp,
    expected_identity: Option<&str>,
    context: AutoGateContext<'_>,
    readbacks: &mut Vec<FanReadbackEvidence>,
    faults: &mut Vec<FaultEvidence>,
) -> FanConfirmation
where
    E: LiveLifecycleEnvironment + ?Sized,
{
    let requested_at = environment.timestamp();
    let result = environment.confirm_firmware_auto(fan);
    let raw_completed_at = environment.timestamp();
    match result {
        Ok(observation) => {
            let timestamp_valid = observation.fresh
                && observation.observed_at.monotonic_millis >= requested_at.monotonic_millis
                && observation.observed_at.wall_unix_millis >= requested_at.wall_unix_millis
                && observation.observed_at.monotonic_millis <= raw_completed_at.monotonic_millis
                && observation.observed_at.wall_unix_millis <= raw_completed_at.wall_unix_millis
                && observation.observed_at.monotonic_millis >= not_before.monotonic_millis
                && observation.observed_at.wall_unix_millis >= not_before.wall_unix_millis;
            let identity_valid = identity_has_nonblank_character(&observation.endpoint_identity);
            let completed_at = if context.allow_clock_reset {
                observation.observed_at
            } else {
                strictly_after_timestamp(observation.observed_at, not_before)
            };
            let evidence_identity = if identity_valid {
                observation.endpoint_identity.clone()
            } else {
                expected_identity
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| unresolved_auto_target(fan))
            };
            readbacks.push(FanReadbackEvidence {
                timestamp: completed_at,
                source_timestamp: Some(observation.observed_at),
                fresh: Some(observation.fresh),
                boot_id: context.boot_id.map(ToOwned::to_owned),
                fan,
                field: FanReadbackField::Enable,
                value: if identity_valid {
                    observation.enable_readback
                } else {
                    None
                },
                endpoint_identity: evidence_identity,
                outcome: if timestamp_valid
                    && identity_valid
                    && observation.enable_readback == Some(2)
                {
                    ObservationOutcome::Confirmed
                } else if identity_valid && observation.enable_readback.is_some() {
                    ObservationOutcome::Unexpected
                } else {
                    ObservationOutcome::Unreadable
                },
                phase: None,
            });
            if !timestamp_valid || !identity_valid {
                faults.push(FaultEvidence {
                    timestamp: completed_at,
                    boot_id: context.boot_id.map(ToOwned::to_owned),
                    code: "firmware-auto-observation-invalid".into(),
                    detail: format!(
                        "{fan:?} Firmware Auto readback has invalid time or endpoint identity"
                    ),
                });
            }
            FanConfirmation {
                completed_at,
                observation: Some(observation),
                valid: timestamp_valid && identity_valid,
            }
        }
        Err(error) => {
            let completed_at = if context.allow_clock_reset {
                raw_completed_at
            } else {
                strictly_after_timestamp(raw_completed_at, not_before)
            };
            readbacks.push(FanReadbackEvidence {
                timestamp: completed_at,
                source_timestamp: Some(raw_completed_at),
                fresh: Some(false),
                boot_id: context.boot_id.map(ToOwned::to_owned),
                fan,
                field: FanReadbackField::Enable,
                value: None,
                endpoint_identity: expected_identity
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| unresolved_auto_target(fan)),
                outcome: ObservationOutcome::Unreadable,
                phase: None,
            });
            faults.push(FaultEvidence {
                timestamp: completed_at,
                boot_id: context.boot_id.map(ToOwned::to_owned),
                code: "firmware-auto-observation-failed".into(),
                detail: format!("cannot read {fan:?} Firmware Auto state: {error}"),
            });
            FanConfirmation {
                completed_at,
                observation: None,
                valid: false,
            }
        }
    }
}

fn unresolved_auto_target(fan: EvidenceFan) -> String {
    match fan {
        EvidenceFan::Cpu => "cpu-enable-target-unresolved",
        EvidenceFan::Gpu => "gpu-enable-target-unresolved",
    }
    .to_owned()
}

fn reboot_boot_ids_are_valid(boot_id_before: &str, boot_id_after: &str) -> bool {
    crate::evidence::is_identifier(boot_id_before)
        && crate::evidence::is_identifier(boot_id_after)
        && boot_id_before != boot_id_after
}

fn validate_reboot_continuation(
    observation: &LiveLifecycleCaseObservation,
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
    expected_boot_id_before: &str,
    expected_boot_id_after: &str,
) -> Result<(), String> {
    match observation {
        LiveLifecycleCaseObservation::Reboot {
            reboot_completed: true,
            boot_id_before,
            boot_id_after,
            post_boot_at,
            auto_before_arm: None,
            armed_at: None,
            controller_process_identity: None,
            restored_at: None,
            auto_after_arm: None,
        } if reboot_boot_ids_are_valid(boot_id_before, boot_id_after)
            && boot_id_before == expected_boot_id_before
            && boot_id_after == expected_boot_id_after
            && post_boot_at.wall_unix_millis > started_at.wall_unix_millis
            && post_boot_at.wall_unix_millis <= completed_at.wall_unix_millis
            && post_boot_at.monotonic_millis <= completed_at.monotonic_millis =>
        {
            Ok(())
        }
        _ => Err(
            "reboot failed: continuation must prove a distinct post-boot identity without arming Custom control"
                .into(),
        ),
    }
}

struct BoundedRecoveryProof<'a> {
    start_limit_reset_at: EvidenceTimestamp,
    event_at: EvidenceTimestamp,
    auto_before_restart: &'a LiveLifecycleFanAutoPair,
    restarted_at: EvidenceTimestamp,
    process_identity_before: &'a str,
    process_identity_after: &'a str,
}

fn validate_bounded_recovery(
    proof: BoundedRecoveryProof<'_>,
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
    expected_identities: &(String, String),
) -> Result<(), String> {
    if started_at.monotonic_millis >= proof.start_limit_reset_at.monotonic_millis
        || started_at.wall_unix_millis > proof.start_limit_reset_at.wall_unix_millis
        || proof.start_limit_reset_at.monotonic_millis >= proof.event_at.monotonic_millis
        || proof.start_limit_reset_at.wall_unix_millis > proof.event_at.wall_unix_millis
        || !identity_has_nonblank_character(proof.process_identity_before)
        || !identity_has_nonblank_character(proof.process_identity_after)
        || proof.process_identity_before == proof.process_identity_after
    {
        return Err(
            "bounded recovery must reset the start limit before the event and restart a new process"
                .into(),
        );
    }
    validate_auto_after_event_before_boundary(
        proof.auto_before_restart,
        proof.event_at,
        proof.restarted_at,
        started_at,
        completed_at,
        expected_identities,
        "restart",
    )
}

fn validate_case_observation(
    expected_case: LiveLifecycleCase,
    observation: &LiveLifecycleCaseObservation,
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
    expected_identities: &(String, String),
) -> Result<(), String> {
    let failure = |detail: &str| Err(format!("{} failed: {detail}", expected_case.id()));
    match (expected_case, observation) {
        (
            LiveLifecycleCase::InvalidConfiguration,
            LiveLifecycleCaseObservation::InvalidConfiguration {
                observed_at,
                fresh: true,
                rejected_before_custom_control: true,
            },
        ) if timestamp_is_inside_case(*observed_at, started_at, completed_at) => Ok(()),
        (
            LiveLifecycleCase::DuplicateProcess,
            LiveLifecycleCaseObservation::DuplicateProcess {
                observed_at,
                fresh: true,
                duplicate_rejected: true,
                original_owner_preserved: true,
                original_process_identity,
                rejected_process_identity,
            },
        ) if timestamp_is_inside_case(*observed_at, started_at, completed_at)
            && identity_has_nonblank_character(original_process_identity)
            && identity_has_nonblank_character(rejected_process_identity)
            && original_process_identity != rejected_process_identity =>
        {
            Ok(())
        }
        (
            LiveLifecycleCase::NormalStopRestart,
            LiveLifecycleCaseObservation::NormalStopRestart {
                clean_stop: true,
                stopped_at,
                auto_before_restart,
                restarted_at,
                fresh_process: true,
                process_identity_before,
                process_identity_after,
            },
        ) if identity_has_nonblank_character(process_identity_before)
            && identity_has_nonblank_character(process_identity_after)
            && process_identity_before != process_identity_after =>
        {
            validate_auto_after_event_before_boundary(
                auto_before_restart,
                *stopped_at,
                *restarted_at,
                started_at,
                completed_at,
                expected_identities,
                "restart",
            )
        }
        (
            LiveLifecycleCase::ProcessKillRecovery,
            LiveLifecycleCaseObservation::ProcessKillRecovery {
                sigkill_observed: true,
                start_limit_reset_at,
                killed_at,
                auto_before_restart,
                restarted_at,
                process_identity_before,
                process_identity_after,
                restart_delay_millis: LIVE_RESTART_DELAY_MILLIS,
                start_limit_burst: LIVE_START_LIMIT_BURST,
            },
        ) => validate_bounded_recovery(
            BoundedRecoveryProof {
                start_limit_reset_at: *start_limit_reset_at,
                event_at: *killed_at,
                auto_before_restart,
                restarted_at: *restarted_at,
                process_identity_before,
                process_identity_after,
            },
            started_at,
            completed_at,
            expected_identities,
        )
        .map_err(|detail| format!("{} failed: {detail}", expected_case.id())),
        (
            LiveLifecycleCase::WatchdogRecovery,
            LiveLifecycleCaseObservation::WatchdogRecovery {
                watchdog_expired: true,
                start_limit_reset_at,
                expired_at,
                auto_before_restart,
                restarted_at,
                process_identity_before,
                process_identity_after,
                restart_delay_millis: LIVE_RESTART_DELAY_MILLIS,
                start_limit_burst: LIVE_START_LIMIT_BURST,
            },
        ) => validate_bounded_recovery(
            BoundedRecoveryProof {
                start_limit_reset_at: *start_limit_reset_at,
                event_at: *expired_at,
                auto_before_restart,
                restarted_at: *restarted_at,
                process_identity_before,
                process_identity_after,
            },
            started_at,
            completed_at,
            expected_identities,
        )
        .map_err(|detail| format!("{} failed: {detail}", expected_case.id())),
        (
            LiveLifecycleCase::AcToBatteryTransition,
            LiveLifecycleCaseObservation::AcToBatteryTransition {
                before:
                    LiveLifecyclePowerObservation {
                        observed_at: before_at,
                        fresh: true,
                        source: EvidenceExternalPower::Ac,
                    },
                after:
                    LiveLifecyclePowerObservation {
                        observed_at: after_at,
                        fresh: true,
                        source: EvidenceExternalPower::Battery,
                    },
                selected_profile_after:
                    LiveLifecycleProfileObservation {
                        observed_at: profile_at,
                        fresh: true,
                        profile: EvidenceProfile::Battery,
                    },
            },
        ) if started_at.monotonic_millis < before_at.monotonic_millis
            && started_at.wall_unix_millis <= before_at.wall_unix_millis
            && before_at.monotonic_millis < after_at.monotonic_millis
            && before_at.wall_unix_millis <= after_at.wall_unix_millis
            && after_at.monotonic_millis <= profile_at.monotonic_millis
            && after_at.wall_unix_millis <= profile_at.wall_unix_millis
            && profile_at.monotonic_millis <= completed_at.monotonic_millis
            && profile_at.wall_unix_millis <= completed_at.wall_unix_millis =>
        {
            Ok(())
        }
        (
            LiveLifecycleCase::SuspendResume,
            LiveLifecycleCaseObservation::SuspendResume {
                auto_before_sleep,
                suspended_at,
                suspend_completed: true,
                resumed_at,
                process_started_at,
                process_identity_before,
                process_identity_after,
            },
        ) if suspended_at.monotonic_millis < resumed_at.monotonic_millis
            && suspended_at.wall_unix_millis <= resumed_at.wall_unix_millis
            && resumed_at.monotonic_millis < process_started_at.monotonic_millis
            && resumed_at.wall_unix_millis <= process_started_at.wall_unix_millis
            && process_started_at.monotonic_millis <= completed_at.monotonic_millis
            && process_started_at.wall_unix_millis <= completed_at.wall_unix_millis
            && identity_has_nonblank_character(process_identity_before)
            && identity_has_nonblank_character(process_identity_after)
            && process_identity_before != process_identity_after =>
        {
            validate_auto_before_boundary(
                auto_before_sleep,
                *suspended_at,
                started_at,
                completed_at,
                expected_identities,
                "sleep",
            )
        }
        (
            LiveLifecycleCase::Reboot,
            LiveLifecycleCaseObservation::Reboot {
                reboot_completed: true,
                boot_id_before,
                boot_id_after,
                post_boot_at,
                auto_before_arm: Some(auto_before_arm),
                armed_at: Some(armed_at),
                controller_process_identity: Some(controller_process_identity),
                restored_at: Some(restored_at),
                auto_after_arm: Some(auto_after_arm),
            },
        ) if reboot_boot_ids_are_valid(boot_id_before, boot_id_after)
            && post_boot_at.wall_unix_millis > started_at.wall_unix_millis
            && post_boot_at.monotonic_millis <= completed_at.monotonic_millis
            && auto_before_arm.cpu.observed_at.monotonic_millis
                > post_boot_at.monotonic_millis
            && auto_before_arm.gpu.observed_at.monotonic_millis
                > post_boot_at.monotonic_millis
            && auto_before_arm.cpu.observed_at.wall_unix_millis
                > post_boot_at.wall_unix_millis
            && auto_before_arm.gpu.observed_at.wall_unix_millis
                > post_boot_at.wall_unix_millis
            && auto_before_arm.cpu.observed_at.monotonic_millis < armed_at.monotonic_millis
            && auto_before_arm.gpu.observed_at.monotonic_millis < armed_at.monotonic_millis
            && auto_before_arm.cpu.observed_at.wall_unix_millis < armed_at.wall_unix_millis
            && auto_before_arm.gpu.observed_at.wall_unix_millis < armed_at.wall_unix_millis
            && armed_at.monotonic_millis <= completed_at.monotonic_millis
            && armed_at.wall_unix_millis <= completed_at.wall_unix_millis
            && armed_at.monotonic_millis < restored_at.monotonic_millis
            && armed_at.wall_unix_millis < restored_at.wall_unix_millis
            && restored_at.monotonic_millis <= completed_at.monotonic_millis
            && restored_at.wall_unix_millis <= completed_at.wall_unix_millis =>
        {
            if !identity_has_nonblank_character(controller_process_identity) {
                return Err("reboot failed: armed controller process identity is empty".into());
            }
            validate_rebound_auto_pair(auto_before_arm, expected_identities).map_err(|_| {
                "reboot failed: both fans must confirm Firmware Auto after boot and before arming"
                    .to_owned()
            })?;
            let rebound = rebound_identities(auto_before_arm, Some(expected_identities))
                .ok_or_else(|| "reboot failed: endpoint identities did not rebind".to_owned())?;
            validate_rebound_auto_pair(auto_after_arm, &rebound).map_err(|_| {
                "reboot failed: both fans must confirm Firmware Auto after post-boot arming"
                    .to_owned()
            })?;
            if auto_after_arm.cpu.observed_at.monotonic_millis < restored_at.monotonic_millis
                || auto_after_arm.gpu.observed_at.monotonic_millis < restored_at.monotonic_millis
                || auto_after_arm.cpu.observed_at.wall_unix_millis < restored_at.wall_unix_millis
                || auto_after_arm.gpu.observed_at.wall_unix_millis < restored_at.wall_unix_millis
            {
                return Err("reboot failed: terminal Firmware Auto observations predate restoration".into());
            }
            Ok(())
        }
        (LiveLifecycleCase::Reboot, LiveLifecycleCaseObservation::Reboot { .. }) => Err(
            "reboot failed: both fans must confirm Firmware Auto after a verified boot change and before arming"
                .to_owned(),
        ),
        (case, observation) if observation_case(observation) != case => {
            failure("environment returned evidence for a different lifecycle case")
        }
        _ => failure("required non-destructive outcome was not confirmed"),
    }
}

fn observation_case(observation: &LiveLifecycleCaseObservation) -> LiveLifecycleCase {
    match observation {
        LiveLifecycleCaseObservation::InvalidConfiguration { .. } => {
            LiveLifecycleCase::InvalidConfiguration
        }
        LiveLifecycleCaseObservation::DuplicateProcess { .. } => {
            LiveLifecycleCase::DuplicateProcess
        }
        LiveLifecycleCaseObservation::NormalStopRestart { .. } => {
            LiveLifecycleCase::NormalStopRestart
        }
        LiveLifecycleCaseObservation::ProcessKillRecovery { .. } => {
            LiveLifecycleCase::ProcessKillRecovery
        }
        LiveLifecycleCaseObservation::WatchdogRecovery { .. } => {
            LiveLifecycleCase::WatchdogRecovery
        }
        LiveLifecycleCaseObservation::AcToBatteryTransition { .. } => {
            LiveLifecycleCase::AcToBatteryTransition
        }
        LiveLifecycleCaseObservation::SuspendResume { .. } => LiveLifecycleCase::SuspendResume,
        LiveLifecycleCaseObservation::Reboot { .. } => LiveLifecycleCase::Reboot,
    }
}

fn timestamp_is_inside_case(
    timestamp: EvidenceTimestamp,
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
) -> bool {
    started_at.monotonic_millis < timestamp.monotonic_millis
        && started_at.wall_unix_millis <= timestamp.wall_unix_millis
        && timestamp.monotonic_millis <= completed_at.monotonic_millis
        && timestamp.wall_unix_millis <= completed_at.wall_unix_millis
}

fn validate_auto_before_boundary(
    pair: &LiveLifecycleFanAutoPair,
    boundary: EvidenceTimestamp,
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
    expected_identities: &(String, String),
    boundary_name: &str,
) -> Result<(), String> {
    let time_is_valid = started_at.monotonic_millis < pair.cpu.observed_at.monotonic_millis
        && started_at.wall_unix_millis <= pair.cpu.observed_at.wall_unix_millis
        && started_at.monotonic_millis < pair.gpu.observed_at.monotonic_millis
        && started_at.wall_unix_millis <= pair.gpu.observed_at.wall_unix_millis
        && pair.cpu.observed_at.monotonic_millis < pair.gpu.observed_at.monotonic_millis
        && pair.cpu.observed_at.wall_unix_millis <= pair.gpu.observed_at.wall_unix_millis
        && pair.cpu.observed_at.monotonic_millis < boundary.monotonic_millis
        && pair.cpu.observed_at.wall_unix_millis <= boundary.wall_unix_millis
        && pair.gpu.observed_at.monotonic_millis < boundary.monotonic_millis
        && pair.gpu.observed_at.wall_unix_millis <= boundary.wall_unix_millis
        && boundary.monotonic_millis <= completed_at.monotonic_millis
        && boundary.wall_unix_millis <= completed_at.wall_unix_millis;
    if time_is_valid && validate_auto_pair(pair, expected_identities).is_ok() {
        Ok(())
    } else {
        Err(format!(
            "both fans must confirm Firmware Auto before {boundary_name}"
        ))
    }
}

fn validate_auto_after_event_before_boundary(
    pair: &LiveLifecycleFanAutoPair,
    event_at: EvidenceTimestamp,
    boundary: EvidenceTimestamp,
    started_at: EvidenceTimestamp,
    completed_at: EvidenceTimestamp,
    expected_identities: &(String, String),
    boundary_name: &str,
) -> Result<(), String> {
    if event_at.monotonic_millis <= started_at.monotonic_millis
        || event_at.wall_unix_millis < started_at.wall_unix_millis
        || pair.cpu.observed_at.monotonic_millis <= event_at.monotonic_millis
        || pair.cpu.observed_at.wall_unix_millis < event_at.wall_unix_millis
        || pair.gpu.observed_at.monotonic_millis <= event_at.monotonic_millis
        || pair.gpu.observed_at.wall_unix_millis < event_at.wall_unix_millis
    {
        return Err(format!(
            "both fans must confirm Firmware Auto after the recovery event and before {boundary_name}"
        ));
    }
    validate_auto_before_boundary(
        pair,
        boundary,
        event_at,
        completed_at,
        expected_identities,
        boundary_name,
    )
}

fn validate_auto_pair(
    pair: &LiveLifecycleFanAutoPair,
    expected_identities: &(String, String),
) -> Result<(), ()> {
    let auto_is_confirmed = pair.cpu.fresh
        && pair.gpu.fresh
        && pair.cpu.enable_readback == Some(2)
        && pair.gpu.enable_readback == Some(2)
        && pair.cpu.endpoint_identity == expected_identities.0
        && pair.gpu.endpoint_identity == expected_identities.1;
    if auto_is_confirmed { Ok(()) } else { Err(()) }
}

fn validate_rebound_auto_pair(
    pair: &LiveLifecycleFanAutoPair,
    previous_identities: &(String, String),
) -> Result<(), ()> {
    let auto_is_confirmed = pair.cpu.fresh
        && pair.gpu.fresh
        && pair.cpu.enable_readback == Some(2)
        && pair.gpu.enable_readback == Some(2);
    if rebound_identities(pair, Some(previous_identities)).is_some() && auto_is_confirmed {
        Ok(())
    } else {
        Err(())
    }
}

fn rebound_identities(
    pair: &LiveLifecycleFanAutoPair,
    previous_identities: Option<&(String, String)>,
) -> Option<(String, String)> {
    let identities_are_unambiguous = identity_has_nonblank_character(&pair.cpu.endpoint_identity)
        && identity_has_nonblank_character(&pair.gpu.endpoint_identity)
        && pair.cpu.endpoint_identity != pair.gpu.endpoint_identity
        && previous_identities.is_none_or(|previous| {
            pair.cpu.endpoint_identity != previous.1 && pair.gpu.endpoint_identity != previous.0
        });
    identities_are_unambiguous.then(|| {
        (
            pair.cpu.endpoint_identity.clone(),
            pair.gpu.endpoint_identity.clone(),
        )
    })
}

pub(crate) fn identity_has_nonblank_character(identity: &str) -> bool {
    identity.chars().any(|character| {
        !matches!(
            character,
            '\u{0000}'..='\u{0020}'
                | '\u{007f}'..='\u{00a0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
        )
    })
}

fn normalize_timestamp(
    observed: EvidenceTimestamp,
    not_before: EvidenceTimestamp,
) -> EvidenceTimestamp {
    if observed.monotonic_millis < not_before.monotonic_millis {
        not_before
    } else {
        observed
    }
}

fn strictly_after_timestamp(
    observed: EvidenceTimestamp,
    not_before: EvidenceTimestamp,
) -> EvidenceTimestamp {
    if observed.monotonic_millis <= not_before.monotonic_millis {
        EvidenceTimestamp {
            monotonic_millis: not_before.monotonic_millis.saturating_add(1),
            wall_unix_millis: observed.wall_unix_millis.max(not_before.wall_unix_millis),
        }
    } else {
        observed
    }
}

fn later_timestamp(left: EvidenceTimestamp, right: EvidenceTimestamp) -> EvidenceTimestamp {
    if left.monotonic_millis >= right.monotonic_millis {
        left
    } else {
        right
    }
}

fn case_result_fits_transition_window(
    case: LiveLifecycleCase,
    result: &LiveLifecycleCaseResult,
    entered: &StateTransitionEvidence,
    restored: &StateTransitionEvidence,
    record: &EvidenceRecord,
) -> bool {
    let case_clock_is_ordered = result.started_at.wall_unix_millis
        < result.completed_at.wall_unix_millis
        && (case == LiveLifecycleCase::Reboot
            || !result.passed
            || result.started_at.monotonic_millis < result.completed_at.monotonic_millis);
    let monotonic_is_in_record_window = case == LiveLifecycleCase::Reboot
        || (record.started_at.monotonic_millis <= result.started_at.monotonic_millis
            && record.started_at.monotonic_millis <= result.completed_at.monotonic_millis
            && result.completed_at.monotonic_millis <= record.completed_at.monotonic_millis);
    case_clock_is_ordered
        && monotonic_is_in_record_window
        && entered.timestamp.monotonic_millis < result.started_at.monotonic_millis
        && entered.timestamp.wall_unix_millis <= result.started_at.wall_unix_millis
        && result.completed_at.wall_unix_millis <= restored.timestamp.wall_unix_millis
}

pub(crate) fn post_reboot_boot_id(record: &EvidenceRecord) -> Option<&str> {
    let reboot = record
        .live_lifecycle_cases
        .as_ref()?
        .iter()
        .find(|result| result.case == LiveLifecycleCase::Reboot)?;
    match reboot.observation.as_ref() {
        Some(LiveLifecycleCaseObservation::Reboot {
            boot_id_before,
            boot_id_after,
            ..
        }) if reboot_boot_ids_are_valid(boot_id_before, boot_id_after) => {
            Some(boot_id_after.as_str())
        }
        _ if !reboot.passed => Some(UNVERIFIED_POST_REBOOT_BOOT_ID),
        _ => None,
    }
}

pub(crate) fn live_lifecycle_cases_are_well_formed(record: &EvidenceRecord) -> bool {
    let Some(cases) = record.live_lifecycle_cases.as_ref() else {
        return false;
    };
    if cases.len() > LiveLifecycleCase::ALL.len() {
        return false;
    }
    let base_readback_count = 2 + cases.len() * 2;
    let initial_recovery_gate_present = cases.is_empty() && record.readbacks.len() == 4;
    let terminal_reboot_gate_present = cases
        .last()
        .is_some_and(|result| result.case == LiveLifecycleCase::Reboot)
        && record.readbacks.len() == base_readback_count + 2;
    if record.state_transitions.len() != cases.len() * 2
        || (record.readbacks.len() != base_readback_count
            && !terminal_reboot_gate_present
            && !initial_recovery_gate_present)
    {
        return false;
    }

    let mut expected_identities = record.readbacks.get(..2).and_then(|pair| match pair {
        [cpu, gpu]
            if cpu.fan == EvidenceFan::Cpu
                && gpu.fan == EvidenceFan::Gpu
                && identity_has_nonblank_character(&cpu.endpoint_identity)
                && identity_has_nonblank_character(&gpu.endpoint_identity)
                && cpu.endpoint_identity != gpu.endpoint_identity =>
        {
            Some((cpu.endpoint_identity.clone(), gpu.endpoint_identity.clone()))
        }
        _ => None,
    });
    let initial_gate = &record.readbacks[..2];
    let Some(first_entered) = record.state_transitions.first() else {
        if !cases.is_empty()
            || !readback_pair_sources_fit_gate_window(
                initial_gate,
                record.started_at,
                record.completed_at,
                false,
            )
        {
            return false;
        }
        return !initial_recovery_gate_present
            || (readback_pair_is_ordered_attempt(&record.readbacks[2..])
                && readback_pair_sources_fit_gate_window(
                    &record.readbacks[2..],
                    initial_gate[1].timestamp,
                    record.completed_at,
                    false,
                ));
    };
    if !readback_pair_sources_fit_gate_window(
        initial_gate,
        record.started_at,
        first_entered.timestamp,
        false,
    ) {
        return false;
    }

    for (index, result) in cases.iter().enumerate() {
        let expected_case = LiveLifecycleCase::ALL[index];
        let entered = &record.state_transitions[index * 2];
        let restored = &record.state_transitions[index * 2 + 1];
        let preceding_gate = &record.readbacks[index * 2..index * 2 + 2];
        let following_gate = &record.readbacks[(index + 1) * 2..(index + 2) * 2];
        let observation_is_well_formed = result.observation.as_ref().is_none_or(|observation| {
            observation_case(observation) == expected_case
                && observation_values_fit_schema(observation)
        });
        if result.case != expected_case
            || result.detail.trim().is_empty()
            || !observation_is_well_formed
            || (result.passed && result.observation.is_none())
            || (index + 1 != cases.len() && !result.passed)
            || entered.from != "firmware-auto"
            || entered.to != expected_case.id()
            || restored.from != expected_case.id()
            || !matches!(restored.to.as_str(), "firmware-auto" | "lifecycle-blocked")
            || result.passed && restored.to != "firmware-auto"
            || result.passed
                && validate_observer_attestations(
                    expected_case,
                    &result.observer_attestations,
                    result.observation.as_ref().expect("checked above"),
                    result.started_at,
                    result.completed_at,
                )
                .is_err()
            || !case_result_fits_transition_window(expected_case, result, entered, restored, record)
        {
            return false;
        }
        let Some(identities) = expected_identities.as_ref() else {
            return false;
        };
        if !readback_pair_confirms_auto_unscoped(preceding_gate, identities)
            || !readback_pair_is_ordered_attempt(following_gate)
            || (expected_case == LiveLifecycleCase::Reboot
                && result.passed
                && following_gate[1].timestamp.monotonic_millis
                    >= result.completed_at.monotonic_millis)
            || (expected_case != LiveLifecycleCase::Reboot
                && result.completed_at.monotonic_millis
                    >= following_gate[0].timestamp.monotonic_millis)
            || following_gate[1].timestamp.monotonic_millis >= restored.timestamp.monotonic_millis
        {
            return false;
        }
        let gate_not_before = match result.observation.as_ref() {
            Some(LiveLifecycleCaseObservation::Reboot { post_boot_at, .. }) => *post_boot_at,
            _ => result.completed_at,
        };
        if result.passed
            && !readback_pair_sources_fit_gate_window(
                following_gate,
                gate_not_before,
                restored.timestamp,
                true,
            )
        {
            return false;
        }
        if result.passed {
            let observation = result.observation.as_ref().expect("checked above");
            if validate_case_observation(
                expected_case,
                observation,
                result.started_at,
                result.completed_at,
                identities,
            )
            .is_err()
            {
                return false;
            }
            if let LiveLifecycleCaseObservation::Reboot {
                auto_before_arm: Some(auto_before_arm),
                ..
            } = observation
            {
                let Some(rebound) = rebound_identities(auto_before_arm, Some(identities)) else {
                    return false;
                };
                if !readback_pair_confirms_auto_unscoped(following_gate, &rebound) {
                    return false;
                }
                expected_identities = Some(rebound);
            } else if !readback_pair_confirms_auto_unscoped(following_gate, identities) {
                return false;
            }
        }
    }
    if terminal_reboot_gate_present {
        let result = cases.last().expect("reboot result exists");
        let restored = record
            .state_transitions
            .last()
            .expect("reboot transition exists");
        let terminal_gate = &record.readbacks[record.readbacks.len() - 2..];
        if !readback_pair_is_ordered_attempt(terminal_gate)
            || terminal_gate[1].timestamp.monotonic_millis >= restored.timestamp.monotonic_millis
        {
            return false;
        }
        if result.passed {
            let Some(LiveLifecycleCaseObservation::Reboot {
                auto_after_arm: Some(auto_after_arm),
                restored_at: Some(restored_at),
                ..
            }) = result.observation.as_ref()
            else {
                return false;
            };
            let terminal_identities = (
                auto_after_arm.cpu.endpoint_identity.clone(),
                auto_after_arm.gpu.endpoint_identity.clone(),
            );
            if !readback_pair_confirms_auto_unscoped(terminal_gate, &terminal_identities)
                || !readback_pair_sources_fit_gate_window(
                    terminal_gate,
                    *restored_at,
                    restored.timestamp,
                    true,
                )
            {
                return false;
            }
        }
    }
    true
}

fn validate_observer_attestations(
    case: LiveLifecycleCase,
    attestations: &[LiveLifecycleObserverAttestation],
    observation: &LiveLifecycleCaseObservation,
    case_started_at: EvidenceTimestamp,
    case_completed_at: EvidenceTimestamp,
) -> Result<(), String> {
    let point = |value| (value, value);
    let expected_actions: Vec<(&str, (EvidenceTimestamp, EvidenceTimestamp))> = match observation {
        LiveLifecycleCaseObservation::InvalidConfiguration { .. } => vec![],
        LiveLifecycleCaseObservation::DuplicateProcess { observed_at, .. } => vec![
            ("duplicate-owner-custom", point(*observed_at)),
            ("duplicate-process-cleanup", point(case_completed_at)),
        ],
        LiveLifecycleCaseObservation::NormalStopRestart {
            stopped_at,
            restarted_at,
            ..
        } => vec![
            ("normal-owner-before-stop", point(*stopped_at)),
            ("normal-restart-custom", point(*restarted_at)),
            ("normal-stop-restart-cleanup", point(case_completed_at)),
        ],
        LiveLifecycleCaseObservation::ProcessKillRecovery {
            killed_at,
            restarted_at,
            ..
        } => vec![
            ("process-before-kill", point(*killed_at)),
            ("bounded-restart-custom", point(*restarted_at)),
            ("process-kill-recovery-cleanup", point(case_completed_at)),
        ],
        LiveLifecycleCaseObservation::WatchdogRecovery {
            expired_at,
            restarted_at,
            ..
        } => vec![
            ("watchdog-monitored-custom", point(*expired_at)),
            ("bounded-restart-custom", point(*restarted_at)),
            ("watchdog-recovery-cleanup", point(case_completed_at)),
        ],
        LiveLifecycleCaseObservation::AcToBatteryTransition {
            before,
            selected_profile_after,
            ..
        } => vec![
            (
                "ac-transition-custom",
                (before.observed_at, selected_profile_after.observed_at),
            ),
            ("ac-to-battery-transition-cleanup", point(case_completed_at)),
        ],
        LiveLifecycleCaseObservation::SuspendResume {
            suspended_at,
            process_started_at,
            ..
        } => vec![
            ("pre-suspend-custom", point(*suspended_at)),
            ("post-resume-custom", point(*process_started_at)),
            ("suspend-resume-cleanup", point(case_completed_at)),
        ],
        LiveLifecycleCaseObservation::Reboot {
            armed_at: Some(armed_at),
            restored_at: Some(restored_at),
            ..
        } => vec![
            ("post-reboot-arm", point(*armed_at)),
            ("post-reboot-restore", point(*restored_at)),
        ],
        LiveLifecycleCaseObservation::Reboot { .. } => vec![],
    };
    if attestations.len() != expected_actions.len()
        || attestations
            .iter()
            .zip(&expected_actions)
            .any(|(attestation, (expected, _))| attestation.action != *expected)
    {
        return Err(format!(
            "{} failed: exact per-action observer coverage is required",
            case.id()
        ));
    }
    if attestations.windows(2).any(|pair| {
        let previous = pair[0].completed_at;
        let next = pair[1].started_at;
        next.monotonic_millis > previous.monotonic_millis
            && next.monotonic_millis - previous.monotonic_millis
                > LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS
            || next.wall_unix_millis > previous.wall_unix_millis
                && next.wall_unix_millis - previous.wall_unix_millis
                    > LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS as i64
    }) {
        return Err(format!(
            "{} failed: observer coverage is not continuous between Custom-control actions",
            case.id()
        ));
    }
    if case != LiveLifecycleCase::Reboot && !attestations.is_empty() {
        let first = attestations.first().expect("nonempty above").started_at;
        let last = attestations.last().expect("nonempty above").completed_at;
        let starts_promptly = first.monotonic_millis >= case_started_at.monotonic_millis
            && first.monotonic_millis - case_started_at.monotonic_millis
                <= LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS
            && first.wall_unix_millis >= case_started_at.wall_unix_millis
            && first.wall_unix_millis - case_started_at.wall_unix_millis
                <= LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS as i64;
        let ends_promptly = last.monotonic_millis <= case_completed_at.monotonic_millis
            && case_completed_at.monotonic_millis - last.monotonic_millis
                <= LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS
            && last.wall_unix_millis <= case_completed_at.wall_unix_millis
            && case_completed_at.wall_unix_millis - last.wall_unix_millis
                <= LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS as i64;
        if !starts_promptly || !ends_promptly {
            return Err(format!(
                "{} failed: observer coverage does not span the complete live case",
                case.id()
            ));
        }
    }
    for (attestation, (_, (action_started_at, action_completed_at))) in
        attestations.iter().zip(expected_actions)
    {
        let checks_fit = attestation.checks.len() >= 2
            && attestation.checks.first() == Some(&attestation.started_at)
            && attestation.checks.last() == Some(&attestation.completed_at)
            && (case == LiveLifecycleCase::Reboot
                || attestation.started_at.monotonic_millis >= case_started_at.monotonic_millis)
            && attestation.started_at.wall_unix_millis >= case_started_at.wall_unix_millis
            && attestation.completed_at.monotonic_millis <= case_completed_at.monotonic_millis
            && attestation.completed_at.wall_unix_millis <= case_completed_at.wall_unix_millis
            && attestation.started_at.monotonic_millis <= action_started_at.monotonic_millis
            && attestation.started_at.wall_unix_millis <= action_started_at.wall_unix_millis
            && attestation.completed_at.monotonic_millis >= action_completed_at.monotonic_millis
            && attestation.completed_at.wall_unix_millis >= action_completed_at.wall_unix_millis
            && attestation.checks.windows(2).all(|pair| {
                pair[0].monotonic_millis < pair[1].monotonic_millis
                    && pair[0].wall_unix_millis <= pair[1].wall_unix_millis
                    && pair[1].monotonic_millis - pair[0].monotonic_millis
                        <= LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS
                    && pair[1]
                        .wall_unix_millis
                        .checked_sub(pair[0].wall_unix_millis)
                        .is_some_and(|gap| gap <= LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS as i64)
            });
        if !checks_fit {
            return Err(format!(
                "{} failed: observer coverage for {} is stale, gapped, or outside the action",
                case.id(),
                attestation.action
            ));
        }
    }
    Ok(())
}

fn observation_values_fit_schema(observation: &LiveLifecycleCaseObservation) -> bool {
    let auto_pair_fits = |pair: &LiveLifecycleFanAutoPair| {
        [pair.cpu.enable_readback, pair.gpu.enable_readback]
            .into_iter()
            .all(|value| value.is_none_or(|value| value <= 2))
    };
    match observation {
        LiveLifecycleCaseObservation::NormalStopRestart {
            auto_before_restart,
            ..
        }
        | LiveLifecycleCaseObservation::ProcessKillRecovery {
            auto_before_restart,
            ..
        }
        | LiveLifecycleCaseObservation::WatchdogRecovery {
            auto_before_restart,
            ..
        } => auto_pair_fits(auto_before_restart),
        LiveLifecycleCaseObservation::SuspendResume {
            auto_before_sleep, ..
        } => auto_pair_fits(auto_before_sleep),
        LiveLifecycleCaseObservation::Reboot {
            auto_before_arm,
            auto_after_arm,
            ..
        } => {
            auto_before_arm.as_ref().is_none_or(auto_pair_fits)
                && auto_after_arm.as_ref().is_none_or(auto_pair_fits)
        }
        _ => true,
    }
}

fn readback_pair_confirms_auto(
    pair: &[crate::FanReadbackEvidence],
    expected_identities: &(String, String),
    expected_boot_id: &str,
) -> bool {
    readback_pair_confirms_auto_unscoped(pair, expected_identities)
        && pair.iter().all(|readback| {
            readback.boot_id.as_deref() == Some(expected_boot_id)
                && readback.source_timestamp.is_some_and(|source| {
                    source.monotonic_millis <= readback.timestamp.monotonic_millis
                        && source.wall_unix_millis <= readback.timestamp.wall_unix_millis
                })
        })
}

fn readback_pair_confirms_auto_unscoped(
    pair: &[crate::FanReadbackEvidence],
    expected_identities: &(String, String),
) -> bool {
    matches!(pair, [cpu, gpu]
        if cpu.fan == EvidenceFan::Cpu
            && gpu.fan == EvidenceFan::Gpu
            && cpu.field == FanReadbackField::Enable
            && gpu.field == FanReadbackField::Enable
            && cpu.value == Some(2)
            && gpu.value == Some(2)
            && cpu.outcome == ObservationOutcome::Confirmed
            && gpu.outcome == ObservationOutcome::Confirmed
            && cpu.fresh == Some(true)
            && gpu.fresh == Some(true)
            && cpu.source_timestamp.is_some_and(|source|
                source.monotonic_millis <= cpu.timestamp.monotonic_millis
                    && source.wall_unix_millis <= cpu.timestamp.wall_unix_millis)
            && gpu.source_timestamp.is_some_and(|source|
                source.monotonic_millis <= gpu.timestamp.monotonic_millis
                    && source.wall_unix_millis <= gpu.timestamp.wall_unix_millis)
            && cpu.endpoint_identity == expected_identities.0
            && gpu.endpoint_identity == expected_identities.1)
}

fn readback_pair_is_ordered_attempt(pair: &[crate::FanReadbackEvidence]) -> bool {
    matches!(pair, [cpu, gpu]
        if cpu.fan == EvidenceFan::Cpu
            && gpu.fan == EvidenceFan::Gpu
            && cpu.field == FanReadbackField::Enable
            && gpu.field == FanReadbackField::Enable
            && cpu.source_timestamp.is_some()
            && gpu.source_timestamp.is_some()
            && cpu.timestamp.monotonic_millis < gpu.timestamp.monotonic_millis
            && cpu.timestamp.wall_unix_millis <= gpu.timestamp.wall_unix_millis)
}

fn readback_pair_sources_fit_gate_window(
    pair: &[crate::FanReadbackEvidence],
    not_before: EvidenceTimestamp,
    before: EvidenceTimestamp,
    strictly_after_start: bool,
) -> bool {
    let source_fits = |readback: &crate::FanReadbackEvidence| {
        readback.source_timestamp.is_some_and(|source| {
            (if strictly_after_start {
                source.monotonic_millis > not_before.monotonic_millis
            } else {
                source.monotonic_millis >= not_before.monotonic_millis
            }) && source.wall_unix_millis >= not_before.wall_unix_millis
                && source.monotonic_millis <= readback.timestamp.monotonic_millis
                && source.wall_unix_millis <= readback.timestamp.wall_unix_millis
                && readback.timestamp.monotonic_millis < before.monotonic_millis
                && readback.timestamp.wall_unix_millis <= before.wall_unix_millis
        })
    };
    matches!(pair, [cpu, gpu]
        if cpu.fan == EvidenceFan::Cpu
            && gpu.fan == EvidenceFan::Gpu
            && cpu.field == FanReadbackField::Enable
            && gpu.field == FanReadbackField::Enable
            && source_fits(cpu)
            && source_fits(gpu)
            && cpu.source_timestamp.is_some_and(|cpu_source|
                gpu.source_timestamp.is_some_and(|gpu_source|
                    cpu_source.monotonic_millis < gpu_source.monotonic_millis
                        && cpu_source.wall_unix_millis <= gpu_source.wall_unix_millis)))
}

pub(crate) fn live_lifecycle_is_complete(record: &EvidenceRecord) -> bool {
    if record.schema_version != EVIDENCE_SCHEMA_VERSION_V2
        || record.stage != "live-lifecycle"
        || record.workload.is_some()
        || !record.samples.is_empty()
        || !record.commands.is_empty()
        || !record.faults.is_empty()
        || !record.restoration_attempts.is_empty()
        || !record.calibration.is_empty()
        || record.thermal_summary.is_some()
        || record.live_lifecycle_cases.as_ref().is_none_or(|cases| {
            cases.len() != LiveLifecycleCase::ALL.len()
                || cases
                    .iter()
                    .zip(LiveLifecycleCase::ALL)
                    .any(|(result, case)| {
                        result.case != case || !result.passed || result.observation.is_none()
                    })
        })
        || record.readbacks.len() != 4 + LiveLifecycleCase::ALL.len() * 2
        || record.state_transitions.len() != LiveLifecycleCase::ALL.len() * 2
    {
        return false;
    }

    let identities = [EvidenceFan::Cpu, EvidenceFan::Gpu].map(|fan| {
        record
            .readbacks
            .iter()
            .find(|readback| readback.fan == fan)
            .map(|readback| readback.endpoint_identity.as_str())
    });
    let [Some(cpu_identity), Some(gpu_identity)] = identities else {
        return false;
    };
    let expected_identities = (cpu_identity.to_owned(), gpu_identity.to_owned());
    if !identity_has_nonblank_character(cpu_identity)
        || !identity_has_nonblank_character(gpu_identity)
        || cpu_identity == gpu_identity
    {
        return false;
    }

    let (boot_id_before, boot_id_after, reboot_auto_pair, terminal_auto_pair) = match record
        .live_lifecycle_cases
        .as_ref()
        .and_then(|cases| cases.last())
        .and_then(|result| result.observation.as_ref())
    {
        Some(LiveLifecycleCaseObservation::Reboot {
            boot_id_before,
            boot_id_after,
            auto_before_arm: Some(auto_before_arm),
            auto_after_arm: Some(auto_after_arm),
            ..
        }) => (
            boot_id_before.as_str(),
            boot_id_after.as_str(),
            auto_before_arm,
            auto_after_arm,
        ),
        _ => return false,
    };
    let pre_reboot_pairs = &record.readbacks[..record.readbacks.len() - 4];
    if pre_reboot_pairs
        .chunks_exact(2)
        .any(|pair| !readback_pair_confirms_auto(pair, &expected_identities, boot_id_before))
    {
        return false;
    }
    if validate_rebound_auto_pair(reboot_auto_pair, &expected_identities).is_err() {
        return false;
    }
    let post_reboot_identities = (
        reboot_auto_pair.cpu.endpoint_identity.clone(),
        reboot_auto_pair.gpu.endpoint_identity.clone(),
    );
    if !readback_pair_confirms_auto(
        &record.readbacks[record.readbacks.len() - 4..record.readbacks.len() - 2],
        &post_reboot_identities,
        boot_id_after,
    ) {
        return false;
    }
    let terminal_identities = (
        terminal_auto_pair.cpu.endpoint_identity.clone(),
        terminal_auto_pair.gpu.endpoint_identity.clone(),
    );
    if terminal_identities != post_reboot_identities
        || !readback_pair_confirms_auto(
            &record.readbacks[record.readbacks.len() - 2..],
            &terminal_identities,
            boot_id_after,
        )
    {
        return false;
    }
    let initial_gate_precedes_first_case = record.state_transitions.first().is_some_and(|first| {
        record.readbacks[0].timestamp.monotonic_millis < first.timestamp.monotonic_millis
            && record.readbacks[1].timestamp.monotonic_millis < first.timestamp.monotonic_millis
    });
    if !initial_gate_precedes_first_case {
        return false;
    }

    for (index, case) in LiveLifecycleCase::ALL.iter().enumerate() {
        let entered = &record.state_transitions[index * 2];
        let restored = &record.state_transitions[index * 2 + 1];
        let gate = &record.readbacks[(index + 1) * 2..(index + 2) * 2];
        let result = &record.live_lifecycle_cases.as_ref().expect("checked above")[index];
        let case_identities = if *case == LiveLifecycleCase::Reboot {
            &post_reboot_identities
        } else {
            &expected_identities
        };
        let clock_domains_and_order_are_valid = if *case == LiveLifecycleCase::Reboot {
            entered.boot_id.as_deref() == Some(boot_id_before)
                && restored.boot_id.as_deref() == Some(boot_id_after)
                && gate[0].timestamp.monotonic_millis < gate[1].timestamp.monotonic_millis
                && gate[1].timestamp.monotonic_millis < result.completed_at.monotonic_millis
                && result.completed_at.monotonic_millis < restored.timestamp.monotonic_millis
        } else {
            entered.boot_id.as_deref() == Some(boot_id_before)
                && restored.boot_id.as_deref() == Some(boot_id_before)
                && result.completed_at.monotonic_millis < gate[0].timestamp.monotonic_millis
                && gate[0].timestamp.monotonic_millis < gate[1].timestamp.monotonic_millis
                && gate[1].timestamp.monotonic_millis < restored.timestamp.monotonic_millis
                && record
                    .state_transitions
                    .get(index * 2 + 2)
                    .is_none_or(|next| {
                        restored.timestamp.monotonic_millis < next.timestamp.monotonic_millis
                    })
        };
        if !(entered.from == "firmware-auto"
            && entered.to == case.id()
            && restored.from == case.id()
            && restored.to == "firmware-auto"
            && clock_domains_and_order_are_valid
            && case_result_fits_transition_window(*case, result, entered, restored, record)
            && result.observation.as_ref().is_some_and(|observation| {
                validate_case_observation(
                    *case,
                    observation,
                    result.started_at,
                    result.completed_at,
                    if *case == LiveLifecycleCase::Reboot {
                        &expected_identities
                    } else {
                        case_identities
                    },
                )
                .is_ok()
            }))
        {
            return false;
        }
    }
    true
}
