use std::{error::Error, fmt};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    EVIDENCE_SCHEMA_VERSION_V2, EvidenceExternalPower, EvidenceFan, EvidenceProfile,
    EvidenceRecord, EvidenceRecordStatus, EvidenceTimestamp, EvidenceValidationError,
    FanReadbackEvidence, FanReadbackField, FaultEvidence, ObservationOutcome,
    QualificationEnvelopeIdentityV1, RunOutcomeEvidence, RunOutcomeStatus, StateTransitionEvidence,
    evidence::validate_identity,
};

pub const LIVE_RESTART_DELAY_MILLIS: u64 = 2_000;
pub const LIVE_START_LIMIT_BURST: u32 = 2;
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
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveLifecycleRebootContinuation {
    pub reboot_completed: bool,
    pub boot_id_before: String,
    pub boot_id_after: String,
    pub post_boot_at: EvidenceTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveLifecycleRebootArmObservation {
    pub armed_at: EvidenceTimestamp,
    pub controller_process_identity: String,
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

    /// Performs exactly the guided, non-destructive non-reboot case requested by the
    /// runner and returns a newly collected observation.
    ///
    /// A persisted outer coordinator must resume the reboot case after boot and provide
    /// distinct pre-boot and post-boot IDs. This core stage never initiates a reboot.
    fn run_case(&mut self, case: LiveLifecycleCase)
    -> Result<LiveLifecycleCaseObservation, String>;

    /// Resumes the persisted reboot case without arming Custom control.
    fn resume_after_reboot(&mut self) -> Result<LiveLifecycleRebootContinuation, String>;

    /// Arms the post-boot controller only after the runner independently confirms Auto.
    fn arm_after_reboot(&mut self) -> Result<LiveLifecycleRebootArmObservation, String>;

    /// Reads one fan's enable endpoint. The runner always calls this once for each fan.
    fn confirm_firmware_auto(
        &mut self,
        fan: EvidenceFan,
    ) -> Result<LiveLifecycleFanAutoObservation, String>;
}

#[derive(Debug)]
pub enum LiveLifecyclePlanError {
    InvalidEnvelope(EvidenceValidationError),
    InvalidGeneratedEvidence(EvidenceValidationError),
}

impl fmt::Display for LiveLifecyclePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope(error) => {
                write!(formatter, "invalid qualification envelope: {error}")
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

/// Validates the full approved live sequence through the supplied environment.
///
/// Any failed case or Auto gate prevents later cases. Production command orchestration,
/// reboot resumption, and root-owned evidence publication belong to the final qualification
/// coordinator; this core stage defines and validates its live-lifecycle evidence contract.
pub fn run_live_lifecycle_qualification<E>(
    environment: &mut E,
    envelope: &QualificationEnvelopeIdentityV1,
) -> Result<LiveLifecycleReport, LiveLifecyclePlanError>
where
    E: LiveLifecycleEnvironment + ?Sized,
{
    validate_identity(envelope).map_err(LiveLifecyclePlanError::InvalidEnvelope)?;

    let started_at = environment.timestamp();
    let mut last_event_at = started_at;
    let mut readbacks = Vec::new();
    let mut transitions = Vec::new();
    let mut faults = Vec::new();
    let mut cases = Vec::new();

    let initial_gate = confirm_auto_gate(
        environment,
        started_at,
        None,
        None,
        &mut readbacks,
        &mut faults,
    );
    last_event_at = later_timestamp(last_event_at, initial_gate.completed_at);
    let mut expected_identities = initial_gate.identities;
    let mut final_auto_confirmed = initial_gate.confirmed;

    if initial_gate.confirmed {
        for case in LiveLifecycleCase::ALL {
            let requested_at = strictly_after_timestamp(environment.timestamp(), last_event_at);
            transitions.push(StateTransitionEvidence {
                timestamp: requested_at,
                boot_id: None,
                from: "firmware-auto".into(),
                to: case.id().into(),
            });

            let case_started_at = strictly_after_timestamp(environment.timestamp(), requested_at);
            let observation_result = if case == LiveLifecycleCase::Reboot {
                environment.resume_after_reboot().map(|continuation| {
                    LiveLifecycleCaseObservation::Reboot {
                        reboot_completed: continuation.reboot_completed,
                        boot_id_before: continuation.boot_id_before,
                        boot_id_after: continuation.boot_id_after,
                        post_boot_at: continuation.post_boot_at,
                        auto_before_arm: None,
                        armed_at: None,
                        controller_process_identity: None,
                    }
                })
            } else {
                environment.run_case(case)
            };
            let observed_completed_at = environment.timestamp();
            let mut case_completed_at = observed_completed_at;
            let completed_at = if case == LiveLifecycleCase::Reboot {
                case_completed_at
            } else {
                strictly_after_timestamp(case_completed_at, requested_at)
            };
            let (mut observation, mut observation_error) = match observation_result {
                Ok(observation) => {
                    let validation = if case == LiveLifecycleCase::Reboot {
                        validate_reboot_continuation(
                            &observation,
                            case_started_at,
                            case_completed_at,
                        )
                    } else {
                        validate_case_observation(
                            case,
                            &observation,
                            case_started_at,
                            case_completed_at,
                            expected_identities
                                .as_ref()
                                .expect("the initial gate established identities"),
                        )
                    };
                    (Some(observation), validation.err())
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

            let mut gate_boot_id = None;
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
                for readback in &mut readbacks {
                    readback
                        .boot_id
                        .get_or_insert_with(|| pre_boot_id.to_owned());
                }
                for transition in &mut transitions {
                    transition
                        .boot_id
                        .get_or_insert_with(|| pre_boot_id.to_owned());
                }
                gate_boot_id = Some(post_boot_id.to_owned());
            }

            let gate = confirm_auto_gate(
                environment,
                completed_at,
                if case == LiveLifecycleCase::Reboot {
                    None
                } else {
                    expected_identities.as_ref()
                },
                gate_boot_id.as_deref(),
                &mut readbacks,
                &mut faults,
            );
            if case == LiveLifecycleCase::Reboot && observation_error.is_none() && gate.confirmed {
                let gate_pair = gate
                    .auto_pair
                    .clone()
                    .expect("a confirmed gate retains both observations");
                if let Some(rebound) = rebound_identities(&gate_pair, expected_identities.as_ref())
                {
                    match environment.arm_after_reboot() {
                        Ok(arm) => {
                            let arm_completed_at = environment.timestamp();
                            let arm_is_ordered = arm.armed_at.monotonic_millis
                                > gate.completed_at.monotonic_millis
                                && arm.armed_at.monotonic_millis
                                    <= arm_completed_at.monotonic_millis
                                && !arm.controller_process_identity.trim().is_empty();
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
                                expected_identities = Some(rebound);
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
            if let Some(detail) = &observation_error {
                faults.push(FaultEvidence {
                    timestamp: gate.completed_at,
                    boot_id: gate_boot_id.clone(),
                    code: "live-lifecycle-case-failed".into(),
                    detail: detail.clone(),
                });
            }
            let restored_at = if gate_boot_id.is_some() {
                environment.timestamp()
            } else {
                strictly_after_timestamp(environment.timestamp(), gate.completed_at)
            };
            last_event_at = if gate_boot_id.is_some() {
                strictly_after_timestamp(restored_at, last_event_at)
            } else {
                later_timestamp(
                    last_event_at,
                    later_timestamp(restored_at, gate.completed_at),
                )
            };
            final_auto_confirmed = gate.confirmed;
            if gate.confirmed {
                expected_identities = gate.identities;
            }
            transitions.push(StateTransitionEvidence {
                timestamp: restored_at,
                boot_id: gate_boot_id,
                from: case.id().into(),
                to: if gate.confirmed {
                    "firmware-auto".into()
                } else {
                    "lifecycle-blocked".into()
                },
            });

            let passed = observation_error.is_none() && gate.confirmed;
            let detail = observation_error.unwrap_or_else(|| {
                if gate.confirmed {
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
                passed,
                detail,
            });
            if !passed {
                break;
            }
        }
    }

    let completed_at = normalize_timestamp(environment.timestamp(), last_event_at);
    let accepted = cases.len() == LiveLifecycleCase::ALL.len()
        && cases.iter().all(LiveLifecycleCaseResult::passed)
        && final_auto_confirmed
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
    let record = EvidenceRecord {
        schema_version: EVIDENCE_SCHEMA_VERSION_V2,
        record_status: EvidenceRecordStatus::Complete,
        qualification_envelope: envelope.clone(),
        stage: "live-lifecycle".into(),
        started_at,
        completed_at,
        starting_conditions_captured_at: None,
        workload_started_at: None,
        baseline_binding_sha256: None,
        workload: None,
        samples: Vec::new(),
        commands: Vec::new(),
        readbacks,
        state_transitions: transitions,
        faults,
        restoration_attempts: Vec::new(),
        calibration: Vec::new(),
        thermal_summary: None,
        live_lifecycle_cases: Some(cases.clone()),
        outcome: RunOutcomeEvidence {
            status: if accepted {
                RunOutcomeStatus::Passed
            } else {
                RunOutcomeStatus::Failed
            },
            reason,
            another_passing_run_required: !accepted,
            final_firmware_auto_confirmed: final_auto_confirmed,
        },
    };
    record
        .validate()
        .map_err(LiveLifecyclePlanError::InvalidGeneratedEvidence)?;
    let report = LiveLifecycleReport { record };
    report
        .validate()
        .map_err(LiveLifecyclePlanError::InvalidGeneratedEvidence)?;
    Ok(report)
}

struct AutoGate {
    completed_at: EvidenceTimestamp,
    identities: Option<(String, String)>,
    auto_pair: Option<LiveLifecycleFanAutoPair>,
    confirmed: bool,
}

fn confirm_auto_gate<E>(
    environment: &mut E,
    not_before: EvidenceTimestamp,
    expected_identities: Option<&(String, String)>,
    boot_id: Option<&str>,
    readbacks: &mut Vec<FanReadbackEvidence>,
    faults: &mut Vec<FaultEvidence>,
) -> AutoGate
where
    E: LiveLifecycleEnvironment + ?Sized,
{
    let cpu = confirm_one_fan(
        environment,
        EvidenceFan::Cpu,
        not_before,
        expected_identities.map(|identities| identities.0.as_str()),
        boot_id,
        readbacks,
        faults,
    );
    let gpu_not_before = if boot_id.is_some() {
        cpu.completed_at
    } else {
        later_timestamp(not_before, cpu.completed_at)
    };
    let gpu = confirm_one_fan(
        environment,
        EvidenceFan::Gpu,
        gpu_not_before,
        expected_identities.map(|identities| identities.1.as_str()),
        boot_id,
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
        if cpu_identity.is_empty() || gpu_identity.is_empty() || cpu_identity == gpu_identity {
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
    boot_id: Option<&str>,
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
            let identity_valid = !observation.endpoint_identity.is_empty();
            let completed_at = if boot_id.is_some() {
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
                boot_id: boot_id.map(ToOwned::to_owned),
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
                    boot_id: boot_id.map(ToOwned::to_owned),
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
            let completed_at = if boot_id.is_some() {
                raw_completed_at
            } else {
                strictly_after_timestamp(raw_completed_at, not_before)
            };
            readbacks.push(FanReadbackEvidence {
                timestamp: completed_at,
                source_timestamp: Some(raw_completed_at),
                fresh: Some(false),
                boot_id: boot_id.map(ToOwned::to_owned),
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
                boot_id: boot_id.map(ToOwned::to_owned),
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
        } if reboot_boot_ids_are_valid(boot_id_before, boot_id_after)
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
        || proof.process_identity_before.trim().is_empty()
        || proof.process_identity_after.trim().is_empty()
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
            && !original_process_identity.trim().is_empty()
            && !rejected_process_identity.trim().is_empty()
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
        ) if !process_identity_before.trim().is_empty()
            && !process_identity_after.trim().is_empty()
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
            && !process_identity_before.is_empty()
            && !process_identity_after.is_empty()
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
            && armed_at.wall_unix_millis <= completed_at.wall_unix_millis =>
        {
            if controller_process_identity.trim().is_empty() {
                return Err("reboot failed: armed controller process identity is empty".into());
            }
            validate_rebound_auto_pair(auto_before_arm, expected_identities).map_err(|_| {
                "reboot failed: both fans must confirm Firmware Auto after boot and before arming"
                    .to_owned()
            })
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
    let identities_are_unambiguous = !pair.cpu.endpoint_identity.is_empty()
        && !pair.gpu.endpoint_identity.is_empty()
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
    if record.state_transitions.len() != cases.len() * 2
        || record.readbacks.len() != 2 + cases.len() * 2
    {
        return false;
    }

    let mut expected_identities = record.readbacks.get(..2).and_then(|pair| match pair {
        [cpu, gpu]
            if cpu.fan == EvidenceFan::Cpu
                && gpu.fan == EvidenceFan::Gpu
                && cpu.endpoint_identity != gpu.endpoint_identity =>
        {
            Some((cpu.endpoint_identity.clone(), gpu.endpoint_identity.clone()))
        }
        _ => None,
    });
    let initial_gate = &record.readbacks[..2];
    let Some(first_entered) = record.state_transitions.first() else {
        return cases.is_empty()
            && readback_pair_sources_fit_gate_window(
                initial_gate,
                record.started_at,
                record.completed_at,
                false,
            );
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
    true
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
            auto_before_arm, ..
        } => auto_before_arm.as_ref().is_none_or(auto_pair_fits),
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
        || record.readbacks.len() != 2 + LiveLifecycleCase::ALL.len() * 2
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
    if cpu_identity == gpu_identity {
        return false;
    }

    let (boot_id_before, boot_id_after, reboot_auto_pair) = match record
        .live_lifecycle_cases
        .as_ref()
        .and_then(|cases| cases.last())
        .and_then(|result| result.observation.as_ref())
    {
        Some(LiveLifecycleCaseObservation::Reboot {
            boot_id_before,
            boot_id_after,
            auto_before_arm: Some(auto_before_arm),
            ..
        }) => (
            boot_id_before.as_str(),
            boot_id_after.as_str(),
            auto_before_arm,
        ),
        _ => return false,
    };
    let pre_reboot_pairs = &record.readbacks[..record.readbacks.len() - 2];
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
        &record.readbacks[record.readbacks.len() - 2..],
        &post_reboot_identities,
        boot_id_after,
    ) {
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
