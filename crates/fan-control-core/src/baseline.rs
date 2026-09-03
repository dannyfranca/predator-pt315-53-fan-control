use std::{error::Error, fmt, path::Path, time::Duration};

use crate::{
    AcerHwmonDevice, AcerHwmonDiscoveryError, BoundedIdentityBoundFileAccess, Clock,
    EvidenceExternalPower, EvidenceFan, EvidenceProfile, EvidenceRecord, EvidenceTimestamp,
    EvidenceValidationError, FanEndpointIdentitiesEvidence, FanReadbackEvidence, FanReadbackField,
    FanReadbackPhase, FaultEvidence, FirmwareAutoCleanupEvidence, IdentityBoundReadAccess,
    ObservationOutcome, PlatformError, QualificationEnvelopeIdentityV1, RunOutcomeEvidence,
    RunOutcomeStatus, SampleFreshness, TelemetrySampleEvidence, WorkloadEvidence,
    discover_acer_hwmon,
    evidence::{summarize_thermal_evidence, validate_identity, validate_workload},
    restoration::FIRMWARE_AUTO,
};

pub const CPU_ABSOLUTE_ABORT_MILLICELSIUS: i32 = 95_000;
pub const GPU_ABSOLUTE_ABORT_MILLICELSIUS: i32 = 85_000;
const SAMPLE_CADENCE_MILLIS: u64 = 2_000;
const SAMPLE_CADENCE_JITTER_MILLIS: u64 = 100;
const MIN_PLAUSIBLE_TEMPERATURE_MILLICELSIUS: i32 = -40_000;
const MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS: i32 = 150_000;
const MAX_PLAUSIBLE_AMBIENT_MILLICELSIUS: i32 = 80_000;
const MODE_CHECK_BUDGET: Duration = Duration::from_millis(100);
const WORKLOAD_START_TIMEOUT_MILLIS: u64 = 10_000;
pub(crate) const WORKLOAD_STOP_TIMEOUT_MILLIS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineObservation {
    pub sample: TelemetrySampleEvidence,
    pub system_stable: bool,
    pub kernel_faults: Vec<String>,
    pub nvidia_faults: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineStartingConditions {
    pub ambient_millicelsius: i32,
    pub cpu_millicelsius: i32,
    pub gpu_millicelsius: i32,
    pub power_profile: EvidenceProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedBaselineStartingConditions {
    pub conditions: BaselineStartingConditions,
    pub captured_at: EvidenceTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineCleanupAttestation {
    /// Every attempted write to either fan-control endpoint during cleanup.
    pub fan_control_write_count: u64,
}

pub trait FirmwareAutoBaselineEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp;

    fn capture_starting_conditions(&mut self)
    -> Result<CapturedBaselineStartingConditions, String>;

    /// Must return no later than `deadline_monotonic_millis`, including ambiguous launch failures.
    fn start_workload(
        &mut self,
        workload: &WorkloadEvidence,
        deadline_monotonic_millis: u64,
    ) -> Result<EvidenceTimestamp, String>;

    /// Waits for `target_monotonic_millis` and must return by the absolute deadline.
    fn wait_until(
        &mut self,
        target_monotonic_millis: u64,
        deadline_monotonic_millis: u64,
    ) -> Result<(), String>;

    /// Captures one fresh observation and must return by the absolute deadline.
    fn capture_observation(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<BaselineObservation, String>;

    /// Must confirm workload termination no later than the absolute deadline.
    fn stop_workload(&mut self, deadline_monotonic_millis: u64) -> Result<(), String>;

    fn contain_workload(&mut self, deadline_monotonic_millis: u64) -> Result<(), String> {
        self.stop_workload(deadline_monotonic_millis)
    }

    /// Must report every attempted fan-control write. Any nonzero count blocks acceptance.
    fn cleanup_after_workload(&mut self) -> Result<BaselineCleanupAttestation, String>;
}

pub trait FirmwareAutoBaselineAccess: IdentityBoundReadAccess + Clock {
    fn baseline_abi_is_current_before(
        &mut self,
        device: &AcerHwmonDevice,
        deadline: Duration,
    ) -> Result<bool, AcerHwmonDiscoveryError>;

    fn baseline_read_endpoint_before(
        &mut self,
        device: &AcerHwmonDevice,
        child: &str,
        expected_child: crate::FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError>;
}

impl<T> FirmwareAutoBaselineAccess for T
where
    T: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    fn baseline_abi_is_current_before(
        &mut self,
        device: &AcerHwmonDevice,
        deadline: Duration,
    ) -> Result<bool, AcerHwmonDiscoveryError> {
        device.abi_is_current_before(self, deadline)
    }

    fn baseline_read_endpoint_before(
        &mut self,
        device: &AcerHwmonDevice,
        child: &str,
        expected_child: crate::FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError> {
        self.read_bound_before(
            device.root(),
            device.backing_identity(),
            child,
            expected_child,
            deadline,
        )
    }
}

pub struct FirmwareAutoBaselinePlan<'a> {
    pub hwmon_root: &'a Path,
    pub qualification_envelope: QualificationEnvelopeIdentityV1,
    pub preflight_binding_sha256: String,
    pub nvidia_gpu_uuid: String,
    pub expected_fan_endpoint_identities: FanEndpointIdentitiesEvidence,
    pub workload: WorkloadEvidence,
    pub samples_required: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareAutoBaselinePlanError {
    InvalidQualificationEnvelope(EvidenceValidationError),
    InvalidPreflightBinding,
    InvalidHardwareIdentity,
}

impl fmt::Display for FirmwareAutoBaselinePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQualificationEnvelope(error) => {
                write!(formatter, "invalid qualification envelope: {error}")
            }
            Self::InvalidPreflightBinding => {
                formatter.write_str("invalid preflight evidence binding")
            }
            Self::InvalidHardwareIdentity => {
                formatter.write_str("invalid baseline hardware identity")
            }
        }
    }
}

impl Error for FirmwareAutoBaselinePlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidQualificationEnvelope(error) => Some(error),
            Self::InvalidPreflightBinding => None,
            Self::InvalidHardwareIdentity => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareAutoBaselineReport {
    record: EvidenceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareAutoBaselineResumeError(String);

impl fmt::Display for FirmwareAutoBaselineResumeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for FirmwareAutoBaselineResumeError {}

/// Accepts an immutable prior baseline only when its complete transcript matches this exact plan
/// and the currently discovered fan endpoint identities still read Firmware Auto.
pub fn validate_firmware_auto_baseline_resume<P>(
    platform: &mut P,
    record: &EvidenceRecord,
    plan: &FirmwareAutoBaselinePlan<'_>,
) -> Result<(), FirmwareAutoBaselineResumeError>
where
    P: FirmwareAutoBaselineAccess,
{
    record
        .validate()
        .map_err(|error| FirmwareAutoBaselineResumeError(format!("invalid evidence: {error}")))?;
    let workload = record
        .workload
        .as_ref()
        .ok_or_else(|| FirmwareAutoBaselineResumeError("workload evidence is missing".into()))?;
    if record.stage != "firmware-auto-baseline"
        || record.outcome.status != RunOutcomeStatus::Passed
        || record.outcome.another_passing_run_required
        || record.qualification_envelope != plan.qualification_envelope
        || record.preflight_binding_sha256.as_deref()
            != Some(plan.preflight_binding_sha256.as_str())
        || record.nvidia_gpu_uuid.as_deref() != Some(plan.nvidia_gpu_uuid.as_str())
        || record.fan_endpoint_identities.as_ref() != Some(&plan.expected_fan_endpoint_identities)
        || workload.workload_id != plan.workload.workload_id
        || workload.command != plan.workload.command
        || workload.version != plan.workload.version
        || workload.power_profile != plan.workload.power_profile
        || record.samples.len() != plan.samples_required
    {
        return Err(FirmwareAutoBaselineResumeError(
            "evidence is incomplete or belongs to a different baseline plan".into(),
        ));
    }
    let workload_started_at = record.workload_started_at.ok_or_else(|| {
        FirmwareAutoBaselineResumeError("workload start evidence is missing".into())
    })?;
    if record.samples.iter().enumerate().any(|(index, sample)| {
        workload_started_at
            .monotonic_millis
            .checked_add((index as u64 + 1).saturating_mul(SAMPLE_CADENCE_MILLIS))
            .is_none_or(|expected| {
                sample.timestamp.monotonic_millis.abs_diff(expected) > SAMPLE_CADENCE_JITTER_MILLIS
            })
    }) {
        return Err(FirmwareAutoBaselineResumeError(
            "evidence has a substituted telemetry cadence".into(),
        ));
    }

    let device = discover_acer_hwmon(platform, plan.hwmon_root)
        .map_err(|error| FirmwareAutoBaselineResumeError(error.to_string()))?;
    if !device_matches_expected_endpoints(&device, plan) {
        return Err(FirmwareAutoBaselineResumeError(
            "fan endpoint identity changed since preflight".into(),
        ));
    }
    let mut current = observe_firmware_auto(platform, Some(&device), FanReadbackPhase::Final);
    if let Some(error) = current.failure.take() {
        return Err(FirmwareAutoBaselineResumeError(error));
    }
    for fan in [EvidenceFan::Cpu, EvidenceFan::Gpu] {
        let previous = record
            .readbacks
            .iter()
            .rev()
            .find(|readback| {
                readback.fan == fan
                    && readback.field == FanReadbackField::Enable
                    && readback.phase == Some(FanReadbackPhase::Final)
            })
            .ok_or_else(|| {
                FirmwareAutoBaselineResumeError("final fan endpoint evidence is missing".into())
            })?;
        let now = current
            .readbacks
            .iter()
            .find(|readback| readback.fan == fan)
            .ok_or_else(|| {
                FirmwareAutoBaselineResumeError("current fan endpoint cannot be confirmed".into())
            })?;
        if previous.endpoint_identity != now.endpoint_identity
            || now.value != Some(2)
            || now.outcome != ObservationOutcome::Confirmed
        {
            return Err(FirmwareAutoBaselineResumeError(
                "fan endpoint identity changed or is no longer Firmware Auto".into(),
            ));
        }
    }
    Ok(())
}

impl FirmwareAutoBaselineReport {
    pub const fn record(&self) -> &EvidenceRecord {
        &self.record
    }

    pub const fn accepted(&self) -> bool {
        matches!(self.record.outcome.status, RunOutcomeStatus::Passed)
    }

    pub fn into_record(self) -> EvidenceRecord {
        self.record
    }
}

pub fn run_firmware_auto_baseline<P, E>(
    platform: &mut P,
    environment: &mut E,
    plan: &FirmwareAutoBaselinePlan<'_>,
) -> Result<FirmwareAutoBaselineReport, FirmwareAutoBaselinePlanError>
where
    P: FirmwareAutoBaselineAccess,
    E: FirmwareAutoBaselineEnvironment + ?Sized,
{
    validate_identity(&plan.qualification_envelope)
        .map_err(FirmwareAutoBaselinePlanError::InvalidQualificationEnvelope)?;
    if plan.preflight_binding_sha256.len() != 64
        || !plan
            .preflight_binding_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FirmwareAutoBaselinePlanError::InvalidPreflightBinding);
    }
    if !crate::nvidia_gpu::is_nvidia_gpu_uuid(&plan.nvidia_gpu_uuid)
        || !plan.expected_fan_endpoint_identities.is_valid()
    {
        return Err(FirmwareAutoBaselinePlanError::InvalidHardwareIdentity);
    }

    let started_at = environment.timestamp();
    let mut samples = Vec::with_capacity(plan.samples_required);
    let mut readbacks = Vec::new();
    let mut faults = Vec::new();
    let mut kernel_faults = Vec::new();
    let mut nvidia_faults = Vec::new();
    let mut system_stable = true;
    let mut workload = plan.workload.clone();
    let mut starting_conditions_valid = false;
    let mut starting_conditions_captured_at = None;
    let mut firmware_auto_cleanup = None;

    let device = discover_acer_hwmon(platform, plan.hwmon_root).ok();
    if device
        .as_ref()
        .is_some_and(|device| !device_matches_expected_endpoints(device, plan))
    {
        push_fault(
            &mut faults,
            started_at,
            "fan-endpoint-identity",
            "discovered fan endpoints do not match preflight evidence",
        );
    }
    let mut initial_modes =
        observe_firmware_auto(platform, device.as_ref(), FanReadbackPhase::Initial);
    let initial_modes_at = environment.timestamp();
    initial_modes.set_timestamp(initial_modes_at);
    readbacks.extend(initial_modes.readbacks);
    if let Some(detail) = initial_modes.failure {
        push_fault(
            &mut faults,
            initial_modes_at,
            "firmware-auto-unconfirmed",
            detail,
        );
    }

    if plan.samples_required < 2 {
        push_fault(
            &mut faults,
            started_at,
            "invalid-baseline-plan",
            "at least two telemetry samples are required to calculate thermal slope",
        );
    }

    if faults.is_empty() {
        let result = environment.capture_starting_conditions();
        let callback_completed_at = environment.timestamp();
        match result {
            Ok(capture)
                if capture.captured_at.monotonic_millis < initial_modes_at.monotonic_millis
                    || capture.captured_at.monotonic_millis
                        > callback_completed_at.monotonic_millis
                    || capture.captured_at.wall_unix_millis < initial_modes_at.wall_unix_millis
                    || capture.captured_at.wall_unix_millis
                        > callback_completed_at.wall_unix_millis =>
            {
                push_fault(
                    &mut faults,
                    callback_completed_at,
                    "starting-conditions",
                    "starting-condition source timestamp lies outside its confirmed Firmware Auto capture window",
                );
            }
            Ok(capture) => {
                starting_conditions_captured_at = Some(capture.captured_at);
                let conditions = capture.conditions;
                if conditions.power_profile == workload.power_profile
                    && plausible_temperature(
                        conditions.ambient_millicelsius,
                        MAX_PLAUSIBLE_AMBIENT_MILLICELSIUS,
                    )
                    && plausible_temperature(
                        conditions.cpu_millicelsius,
                        MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
                    )
                    && plausible_temperature(
                        conditions.gpu_millicelsius,
                        MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
                    )
                    && conditions.cpu_millicelsius < CPU_ABSOLUTE_ABORT_MILLICELSIUS
                    && conditions.gpu_millicelsius < GPU_ABSOLUTE_ABORT_MILLICELSIUS
                {
                    workload.ambient_millicelsius = conditions.ambient_millicelsius;
                    workload.starting_cpu_millicelsius = conditions.cpu_millicelsius;
                    workload.starting_gpu_millicelsius = conditions.gpu_millicelsius;
                    starting_conditions_valid = true;
                } else {
                    push_fault(
                        &mut faults,
                        capture.captured_at,
                        "starting-conditions",
                        "measured temperatures are implausible, at an abort limit, or the power profile does not match",
                    );
                }
            }
            Err(error) => push_fault(
                &mut faults,
                callback_completed_at,
                "starting-conditions",
                format!("cannot capture starting conditions: {error}"),
            ),
        }
    }
    let workload_is_valid = starting_conditions_valid
        && match validate_workload(&workload) {
            Ok(()) => true,
            Err(error) => {
                if faults.is_empty() {
                    push_fault(
                        &mut faults,
                        started_at,
                        "invalid-baseline-plan",
                        error.to_string(),
                    );
                }
                false
            }
        };

    let mut start_gate_confirmed_at = None;
    if faults.is_empty() {
        let mut modes =
            observe_firmware_auto(platform, device.as_ref(), FanReadbackPhase::StartGate);
        let timestamp = environment.timestamp();
        modes.set_timestamp(timestamp);
        readbacks.extend(modes.readbacks);
        if let Some(detail) = modes.failure {
            push_fault(&mut faults, timestamp, "firmware-auto-unconfirmed", detail);
        } else {
            start_gate_confirmed_at = Some(timestamp);
        }
    }

    let mut workload_attempted = false;
    let mut workload_started_at = None;
    if faults.is_empty() {
        workload_attempted = true;
        let start_requested_at = environment.timestamp();
        let start_deadline = start_requested_at
            .monotonic_millis
            .saturating_add(WORKLOAD_START_TIMEOUT_MILLIS);
        let start_result = environment.start_workload(&workload, start_deadline);
        let timestamp = environment.timestamp();
        if timestamp.monotonic_millis > start_deadline {
            push_fault(
                &mut faults,
                timestamp,
                "workload-start",
                "fixed workload launch exceeded its deadline",
            );
        }
        match start_result {
            Err(error) => push_fault(
                &mut faults,
                timestamp,
                "workload-start",
                format!("cannot start fixed workload: {error}"),
            ),
            Ok(source_started_at)
                if source_started_at.monotonic_millis < start_requested_at.monotonic_millis
                    || source_started_at.monotonic_millis > timestamp.monotonic_millis
                    || source_started_at.wall_unix_millis < start_requested_at.wall_unix_millis
                    || source_started_at.wall_unix_millis > timestamp.wall_unix_millis
                    || start_gate_confirmed_at.is_some_and(|confirmed_at| {
                        source_started_at.monotonic_millis < confirmed_at.monotonic_millis
                            || source_started_at.wall_unix_millis < confirmed_at.wall_unix_millis
                    }) =>
            {
                push_fault(
                    &mut faults,
                    timestamp,
                    "workload-start",
                    "workload source timestamp lies outside its confirmed launch window",
                );
            }
            Ok(source_started_at) if faults.is_empty() => {
                workload_started_at = Some(source_started_at);
                let mut modes = observe_firmware_auto(
                    platform,
                    device.as_ref(),
                    FanReadbackPhase::WorkloadStarted,
                );
                let mode_timestamp = environment.timestamp();
                modes.set_timestamp(mode_timestamp);
                readbacks.extend(modes.readbacks);
                if let Some(detail) = modes.failure {
                    push_fault(&mut faults, mode_timestamp, "firmware-auto-lost", detail);
                }
            }
            Ok(_) => {}
        }
    }

    while faults.is_empty() && samples.len() < plan.samples_required {
        let sample_number = samples.len() as u64 + 1;
        let expected_millis = workload_started_at
            .expect("sampling only begins after successful workload start")
            .monotonic_millis
            .checked_add(sample_number.saturating_mul(SAMPLE_CADENCE_MILLIS));
        let Some(expected_millis) = expected_millis else {
            push_fault(
                &mut faults,
                started_at,
                "sample-cadence",
                "telemetry schedule overflowed",
            );
            break;
        };
        let Some(sample_deadline) = expected_millis.checked_add(SAMPLE_CADENCE_JITTER_MILLIS)
        else {
            push_fault(
                &mut faults,
                started_at,
                "sample-cadence",
                "telemetry deadline overflowed",
            );
            break;
        };
        let before_wait = environment.timestamp();
        if before_wait.monotonic_millis > sample_deadline {
            push_fault(
                &mut faults,
                before_wait,
                "sample-cadence",
                "workload launch acknowledgement missed the telemetry deadline",
            );
            break;
        }
        if let Err(error) = environment.wait_until(expected_millis, sample_deadline) {
            push_fault(
                &mut faults,
                environment.timestamp(),
                "sample-cadence",
                format!("cannot wait for the next telemetry sample: {error}"),
            );
            break;
        }
        let wait_returned_at = environment.timestamp();
        if wait_returned_at.monotonic_millis > sample_deadline {
            push_fault(
                &mut faults,
                wait_returned_at,
                "sample-cadence",
                "telemetry wait exceeded its deadline",
            );
            break;
        }
        let mut observation = match environment.capture_observation(sample_deadline) {
            Ok(observation) => observation,
            Err(error) => {
                let timestamp = environment.timestamp();
                push_fault(
                    &mut faults,
                    timestamp,
                    "invalid-telemetry",
                    format!("cannot capture required telemetry: {error}"),
                );
                break;
            }
        };
        let captured_at = environment.timestamp();
        if captured_at.monotonic_millis > sample_deadline {
            push_fault(
                &mut faults,
                captured_at,
                "sample-cadence",
                "telemetry capture exceeded its deadline",
            );
        }
        let source_timestamp = observation.sample.timestamp;
        if source_timestamp.monotonic_millis < started_at.monotonic_millis
            || source_timestamp.monotonic_millis > captured_at.monotonic_millis
            || source_timestamp.wall_unix_millis < started_at.wall_unix_millis
            || source_timestamp.wall_unix_millis > captured_at.wall_unix_millis
        {
            push_fault(
                &mut faults,
                captured_at,
                "invalid-telemetry",
                format!(
                    "telemetry source timestamp {} lies outside the active run through {}",
                    source_timestamp.monotonic_millis, captured_at.monotonic_millis
                ),
            );
            observation.sample.timestamp = captured_at;
            observation.sample.freshness = SampleFreshness::Invalid;
        }
        let timestamp = observation.sample.timestamp;
        validate_observation(&mut observation, &workload, expected_millis, &mut faults);
        kernel_faults.extend(observation.kernel_faults.iter().cloned());
        nvidia_faults.extend(observation.nvidia_faults.iter().cloned());
        for detail in &observation.kernel_faults {
            push_fault(
                &mut faults,
                timestamp,
                "kernel-instability",
                nonempty_instability_detail(detail, "kernel fault reported"),
            );
        }
        for detail in &observation.nvidia_faults {
            push_fault(
                &mut faults,
                timestamp,
                "nvidia-instability",
                nonempty_instability_detail(detail, "NVIDIA fault reported"),
            );
        }
        system_stable &= observation.system_stable;
        samples.push(observation.sample);
        if faults.is_empty() {
            let readback_deadline = platform.monotonic_now().checked_add(MODE_CHECK_BUDGET);
            let mut modes = observe_firmware_auto_before(
                platform,
                device.as_ref(),
                FanReadbackPhase::Sample,
                readback_deadline,
            );
            let mode_timestamp = environment.timestamp();
            modes.set_timestamp(mode_timestamp);
            readbacks.extend(modes.readbacks);
            if let Some(detail) = modes.failure {
                push_fault(&mut faults, mode_timestamp, "firmware-auto-lost", detail);
            } else {
                let mut rpms = observe_firmware_rpm(
                    platform,
                    device.as_ref(),
                    FanReadbackPhase::Sample,
                    readback_deadline,
                );
                let rpm_timestamp = environment.timestamp();
                rpms.set_timestamp(rpm_timestamp);
                readbacks.extend(rpms.readbacks);
                if let Some(detail) = rpms.failure {
                    push_fault(&mut faults, rpm_timestamp, "tachometer", detail);
                }
            }
        }
    }

    if workload_attempted {
        let stop_requested_at = environment.timestamp();
        let stop_deadline = stop_requested_at
            .monotonic_millis
            .saturating_add(WORKLOAD_STOP_TIMEOUT_MILLIS);
        let mut cleanup_evidence = FirmwareAutoCleanupEvidence {
            workload_stop_requested_at: stop_requested_at,
            workload_stop_confirmed_at: None,
            containment_required: false,
            containment_confirmed: false,
            containment_confirmed_at: None,
            cleanup_completed_at: None,
            fan_control_write_count: None,
        };
        match environment.stop_workload(stop_deadline) {
            Ok(()) => {
                let stopped_at = environment.timestamp();
                cleanup_evidence.workload_stop_confirmed_at = Some(stopped_at);
                let mut safe_to_cleanup = true;
                if stopped_at.monotonic_millis > stop_deadline {
                    cleanup_evidence.containment_required = true;
                    push_fault(
                        &mut faults,
                        stopped_at,
                        "workload-stop",
                        "workload termination exceeded its deadline",
                    );
                    let containment_deadline = stopped_at
                        .monotonic_millis
                        .saturating_add(WORKLOAD_STOP_TIMEOUT_MILLIS);
                    if let Err(error) = environment.contain_workload(containment_deadline) {
                        safe_to_cleanup = false;
                        push_fault(
                            &mut faults,
                            environment.timestamp(),
                            "workload-containment",
                            format!("cannot contain workload after late stop: {error}"),
                        );
                    } else {
                        let contained_at = environment.timestamp();
                        if contained_at.monotonic_millis > containment_deadline {
                            safe_to_cleanup = false;
                            push_fault(
                                &mut faults,
                                contained_at,
                                "workload-containment",
                                "workload containment exceeded its deadline",
                            );
                        } else {
                            cleanup_evidence.containment_confirmed = true;
                            cleanup_evidence.containment_confirmed_at = Some(contained_at);
                        }
                    }
                }
                match safe_to_cleanup.then(|| environment.cleanup_after_workload()) {
                    None => {}
                    Some(result) => match result {
                        Ok(attestation) => {
                            cleanup_evidence.fan_control_write_count =
                                Some(attestation.fan_control_write_count);
                            cleanup_evidence.cleanup_completed_at = Some(environment.timestamp());
                            if attestation.fan_control_write_count > 0 {
                                push_fault(
                                    &mut faults,
                                    environment.timestamp(),
                                    "cleanup-fan-control-write",
                                    format!(
                                        "post-workload cleanup attempted {} fan-control writes",
                                        attestation.fan_control_write_count
                                    ),
                                );
                            }
                        }
                        Err(error) => {
                            let cleanup_failed_at = environment.timestamp();
                            push_fault(
                                &mut faults,
                                cleanup_failed_at,
                                "cleanup",
                                format!("post-workload cleanup failed: {error}"),
                            );
                        }
                    },
                }
            }
            Err(error) => {
                let stopped_at = environment.timestamp();
                cleanup_evidence.containment_required = true;
                push_fault(
                    &mut faults,
                    stopped_at,
                    "workload-stop",
                    format!("cannot confirm fixed workload stopped: {error}"),
                );
                let containment_deadline = stopped_at
                    .monotonic_millis
                    .saturating_add(WORKLOAD_STOP_TIMEOUT_MILLIS);
                match environment.contain_workload(containment_deadline) {
                    Ok(()) => {
                        let contained_at = environment.timestamp();
                        if contained_at.monotonic_millis > containment_deadline {
                            push_fault(
                                &mut faults,
                                contained_at,
                                "workload-containment",
                                "workload containment exceeded its deadline",
                            );
                        } else {
                            cleanup_evidence.containment_confirmed = true;
                            cleanup_evidence.containment_confirmed_at = Some(contained_at);
                            match environment.cleanup_after_workload() {
                                Ok(attestation) => {
                                    cleanup_evidence.fan_control_write_count =
                                        Some(attestation.fan_control_write_count);
                                    cleanup_evidence.cleanup_completed_at =
                                        Some(environment.timestamp());
                                    if attestation.fan_control_write_count > 0 {
                                        push_fault(
                                            &mut faults,
                                            environment.timestamp(),
                                            "cleanup-fan-control-write",
                                            format!(
                                                "post-containment cleanup attempted {} fan-control writes",
                                                attestation.fan_control_write_count
                                            ),
                                        );
                                    }
                                }
                                Err(error) => push_fault(
                                    &mut faults,
                                    environment.timestamp(),
                                    "cleanup",
                                    format!("post-containment cleanup failed: {error}"),
                                ),
                            }
                        }
                    }
                    Err(containment_error) => push_fault(
                        &mut faults,
                        environment.timestamp(),
                        "workload-containment",
                        format!(
                            "cannot contain fixed workload after stop failure: {containment_error}"
                        ),
                    ),
                }
            }
        }
        firmware_auto_cleanup = Some(cleanup_evidence);
    }

    let mut final_modes = observe_firmware_auto(platform, device.as_ref(), FanReadbackPhase::Final);
    let completed_at = environment.timestamp();
    final_modes.set_timestamp(completed_at);
    let final_firmware_auto_confirmed = final_modes.failure.is_none();
    readbacks.extend(final_modes.readbacks);
    if let Some(detail) = final_modes.failure {
        push_fault(
            &mut faults,
            completed_at,
            "firmware-auto-unconfirmed",
            detail,
        );
    }

    let thermal_summary = summarize_thermal_evidence(
        &samples,
        system_stable,
        kernel_faults
            .into_iter()
            .map(|detail| nonempty_instability_detail(&detail, "kernel fault reported"))
            .collect(),
        nvidia_faults
            .into_iter()
            .map(|detail| nonempty_instability_detail(&detail, "NVIDIA fault reported"))
            .collect(),
    );
    let accepted = faults.is_empty() && samples.len() == plan.samples_required;
    let reason = if accepted {
        "Firmware Auto baseline accepted".to_owned()
    } else {
        faults
            .first()
            .map(|fault| fault.detail.clone())
            .unwrap_or_else(|| "Firmware Auto baseline incomplete".to_owned())
    };
    let mut record = EvidenceRecord::complete_v2(
        plan.qualification_envelope.clone(),
        "firmware-auto-baseline",
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
            final_firmware_auto_confirmed,
        },
    );
    record.starting_conditions_captured_at = starting_conditions_captured_at;
    record.workload_started_at = workload_started_at;
    record.preflight_binding_sha256 = Some(plan.preflight_binding_sha256.clone());
    record.nvidia_gpu_uuid = Some(plan.nvidia_gpu_uuid.clone());
    record.fan_endpoint_identities = Some(plan.expected_fan_endpoint_identities.clone());
    record.firmware_auto_cleanup = firmware_auto_cleanup;
    record.workload = workload_is_valid.then_some(workload);
    record.samples = samples;
    record.readbacks = readbacks;
    record.faults = faults;
    record.thermal_summary = Some(thermal_summary);
    if accepted {
        if let Err(error) = record.validate() {
            push_fault(
                &mut record.faults,
                completed_at,
                "invalid-evidence",
                error.to_string(),
            );
            record.outcome.status = RunOutcomeStatus::Failed;
            record.outcome.reason = "generated baseline evidence is invalid".to_owned();
            record.outcome.another_passing_run_required = true;
        }
    }
    Ok(FirmwareAutoBaselineReport { record })
}

fn validate_observation(
    observation: &mut BaselineObservation,
    workload: &WorkloadEvidence,
    expected_millis: u64,
    faults: &mut Vec<FaultEvidence>,
) {
    let sample = &mut observation.sample;
    let timestamp = sample.timestamp;
    let telemetry_complete = sample.freshness == SampleFreshness::Fresh
        && sample.cpu_millicelsius.is_some()
        && sample.gpu_millicelsius.is_some()
        && sample.external_power.is_some()
        && sample.selected_profile.is_some()
        && sample.cpu_source_demand_basis_points.is_some()
        && sample.gpu_source_demand_basis_points.is_some()
        && sample.cpu_utilization_basis_points.is_some()
        && sample.gpu_utilization_basis_points.is_some()
        && sample.commanded_demand_basis_points.is_some()
        && sample.cpu_thermal_throttling.is_some()
        && sample.gpu_thermal_throttling.is_some();
    let temperature_out_of_range = [sample.cpu_millicelsius, sample.gpu_millicelsius]
        .into_iter()
        .flatten()
        .any(|value| {
            !plausible_temperature(value, MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS)
        });
    let demand_out_of_range = [
        &mut sample.cpu_source_demand_basis_points,
        &mut sample.gpu_source_demand_basis_points,
        &mut sample.commanded_demand_basis_points,
        &mut sample.cpu_utilization_basis_points,
        &mut sample.gpu_utilization_basis_points,
    ]
    .into_iter()
    .fold(false, |invalid, demand| {
        if demand.is_some_and(|value| value > 10_000) {
            *demand = None;
            true
        } else {
            invalid
        }
    });
    if !telemetry_complete || temperature_out_of_range || demand_out_of_range {
        sample.freshness = SampleFreshness::Invalid;
        push_fault(
            faults,
            timestamp,
            "invalid-telemetry",
            "required telemetry is missing, stale, or invalid",
        );
    }
    if timestamp.monotonic_millis.abs_diff(expected_millis) > SAMPLE_CADENCE_JITTER_MILLIS {
        push_fault(
            faults,
            timestamp,
            "sample-cadence",
            "telemetry did not arrive on the runner-owned two-second schedule",
        );
    }
    if telemetry_complete
        && (sample.external_power != Some(profile_power(workload.power_profile))
            || sample.selected_profile != Some(workload.power_profile))
    {
        push_fault(
            faults,
            timestamp,
            "starting-conditions",
            "observed power/profile does not match the fixed workload",
        );
    }
    if sample.cpu_thermal_throttling == Some(true) || sample.gpu_thermal_throttling == Some(true) {
        push_fault(
            faults,
            timestamp,
            "thermal-throttling",
            "CPU or GPU thermal throttling was observed",
        );
    }
    if sample
        .cpu_millicelsius
        .is_some_and(|value| value >= CPU_ABSOLUTE_ABORT_MILLICELSIUS)
        || sample
            .gpu_millicelsius
            .is_some_and(|value| value >= GPU_ABSOLUTE_ABORT_MILLICELSIUS)
    {
        push_fault(
            faults,
            timestamp,
            "absolute-thermal-abort",
            "CPU reached 95 C or GPU reached 85 C",
        );
    }
    if !observation.system_stable {
        push_fault(
            faults,
            timestamp,
            "system-instability",
            "system stability check failed",
        );
    }
}

fn profile_power(profile: EvidenceProfile) -> EvidenceExternalPower {
    match profile {
        EvidenceProfile::Ac => EvidenceExternalPower::Ac,
        EvidenceProfile::Battery => EvidenceExternalPower::Battery,
    }
}

fn plausible_temperature(value: i32, maximum: i32) -> bool {
    (MIN_PLAUSIBLE_TEMPERATURE_MILLICELSIUS..=maximum).contains(&value)
}

fn nonempty_instability_detail(detail: &str, fallback: &str) -> String {
    if detail.is_empty() {
        fallback.to_owned()
    } else {
        detail.to_owned()
    }
}

struct ModeObservation {
    readbacks: Vec<FanReadbackEvidence>,
    failure: Option<String>,
}

impl ModeObservation {
    fn set_timestamp(&mut self, timestamp: EvidenceTimestamp) {
        for readback in &mut self.readbacks {
            readback.timestamp = timestamp;
        }
    }
}

fn endpoint_evidence_identity(device: &AcerHwmonDevice, endpoint: &Path) -> String {
    FanEndpointIdentitiesEvidence::endpoint_identity(device, endpoint)
        .unwrap_or_else(|| "unbound-endpoint".to_owned())
}

fn device_matches_expected_endpoints(
    device: &AcerHwmonDevice,
    plan: &FirmwareAutoBaselinePlan<'_>,
) -> bool {
    FanEndpointIdentitiesEvidence::from_device(device).as_ref()
        == Some(&plan.expected_fan_endpoint_identities)
}

fn observe_firmware_auto(
    platform: &mut impl FirmwareAutoBaselineAccess,
    device: Option<&AcerHwmonDevice>,
    phase: FanReadbackPhase,
) -> ModeObservation {
    let deadline = platform.monotonic_now().checked_add(MODE_CHECK_BUDGET);
    observe_firmware_auto_before(platform, device, phase, deadline)
}

fn observe_firmware_auto_before(
    platform: &mut impl FirmwareAutoBaselineAccess,
    device: Option<&AcerHwmonDevice>,
    phase: FanReadbackPhase,
    deadline: Option<Duration>,
) -> ModeObservation {
    let unstamped = EvidenceTimestamp {
        monotonic_millis: 0,
        wall_unix_millis: 0,
    };
    let Some(device) = device else {
        return ModeObservation {
            readbacks: Vec::new(),
            failure: Some("Acer hwmon device was not safely discovered".to_owned()),
        };
    };
    let Some(deadline) = deadline else {
        return ModeObservation {
            readbacks: Vec::new(),
            failure: Some("Firmware Auto mode-check deadline overflowed".to_owned()),
        };
    };
    match platform.baseline_abi_is_current_before(device, deadline) {
        Ok(true) => {}
        Ok(false) => {
            return ModeObservation {
                readbacks: Vec::new(),
                failure: Some(
                    "Acer hwmon identity changed during fan-mode confirmation".to_owned(),
                ),
            };
        }
        Err(error) => {
            return ModeObservation {
                readbacks: Vec::new(),
                failure: Some(error.to_string()),
            };
        }
    }
    let mut readbacks = Vec::with_capacity(2);
    let mut observed = Vec::with_capacity(2);
    for (fan, child, endpoint) in [
        (EvidenceFan::Cpu, "pwm1_enable", device.cpu().enable()),
        (EvidenceFan::Gpu, "pwm2_enable", device.gpu().enable()),
    ] {
        let fan_name = match fan {
            EvidenceFan::Cpu => "CPU",
            EvidenceFan::Gpu => "GPU",
        };
        let endpoint_identity = endpoint_evidence_identity(device, endpoint);
        let expected_endpoint = device
            .endpoint_identity(endpoint)
            .expect("discovery binds every fan endpoint");
        match platform.baseline_read_endpoint_before(device, child, expected_endpoint, deadline) {
            Ok(payload) => match payload.trim().parse::<u32>() {
                Ok(value @ 0..=2) => {
                    let outcome = if value.to_string() == FIRMWARE_AUTO {
                        ObservationOutcome::Confirmed
                    } else {
                        ObservationOutcome::Unexpected
                    };
                    observed.push(format!("{fan_name}={value}"));
                    readbacks.push(FanReadbackEvidence {
                        timestamp: unstamped,
                        source_timestamp: None,
                        fresh: None,
                        boot_id: None,
                        fan,
                        field: FanReadbackField::Enable,
                        value: Some(value),
                        endpoint_identity,
                        outcome,
                        phase: Some(phase),
                    });
                }
                Ok(_) | Err(_) => {
                    observed.push(format!("{fan_name}=invalid"));
                    readbacks.push(FanReadbackEvidence {
                        timestamp: unstamped,
                        source_timestamp: None,
                        fresh: None,
                        boot_id: None,
                        fan,
                        field: FanReadbackField::Enable,
                        value: None,
                        endpoint_identity,
                        outcome: ObservationOutcome::Unreadable,
                        phase: Some(phase),
                    });
                }
            },
            Err(error) => {
                observed.push(format!("{fan_name}=unreadable ({error})"));
                readbacks.push(FanReadbackEvidence {
                    timestamp: unstamped,
                    source_timestamp: None,
                    fresh: None,
                    boot_id: None,
                    fan,
                    field: FanReadbackField::Enable,
                    value: None,
                    endpoint_identity,
                    outcome: ObservationOutcome::Unreadable,
                    phase: Some(phase),
                });
            }
        }
    }
    let identity_changed = !matches!(
        platform.baseline_abi_is_current_before(device, deadline),
        Ok(true)
    );
    let all_auto = readbacks.iter().all(|readback| {
        readback.value == Some(2) && readback.outcome == ObservationOutcome::Confirmed
    });
    let failure = if identity_changed {
        Some("Acer hwmon identity changed during fan-mode confirmation".to_owned())
    } else if !all_auto {
        Some(format!(
            "both fans must remain Firmware Auto (2); observed {}",
            observed.join(" ")
        ))
    } else {
        None
    };
    ModeObservation { readbacks, failure }
}

fn observe_firmware_rpm(
    platform: &mut impl FirmwareAutoBaselineAccess,
    device: Option<&AcerHwmonDevice>,
    phase: FanReadbackPhase,
    deadline: Option<Duration>,
) -> ModeObservation {
    let unstamped = EvidenceTimestamp {
        monotonic_millis: 0,
        wall_unix_millis: 0,
    };
    let Some(device) = device else {
        return ModeObservation {
            readbacks: Vec::new(),
            failure: Some("Acer hwmon device was not safely discovered".to_owned()),
        };
    };
    let Some(deadline) = deadline else {
        return ModeObservation {
            readbacks: Vec::new(),
            failure: Some("tachometer read deadline overflowed".to_owned()),
        };
    };
    if !matches!(
        platform.baseline_abi_is_current_before(device, deadline),
        Ok(true)
    ) {
        return ModeObservation {
            readbacks: Vec::new(),
            failure: Some("Acer hwmon identity changed during tachometer capture".to_owned()),
        };
    }
    let mut readbacks = Vec::with_capacity(2);
    let mut failure = None;
    for (fan, child, endpoint) in [
        (EvidenceFan::Cpu, "fan1_input", device.cpu().tachometer()),
        (EvidenceFan::Gpu, "fan2_input", device.gpu().tachometer()),
    ] {
        let endpoint_identity = endpoint_evidence_identity(device, endpoint);
        let expected_endpoint = device
            .endpoint_identity(endpoint)
            .expect("discovery binds every fan endpoint");
        let value = platform
            .baseline_read_endpoint_before(device, child, expected_endpoint, deadline)
            .ok()
            .and_then(|payload| payload.trim().parse::<u32>().ok())
            .filter(|rpm| {
                (crate::tachometer::MINIMUM_PLAUSIBLE_RPM
                    ..=crate::tachometer::MAXIMUM_PLAUSIBLE_RPM)
                    .contains(rpm)
            });
        let outcome = if value.is_some() {
            ObservationOutcome::Confirmed
        } else {
            failure.get_or_insert_with(|| {
                format!(
                    "{} fan tachometer is unreadable or implausible",
                    match fan {
                        EvidenceFan::Cpu => "CPU",
                        EvidenceFan::Gpu => "GPU",
                    }
                )
            });
            ObservationOutcome::Unreadable
        };
        readbacks.push(FanReadbackEvidence {
            timestamp: unstamped,
            source_timestamp: None,
            fresh: None,
            boot_id: None,
            fan,
            field: FanReadbackField::Rpm,
            value,
            endpoint_identity,
            outcome,
            phase: Some(phase),
        });
    }
    if !matches!(
        platform.baseline_abi_is_current_before(device, deadline),
        Ok(true)
    ) {
        failure = Some("Acer hwmon identity changed during tachometer capture".to_owned());
    }
    ModeObservation { readbacks, failure }
}

fn push_fault(
    faults: &mut Vec<FaultEvidence>,
    timestamp: EvidenceTimestamp,
    code: impl Into<String>,
    detail: impl Into<String>,
) {
    faults.push(FaultEvidence {
        timestamp,
        boot_id: None,
        code: code.into(),
        detail: detail.into(),
    });
}
