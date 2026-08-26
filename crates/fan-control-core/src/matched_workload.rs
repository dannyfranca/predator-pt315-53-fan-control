use std::{collections::HashSet, error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::{
    CPU_ABSOLUTE_ABORT_MILLICELSIUS, EVIDENCE_SCHEMA_VERSION_V2, EvidenceExternalPower,
    EvidenceFan, EvidenceProfile, EvidenceRecord, EvidenceRecordStatus, EvidenceTimestamp,
    EvidenceValidationError, Fan, FanCalibrationEvidence, FanCommandEvidence, FanControlField,
    FanReadbackEvidence, FanReadbackField, FaultEvidence, GPU_ABSOLUTE_ABORT_MILLICELSIUS,
    ObservationOutcome, RestorationAttemptEvidence, RestorationOutcome, RunOutcomeEvidence,
    RunOutcomeStatus, SampleFreshness, StateTransitionEvidence, TelemetrySampleEvidence,
    WorkloadEvidence,
    evidence::{precise_final_thermal_slopes, summarize_thermal_evidence},
    tachometer::{expected_rpm_from_evidence, rpm_in_band},
};

pub const AMBIENT_COMPARABILITY_MILLICELSIUS: i32 = 2_000;
pub const STARTING_TEMPERATURE_COMPARABILITY_MILLICELSIUS: i32 = 3_000;
pub const THERMAL_COMPARISON_MARGIN_MILLICELSIUS: i32 = 2_000;
pub const THERMAL_SLOPE_LIMIT_MILLICELSIUS_PER_MINUTE: i32 = 1_000;
pub const MINIMUM_MATCHED_WORKLOAD_SAMPLES: usize = 151;

const SAMPLE_CADENCE_MILLIS: u64 = 2_000;
const SAMPLE_CADENCE_JITTER_MILLIS: u64 = 100;
const CUSTOM_HANDOVER_TIMEOUT_MILLIS: u64 = 5_000;
const WORKLOAD_START_TIMEOUT_MILLIS: u64 = 10_000;
const WORKLOAD_STOP_TIMEOUT_MILLIS: u64 = 5_000;
const FAN_RESTORATION_TIMEOUT_MILLIS: u64 = 5_000;
const MIN_PLAUSIBLE_TEMPERATURE_MILLICELSIUS: i32 = -40_000;
const MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS: i32 = 150_000;
const MAX_PLAUSIBLE_AMBIENT_MILLICELSIUS: i32 = 80_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedWorkloadClass {
    Idle,
    Cpu,
    Gpu,
    Combined,
}

impl MatchedWorkloadClass {
    const fn required_passing_runs(self) -> u8 {
        match self {
            Self::Idle => 1,
            Self::Cpu | Self::Gpu | Self::Combined => 2,
        }
    }

    fn from_workload_id(workload_id: &str) -> Option<Self> {
        match workload_id.split('-').next() {
            Some("idle") => Some(Self::Idle),
            Some("cpu") => Some(Self::Cpu),
            Some("gpu") => Some(Self::Gpu),
            Some("combined") => Some(Self::Combined),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchedWorkloadStartingConditions {
    pub ambient_millicelsius: i32,
    pub cpu_millicelsius: i32,
    pub gpu_millicelsius: i32,
    pub power_profile: EvidenceProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedMatchedWorkloadStartingConditions {
    pub conditions: MatchedWorkloadStartingConditions,
    pub captured_at: EvidenceTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedWorkloadObservation {
    pub sample: TelemetrySampleEvidence,
    pub commands: Vec<FanCommandEvidence>,
    pub readbacks: Vec<FanReadbackEvidence>,
    pub controller_fault: Option<String>,
    pub system_stable: bool,
    pub kernel_faults: Vec<String>,
    pub nvidia_faults: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedWorkloadFanRestoration {
    pub auto_write_succeeded: bool,
    pub enable_readback: Option<u32>,
    pub endpoint_identity: String,
    pub outcome: RestorationOutcome,
}

pub trait MatchedWorkloadEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp;

    fn capture_starting_conditions(
        &mut self,
    ) -> Result<CapturedMatchedWorkloadStartingConditions, String>;

    /// Enters the already-admitted Custom-control path. An error is treated as an ambiguous
    /// partial handover and therefore still triggers restoration of both fans.
    /// Must confirm both fans entered Custom control by the absolute deadline.
    fn enter_custom_control(&mut self, deadline_monotonic_millis: u64) -> Result<(), String>;

    /// Must return no later than `deadline_monotonic_millis`, including ambiguous launch errors.
    fn start_workload(
        &mut self,
        workload: &WorkloadEvidence,
        deadline_monotonic_millis: u64,
    ) -> Result<EvidenceTimestamp, String>;

    fn wait_until(
        &mut self,
        target_monotonic_millis: u64,
        deadline_monotonic_millis: u64,
    ) -> Result<(), String>;

    fn capture_observation(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<MatchedWorkloadObservation, String>;

    /// Must confirm workload termination by the absolute deadline.
    fn stop_workload(&mut self, deadline_monotonic_millis: u64) -> Result<(), String>;

    /// Restores exactly one fan by the absolute deadline. The runner calls this once for each fan
    /// even if the first fails or completes late.
    fn restore_fan(
        &mut self,
        fan: EvidenceFan,
        deadline_monotonic_millis: u64,
    ) -> MatchedWorkloadFanRestoration;
}

pub struct MatchedWorkloadPlan<'a> {
    pub baseline: &'a EvidenceRecord,
    pub previous_passing_runs: &'a [&'a EvidenceRecord],
    pub tachometer_calibrations: MatchedWorkloadTachometerCalibrations<'a>,
}

#[derive(Debug, Clone, Copy)]
pub struct MatchedWorkloadTachometerCalibrations<'a> {
    pub cpu: &'a FanCalibrationEvidence,
    pub gpu: &'a FanCalibrationEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchedWorkloadPlanError {
    InvalidBaseline(EvidenceValidationError),
    InvalidPriorRun { index: usize, reason: String },
    BaselineNotAccepted,
    InvalidCalibration { fan: EvidenceFan },
    UnknownWorkloadClass,
    InvalidGeneratedEvidence(EvidenceValidationError),
}

impl fmt::Display for MatchedWorkloadPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseline(error) => write!(formatter, "invalid baseline: {error}"),
            Self::InvalidPriorRun { index, reason } => {
                write!(formatter, "invalid previous passing run {index}: {reason}")
            }
            Self::BaselineNotAccepted => {
                formatter.write_str("baseline must be an accepted Firmware Auto baseline")
            }
            Self::InvalidCalibration { fan } => {
                write!(formatter, "{fan:?} tachometer calibration is not qualified")
            }
            Self::UnknownWorkloadClass => formatter
                .write_str("baseline workload id must begin with idle-, cpu-, gpu-, or combined-"),
            Self::InvalidGeneratedEvidence(error) => {
                write!(
                    formatter,
                    "generated matched-workload evidence is invalid: {error}"
                )
            }
        }
    }
}

impl Error for MatchedWorkloadPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBaseline(error) => Some(error),
            Self::InvalidGeneratedEvidence(error) => Some(error),
            Self::InvalidPriorRun { .. }
            | Self::BaselineNotAccepted
            | Self::InvalidCalibration { .. }
            | Self::UnknownWorkloadClass => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedWorkloadReport {
    record: EvidenceRecord,
}

impl MatchedWorkloadReport {
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

pub fn run_matched_custom_workload<E>(
    environment: &mut E,
    plan: &MatchedWorkloadPlan<'_>,
) -> Result<MatchedWorkloadReport, MatchedWorkloadPlanError>
where
    E: MatchedWorkloadEnvironment + ?Sized,
{
    validate_plan(plan)?;
    let baseline_workload = plan
        .baseline
        .workload
        .as_ref()
        .expect("validated baseline has a workload");
    let baseline_summary = plan
        .baseline
        .thermal_summary
        .as_ref()
        .expect("validated baseline has a thermal summary");
    let workload_class = MatchedWorkloadClass::from_workload_id(&baseline_workload.workload_id)
        .expect("validated plan has a recognized workload class");
    let started_at = environment.timestamp();
    let mut workload = baseline_workload.clone();
    let mut starting_conditions_captured_at = None;
    let mut workload_started_at = None;
    let samples_required = plan.baseline.samples.len();
    let mut samples = Vec::with_capacity(samples_required);
    let mut commands = Vec::new();
    let mut readbacks = Vec::new();
    let mut state_transitions = Vec::new();
    let mut faults = Vec::new();
    let mut restoration_attempts = Vec::new();
    let mut kernel_faults = Vec::new();
    let mut nvidia_faults = Vec::new();
    let mut system_stable = true;
    let mut custom_attempted = false;
    let mut workload_attempted = false;
    let mut control_evidence = ControlEvidenceState::default();
    let mut tachometer_evidence = TachometerEvidenceState::default();
    let mut restoration_not_before = started_at;

    match environment.capture_starting_conditions() {
        Ok(capture) => {
            let callback_completed_at = environment.timestamp();
            if capture.captured_at.monotonic_millis < started_at.monotonic_millis
                || capture.captured_at.monotonic_millis > callback_completed_at.monotonic_millis
            {
                push_fault(
                    &mut faults,
                    callback_completed_at,
                    "starting-conditions",
                    "starting-condition timestamp lies outside its capture window",
                );
            } else {
                starting_conditions_captured_at = Some(capture.captured_at);
                workload.ambient_millicelsius = capture.conditions.ambient_millicelsius;
                workload.starting_cpu_millicelsius = capture.conditions.cpu_millicelsius;
                workload.starting_gpu_millicelsius = capture.conditions.gpu_millicelsius;
                let safe_start = plausible_temperature(
                    capture.conditions.ambient_millicelsius,
                    MAX_PLAUSIBLE_AMBIENT_MILLICELSIUS,
                ) && plausible_temperature(
                    capture.conditions.cpu_millicelsius,
                    MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
                ) && plausible_temperature(
                    capture.conditions.gpu_millicelsius,
                    MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
                ) && capture.conditions.cpu_millicelsius
                    < CPU_ABSOLUTE_ABORT_MILLICELSIUS
                    && capture.conditions.gpu_millicelsius < GPU_ABSOLUTE_ABORT_MILLICELSIUS;
                if !safe_start {
                    push_fault(
                        &mut faults,
                        capture.captured_at,
                        "starting-conditions",
                        "measured temperatures are implausible or at an absolute abort limit",
                    );
                } else if capture.conditions.power_profile != baseline_workload.power_profile
                    || capture
                        .conditions
                        .ambient_millicelsius
                        .abs_diff(baseline_workload.ambient_millicelsius)
                        > AMBIENT_COMPARABILITY_MILLICELSIUS as u32
                    || capture
                        .conditions
                        .cpu_millicelsius
                        .abs_diff(baseline_workload.starting_cpu_millicelsius)
                        > STARTING_TEMPERATURE_COMPARABILITY_MILLICELSIUS as u32
                    || capture
                        .conditions
                        .gpu_millicelsius
                        .abs_diff(baseline_workload.starting_gpu_millicelsius)
                        > STARTING_TEMPERATURE_COMPARABILITY_MILLICELSIUS as u32
                {
                    push_fault(
                        &mut faults,
                        capture.captured_at,
                        "starting-conditions-not-comparable",
                        "ambient must be within 2 C and starting CPU/GPU within 3 C of baseline",
                    );
                }
            }
        }
        Err(error) => push_fault(
            &mut faults,
            environment.timestamp(),
            "starting-conditions",
            format!("cannot capture starting conditions: {error}"),
        ),
    }

    if faults.is_empty() {
        custom_attempted = true;
        let requested_at = environment.timestamp();
        if let Some(deadline) = checked_deadline(
            requested_at.monotonic_millis,
            CUSTOM_HANDOVER_TIMEOUT_MILLIS,
            requested_at,
            "custom-control-entry",
            &mut faults,
        ) {
            let result = environment.enter_custom_control(deadline);
            let completed_at = environment.timestamp();
            if completed_at.monotonic_millis < requested_at.monotonic_millis {
                push_fault(
                    &mut faults,
                    requested_at,
                    "custom-control-entry",
                    "Custom control handover completion time regressed",
                );
            } else if completed_at.monotonic_millis > deadline {
                push_fault(
                    &mut faults,
                    completed_at,
                    "custom-control-entry",
                    "Custom control handover exceeded its deadline",
                );
            }
            restoration_not_before =
                if completed_at.monotonic_millis < requested_at.monotonic_millis {
                    requested_at
                } else {
                    completed_at
                };
            match result {
                Ok(()) if faults.is_empty() => state_transitions.push(StateTransitionEvidence {
                    timestamp: completed_at,
                    from: "firmware-auto".into(),
                    to: "custom-control".into(),
                }),
                Ok(()) => {}
                Err(error) => push_fault(
                    &mut faults,
                    completed_at,
                    "custom-control-entry",
                    format!("cannot confirm Custom control handover: {error}"),
                ),
            }
        }
    }

    if faults.is_empty() {
        let requested_at = environment.timestamp();
        if let Some(deadline) = checked_deadline(
            requested_at.monotonic_millis,
            WORKLOAD_START_TIMEOUT_MILLIS,
            requested_at,
            "workload-start",
            &mut faults,
        ) {
            workload_attempted = true;
            let result = environment.start_workload(&workload, deadline);
            let completed_at = environment.timestamp();
            if completed_at.monotonic_millis >= requested_at.monotonic_millis {
                restoration_not_before = completed_at;
            }
            if completed_at.monotonic_millis > deadline {
                push_fault(
                    &mut faults,
                    completed_at,
                    "workload-start",
                    "fixed workload launch exceeded its deadline",
                );
            }
            match result {
                Ok(source_at)
                    if source_at.monotonic_millis >= requested_at.monotonic_millis
                        && source_at.monotonic_millis <= completed_at.monotonic_millis
                        && faults.is_empty() =>
                {
                    workload_started_at = Some(source_at);
                }
                Ok(_) => {
                    if faults.is_empty() {
                        push_fault(
                            &mut faults,
                            completed_at,
                            "workload-start",
                            "workload timestamp lies outside its launch window",
                        );
                    }
                }
                Err(error) => push_fault(
                    &mut faults,
                    completed_at,
                    "workload-start",
                    format!("cannot start fixed workload: {error}"),
                ),
            }
        }
    }

    while faults.is_empty() && samples.len() < samples_required {
        let sample_number = samples.len() as u64 + 1;
        let Some(offset) = sample_number.checked_mul(SAMPLE_CADENCE_MILLIS) else {
            push_fault(
                &mut faults,
                environment.timestamp(),
                "sample-cadence",
                "telemetry schedule overflowed",
            );
            break;
        };
        let Some(expected_millis) = workload_started_at
            .expect("sampling follows a confirmed workload start")
            .monotonic_millis
            .checked_add(offset)
        else {
            push_fault(
                &mut faults,
                environment.timestamp(),
                "sample-cadence",
                "telemetry schedule overflowed",
            );
            break;
        };
        let Some(deadline) = expected_millis.checked_add(SAMPLE_CADENCE_JITTER_MILLIS) else {
            push_fault(
                &mut faults,
                environment.timestamp(),
                "sample-cadence",
                "telemetry deadline overflowed",
            );
            break;
        };
        if environment.timestamp().monotonic_millis > deadline {
            push_fault(
                &mut faults,
                environment.timestamp(),
                "sample-cadence",
                "telemetry deadline elapsed before the wait began",
            );
            break;
        }
        if let Err(error) = environment.wait_until(expected_millis, deadline) {
            push_fault(
                &mut faults,
                environment.timestamp(),
                "sample-cadence",
                format!("cannot wait for telemetry: {error}"),
            );
            break;
        }
        if environment.timestamp().monotonic_millis > deadline {
            push_fault(
                &mut faults,
                environment.timestamp(),
                "sample-cadence",
                "telemetry wait exceeded its deadline",
            );
            break;
        }
        let mut observation = match environment.capture_observation(deadline) {
            Ok(observation) => observation,
            Err(error) => {
                push_fault(
                    &mut faults,
                    environment.timestamp(),
                    "invalid-telemetry",
                    format!("cannot capture required telemetry: {error}"),
                );
                break;
            }
        };
        let captured_at = environment.timestamp();
        if captured_at.monotonic_millis >= restoration_not_before.monotonic_millis {
            restoration_not_before = captured_at;
        }
        if captured_at.monotonic_millis > deadline {
            push_fault(
                &mut faults,
                captured_at,
                "sample-cadence",
                "telemetry capture exceeded its deadline",
            );
        }
        validate_observation(
            &mut observation,
            &workload,
            started_at,
            captured_at,
            expected_millis,
            &mut control_evidence,
            plan.tachometer_calibrations,
            &mut tachometer_evidence,
            &mut faults,
        );
        system_stable &= observation.system_stable;
        kernel_faults.extend(observation.kernel_faults.iter().cloned());
        nvidia_faults.extend(observation.nvidia_faults.iter().cloned());
        commands.extend(observation.commands);
        readbacks.extend(observation.readbacks);
        samples.push(observation.sample);
    }

    if workload_attempted {
        let stop_requested_at = environment.timestamp();
        let stop_request_boundary =
            if stop_requested_at.monotonic_millis < restoration_not_before.monotonic_millis {
                push_fault(
                    &mut faults,
                    restoration_not_before,
                    "workload-stop",
                    "workload termination request time regressed",
                );
                restoration_not_before
            } else {
                stop_requested_at
            };
        let deadline = stop_request_boundary
            .monotonic_millis
            .checked_add(WORKLOAD_STOP_TIMEOUT_MILLIS)
            .unwrap_or_else(|| {
                push_fault(
                    &mut faults,
                    stop_request_boundary,
                    "workload-stop",
                    "workload termination deadline overflowed",
                );
                u64::MAX
            });
        let result = environment.stop_workload(deadline);
        let stopped_at = environment.timestamp();
        let stop_event_at = if stopped_at.monotonic_millis < stop_request_boundary.monotonic_millis
        {
            push_fault(
                &mut faults,
                stop_request_boundary,
                "workload-stop",
                "workload termination completion time regressed",
            );
            stop_request_boundary
        } else {
            stopped_at
        };
        restoration_not_before = stop_event_at;
        if let Err(error) = result {
            push_fault(
                &mut faults,
                stop_event_at,
                "workload-stop",
                format!("cannot confirm fixed workload stopped: {error}"),
            );
        } else if stopped_at.monotonic_millis > deadline {
            push_fault(
                &mut faults,
                stopped_at,
                "workload-stop",
                "workload termination exceeded its deadline",
            );
        }
    }

    let mut both_fans_restored = false;
    if custom_attempted {
        both_fans_restored = true;
        for fan in [EvidenceFan::Cpu, EvidenceFan::Gpu] {
            let requested_at = environment.timestamp();
            let request_boundary =
                if requested_at.monotonic_millis < restoration_not_before.monotonic_millis {
                    push_fault(
                        &mut faults,
                        restoration_not_before,
                        "firmware-auto-restoration",
                        "restoration request time regressed",
                    );
                    restoration_not_before
                } else {
                    requested_at
                };
            let deadline = request_boundary
                .monotonic_millis
                .checked_add(FAN_RESTORATION_TIMEOUT_MILLIS)
                .unwrap_or_else(|| {
                    push_fault(
                        &mut faults,
                        request_boundary,
                        "firmware-auto-restoration",
                        "restoration deadline overflowed",
                    );
                    u64::MAX
                });
            let restoration = environment.restore_fan(fan, deadline);
            let completed_at = environment.timestamp();
            let timing_confirmed = completed_at.monotonic_millis
                >= request_boundary.monotonic_millis
                && completed_at.monotonic_millis <= deadline;
            let timestamp = if completed_at.monotonic_millis < request_boundary.monotonic_millis {
                push_fault(
                    &mut faults,
                    request_boundary,
                    "firmware-auto-restoration",
                    format!("{fan:?} restoration completion time regressed"),
                );
                request_boundary
            } else {
                if completed_at.monotonic_millis > deadline {
                    push_fault(
                        &mut faults,
                        completed_at,
                        "firmware-auto-restoration",
                        format!("{fan:?} restoration exceeded its deadline"),
                    );
                }
                completed_at
            };
            restoration_not_before = timestamp;
            let expected_identity =
                control_evidence.endpoint_identity(fan, FanReadbackField::Enable);
            let identity_matches =
                expected_identity == Some(restoration.endpoint_identity.as_str());
            both_fans_restored &= restoration.outcome == RestorationOutcome::FirmwareAutoConfirmed
                && restoration.enable_readback == Some(2)
                && identity_matches
                && timing_confirmed;
            restoration_attempts.push(RestorationAttemptEvidence {
                timestamp,
                fan,
                auto_write_succeeded: restoration.auto_write_succeeded,
                enable_readback: restoration.enable_readback,
                outcome: restoration.outcome,
            });
            readbacks.push(FanReadbackEvidence {
                timestamp,
                fan,
                field: FanReadbackField::Enable,
                value: restoration.enable_readback,
                endpoint_identity: restoration.endpoint_identity,
                outcome: if restoration.enable_readback == Some(2)
                    && identity_matches
                    && timing_confirmed
                {
                    ObservationOutcome::Confirmed
                } else if restoration.enable_readback.is_some() {
                    ObservationOutcome::Unexpected
                } else {
                    ObservationOutcome::Unreadable
                },
                phase: Some(crate::FanReadbackPhase::Final),
            });
        }
        let observed_transition_at = environment.timestamp();
        let transition_at =
            if observed_transition_at.monotonic_millis < restoration_not_before.monotonic_millis {
                push_fault(
                    &mut faults,
                    restoration_not_before,
                    "firmware-auto-restoration",
                    "final restoration transition time regressed",
                );
                restoration_not_before
            } else {
                observed_transition_at
            };
        state_transitions.push(StateTransitionEvidence {
            timestamp: transition_at,
            from: "custom-control".into(),
            to: if both_fans_restored {
                "firmware-auto".into()
            } else {
                "restoration-failed".into()
            },
        });
        if !both_fans_restored {
            push_fault(
                &mut faults,
                transition_at,
                "firmware-auto-unconfirmed",
                "both fans were not confirmed in Firmware Auto",
            );
        }
    }

    let thermal_summary =
        summarize_thermal_evidence(&samples, system_stable, kernel_faults, nvidia_faults);
    if faults.is_empty() {
        compare_thermal_summaries(
            baseline_summary,
            &thermal_summary,
            &samples,
            &mut faults,
            environment,
        );
    }

    let observed_completed_at = environment.timestamp();
    let completed_at =
        if observed_completed_at.monotonic_millis < restoration_not_before.monotonic_millis {
            push_fault(
                &mut faults,
                restoration_not_before,
                "matched-workload-completion",
                "run completion time regressed",
            );
            restoration_not_before
        } else {
            observed_completed_at
        };
    let accepted = faults.is_empty() && samples.len() == samples_required && both_fans_restored;
    let another_passing_run_required = !accepted
        || plan.previous_passing_runs.len().saturating_add(1)
            < usize::from(workload_class.required_passing_runs());
    let reason = if accepted {
        "Custom workload accepted against its Firmware Auto baseline".to_owned()
    } else {
        faults
            .first()
            .map(|fault| fault.detail.clone())
            .unwrap_or_else(|| "Custom workload incomplete".to_owned())
    };
    let record = EvidenceRecord {
        schema_version: EVIDENCE_SCHEMA_VERSION_V2,
        record_status: EvidenceRecordStatus::Complete,
        qualification_envelope: plan.baseline.qualification_envelope.clone(),
        stage: "matched-workload".into(),
        started_at,
        completed_at,
        starting_conditions_captured_at,
        workload_started_at,
        baseline_binding_sha256: Some(baseline_fingerprint(plan.baseline)),
        workload: Some(workload),
        samples,
        commands,
        readbacks,
        state_transitions,
        faults,
        restoration_attempts,
        calibration: vec![],
        thermal_summary: Some(thermal_summary),
        outcome: RunOutcomeEvidence {
            status: if accepted {
                RunOutcomeStatus::Passed
            } else {
                RunOutcomeStatus::Failed
            },
            reason,
            another_passing_run_required,
            final_firmware_auto_confirmed: both_fans_restored,
        },
    };
    record
        .validate()
        .map_err(MatchedWorkloadPlanError::InvalidGeneratedEvidence)?;
    Ok(MatchedWorkloadReport { record })
}

fn validate_plan(plan: &MatchedWorkloadPlan<'_>) -> Result<(), MatchedWorkloadPlanError> {
    plan.baseline
        .validate()
        .map_err(MatchedWorkloadPlanError::InvalidBaseline)?;
    if plan.baseline.stage != "firmware-auto-baseline"
        || plan.baseline.outcome.status != RunOutcomeStatus::Passed
        || plan.baseline.workload.is_none()
        || plan.baseline.thermal_summary.is_none()
        || !covers_final_five_minutes(plan.baseline)
    {
        return Err(MatchedWorkloadPlanError::BaselineNotAccepted);
    }
    let baseline_workload = plan.baseline.workload.as_ref().expect("checked above");
    let expected_baseline_binding = baseline_fingerprint(plan.baseline);
    if MatchedWorkloadClass::from_workload_id(&baseline_workload.workload_id).is_none() {
        return Err(MatchedWorkloadPlanError::UnknownWorkloadClass);
    }
    for (fan, calibration) in [
        (EvidenceFan::Cpu, plan.tachometer_calibrations.cpu),
        (EvidenceFan::Gpu, plan.tachometer_calibrations.gpu),
    ] {
        if !calibration_is_qualified(calibration, fan) {
            return Err(MatchedWorkloadPlanError::InvalidCalibration { fan });
        }
    }
    let mut prior_fingerprints = HashSet::new();
    for (index, prior) in plan.previous_passing_runs.iter().enumerate() {
        prior
            .validate()
            .map_err(|error| MatchedWorkloadPlanError::InvalidPriorRun {
                index,
                reason: error.to_string(),
            })?;
        if !prior_fingerprints.insert(baseline_fingerprint(prior)) {
            return Err(MatchedWorkloadPlanError::InvalidPriorRun {
                index,
                reason: "duplicate previous passing run".into(),
            });
        }
        if prior.stage != "matched-workload"
            || prior.outcome.status != RunOutcomeStatus::Passed
            || !prior.faults.is_empty()
            || prior.qualification_envelope != plan.baseline.qualification_envelope
            || prior.baseline_binding_sha256.as_deref() != Some(expected_baseline_binding.as_str())
            || !matched_workload_is_complete(prior)
            || !matched_workload_matches_baseline(prior, plan.baseline)
            || !matched_workload_matches_calibrations(prior, plan.tachometer_calibrations)
        {
            return Err(MatchedWorkloadPlanError::InvalidPriorRun {
                index,
                reason:
                    "run must be a complete passing match for this baseline envelope and workload"
                        .into(),
            });
        }
    }
    Ok(())
}

fn baseline_fingerprint(baseline: &EvidenceRecord) -> String {
    let canonical = serde_json::to_vec(baseline).expect("validated evidence always serializes");
    format!("{:x}", Sha256::digest(canonical))
}

fn calibration_is_qualified(
    calibration: &FanCalibrationEvidence,
    expected_fan: EvidenceFan,
) -> bool {
    if calibration.fan != expected_fan {
        return false;
    }
    let fan = match expected_fan {
        EvidenceFan::Cpu => Fan::Cpu,
        EvidenceFan::Gpu => Fan::Gpu,
    };
    calibration
        .protocol_checkpoint
        .as_ref()
        .and_then(|checkpoint| {
            crate::ConservativeFanCalibration::resume(fan, checkpoint.clone()).ok()
        })
        .and_then(|session| session.evidence().cloned())
        .is_some_and(|derived| derived == *calibration)
}

fn covers_final_five_minutes(record: &EvidenceRecord) -> bool {
    record
        .samples
        .first()
        .zip(record.samples.last())
        .is_some_and(|(first, last)| {
            last.timestamp
                .monotonic_millis
                .checked_sub(first.timestamp.monotonic_millis)
                .is_some_and(|span| span >= 5 * 60 * 1_000)
        })
}

pub(crate) fn matched_workload_is_complete(record: &EvidenceRecord) -> bool {
    let (Some(workload), Some(workload_started_at), Some(starting_conditions_captured_at)) = (
        record.workload.as_ref(),
        record.workload_started_at,
        record.starting_conditions_captured_at,
    ) else {
        return false;
    };
    let samples_are_complete = record.samples.len() >= MINIMUM_MATCHED_WORKLOAD_SAMPLES
        && record.samples.iter().all(|sample| {
            sample.freshness == SampleFreshness::Fresh
                && sample.cpu_millicelsius.is_some_and(|value| {
                    plausible_temperature(value, MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS)
                        && value < CPU_ABSOLUTE_ABORT_MILLICELSIUS
                })
                && sample.gpu_millicelsius.is_some_and(|value| {
                    plausible_temperature(value, MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS)
                        && value < GPU_ABSOLUTE_ABORT_MILLICELSIUS
                })
                && sample.external_power == Some(profile_power(workload.power_profile))
                && sample.selected_profile == Some(workload.power_profile)
                && sample.cpu_source_demand_basis_points.is_some()
                && sample.gpu_source_demand_basis_points.is_some()
                && sample.commanded_demand_basis_points.is_some()
                && sample.cpu_thermal_throttling == Some(false)
                && sample.gpu_thermal_throttling == Some(false)
        });
    let cadence_is_complete = record.samples.first().is_some_and(|sample| {
        sample
            .timestamp
            .monotonic_millis
            .checked_sub(workload_started_at.monotonic_millis)
            .is_some_and(|elapsed| {
                elapsed.abs_diff(SAMPLE_CADENCE_MILLIS) <= SAMPLE_CADENCE_JITTER_MILLIS
            })
    }) && record.samples.windows(2).all(|samples| {
        samples[1]
            .timestamp
            .monotonic_millis
            .checked_sub(samples[0].timestamp.monotonic_millis)
            .is_some_and(|elapsed| {
                elapsed.abs_diff(SAMPLE_CADENCE_MILLIS) <= SAMPLE_CADENCE_JITTER_MILLIS
            })
    });
    let control_evidence_is_complete = record.commands.len() == record.samples.len() * 2
        && record.readbacks.len() == record.samples.len() * 6 + 2
        && [EvidenceFan::Cpu, EvidenceFan::Gpu]
            .into_iter()
            .all(|fan| matched_fan_evidence_is_complete(record, fan));
    let transitions_are_complete = matches!(
        record.state_transitions.as_slice(),
        [entered, restored]
            if entered.from == "firmware-auto"
                && entered.to == "custom-control"
                && restored.from == "custom-control"
                && restored.to == "firmware-auto"
                && starting_conditions_captured_at.monotonic_millis
                    <= entered.timestamp.monotonic_millis
                && entered.timestamp.monotonic_millis <= workload_started_at.monotonic_millis
                && restored.timestamp.monotonic_millis >= workload_started_at.monotonic_millis
    );
    let summary_matches = record.thermal_summary.as_ref().is_some_and(|summary| {
        summary == &summarize_thermal_evidence(&record.samples, true, Vec::new(), Vec::new())
    });
    let starting_conditions_are_safe = plausible_temperature(
        workload.ambient_millicelsius,
        MAX_PLAUSIBLE_AMBIENT_MILLICELSIUS,
    ) && plausible_temperature(
        workload.starting_cpu_millicelsius,
        MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
    ) && plausible_temperature(
        workload.starting_gpu_millicelsius,
        MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
    ) && workload.starting_cpu_millicelsius
        < CPU_ABSOLUTE_ABORT_MILLICELSIUS
        && workload.starting_gpu_millicelsius < GPU_ABSOLUTE_ABORT_MILLICELSIUS;

    record.schema_version == EVIDENCE_SCHEMA_VERSION_V2
        && record.stage == "matched-workload"
        && record.outcome.status == RunOutcomeStatus::Passed
        && record.outcome.final_firmware_auto_confirmed
        && record.started_at.monotonic_millis <= starting_conditions_captured_at.monotonic_millis
        && starting_conditions_captured_at.monotonic_millis <= workload_started_at.monotonic_millis
        && starting_conditions_are_safe
        && samples_are_complete
        && cadence_is_complete
        && control_evidence_is_complete
        && transitions_are_complete
        && summary_matches
        && record.faults.is_empty()
        && record.calibration.is_empty()
}

fn matched_fan_evidence_is_complete(record: &EvidenceRecord, fan: EvidenceFan) -> bool {
    let mut endpoint_identities: [Option<&str>; 3] = [None; 3];
    for sample in &record.samples {
        let commands = record
            .commands
            .iter()
            .filter(|command| {
                command.fan == fan
                    && command.field == FanControlField::Pwm
                    && timestamp_within_sample(command.timestamp, sample.timestamp)
            })
            .collect::<Vec<_>>();
        let [command] = commands.as_slice() else {
            return false;
        };
        for (field_index, field) in [
            FanReadbackField::Enable,
            FanReadbackField::Pwm,
            FanReadbackField::Rpm,
        ]
        .into_iter()
        .enumerate()
        {
            let readbacks = record
                .readbacks
                .iter()
                .filter(|readback| {
                    readback.fan == fan
                        && readback.field == field
                        && readback.phase == Some(crate::FanReadbackPhase::Sample)
                        && timestamp_within_sample(readback.timestamp, sample.timestamp)
                })
                .collect::<Vec<_>>();
            let [readback] = readbacks.as_slice() else {
                return false;
            };
            let expected_value = match field {
                FanReadbackField::Enable => Some(1),
                FanReadbackField::Pwm => Some(command.value),
                FanReadbackField::Rpm => readback.value.filter(|value| *value > 0),
            };
            if readback.outcome != ObservationOutcome::Confirmed
                || readback.value != expected_value
                || endpoint_identities[field_index]
                    .is_some_and(|identity| identity != readback.endpoint_identity)
            {
                return false;
            }
            endpoint_identities[field_index] = Some(readback.endpoint_identity.as_str());
        }
    }
    let final_readbacks = record
        .readbacks
        .iter()
        .filter(|readback| {
            readback.fan == fan
                && readback.field == FanReadbackField::Enable
                && readback.phase == Some(crate::FanReadbackPhase::Final)
        })
        .collect::<Vec<_>>();
    let attempts = record
        .restoration_attempts
        .iter()
        .filter(|attempt| attempt.fan == fan)
        .collect::<Vec<_>>();
    matches!(
        (final_readbacks.as_slice(), attempts.as_slice()),
        ([readback], [attempt])
            if readback.value == Some(2)
                && readback.outcome == ObservationOutcome::Confirmed
                && Some(readback.endpoint_identity.as_str()) == endpoint_identities[0]
                && attempt.timestamp == readback.timestamp
                && attempt.auto_write_succeeded
                && attempt.enable_readback == Some(2)
                && attempt.outcome == RestorationOutcome::FirmwareAutoConfirmed
    )
}

fn timestamp_within_sample(timestamp: EvidenceTimestamp, sample_at: EvidenceTimestamp) -> bool {
    timestamp
        .monotonic_millis
        .checked_sub(sample_at.monotonic_millis)
        .is_some_and(|delay| delay <= SAMPLE_CADENCE_JITTER_MILLIS)
}

fn matched_workload_matches_baseline(custom: &EvidenceRecord, baseline: &EvidenceRecord) -> bool {
    let (
        Some(custom_workload),
        Some(baseline_workload),
        Some(custom_summary),
        Some(baseline_summary),
    ) = (
        custom.workload.as_ref(),
        baseline.workload.as_ref(),
        custom.thermal_summary.as_ref(),
        baseline.thermal_summary.as_ref(),
    )
    else {
        return false;
    };
    let comparison = evaluate_thermal_comparison(baseline_summary, custom_summary, &custom.samples);
    custom_workload.workload_id == baseline_workload.workload_id
        && custom_workload.command == baseline_workload.command
        && custom_workload.version == baseline_workload.version
        && custom_workload.power_profile == baseline_workload.power_profile
        && custom_workload
            .ambient_millicelsius
            .abs_diff(baseline_workload.ambient_millicelsius)
            <= AMBIENT_COMPARABILITY_MILLICELSIUS as u32
        && custom_workload
            .starting_cpu_millicelsius
            .abs_diff(baseline_workload.starting_cpu_millicelsius)
            <= STARTING_TEMPERATURE_COMPARABILITY_MILLICELSIUS as u32
        && custom_workload
            .starting_gpu_millicelsius
            .abs_diff(baseline_workload.starting_gpu_millicelsius)
            <= STARTING_TEMPERATURE_COMPARABILITY_MILLICELSIUS as u32
        && custom.samples.len() == baseline.samples.len()
        && comparison.accepted()
        && custom_summary.system_stable == Some(true)
        && custom_summary.kernel_faults.is_empty()
        && custom_summary.nvidia_faults.is_empty()
}

fn matched_workload_matches_calibrations(
    record: &EvidenceRecord,
    calibrations: MatchedWorkloadTachometerCalibrations<'_>,
) -> bool {
    let mut state = TachometerEvidenceState::default();
    record.samples.iter().all(|sample| {
        [EvidenceFan::Cpu, EvidenceFan::Gpu].into_iter().all(|fan| {
            evaluate_tachometer_sample(
                sample.timestamp,
                &record.commands,
                &record.readbacks,
                fan,
                calibration_for_fan(calibrations, fan),
                state_for_fan(&mut state, fan),
            )
            .is_ok()
        })
    })
}

#[derive(Default)]
struct ControlEvidenceState {
    endpoint_identities: [Option<String>; 6],
}

impl ControlEvidenceState {
    fn endpoint_identity(&self, fan: EvidenceFan, field: FanReadbackField) -> Option<&str> {
        self.endpoint_identities[endpoint_index(fan, field)].as_deref()
    }
}

fn validate_observation(
    observation: &mut MatchedWorkloadObservation,
    workload: &WorkloadEvidence,
    run_started_at: EvidenceTimestamp,
    captured_at: EvidenceTimestamp,
    expected_millis: u64,
    control_evidence: &mut ControlEvidenceState,
    tachometer_calibrations: MatchedWorkloadTachometerCalibrations<'_>,
    tachometer_evidence: &mut TachometerEvidenceState,
    faults: &mut Vec<FaultEvidence>,
) {
    let source_timestamp = observation.sample.timestamp;
    if source_timestamp.monotonic_millis < run_started_at.monotonic_millis
        || source_timestamp.monotonic_millis > captured_at.monotonic_millis
    {
        push_fault(
            faults,
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
    let sample = &mut observation.sample;
    let timestamp = sample.timestamp;
    if timestamp.monotonic_millis < run_started_at.monotonic_millis
        || timestamp.monotonic_millis > captured_at.monotonic_millis
        || timestamp.monotonic_millis.abs_diff(expected_millis) > SAMPLE_CADENCE_JITTER_MILLIS
    {
        push_fault(
            faults,
            captured_at,
            "sample-cadence",
            "telemetry did not arrive on the runner-owned two-second schedule",
        );
    }
    let complete = sample.freshness == SampleFreshness::Fresh
        && sample.cpu_millicelsius.is_some()
        && sample.gpu_millicelsius.is_some()
        && sample.external_power.is_some()
        && sample.selected_profile.is_some()
        && sample.cpu_source_demand_basis_points.is_some()
        && sample.gpu_source_demand_basis_points.is_some()
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
    if !complete || temperature_out_of_range || demand_out_of_range {
        sample.freshness = SampleFreshness::Invalid;
        push_fault(
            faults,
            timestamp,
            "invalid-telemetry",
            "required telemetry is missing, stale, or invalid",
        );
    }
    if sample.external_power != Some(profile_power(workload.power_profile))
        || sample.selected_profile != Some(workload.power_profile)
    {
        push_fault(
            faults,
            timestamp,
            "workload-profile-mismatch",
            "observed power/profile does not match the baseline workload",
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
    if let Some(detail) = observation.controller_fault.as_deref() {
        push_fault(
            faults,
            timestamp,
            "controller-fault",
            nonempty(detail, "controller fault reported"),
        );
    }
    sanitize_control_evidence(observation, run_started_at, captured_at, faults);
    validate_fan_control_evidence(
        observation,
        EvidenceFan::Cpu,
        captured_at,
        control_evidence,
        faults,
    );
    validate_fan_control_evidence(
        observation,
        EvidenceFan::Gpu,
        captured_at,
        control_evidence,
        faults,
    );
    validate_tachometer_evidence(
        observation,
        tachometer_calibrations,
        tachometer_evidence,
        faults,
    );
    if !observation.system_stable {
        push_fault(
            faults,
            timestamp,
            "system-instability",
            "system stability check failed",
        );
    }
    for detail in &observation.kernel_faults {
        push_fault(
            faults,
            timestamp,
            "kernel-instability",
            nonempty(detail, "kernel fault reported"),
        );
    }
    for detail in &observation.nvidia_faults {
        push_fault(
            faults,
            timestamp,
            "nvidia-instability",
            nonempty(detail, "NVIDIA fault reported"),
        );
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct TachometerEvidenceState {
    cpu: Option<TachometerCommandState>,
    gpu: Option<TachometerCommandState>,
}

#[derive(Debug, Clone, Copy)]
struct TachometerCommandState {
    pwm: u8,
    confirmed_at_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TachometerEvidenceError {
    InvalidEvidence,
    DeadlineOverflow,
    OutOfBand { expected_rpm: u32, actual_rpm: u32 },
}

fn validate_tachometer_evidence(
    observation: &MatchedWorkloadObservation,
    calibrations: MatchedWorkloadTachometerCalibrations<'_>,
    state: &mut TachometerEvidenceState,
    faults: &mut Vec<FaultEvidence>,
) {
    for fan in [EvidenceFan::Cpu, EvidenceFan::Gpu] {
        match evaluate_tachometer_sample(
            observation.sample.timestamp,
            &observation.commands,
            &observation.readbacks,
            fan,
            calibration_for_fan(calibrations, fan),
            state_for_fan(state, fan),
        ) {
            Ok(()) => {}
            Err(TachometerEvidenceError::InvalidEvidence) => push_fault(
                faults,
                observation.sample.timestamp,
                "invalid-control-evidence",
                format!("{fan:?} tachometer evidence is missing, ambiguous, or misordered"),
            ),
            Err(TachometerEvidenceError::DeadlineOverflow) => push_fault(
                faults,
                observation.sample.timestamp,
                "fan-feedback-loss",
                format!("{fan:?} tachometer response deadline overflowed"),
            ),
            Err(TachometerEvidenceError::OutOfBand {
                expected_rpm,
                actual_rpm,
            }) => push_fault(
                faults,
                observation.sample.timestamp,
                "fan-feedback-loss",
                format!(
                    "{fan:?} fan tachometer settled outside its qualified ±30% band (expected {expected_rpm} RPM, got {actual_rpm} RPM)"
                ),
            ),
        }
    }
}

fn evaluate_tachometer_sample(
    sample_at: EvidenceTimestamp,
    commands: &[FanCommandEvidence],
    readbacks: &[FanReadbackEvidence],
    fan: EvidenceFan,
    calibration: &FanCalibrationEvidence,
    state: &mut Option<TachometerCommandState>,
) -> Result<(), TachometerEvidenceError> {
    let commands = commands
        .iter()
        .filter(|command| {
            command.fan == fan
                && command.field == FanControlField::Pwm
                && timestamp_within_sample(command.timestamp, sample_at)
        })
        .collect::<Vec<_>>();
    let pwm_readbacks = readbacks
        .iter()
        .filter(|readback| {
            readback.fan == fan
                && readback.field == FanReadbackField::Pwm
                && readback.phase == Some(crate::FanReadbackPhase::Sample)
                && timestamp_within_sample(readback.timestamp, sample_at)
        })
        .collect::<Vec<_>>();
    let rpm_readbacks = readbacks
        .iter()
        .filter(|readback| {
            readback.fan == fan
                && readback.field == FanReadbackField::Rpm
                && readback.phase == Some(crate::FanReadbackPhase::Sample)
                && timestamp_within_sample(readback.timestamp, sample_at)
        })
        .collect::<Vec<_>>();
    let ([command], [pwm_readback], [rpm_readback]) = (
        commands.as_slice(),
        pwm_readbacks.as_slice(),
        rpm_readbacks.as_slice(),
    ) else {
        return Err(TachometerEvidenceError::InvalidEvidence);
    };
    let pwm = u8::try_from(command.value).map_err(|_| TachometerEvidenceError::InvalidEvidence)?;
    let rpm = rpm_readback
        .value
        .filter(|value| *value > 0)
        .ok_or(TachometerEvidenceError::InvalidEvidence)?;
    if pwm_readback.outcome != ObservationOutcome::Confirmed
        || pwm_readback.value != Some(command.value)
        || rpm_readback.outcome != ObservationOutcome::Confirmed
        || rpm_readback.timestamp.monotonic_millis < pwm_readback.timestamp.monotonic_millis
    {
        return Err(TachometerEvidenceError::InvalidEvidence);
    }
    if state.is_none_or(|current| current.pwm != pwm) {
        *state = Some(TachometerCommandState {
            pwm,
            confirmed_at_millis: pwm_readback.timestamp.monotonic_millis,
        });
    }
    let current = state.expect("tachometer command state was initialized");
    let deadline = current
        .confirmed_at_millis
        .checked_add(calibration.response_deadline_millis)
        .ok_or(TachometerEvidenceError::DeadlineOverflow)?;
    let expected_rpm = expected_rpm_from_evidence(calibration, pwm)
        .ok_or(TachometerEvidenceError::InvalidEvidence)?;
    if rpm_in_band(rpm, expected_rpm) || rpm_readback.timestamp.monotonic_millis <= deadline {
        Ok(())
    } else {
        Err(TachometerEvidenceError::OutOfBand {
            expected_rpm,
            actual_rpm: rpm,
        })
    }
}

const fn calibration_for_fan(
    calibrations: MatchedWorkloadTachometerCalibrations<'_>,
    fan: EvidenceFan,
) -> &FanCalibrationEvidence {
    match fan {
        EvidenceFan::Cpu => calibrations.cpu,
        EvidenceFan::Gpu => calibrations.gpu,
    }
}

fn state_for_fan(
    state: &mut TachometerEvidenceState,
    fan: EvidenceFan,
) -> &mut Option<TachometerCommandState> {
    match fan {
        EvidenceFan::Cpu => &mut state.cpu,
        EvidenceFan::Gpu => &mut state.gpu,
    }
}

fn sanitize_control_evidence(
    observation: &mut MatchedWorkloadObservation,
    run_started_at: EvidenceTimestamp,
    captured_at: EvidenceTimestamp,
    faults: &mut Vec<FaultEvidence>,
) {
    let command_count = observation.commands.len();
    observation.commands.retain(|command| {
        command.timestamp.monotonic_millis >= run_started_at.monotonic_millis
            && command.timestamp.monotonic_millis <= captured_at.monotonic_millis
            && match command.field {
                FanControlField::Pwm => command.value <= 255,
                FanControlField::Enable => command.value <= 2,
            }
    });
    let readback_count = observation.readbacks.len();
    observation.readbacks.retain(|readback| {
        let outcome_matches_value = match readback.outcome {
            ObservationOutcome::Confirmed | ObservationOutcome::Unexpected => {
                readback.value.is_some()
            }
            ObservationOutcome::Unreadable => readback.value.is_none(),
        };
        readback.timestamp.monotonic_millis >= run_started_at.monotonic_millis
            && readback.timestamp.monotonic_millis <= captured_at.monotonic_millis
            && !readback.endpoint_identity.is_empty()
            && outcome_matches_value
            && !(readback.field == FanReadbackField::Pwm
                && readback.value.is_some_and(|value| value > 255))
            && !(readback.field == FanReadbackField::Enable
                && readback.value.is_some_and(|value| value > 2))
    });
    if command_count != observation.commands.len() || readback_count != observation.readbacks.len()
    {
        push_fault(
            faults,
            observation.sample.timestamp,
            "invalid-control-evidence",
            "fan command or readback evidence is malformed or outside its capture window",
        );
    }
}

fn validate_fan_control_evidence(
    observation: &MatchedWorkloadObservation,
    fan: EvidenceFan,
    captured_at: EvidenceTimestamp,
    state: &mut ControlEvidenceState,
    faults: &mut Vec<FaultEvidence>,
) {
    let sample_at = observation.sample.timestamp;
    let pwm_commands = observation
        .commands
        .iter()
        .filter(|command| command.fan == fan && command.field == FanControlField::Pwm)
        .collect::<Vec<_>>();
    let command = match pwm_commands.as_slice() {
        [command]
            if command.timestamp.monotonic_millis >= sample_at.monotonic_millis
                && command.timestamp.monotonic_millis <= captured_at.monotonic_millis =>
        {
            Some(*command)
        }
        _ => {
            push_fault(
                faults,
                sample_at,
                "mode-pwm-mismatch",
                format!("{fan:?} requires one timestamp-bound PWM command per sample"),
            );
            None
        }
    };

    for field in [
        FanReadbackField::Enable,
        FanReadbackField::Pwm,
        FanReadbackField::Rpm,
    ] {
        let matching = observation
            .readbacks
            .iter()
            .filter(|readback| readback.fan == fan && readback.field == field)
            .collect::<Vec<_>>();
        let readback = match matching.as_slice() {
            [readback]
                if readback.phase == Some(crate::FanReadbackPhase::Sample)
                    && readback.outcome == ObservationOutcome::Confirmed
                    && readback.timestamp.monotonic_millis >= sample_at.monotonic_millis
                    && readback.timestamp.monotonic_millis <= captured_at.monotonic_millis =>
            {
                *readback
            }
            _ => {
                push_fault(
                    faults,
                    sample_at,
                    if field == FanReadbackField::Rpm {
                        "fan-feedback-loss"
                    } else {
                        "mode-pwm-mismatch"
                    },
                    format!("{fan:?} {field:?} readback is missing, ambiguous, or unconfirmed"),
                );
                continue;
            }
        };
        let expected = match field {
            FanReadbackField::Enable => Some(1),
            FanReadbackField::Pwm => command.map(|command| command.value),
            FanReadbackField::Rpm => readback.value.filter(|value| *value > 0),
        };
        if readback.value != expected || expected.is_none() {
            push_fault(
                faults,
                sample_at,
                if field == FanReadbackField::Rpm {
                    "fan-feedback-loss"
                } else {
                    "mode-pwm-mismatch"
                },
                format!("{fan:?} {field:?} readback does not confirm the commanded state"),
            );
        }
        let index = endpoint_index(fan, field);
        match &state.endpoint_identities[index] {
            Some(identity) if identity != &readback.endpoint_identity => push_fault(
                faults,
                sample_at,
                "endpoint-identity-change",
                format!("{fan:?} {field:?} endpoint identity changed"),
            ),
            None => state.endpoint_identities[index] = Some(readback.endpoint_identity.clone()),
            Some(_) => {}
        }
    }
}

const fn endpoint_index(fan: EvidenceFan, field: FanReadbackField) -> usize {
    let fan_offset = match fan {
        EvidenceFan::Cpu => 0,
        EvidenceFan::Gpu => 3,
    };
    fan_offset
        + match field {
            FanReadbackField::Pwm => 0,
            FanReadbackField::Enable => 1,
            FanReadbackField::Rpm => 2,
        }
}

fn compare_thermal_summaries<E: MatchedWorkloadEnvironment + ?Sized>(
    baseline: &crate::ThermalSummaryEvidence,
    custom: &crate::ThermalSummaryEvidence,
    custom_samples: &[TelemetrySampleEvidence],
    faults: &mut Vec<FaultEvidence>,
    environment: &mut E,
) {
    let timestamp = environment.timestamp();
    let comparison = evaluate_thermal_comparison(baseline, custom, custom_samples);
    if !comparison.peaks_acceptable {
        push_fault(
            faults,
            timestamp,
            "peak-temperature-regression",
            "Custom CPU or GPU peak exceeded baseline by more than 2 C",
        );
    }
    if !comparison.percentiles_acceptable {
        push_fault(
            faults,
            timestamp,
            "p95-temperature-regression",
            "Custom CPU or GPU 95th percentile exceeded baseline by more than 2 C",
        );
    }
    if !comparison.slopes_acceptable {
        push_fault(
            faults,
            timestamp,
            "final-slope-regression",
            "Custom final-five-minute CPU or GPU slope exceeded 1 C/min",
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct ThermalComparison {
    peaks_acceptable: bool,
    percentiles_acceptable: bool,
    slopes_acceptable: bool,
}

impl ThermalComparison {
    const fn accepted(self) -> bool {
        self.peaks_acceptable && self.percentiles_acceptable && self.slopes_acceptable
    }
}

fn evaluate_thermal_comparison(
    baseline: &crate::ThermalSummaryEvidence,
    custom: &crate::ThermalSummaryEvidence,
    custom_samples: &[TelemetrySampleEvidence],
) -> ThermalComparison {
    let peaks_acceptable = custom.cpu_peak_millicelsius
        <= baseline
            .cpu_peak_millicelsius
            .saturating_add(THERMAL_COMPARISON_MARGIN_MILLICELSIUS)
        && custom.gpu_peak_millicelsius
            <= baseline
                .gpu_peak_millicelsius
                .saturating_add(THERMAL_COMPARISON_MARGIN_MILLICELSIUS);
    let percentiles_acceptable = custom.cpu_p95_millicelsius
        <= baseline
            .cpu_p95_millicelsius
            .saturating_add(THERMAL_COMPARISON_MARGIN_MILLICELSIUS)
        && custom.gpu_p95_millicelsius
            <= baseline
                .gpu_p95_millicelsius
                .saturating_add(THERMAL_COMPARISON_MARGIN_MILLICELSIUS);
    let (cpu_precise_slope, gpu_precise_slope) = precise_final_thermal_slopes(custom_samples);
    ThermalComparison {
        peaks_acceptable,
        percentiles_acceptable,
        slopes_acceptable: cpu_precise_slope
            <= f64::from(THERMAL_SLOPE_LIMIT_MILLICELSIUS_PER_MINUTE)
            && gpu_precise_slope <= f64::from(THERMAL_SLOPE_LIMIT_MILLICELSIUS_PER_MINUTE),
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

fn nonempty(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}

fn checked_deadline(
    now_millis: u64,
    timeout_millis: u64,
    timestamp: EvidenceTimestamp,
    code: &str,
    faults: &mut Vec<FaultEvidence>,
) -> Option<u64> {
    match now_millis.checked_add(timeout_millis) {
        Some(deadline) => Some(deadline),
        None => {
            push_fault(faults, timestamp, code, "deadline overflowed");
            None
        }
    }
}

fn push_fault(
    faults: &mut Vec<FaultEvidence>,
    timestamp: EvidenceTimestamp,
    code: &str,
    detail: impl Into<String>,
) {
    faults.push(FaultEvidence {
        timestamp,
        code: code.to_owned(),
        detail: detail.into(),
    });
}
