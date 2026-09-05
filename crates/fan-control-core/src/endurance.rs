use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
};

use crate::{
    CPU_ABSOLUTE_ABORT_MILLICELSIUS, CapturedMatchedWorkloadStartingConditions,
    EVIDENCE_SCHEMA_VERSION_V2, EnduranceObserverAttestationEvidence,
    EnduranceThermalEnvelopeEvidence, EvidenceExternalPower, EvidenceFan, EvidenceProfile,
    EvidenceRecord, EvidenceRecordStatus, EvidenceTimestamp, EvidenceValidationError,
    FanReadbackEvidence, FanReadbackField, FaultEvidence, MatchedWorkloadFanRestoration,
    MatchedWorkloadObservation, MatchedWorkloadTachometerCalibrations, ObservationOutcome,
    ProcessStopEvidence, QualificationEnvelopeIdentityV1, RestorationAttemptEvidence,
    RestorationOutcome, RunOutcomeEvidence, RunOutcomeStatus, SampleFreshness,
    StateTransitionEvidence, StoppedProcess, ThermalSummaryEvidence, WorkloadEvidence,
    evidence::{precise_final_thermal_slopes, summarize_thermal_evidence, validate_workload},
    matched_workload::{
        ControlEvidenceState, MAX_PLAUSIBLE_AMBIENT_MILLICELSIUS,
        MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS, MatchedWorkloadClass,
        ObservationSchedule, TachometerEvidenceState, baseline_fingerprint,
        baseline_measurement_fingerprint, calibration_record_is_qualified,
        matched_control_evidence_is_complete, matched_run_fingerprint,
        matched_workload_is_complete, matched_workload_matches_baseline,
        matched_workload_matches_calibrations, plausible_temperature, validate_observation,
    },
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::{QualificationRecordV2, SupervisedEnduranceAuthorizationV1};

pub const SUPERVISED_ENDURANCE_DURATION_MILLIS: u64 = 60 * 60 * 1_000;
pub const SUPERVISED_ENDURANCE_SAMPLE_COUNT: usize = 1_800;
pub const SUPERVISED_ENDURANCE_WORKLOAD_ID: &str = "supervised-mixed-endurance";
const QUALIFICATION_WORKLOAD_VERSION: &str = "1.0.0";

const SAMPLE_CADENCE_MILLIS: u64 = 2_000;
const SAMPLE_CADENCE_JITTER_MILLIS: u64 = 100;
const SEGMENT_TRANSITION_WINDOW_MILLIS: u64 = SAMPLE_CADENCE_MILLIS;
const OPERATION_TIMEOUT_MILLIS: u64 = 10_000;
const RESTORATION_TIMEOUT_MILLIS: u64 = 5_000;
const THERMAL_COMPARISON_MARGIN_MILLICELSIUS: i32 = 2_000;
const THERMAL_SLOPE_LIMIT_MILLICELSIUS_PER_MINUTE: f64 = 1_000.0;
const LOAD_MINIMUM_UTILIZATION_BASIS_POINTS: u16 = 5_000;
const IDLE_MAXIMUM_UTILIZATION_BASIS_POINTS: u16 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct WorkloadKey {
    profile: EvidenceProfile,
    class: MatchedWorkloadClass,
}

impl WorkloadKey {
    const fn required_duration_millis(self) -> u64 {
        match (self.profile, self.class) {
            (EvidenceProfile::Ac, MatchedWorkloadClass::Idle)
            | (EvidenceProfile::Battery, MatchedWorkloadClass::Idle)
            | (EvidenceProfile::Battery, MatchedWorkloadClass::Cpu)
            | (EvidenceProfile::Battery, MatchedWorkloadClass::Gpu) => 10 * 60 * 1_000,
            (EvidenceProfile::Ac, MatchedWorkloadClass::Cpu)
            | (EvidenceProfile::Ac, MatchedWorkloadClass::Gpu) => 20 * 60 * 1_000,
            (EvidenceProfile::Ac, MatchedWorkloadClass::Combined) => 30 * 60 * 1_000,
            (EvidenceProfile::Battery, MatchedWorkloadClass::Combined) => 0,
        }
    }

    const fn expected() -> [Self; 7] {
        [
            Self {
                profile: EvidenceProfile::Ac,
                class: MatchedWorkloadClass::Idle,
            },
            Self {
                profile: EvidenceProfile::Ac,
                class: MatchedWorkloadClass::Cpu,
            },
            Self {
                profile: EvidenceProfile::Ac,
                class: MatchedWorkloadClass::Gpu,
            },
            Self {
                profile: EvidenceProfile::Ac,
                class: MatchedWorkloadClass::Combined,
            },
            Self {
                profile: EvidenceProfile::Battery,
                class: MatchedWorkloadClass::Idle,
            },
            Self {
                profile: EvidenceProfile::Battery,
                class: MatchedWorkloadClass::Cpu,
            },
            Self {
                profile: EvidenceProfile::Battery,
                class: MatchedWorkloadClass::Gpu,
            },
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisedEnduranceLoad {
    Load,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisedEnduranceSegment {
    pub id: &'static str,
    pub power_profile: EvidenceProfile,
    pub load: SupervisedEnduranceLoad,
    pub duration_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisedEnduranceSegmentConfirmation {
    pub observed_at: EvidenceTimestamp,
    pub load: SupervisedEnduranceLoad,
    pub external_power: EvidenceExternalPower,
    pub selected_profile: EvidenceProfile,
    pub cpu_utilization_basis_points: u16,
    pub gpu_utilization_basis_points: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisedEnduranceProcessStopConfirmation {
    pub observed_at: EvidenceTimestamp,
    pub process_identity: String,
    pub running: bool,
}

/// Independent Custom-mode and maximum-PWM confirmation for emergency containment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisedEnduranceFanContainment {
    pub enable_readback: Option<u32>,
    pub pwm_write_succeeded: bool,
    pub pwm_readback: Option<u32>,
    pub enable_endpoint_identity: String,
    pub pwm_endpoint_identity: String,
    pub outcome: RestorationOutcome,
}

pub const SUPERVISED_ENDURANCE_SEGMENTS: [SupervisedEnduranceSegment; 6] = [
    SupervisedEnduranceSegment {
        id: "endurance-ac-load-1",
        power_profile: EvidenceProfile::Ac,
        load: SupervisedEnduranceLoad::Load,
        duration_millis: 15 * 60 * 1_000,
    },
    SupervisedEnduranceSegment {
        id: "endurance-ac-idle-1",
        power_profile: EvidenceProfile::Ac,
        load: SupervisedEnduranceLoad::Idle,
        duration_millis: 10 * 60 * 1_000,
    },
    SupervisedEnduranceSegment {
        id: "endurance-battery-load",
        power_profile: EvidenceProfile::Battery,
        load: SupervisedEnduranceLoad::Load,
        duration_millis: 10 * 60 * 1_000,
    },
    SupervisedEnduranceSegment {
        id: "endurance-battery-idle",
        power_profile: EvidenceProfile::Battery,
        load: SupervisedEnduranceLoad::Idle,
        duration_millis: 5 * 60 * 1_000,
    },
    SupervisedEnduranceSegment {
        id: "endurance-ac-load-2",
        power_profile: EvidenceProfile::Ac,
        load: SupervisedEnduranceLoad::Load,
        duration_millis: 10 * 60 * 1_000,
    },
    SupervisedEnduranceSegment {
        id: "endurance-ac-idle-2",
        power_profile: EvidenceProfile::Ac,
        load: SupervisedEnduranceLoad::Idle,
        duration_millis: 10 * 60 * 1_000,
    },
];

pub trait SupervisedEnduranceEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp;

    /// Reconfirms that the physical safety observer is present before and throughout Custom.
    fn confirm_observer(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<EvidenceTimestamp, String>;

    fn capture_starting_conditions(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<CapturedMatchedWorkloadStartingConditions, String>;

    fn enter_custom_control(&mut self, deadline_monotonic_millis: u64) -> Result<(), String>;

    fn begin_segment(
        &mut self,
        segment: SupervisedEnduranceSegment,
        deadline_monotonic_millis: u64,
    ) -> Result<SupervisedEnduranceSegmentConfirmation, String>;

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

    fn stop_workload(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String>;

    /// Escalates workload termination after a normal stop was not confirmed.
    fn contain_workload(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.stop_workload(deadline_monotonic_millis)
    }

    /// Performs terminal containment after graceful and escalated workload stops both fail.
    fn force_contain_workload(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String>;

    fn stop_service(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String>;

    /// Escalates service termination after a normal stop was not confirmed.
    fn contain_service(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.stop_service(deadline_monotonic_millis)
    }

    /// Performs terminal service containment and confirms process absence.
    fn force_contain_service(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String>;

    fn restore_fan(
        &mut self,
        fan: EvidenceFan,
        deadline_monotonic_millis: u64,
    ) -> MatchedWorkloadFanRestoration;

    /// Commands and confirms emergency maximum fan containment without first selecting Auto.
    fn contain_fan_at_maximum(
        &mut self,
        fan: EvidenceFan,
        deadline_monotonic_millis: u64,
    ) -> SupervisedEnduranceFanContainment;
}

pub struct SupervisedEndurancePlan<'a> {
    pub prerequisite_binding_sha256: String,
    pub preflight: &'a EvidenceRecord,
    pub baselines: &'a [&'a EvidenceRecord],
    pub matched_workload_runs: &'a [&'a EvidenceRecord],
    pub tachometer_calibrations: MatchedWorkloadTachometerCalibrations<'a>,
    pub live_lifecycle: &'a EvidenceRecord,
    pub workload: WorkloadEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisedEndurancePlanError {
    InvalidQualificationEvidence { artifact: String, reason: String },
    IncompleteWorkloadMatrix { reason: String },
    InvalidWorkload { reason: String },
    InvalidGeneratedEvidence(EvidenceValidationError),
}

impl fmt::Display for SupervisedEndurancePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQualificationEvidence { artifact, reason } => {
                write!(formatter, "invalid {artifact} evidence: {reason}")
            }
            Self::IncompleteWorkloadMatrix { reason } => {
                write!(formatter, "incomplete workload matrix: {reason}")
            }
            Self::InvalidWorkload { reason } => {
                write!(formatter, "invalid endurance workload: {reason}")
            }
            Self::InvalidGeneratedEvidence(error) => {
                write!(
                    formatter,
                    "generated endurance evidence is invalid: {error}"
                )
            }
        }
    }
}

impl Error for SupervisedEndurancePlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidGeneratedEvidence(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisedEnduranceReport {
    record: EvidenceRecord,
}

impl SupervisedEnduranceReport {
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

pub fn run_supervised_endurance<E>(
    environment: &mut E,
    plan: &SupervisedEndurancePlan<'_>,
) -> Result<SupervisedEnduranceReport, SupervisedEndurancePlanError>
where
    E: SupervisedEnduranceEnvironment + ?Sized,
{
    if !crate::evidence::is_lower_hex(&plan.prerequisite_binding_sha256, 64) {
        return Err(SupervisedEndurancePlanError::InvalidQualificationEvidence {
            artifact: "prerequisite binding".into(),
            reason: "lowercase SHA-256 required".into(),
        });
    }
    let envelope = validate_qualification_plan(plan)?;
    let endurance_thermal_envelope = endurance_thermal_envelope(plan.baselines)?;
    validate_endurance_workload(&plan.workload)?;

    let started_at = environment.timestamp();
    let mut workload = plan.workload.clone();
    let mut starting_conditions_captured_at = None;
    let mut workload_started_at = None;
    let mut samples = Vec::with_capacity(SUPERVISED_ENDURANCE_SAMPLE_COUNT);
    let mut commands = Vec::with_capacity(SUPERVISED_ENDURANCE_SAMPLE_COUNT * 2);
    let mut readbacks = Vec::with_capacity(SUPERVISED_ENDURANCE_SAMPLE_COUNT * 6 + 2);
    let mut transitions = Vec::with_capacity(SUPERVISED_ENDURANCE_SEGMENTS.len() + 2);
    let mut faults = Vec::new();
    let mut restoration_attempts = Vec::with_capacity(2);
    let mut process_stops = Vec::with_capacity(2);
    let mut observer_checks = Vec::with_capacity(SUPERVISED_ENDURANCE_SAMPLE_COUNT + 8);
    let mut kernel_faults = Vec::new();
    let mut nvidia_faults = Vec::new();
    let mut system_stable = true;
    let mut control_state = ControlEvidenceState::default();
    let mut tachometer_state = TachometerEvidenceState::default();
    let mut custom_attempted = false;
    let mut workload_attempted = false;
    let mut active_segment_index = 0usize;
    let mut lifecycle_not_before = started_at;

    let deadline = operation_deadline(started_at, &mut faults, "starting-conditions");
    if let Some(deadline) = deadline {
        let result = environment.capture_starting_conditions(deadline);
        let completed_at = environment.timestamp();
        if completed_at.monotonic_millis < lifecycle_not_before.monotonic_millis
            || completed_at.monotonic_millis > deadline
        {
            push_fault(
                &mut faults,
                later_timestamp(completed_at, lifecycle_not_before),
                "starting-conditions",
                "starting-condition capture completed outside its deadline",
            );
        }
        match result {
            Ok(capture)
                if capture.captured_at.monotonic_millis >= started_at.monotonic_millis
                    && capture.captured_at.monotonic_millis <= completed_at.monotonic_millis
                    && capture.conditions.power_profile == EvidenceProfile::Ac
                    && plausible_temperature(
                        capture.conditions.ambient_millicelsius,
                        MAX_PLAUSIBLE_AMBIENT_MILLICELSIUS,
                    )
                    && plausible_temperature(
                        capture.conditions.cpu_millicelsius,
                        MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
                    )
                    && plausible_temperature(
                        capture.conditions.gpu_millicelsius,
                        MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
                    )
                    && capture.conditions.cpu_millicelsius < CPU_ABSOLUTE_ABORT_MILLICELSIUS
                    && capture.conditions.gpu_millicelsius
                        < crate::GPU_ABSOLUTE_ABORT_MILLICELSIUS =>
            {
                starting_conditions_captured_at = Some(capture.captured_at);
                workload.ambient_millicelsius = capture.conditions.ambient_millicelsius;
                workload.starting_cpu_millicelsius = capture.conditions.cpu_millicelsius;
                workload.starting_gpu_millicelsius = capture.conditions.gpu_millicelsius;
            }
            Ok(_) => push_fault(
                &mut faults,
                completed_at,
                "starting-conditions",
                "endurance must begin on AC with fresh temperatures below abort limits",
            ),
            Err(error) => push_fault(
                &mut faults,
                completed_at,
                "starting-conditions",
                format!("cannot capture starting conditions: {error}"),
            ),
        }
        lifecycle_not_before = later_timestamp(completed_at, lifecycle_not_before);
    }

    if faults.is_empty() {
        let observed_at = environment.timestamp();
        if observed_at.monotonic_millis < lifecycle_not_before.monotonic_millis {
            push_fault(
                &mut faults,
                lifecycle_not_before,
                "custom-control-entry",
                "clock regressed before Custom-control entry",
            );
        }
        let requested_at = later_timestamp(observed_at, lifecycle_not_before);
        let deadline = faults
            .is_empty()
            .then(|| observer_bounded_deadline(requested_at, &mut faults, "custom-control-entry"))
            .flatten();
        if let Some(deadline) = deadline {
            let observer =
                record_observer_confirmation(environment, deadline, &mut observer_checks);
            let result = observer.and_then(|()| {
                custom_attempted = true;
                environment.enter_custom_control(deadline)
            });
            let observed_completed_at = environment.timestamp();
            if observed_completed_at.monotonic_millis < requested_at.monotonic_millis {
                push_fault(
                    &mut faults,
                    requested_at,
                    "custom-control-entry",
                    "clock regressed during Custom-control entry",
                );
            }
            let completed_at = later_timestamp(observed_completed_at, requested_at);
            if completed_at.monotonic_millis > deadline {
                push_fault(
                    &mut faults,
                    completed_at,
                    "custom-control-entry",
                    "Custom-control entry exceeded its deadline",
                );
            }
            match result {
                Ok(()) if faults.is_empty() => transitions.push(StateTransitionEvidence {
                    timestamp: completed_at,
                    boot_id: None,
                    from: "firmware-auto".into(),
                    to: "custom-control".into(),
                }),
                Ok(()) => {}
                Err(error) => push_fault(
                    &mut faults,
                    completed_at,
                    "custom-control-entry",
                    format!("cannot confirm Custom control: {error}"),
                ),
            }
            lifecycle_not_before = completed_at;
        }
    }

    if faults.is_empty() {
        let segment = SUPERVISED_ENDURANCE_SEGMENTS[0];
        let observed_at = environment.timestamp();
        if observed_at.monotonic_millis < lifecycle_not_before.monotonic_millis {
            push_fault(
                &mut faults,
                lifecycle_not_before,
                "endurance-segment",
                "clock regressed before initial endurance segment",
            );
        }
        let requested_at = later_timestamp(observed_at, lifecycle_not_before);
        let deadline = faults
            .is_empty()
            .then(|| observer_bounded_deadline(requested_at, &mut faults, "endurance-segment"))
            .flatten();
        if let Some(deadline) = deadline {
            let result = record_observer_confirmation(environment, deadline, &mut observer_checks)
                .and_then(|()| environment.begin_segment(segment, deadline));
            let observed_completed_at = environment.timestamp();
            if observed_completed_at.monotonic_millis < requested_at.monotonic_millis {
                push_fault(
                    &mut faults,
                    requested_at,
                    "endurance-segment",
                    "clock regressed during initial endurance segment",
                );
            }
            let completed_at = later_timestamp(observed_completed_at, requested_at);
            match result {
                Ok(confirmation)
                    if faults.is_empty()
                        && segment_state_confirmation_matches(confirmation, segment)
                        && confirmation.observed_at.monotonic_millis
                            >= requested_at.monotonic_millis
                        && confirmation.observed_at.monotonic_millis
                            <= completed_at.monotonic_millis
                        && completed_at.monotonic_millis <= deadline =>
                {
                    transitions.push(StateTransitionEvidence {
                        timestamp: confirmation.observed_at,
                        boot_id: None,
                        from: "custom-control".into(),
                        to: segment.id.into(),
                    });
                }
                Ok(_) => push_fault(
                    &mut faults,
                    completed_at,
                    "endurance-segment",
                    "initial endurance segment was not confirmed inside its deadline",
                ),
                Err(error) => push_fault(
                    &mut faults,
                    completed_at,
                    "endurance-segment",
                    format!("cannot begin initial endurance segment: {error}"),
                ),
            }
            lifecycle_not_before = completed_at;
        }
    }

    if faults.is_empty() {
        let observed_at = environment.timestamp();
        if observed_at.monotonic_millis < lifecycle_not_before.monotonic_millis {
            push_fault(
                &mut faults,
                lifecycle_not_before,
                "workload-start",
                "clock regressed before workload start",
            );
        }
        let requested_at = later_timestamp(observed_at, lifecycle_not_before);
        let deadline = faults
            .is_empty()
            .then(|| observer_bounded_deadline(requested_at, &mut faults, "workload-start"))
            .flatten();
        if let Some(deadline) = deadline {
            let result = record_observer_confirmation(environment, deadline, &mut observer_checks)
                .and_then(|()| {
                    workload_attempted = true;
                    environment.start_workload(&workload, deadline)
                });
            let observed_completed_at = environment.timestamp();
            if observed_completed_at.monotonic_millis < requested_at.monotonic_millis {
                push_fault(
                    &mut faults,
                    requested_at,
                    "workload-start",
                    "clock regressed during workload start",
                );
            }
            let completed_at = later_timestamp(observed_completed_at, requested_at);
            match result {
                Ok(source_at)
                    if faults.is_empty()
                        && source_at.monotonic_millis >= requested_at.monotonic_millis
                        && source_at.monotonic_millis <= completed_at.monotonic_millis
                        && completed_at.monotonic_millis <= deadline =>
                {
                    workload_started_at = Some(source_at);
                }
                Ok(_) => push_fault(
                    &mut faults,
                    completed_at,
                    "workload-start",
                    "mixed workload start was not confirmed inside its deadline",
                ),
                Err(error) => push_fault(
                    &mut faults,
                    completed_at,
                    "workload-start",
                    format!("cannot start mixed workload: {error}"),
                ),
            }
            lifecycle_not_before = completed_at;
        }
    }

    while faults.is_empty() && samples.len() < SUPERVISED_ENDURANCE_SAMPLE_COUNT {
        let sample_number = samples.len() as u64 + 1;
        let expected_elapsed = sample_number * SAMPLE_CADENCE_MILLIS;
        let expected_segment_index = segment_index_at_elapsed(expected_elapsed);
        if expected_segment_index != active_segment_index {
            let previous = SUPERVISED_ENDURANCE_SEGMENTS[active_segment_index];
            let next = SUPERVISED_ENDURANCE_SEGMENTS[expected_segment_index];
            let Some(boundary) = workload_started_at.and_then(|started| {
                segment_boundary_elapsed(expected_segment_index)
                    .and_then(|elapsed| started.monotonic_millis.checked_add(elapsed))
            }) else {
                push_fault(
                    &mut faults,
                    lifecycle_not_before,
                    "endurance-segment",
                    "scheduled segment boundary overflowed",
                );
                break;
            };
            // The sample at the boundary still belongs to the ending segment and may
            // consume its full jitter allowance. Give the following transition its
            // own window, ending at the next scheduled sample.
            let Some(deadline) = boundary.checked_add(SEGMENT_TRANSITION_WINDOW_MILLIS) else {
                push_fault(
                    &mut faults,
                    lifecycle_not_before,
                    "endurance-segment",
                    "scheduled segment deadline overflowed",
                );
                break;
            };
            let requested_at = environment.timestamp();
            if requested_at.monotonic_millis < lifecycle_not_before.monotonic_millis
                || requested_at.monotonic_millis > deadline
            {
                push_fault(
                    &mut faults,
                    later_timestamp(requested_at, lifecycle_not_before),
                    "endurance-segment",
                    "endurance segment transition missed its scheduled boundary",
                );
                break;
            }
            let result = record_observer_confirmation(environment, deadline, &mut observer_checks)
                .and_then(|()| environment.begin_segment(next, deadline));
            let completed_at = environment.timestamp();
            match result {
                Ok(confirmation)
                    if segment_confirmation_matches(confirmation, next)
                        && confirmation.observed_at.monotonic_millis >= boundary
                        && confirmation.observed_at.monotonic_millis
                            >= requested_at.monotonic_millis
                        && confirmation.observed_at.monotonic_millis
                            <= completed_at.monotonic_millis
                        && completed_at.monotonic_millis <= deadline =>
                {
                    transitions.push(StateTransitionEvidence {
                        timestamp: confirmation.observed_at,
                        boot_id: None,
                        from: previous.id.into(),
                        to: next.id.into(),
                    });
                    active_segment_index = expected_segment_index;
                }
                Ok(_) => push_fault(
                    &mut faults,
                    completed_at,
                    "endurance-segment",
                    "endurance segment transition was not confirmed inside its deadline",
                ),
                Err(error) => push_fault(
                    &mut faults,
                    completed_at,
                    "endurance-segment",
                    format!("cannot change endurance segment: {error}"),
                ),
            }
            lifecycle_not_before = completed_at;
            if !faults.is_empty() {
                break;
            }
        }

        let expected_millis = workload_started_at
            .expect("sampling follows a confirmed workload start")
            .monotonic_millis
            .saturating_add(expected_elapsed);
        let deadline = expected_millis.saturating_add(SAMPLE_CADENCE_JITTER_MILLIS);
        let wait_started_at = environment.timestamp();
        if wait_started_at.monotonic_millis > deadline
            || environment.wait_until(expected_millis, deadline).is_err()
        {
            push_fault(
                &mut faults,
                wait_started_at,
                "sample-cadence",
                "cannot meet the runner-owned two-second endurance cadence",
            );
            break;
        }
        let wait_completed_at = environment.timestamp();
        if wait_completed_at.monotonic_millis < expected_millis
            || wait_completed_at.monotonic_millis > deadline
        {
            push_fault(
                &mut faults,
                wait_completed_at,
                "sample-cadence",
                "endurance wait completed outside its sample window",
            );
            break;
        }
        lifecycle_not_before = later_timestamp(wait_completed_at, lifecycle_not_before);
        match record_observer_confirmation(environment, deadline, &mut observer_checks) {
            Ok(()) => {}
            Err(error) => {
                push_fault(
                    &mut faults,
                    wait_completed_at,
                    "observer-withdrawn",
                    format!("physical safety observer is not continuously present: {error}"),
                );
                break;
            }
        }
        let mut observation = match environment.capture_observation(deadline) {
            Ok(observation) => observation,
            Err(error) => {
                push_fault(
                    &mut faults,
                    environment.timestamp(),
                    "invalid-telemetry",
                    format!("cannot capture endurance telemetry: {error}"),
                );
                break;
            }
        };
        let captured_at = environment.timestamp();
        if captured_at.monotonic_millis < wait_completed_at.monotonic_millis
            || captured_at.monotonic_millis > deadline
        {
            push_fault(
                &mut faults,
                later_timestamp(captured_at, wait_completed_at),
                "sample-cadence",
                "endurance telemetry capture did not follow its completed wait inside the sample deadline",
            );
            break;
        }
        if !sample_utilization_matches(
            &observation.sample,
            SUPERVISED_ENDURANCE_SEGMENTS[active_segment_index].load,
        ) {
            push_fault(
                &mut faults,
                captured_at,
                "endurance-segment",
                "continuous workload utilization did not match the active endurance segment",
            );
            break;
        }
        validate_observation(
            &mut observation,
            SUPERVISED_ENDURANCE_SEGMENTS[active_segment_index].power_profile,
            ObservationSchedule {
                run_started_at: started_at,
                captured_at,
                expected_millis,
            },
            &mut control_state,
            plan.tachometer_calibrations,
            &mut tachometer_state,
            &mut faults,
        );
        system_stable &= observation.system_stable;
        kernel_faults.extend(observation.kernel_faults.iter().cloned());
        nvidia_faults.extend(observation.nvidia_faults.iter().cloned());
        commands.extend(observation.commands);
        readbacks.extend(observation.readbacks);
        samples.push(observation.sample);
        lifecycle_not_before = later_timestamp(captured_at, lifecycle_not_before);
        let rolling_thermal_summary = summarize_thermal_evidence(
            &samples,
            system_stable,
            kernel_faults.clone(),
            nvidia_faults.clone(),
        );
        if let Err(error) = validate_endurance_thermal_limits_against_envelope(
            &rolling_thermal_summary,
            &samples,
            &endurance_thermal_envelope,
        ) {
            push_fault(
                &mut faults,
                captured_at,
                "qualified-thermal-envelope-abort",
                error.to_string(),
            );
            break;
        }
    }

    if faults.is_empty() {
        for fan in tachometer_state.pending_fans() {
            push_fault(
                &mut faults,
                samples
                    .last()
                    .map_or(lifecycle_not_before, |sample| sample.timestamp),
                "fan-feedback-loss",
                format!("{fan:?} fan response did not settle before endurance completion"),
            );
        }
    }

    let mut workload_stopped = false;
    {
        if custom_attempted {
            confirm_shutdown_observer(
                environment,
                &mut faults,
                &mut lifecycle_not_before,
                &mut observer_checks,
            );
        }
        let scheduled_stop_endpoint = if samples.len() == SUPERVISED_ENDURANCE_SAMPLE_COUNT {
            workload_started_at.and_then(|started| {
                started
                    .monotonic_millis
                    .checked_add(SUPERVISED_ENDURANCE_DURATION_MILLIS)
            })
        } else {
            None
        };
        let scheduled_stop_deadline = scheduled_stop_endpoint
            .and_then(|endpoint| endpoint.checked_add(OPERATION_TIMEOUT_MILLIS));
        if scheduled_stop_endpoint.is_some() {
            if scheduled_stop_deadline.is_none() {
                push_fault(
                    &mut faults,
                    lifecycle_not_before,
                    "workload-stop",
                    "scheduled workload-stop deadline overflowed",
                );
            }
            if scheduled_stop_endpoint
                .and_then(|endpoint| endpoint.checked_add(SAMPLE_CADENCE_JITTER_MILLIS))
                .is_none_or(|latest_request| lifecycle_not_before.monotonic_millis > latest_request)
            {
                push_fault(
                    &mut faults,
                    lifecycle_not_before,
                    "workload-stop",
                    "workload stop was not requested within the endpoint jitter window",
                );
            }
        }
        if let Some(stop) = perform_confirmed_stop(
            environment,
            &mut faults,
            &mut lifecycle_not_before,
            StopExpectation {
                code: "workload-stop",
                process: StoppedProcess::Workload,
                identity: workload.command.first().expect("validated command"),
                fixed_deadline: scheduled_stop_deadline,
            },
            |environment, deadline| environment.stop_workload(deadline),
        ) {
            process_stops.push(stop);
            workload_stopped = true;
        } else {
            if custom_attempted {
                confirm_shutdown_observer(
                    environment,
                    &mut faults,
                    &mut lifecycle_not_before,
                    &mut observer_checks,
                );
            }
            if let Some(stop) = perform_confirmed_stop(
                environment,
                &mut faults,
                &mut lifecycle_not_before,
                StopExpectation {
                    code: "workload-containment",
                    process: StoppedProcess::Workload,
                    identity: workload.command.first().expect("validated command"),
                    fixed_deadline: None,
                },
                |environment, deadline| environment.contain_workload(deadline),
            ) {
                process_stops.push(stop);
                workload_stopped = true;
            } else {
                if custom_attempted {
                    confirm_shutdown_observer(
                        environment,
                        &mut faults,
                        &mut lifecycle_not_before,
                        &mut observer_checks,
                    );
                }
                if let Some(stop) = perform_confirmed_stop(
                    environment,
                    &mut faults,
                    &mut lifecycle_not_before,
                    StopExpectation {
                        code: "workload-terminal-containment",
                        process: StoppedProcess::Workload,
                        identity: workload.command.first().expect("validated command"),
                        fixed_deadline: None,
                    },
                    |environment, deadline| environment.force_contain_workload(deadline),
                ) {
                    process_stops.push(stop);
                    workload_stopped = true;
                }
            }
        }
    }
    if custom_attempted && workload_stopped {
        confirm_shutdown_observer(
            environment,
            &mut faults,
            &mut lifecycle_not_before,
            &mut observer_checks,
        );
    }
    let mut service_stopped = !custom_attempted;
    if custom_attempted {
        confirm_shutdown_observer(
            environment,
            &mut faults,
            &mut lifecycle_not_before,
            &mut observer_checks,
        );
        if let Some(stop) = perform_confirmed_stop(
            environment,
            &mut faults,
            &mut lifecycle_not_before,
            StopExpectation {
                code: "service-stop",
                process: StoppedProcess::Service,
                identity: "pt31553-fan-control.service",
                fixed_deadline: None,
            },
            |environment, deadline| environment.stop_service(deadline),
        ) {
            process_stops.push(stop);
            service_stopped = true;
        } else {
            confirm_shutdown_observer(
                environment,
                &mut faults,
                &mut lifecycle_not_before,
                &mut observer_checks,
            );
            if let Some(stop) = perform_confirmed_stop(
                environment,
                &mut faults,
                &mut lifecycle_not_before,
                StopExpectation {
                    code: "service-containment",
                    process: StoppedProcess::Service,
                    identity: "pt31553-fan-control.service",
                    fixed_deadline: None,
                },
                |environment, deadline| environment.contain_service(deadline),
            ) {
                process_stops.push(stop);
                service_stopped = true;
            } else {
                confirm_shutdown_observer(
                    environment,
                    &mut faults,
                    &mut lifecycle_not_before,
                    &mut observer_checks,
                );
                if let Some(stop) = perform_confirmed_stop(
                    environment,
                    &mut faults,
                    &mut lifecycle_not_before,
                    StopExpectation {
                        code: "service-terminal-containment",
                        process: StoppedProcess::Service,
                        identity: "pt31553-fan-control.service",
                        fixed_deadline: None,
                    },
                    |environment, deadline| environment.force_contain_service(deadline),
                ) {
                    process_stops.push(stop);
                    service_stopped = true;
                }
            }
        }
    }

    if custom_attempted && service_stopped {
        confirm_shutdown_observer(
            environment,
            &mut faults,
            &mut lifecycle_not_before,
            &mut observer_checks,
        );
    }

    let both_fans_observed_auto = if workload_stopped && service_stopped {
        restore_both_fans(
            environment,
            &mut readbacks,
            &mut restoration_attempts,
            &mut faults,
            &control_state,
            &mut lifecycle_not_before,
        )
    } else {
        false
    };
    let both_fans_contained_at_maximum = if !both_fans_observed_auto {
        contain_both_fans_at_maximum(
            environment,
            &mut readbacks,
            &mut restoration_attempts,
            &mut faults,
            &control_state,
            &mut lifecycle_not_before,
        )
    } else {
        false
    };
    // This field attests the observed final hardware state, not overall run success. A failed run
    // may still truthfully confirm Auto; acceptance separately requires every safety gate.
    let final_firmware_auto_confirmed = both_fans_observed_auto;
    if custom_attempted {
        let from = transitions
            .last()
            .map_or("custom-control", |transition| transition.to.as_str())
            .to_owned();
        transitions.push(StateTransitionEvidence {
            timestamp: lifecycle_not_before,
            boot_id: None,
            from,
            to: if final_firmware_auto_confirmed {
                "firmware-auto"
            } else if both_fans_contained_at_maximum {
                "emergency-maximum-containment"
            } else {
                "restoration-failed"
            }
            .into(),
        });
    }

    let thermal_summary =
        summarize_thermal_evidence(&samples, system_stable, kernel_faults, nvidia_faults);
    if faults.is_empty() {
        validate_endurance_thermal_limits(
            &thermal_summary,
            &samples,
            plan.baselines,
            lifecycle_not_before,
            &mut faults,
        );
    }
    let observed_completed_at = environment.timestamp();
    if observed_completed_at.monotonic_millis < lifecycle_not_before.monotonic_millis {
        push_fault(
            &mut faults,
            lifecycle_not_before,
            "endurance-completion",
            "clock regressed before endurance completion",
        );
    }
    let completed_at = later_timestamp(observed_completed_at, lifecycle_not_before);
    let accepted = faults.is_empty()
        && samples.len() == SUPERVISED_ENDURANCE_SAMPLE_COUNT
        && workload_stopped
        && service_stopped
        && final_firmware_auto_confirmed;
    let reason = if accepted {
        "supervised endurance completed; unattended authorization may be published".into()
    } else {
        faults.first().map_or_else(
            || "supervised endurance incomplete".into(),
            |fault| fault.detail.clone(),
        )
    };
    let mut record = EvidenceRecord::complete_v2(
        envelope,
        "supervised-endurance",
        started_at,
        completed_at,
        RunOutcomeEvidence {
            status: if accepted {
                RunOutcomeStatus::Passed
            } else {
                RunOutcomeStatus::Failed
            },
            reason,
            another_passing_run_required: false,
            final_firmware_auto_confirmed,
        },
    );
    record.starting_conditions_captured_at = starting_conditions_captured_at;
    record.workload_started_at = workload_started_at;
    record.workload = Some(workload);
    record.samples = samples;
    record.commands = commands;
    record.readbacks = readbacks;
    record.state_transitions = transitions;
    record.faults = faults;
    record.restoration_attempts = restoration_attempts;
    record.process_stops = process_stops;
    record.thermal_summary = Some(thermal_summary);
    record.endurance_thermal_envelope = Some(endurance_thermal_envelope);
    record.endurance_observer_attestation = (custom_attempted
        && service_stopped
        && record.faults.is_empty()
        && observer_checks.len() >= 2)
        .then(|| EnduranceObserverAttestationEvidence {
            started_at: observer_checks[0],
            completed_at: *observer_checks
                .last()
                .expect("at least two observer checks"),
            checks: observer_checks,
        });
    record.prerequisite_binding_sha256 = Some(plan.prerequisite_binding_sha256.clone());
    record
        .validate()
        .map_err(SupervisedEndurancePlanError::InvalidGeneratedEvidence)?;
    Ok(SupervisedEnduranceReport { record })
}

pub(crate) fn validate_qualification_plan(
    plan: &SupervisedEndurancePlan<'_>,
) -> Result<QualificationEnvelopeIdentityV1, SupervisedEndurancePlanError> {
    validate_required_record("preflight", plan.preflight, "preflight")?;
    if !plan.preflight.faults.is_empty() {
        return Err(invalid_artifact(
            "preflight",
            "fault-free preflight evidence is required",
        ));
    }
    let envelope = plan.preflight.qualification_envelope.clone();

    for (fan, calibration) in [
        (EvidenceFan::Cpu, plan.tachometer_calibrations.cpu),
        (EvidenceFan::Gpu, plan.tachometer_calibrations.gpu),
    ] {
        let baseline = plan
            .baselines
            .first()
            .copied()
            .ok_or_else(|| matrix_error("seven Firmware Auto baselines are required"))?;
        if !calibration_record_is_qualified(calibration, fan, baseline) {
            return Err(invalid_artifact(
                &format!("{fan:?} calibration"),
                "complete passing calibration for the qualification envelope is required",
            ));
        }
    }

    validate_required_record("live lifecycle", plan.live_lifecycle, "live-lifecycle")?;
    if !crate::live_lifecycle::live_lifecycle_is_complete(plan.live_lifecycle) {
        return Err(invalid_artifact(
            "live lifecycle",
            "all lifecycle cases must pass",
        ));
    }

    let mut baselines = HashMap::new();
    let mut baseline_measurements = HashSet::new();
    for (index, baseline) in plan.baselines.iter().copied().enumerate() {
        validate_required_record(
            &format!("baseline {index}"),
            baseline,
            "firmware-auto-baseline",
        )?;
        require_envelope(&envelope, baseline, &format!("baseline {index}"))?;
        let key = workload_key(baseline).ok_or_else(|| {
            matrix_error(format!(
                "baseline {index} has an unsupported workload/profile"
            ))
        })?;
        if !WorkloadKey::expected().contains(&key) {
            return Err(matrix_error(format!(
                "baseline {index} is outside the required matrix"
            )));
        }
        if !baseline_measurements.insert(baseline_measurement_fingerprint(baseline)) {
            return Err(matrix_error(format!(
                "baseline {index} reuses an earlier measurement transcript"
            )));
        }
        let required_samples = (key.required_duration_millis() / SAMPLE_CADENCE_MILLIS) as usize;
        if baseline.samples.len() != required_samples
            || baseline
                .workload_started_at
                .zip(baseline.samples.last().map(|sample| sample.timestamp))
                .is_none_or(|(started, last)| {
                    last.monotonic_millis
                        .saturating_sub(started.monotonic_millis)
                        != key.required_duration_millis()
                })
        {
            return Err(matrix_error(format!(
                "baseline {index} does not cover the exact required duration"
            )));
        }
        if baselines.insert(key, baseline).is_some() {
            return Err(matrix_error(format!(
                "duplicate {:?}/{:?} baseline",
                key.profile, key.class
            )));
        }
    }
    if baselines.len() != WorkloadKey::expected().len()
        || WorkloadKey::expected()
            .iter()
            .any(|key| !baselines.contains_key(key))
    {
        return Err(matrix_error(
            "the seven required Firmware Auto baselines are not complete",
        ));
    }

    let mut run_counts = HashMap::<WorkloadKey, usize>::new();
    let mut final_run_counts = HashMap::<WorkloadKey, usize>::new();
    let mut run_fingerprints = HashSet::new();
    for (index, run) in plan.matched_workload_runs.iter().copied().enumerate() {
        validate_required_record(&format!("matched run {index}"), run, "matched-workload")?;
        require_envelope(&envelope, run, &format!("matched run {index}"))?;
        let key = workload_key(run).ok_or_else(|| {
            matrix_error(format!(
                "matched run {index} has an unsupported workload/profile"
            ))
        })?;
        let baseline = baselines
            .get(&key)
            .ok_or_else(|| matrix_error(format!("matched run {index} has no required baseline")))?;
        if !matched_workload_is_complete(run)
            || run.baseline_binding_sha256.as_deref()
                != Some(baseline_fingerprint(baseline).as_str())
            || !matched_workload_matches_baseline(run, baseline)
            || !matched_workload_matches_calibrations(run, plan.tachometer_calibrations)
        {
            return Err(invalid_artifact(
                &format!("matched run {index}"),
                "run is not a complete match for its baseline and calibrations",
            ));
        }
        let fingerprint = matched_run_fingerprint(run);
        if !run_fingerprints.insert(fingerprint) {
            return Err(matrix_error(format!(
                "matched run {index} duplicates an earlier artifact"
            )));
        }
        *run_counts.entry(key).or_default() += 1;
        if !run.outcome.another_passing_run_required {
            *final_run_counts.entry(key).or_default() += 1;
        }
    }
    for key in WorkloadKey::expected() {
        let required_runs = key.class.required_passing_runs();
        if run_counts.get(&key).copied().unwrap_or_default() != required_runs
            || final_run_counts.get(&key).copied().unwrap_or_default() == 0
        {
            return Err(matrix_error(format!(
                "{:?}/{:?} requires exactly {} passing Custom runs ending in a final run",
                key.profile, key.class, required_runs
            )));
        }
    }

    for (artifact, record) in [
        ("live lifecycle", plan.live_lifecycle),
        ("CPU calibration", plan.tachometer_calibrations.cpu),
        ("GPU calibration", plan.tachometer_calibrations.gpu),
    ] {
        require_envelope(&envelope, record, artifact)?;
    }
    endurance_thermal_envelope(plan.baselines)?;
    Ok(envelope)
}

fn validate_required_record(
    artifact: &str,
    record: &EvidenceRecord,
    stage: &str,
) -> Result<(), SupervisedEndurancePlanError> {
    record
        .validate()
        .map_err(|error| invalid_artifact(artifact, error.to_string()))?;
    if record.schema_version != EVIDENCE_SCHEMA_VERSION_V2
        || record.record_status != EvidenceRecordStatus::Complete
        || record.stage != stage
        || record.outcome.status != RunOutcomeStatus::Passed
        || (stage != "matched-workload" && record.outcome.another_passing_run_required)
        || !record.outcome.final_firmware_auto_confirmed
    {
        return Err(invalid_artifact(
            artifact,
            "complete passing V2 evidence ending in Firmware Auto is required",
        ));
    }
    Ok(())
}

fn require_envelope(
    expected: &QualificationEnvelopeIdentityV1,
    record: &EvidenceRecord,
    artifact: &str,
) -> Result<(), SupervisedEndurancePlanError> {
    if &record.qualification_envelope != expected {
        return Err(invalid_artifact(
            artifact,
            "qualification envelope does not match preflight",
        ));
    }
    Ok(())
}

fn workload_key(record: &EvidenceRecord) -> Option<WorkloadKey> {
    record.workload.as_ref().and_then(|workload| {
        let class = MatchedWorkloadClass::from_workload_id(&workload.workload_id)?;
        let expected_command = match (workload.workload_id.as_str(), workload.power_profile) {
            ("idle-ac-v1", EvidenceProfile::Ac) | ("idle-battery-v1", EvidenceProfile::Battery) => {
                ["/usr/lib/pt31553-fan-control/workloads/idle", "--fixed"]
            }
            ("cpu-ac-v1", EvidenceProfile::Ac) | ("cpu-battery-v1", EvidenceProfile::Battery) => {
                ["/usr/lib/pt31553-fan-control/workloads/cpu", "--fixed"]
            }
            ("gpu-ac-v1", EvidenceProfile::Ac) | ("gpu-battery-v1", EvidenceProfile::Battery) => {
                ["/usr/lib/pt31553-fan-control/workloads/gpu", "--fixed"]
            }
            ("combined-ac-v1", EvidenceProfile::Ac) => {
                ["/usr/lib/pt31553-fan-control/workloads/combined", "--fixed"]
            }
            _ => return None,
        };
        let canonical = workload.version == QUALIFICATION_WORKLOAD_VERSION
            && workload
                .command
                .iter()
                .map(String::as_str)
                .eq(expected_command);
        canonical.then_some(WorkloadKey {
            profile: workload.power_profile,
            class,
        })
    })
}

fn validate_endurance_workload(
    workload: &WorkloadEvidence,
) -> Result<(), SupervisedEndurancePlanError> {
    validate_workload(workload).map_err(|error| SupervisedEndurancePlanError::InvalidWorkload {
        reason: error.to_string(),
    })?;
    if !canonical_endurance_workload(workload) {
        return Err(SupervisedEndurancePlanError::InvalidWorkload {
            reason: "the canonical supervised mixed workload must start on AC".into(),
        });
    }
    Ok(())
}

fn canonical_endurance_workload(workload: &WorkloadEvidence) -> bool {
    workload.workload_id == SUPERVISED_ENDURANCE_WORKLOAD_ID
        && workload.power_profile == EvidenceProfile::Ac
        && workload.version == QUALIFICATION_WORKLOAD_VERSION
        && workload
            .command
            .iter()
            .map(String::as_str)
            .eq(["/usr/lib/pt31553-fan-control/workloads/mixed", "--fixed"])
}

fn invalid_artifact(artifact: &str, reason: impl Into<String>) -> SupervisedEndurancePlanError {
    SupervisedEndurancePlanError::InvalidQualificationEvidence {
        artifact: artifact.to_owned(),
        reason: reason.into(),
    }
}

fn matrix_error(reason: impl Into<String>) -> SupervisedEndurancePlanError {
    SupervisedEndurancePlanError::IncompleteWorkloadMatrix {
        reason: reason.into(),
    }
}

fn later_timestamp(left: EvidenceTimestamp, right: EvidenceTimestamp) -> EvidenceTimestamp {
    if left.monotonic_millis >= right.monotonic_millis {
        left
    } else {
        right
    }
}

fn operation_deadline(
    requested_at: EvidenceTimestamp,
    faults: &mut Vec<FaultEvidence>,
    code: &str,
) -> Option<u64> {
    requested_at
        .monotonic_millis
        .checked_add(OPERATION_TIMEOUT_MILLIS)
        .or_else(|| {
            push_fault(faults, requested_at, code, "operation deadline overflowed");
            None
        })
}

fn observer_bounded_deadline(
    requested_at: EvidenceTimestamp,
    faults: &mut Vec<FaultEvidence>,
    code: &str,
) -> Option<u64> {
    operation_deadline(requested_at, faults, code).map(|deadline| {
        deadline.min(
            requested_at
                .monotonic_millis
                .saturating_add(crate::LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS),
        )
    })
}

fn record_observer_confirmation<E>(
    environment: &mut E,
    deadline: u64,
    checks: &mut Vec<EvidenceTimestamp>,
) -> Result<(), String>
where
    E: SupervisedEnduranceEnvironment + ?Sized,
{
    let requested_at = environment.timestamp();
    let observed_at = environment.confirm_observer(deadline)?;
    let completed_at = environment.timestamp();
    let follows_previous = checks.last().is_none_or(|previous| {
        observed_at.monotonic_millis > previous.monotonic_millis
            && observed_at.wall_unix_millis > previous.wall_unix_millis
            && observed_at.monotonic_millis - previous.monotonic_millis <= 5_000
            && observed_at
                .wall_unix_millis
                .checked_sub(previous.wall_unix_millis)
                .is_some_and(|gap| gap <= 5_000)
    });
    if requested_at.monotonic_millis > deadline
        || completed_at.monotonic_millis > deadline
        || observed_at.monotonic_millis < requested_at.monotonic_millis
        || observed_at.wall_unix_millis < requested_at.wall_unix_millis
        || observed_at.monotonic_millis > completed_at.monotonic_millis
        || observed_at.wall_unix_millis > completed_at.wall_unix_millis
        || !follows_previous
    {
        return Err("observer confirmation was stale, replayed, or outside its call window".into());
    }
    checks.push(observed_at);
    Ok(())
}

fn confirm_shutdown_observer<E>(
    environment: &mut E,
    faults: &mut Vec<FaultEvidence>,
    not_before: &mut EvidenceTimestamp,
    checks: &mut Vec<EvidenceTimestamp>,
) where
    E: SupervisedEnduranceEnvironment + ?Sized,
{
    let requested_at = environment.timestamp();
    let deadline = observer_bounded_deadline(requested_at, faults, "observer-shutdown-boundary");
    if let Some(deadline) = deadline {
        if let Err(error) = record_observer_confirmation(environment, deadline, checks) {
            push_fault(
                faults,
                requested_at,
                "observer-withdrawn",
                format!(
                    "physical safety observer was not present through service shutdown: {error}"
                ),
            );
        }
    }
    *not_before = later_timestamp(environment.timestamp(), *not_before);
}

fn segment_index_at_elapsed(elapsed_millis: u64) -> usize {
    let mut end = 0;
    for (index, segment) in SUPERVISED_ENDURANCE_SEGMENTS.iter().enumerate() {
        end += segment.duration_millis;
        if elapsed_millis <= end {
            return index;
        }
    }
    SUPERVISED_ENDURANCE_SEGMENTS.len() - 1
}

fn segment_boundary_elapsed(segment_index: usize) -> Option<u64> {
    SUPERVISED_ENDURANCE_SEGMENTS
        .get(..segment_index)?
        .iter()
        .try_fold(0u64, |elapsed, segment| {
            elapsed.checked_add(segment.duration_millis)
        })
}

fn segment_confirmation_matches(
    confirmation: SupervisedEnduranceSegmentConfirmation,
    segment: SupervisedEnduranceSegment,
) -> bool {
    segment_state_confirmation_matches(confirmation, segment)
        && match segment.load {
            SupervisedEnduranceLoad::Load => {
                confirmation.cpu_utilization_basis_points >= LOAD_MINIMUM_UTILIZATION_BASIS_POINTS
                    && confirmation.gpu_utilization_basis_points
                        >= LOAD_MINIMUM_UTILIZATION_BASIS_POINTS
            }
            SupervisedEnduranceLoad::Idle => {
                confirmation.cpu_utilization_basis_points <= IDLE_MAXIMUM_UTILIZATION_BASIS_POINTS
                    && confirmation.gpu_utilization_basis_points
                        <= IDLE_MAXIMUM_UTILIZATION_BASIS_POINTS
            }
        }
}

fn segment_state_confirmation_matches(
    confirmation: SupervisedEnduranceSegmentConfirmation,
    segment: SupervisedEnduranceSegment,
) -> bool {
    confirmation.load == segment.load
        && confirmation.selected_profile == segment.power_profile
        && confirmation.external_power
            == match segment.power_profile {
                EvidenceProfile::Ac => EvidenceExternalPower::Ac,
                EvidenceProfile::Battery => EvidenceExternalPower::Battery,
            }
        && confirmation.cpu_utilization_basis_points <= 10_000
        && confirmation.gpu_utilization_basis_points <= 10_000
}

fn sample_utilization_matches(
    sample: &crate::TelemetrySampleEvidence,
    load: SupervisedEnduranceLoad,
) -> bool {
    let (Some(cpu), Some(gpu)) = (
        sample.cpu_utilization_basis_points,
        sample.gpu_utilization_basis_points,
    ) else {
        return false;
    };
    if cpu > 10_000 || gpu > 10_000 {
        return false;
    }
    match load {
        SupervisedEnduranceLoad::Load => {
            cpu >= LOAD_MINIMUM_UTILIZATION_BASIS_POINTS
                && gpu >= LOAD_MINIMUM_UTILIZATION_BASIS_POINTS
        }
        SupervisedEnduranceLoad::Idle => {
            cpu <= IDLE_MAXIMUM_UTILIZATION_BASIS_POINTS
                && gpu <= IDLE_MAXIMUM_UTILIZATION_BASIS_POINTS
        }
    }
}

struct StopExpectation<'a> {
    code: &'a str,
    process: StoppedProcess,
    identity: &'a str,
    fixed_deadline: Option<u64>,
}

fn perform_confirmed_stop<E>(
    environment: &mut E,
    faults: &mut Vec<FaultEvidence>,
    not_before: &mut EvidenceTimestamp,
    expectation: StopExpectation<'_>,
    stop: impl FnOnce(&mut E, u64) -> Result<SupervisedEnduranceProcessStopConfirmation, String>,
) -> Option<ProcessStopEvidence>
where
    E: SupervisedEnduranceEnvironment + ?Sized,
{
    let StopExpectation {
        code,
        process,
        identity: expected_identity,
        fixed_deadline,
    } = expectation;
    let observed_at = environment.timestamp();
    if observed_at.monotonic_millis < not_before.monotonic_millis {
        push_fault(
            faults,
            *not_before,
            code,
            "clock regressed before stop operation",
        );
    }
    let requested_at = later_timestamp(observed_at, *not_before);
    let deadline = if let Some(deadline) = fixed_deadline {
        deadline
    } else {
        operation_deadline(requested_at, faults, code).unwrap_or(requested_at.monotonic_millis)
    }
    .min(
        requested_at
            .monotonic_millis
            .saturating_add(crate::LIVE_OBSERVER_MAX_CHECK_GAP_MILLIS),
    );
    if requested_at.monotonic_millis > deadline {
        push_fault(
            faults,
            requested_at,
            code,
            "stop operation missed its scheduled deadline",
        );
    }
    let result = stop(environment, deadline);
    let observed_completed_at = environment.timestamp();
    if observed_completed_at.monotonic_millis < requested_at.monotonic_millis {
        push_fault(
            faults,
            requested_at,
            code,
            "clock regressed during stop operation",
        );
    }
    let completed_at = later_timestamp(observed_completed_at, requested_at);
    if completed_at.monotonic_millis > deadline {
        push_fault(
            faults,
            completed_at,
            code,
            "stop operation exceeded its deadline",
        );
    }
    let evidence = match result {
        Ok(confirmation)
            if !confirmation.running
                && confirmation.process_identity == expected_identity
                && confirmation.observed_at.monotonic_millis >= requested_at.monotonic_millis
                && confirmation.observed_at.monotonic_millis <= completed_at.monotonic_millis
                && completed_at.monotonic_millis <= deadline =>
        {
            Some(ProcessStopEvidence {
                process,
                process_identity: confirmation.process_identity,
                requested_at,
                confirmed_at: confirmation.observed_at,
                running: false,
            })
        }
        Ok(_) => {
            push_fault(
                faults,
                completed_at,
                code,
                "stop postcondition was not confirmed for the expected process",
            );
            None
        }
        Err(error) => {
            push_fault(
                faults,
                completed_at,
                code,
                format!("stop operation failed: {error}"),
            );
            None
        }
    };
    *not_before = completed_at;
    evidence
}

fn restore_both_fans<E>(
    environment: &mut E,
    readbacks: &mut Vec<FanReadbackEvidence>,
    attempts: &mut Vec<RestorationAttemptEvidence>,
    faults: &mut Vec<FaultEvidence>,
    control: &ControlEvidenceState,
    not_before: &mut EvidenceTimestamp,
) -> bool
where
    E: SupervisedEnduranceEnvironment + ?Sized,
{
    let mut restored = true;
    for fan in [EvidenceFan::Cpu, EvidenceFan::Gpu] {
        let observed_at = environment.timestamp();
        if observed_at.monotonic_millis < not_before.monotonic_millis {
            push_fault(
                faults,
                *not_before,
                "firmware-auto-restoration",
                "clock regressed before fan restoration",
            );
        }
        let requested_at = later_timestamp(observed_at, *not_before);
        let deadline = requested_at
            .monotonic_millis
            .checked_add(RESTORATION_TIMEOUT_MILLIS);
        let deadline_is_valid = deadline.is_some();
        if deadline.is_none() {
            push_fault(
                faults,
                requested_at,
                "firmware-auto-restoration",
                "fan restoration deadline overflowed",
            );
        }
        let deadline = deadline.unwrap_or(requested_at.monotonic_millis);
        let result = environment.restore_fan(fan, deadline);
        let observed_completed_at = environment.timestamp();
        if observed_completed_at.monotonic_millis < requested_at.monotonic_millis {
            push_fault(
                faults,
                requested_at,
                "firmware-auto-restoration",
                "clock regressed during fan restoration",
            );
        }
        let completed_at = later_timestamp(observed_completed_at, requested_at);
        let endpoint_identity_is_trusted = !result.endpoint_identity.trim().is_empty()
            && control
                .endpoint_identity(fan, FanReadbackField::Enable)
                .is_none_or(|identity| identity == result.endpoint_identity);
        let confirmed = result.auto_write_succeeded
            && result.enable_readback == Some(2)
            && result.outcome == RestorationOutcome::FirmwareAutoConfirmed
            && endpoint_identity_is_trusted
            && deadline_is_valid
            && completed_at.monotonic_millis <= deadline;
        restored &= confirmed;
        attempts.push(RestorationAttemptEvidence {
            timestamp: completed_at,
            fan,
            auto_write_succeeded: result.auto_write_succeeded,
            enable_readback: result.enable_readback,
            outcome: if confirmed {
                RestorationOutcome::FirmwareAutoConfirmed
            } else if result.outcome == RestorationOutcome::ContainmentFailed {
                RestorationOutcome::ContainmentFailed
            } else {
                RestorationOutcome::FirmwareAutoUnconfirmed
            },
        });
        readbacks.push(FanReadbackEvidence {
            timestamp: completed_at,
            source_timestamp: None,
            fresh: None,
            boot_id: None,
            fan,
            field: FanReadbackField::Enable,
            value: result.enable_readback,
            endpoint_identity: result.endpoint_identity,
            outcome: if confirmed {
                ObservationOutcome::Confirmed
            } else if result.enable_readback.is_some() {
                ObservationOutcome::Unexpected
            } else {
                ObservationOutcome::Unreadable
            },
            phase: Some(crate::FanReadbackPhase::Final),
        });
        if !confirmed {
            push_fault(
                faults,
                completed_at,
                "firmware-auto-unconfirmed",
                format!("{fan:?} fan was not independently confirmed in Firmware Auto"),
            );
        }
        *not_before = completed_at;
    }
    restored
}

fn contain_both_fans_at_maximum<E>(
    environment: &mut E,
    readbacks: &mut Vec<FanReadbackEvidence>,
    attempts: &mut Vec<RestorationAttemptEvidence>,
    faults: &mut Vec<FaultEvidence>,
    control: &ControlEvidenceState,
    not_before: &mut EvidenceTimestamp,
) -> bool
where
    E: SupervisedEnduranceEnvironment + ?Sized,
{
    let mut contained = true;
    for fan in [EvidenceFan::Cpu, EvidenceFan::Gpu] {
        let requested_at = later_timestamp(environment.timestamp(), *not_before);
        let deadline = requested_at
            .monotonic_millis
            .checked_add(RESTORATION_TIMEOUT_MILLIS);
        if deadline.is_none() {
            push_fault(
                faults,
                requested_at,
                "emergency-maximum-containment",
                "fan containment deadline overflowed",
            );
        }
        let deadline = deadline.unwrap_or(requested_at.monotonic_millis);
        let result = environment.contain_fan_at_maximum(fan, deadline);
        let completed_at = later_timestamp(environment.timestamp(), requested_at);
        let enable_identity_is_trusted = !result.enable_endpoint_identity.trim().is_empty()
            && control.endpoint_identity(fan, FanReadbackField::Enable)
                == Some(result.enable_endpoint_identity.as_str());
        let pwm_identity_is_trusted = !result.pwm_endpoint_identity.trim().is_empty()
            && control.endpoint_identity(fan, FanReadbackField::Pwm)
                == Some(result.pwm_endpoint_identity.as_str());
        let confirmed = result.outcome == RestorationOutcome::MaximumContainmentConfirmed
            && result.enable_readback == Some(1)
            && result.pwm_write_succeeded
            && result.pwm_readback == Some(u8::MAX.into())
            && enable_identity_is_trusted
            && pwm_identity_is_trusted
            && completed_at.monotonic_millis <= deadline;
        contained &= confirmed;
        attempts.push(RestorationAttemptEvidence {
            timestamp: completed_at,
            fan,
            auto_write_succeeded: false,
            enable_readback: result.enable_readback,
            outcome: if confirmed {
                RestorationOutcome::MaximumContainmentConfirmed
            } else {
                RestorationOutcome::ContainmentFailed
            },
        });
        readbacks.push(FanReadbackEvidence {
            timestamp: completed_at,
            source_timestamp: None,
            fresh: None,
            boot_id: None,
            fan,
            field: FanReadbackField::Enable,
            value: result.enable_readback,
            endpoint_identity: result.enable_endpoint_identity,
            outcome: if result.enable_readback == Some(1) && enable_identity_is_trusted {
                ObservationOutcome::Confirmed
            } else if result.enable_readback.is_some() {
                ObservationOutcome::Unexpected
            } else {
                ObservationOutcome::Unreadable
            },
            phase: Some(crate::FanReadbackPhase::Final),
        });
        readbacks.push(FanReadbackEvidence {
            timestamp: completed_at,
            source_timestamp: None,
            fresh: None,
            boot_id: None,
            fan,
            field: FanReadbackField::Pwm,
            value: result.pwm_readback,
            endpoint_identity: result.pwm_endpoint_identity,
            outcome: if result.pwm_write_succeeded
                && result.pwm_readback == Some(u8::MAX.into())
                && pwm_identity_is_trusted
            {
                ObservationOutcome::Confirmed
            } else if result.pwm_readback.is_some() {
                ObservationOutcome::Unexpected
            } else {
                ObservationOutcome::Unreadable
            },
            phase: Some(crate::FanReadbackPhase::Final),
        });
        push_fault(
            faults,
            completed_at,
            "firmware-auto-unconfirmed",
            if confirmed {
                format!(
                    "{fan:?} fan used explicit maximum containment because workload absence was unconfirmed"
                )
            } else {
                format!(
                    "{fan:?} fan could not be placed in explicit maximum containment after workload termination failed"
                )
            },
        );
        *not_before = completed_at;
    }
    contained
}

fn validate_endurance_thermal_limits(
    summary: &ThermalSummaryEvidence,
    samples: &[crate::TelemetrySampleEvidence],
    baselines: &[&EvidenceRecord],
    timestamp: EvidenceTimestamp,
    faults: &mut Vec<FaultEvidence>,
) {
    if let Err(error) =
        validate_endurance_thermal_limits_against_baselines(summary, samples, baselines)
    {
        push_fault(faults, timestamp, "thermal-envelope", error.to_string());
    }
}

pub(crate) fn validate_endurance_thermal_limits_against_baselines(
    summary: &ThermalSummaryEvidence,
    samples: &[crate::TelemetrySampleEvidence],
    baselines: &[&EvidenceRecord],
) -> Result<(), SupervisedEndurancePlanError> {
    let envelope = endurance_thermal_envelope(baselines)?;
    validate_endurance_thermal_limits_against_envelope(summary, samples, &envelope)
}

pub(crate) fn endurance_thermal_envelope(
    baselines: &[&EvidenceRecord],
) -> Result<EnduranceThermalEnvelopeEvidence, SupervisedEndurancePlanError> {
    let summaries = baselines
        .iter()
        .filter_map(|record| record.thermal_summary.as_ref())
        .collect::<Vec<_>>();
    let maxima = (
        summaries
            .iter()
            .map(|value| value.cpu_peak_millicelsius)
            .max(),
        summaries
            .iter()
            .map(|value| value.gpu_peak_millicelsius)
            .max(),
        summaries
            .iter()
            .map(|value| value.cpu_p95_millicelsius)
            .max(),
        summaries
            .iter()
            .map(|value| value.gpu_p95_millicelsius)
            .max(),
    );
    let (Some(cpu_peak), Some(gpu_peak), Some(cpu_p95), Some(gpu_p95)) = maxima else {
        return Err(matrix_error("all baselines require thermal summaries"));
    };
    let add_margin = |value: i32, limit: i32, field: &'static str| {
        value
            .checked_add(THERMAL_COMPARISON_MARGIN_MILLICELSIUS)
            .filter(|derived| *derived > 0 && *derived < limit)
            .ok_or_else(|| {
                invalid_artifact(
                    "baseline thermal envelope",
                    format!("{field} plus comparison margin exceeds the supported limit"),
                )
            })
    };
    Ok(EnduranceThermalEnvelopeEvidence {
        cpu_peak_limit_millicelsius: add_margin(
            cpu_peak,
            CPU_ABSOLUTE_ABORT_MILLICELSIUS,
            "CPU peak",
        )?,
        gpu_peak_limit_millicelsius: add_margin(
            gpu_peak,
            crate::GPU_ABSOLUTE_ABORT_MILLICELSIUS,
            "GPU peak",
        )?,
        cpu_p95_limit_millicelsius: add_margin(
            cpu_p95,
            CPU_ABSOLUTE_ABORT_MILLICELSIUS,
            "CPU p95",
        )?,
        gpu_p95_limit_millicelsius: add_margin(
            gpu_p95,
            crate::GPU_ABSOLUTE_ABORT_MILLICELSIUS,
            "GPU p95",
        )?,
    })
}

fn validate_endurance_thermal_limits_against_envelope(
    summary: &ThermalSummaryEvidence,
    samples: &[crate::TelemetrySampleEvidence],
    envelope: &EnduranceThermalEnvelopeEvidence,
) -> Result<(), SupervisedEndurancePlanError> {
    let slopes = precise_final_thermal_slopes(samples);
    if envelope.cpu_peak_limit_millicelsius >= CPU_ABSOLUTE_ABORT_MILLICELSIUS
        || envelope.gpu_peak_limit_millicelsius >= crate::GPU_ABSOLUTE_ABORT_MILLICELSIUS
        || envelope.cpu_p95_limit_millicelsius > envelope.cpu_peak_limit_millicelsius
        || envelope.gpu_p95_limit_millicelsius > envelope.gpu_peak_limit_millicelsius
        || summary.system_stable != Some(true)
        || !summary.kernel_faults.is_empty()
        || !summary.nvidia_faults.is_empty()
        || summary.cpu_peak_millicelsius > envelope.cpu_peak_limit_millicelsius
        || summary.gpu_peak_millicelsius > envelope.gpu_peak_limit_millicelsius
        || summary.cpu_p95_millicelsius > envelope.cpu_p95_limit_millicelsius
        || summary.gpu_p95_millicelsius > envelope.gpu_p95_limit_millicelsius
        || slopes.0 > THERMAL_SLOPE_LIMIT_MILLICELSIUS_PER_MINUTE
        || slopes.1 > THERMAL_SLOPE_LIMIT_MILLICELSIUS_PER_MINUTE
    {
        return Err(invalid_artifact(
            "supervised endurance",
            "thermal or stability envelope was exceeded",
        ));
    }
    Ok(())
}

pub(crate) fn supervised_endurance_is_complete(record: &EvidenceRecord) -> bool {
    let (Some(workload_started_at), Some(starting_conditions_captured_at)) = (
        record.workload_started_at,
        record.starting_conditions_captured_at,
    ) else {
        return false;
    };
    let expected_transitions = SUPERVISED_ENDURANCE_SEGMENTS.len() + 2;
    let schedule_matches = record.samples.iter().enumerate().all(|(index, sample)| {
        let elapsed = (index as u64 + 1) * SAMPLE_CADENCE_MILLIS;
        let segment = SUPERVISED_ENDURANCE_SEGMENTS[segment_index_at_elapsed(elapsed)];
        workload_started_at
            .monotonic_millis
            .checked_add(elapsed)
            .is_some_and(|expected| {
                sample.timestamp.monotonic_millis.abs_diff(expected) <= SAMPLE_CADENCE_JITTER_MILLIS
            })
            && sample.freshness == SampleFreshness::Fresh
            && sample.external_power
                == Some(match segment.power_profile {
                    EvidenceProfile::Ac => EvidenceExternalPower::Ac,
                    EvidenceProfile::Battery => EvidenceExternalPower::Battery,
                })
            && sample.selected_profile == Some(segment.power_profile)
            && sample_utilization_matches(sample, segment.load)
            && sample.cpu_millicelsius.is_some_and(|value| {
                plausible_temperature(value, MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS)
                    && value < CPU_ABSOLUTE_ABORT_MILLICELSIUS
            })
            && sample.gpu_millicelsius.is_some_and(|value| {
                plausible_temperature(value, MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS)
                    && value < crate::GPU_ABSOLUTE_ABORT_MILLICELSIUS
            })
            && sample.cpu_thermal_throttling == Some(false)
            && sample.gpu_thermal_throttling == Some(false)
    });
    let transition_names_match = record
        .state_transitions
        .first()
        .is_some_and(|value| value.from == "firmware-auto" && value.to == "custom-control")
        && record.state_transitions.get(1).is_some_and(|value| {
            value.from == "custom-control" && value.to == SUPERVISED_ENDURANCE_SEGMENTS[0].id
        })
        && SUPERVISED_ENDURANCE_SEGMENTS
            .windows(2)
            .enumerate()
            .all(|(index, pair)| {
                record
                    .state_transitions
                    .get(index + 2)
                    .is_some_and(|value| value.from == pair[0].id && value.to == pair[1].id)
            })
        && record.state_transitions.last().is_some_and(|value| {
            value.from == SUPERVISED_ENDURANCE_SEGMENTS.last().unwrap().id
                && value.to == "firmware-auto"
        });
    let transition_timestamps_match = record.state_transitions.first().is_some_and(|entered| {
        record.started_at.monotonic_millis <= starting_conditions_captured_at.monotonic_millis
            && starting_conditions_captured_at.monotonic_millis
                <= entered.timestamp.monotonic_millis
            && record.state_transitions.get(1).is_some_and(|initial| {
                entered.timestamp.monotonic_millis <= initial.timestamp.monotonic_millis
                    && initial.timestamp.monotonic_millis <= workload_started_at.monotonic_millis
            })
    }) && SUPERVISED_ENDURANCE_SEGMENTS
        .iter()
        .enumerate()
        .skip(1)
        .all(|(segment_index, _)| {
            workload_started_at
                .monotonic_millis
                .checked_add(
                    segment_boundary_elapsed(segment_index)
                        .expect("known endurance segment has a boundary"),
                )
                .is_some_and(|boundary| {
                    record
                        .state_transitions
                        .get(segment_index + 1)
                        .is_some_and(|transition| {
                            transition.timestamp.monotonic_millis >= boundary
                                && transition.timestamp.monotonic_millis
                                    <= boundary.saturating_add(SEGMENT_TRANSITION_WINDOW_MILLIS)
                        })
                })
        })
        && record
            .state_transitions
            .windows(2)
            .all(|pair| pair[0].timestamp.monotonic_millis <= pair[1].timestamp.monotonic_millis)
        && record.state_transitions.last().is_some_and(|restored| {
            record.samples.last().is_some_and(|sample| {
                sample.timestamp.monotonic_millis <= restored.timestamp.monotonic_millis
                    && restored.timestamp.monotonic_millis <= record.completed_at.monotonic_millis
            })
        });
    let control_evidence_matches = matched_control_evidence_is_complete(record);
    let cleanup_matches = matches!(record.process_stops.as_slice(), [workload_stop, service_stop]
    if workload_stop.process == StoppedProcess::Workload
        && workload_stop.process_identity == "/usr/lib/pt31553-fan-control/workloads/mixed"
        && !workload_stop.running
        && service_stop.process == StoppedProcess::Service
        && service_stop.process_identity == "pt31553-fan-control.service"
        && !service_stop.running
        && workload_started_at.monotonic_millis
            .checked_add(SUPERVISED_ENDURANCE_DURATION_MILLIS)
            .is_some_and(|endpoint| {
                workload_stop.requested_at.monotonic_millis >= endpoint
                    && workload_stop.requested_at.monotonic_millis
                        <= endpoint.saturating_add(SAMPLE_CADENCE_JITTER_MILLIS)
            })
        && workload_stop.confirmed_at.monotonic_millis
            <= workload_stop.requested_at.monotonic_millis
                .saturating_add(OPERATION_TIMEOUT_MILLIS)
        && workload_stop.confirmed_at.monotonic_millis
            <= service_stop.requested_at.monotonic_millis
        && service_stop.confirmed_at.monotonic_millis
            <= service_stop.requested_at.monotonic_millis
                .saturating_add(OPERATION_TIMEOUT_MILLIS)
        && record.restoration_attempts.iter().all(|attempt| {
            service_stop.confirmed_at.monotonic_millis
                <= attempt.timestamp.monotonic_millis
        })
        && record
            .readbacks
            .iter()
            .filter(|readback| readback.phase == Some(crate::FanReadbackPhase::Final))
            .all(|readback| {
                service_stop.confirmed_at.monotonic_millis
                    <= readback.timestamp.monotonic_millis
            })
        && record.state_transitions.last().is_some_and(|restored| {
            service_stop.confirmed_at.monotonic_millis
                <= restored.timestamp.monotonic_millis
        }));
    let starting_temperatures_are_safe = record.workload.as_ref().is_some_and(|workload| {
        plausible_temperature(
            workload.ambient_millicelsius,
            MAX_PLAUSIBLE_AMBIENT_MILLICELSIUS,
        ) && plausible_temperature(
            workload.starting_cpu_millicelsius,
            MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
        ) && plausible_temperature(
            workload.starting_gpu_millicelsius,
            MAX_PLAUSIBLE_COMPONENT_TEMPERATURE_MILLICELSIUS,
        ) && workload.starting_cpu_millicelsius < CPU_ABSOLUTE_ABORT_MILLICELSIUS
            && workload.starting_gpu_millicelsius < crate::GPU_ABSOLUTE_ABORT_MILLICELSIUS
    });
    record.schema_version == EVIDENCE_SCHEMA_VERSION_V2
        && record.record_status == EvidenceRecordStatus::Complete
        && record.stage == "supervised-endurance"
        && record
            .workload
            .as_ref()
            .is_some_and(canonical_endurance_workload)
        && record.samples.len() == SUPERVISED_ENDURANCE_SAMPLE_COUNT
        && record.commands.len() == SUPERVISED_ENDURANCE_SAMPLE_COUNT * 2
        && record.readbacks.len() == SUPERVISED_ENDURANCE_SAMPLE_COUNT * 6 + 2
        && record.state_transitions.len() == expected_transitions
        && record.restoration_attempts.len() == 2
        && matches!(
            record.restoration_attempts.as_slice(),
            [cpu, gpu] if cpu.fan == EvidenceFan::Cpu && gpu.fan == EvidenceFan::Gpu
        )
        && cleanup_matches
        && record.faults.is_empty()
        && record.calibration.is_empty()
        && schedule_matches
        && starting_temperatures_are_safe
        && transition_names_match
        && transition_timestamps_match
        && record
            .endurance_observer_attestation
            .as_ref()
            .is_some_and(|attestation| {
                crate::evidence::endurance_observer_attestation_is_valid(record, attestation)
            })
        && control_evidence_matches
        && record.thermal_summary.as_ref().is_some_and(|summary| {
            summary == &summarize_thermal_evidence(&record.samples, true, Vec::new(), Vec::new())
                && record
                    .endurance_thermal_envelope
                    .as_ref()
                    .is_some_and(|envelope| {
                        validate_endurance_thermal_limits_against_envelope(
                            summary,
                            &record.samples,
                            envelope,
                        )
                        .is_ok()
                    })
        })
        && record.outcome.status == RunOutcomeStatus::Passed
        && !record.outcome.another_passing_run_required
        && record.outcome.final_firmware_auto_confirmed
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

#[cfg(test)]
mod tests {
    use super::*;

    struct OverflowRestorationEnvironment {
        now: EvidenceTimestamp,
        restored: Vec<EvidenceFan>,
        stops: Vec<&'static str>,
    }

    impl SupervisedEnduranceEnvironment for OverflowRestorationEnvironment {
        fn timestamp(&mut self) -> EvidenceTimestamp {
            self.now
        }

        fn confirm_observer(&mut self, _: u64) -> Result<EvidenceTimestamp, String> {
            unreachable!()
        }

        fn capture_starting_conditions(
            &mut self,
            _: u64,
        ) -> Result<CapturedMatchedWorkloadStartingConditions, String> {
            unreachable!()
        }

        fn enter_custom_control(&mut self, _: u64) -> Result<(), String> {
            unreachable!()
        }

        fn begin_segment(
            &mut self,
            _: SupervisedEnduranceSegment,
            _: u64,
        ) -> Result<SupervisedEnduranceSegmentConfirmation, String> {
            unreachable!()
        }

        fn start_workload(
            &mut self,
            _: &WorkloadEvidence,
            _: u64,
        ) -> Result<EvidenceTimestamp, String> {
            unreachable!()
        }

        fn wait_until(&mut self, _: u64, _: u64) -> Result<(), String> {
            unreachable!()
        }

        fn capture_observation(&mut self, _: u64) -> Result<MatchedWorkloadObservation, String> {
            unreachable!()
        }

        fn stop_workload(
            &mut self,
            _: u64,
        ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
            self.stops.push("workload");
            Ok(SupervisedEnduranceProcessStopConfirmation {
                observed_at: self.now,
                process_identity: "/usr/lib/pt31553-fan-control/workloads/mixed".into(),
                running: false,
            })
        }

        fn stop_service(
            &mut self,
            _: u64,
        ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
            self.stops.push("service");
            Ok(SupervisedEnduranceProcessStopConfirmation {
                observed_at: self.now,
                process_identity: "pt31553-fan-control.service".into(),
                running: false,
            })
        }

        fn force_contain_workload(
            &mut self,
            deadline: u64,
        ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
            self.stop_workload(deadline)
        }

        fn force_contain_service(
            &mut self,
            deadline: u64,
        ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
            self.stop_service(deadline)
        }

        fn restore_fan(&mut self, fan: EvidenceFan, _: u64) -> MatchedWorkloadFanRestoration {
            self.restored.push(fan);
            MatchedWorkloadFanRestoration {
                auto_write_succeeded: true,
                enable_readback: Some(2),
                endpoint_identity: format!("{fan:?}-enable"),
                outcome: RestorationOutcome::FirmwareAutoConfirmed,
            }
        }

        fn contain_fan_at_maximum(
            &mut self,
            fan: EvidenceFan,
            _: u64,
        ) -> SupervisedEnduranceFanContainment {
            self.restored.push(fan);
            SupervisedEnduranceFanContainment {
                enable_readback: Some(1),
                pwm_write_succeeded: true,
                pwm_readback: Some(255),
                enable_endpoint_identity: format!("{fan:?}-enable"),
                pwm_endpoint_identity: format!("{fan:?}-pwm"),
                outcome: RestorationOutcome::MaximumContainmentConfirmed,
            }
        }
    }

    fn legacy_record() -> EvidenceRecord {
        serde_json::from_str(include_str!(
            "../../../qualification/evidence-example/evidence-v1.json"
        ))
        .expect("checked-in legacy evidence parses")
    }

    #[test]
    fn endurance_schedule_is_exactly_sixty_minutes_with_two_load_idle_cycles() {
        assert_eq!(
            SUPERVISED_ENDURANCE_SEGMENTS
                .iter()
                .map(|segment| segment.duration_millis)
                .sum::<u64>(),
            SUPERVISED_ENDURANCE_DURATION_MILLIS
        );
        assert_eq!(
            SUPERVISED_ENDURANCE_SEGMENTS
                .iter()
                .map(|segment| segment.power_profile)
                .collect::<Vec<_>>(),
            vec![
                EvidenceProfile::Ac,
                EvidenceProfile::Ac,
                EvidenceProfile::Battery,
                EvidenceProfile::Battery,
                EvidenceProfile::Ac,
                EvidenceProfile::Ac,
            ]
        );
        assert_eq!(
            SUPERVISED_ENDURANCE_SEGMENTS
                .iter()
                .map(|segment| segment.load)
                .collect::<Vec<_>>(),
            vec![
                SupervisedEnduranceLoad::Load,
                SupervisedEnduranceLoad::Idle,
                SupervisedEnduranceLoad::Load,
                SupervisedEnduranceLoad::Idle,
                SupervisedEnduranceLoad::Load,
                SupervisedEnduranceLoad::Idle,
            ]
        );
        assert_eq!(segment_index_at_elapsed(15 * 60 * 1_000), 0);
        assert_eq!(segment_index_at_elapsed(15 * 60 * 1_000 + 2_000), 1);
        assert_eq!(
            segment_index_at_elapsed(SUPERVISED_ENDURANCE_DURATION_MILLIS),
            5
        );
    }

    #[test]
    fn incomplete_evidence_matrix_is_rejected_before_endurance() {
        let preflight = legacy_record();
        let plan = SupervisedEndurancePlan {
            prerequisite_binding_sha256: "a".repeat(64),
            preflight: &preflight,
            baselines: &[],
            matched_workload_runs: &[],
            tachometer_calibrations: MatchedWorkloadTachometerCalibrations {
                cpu: &preflight,
                gpu: &preflight,
            },
            live_lifecycle: &preflight,
            workload: preflight.workload.clone().expect("fixture workload"),
        };
        assert!(matches!(
            validate_qualification_plan(&plan),
            Err(SupervisedEndurancePlanError::InvalidQualificationEvidence { .. })
        ));
    }

    #[test]
    fn baseline_thermal_margin_must_fit_the_persisted_schema_envelope() {
        for cpu_peak in [94_000, i32::MAX] {
            let mut baseline = legacy_record();
            baseline.thermal_summary = Some(ThermalSummaryEvidence {
                cpu_peak_millicelsius: cpu_peak,
                gpu_peak_millicelsius: 80_000,
                cpu_p95_millicelsius: 90_000,
                gpu_p95_millicelsius: 75_000,
                cpu_final_slope_millicelsius_per_minute: 0,
                gpu_final_slope_millicelsius_per_minute: 0,
                system_stable: Some(true),
                kernel_faults: vec![],
                nvidia_faults: vec![],
            });

            assert!(matches!(
                endurance_thermal_envelope(&[&baseline]),
                Err(SupervisedEndurancePlanError::InvalidQualificationEvidence { .. })
            ));
        }
    }

    #[test]
    fn qualification_record_deserialization_requires_the_authority_schema() {
        let identity = legacy_record().qualification_envelope;
        let record = QualificationRecordV2 {
            schema_version: 2,
            qualification_id: identity.qualification_id,
            policy_version: identity.policy_version,
            protected_policy_sha256: identity.protected_policy_sha256,
            compatibility: identity.compatibility,
            supervised_endurance: SupervisedEnduranceAuthorizationV1 {
                schema_version: 1,
                evidence_sha256: "a".repeat(64),
                evidence_path: crate::SUPERVISED_ENDURANCE_EVIDENCE_PATH.into(),
                evidence_schema_version: 2,
                stage: "supervised-endurance".into(),
                record_status: EvidenceRecordStatus::Complete,
                outcome: RunOutcomeStatus::Passed,
                final_firmware_auto_confirmed: true,
                workload_stopped: true,
                service_stopped: true,
                completed_at: EvidenceTimestamp {
                    monotonic_millis: 1,
                    wall_unix_millis: 1,
                },
            },
        };
        let source = serde_json::to_string(&record).expect("qualification record serializes");
        assert!(serde_json::from_str::<QualificationRecordV2>(&source).is_ok());
        assert!(
            serde_json::from_str::<QualificationRecordV2>(&source.replacen(
                "\"schema_version\":2",
                "\"schema_version\":1",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn restoration_deadline_overflow_still_attempts_both_fans() {
        let now = EvidenceTimestamp {
            monotonic_millis: u64::MAX - 1,
            wall_unix_millis: 0,
        };
        let mut environment = OverflowRestorationEnvironment {
            now,
            restored: Vec::new(),
            stops: Vec::new(),
        };
        let mut readbacks = Vec::new();
        let mut attempts = Vec::new();
        let mut faults = Vec::new();
        let mut not_before = now;

        assert!(!restore_both_fans(
            &mut environment,
            &mut readbacks,
            &mut attempts,
            &mut faults,
            &ControlEvidenceState::default(),
            &mut not_before,
        ));
        assert_eq!(environment.restored, [EvidenceFan::Cpu, EvidenceFan::Gpu]);
        assert_eq!(attempts.len(), 2);
        assert_eq!(
            faults
                .iter()
                .filter(|fault| fault.detail == "fan restoration deadline overflowed")
                .count(),
            2
        );
    }

    #[test]
    fn stop_deadline_overflow_still_stops_workload_before_service() {
        let now = EvidenceTimestamp {
            monotonic_millis: u64::MAX - 1,
            wall_unix_millis: 0,
        };
        let mut environment = OverflowRestorationEnvironment {
            now,
            restored: Vec::new(),
            stops: Vec::new(),
        };
        let mut faults = Vec::new();
        let mut not_before = now;

        perform_confirmed_stop(
            &mut environment,
            &mut faults,
            &mut not_before,
            StopExpectation {
                code: "workload-stop",
                process: StoppedProcess::Workload,
                identity: "/usr/lib/pt31553-fan-control/workloads/mixed",
                fixed_deadline: None,
            },
            SupervisedEnduranceEnvironment::stop_workload,
        );
        perform_confirmed_stop(
            &mut environment,
            &mut faults,
            &mut not_before,
            StopExpectation {
                code: "service-stop",
                process: StoppedProcess::Service,
                identity: "pt31553-fan-control.service",
                fixed_deadline: None,
            },
            SupervisedEnduranceEnvironment::stop_service,
        );

        assert_eq!(environment.stops, ["workload", "service"]);
        assert_eq!(
            faults
                .iter()
                .filter(|fault| fault.detail == "operation deadline overflowed")
                .count(),
            2
        );
    }
}
