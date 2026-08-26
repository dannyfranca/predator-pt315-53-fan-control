use std::{error::Error, fmt, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    EVIDENCE_SCHEMA_VERSION_V2, EvidenceFan, EvidenceRecord, EvidenceValidationError,
    EvidenceWriteError, Fan, FanCalibrationEvidence, RpmAnchorEvidence,
    tachometer::{MAXIMUM_PLAUSIBLE_RPM, MINIMUM_PLAUSIBLE_RPM},
    write_evidence_atomically,
};

const CUSTOM_CONTROL: u8 = 1;
const MAXIMUM_DUTY_BASIS_POINTS: u16 = 10_000;
const COARSE_SWEEP_BASIS_POINTS: [u16; 5] = [10_000, 6_000, 5_000, 4_000, 3_000];
const CONSERVATIVE_MARGIN_BASIS_POINTS: u16 = 1_000;
const RESPONSE_MARGIN_MILLIS: u64 = 2_000;
const MAXIMUM_HOLD_SAMPLE_GAP_MILLIS: u64 = 2_000;
const MAXIMUM_PROTOCOL_VERIFICATION_GAP_MILLIS: u64 = 2_000;
const MINIMUM_SETTLED_RESPONSE_MILLIS: u64 = 1_000;
const MINIMUM_SETTLED_SAMPLE_SPAN_MILLIS: u64 = 1_000;
const MINIMUM_SETTLED_SAMPLE_GAP_MILLIS: u64 = 250;
const SETTLED_SAMPLE_TOLERANCE_PERCENT: u32 = 10;
const MINIMUM_SETTLED_SAMPLES: usize = 3;

pub const REQUIRED_MAXIMUM_TO_FLOOR_TRANSITIONS: u8 = 5;
pub const REQUIRED_FLOOR_HOLD_MILLIS: u64 = 15 * 60 * 1_000;
pub const MAXIMUM_CALIBRATION_RESPONSE_MILLIS: u64 = 10_000;

pub(crate) fn calibration_response_deadline(slowest_response_millis: u64) -> u64 {
    slowest_response_millis
        .saturating_add(RESPONSE_MARGIN_MILLIS)
        .min(MAXIMUM_CALIBRATION_RESPONSE_MILLIS)
}

pub(crate) const fn is_allowed_calibration_floor(floor_basis_points: u16) -> bool {
    matches!(floor_basis_points, 4_000 | 5_000 | 6_000 | 7_000)
}

pub(crate) fn canonical_calibration_anchor_duties(floor_basis_points: u16) -> Vec<u16> {
    let midpoint = floor_basis_points + (7_500_u16.saturating_sub(floor_basis_points)) / 2;
    let mut duties = vec![
        floor_basis_points,
        midpoint,
        7_500,
        MAXIMUM_DUTY_BASIS_POINTS,
    ];
    duties.dedup();
    duties
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", deny_unknown_fields)]
pub enum CalibrationStep {
    RevalidateBothAtMaximum {
        pwm_value: u8,
    },
    Sweep {
        duty_basis_points: u16,
        pwm_value: u8,
    },
    TransitionToMaximum {
        attempt: u8,
        pwm_value: u8,
    },
    TransitionToFloor {
        attempt: u8,
        duty_basis_points: u16,
        pwm_value: u8,
    },
    HoldFloor {
        duty_basis_points: u16,
        pwm_value: u8,
        required_duration_millis: u64,
    },
    CaptureAnchor {
        duty_basis_points: u16,
        pwm_value: u8,
    },
    Complete,
    Failed,
}

impl CalibrationStep {
    pub const fn duty_basis_points(self) -> Option<u16> {
        match self {
            Self::Sweep {
                duty_basis_points, ..
            }
            | Self::TransitionToFloor {
                duty_basis_points, ..
            }
            | Self::HoldFloor {
                duty_basis_points, ..
            }
            | Self::CaptureAnchor {
                duty_basis_points, ..
            } => Some(duty_basis_points),
            Self::RevalidateBothAtMaximum { .. } | Self::TransitionToMaximum { .. } => {
                Some(MAXIMUM_DUTY_BASIS_POINTS)
            }
            Self::Complete | Self::Failed => None,
        }
    }

    pub const fn pwm_value(self) -> Option<u8> {
        match self {
            Self::RevalidateBothAtMaximum { pwm_value }
            | Self::Sweep { pwm_value, .. }
            | Self::TransitionToMaximum { pwm_value, .. }
            | Self::TransitionToFloor { pwm_value, .. }
            | Self::HoldFloor { pwm_value, .. }
            | Self::CaptureAnchor { pwm_value, .. } => Some(pwm_value),
            Self::Complete | Self::Failed => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationReadbackSample {
    pub monotonic_millis: u64,
    pub selected_enable_readback: u8,
    pub selected_pwm_readback: u8,
    pub other_enable_readback: u8,
    pub other_pwm_readback: u8,
    pub selected_rpm: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationLevelObservation {
    pub commanded_at_monotonic_millis: u64,
    pub samples: Vec<CalibrationReadbackSample>,
    pub stall_observed: bool,
    pub unexplained_rpm_collapse_observed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FanHoldObservation {
    pub samples: Vec<CalibrationReadbackSample>,
    pub stall_observed: bool,
    pub unexplained_rpm_collapse_observed: bool,
}

#[derive(Debug)]
pub enum CalibrationEvidenceWriteError {
    IncompleteCalibration,
    UnsupportedEvidenceVersion,
    UnsuccessfulEvidenceOutcome,
    RecordAlreadyContainsCalibration,
    InvalidRecord(EvidenceValidationError),
    Write(EvidenceWriteError),
}

impl fmt::Display for CalibrationEvidenceWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteCalibration => formatter.write_str("calibration is not complete"),
            Self::UnsupportedEvidenceVersion => {
                formatter.write_str("calibration evidence requires schema version 2")
            }
            Self::UnsuccessfulEvidenceOutcome => {
                formatter.write_str("completed calibration evidence must have a passed outcome")
            }
            Self::RecordAlreadyContainsCalibration => {
                formatter.write_str("evidence record already contains calibration")
            }
            Self::InvalidRecord(error) => {
                write!(formatter, "invalid calibration evidence: {error}")
            }
            Self::Write(error) => write!(formatter, "cannot publish calibration evidence: {error}"),
        }
    }
}

impl Error for CalibrationEvidenceWriteError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationObservationError {
    UnexpectedStep,
    SelectedFanReadbackMismatch,
    OtherFanNotAtMaximum,
    InvalidRpm,
    InconclusiveObservation,
    ConservativeMarginUnavailable,
    UnstableRequiredLevel,
    IncompleteHold,
    DecreasingAnchorRpm,
    StageAlreadyFailed,
    InvalidCheckpoint,
}

impl fmt::Display for CalibrationObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnexpectedStep => "observation does not match the pending calibration step",
            Self::SelectedFanReadbackMismatch => {
                "selected fan mode or PWM readback does not match the command"
            }
            Self::OtherFanNotAtMaximum => "the other fan is not verified in Custom mode at maximum",
            Self::InvalidRpm => "tachometer sample is outside the plausible range",
            Self::InconclusiveObservation => {
                "calibration observation does not contain conclusive settled evidence"
            }
            Self::ConservativeMarginUnavailable => {
                "a full ten-point margin above the lowest stable level cannot fit"
            }
            Self::UnstableRequiredLevel => "a required calibration level was unstable",
            Self::IncompleteHold => {
                "the floor hold was shorter than fifteen minutes or had a sampling gap"
            }
            Self::DecreasingAnchorRpm => {
                "steady RPM anchor medians must not decrease as duty increases"
            }
            Self::StageAlreadyFailed => "the calibration stage has already failed",
            Self::InvalidCheckpoint => "the calibration checkpoint is invalid",
        })
    }
}

impl Error for CalibrationObservationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CalibrationPhase {
    Sweep { index: usize },
    TransitionToMaximum { attempt: u8 },
    TransitionToFloor { attempt: u8 },
    HoldFloor,
    CaptureAnchor { index: usize },
    Complete,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    tag = "kind",
    content = "observation",
    deny_unknown_fields
)]
enum CalibrationCheckpointEvent {
    Level {
        step: CalibrationStep,
        observation: CalibrationLevelObservation,
    },
    Hold {
        step: CalibrationStep,
        observation: FanHoldObservation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationCheckpoint {
    schema_version: u32,
    fan: EvidenceFan,
    failed: bool,
    events: Vec<CalibrationCheckpointEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CalibrationCommandExpectation {
    pub monotonic_millis: u64,
    pub pwm_value: u8,
}

impl CalibrationCheckpoint {
    pub(crate) fn observed_time_bounds(&self) -> Option<(u64, u64)> {
        let mut bounds: Option<(u64, u64)> = None;
        for event in &self.events {
            let (commanded_at, samples) = match event {
                CalibrationCheckpointEvent::Level { observation, .. } => (
                    Some(observation.commanded_at_monotonic_millis),
                    observation.samples.as_slice(),
                ),
                CalibrationCheckpointEvent::Hold { observation, .. } => {
                    (None, observation.samples.as_slice())
                }
            };
            for timestamp in commanded_at
                .into_iter()
                .chain(samples.iter().map(|sample| sample.monotonic_millis))
            {
                bounds = Some(match bounds {
                    Some((minimum, maximum)) => (minimum.min(timestamp), maximum.max(timestamp)),
                    None => (timestamp, timestamp),
                });
            }
        }
        bounds
    }

    pub(crate) fn command_expectations(&self) -> Vec<CalibrationCommandExpectation> {
        self.events
            .iter()
            .filter_map(|event| match event {
                CalibrationCheckpointEvent::Level { step, observation } => {
                    Some(CalibrationCommandExpectation {
                        monotonic_millis: observation.commanded_at_monotonic_millis,
                        pwm_value: step.pwm_value()?,
                    })
                }
                CalibrationCheckpointEvent::Hold { .. } => None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConservativeFanCalibration {
    fan: Fan,
    phase: CalibrationPhase,
    stable_sweep_levels: Vec<u16>,
    floor_basis_points: Option<u16>,
    slowest_response_millis: u64,
    anchors: Vec<RpmAnchorEvidence>,
    evidence: Option<FanCalibrationEvidence>,
    events: Vec<CalibrationCheckpointEvent>,
    last_observed_monotonic_millis: Option<u64>,
    resume_phase: Option<CalibrationPhase>,
}

impl ConservativeFanCalibration {
    pub fn start(fan: Fan) -> Self {
        Self {
            fan,
            phase: CalibrationPhase::Sweep { index: 0 },
            stable_sweep_levels: Vec::new(),
            floor_basis_points: None,
            slowest_response_millis: 0,
            anchors: Vec::new(),
            evidence: None,
            events: Vec::new(),
            last_observed_monotonic_millis: None,
            resume_phase: None,
        }
    }

    pub fn checkpoint(&self) -> CalibrationCheckpoint {
        CalibrationCheckpoint {
            schema_version: 1,
            fan: evidence_fan(self.fan),
            failed: self.phase == CalibrationPhase::Failed,
            events: self.events.clone(),
        }
    }

    pub fn resume(
        expected_fan: Fan,
        checkpoint: CalibrationCheckpoint,
    ) -> Result<Self, CalibrationObservationError> {
        if checkpoint.schema_version != 1
            || checkpoint.failed
            || checkpoint.fan != evidence_fan(expected_fan)
        {
            return Err(CalibrationObservationError::InvalidCheckpoint);
        }
        let mut session = Self::start(expected_fan);
        for event in checkpoint.events {
            if session.phase == CalibrationPhase::Complete {
                return Err(CalibrationObservationError::InvalidCheckpoint);
            }
            if matches!(
                &event,
                CalibrationCheckpointEvent::Level {
                    step: CalibrationStep::RevalidateBothAtMaximum { .. },
                    ..
                }
            ) && session.resume_phase.is_none()
            {
                session.resume_phase = Some(session.phase);
            }
            let result = match event {
                CalibrationCheckpointEvent::Level { step, observation }
                    if session.next_step() == step =>
                {
                    session.record_level(observation)
                }
                CalibrationCheckpointEvent::Hold { step, observation }
                    if session.next_step() == step =>
                {
                    session.record_hold(observation)
                }
                _ => return Err(CalibrationObservationError::InvalidCheckpoint),
            };
            if result.is_err() {
                return Err(CalibrationObservationError::InvalidCheckpoint);
            }
        }
        if session.phase != CalibrationPhase::Complete {
            session.resume_phase = Some(session.phase);
        }
        Ok(session)
    }

    pub fn next_step(&self) -> CalibrationStep {
        if self.resume_phase.is_some() {
            return CalibrationStep::RevalidateBothAtMaximum { pwm_value: u8::MAX };
        }
        match self.phase {
            CalibrationPhase::Sweep { index } => {
                let duty_basis_points = COARSE_SWEEP_BASIS_POINTS[index];
                CalibrationStep::Sweep {
                    duty_basis_points,
                    pwm_value: basis_points_to_pwm(duty_basis_points),
                }
            }
            CalibrationPhase::TransitionToMaximum { attempt } => {
                CalibrationStep::TransitionToMaximum {
                    attempt,
                    pwm_value: u8::MAX,
                }
            }
            CalibrationPhase::TransitionToFloor { attempt } => {
                let duty_basis_points = self.floor();
                CalibrationStep::TransitionToFloor {
                    attempt,
                    duty_basis_points,
                    pwm_value: basis_points_to_pwm(duty_basis_points),
                }
            }
            CalibrationPhase::HoldFloor => {
                let duty_basis_points = self.floor();
                CalibrationStep::HoldFloor {
                    duty_basis_points,
                    pwm_value: basis_points_to_pwm(duty_basis_points),
                    required_duration_millis: REQUIRED_FLOOR_HOLD_MILLIS,
                }
            }
            CalibrationPhase::CaptureAnchor { index } => {
                let duty_basis_points = self.anchor_duties()[index];
                CalibrationStep::CaptureAnchor {
                    duty_basis_points,
                    pwm_value: basis_points_to_pwm(duty_basis_points),
                }
            }
            CalibrationPhase::Complete => CalibrationStep::Complete,
            CalibrationPhase::Failed => CalibrationStep::Failed,
        }
    }

    pub fn floor_basis_points(&self) -> Option<u16> {
        self.floor_basis_points
    }

    pub fn lowest_stable_basis_points(&self) -> Option<u16> {
        self.stable_sweep_levels.last().copied()
    }

    pub fn evidence(&self) -> Option<&FanCalibrationEvidence> {
        self.evidence.as_ref()
    }

    /// Adds the completed calibration to a qualification record and publishes it atomically.
    /// Record validation protects the one-fan scope, canonical anchors, and final restoration.
    pub fn publish_evidence(
        &self,
        destination: &Path,
        mut record: EvidenceRecord,
    ) -> Result<(), CalibrationEvidenceWriteError> {
        if record.schema_version != EVIDENCE_SCHEMA_VERSION_V2 {
            return Err(CalibrationEvidenceWriteError::UnsupportedEvidenceVersion);
        }
        if record.outcome.status != crate::RunOutcomeStatus::Passed {
            return Err(CalibrationEvidenceWriteError::UnsuccessfulEvidenceOutcome);
        }
        let evidence = self
            .evidence
            .clone()
            .ok_or(CalibrationEvidenceWriteError::IncompleteCalibration)?;
        if !record.calibration.is_empty() {
            return Err(CalibrationEvidenceWriteError::RecordAlreadyContainsCalibration);
        }
        record.stage = "fan-calibration".to_owned();
        record.calibration.push(evidence);
        record
            .validate()
            .map_err(CalibrationEvidenceWriteError::InvalidRecord)?;
        write_evidence_atomically(destination, &record)
            .map_err(CalibrationEvidenceWriteError::Write)
    }

    pub fn record_level(
        &mut self,
        observation: CalibrationLevelObservation,
    ) -> Result<(), CalibrationObservationError> {
        if self.phase == CalibrationPhase::Failed {
            return Err(CalibrationObservationError::StageAlreadyFailed);
        }
        let step = self.next_step();
        if matches!(
            step,
            CalibrationStep::Complete | CalibrationStep::Failed | CalibrationStep::HoldFloor { .. }
        ) {
            return self.fail(CalibrationObservationError::UnexpectedStep);
        }
        self.validate_readbacks(step, &observation)?;
        if observation
            .samples
            .iter()
            .filter_map(|sample| sample.selected_rpm)
            .any(|rpm| !(MINIMUM_PLAUSIBLE_RPM..=MAXIMUM_PLAUSIBLE_RPM).contains(&rpm))
            || observation
                .samples
                .iter()
                .all(|sample| sample.selected_rpm.is_none())
        {
            return self.fail(CalibrationObservationError::InvalidRpm);
        }
        let reported_instability =
            observation.stall_observed || observation.unexplained_rpm_collapse_observed;
        let settled = if reported_instability {
            if observation
                .samples
                .iter()
                .any(|sample| sample.selected_rpm.is_none())
            {
                return self.fail(CalibrationObservationError::InvalidRpm);
            }
            if !matches!(self.phase, CalibrationPhase::Sweep { .. }) {
                return self.fail(CalibrationObservationError::UnstableRequiredLevel);
            }
            None
        } else {
            match settled_level(&observation) {
                Ok(settled) => settled,
                Err(error) => return self.fail(error),
            }
        };

        let checkpoint_observation = observation.clone();
        let result = if let Some(resume_phase) = self.resume_phase.take() {
            let response = self.require_stable(settled)?;
            self.observe_response(response.response_millis);
            self.phase = resume_phase;
            Ok(())
        } else {
            match self.phase {
                CalibrationPhase::Sweep { index } => self.record_sweep(index, settled),
                CalibrationPhase::TransitionToMaximum { attempt } => {
                    let response = self.require_stable(settled)?;
                    self.observe_response(response.response_millis);
                    self.phase = CalibrationPhase::TransitionToFloor { attempt };
                    Ok(())
                }
                CalibrationPhase::TransitionToFloor { attempt } => {
                    let response = self.require_stable(settled)?;
                    self.observe_response(response.response_millis);
                    if attempt == REQUIRED_MAXIMUM_TO_FLOOR_TRANSITIONS {
                        self.phase = CalibrationPhase::HoldFloor;
                    } else {
                        self.phase = CalibrationPhase::TransitionToMaximum {
                            attempt: attempt + 1,
                        };
                    }
                    Ok(())
                }
                CalibrationPhase::CaptureAnchor { index } => {
                    let response = self.require_stable(settled)?;
                    self.observe_response(response.response_millis);
                    if self
                        .anchors
                        .last()
                        .is_some_and(|previous| response.median_rpm < previous.median_rpm)
                    {
                        return self.fail(CalibrationObservationError::DecreasingAnchorRpm);
                    }
                    let duty_basis_points = self.anchor_duties()[index];
                    self.anchors.push(RpmAnchorEvidence {
                        duty_basis_points,
                        median_rpm: response.median_rpm,
                    });
                    if index + 1 == self.anchor_duties().len() {
                        self.complete();
                    } else {
                        self.phase = CalibrationPhase::CaptureAnchor { index: index + 1 };
                    }
                    Ok(())
                }
                CalibrationPhase::HoldFloor
                | CalibrationPhase::Complete
                | CalibrationPhase::Failed => {
                    self.fail(CalibrationObservationError::UnexpectedStep)
                }
            }
        };
        if result.is_ok() {
            self.last_observed_monotonic_millis = observation
                .samples
                .last()
                .map(|sample| sample.monotonic_millis);
            self.events.push(CalibrationCheckpointEvent::Level {
                step,
                observation: checkpoint_observation,
            });
            if self.phase == CalibrationPhase::Complete {
                let checkpoint = self.checkpoint();
                self.evidence
                    .as_mut()
                    .expect("complete calibration has evidence")
                    .protocol_checkpoint = Some(checkpoint);
            }
        }
        result
    }

    pub fn record_hold(
        &mut self,
        observation: FanHoldObservation,
    ) -> Result<(), CalibrationObservationError> {
        if self.phase == CalibrationPhase::Failed {
            return Err(CalibrationObservationError::StageAlreadyFailed);
        }
        if self.resume_phase.is_some() || self.phase != CalibrationPhase::HoldFloor {
            return self.fail(CalibrationObservationError::UnexpectedStep);
        }
        let step = self.next_step();
        if observation.stall_observed || observation.unexplained_rpm_collapse_observed {
            return self.fail(CalibrationObservationError::IncompleteHold);
        }
        self.validate_chronology(&observation.samples)?;
        self.validate_samples(step, &observation.samples)?;
        let minimum_samples =
            usize::try_from(REQUIRED_FLOOR_HOLD_MILLIS.div_ceil(MAXIMUM_HOLD_SAMPLE_GAP_MILLIS))
                .unwrap_or(usize::MAX)
                .saturating_add(1);
        let duration_millis = sample_duration(&observation.samples).unwrap_or(0);
        if duration_millis < REQUIRED_FLOOR_HOLD_MILLIS
            || observation.samples.len() < minimum_samples
            || !timestamps_are_continuous(&observation.samples)
        {
            return self.fail(CalibrationObservationError::IncompleteHold);
        }
        match stable_rpm_median(&observation.samples) {
            Ok(Some(_)) => {}
            Ok(None) => return self.fail(CalibrationObservationError::IncompleteHold),
            Err(error) => return self.fail(error),
        }
        self.phase = CalibrationPhase::CaptureAnchor { index: 0 };
        self.last_observed_monotonic_millis = observation
            .samples
            .last()
            .map(|sample| sample.monotonic_millis);
        self.events
            .push(CalibrationCheckpointEvent::Hold { step, observation });
        Ok(())
    }

    fn record_sweep(
        &mut self,
        index: usize,
        settled: Option<SettledLevel>,
    ) -> Result<(), CalibrationObservationError> {
        if let Some(response) = settled {
            self.observe_response(response.response_millis);
            self.stable_sweep_levels
                .push(COARSE_SWEEP_BASIS_POINTS[index]);
            if index + 1 < COARSE_SWEEP_BASIS_POINTS.len() {
                self.phase = CalibrationPhase::Sweep { index: index + 1 };
                return Ok(());
            }
        }

        let Some(lowest_stable) = self.lowest_stable_basis_points() else {
            return self.fail(CalibrationObservationError::ConservativeMarginUnavailable);
        };
        let Some(floor) = lowest_stable.checked_add(CONSERVATIVE_MARGIN_BASIS_POINTS) else {
            return self.fail(CalibrationObservationError::ConservativeMarginUnavailable);
        };
        if floor > MAXIMUM_DUTY_BASIS_POINTS {
            return self.fail(CalibrationObservationError::ConservativeMarginUnavailable);
        }
        self.floor_basis_points = Some(floor);
        self.phase = CalibrationPhase::TransitionToMaximum { attempt: 1 };
        Ok(())
    }

    fn validate_readbacks(
        &mut self,
        step: CalibrationStep,
        observation: &CalibrationLevelObservation,
    ) -> Result<(), CalibrationObservationError> {
        if observation
            .samples
            .first()
            .map(|sample| sample.monotonic_millis)
            != Some(observation.commanded_at_monotonic_millis)
            || !timestamps_are_continuous(&observation.samples)
        {
            return self.fail(CalibrationObservationError::UnexpectedStep);
        }
        self.validate_chronology(&observation.samples)?;
        self.validate_samples(step, &observation.samples)
    }

    fn validate_chronology(
        &mut self,
        samples: &[CalibrationReadbackSample],
    ) -> Result<(), CalibrationObservationError> {
        if self.resume_phase.is_none()
            && self.last_observed_monotonic_millis.is_some_and(|last| {
                samples.first().is_none_or(|sample| {
                    sample.monotonic_millis <= last
                        || sample.monotonic_millis - last > MAXIMUM_PROTOCOL_VERIFICATION_GAP_MILLIS
                })
            })
        {
            return self.fail(CalibrationObservationError::UnexpectedStep);
        }
        Ok(())
    }

    fn validate_samples(
        &mut self,
        step: CalibrationStep,
        samples: &[CalibrationReadbackSample],
    ) -> Result<(), CalibrationObservationError> {
        if samples.iter().any(|sample| {
            sample.other_enable_readback != CUSTOM_CONTROL || sample.other_pwm_readback != u8::MAX
        }) {
            return self.fail(CalibrationObservationError::OtherFanNotAtMaximum);
        }
        if samples.is_empty()
            || samples.iter().any(|sample| {
                sample.selected_enable_readback != CUSTOM_CONTROL
                    || Some(sample.selected_pwm_readback) != step.pwm_value()
            })
        {
            return self.fail(CalibrationObservationError::SelectedFanReadbackMismatch);
        }
        Ok(())
    }

    fn require_stable(
        &mut self,
        settled: Option<SettledLevel>,
    ) -> Result<SettledLevel, CalibrationObservationError> {
        match settled {
            Some(response) => Ok(response),
            None => self.fail(CalibrationObservationError::UnstableRequiredLevel),
        }
    }

    fn observe_response(&mut self, response_millis: u64) {
        self.slowest_response_millis = self.slowest_response_millis.max(response_millis);
    }

    fn complete(&mut self) {
        self.evidence = Some(FanCalibrationEvidence {
            fan: evidence_fan(self.fan),
            floor_basis_points: self.floor(),
            slowest_response_millis: Some(self.slowest_response_millis),
            protocol_checkpoint: None,
            response_deadline_millis: calibration_response_deadline(self.slowest_response_millis),
            anchors: self.anchors.clone(),
        });
        self.phase = CalibrationPhase::Complete;
    }

    fn anchor_duties(&self) -> Vec<u16> {
        canonical_calibration_anchor_duties(self.floor())
    }

    fn floor(&self) -> u16 {
        self.floor_basis_points
            .expect("floor exists after the descending sweep")
    }

    fn fail<T>(
        &mut self,
        error: CalibrationObservationError,
    ) -> Result<T, CalibrationObservationError> {
        self.phase = CalibrationPhase::Failed;
        self.evidence = None;
        self.resume_phase = None;
        Err(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SettledLevel {
    median_rpm: u32,
    response_millis: u64,
}

fn settled_level(
    observation: &CalibrationLevelObservation,
) -> Result<Option<SettledLevel>, CalibrationObservationError> {
    if observation
        .samples
        .iter()
        .filter_map(|sample| sample.selected_rpm)
        .any(|rpm| !(MINIMUM_PLAUSIBLE_RPM..=MAXIMUM_PLAUSIBLE_RPM).contains(&rpm))
    {
        return Err(CalibrationObservationError::InvalidRpm);
    }
    if observation
        .samples
        .iter()
        .all(|sample| sample.selected_rpm.is_none())
    {
        return Err(CalibrationObservationError::InvalidRpm);
    }
    let Some(response_millis) = observation.samples.last().and_then(|sample| {
        sample
            .monotonic_millis
            .checked_sub(observation.commanded_at_monotonic_millis)
    }) else {
        return Err(CalibrationObservationError::InconclusiveObservation);
    };
    if !(MINIMUM_SETTLED_RESPONSE_MILLIS..=MAXIMUM_CALIBRATION_RESPONSE_MILLIS)
        .contains(&response_millis)
    {
        return Err(CalibrationObservationError::InconclusiveObservation);
    }
    let first_rpm_index = observation
        .samples
        .iter()
        .position(|sample| sample.selected_rpm.is_some())
        .ok_or(CalibrationObservationError::InvalidRpm)?;
    let rpm_samples = observation.samples[first_rpm_index..]
        .iter()
        .map(|sample| sample.selected_rpm)
        .collect::<Option<Vec<_>>>()
        .ok_or(CalibrationObservationError::InvalidRpm)?;
    if rpm_samples.len() < MINIMUM_SETTLED_SAMPLES {
        return Err(CalibrationObservationError::InconclusiveObservation);
    }
    let settled_samples = &observation.samples[observation.samples.len() - rpm_samples.len()..];
    if sample_duration(settled_samples)
        .is_none_or(|duration| duration < MINIMUM_SETTLED_SAMPLE_SPAN_MILLIS)
        || settled_samples.windows(2).any(|samples| {
            samples[1]
                .monotonic_millis
                .saturating_sub(samples[0].monotonic_millis)
                < MINIMUM_SETTLED_SAMPLE_GAP_MILLIS
        })
    {
        return Err(CalibrationObservationError::InconclusiveObservation);
    }
    let Some(median_rpm) = stable_rpm_median_values(&rpm_samples) else {
        return Ok(None);
    };
    Ok(Some(SettledLevel {
        median_rpm,
        response_millis,
    }))
}

fn stable_rpm_median(
    samples: &[CalibrationReadbackSample],
) -> Result<Option<u32>, CalibrationObservationError> {
    let Some(rpm_samples) = samples
        .iter()
        .map(|sample| sample.selected_rpm)
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(None);
    };
    if rpm_samples
        .iter()
        .any(|rpm| !(MINIMUM_PLAUSIBLE_RPM..=MAXIMUM_PLAUSIBLE_RPM).contains(rpm))
    {
        return Err(CalibrationObservationError::InvalidRpm);
    }
    Ok(stable_rpm_median_values(&rpm_samples))
}

fn stable_rpm_median_values(rpm_samples: &[u32]) -> Option<u32> {
    if rpm_samples.len() < MINIMUM_SETTLED_SAMPLES {
        return None;
    }
    let median_rpm = median(rpm_samples);
    let minimum = rpm_samples
        .iter()
        .copied()
        .min()
        .expect("settled samples are nonempty");
    let maximum = rpm_samples
        .iter()
        .copied()
        .max()
        .expect("settled samples are nonempty");
    let tolerance = (median_rpm * SETTLED_SAMPLE_TOLERANCE_PERCENT / 100).max(50);
    if maximum.saturating_sub(minimum) > tolerance {
        return None;
    }
    Some(median_rpm)
}

fn sample_duration(samples: &[CalibrationReadbackSample]) -> Option<u64> {
    samples
        .last()?
        .monotonic_millis
        .checked_sub(samples.first()?.monotonic_millis)
}

fn timestamps_are_continuous(samples: &[CalibrationReadbackSample]) -> bool {
    !samples.is_empty()
        && samples.windows(2).all(|samples| {
            let Some(gap) = samples[1]
                .monotonic_millis
                .checked_sub(samples[0].monotonic_millis)
            else {
                return false;
            };
            (1..=MAXIMUM_HOLD_SAMPLE_GAP_MILLIS).contains(&gap)
        })
}

const fn evidence_fan(fan: Fan) -> EvidenceFan {
    match fan {
        Fan::Cpu => EvidenceFan::Cpu,
        Fan::Gpu => EvidenceFan::Gpu,
    }
}

fn median(samples: &[u32]) -> u32 {
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    ordered[ordered.len() / 2]
}

fn basis_points_to_pwm(basis_points: u16) -> u8 {
    let scaled = u32::from(basis_points) * u32::from(u8::MAX);
    scaled.div_ceil(u32::from(MAXIMUM_DUTY_BASIS_POINTS)) as u8
}
