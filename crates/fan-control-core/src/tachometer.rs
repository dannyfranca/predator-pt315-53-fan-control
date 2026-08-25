use std::{error::Error, fmt, time::Duration};

use serde::Deserialize;

use crate::{Fan, Pwm, ValidatedConfig};

const MAXIMUM_DUTY_BASIS_POINTS: u16 = 10_000;
const MAXIMUM_RESPONSE_DEADLINE_MILLIS: u64 = 30_000;
pub(crate) const MINIMUM_PLAUSIBLE_RPM: u32 = 100;
pub(crate) const MAXIMUM_PLAUSIBLE_RPM: u32 = 20_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TachometerCalibrationConfig {
    cpu: FanCalibrationConfig,
    gpu: FanCalibrationConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct FanCalibrationConfig {
    floor_basis_points: u16,
    response_deadline_millis: u64,
    anchors: Vec<RpmAnchor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpmAnchor {
    duty_basis_points: u16,
    median_rpm: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QualifiedTachometerCalibrations {
    cpu: QualifiedFanCalibration,
    gpu: QualifiedFanCalibration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QualifiedFanCalibration {
    response_window: Duration,
    anchors: Vec<RpmAnchor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TachometerCalibrationError {
    FloorMismatch {
        fan: Fan,
        configured_basis_points: u16,
        protected_basis_points: u16,
    },
    ZeroResponseDeadline {
        fan: Fan,
    },
    ResponseDeadlineTooLong {
        fan: Fan,
        value_millis: u64,
        maximum_millis: u64,
    },
    InsufficientAnchors {
        fan: Fan,
    },
    AnchorRangeMismatch {
        fan: Fan,
    },
    AnchorsNotStrictlyIncreasing {
        fan: Fan,
    },
    RpmZeroOrDecreasing {
        fan: Fan,
    },
    RpmOutOfRange {
        fan: Fan,
        value: u32,
        minimum: u32,
        maximum: u32,
    },
}

impl fmt::Display for TachometerCalibrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FloorMismatch {
                fan,
                configured_basis_points,
                protected_basis_points,
            } => write!(
                formatter,
                "{} calibration floor {configured_basis_points} does not match protected floor {protected_basis_points} basis points",
                fan.name()
            ),
            Self::ZeroResponseDeadline { fan } => {
                write!(
                    formatter,
                    "{} calibration response deadline is zero",
                    fan.name()
                )
            }
            Self::ResponseDeadlineTooLong {
                fan,
                value_millis,
                maximum_millis,
            } => write!(
                formatter,
                "{} calibration response deadline {value_millis} ms exceeds the {maximum_millis} ms safety limit",
                fan.name()
            ),
            Self::InsufficientAnchors { fan } => write!(
                formatter,
                "{} calibration requires at least two PWM/RPM anchors",
                fan.name()
            ),
            Self::AnchorRangeMismatch { fan } => write!(
                formatter,
                "{} calibration anchors must span its protected floor through full duty",
                fan.name()
            ),
            Self::AnchorsNotStrictlyIncreasing { fan } => write!(
                formatter,
                "{} calibration anchor duties are not strictly increasing",
                fan.name()
            ),
            Self::RpmZeroOrDecreasing { fan } => write!(
                formatter,
                "{} calibration RPM anchors must be nonzero and nondecreasing",
                fan.name()
            ),
            Self::RpmOutOfRange {
                fan,
                value,
                minimum,
                maximum,
            } => write!(
                formatter,
                "{} calibration RPM anchor {value} is outside the plausible range {minimum}..={maximum}",
                fan.name()
            ),
        }
    }
}

impl Error for TachometerCalibrationError {}

impl TachometerCalibrationConfig {
    pub(crate) fn qualify(
        self,
        protected: &ValidatedConfig,
    ) -> Result<QualifiedTachometerCalibrations, TachometerCalibrationError> {
        Ok(QualifiedTachometerCalibrations {
            cpu: qualify_fan(
                Fan::Cpu,
                self.cpu,
                percent_to_basis_points(protected.fans().cpu().minimum_duty().value()),
            )?,
            gpu: qualify_fan(
                Fan::Gpu,
                self.gpu,
                percent_to_basis_points(protected.fans().gpu().minimum_duty().value()),
            )?,
        })
    }
}

fn qualify_fan(
    fan: Fan,
    calibration: FanCalibrationConfig,
    protected_floor: u16,
) -> Result<QualifiedFanCalibration, TachometerCalibrationError> {
    if calibration.floor_basis_points != protected_floor {
        return Err(TachometerCalibrationError::FloorMismatch {
            fan,
            configured_basis_points: calibration.floor_basis_points,
            protected_basis_points: protected_floor,
        });
    }
    if calibration.response_deadline_millis == 0 {
        return Err(TachometerCalibrationError::ZeroResponseDeadline { fan });
    }
    if calibration.response_deadline_millis > MAXIMUM_RESPONSE_DEADLINE_MILLIS {
        return Err(TachometerCalibrationError::ResponseDeadlineTooLong {
            fan,
            value_millis: calibration.response_deadline_millis,
            maximum_millis: MAXIMUM_RESPONSE_DEADLINE_MILLIS,
        });
    }
    if calibration.anchors.len() < 2 {
        return Err(TachometerCalibrationError::InsufficientAnchors { fan });
    }
    if calibration
        .anchors
        .first()
        .map(|anchor| anchor.duty_basis_points)
        != Some(protected_floor)
        || calibration
            .anchors
            .last()
            .map(|anchor| anchor.duty_basis_points)
            != Some(MAXIMUM_DUTY_BASIS_POINTS)
    {
        return Err(TachometerCalibrationError::AnchorRangeMismatch { fan });
    }
    if calibration
        .anchors
        .windows(2)
        .any(|pair| pair[0].duty_basis_points >= pair[1].duty_basis_points)
    {
        return Err(TachometerCalibrationError::AnchorsNotStrictlyIncreasing { fan });
    }
    if let Some(anchor) = calibration.anchors.iter().find(|anchor| {
        !(MINIMUM_PLAUSIBLE_RPM..=MAXIMUM_PLAUSIBLE_RPM).contains(&anchor.median_rpm)
    }) {
        return Err(TachometerCalibrationError::RpmOutOfRange {
            fan,
            value: anchor.median_rpm,
            minimum: MINIMUM_PLAUSIBLE_RPM,
            maximum: MAXIMUM_PLAUSIBLE_RPM,
        });
    }
    if calibration
        .anchors
        .first()
        .is_some_and(|anchor| anchor.median_rpm == 0)
        || calibration
            .anchors
            .windows(2)
            .any(|pair| pair[0].median_rpm > pair[1].median_rpm || pair[1].median_rpm == 0)
    {
        return Err(TachometerCalibrationError::RpmZeroOrDecreasing { fan });
    }

    Ok(QualifiedFanCalibration {
        response_window: Duration::from_millis(calibration.response_deadline_millis),
        anchors: calibration.anchors,
    })
}

const fn percent_to_basis_points(percent: f64) -> u16 {
    (percent * 100.0) as u16
}

#[derive(Debug, Clone)]
pub(crate) struct TachometerValidator {
    calibration: QualifiedTachometerCalibrations,
    cpu: FanResponseState,
    gpu: FanResponseState,
}

#[derive(Debug, Clone, Copy)]
struct FanResponseState {
    commanded_pwm: Pwm,
    commanded_at: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TachometerObservationError {
    DeadlineOverflow,
    OutOfBand { expected_rpm: u32, actual_rpm: u32 },
}

impl TachometerValidator {
    pub(crate) fn new(
        calibration: QualifiedTachometerCalibrations,
        commanded_pwm: Pwm,
        cpu_commanded_at: Duration,
        gpu_commanded_at: Duration,
    ) -> Self {
        Self {
            calibration,
            cpu: FanResponseState {
                commanded_pwm,
                commanded_at: cpu_commanded_at,
            },
            gpu: FanResponseState {
                commanded_pwm,
                commanded_at: gpu_commanded_at,
            },
        }
    }

    pub(crate) fn command_confirmed(&mut self, fan: Fan, pwm: Pwm, confirmed_at: Duration) {
        let state = match fan {
            Fan::Cpu => &mut self.cpu,
            Fan::Gpu => &mut self.gpu,
        };
        *state = FanResponseState {
            commanded_pwm: pwm,
            commanded_at: confirmed_at,
        };
    }

    pub(crate) fn observe(
        &mut self,
        fan: Fan,
        rpm: u32,
        observed_at: Duration,
    ) -> Result<(), TachometerObservationError> {
        let (calibration, state) = match fan {
            Fan::Cpu => (&self.calibration.cpu, self.cpu),
            Fan::Gpu => (&self.calibration.gpu, self.gpu),
        };
        let response_deadline = state
            .commanded_at
            .checked_add(calibration.response_window)
            .ok_or(TachometerObservationError::DeadlineOverflow)?;

        let expected_rpm = calibration.expected_rpm(state.commanded_pwm);
        if rpm_in_band(rpm, expected_rpm) {
            return Ok(());
        }
        if observed_at <= response_deadline {
            return Ok(());
        }
        Err(TachometerObservationError::OutOfBand {
            expected_rpm,
            actual_rpm: rpm,
        })
    }
}

impl QualifiedFanCalibration {
    fn expected_rpm(&self, pwm: Pwm) -> u32 {
        let duty = pwm_to_basis_points(pwm);
        let adjacent = self
            .anchors
            .windows(2)
            .find(|pair| duty <= pair[1].duty_basis_points)
            .expect("qualified calibration spans every allowed PWM output");
        interpolate_rpm(adjacent[0], adjacent[1], duty)
    }
}

fn interpolate_rpm(lower: RpmAnchor, upper: RpmAnchor, duty: u16) -> u32 {
    let duty = duty.clamp(lower.duty_basis_points, upper.duty_basis_points);
    let span = u64::from(upper.duty_basis_points - lower.duty_basis_points);
    let offset = u64::from(duty - lower.duty_basis_points);
    let rpm_delta = u64::from(upper.median_rpm - lower.median_rpm);
    let interpolated = u64::from(lower.median_rpm) + (rpm_delta * offset + span / 2) / span;
    u32::try_from(interpolated).expect("interpolation stays between u32 anchors")
}

const fn pwm_to_basis_points(pwm: Pwm) -> u16 {
    ((pwm.value() as u32 * MAXIMUM_DUTY_BASIS_POINTS as u32 + u8::MAX as u32 / 2) / u8::MAX as u32)
        as u16
}

const fn rpm_in_band(actual: u32, expected: u32) -> bool {
    let actual = actual as u64;
    let expected = expected as u64;
    actual * 100 >= expected * 70 && actual * 100 <= expected * 130
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{Fan, Pwm};

    use super::{
        QualifiedFanCalibration, QualifiedTachometerCalibrations, RpmAnchor,
        TachometerObservationError, TachometerValidator, interpolate_rpm, rpm_in_band,
    };

    #[test]
    fn expected_rpm_is_interpolated_between_adjacent_qualified_anchors() {
        let lower = RpmAnchor {
            duty_basis_points: 3_000,
            median_rpm: 2_500,
        };
        let upper = RpmAnchor {
            duty_basis_points: 10_000,
            median_rpm: 3_500,
        };

        assert_eq!(interpolate_rpm(lower, upper, 3_000), 2_500);
        assert_eq!(interpolate_rpm(lower, upper, 6_000), 2_929);
        assert_eq!(interpolate_rpm(lower, upper, 10_000), 3_500);
    }

    #[test]
    fn thirty_percent_tachometer_band_is_inclusive() {
        assert!(rpm_in_band(2_051, 2_929));
        assert!(rpm_in_band(3_807, 2_929));
        assert!(!rpm_in_band(2_050, 2_929));
        assert!(!rpm_in_band(3_808, 2_929));
        assert!(!rpm_in_band(0, 2_929));
    }

    #[test]
    fn response_deadline_starts_at_command_confirmation() {
        let fan = QualifiedFanCalibration {
            response_window: Duration::from_secs(4),
            anchors: vec![
                RpmAnchor {
                    duty_basis_points: 3_000,
                    median_rpm: 2_500,
                },
                RpmAnchor {
                    duty_basis_points: 10_000,
                    median_rpm: 3_500,
                },
            ],
        };
        let calibration = QualifiedTachometerCalibrations {
            cpu: fan.clone(),
            gpu: fan,
        };
        let mut validator = TachometerValidator::new(
            calibration,
            Pwm::MAXIMUM,
            Duration::from_secs(1),
            Duration::from_secs(2),
        );

        assert_eq!(
            validator.observe(Fan::Cpu, 0, Duration::from_millis(4_999)),
            Ok(())
        );
        assert_eq!(
            validator.observe(Fan::Cpu, 0, Duration::from_secs(5)),
            Ok(())
        );
        assert!(matches!(
            validator.observe(Fan::Cpu, 0, Duration::from_millis(5_001)),
            Err(TachometerObservationError::OutOfBand {
                expected_rpm: 3_500,
                actual_rpm: 0,
            })
        ));
        assert_eq!(
            validator.observe(Fan::Gpu, 0, Duration::from_millis(5_999)),
            Ok(())
        );
        assert_eq!(
            validator.observe(Fan::Gpu, 0, Duration::from_secs(6)),
            Ok(())
        );
        assert!(matches!(
            validator.observe(Fan::Gpu, 0, Duration::from_millis(6_001)),
            Err(TachometerObservationError::OutOfBand { .. })
        ));
    }
}
