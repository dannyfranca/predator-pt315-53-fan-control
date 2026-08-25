//! Shared types for the PT315-53 fan-control executables.

use std::fmt;

mod curve;
mod demand;
mod policy;

pub use curve::{CurvePoint, DemandCurve, DemandCurveError, TemperatureCelsius, TemperatureError};
pub use demand::{DemandPercent, DemandPercentError, Pwm};
pub use policy::{
    DemandSmoother, DownshiftPolicy, DownshiftPolicyError, EffectiveTemperature, HysteresisCelsius,
    HysteresisError, MonotonicTime, MonotonicTimeError,
};

/// Source-build status before model qualification and configuration exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupStatus {
    /// The source tree must not attempt Custom fan control.
    UnqualifiedNotConfigured,
}

impl fmt::Display for StartupStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnqualifiedNotConfigured => formatter.write_str("unqualified/not configured"),
        }
    }
}
