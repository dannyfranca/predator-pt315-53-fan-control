//! Shared types for the PT315-53 fan-control executables.

use std::fmt;

mod acer_hwmon;
mod config;
mod coretemp;
mod curve;
mod demand;
mod envelope;
mod nvidia_gpu;
mod output;
mod platform;
mod policy;
mod restoration;
mod validation;

pub use acer_hwmon::{AcerHwmonDevice, AcerHwmonDiscoveryError, FanEndpoints, discover_acer_hwmon};
pub use config::{
    ConfigParseError, ConfigV1, ControlConfig, CurvePointConfig, FanConfig, FansConfig, FiniteF64,
    ProfileConfig, ProfilesConfig, parse_config_v1,
};
pub use coretemp::{CoretempDevice, CoretempError, discover_coretemp};
pub use curve::{CurvePoint, DemandCurve, DemandCurveError, TemperatureCelsius, TemperatureError};
pub use demand::{DemandPercent, DemandPercentError, Pwm};
pub use envelope::{EnvelopeValidationError, validate_against_protected_envelope};
pub use nvidia_gpu::{
    NvidiaGpuSampleError, NvidiaGpuSelector, NvidiaGpuSelectorError, NvidiaGpuSelectorKind,
    NvmlAccess, NvmlError, NvmlErrorKind, NvmlGpuSample, sample_nvidia_gpu,
};
pub use output::{ExternalPower, FanOutputs, calculate_fan_outputs};
pub use platform::{
    BoundedFileAccess, Clock, FakePlatform, FakeStep, FileAccess, FileIdentity, FilePermissions,
    IdentityBoundFileAccess, PlatformError, PlatformErrorKind, PlatformOperation, ServiceAccess,
};
pub use policy::{
    DemandSmoother, DownshiftPolicy, DownshiftPolicyError, EffectiveTemperature, HysteresisCelsius,
    HysteresisError, MonotonicTime, MonotonicTimeError,
};
pub use restoration::{
    EmergencyContainmentReport, EmergencyFanStatus, FanModeFailure, FanRestorationStatus,
    FirmwareAutoReadback, FirmwareAutoRestorationError, MaximumPwmReadback,
    contain_custom_fans_at_maximum, recover_firmware_auto, restore_firmware_auto,
};
pub use validation::{
    Component, ConfigValidationError, Fan, Profile, ValidatedConfig, ValidatedControlConfig,
    ValidatedFanConfig, ValidatedFansConfig, ValidatedProfileConfig, ValidatedProfilesConfig,
    validate_config_v1,
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
