//! Shared types for the PT315-53 fan-control executables.

use std::fmt;

mod acer_hwmon;
mod arming;
mod authority;
mod compatibility;
mod config;
mod control_cycle;
mod coretemp;
mod curve;
mod demand;
mod envelope;
mod external_power;
mod nvidia_gpu;
mod output;
mod ownership;
mod platform;
mod policy;
mod restoration;
mod sampling;
mod validation;

pub use acer_hwmon::{AcerHwmonDevice, AcerHwmonDiscoveryError, FanEndpoints, discover_acer_hwmon};
pub use arming::{
    ArmedFanControl, FanArmingError, FanArmingFailure, FanArmingOperation, FanArmingReadback,
    arm_both_fans_safely,
};
pub use authority::{
    AdmittedPolicyAuthority, PolicyAuthorityAdmissionError, PolicyAuthorityError,
    admit_policy_authority,
};
pub use compatibility::{
    AdmittedCompatibility, CompatibilityAdmissionError, CompatibilityDeclarationError,
    CompatibilityDeclarationV1, CompatibilityObservation, EscapeHatchCapability,
    EvidenceCompleteness, FanControlDeclaration, FanWriteBackend, HardwareIdentity, KernelIdentity,
    ModuleIdentity, ModuleProvenance, ObservedFanAbi, SecureBootRequirements, admit_compatibility,
    parse_compatibility_v1,
};
pub use config::{
    ConfigParseError, ConfigV1, ControlConfig, CurvePointConfig, FanConfig, FansConfig, FiniteF64,
    ProfileConfig, ProfilesConfig, parse_config_v1,
};
pub use control_cycle::{
    CompletedControlCycle, ControlCycleOperation, ControlCycleReadback, HealthyControl,
    HealthyControlCycleError, run_healthy_control_cycle,
};
pub use coretemp::{CoretempDevice, CoretempError, discover_coretemp};
pub use curve::{CurvePoint, DemandCurve, DemandCurveError, TemperatureCelsius, TemperatureError};
pub use demand::{DemandPercent, DemandPercentError, Pwm};
pub use envelope::{EnvelopeValidationError, validate_against_protected_envelope};
pub use external_power::observe_external_power;
pub use nvidia_gpu::{
    NvidiaGpuSampleError, NvidiaGpuSelector, NvidiaGpuSelectorError, NvidiaGpuSelectorKind,
    NvmlAccess, NvmlError, NvmlErrorKind, NvmlGpuSample, sample_nvidia_gpu,
};
pub use output::{ExternalPower, FanOutputs, calculate_fan_outputs};
pub use ownership::{
    ArmingReadySample, COMPETING_FAN_CONTROL_SERVICES, ControllerOwnership,
    ControllerOwnershipError, ControllerReleaseError, OwnershipSampleReadiness, RUNTIME_LOCK_PATH,
    acquire_controller_ownership,
};
pub use platform::{
    BoundedFileAccess, BoundedIdentityBoundFileAccess, Clock, FakePlatform, FakeRuntimeLock,
    FakeRuntimeLockBackend, FakeStep, FileAccess, FileIdentity, FilePermissions,
    IdentityBoundFileAccess, PlatformError, PlatformErrorKind, PlatformOperation,
    RuntimeLockAccess, RuntimeLockError, ServiceAccess, SystemOwnershipPlatform, SystemRuntimeLock,
};
pub use policy::{
    DemandSmoother, DownshiftPolicy, DownshiftPolicyError, EffectiveTemperature, HysteresisCelsius,
    HysteresisError, MonotonicTime, MonotonicTimeError,
};
pub use restoration::{
    EmergencyContainmentReport, EmergencyFanStatus, FanModeFailure, FanRestorationStatus,
    FirmwareAutoReadback, FirmwareAutoRestorationError, MaximumPwmReadback,
};
pub use sampling::{
    CompleteSampleSet, ControlCycleSampleGate, FreshSampleGate, MAX_SAMPLE_CADENCE_JITTER,
    NORMAL_SAMPLE_CADENCE, ObservedSample, RequiredInput, SampleCapture, SampleReadiness,
    SampleSetError, SampleSourceError, SampleSources,
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
