//! Shared types for the PT315-53 fan-control executables.

use std::fmt;

mod acer_hwmon;
mod arming;
mod authority;
mod baseline;
mod calibration;
mod compatibility;
mod config;
mod control_cycle;
mod coretemp;
mod curve;
mod demand;
mod diagnostics;
mod envelope;
mod evidence;
mod external_power;
mod matched_workload;
mod nvidia_gpu;
mod output;
mod ownership;
mod platform;
mod policy;
mod preflight;
mod restoration;
mod sampling;
mod sensor_recovery;
mod supervision;
mod tachometer;
mod termination;
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
pub use baseline::{
    BaselineCleanupAttestation, BaselineObservation, BaselineStartingConditions,
    CPU_ABSOLUTE_ABORT_MILLICELSIUS, CapturedBaselineStartingConditions,
    FirmwareAutoBaselineAccess, FirmwareAutoBaselineEnvironment, FirmwareAutoBaselinePlan,
    FirmwareAutoBaselinePlanError, FirmwareAutoBaselineReport, GPU_ABSOLUTE_ABORT_MILLICELSIUS,
    run_firmware_auto_baseline,
};
pub use calibration::{
    CalibrationCheckpoint, CalibrationEvidenceWriteError, CalibrationLevelObservation,
    CalibrationObservationError, CalibrationReadbackSample, CalibrationStep,
    ConservativeFanCalibration, FanHoldObservation, MAXIMUM_CALIBRATION_RESPONSE_MILLIS,
    REQUIRED_FLOOR_HOLD_MILLIS, REQUIRED_MAXIMUM_TO_FLOOR_TRANSITIONS,
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
pub use diagnostics::{
    CONTROL_CYCLE_EVENT_ID, ControlCycleDiagnostic, FanDiagnostic, RESTORATION_ATTEMPT_EVENT_ID,
    RUNTIME_FAULT_EVENT_ID, RestorationAttemptDiagnostic, RestorationFanDiagnostic,
    RestorationReadback, RuntimeEndpoint, RuntimeFault, RuntimeState, RuntimeTransition,
    STATE_TRANSITION_EVENT_ID, emit_control_cycle, emit_fault, emit_restoration_attempt,
    emit_state_transition, init_journald_diagnostics,
};
pub use envelope::{EnvelopeValidationError, validate_against_protected_envelope};
pub use evidence::{
    EVIDENCE_SCHEMA_VERSION, EVIDENCE_SCHEMA_VERSION_V2, EvidenceExternalPower, EvidenceFan,
    EvidenceParseError, EvidenceProfile, EvidenceRecord, EvidenceRecordStatus, EvidenceTimestamp,
    EvidenceValidationError, EvidenceWriteError, FanCalibrationEvidence, FanCommandEvidence,
    FanControlField, FanReadbackEvidence, FanReadbackField, FanReadbackPhase, FaultEvidence,
    ObservationOutcome, QualificationEnvelopeIdentityV1, RestorationAttemptEvidence,
    RestorationOutcome, RpmAnchorEvidence, RunOutcomeEvidence, RunOutcomeStatus, SampleFreshness,
    StateTransitionEvidence, TelemetrySampleEvidence, ThermalSummaryEvidence, WorkloadEvidence,
    parse_evidence_v1, parse_evidence_v2, write_evidence_atomically,
};
pub use external_power::observe_external_power;
pub use matched_workload::{
    AMBIENT_COMPARABILITY_MILLICELSIUS, CapturedMatchedWorkloadStartingConditions,
    MINIMUM_MATCHED_WORKLOAD_SAMPLES, MatchedWorkloadClass, MatchedWorkloadEnvironment,
    MatchedWorkloadFanRestoration, MatchedWorkloadObservation, MatchedWorkloadPlan,
    MatchedWorkloadPlanError, MatchedWorkloadReport, MatchedWorkloadStartingConditions,
    STARTING_TEMPERATURE_COMPARABILITY_MILLICELSIUS, THERMAL_COMPARISON_MARGIN_MILLICELSIUS,
    THERMAL_SLOPE_LIMIT_MILLICELSIUS_PER_MINUTE, run_matched_custom_workload,
};
pub use nvidia_gpu::{
    NvidiaGpuSampleError, NvidiaGpuSelector, NvidiaGpuSelectorError, NvidiaGpuSelectorKind,
    NvmlAccess, NvmlError, NvmlErrorKind, NvmlGpuSample, sample_nvidia_gpu,
};
pub use output::{ExternalPower, FanOutputs, calculate_fan_outputs};
pub use ownership::{
    ArmingReadySample, COMPETING_FAN_CONTROL_SERVICES, ControllerOwnership,
    ControllerOwnershipError, ControllerReleaseError, OwnershipSampleReadiness, RUNTIME_LOCK_PATH,
    SystemFirmwareAutoRecovery, acquire_controller_ownership,
};
pub use platform::{
    BoundedFileAccess, BoundedIdentityBoundFileAccess, Clock, FakePlatform, FakeRuntimeLock,
    FakeRuntimeLockBackend, FakeStep, FileAccess, FileIdentity, FilePermissions,
    IdentityBoundFileAccess, IdentityBoundReadAccess, PlatformError, PlatformErrorKind,
    PlatformOperation, RuntimeLockAccess, RuntimeLockError, ServiceAccess, SystemOwnershipPlatform,
    SystemRuntimeLock,
};
pub use policy::{
    DemandSmoother, DownshiftPolicy, DownshiftPolicyError, EffectiveTemperature, HysteresisCelsius,
    HysteresisError, MonotonicTime, MonotonicTimeError,
};
pub use preflight::{
    PreflightArtifact, PreflightCheck, PreflightCheckResult, PreflightEnvironment, PreflightInputs,
    PreflightReport, PreflightRequirements, run_read_only_preflight,
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
pub use sensor_recovery::{
    SensorControlState, SensorControlStep, SensorSourceDiscovery, TransientSensorControl,
    TransientSensorControlError,
};
pub use supervision::{
    ControlLoopHeartbeat, ServiceNotification, ServiceNotifier, SupervisedControlIterationError,
    SystemdNotifier, run_supervised_control_iteration,
};
pub use tachometer::TachometerCalibrationError;
pub use termination::{
    GracefulShutdownFailure, ShutdownController, ShutdownRequest, TerminationSignalHandlers,
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
