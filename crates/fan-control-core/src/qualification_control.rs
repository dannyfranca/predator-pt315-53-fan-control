use std::{error::Error, fmt, time::Duration};

use crate::{
    AcerHwmonDevice, BoundedIdentityBoundFileAccess, CalibrationReadbackSample, Clock,
    ControllerOwnership, EmergencyContainmentReport, Fan, FanCalibrationEvidence,
    FirmwareAutoRestorationError, HealthyControl, QualificationArmedFanControl,
    QualificationEnvelopeIdentityV1, QualificationTachometerCalibrationsV1, RuntimeLockAccess,
    ShutdownRequest, ValidatedConfig, authority::requalification_policy_snapshot,
    ownership::FirmwareAutoSafingOutcome,
};

const CUSTOM_CONTROL: &str = "1";
const MAXIMUM_PWM: &str = "255";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationCommandedCalibrationSample {
    pub commanded_at_monotonic_millis: u64,
    pub sample: CalibrationReadbackSample,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualificationControlObservation {
    pub observed_at_monotonic_millis: u64,
    pub cpu_pwm: u8,
    pub gpu_pwm: u8,
    pub cpu_rpm: u32,
    pub gpu_rpm: u32,
}

/// Digest-bound production policy and measured tachometer data admitted only for a supervised
/// qualification session. This cannot satisfy normal runtime authority admission.
#[derive(Debug, Clone, PartialEq)]
pub struct QualificationControlPolicy {
    config: ValidatedConfig,
    calibration: crate::tachometer::QualifiedTachometerCalibrations,
}

impl QualificationControlPolicy {
    /// Returns the exact protected configuration that will drive this temporary controller.
    pub const fn protected_config(&self) -> &ValidatedConfig {
        &self.config
    }
}

/// Validates the exact protected policy identity and measured calibrations before any Custom
/// write. The returned capability can only be combined with a live qualification handover.
pub fn prepare_qualification_control_policy(
    protected_policy_source: &str,
    expected: &QualificationEnvelopeIdentityV1,
    cpu: FanCalibrationEvidence,
    gpu: FanCalibrationEvidence,
) -> Result<QualificationControlPolicy, String> {
    let snapshot = requalification_policy_snapshot(protected_policy_source)
        .map_err(|error| format!("protected qualification policy rejected: {error}"))?;
    if expected.qualification_record_schema_version != 1
        || snapshot.qualification_id != expected.qualification_id
        || snapshot.policy_version != expected.policy_version
        || snapshot.compatibility != expected.compatibility
        || snapshot.protected_policy_sha256 != expected.protected_policy_sha256
    {
        return Err(
            "protected qualification policy does not match the qualification envelope".into(),
        );
    }
    let calibration = QualificationTachometerCalibrationsV1 { cpu, gpu }
        .qualify(&snapshot.protected)
        .map_err(|error| format!("measured qualification calibration rejected: {error}"))?;
    Ok(QualificationControlPolicy {
        config: snapshot.protected,
        calibration,
    })
}

/// Converts the deliberately provisional handover into the ordinary production control state.
/// No persistent authority is created; restoring Firmware Auto invalidates the state.
pub fn begin_qualification_control(
    armed: QualificationArmedFanControl,
    policy: QualificationControlPolicy,
    shutdown: ShutdownRequest,
) -> HealthyControl {
    HealthyControl::from_armed(
        armed.into_control_armed(policy.config, policy.calibration),
        shutdown,
    )
}

/// Captures an identity-bound trace of the output selected by the production control cycle.
/// Any stale receipt, changed endpoint, mode/PWM mismatch, or malformed tachometer immediately
/// restores Firmware Auto (or escalates to maximum containment) before returning an error.
pub fn observe_qualification_control_before<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    control: &HealthyControl,
    deadline: Duration,
) -> Result<QualificationControlObservation, QualificationControlError>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    let device = control.device().clone();
    let result = (|| -> Result<QualificationControlObservation, String> {
        if !control.is_current_for(ownership) {
            return Err("qualification control receipt is not current".into());
        }
        if ownership.platform_mut().monotonic_now() >= deadline {
            return Err("qualification control observation deadline expired".into());
        }
        if !device
            .abi_is_current_before(ownership.platform_mut(), deadline)
            .map_err(|error| format!("fan ABI revalidation failed: {error}"))?
        {
            return Err("fan device or endpoint identity changed".into());
        }
        let outputs = control.last_outputs();
        let cpu_enable = read_u8(ownership, &device, device.cpu().enable(), deadline)?;
        let cpu_pwm = read_u8(ownership, &device, device.cpu().pwm(), deadline)?;
        let cpu_rpm = read_rpm(ownership, &device, device.cpu().tachometer(), deadline)?
            .ok_or("CPU tachometer reported zero RPM")?;
        let gpu_enable = read_u8(ownership, &device, device.gpu().enable(), deadline)?;
        let gpu_pwm = read_u8(ownership, &device, device.gpu().pwm(), deadline)?;
        let gpu_rpm = read_rpm(ownership, &device, device.gpu().tachometer(), deadline)?
            .ok_or("GPU tachometer reported zero RPM")?;
        if cpu_enable != 1
            || gpu_enable != 1
            || cpu_pwm != outputs.cpu_pwm().value()
            || gpu_pwm != outputs.gpu_pwm().value()
        {
            return Err(format!(
                "qualification control readback mismatch: CPU mode/PWM={cpu_enable}/{cpu_pwm}, GPU mode/PWM={gpu_enable}/{gpu_pwm}"
            ));
        }
        let observed_at = ownership.platform_mut().monotonic_now();
        if observed_at >= deadline {
            return Err("qualification control observation exceeded its deadline".into());
        }
        Ok(QualificationControlObservation {
            observed_at_monotonic_millis: duration_millis(observed_at),
            cpu_pwm,
            gpu_pwm,
            cpu_rpm,
            gpu_rpm,
        })
    })();
    result.map_err(|reason| safe_after_failure(ownership, &device, reason))
}

/// Returns the controller clock used by qualification I/O deadlines and observations.
///
/// This narrow accessor lets an external qualification harness bridge its process-wide monotonic
/// protocol clock without exposing the owned platform or bypassing guarded fan operations.
pub fn qualification_control_monotonic_now<P>(
    ownership: &mut ControllerOwnership<'_, P>,
) -> Duration
where
    P: Clock + RuntimeLockAccess,
{
    ownership.platform_mut().monotonic_now()
}

#[derive(Debug)]
pub enum QualificationControlError {
    Rejected {
        reason: String,
    },
    Recovered {
        reason: String,
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
    RestorationFailed {
        reason: String,
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
}

impl fmt::Display for QualificationControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { reason } => {
                write!(formatter, "qualification control rejected: {reason}")
            }
            Self::Recovered {
                reason,
                restoration,
                containment,
            } => write!(
                formatter,
                "qualification control rejected ({reason}); Auto restoration failed ({restoration}), then containment recovered: {containment:?}"
            ),
            Self::RestorationFailed {
                reason,
                restoration,
                containment,
            } => write!(
                formatter,
                "qualification control rejected ({reason}); Auto restoration failed: {restoration}; emergency containment: {containment:?}"
            ),
        }
    }
}

impl Error for QualificationControlError {}

/// Commands one fan during calibration while the other remains guarded at maximum.
///
/// Every endpoint is identity-bound. Any failure immediately attempts full Firmware Auto
/// restoration before returning.
pub fn command_qualification_calibration_fan_before<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    armed: &QualificationArmedFanControl,
    fan: Fan,
    pwm: u8,
    deadline: Duration,
) -> Result<QualificationCommandedCalibrationSample, QualificationControlError>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    let result = command_calibration_fan(ownership, armed, fan, pwm, deadline);
    result.map_err(|reason| safe_after_failure(ownership, &armed.device, reason))
}

/// Captures one identity-bound calibration sample without changing the command.
///
/// Any failed guard, identity check, or read immediately attempts full Firmware Auto restoration.
pub fn observe_qualification_calibration_fan_before<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    armed: &QualificationArmedFanControl,
    fan: Fan,
    expected_pwm: u8,
    deadline: Duration,
) -> Result<CalibrationReadbackSample, QualificationControlError>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    let result = observe_calibration_fan(ownership, armed, fan, expected_pwm, deadline);
    result.map_err(|reason| safe_after_failure(ownership, &armed.device, reason))
}

fn command_calibration_fan<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    armed: &QualificationArmedFanControl,
    fan: Fan,
    pwm: u8,
    deadline: Duration,
) -> Result<QualificationCommandedCalibrationSample, String>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    require_current(ownership, armed)?;
    let now = ownership.platform_mut().monotonic_now();
    if now >= deadline {
        return Err("calibration command deadline expired".into());
    }
    let (selected, other) = fan_endpoints(&armed.device, fan);
    let device = &armed.device;
    let guards = [
        (child_name(device.cpu().enable()), CUSTOM_CONTROL),
        (child_name(device.gpu().enable()), CUSTOM_CONTROL),
        (child_name(other.pwm()), MAXIMUM_PWM),
    ];
    ownership
        .platform_mut()
        .write_bound_if_before(
            device.root(),
            device.backing_identity(),
            &device
                .endpoint_bindings()
                .map(|(path, identity)| (child_name(path), identity)),
            &guards,
            child_name(selected.pwm()),
            &pwm.to_string(),
            deadline,
        )
        .map_err(|error| format!("{} fan calibration command failed: {error}", fan.name()))?;
    let sample = read_calibration_sample(ownership, armed, fan, pwm, now, deadline)?;
    Ok(QualificationCommandedCalibrationSample {
        commanded_at_monotonic_millis: duration_millis(now),
        sample,
    })
}

fn observe_calibration_fan<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    armed: &QualificationArmedFanControl,
    fan: Fan,
    expected_pwm: u8,
    deadline: Duration,
) -> Result<CalibrationReadbackSample, String>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    require_current(ownership, armed)?;
    let observed_at = ownership.platform_mut().monotonic_now();
    if observed_at >= deadline {
        return Err("calibration observation deadline expired".into());
    }
    read_calibration_sample(ownership, armed, fan, expected_pwm, observed_at, deadline)
}

fn read_calibration_sample<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    armed: &QualificationArmedFanControl,
    fan: Fan,
    expected_pwm: u8,
    observed_at: Duration,
    deadline: Duration,
) -> Result<CalibrationReadbackSample, String>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    let device = &armed.device;
    if !device
        .abi_is_current_before(ownership.platform_mut(), deadline)
        .map_err(|error| format!("fan ABI revalidation failed: {error}"))?
    {
        return Err("fan device or endpoint identity changed".into());
    }
    let (selected, other) = fan_endpoints(device, fan);
    let selected_enable = read_u8(ownership, device, selected.enable(), deadline)?;
    let selected_pwm = read_u8(ownership, device, selected.pwm(), deadline)?;
    let other_enable = read_u8(ownership, device, other.enable(), deadline)?;
    let other_pwm = read_u8(ownership, device, other.pwm(), deadline)?;
    let selected_rpm = read_rpm(ownership, device, selected.tachometer(), deadline)?;
    let closing_selected_enable = read_u8(ownership, device, selected.enable(), deadline)?;
    let closing_other_enable = read_u8(ownership, device, other.enable(), deadline)?;
    let closing_other_pwm = read_u8(ownership, device, other.pwm(), deadline)?;
    if selected_enable != 1
        || selected_pwm != expected_pwm
        || other_enable != 1
        || other_pwm != u8::MAX
        || closing_selected_enable != selected_enable
        || closing_other_enable != other_enable
        || closing_other_pwm != other_pwm
    {
        return Err(format!(
            "calibration readback mismatch: selected mode/PWM={selected_enable}/{selected_pwm}, other mode/PWM={other_enable}/{other_pwm}"
        ));
    }
    Ok(CalibrationReadbackSample {
        monotonic_millis: duration_millis(observed_at),
        selected_enable_readback: selected_enable,
        selected_pwm_readback: selected_pwm,
        other_enable_readback: other_enable,
        other_pwm_readback: other_pwm,
        selected_rpm,
    })
}

fn require_current<P>(
    ownership: &ControllerOwnership<'_, P>,
    armed: &QualificationArmedFanControl,
) -> Result<(), String>
where
    P: RuntimeLockAccess + ?Sized,
{
    armed
        .is_current_for(ownership)
        .then_some(())
        .ok_or_else(|| "qualification handover receipt is not current".into())
}

fn read_u8<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    path: &std::path::Path,
    deadline: Duration,
) -> Result<u8, String>
where
    P: BoundedIdentityBoundFileAccess + RuntimeLockAccess,
{
    let raw = read_bound(ownership, device, path, deadline)?;
    raw.trim().parse::<u8>().map_err(|_| {
        format!(
            "invalid numeric fan readback from {}: {raw:?}",
            path.display()
        )
    })
}

fn read_rpm<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    path: &std::path::Path,
    deadline: Duration,
) -> Result<Option<u32>, String>
where
    P: BoundedIdentityBoundFileAccess + RuntimeLockAccess,
{
    let raw = read_bound(ownership, device, path, deadline)?;
    let rpm = raw.trim().parse::<u32>().map_err(|_| {
        format!(
            "invalid tachometer readback from {}: {raw:?}",
            path.display()
        )
    })?;
    Ok((rpm != 0).then_some(rpm))
}

fn read_bound<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    path: &std::path::Path,
    deadline: Duration,
) -> Result<String, String>
where
    P: BoundedIdentityBoundFileAccess + RuntimeLockAccess,
{
    ownership
        .platform_mut()
        .read_bound_before(
            device.root(),
            device.backing_identity(),
            child_name(path),
            device
                .endpoint_identity(path)
                .expect("qualification path belongs to the discovered device"),
            deadline,
        )
        .map_err(|error| format!("fan readback from {} failed: {error}", path.display()))
}

fn fan_endpoints(
    device: &AcerHwmonDevice,
    fan: Fan,
) -> (&crate::FanEndpoints, &crate::FanEndpoints) {
    match fan {
        Fan::Cpu => (device.cpu(), device.gpu()),
        Fan::Gpu => (device.gpu(), device.cpu()),
    }
}

fn child_name(path: &std::path::Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("qualification endpoint is a direct UTF-8 child")
}

fn duration_millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

fn safe_after_failure<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    reason: String,
) -> QualificationControlError
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    match ownership.restore_or_contain_firmware_auto(device) {
        FirmwareAutoSafingOutcome::Restored => QualificationControlError::Rejected { reason },
        FirmwareAutoSafingOutcome::Contained {
            restoration,
            containment,
        } => QualificationControlError::Recovered {
            reason,
            restoration: Box::new(restoration),
            containment: Box::new(containment),
        },
        FirmwareAutoSafingOutcome::Critical {
            restoration,
            containment,
        } => QualificationControlError::RestorationFailed {
            reason,
            restoration: Box::new(restoration),
            containment: Box::new(containment),
        },
    }
}
