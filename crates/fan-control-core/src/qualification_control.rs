use std::{error::Error, fmt, time::Duration};

use crate::{
    AcerHwmonDevice, BoundedIdentityBoundFileAccess, CalibrationReadbackSample, Clock,
    ControllerOwnership, EmergencyContainmentReport, Fan, FirmwareAutoRestorationError,
    QualificationArmedFanControl, RuntimeLockAccess, ownership::FirmwareAutoSafingOutcome,
};

const CUSTOM_CONTROL: &str = "1";
const MAXIMUM_PWM: &str = "255";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationCommandedCalibrationSample {
    pub commanded_at_monotonic_millis: u64,
    pub sample: CalibrationReadbackSample,
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
