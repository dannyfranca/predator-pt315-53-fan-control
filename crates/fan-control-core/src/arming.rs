use std::{error::Error, fmt, path::Path, time::Duration};

use crate::{
    AcerHwmonDevice, AcerHwmonDiscoveryError, AdmittedPolicyAuthority, ArmingReadySample,
    BoundedIdentityBoundFileAccess, Clock, CompleteSampleSet, ControllerOwnership,
    EmergencyContainmentReport, EnvelopeValidationError, Fan, FanEndpoints,
    FirmwareAutoRestorationError, PlatformError, RuntimeLockAccess, ValidatedConfig,
    ownership::FirmwareAutoSafingOutcome,
    tachometer::{MAXIMUM_PLAUSIBLE_RPM, MINIMUM_PLAUSIBLE_RPM, QualifiedTachometerCalibrations},
};

const FIRMWARE_AUTO: &str = "2";
const CUSTOM_CONTROL: &str = "1";
const MAXIMUM_PWM: &str = "255";
const HANDOVER_WINDOW: Duration = Duration::from_secs(2);
const ARMING_TACHOMETER_RESPONSE_WINDOW: Duration = Duration::from_secs(10);
const TACHOMETER_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Receipt for a completed safety handover.
///
/// The recorded state is current only while [`Self::is_current_for`] returns true for the owning
/// controller. Restoring Firmware Auto invalidates the receipt.
#[derive(Debug, PartialEq)]
pub struct ArmedFanControl {
    ownership_id: u64,
    custom_epoch: u64,
    config: ValidatedConfig,
    device: AcerHwmonDevice,
    calibration: QualifiedTachometerCalibrations,
    cpu_custom_confirmed_at: Duration,
    gpu_custom_confirmed_at: Duration,
    cpu_rpm: u32,
    gpu_rpm: u32,
}

impl ArmedFanControl {
    pub fn is_current_for<P>(&self, ownership: &ControllerOwnership<'_, P>) -> bool
    where
        P: RuntimeLockAccess + ?Sized,
    {
        ownership.custom_epoch_is_current(self.ownership_id, self.custom_epoch)
    }

    pub const fn cpu_rpm(&self) -> u32 {
        self.cpu_rpm
    }

    pub const fn gpu_rpm(&self) -> u32 {
        self.gpu_rpm
    }

    pub(crate) fn into_control_parts(self) -> ArmedControlParts {
        ArmedControlParts {
            ownership_id: self.ownership_id,
            custom_epoch: self.custom_epoch,
            config: self.config,
            device: self.device,
            calibration: self.calibration,
            cpu_custom_confirmed_at: self.cpu_custom_confirmed_at,
            gpu_custom_confirmed_at: self.gpu_custom_confirmed_at,
        }
    }
}

pub(crate) struct ArmedControlParts {
    pub ownership_id: u64,
    pub custom_epoch: u64,
    pub config: ValidatedConfig,
    pub device: AcerHwmonDevice,
    pub calibration: QualifiedTachometerCalibrations,
    pub cpu_custom_confirmed_at: Duration,
    pub gpu_custom_confirmed_at: Duration,
}

#[derive(Debug)]
pub enum FanArmingError {
    Rejected(FanArmingFailure),
    Recovered {
        reason: FanArmingFailure,
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
    RestorationFailed {
        reason: FanArmingFailure,
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
}

impl FanArmingError {
    pub const fn reason(&self) -> &FanArmingFailure {
        match self {
            Self::Rejected(reason)
            | Self::Recovered { reason, .. }
            | Self::RestorationFailed { reason, .. } => reason,
        }
    }
}

impl fmt::Display for FanArmingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(reason) => write!(formatter, "fan arming rejected: {reason}"),
            Self::Recovered {
                reason,
                restoration,
                containment,
            } => write!(
                formatter,
                "fan arming rejected ({reason}); initial Firmware Auto restoration failed ({restoration}), then containment recovered: {containment:?}"
            ),
            Self::RestorationFailed {
                reason,
                restoration,
                containment,
            } => write!(
                formatter,
                "fan arming rejected ({reason}); Firmware Auto restoration failed: {restoration}; emergency containment: {containment:?}"
            ),
        }
    }
}

impl Error for FanArmingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rejected(reason)
            | Self::Recovered { reason, .. }
            | Self::RestorationFailed { reason, .. } => Some(reason),
        }
    }
}

#[derive(Debug)]
pub enum FanArmingFailure {
    Policy(EnvelopeValidationError),
    ForeignOwnershipAuthority,
    ForeignOwnershipSample,
    ObsoleteSampleEpoch,
    SampleFromFuture,
    StaleSample,
    DeviceIdentity(PlatformError),
    DeviceAbi(AcerHwmonDiscoveryError),
    DeviceChanged,
    DeadlineOverflow,
    Platform {
        fan: Fan,
        operation: FanArmingOperation,
        source: PlatformError,
    },
    UnexpectedReadback {
        fan: Fan,
        field: FanArmingReadback,
        operation: FanArmingOperation,
        expected: &'static str,
        actual: String,
    },
    InvalidTachometer {
        fan: Fan,
        actual: String,
    },
    TachometerTimeout {
        cpu_rpm: Option<u32>,
        gpu_rpm: Option<u32>,
    },
}

impl fmt::Display for FanArmingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => write!(formatter, "candidate policy: {error}"),
            Self::ForeignOwnershipAuthority => {
                formatter.write_str("policy authority belongs to a different controller ownership")
            }
            Self::ForeignOwnershipSample => {
                formatter.write_str("fresh sample belongs to a different controller ownership")
            }
            Self::ObsoleteSampleEpoch => {
                formatter.write_str("fresh sample belongs to an obsolete Firmware Auto epoch")
            }
            Self::SampleFromFuture => {
                formatter.write_str("fresh sample timestamp is in the future")
            }
            Self::StaleSample => formatter.write_str("fresh sample expired before arming"),
            Self::DeviceIdentity(error) => write!(formatter, "fan device identity check: {error}"),
            Self::DeviceAbi(error) => write!(formatter, "fan device ABI check: {error}"),
            Self::DeviceChanged => formatter.write_str("fan device identity changed during arming"),
            Self::DeadlineOverflow => formatter.write_str("fan arming deadline overflowed"),
            Self::Platform {
                fan,
                operation,
                source,
            } => write!(formatter, "{} fan {operation} failed: {source}", fan.name()),
            Self::UnexpectedReadback {
                fan,
                field,
                operation,
                expected,
                actual,
            } => write!(
                formatter,
                "{} fan {operation} {field} readback expected {expected}, got {actual:?}",
                fan.name()
            ),
            Self::InvalidTachometer { fan, actual } => write!(
                formatter,
                "{} fan tachometer readback is malformed: {actual:?}",
                fan.name()
            ),
            Self::TachometerTimeout { cpu_rpm, gpu_rpm } => write!(
                formatter,
                "fan tachometer response timed out (CPU: {cpu_rpm:?}, GPU: {gpu_rpm:?})"
            ),
        }
    }
}

impl Error for FanArmingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::DeviceIdentity(error) => Some(error),
            Self::DeviceAbi(error) => Some(error),
            Self::Platform { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanArmingOperation {
    ConfirmFirmwareAuto,
    StageMaximum,
    ReadDuty,
    EnterCustom,
    ConfirmCustom,
    FinalConfirmCustom,
    ReadTachometer,
}

impl fmt::Display for FanArmingOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConfirmFirmwareAuto => "Firmware Auto confirmation",
            Self::StageMaximum => "maximum-duty write",
            Self::ReadDuty => "duty read",
            Self::EnterCustom => "Custom-mode write",
            Self::ConfirmCustom => "Custom-mode confirmation",
            Self::FinalConfirmCustom => "final Custom-mode confirmation",
            Self::ReadTachometer => "tachometer read",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanArmingReadback {
    Mode,
    Duty,
}

impl fmt::Display for FanArmingReadback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Mode => "mode",
            Self::Duty => "duty",
        })
    }
}

/// Performs the only Auto-to-Custom handover.
///
/// The returned proof leaves both fans at PWM 255 and carries the admitted configuration into the
/// first healthy control cycle. Normal demand is calculated only from that cycle's fresh sample.
pub fn arm_both_fans_safely<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    authority: &AdmittedPolicyAuthority,
    candidate: &ValidatedConfig,
    ready_sample: ArmingReadySample,
) -> Result<ArmedFanControl, FanArmingError>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    let (sample, sample_ownership_id, sample_epoch) = ready_sample.into_parts();
    let result = if authority.belongs_to_ownership(ownership.ownership_id()) {
        authority
            .validate_candidate(candidate)
            .map_err(FanArmingFailure::Policy)
    } else {
        Err(FanArmingFailure::ForeignOwnershipAuthority)
    }
    .and_then(|()| {
        if sample_ownership_id != ownership.ownership_id() {
            return Err(FanArmingFailure::ForeignOwnershipSample);
        }
        if sample_epoch != ownership.sampling_epoch() {
            return Err(FanArmingFailure::ObsoleteSampleEpoch);
        }
        let ownership_id = ownership.ownership_id();
        let (platform, custom_epoch) = ownership.begin_custom_transition();
        arm(
            platform,
            device,
            sample,
            candidate.clone(),
            authority.tachometer_calibrations(),
            ownership_id,
            custom_epoch,
        )
    });

    match result {
        Ok(armed) => Ok(armed),
        Err(reason) => match ownership.restore_or_contain_firmware_auto(device) {
            FirmwareAutoSafingOutcome::Restored => Err(FanArmingError::Rejected(reason)),
            FirmwareAutoSafingOutcome::Contained {
                restoration,
                containment,
            } => Err(FanArmingError::Recovered {
                reason,
                restoration: Box::new(restoration),
                containment: Box::new(containment),
            }),
            FirmwareAutoSafingOutcome::Critical {
                restoration,
                containment,
            } => Err(FanArmingError::RestorationFailed {
                reason,
                restoration: Box::new(restoration),
                containment: Box::new(containment),
            }),
        },
    }
}

fn arm<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
    sample: CompleteSampleSet,
    config: ValidatedConfig,
    calibration: QualifiedTachometerCalibrations,
    ownership_id: u64,
    custom_epoch: u64,
) -> Result<ArmedFanControl, FanArmingFailure>
where
    P: BoundedIdentityBoundFileAccess + Clock,
{
    let started_at = platform.monotonic_now();
    let sample_age = started_at
        .checked_sub(sample.completed_at())
        .ok_or(FanArmingFailure::SampleFromFuture)?;
    if sample_age > crate::NORMAL_SAMPLE_CADENCE {
        return Err(FanArmingFailure::StaleSample);
    }
    let handover_deadline = started_at
        .checked_add(HANDOVER_WINDOW)
        .ok_or(FanArmingFailure::DeadlineOverflow)?;
    confirm_device_identity(platform, device, handover_deadline)?;

    confirm(
        device,
        device.cpu().enable(),
        Fan::Cpu,
        FanArmingReadback::Mode,
        FIRMWARE_AUTO,
        FanArmingOperation::ConfirmFirmwareAuto,
        platform,
        handover_deadline,
    )?;
    confirm(
        device,
        device.gpu().enable(),
        Fan::Gpu,
        FanArmingReadback::Mode,
        FIRMWARE_AUTO,
        FanArmingOperation::ConfirmFirmwareAuto,
        platform,
        handover_deadline,
    )?;

    write(
        device,
        device.cpu().pwm(),
        &[
            (device.cpu().enable(), FIRMWARE_AUTO),
            (device.gpu().enable(), FIRMWARE_AUTO),
        ],
        Fan::Cpu,
        MAXIMUM_PWM,
        FanArmingOperation::StageMaximum,
        platform,
        handover_deadline,
    )?;
    write(
        device,
        device.gpu().pwm(),
        &[
            (device.cpu().enable(), FIRMWARE_AUTO),
            (device.gpu().enable(), FIRMWARE_AUTO),
        ],
        Fan::Gpu,
        MAXIMUM_PWM,
        FanArmingOperation::StageMaximum,
        platform,
        handover_deadline,
    )?;
    confirm(
        device,
        device.cpu().pwm(),
        Fan::Cpu,
        FanArmingReadback::Duty,
        MAXIMUM_PWM,
        FanArmingOperation::ReadDuty,
        platform,
        handover_deadline,
    )?;
    confirm(
        device,
        device.gpu().pwm(),
        Fan::Gpu,
        FanArmingReadback::Duty,
        MAXIMUM_PWM,
        FanArmingOperation::ReadDuty,
        platform,
        handover_deadline,
    )?;

    write(
        device,
        device.cpu().enable(),
        &[
            (device.cpu().enable(), FIRMWARE_AUTO),
            (device.gpu().enable(), FIRMWARE_AUTO),
        ],
        Fan::Cpu,
        CUSTOM_CONTROL,
        FanArmingOperation::EnterCustom,
        platform,
        handover_deadline,
    )?;
    write(
        device,
        device.gpu().enable(),
        &[
            (device.cpu().enable(), CUSTOM_CONTROL),
            (device.gpu().enable(), FIRMWARE_AUTO),
        ],
        Fan::Gpu,
        CUSTOM_CONTROL,
        FanArmingOperation::EnterCustom,
        platform,
        handover_deadline,
    )?;

    let (cpu_custom_confirmed_at, gpu_custom_confirmed_at) = confirm_custom_at_maximum(
        platform,
        device,
        handover_deadline,
        FanArmingOperation::ConfirmCustom,
    )?;
    let (_, _, response_deadline) = await_tachometer_response(platform, device)?;
    confirm_custom_at_maximum(
        platform,
        device,
        response_deadline,
        FanArmingOperation::FinalConfirmCustom,
    )?;
    let (cpu_rpm, gpu_rpm) = await_tachometer_response_before(platform, device, response_deadline)?;
    confirm_custom_at_maximum(
        platform,
        device,
        response_deadline,
        FanArmingOperation::FinalConfirmCustom,
    )?;
    Ok(ArmedFanControl {
        ownership_id,
        custom_epoch,
        config,
        device: device.clone(),
        calibration,
        cpu_custom_confirmed_at,
        gpu_custom_confirmed_at,
        cpu_rpm,
        gpu_rpm,
    })
}

fn confirm_custom_at_maximum(
    platform: &mut (impl BoundedIdentityBoundFileAccess + Clock + ?Sized),
    device: &AcerHwmonDevice,
    deadline: Duration,
    mode_operation: FanArmingOperation,
) -> Result<(Duration, Duration), FanArmingFailure> {
    confirm_fan_at_maximum(
        platform,
        device,
        device.cpu(),
        Fan::Cpu,
        deadline,
        mode_operation,
    )?;
    let cpu_confirmed_at = platform.monotonic_now();
    confirm_fan_at_maximum(
        platform,
        device,
        device.gpu(),
        Fan::Gpu,
        deadline,
        mode_operation,
    )?;
    let gpu_confirmed_at = platform.monotonic_now();
    Ok((cpu_confirmed_at, gpu_confirmed_at))
}

fn confirm_fan_at_maximum(
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    endpoints: &FanEndpoints,
    fan: Fan,
    deadline: Duration,
    mode_operation: FanArmingOperation,
) -> Result<(), FanArmingFailure> {
    confirm(
        device,
        endpoints.enable(),
        fan,
        FanArmingReadback::Mode,
        CUSTOM_CONTROL,
        mode_operation,
        platform,
        deadline,
    )?;
    confirm(
        device,
        endpoints.pwm(),
        fan,
        FanArmingReadback::Duty,
        MAXIMUM_PWM,
        mode_operation,
        platform,
        deadline,
    )
}

fn await_tachometer_response<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
) -> Result<(u32, u32, Duration), FanArmingFailure>
where
    P: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    let deadline = platform
        .monotonic_now()
        .checked_add(ARMING_TACHOMETER_RESPONSE_WINDOW)
        .ok_or(FanArmingFailure::DeadlineOverflow)?;
    let (cpu_rpm, gpu_rpm) = await_tachometer_response_before(platform, device, deadline)?;
    Ok((cpu_rpm, gpu_rpm, deadline))
}

fn await_tachometer_response_before<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
    deadline: Duration,
) -> Result<(u32, u32), FanArmingFailure>
where
    P: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    let mut last_cpu_rpm = None;
    let mut last_gpu_rpm = None;

    loop {
        let now = platform.monotonic_now();
        if now >= deadline {
            return Err(FanArmingFailure::TachometerTimeout {
                cpu_rpm: last_cpu_rpm,
                gpu_rpm: last_gpu_rpm,
            });
        }
        let cpu_rpm = read_tachometer(platform, device, device.cpu(), Fan::Cpu, deadline)?;
        let gpu_rpm = read_tachometer(platform, device, device.gpu(), Fan::Gpu, deadline)?;
        if let (Some(cpu_rpm), Some(gpu_rpm)) = (cpu_rpm, gpu_rpm) {
            return Ok((cpu_rpm, gpu_rpm));
        }
        last_cpu_rpm = cpu_rpm;
        last_gpu_rpm = gpu_rpm;

        let now = platform.monotonic_now();
        if now >= deadline {
            return Err(FanArmingFailure::TachometerTimeout {
                cpu_rpm: last_cpu_rpm,
                gpu_rpm: last_gpu_rpm,
            });
        }
        platform.delay(TACHOMETER_POLL_INTERVAL.min(deadline - now));
    }
}

fn read_tachometer(
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    fan: &FanEndpoints,
    identity: Fan,
    deadline: Duration,
) -> Result<Option<u32>, FanArmingFailure> {
    let raw = platform
        .read_bound_before(
            device.root(),
            device.backing_identity(),
            child_name(fan.tachometer()),
            endpoint_identity(device, fan.tachometer()),
            deadline,
        )
        .map_err(|source| FanArmingFailure::Platform {
            fan: identity,
            operation: FanArmingOperation::ReadTachometer,
            source,
        })?;
    let value = raw.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FanArmingFailure::InvalidTachometer {
            fan: identity,
            actual: raw,
        });
    }
    let Ok(rpm) = value.parse::<u32>() else {
        return Err(FanArmingFailure::InvalidTachometer {
            fan: identity,
            actual: raw,
        });
    };
    if rpm == 0 {
        Ok(None)
    } else if (MINIMUM_PLAUSIBLE_RPM..=MAXIMUM_PLAUSIBLE_RPM).contains(&rpm) {
        Ok(Some(rpm))
    } else {
        Err(FanArmingFailure::InvalidTachometer {
            fan: identity,
            actual: raw,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn confirm(
    device: &AcerHwmonDevice,
    path: &Path,
    fan: Fan,
    field: FanArmingReadback,
    expected: &'static str,
    operation: FanArmingOperation,
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    deadline: Duration,
) -> Result<(), FanArmingFailure> {
    let actual = platform
        .read_bound_before(
            device.root(),
            device.backing_identity(),
            child_name(path),
            endpoint_identity(device, path),
            deadline,
        )
        .map_err(|source| FanArmingFailure::Platform {
            fan,
            operation,
            source,
        })?;
    if actual.trim() != expected {
        return Err(FanArmingFailure::UnexpectedReadback {
            fan,
            field,
            operation,
            expected,
            actual,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write(
    device: &AcerHwmonDevice,
    path: &Path,
    guards: &[(&Path, &str)],
    fan: Fan,
    contents: &str,
    operation: FanArmingOperation,
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    deadline: Duration,
) -> Result<(), FanArmingFailure> {
    let guard_bindings = guards
        .iter()
        .map(|(path, expected)| (child_name(path), *expected))
        .collect::<Vec<_>>();
    platform
        .write_bound_if_before(
            device.root(),
            device.backing_identity(),
            &device
                .endpoint_bindings()
                .map(|(path, identity)| (child_name(path), identity)),
            &guard_bindings,
            child_name(path),
            contents,
            deadline,
        )
        .map_err(|source| FanArmingFailure::Platform {
            fan,
            operation,
            source,
        })
}

fn confirm_device_identity(
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    deadline: Duration,
) -> Result<(), FanArmingFailure> {
    match device.abi_is_current_before(platform, deadline) {
        Ok(true) => Ok(()),
        Ok(false) => Err(FanArmingFailure::DeviceChanged),
        Err(AcerHwmonDiscoveryError::Platform(error)) => {
            Err(FanArmingFailure::DeviceIdentity(error))
        }
        Err(error) => Err(FanArmingFailure::DeviceAbi(error)),
    }
}

fn child_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("discovered endpoint must have a UTF-8 child name")
}

fn endpoint_identity(device: &AcerHwmonDevice, path: &Path) -> crate::FileIdentity {
    device
        .endpoint_identity(path)
        .expect("arming I/O must use a discovered endpoint")
}
