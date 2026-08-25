use std::{error::Error, fmt, path::Path, time::Duration};

use crate::{
    AcerHwmonDevice, AdmittedPolicyAuthority, ArmingReadySample, BoundedFileAccess, Clock,
    CompleteSampleSet, ControllerOwnership, EmergencyContainmentReport, EnvelopeValidationError,
    Fan, FanEndpoints, FanOutputs, FirmwareAutoRestorationError, PlatformError, RuntimeLockAccess,
    ValidatedConfig, calculate_fan_outputs,
};

const FIRMWARE_AUTO: &str = "2";
const CUSTOM_CONTROL: &str = "1";
const MAXIMUM_PWM: &str = "255";
const HANDOVER_WINDOW: Duration = Duration::from_secs(2);
const ARMING_TACHOMETER_RESPONSE_WINDOW: Duration = Duration::from_secs(10);
const TACHOMETER_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MINIMUM_PLAUSIBLE_ARMING_RPM: u32 = 100;
const MAXIMUM_PLAUSIBLE_ARMING_RPM: u32 = 20_000;

/// Receipt for a completed safety handover.
///
/// The recorded state is current only while [`Self::is_current_for`] returns true for the owning
/// controller. Restoring Firmware Auto invalidates the receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct ArmedFanControl {
    ownership_id: u64,
    custom_epoch: u64,
    initial_outputs: FanOutputs,
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

    pub const fn initial_outputs(&self) -> FanOutputs {
        self.initial_outputs
    }

    pub const fn cpu_rpm(&self) -> u32 {
        self.cpu_rpm
    }

    pub const fn gpu_rpm(&self) -> u32 {
        self.gpu_rpm
    }
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
/// The returned proof leaves both fans at PWM 255. Its initial outputs are calculated from the
/// already-admitted candidate and the second fresh sample, but are deliberately not written until
/// the first healthy control cycle.
pub fn arm_both_fans_safely<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    authority: &AdmittedPolicyAuthority,
    candidate: &ValidatedConfig,
    ready_sample: ArmingReadySample,
) -> Result<ArmedFanControl, FanArmingError>
where
    P: BoundedFileAccess + Clock + RuntimeLockAccess + ?Sized,
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
        let initial_outputs = calculate_fan_outputs(
            candidate,
            sample.cpu_temperature(),
            sample.gpu_temperature(),
            sample.external_power(),
        );
        let ownership_id = ownership.ownership_id();
        let (platform, custom_epoch) = ownership.begin_custom_transition();
        arm(
            platform,
            device,
            sample,
            initial_outputs,
            ownership_id,
            custom_epoch,
        )
    });

    match result {
        Ok(armed) => Ok(armed),
        Err(reason) => match ownership.restore_firmware_auto(device) {
            Ok(()) => Err(FanArmingError::Rejected(reason)),
            Err(restoration) => {
                let containment = ownership.contain_custom_fans_at_maximum(device);
                if containment.restoration_confirmed() {
                    Err(FanArmingError::Recovered {
                        reason,
                        restoration: Box::new(restoration),
                        containment: Box::new(containment),
                    })
                } else {
                    Err(FanArmingError::RestorationFailed {
                        reason,
                        restoration: Box::new(restoration),
                        containment: Box::new(containment),
                    })
                }
            }
        },
    }
}

fn arm<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
    sample: CompleteSampleSet,
    initial_outputs: FanOutputs,
    ownership_id: u64,
    custom_epoch: u64,
) -> Result<ArmedFanControl, FanArmingFailure>
where
    P: BoundedFileAccess + Clock + ?Sized,
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

    confirm(
        device.cpu().enable(),
        Fan::Cpu,
        FanArmingReadback::Mode,
        FIRMWARE_AUTO,
        FanArmingOperation::ConfirmFirmwareAuto,
        platform,
        handover_deadline,
    )?;
    confirm(
        device.gpu().enable(),
        Fan::Gpu,
        FanArmingReadback::Mode,
        FIRMWARE_AUTO,
        FanArmingOperation::ConfirmFirmwareAuto,
        platform,
        handover_deadline,
    )?;

    write(
        device.cpu().pwm(),
        Fan::Cpu,
        MAXIMUM_PWM,
        FanArmingOperation::StageMaximum,
        platform,
        handover_deadline,
    )?;
    write(
        device.gpu().pwm(),
        Fan::Gpu,
        MAXIMUM_PWM,
        FanArmingOperation::StageMaximum,
        platform,
        handover_deadline,
    )?;
    confirm(
        device.cpu().pwm(),
        Fan::Cpu,
        FanArmingReadback::Duty,
        MAXIMUM_PWM,
        FanArmingOperation::ReadDuty,
        platform,
        handover_deadline,
    )?;
    confirm(
        device.gpu().pwm(),
        Fan::Gpu,
        FanArmingReadback::Duty,
        MAXIMUM_PWM,
        FanArmingOperation::ReadDuty,
        platform,
        handover_deadline,
    )?;

    write(
        device.cpu().enable(),
        Fan::Cpu,
        CUSTOM_CONTROL,
        FanArmingOperation::EnterCustom,
        platform,
        handover_deadline,
    )?;
    write(
        device.gpu().enable(),
        Fan::Gpu,
        CUSTOM_CONTROL,
        FanArmingOperation::EnterCustom,
        platform,
        handover_deadline,
    )?;

    confirm_custom_at_maximum(
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
        initial_outputs,
        cpu_rpm,
        gpu_rpm,
    })
}

fn confirm_custom_at_maximum(
    platform: &mut (impl BoundedFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    deadline: Duration,
    mode_operation: FanArmingOperation,
) -> Result<(), FanArmingFailure> {
    for (fan, endpoints) in [(Fan::Cpu, device.cpu()), (Fan::Gpu, device.gpu())] {
        confirm_fan_at_maximum(platform, endpoints, fan, deadline, mode_operation)?;
    }
    Ok(())
}

fn confirm_fan_at_maximum(
    platform: &mut (impl BoundedFileAccess + ?Sized),
    endpoints: &FanEndpoints,
    fan: Fan,
    deadline: Duration,
    mode_operation: FanArmingOperation,
) -> Result<(), FanArmingFailure> {
    confirm(
        endpoints.enable(),
        fan,
        FanArmingReadback::Mode,
        CUSTOM_CONTROL,
        mode_operation,
        platform,
        deadline,
    )?;
    confirm(
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
    P: BoundedFileAccess + Clock + ?Sized,
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
    P: BoundedFileAccess + Clock + ?Sized,
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
        let cpu_rpm = read_tachometer(platform, device.cpu(), Fan::Cpu, deadline)?;
        let gpu_rpm = read_tachometer(platform, device.gpu(), Fan::Gpu, deadline)?;
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
    platform: &mut (impl BoundedFileAccess + ?Sized),
    fan: &FanEndpoints,
    identity: Fan,
    deadline: Duration,
) -> Result<Option<u32>, FanArmingFailure> {
    let raw = platform
        .read_before(fan.tachometer(), deadline)
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
    } else if (MINIMUM_PLAUSIBLE_ARMING_RPM..=MAXIMUM_PLAUSIBLE_ARMING_RPM).contains(&rpm) {
        Ok(Some(rpm))
    } else {
        Err(FanArmingFailure::InvalidTachometer {
            fan: identity,
            actual: raw,
        })
    }
}

fn confirm(
    path: &Path,
    fan: Fan,
    field: FanArmingReadback,
    expected: &'static str,
    operation: FanArmingOperation,
    platform: &mut (impl BoundedFileAccess + ?Sized),
    deadline: Duration,
) -> Result<(), FanArmingFailure> {
    let actual =
        platform
            .read_before(path, deadline)
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

fn write(
    path: &Path,
    fan: Fan,
    contents: &str,
    operation: FanArmingOperation,
    platform: &mut (impl BoundedFileAccess + ?Sized),
    deadline: Duration,
) -> Result<(), FanArmingFailure> {
    platform
        .write_before(path, contents, deadline)
        .map_err(|source| FanArmingFailure::Platform {
            fan,
            operation,
            source,
        })
}
