use std::{error::Error, fmt, time::Duration};

use crate::{
    AcerHwmonDevice, BoundedIdentityBoundFileAccess, Clock, PlatformError,
    RestorationAttemptDiagnostic, RestorationFanDiagnostic, RestorationReadback, RuntimeFault,
    emit_fault, emit_restoration_attempt,
};

pub(crate) const FIRMWARE_AUTO: &str = "2";
const CUSTOM_CONTROL: &str = "1";
const MAXIMUM_PWM: &str = "255";
const MAX_ATTEMPTS: u8 = 3;
const RESTORATION_WINDOW: Duration = Duration::from_secs(2);
const RECOVERY_INTERVAL: Duration = Duration::from_secs(2);
const RECOVERY_RESTORATION_WINDOW: Duration = Duration::from_secs(1);
const RECOVERY_FAN_WINDOW: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareAutoReadback {
    Confirmed,
    NotAuto(String),
    Unreadable(PlatformError),
}

impl FirmwareAutoReadback {
    pub const fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanRestorationStatus {
    write_error: Option<PlatformError>,
    readback: FirmwareAutoReadback,
}

impl FanRestorationStatus {
    pub const fn write_error(&self) -> Option<&PlatformError> {
        self.write_error.as_ref()
    }

    pub const fn readback(&self) -> &FirmwareAutoReadback {
        &self.readback
    }

    pub const fn is_confirmed(&self) -> bool {
        self.readback.is_confirmed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareAutoRestorationError {
    Unconfirmed {
        attempts: u8,
        cpu: Box<FanRestorationStatus>,
        gpu: Box<FanRestorationStatus>,
    },
    DeadlineExceeded {
        attempts: u8,
        cpu: Box<FanRestorationStatus>,
        gpu: Box<FanRestorationStatus>,
    },
}

impl fmt::Display for FirmwareAutoRestorationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unconfirmed { attempts, cpu, gpu } => write!(
                formatter,
                "Firmware Auto unconfirmed after {attempts} attempts (CPU: {cpu:?}, GPU: {gpu:?})"
            ),
            Self::DeadlineExceeded { attempts, cpu, gpu } => write!(
                formatter,
                "Firmware Auto restoration exceeded its deadline after {attempts} attempts (CPU: {cpu:?}, GPU: {gpu:?})"
            ),
        }
    }
}

impl Error for FirmwareAutoRestorationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaximumPwmReadback {
    Confirmed,
    Unexpected(String),
    Unreadable(PlatformError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FanModeFailure {
    Unexpected(String),
    Unreadable(PlatformError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmergencyFanStatus {
    FirmwareAuto,
    MaximumConfirmed,
    ModeUnconfirmed(FanModeFailure),
    MaximumUnconfirmed {
        write_error: Option<PlatformError>,
        readback: MaximumPwmReadback,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyContainmentReport {
    cpu: EmergencyFanStatus,
    gpu: EmergencyFanStatus,
}

impl EmergencyContainmentReport {
    pub const fn cpu(&self) -> &EmergencyFanStatus {
        &self.cpu
    }

    pub const fn gpu(&self) -> &EmergencyFanStatus {
        &self.gpu
    }

    pub const fn restoration_confirmed(&self) -> bool {
        matches!(self.cpu, EmergencyFanStatus::FirmwareAuto)
            && matches!(self.gpu, EmergencyFanStatus::FirmwareAuto)
    }
}

pub(crate) fn restore_firmware_auto<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
) -> Result<(), FirmwareAutoRestorationError>
where
    P: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    let started_at = platform.monotonic_now();
    let deadline = started_at.saturating_add(RESTORATION_WINDOW);
    restore_firmware_auto_before(platform, device, started_at, deadline)
}

fn restore_firmware_auto_before<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
    started_at: Duration,
    deadline: Duration,
) -> Result<(), FirmwareAutoRestorationError>
where
    P: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    let mut last_cpu = None;
    let mut last_gpu = None;
    let mut attempts = 0;
    let mut now = started_at;

    for attempt in 1..=MAX_ATTEMPTS {
        if attempt > 1 && now >= deadline {
            break;
        }
        attempts = attempt;

        let cpu_write_error = write_bound(
            platform,
            device,
            device.cpu().enable(),
            FIRMWARE_AUTO,
            deadline,
        )
        .err();
        let gpu_write_error = write_bound(
            platform,
            device,
            device.gpu().enable(),
            FIRMWARE_AUTO,
            deadline,
        )
        .err();

        let cpu = status(
            platform,
            device,
            device.cpu().enable(),
            cpu_write_error,
            deadline,
        );
        let gpu = status(
            platform,
            device,
            device.gpu().enable(),
            gpu_write_error,
            deadline,
        );
        emit_attempt(attempt, &cpu, &gpu);
        now = platform.monotonic_now();

        if now > deadline {
            emit_fault(RuntimeFault::RestorationUnconfirmed, None);
            return Err(FirmwareAutoRestorationError::DeadlineExceeded {
                attempts,
                cpu: Box::new(cpu),
                gpu: Box::new(gpu),
            });
        }
        if cpu.is_confirmed() && gpu.is_confirmed() {
            return Ok(());
        }
        if now == deadline && attempt < MAX_ATTEMPTS {
            emit_fault(RuntimeFault::RestorationUnconfirmed, None);
            return Err(FirmwareAutoRestorationError::DeadlineExceeded {
                attempts,
                cpu: Box::new(cpu),
                gpu: Box::new(gpu),
            });
        }

        last_cpu = Some(cpu);
        last_gpu = Some(gpu);
    }

    emit_fault(RuntimeFault::RestorationUnconfirmed, None);
    Err(FirmwareAutoRestorationError::Unconfirmed {
        attempts,
        cpu: Box::new(last_cpu.expect("a restoration attempt always records CPU status")),
        gpu: Box::new(last_gpu.expect("a restoration attempt always records GPU status")),
    })
}

fn emit_attempt(attempt: u8, cpu: &FanRestorationStatus, gpu: &FanRestorationStatus) {
    emit_restoration_attempt(RestorationAttemptDiagnostic {
        attempt,
        cpu: restoration_fan_diagnostic(cpu),
        gpu: restoration_fan_diagnostic(gpu),
    });
}

fn restoration_fan_diagnostic(status: &FanRestorationStatus) -> RestorationFanDiagnostic {
    RestorationFanDiagnostic {
        write_succeeded: status.write_error.is_none(),
        readback: match &status.readback {
            FirmwareAutoReadback::Confirmed => RestorationReadback::FirmwareAuto,
            FirmwareAutoReadback::NotAuto(value) if value.trim() == CUSTOM_CONTROL => {
                RestorationReadback::Custom
            }
            FirmwareAutoReadback::NotAuto(_) => RestorationReadback::Other,
            FirmwareAutoReadback::Unreadable(_) => RestorationReadback::Unreadable,
        },
    }
}

pub(crate) fn contain_custom_fans_at_maximum<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
) -> EmergencyContainmentReport
where
    P: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    let started_at = platform.monotonic_now();
    contain_custom_fans_before(
        platform,
        device,
        started_at.saturating_add(Duration::from_secs(1)),
        started_at.saturating_add(RESTORATION_WINDOW),
    )
}

fn contain_custom_fans_before<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
    cpu_deadline: Duration,
    gpu_deadline: Duration,
) -> EmergencyContainmentReport
where
    P: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    EmergencyContainmentReport {
        cpu: contain_fan(platform, device, device.cpu(), cpu_deadline),
        gpu: contain_fan(platform, device, device.gpu(), gpu_deadline),
    }
}

pub(crate) fn recover_firmware_auto<P>(platform: &mut P, device: &AcerHwmonDevice)
where
    P: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    loop {
        let cycle_started = platform.monotonic_now();
        let next_attempt = cycle_started.saturating_add(RECOVERY_INTERVAL);
        let restoration_deadline = cycle_started.saturating_add(RECOVERY_RESTORATION_WINDOW);
        if restore_firmware_auto_before(platform, device, cycle_started, restoration_deadline)
            .is_ok()
        {
            return;
        }
        let cpu_deadline = restoration_deadline.saturating_add(RECOVERY_FAN_WINDOW);
        if contain_custom_fans_before(platform, device, cpu_deadline, next_attempt)
            .restoration_confirmed()
        {
            return;
        }

        let now = platform.monotonic_now();
        if now < next_attempt {
            platform.delay(next_attempt - now);
        }
    }
}

fn contain_fan<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
    fan: &crate::FanEndpoints,
    deadline: Duration,
) -> EmergencyFanStatus
where
    P: BoundedIdentityBoundFileAccess + Clock + ?Sized,
{
    let started_at = platform.monotonic_now();
    let operation_window = deadline.saturating_sub(started_at) / 3;
    let mode_deadline = started_at.saturating_add(operation_window);
    let write_deadline = mode_deadline.saturating_add(operation_window);

    match read_bound(platform, device, fan.enable(), mode_deadline) {
        Ok(mode) if mode.trim() == FIRMWARE_AUTO => EmergencyFanStatus::FirmwareAuto,
        Ok(mode) if mode.trim() == CUSTOM_CONTROL => {
            let write_error =
                write_bound(platform, device, fan.pwm(), MAXIMUM_PWM, write_deadline).err();
            let readback = match read_bound(platform, device, fan.pwm(), deadline) {
                Ok(value) if value.trim() == MAXIMUM_PWM => MaximumPwmReadback::Confirmed,
                Ok(value) => MaximumPwmReadback::Unexpected(value),
                Err(error) => MaximumPwmReadback::Unreadable(error),
            };
            if write_error.is_none() && readback == MaximumPwmReadback::Confirmed {
                EmergencyFanStatus::MaximumConfirmed
            } else {
                EmergencyFanStatus::MaximumUnconfirmed {
                    write_error,
                    readback,
                }
            }
        }
        Ok(mode) => EmergencyFanStatus::ModeUnconfirmed(FanModeFailure::Unexpected(mode)),
        Err(error) => EmergencyFanStatus::ModeUnconfirmed(FanModeFailure::Unreadable(error)),
    }
}

fn status<F: BoundedIdentityBoundFileAccess + ?Sized>(
    files: &mut F,
    device: &AcerHwmonDevice,
    enable: &std::path::Path,
    write_error: Option<PlatformError>,
    deadline: Duration,
) -> FanRestorationStatus {
    let readback = match read_bound(files, device, enable, deadline) {
        Ok(value) if value.trim() == FIRMWARE_AUTO => FirmwareAutoReadback::Confirmed,
        Ok(value) => FirmwareAutoReadback::NotAuto(value),
        Err(error) => FirmwareAutoReadback::Unreadable(error),
    };
    FanRestorationStatus {
        write_error,
        readback,
    }
}

fn read_bound(
    files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    path: &std::path::Path,
    deadline: Duration,
) -> Result<String, PlatformError> {
    files.read_bound_before(
        device.root(),
        device.backing_identity(),
        child_name(path),
        endpoint_identity(device, path),
        deadline,
    )
}

fn write_bound(
    files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    path: &std::path::Path,
    contents: &str,
    deadline: Duration,
) -> Result<(), PlatformError> {
    files.write_bound_if_before(
        device.root(),
        device.backing_identity(),
        &[(child_name(path), endpoint_identity(device, path))],
        &[],
        child_name(path),
        contents,
        deadline,
    )
}

fn endpoint_identity(device: &AcerHwmonDevice, path: &std::path::Path) -> crate::FileIdentity {
    device
        .endpoint_identity(path)
        .expect("fan endpoint belongs to the discovered device")
}

fn child_name(path: &std::path::Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("fan endpoint is a direct UTF-8 child")
}
