use std::{error::Error, fmt, time::Duration};

use crate::{AcerHwmonDevice, BoundedFileAccess, Clock, PlatformError};

const FIRMWARE_AUTO: &str = "2";
const MAX_ATTEMPTS: u8 = 3;
const RESTORATION_WINDOW: Duration = Duration::from_secs(2);

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

pub fn restore_firmware_auto<P>(
    platform: &mut P,
    device: &AcerHwmonDevice,
) -> Result<(), FirmwareAutoRestorationError>
where
    P: BoundedFileAccess + Clock + ?Sized,
{
    let started_at = platform.monotonic_now();
    let deadline = started_at.saturating_add(RESTORATION_WINDOW);
    let mut last_cpu = None;
    let mut last_gpu = None;
    let mut attempts = 0;
    let mut now = started_at;

    for attempt in 1..=MAX_ATTEMPTS {
        if attempt > 1 && now >= deadline {
            break;
        }
        attempts = attempt;

        let cpu_write_error = platform
            .write_before(device.cpu().enable(), FIRMWARE_AUTO, deadline)
            .err();
        let gpu_write_error = platform
            .write_before(device.gpu().enable(), FIRMWARE_AUTO, deadline)
            .err();

        let cpu = status(platform, device.cpu().enable(), cpu_write_error, deadline);
        let gpu = status(platform, device.gpu().enable(), gpu_write_error, deadline);
        now = platform.monotonic_now();

        if now > deadline {
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
            return Err(FirmwareAutoRestorationError::DeadlineExceeded {
                attempts,
                cpu: Box::new(cpu),
                gpu: Box::new(gpu),
            });
        }

        last_cpu = Some(cpu);
        last_gpu = Some(gpu);
    }

    Err(FirmwareAutoRestorationError::Unconfirmed {
        attempts,
        cpu: Box::new(last_cpu.expect("a restoration attempt always records CPU status")),
        gpu: Box::new(last_gpu.expect("a restoration attempt always records GPU status")),
    })
}

fn status<F: BoundedFileAccess + ?Sized>(
    files: &mut F,
    enable: &std::path::Path,
    write_error: Option<PlatformError>,
    deadline: Duration,
) -> FanRestorationStatus {
    let readback = match files.read_before(enable, deadline) {
        Ok(value) if value.trim() == FIRMWARE_AUTO => FirmwareAutoReadback::Confirmed,
        Ok(value) => FirmwareAutoReadback::NotAuto(value),
        Err(error) => FirmwareAutoReadback::Unreadable(error),
    };
    FanRestorationStatus {
        write_error,
        readback,
    }
}
