use std::{error::Error, fmt, path::Path};

use crate::{
    AcerHwmonDevice, BoundedFileAccess, Clock, EmergencyContainmentReport,
    FirmwareAutoRestorationError, PlatformError, PlatformErrorKind, RuntimeLockAccess,
    RuntimeLockError, ServiceAccess,
    restoration::{contain_custom_fans_at_maximum, recover_firmware_auto, restore_firmware_auto},
};

pub const RUNTIME_LOCK_PATH: &str = "/run/pt31553-fan-control/lock";
pub const COMPETING_FAN_CONTROL_SERVICES: [&str; 4] = [
    "fancontrol.service",
    "nbfc.service",
    "nbfc_service.service",
    "coolercontrold.service",
];

/// Exclusive ownership bound to the only platform allowed to write fan state.
#[derive(Debug)]
#[must_use = "ownership must restore Firmware Auto and explicitly release its runtime lock"]
pub struct ControllerOwnership<'a, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    platform: &'a mut P,
    lock: Option<P::RuntimeLock>,
    restoration_confirmed: bool,
}

impl<'a, P> ControllerOwnership<'a, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    pub fn platform(&self) -> &P {
        self.platform
    }

    pub fn restore_firmware_auto(
        &mut self,
        device: &AcerHwmonDevice,
    ) -> Result<(), FirmwareAutoRestorationError>
    where
        P: BoundedFileAccess + Clock,
    {
        self.restoration_confirmed = false;
        restore_firmware_auto(self.platform, device)?;
        self.restoration_confirmed = true;
        Ok(())
    }

    pub fn contain_custom_fans_at_maximum(
        &mut self,
        device: &AcerHwmonDevice,
    ) -> EmergencyContainmentReport
    where
        P: BoundedFileAccess + Clock,
    {
        self.restoration_confirmed = false;
        let report = contain_custom_fans_at_maximum(self.platform, device);
        self.restoration_confirmed = report.restoration_confirmed();
        report
    }

    pub fn recover_firmware_auto(&mut self, device: &AcerHwmonDevice)
    where
        P: BoundedFileAccess + Clock,
    {
        self.restoration_confirmed = false;
        recover_firmware_auto(self.platform, device);
        self.restoration_confirmed = true;
    }

    pub fn release(mut self) -> Result<(), ControllerReleaseError<'a, P>> {
        if !self.restoration_confirmed {
            return Err(ControllerReleaseError {
                ownership: self,
                source: None,
            });
        }
        let lock = self.lock.take().expect("owned controller must hold a lock");
        match self.platform.release_runtime_lock(lock) {
            Ok(()) => Ok(()),
            Err((lock, source)) => {
                self.lock = Some(lock);
                Err(ControllerReleaseError {
                    ownership: self,
                    source: Some(source),
                })
            }
        }
    }
}

pub struct ControllerReleaseError<'a, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    ownership: ControllerOwnership<'a, P>,
    source: Option<PlatformError>,
}

impl<P> fmt::Debug for ControllerReleaseError<'_, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerReleaseError")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl<'a, P> ControllerReleaseError<'a, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    pub const fn platform_error(&self) -> Option<&PlatformError> {
        self.source.as_ref()
    }

    pub fn into_ownership(self) -> ControllerOwnership<'a, P> {
        self.ownership
    }
}

impl<P> fmt::Display for ControllerReleaseError<'_, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(formatter, "cannot release controller ownership: {source}"),
            None => formatter
                .write_str("cannot release controller ownership before Firmware Auto is confirmed"),
        }
    }
}

impl<P> Error for ControllerReleaseError<'_, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerOwnershipError {
    CompetingService {
        service: &'static str,
    },
    ServiceProbe {
        service: &'static str,
        source: PlatformError,
    },
    RuntimeLock(RuntimeLockError),
}

impl fmt::Display for ControllerOwnershipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompetingService { service } => {
                write!(
                    formatter,
                    "competing fan-control service is active: {service}"
                )
            }
            Self::ServiceProbe { service, source } => {
                write!(
                    formatter,
                    "cannot inspect competing service {service}: {source}"
                )
            }
            Self::RuntimeLock(error) => write!(formatter, "cannot acquire ownership: {error}"),
        }
    }
}

impl Error for ControllerOwnershipError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CompetingService { .. } => None,
            Self::ServiceProbe { source, .. } => Some(source),
            Self::RuntimeLock(error) => Some(error),
        }
    }
}

pub fn acquire_controller_ownership<P>(
    platform: &mut P,
) -> Result<ControllerOwnership<'_, P>, ControllerOwnershipError>
where
    P: RuntimeLockAccess + ServiceAccess + ?Sized,
{
    reject_competing_services(platform)?;
    let lock = platform
        .try_acquire_root_runtime_lock(Path::new(RUNTIME_LOCK_PATH))
        .map_err(ControllerOwnershipError::RuntimeLock)?;
    if let Err(rejection) = reject_competing_services(platform) {
        return match platform.release_runtime_lock(lock) {
            Ok(()) => Err(rejection),
            Err((_lock, error)) => Err(ControllerOwnershipError::RuntimeLock(
                RuntimeLockError::Platform(error),
            )),
        };
    }
    Ok(ControllerOwnership {
        platform,
        lock: Some(lock),
        restoration_confirmed: false,
    })
}

fn reject_competing_services(
    services: &mut (impl ServiceAccess + ?Sized),
) -> Result<(), ControllerOwnershipError> {
    for service in COMPETING_FAN_CONTROL_SERVICES {
        match services.is_service_active(service) {
            Ok(false) => {}
            Ok(true) => return Err(ControllerOwnershipError::CompetingService { service }),
            Err(error) if error.kind() == PlatformErrorKind::NotFound => {}
            Err(source) => {
                return Err(ControllerOwnershipError::ServiceProbe { service, source });
            }
        }
    }
    Ok(())
}
