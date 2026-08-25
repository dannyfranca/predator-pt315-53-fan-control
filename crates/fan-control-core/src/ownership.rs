use std::{
    error::Error,
    fmt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    AcerHwmonDevice, BoundedFileAccess, Clock, CompleteSampleSet, EmergencyContainmentReport,
    FirmwareAutoRestorationError, FreshSampleGate, PlatformError, PlatformErrorKind,
    RuntimeLockAccess, RuntimeLockError, SampleReadiness, SampleSetError, SampleSources,
    ServiceAccess,
    restoration::{contain_custom_fans_at_maximum, recover_firmware_auto, restore_firmware_auto},
};

pub const RUNTIME_LOCK_PATH: &str = "/run/pt31553-fan-control/lock";
pub const COMPETING_FAN_CONTROL_SERVICES: [&str; 4] = [
    "fancontrol.service",
    "nbfc.service",
    "nbfc_service.service",
    "coolercontrold.service",
];

static NEXT_OWNERSHIP_ID: AtomicU64 = AtomicU64::new(1);

/// A second consecutive sample captured while one controller held ownership.
#[derive(Debug, PartialEq)]
pub struct ArmingReadySample {
    sample: CompleteSampleSet,
    ownership_id: u64,
    sampling_epoch: u64,
}

impl ArmingReadySample {
    pub(crate) fn into_parts(self) -> (CompleteSampleSet, u64, u64) {
        (self.sample, self.ownership_id, self.sampling_epoch)
    }
}

#[derive(Debug, PartialEq)]
pub enum OwnershipSampleReadiness {
    AwaitingSecondSample,
    Ready(ArmingReadySample),
}

/// Exclusive ownership bound to the only platform allowed to write fan state.
#[derive(Debug)]
#[must_use = "ownership must restore Firmware Auto and explicitly release its runtime lock"]
pub struct ControllerOwnership<'a, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    platform: &'a mut P,
    lock: Option<P::RuntimeLock>,
    ownership_id: u64,
    restoration_confirmed: bool,
    sampling_epoch_started: bool,
    sampling_epoch: u64,
}

impl<'a, P> ControllerOwnership<'a, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    pub fn platform(&self) -> &P {
        self.platform
    }

    /// Collects a fresh sample only after re-confirming both fans remain in Firmware Auto.
    pub fn collect_fresh_sample(
        &mut self,
        device: &AcerHwmonDevice,
        gate: &mut FreshSampleGate,
        sources: &mut dyn SampleSources,
    ) -> Result<OwnershipSampleReadiness, SampleSetError>
    where
        P: BoundedFileAccess + Clock + Sized,
    {
        if !self.refresh_firmware_auto_confirmation(device) {
            gate.reset();
            return Err(SampleSetError::FirmwareAutoUnconfirmed);
        }
        if !self.sampling_epoch_started {
            gate.reset();
            self.sampling_epoch_started = true;
        }
        match gate.sample(sources, self.platform) {
            Ok(readiness) => Ok(match readiness {
                SampleReadiness::AwaitingSecondSample => {
                    OwnershipSampleReadiness::AwaitingSecondSample
                }
                SampleReadiness::Ready(sample) => {
                    OwnershipSampleReadiness::Ready(ArmingReadySample {
                        sample,
                        ownership_id: self.ownership_id,
                        sampling_epoch: self.sampling_epoch,
                    })
                }
            }),
            Err(error) => {
                self.invalidate_firmware_auto_epoch();
                Err(error)
            }
        }
    }

    pub fn delay(&mut self, duration: std::time::Duration)
    where
        P: Clock,
    {
        self.platform.delay(duration);
    }

    pub(crate) fn begin_custom_transition(&mut self) -> (&mut P, u64) {
        self.restoration_confirmed = false;
        self.reset_sampling_epoch();
        (self.platform, self.sampling_epoch)
    }

    pub(crate) const fn ownership_id(&self) -> u64 {
        self.ownership_id
    }

    pub(crate) const fn sampling_epoch(&self) -> u64 {
        self.sampling_epoch
    }

    pub(crate) const fn custom_epoch_is_current(&self, ownership_id: u64, epoch: u64) -> bool {
        self.ownership_id == ownership_id
            && self.sampling_epoch == epoch
            && !self.restoration_confirmed
    }

    fn reset_sampling_epoch(&mut self) {
        self.sampling_epoch_started = false;
        self.sampling_epoch = self
            .sampling_epoch
            .checked_add(1)
            .expect("controller sampling epoch space exhausted");
    }

    pub(crate) fn refresh_firmware_auto_confirmation(&mut self, device: &AcerHwmonDevice) -> bool
    where
        P: BoundedFileAccess + Clock,
    {
        if !self.restoration_confirmed {
            return false;
        }
        let deadline = self
            .platform
            .monotonic_now()
            .saturating_add(crate::NORMAL_SAMPLE_CADENCE);
        let cpu = self.platform.read_before(device.cpu().enable(), deadline);
        let gpu = self.platform.read_before(device.gpu().enable(), deadline);
        let confirmed = matches!(cpu, Ok(ref value) if value.trim() == "2")
            && matches!(gpu, Ok(ref value) if value.trim() == "2");
        if !confirmed {
            self.invalidate_firmware_auto_epoch();
        }
        confirmed
    }

    fn invalidate_firmware_auto_epoch(&mut self) {
        self.restoration_confirmed = false;
        self.reset_sampling_epoch();
    }

    pub fn restore_firmware_auto(
        &mut self,
        device: &AcerHwmonDevice,
    ) -> Result<(), FirmwareAutoRestorationError>
    where
        P: BoundedFileAccess + Clock,
    {
        self.restoration_confirmed = false;
        self.reset_sampling_epoch();
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
        self.reset_sampling_epoch();
        let report = contain_custom_fans_at_maximum(self.platform, device);
        self.restoration_confirmed = report.restoration_confirmed();
        report
    }

    pub fn recover_firmware_auto(&mut self, device: &AcerHwmonDevice)
    where
        P: BoundedFileAccess + Clock,
    {
        self.restoration_confirmed = false;
        self.reset_sampling_epoch();
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
        ownership_id: NEXT_OWNERSHIP_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("controller ownership ID space exhausted"),
        restoration_confirmed: false,
        sampling_epoch_started: false,
        sampling_epoch: 0,
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
