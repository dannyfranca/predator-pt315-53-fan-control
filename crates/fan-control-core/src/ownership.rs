use std::{
    error::Error,
    fmt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    AcerHwmonDevice, AcerHwmonDiscoveryError, BoundedIdentityBoundFileAccess, Clock,
    CompleteSampleSet, EmergencyContainmentReport, FileIdentity, FirmwareAutoRestorationError,
    FreshSampleGate, IdentityBoundFileAccess, PlatformError, PlatformErrorKind, RuntimeLockAccess,
    RuntimeLockError, SampleReadiness, SampleSetError, SampleSources, ServiceAccess,
    restoration::{
        FIRMWARE_AUTO, contain_custom_fans_at_maximum, recover_firmware_auto, restore_firmware_auto,
    },
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

/// Result of one system recovery cycle after every fan has reached a safe state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemFirmwareAutoRecovery {
    /// Both fans were confirmed in Firmware Auto mode.
    Restored,
    /// Firmware Auto could not be confirmed, so both custom-mode fans were held at maximum PWM.
    Contained,
}

#[derive(Debug)]
pub(crate) enum FirmwareAutoSafingOutcome {
    Restored,
    Contained {
        restoration: FirmwareAutoRestorationError,
        containment: EmergencyContainmentReport,
    },
    Critical {
        restoration: FirmwareAutoRestorationError,
        containment: EmergencyContainmentReport,
    },
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
    controlled_device: Option<FileIdentity>,
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
    /// Discovers the exact fan device while this process holds exclusive controller ownership.
    pub fn discover_acer_hwmon(
        &mut self,
        hwmon_root: &Path,
    ) -> Result<AcerHwmonDevice, AcerHwmonDiscoveryError>
    where
        P: IdentityBoundFileAccess + Sized,
    {
        crate::discover_acer_hwmon(self.platform, hwmon_root)
    }

    pub(crate) fn platform_mut(&mut self) -> &mut P {
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
        P: BoundedIdentityBoundFileAccess + Clock + Sized,
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

    /// Waits until the next gate cycle is due, measured from the previous cycle's start.
    pub fn wait_for_next_fresh_sample(
        &mut self,
        gate: &FreshSampleGate,
    ) -> Result<(), SampleSetError>
    where
        P: Clock + Sized,
    {
        gate.wait_for_next_sample(self.platform)
    }

    pub(crate) fn begin_custom_transition(&mut self, device: &AcerHwmonDevice) -> (&mut P, u64) {
        self.controlled_device = Some(device.backing_identity());
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
        P: BoundedIdentityBoundFileAccess + Clock,
    {
        if !self.restoration_confirmed {
            return false;
        }
        if self
            .controlled_device
            .is_some_and(|identity| identity != device.backing_identity())
        {
            self.invalidate_firmware_auto_epoch();
            return false;
        }
        let deadline = self
            .platform
            .monotonic_now()
            .saturating_add(crate::NORMAL_SAMPLE_CADENCE);
        let cpu = self.platform.read_bound_before(
            device.root(),
            device.backing_identity(),
            child_name(device.cpu().enable()),
            endpoint_identity(device, device.cpu().enable()),
            deadline,
        );
        let gpu = self.platform.read_bound_before(
            device.root(),
            device.backing_identity(),
            child_name(device.gpu().enable()),
            endpoint_identity(device, device.gpu().enable()),
            deadline,
        );
        let confirmed = matches!(cpu, Ok(ref value) if value.trim() == FIRMWARE_AUTO)
            && matches!(gpu, Ok(ref value) if value.trim() == FIRMWARE_AUTO);
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
        P: BoundedIdentityBoundFileAccess + Clock,
    {
        self.restoration_confirmed = false;
        self.reset_sampling_epoch();
        restore_firmware_auto(self.platform, device)?;
        if let Some(admitted) = self.controlled_device {
            if admitted != device.backing_identity() {
                return Err(FirmwareAutoRestorationError::DifferentController {
                    admitted,
                    restored: device.backing_identity(),
                });
            }
        }
        self.restoration_confirmed = true;
        Ok(())
    }

    pub fn contain_custom_fans_at_maximum(
        &mut self,
        device: &AcerHwmonDevice,
    ) -> EmergencyContainmentReport
    where
        P: BoundedIdentityBoundFileAccess + Clock,
    {
        self.restoration_confirmed = false;
        self.reset_sampling_epoch();
        let report = contain_custom_fans_at_maximum(self.platform, device);
        self.restoration_confirmed = report.restoration_confirmed()
            && self
                .controlled_device
                .is_none_or(|identity| identity == device.backing_identity());
        report
    }

    pub(crate) fn restore_or_contain_firmware_auto(
        &mut self,
        device: &AcerHwmonDevice,
    ) -> FirmwareAutoSafingOutcome
    where
        P: BoundedIdentityBoundFileAccess + Clock,
    {
        match self.restore_firmware_auto(device) {
            Ok(()) => FirmwareAutoSafingOutcome::Restored,
            Err(restoration) => {
                let containment = self.contain_custom_fans_at_maximum(device);
                if containment.restoration_confirmed() && self.restoration_confirmed {
                    FirmwareAutoSafingOutcome::Contained {
                        restoration,
                        containment,
                    }
                } else {
                    FirmwareAutoSafingOutcome::Critical {
                        restoration,
                        containment,
                    }
                }
            }
        }
    }

    pub fn recover_firmware_auto(&mut self, device: &AcerHwmonDevice)
    where
        P: BoundedIdentityBoundFileAccess + Clock,
    {
        self.restoration_confirmed = false;
        self.reset_sampling_epoch();
        recover_firmware_auto(self.platform, device);
        self.restoration_confirmed = self
            .controlled_device
            .is_none_or(|identity| identity == device.backing_identity());
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
    reject_competing_services(platform).inspect_err(|_| {
        crate::emit_fault(crate::RuntimeFault::OwnershipDenied, None);
    })?;
    let lock = platform
        .try_acquire_root_runtime_lock(Path::new(RUNTIME_LOCK_PATH))
        .map_err(ControllerOwnershipError::RuntimeLock)
        .inspect_err(|_| {
            crate::emit_fault(crate::RuntimeFault::OwnershipDenied, None);
        })?;
    if let Err(rejection) = reject_competing_services(platform) {
        crate::emit_fault(crate::RuntimeFault::OwnershipDenied, None);
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
        controlled_device: None,
        restoration_confirmed: false,
        sampling_epoch_started: false,
        sampling_epoch: 0,
    })
}

impl ControllerOwnership<'_, crate::SystemOwnershipPlatform> {
    /// Runs one configuration-independent, FD-pinned Firmware Auto recovery cycle.
    ///
    /// A contained result means the caller must retry. The independent recovery executable keeps
    /// ownership across retries, so no controller can arm between them.
    pub fn recover_system_firmware_auto_cycle(
        &mut self,
        device: &AcerHwmonDevice,
    ) -> Result<SystemFirmwareAutoRecovery, PlatformError> {
        self.restoration_confirmed = false;
        let outcome = self.platform.restore_firmware_auto_cycle(device)?;
        self.restoration_confirmed = outcome == SystemFirmwareAutoRecovery::Restored
            && self
                .controlled_device
                .is_none_or(|identity| identity == device.backing_identity());
        Ok(outcome)
    }
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

fn endpoint_identity(device: &AcerHwmonDevice, path: &Path) -> crate::FileIdentity {
    device
        .endpoint_identity(path)
        .expect("fan endpoint belongs to the discovered device")
}

fn child_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("fan endpoint is a direct UTF-8 child")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FakePlatform, FilePermissions, PlatformOperation};

    const HWMON_ROOT: &str = "/sys/class/hwmon";
    const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

    #[test]
    fn restoring_a_replacement_controller_cannot_authorize_lock_release() {
        let root = Path::new(ACER_ROOT);
        let mut platform = FakePlatform::new();
        platform.insert_file_with_permissions(
            root.join("name"),
            "acer\n",
            FilePermissions::READ_ONLY,
        );
        for channel in 1..=2 {
            platform.insert_file_with_permissions(
                root.join(format!("pwm{channel}")),
                "128\n",
                FilePermissions::READ_WRITE,
            );
            platform.insert_file_with_permissions(
                root.join(format!("pwm{channel}_enable")),
                "1\n",
                FilePermissions::READ_WRITE,
            );
            platform.insert_file_with_permissions(
                root.join(format!("fan{channel}_input")),
                "2400\n",
                FilePermissions::READ_ONLY,
            );
        }
        let original = crate::discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let _ = ownership.begin_custom_transition(&original);

        ownership.platform_mut().rebind_path_identity(root);
        let replacement = ownership
            .discover_acer_hwmon(Path::new(HWMON_ROOT))
            .unwrap();
        assert_ne!(original.backing_identity(), replacement.backing_identity());

        assert!(matches!(
            ownership.restore_firmware_auto(&replacement),
            Err(FirmwareAutoRestorationError::DifferentController { admitted, restored })
                if admitted == original.backing_identity()
                    && restored == replacement.backing_identity()
        ));
        let ownership = ownership.release().unwrap_err().into_ownership();
        assert!(
            !ownership
                .platform()
                .operations()
                .iter()
                .any(|operation| { matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)) })
        );
    }
}
