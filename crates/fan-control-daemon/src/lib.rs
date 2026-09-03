//! Qualified daemon startup orchestration.

use std::{error::Error, fmt, path::Path};

use fan_control_core::{
    AcerHwmonDevice, ArmedFanControl, BoundedIdentityBoundFileAccess, Clock,
    CompatibilityObservation, ControllerOwnership, FreshSampleGate, OwnershipSampleReadiness,
    RootOwnedQualificationRecordAccess, RuntimeFault, RuntimeLockAccess, SampleSources,
    ServiceAccess, ValidatedConfig, acquire_controller_ownership, admit_compatibility,
    admit_policy_authority, arm_both_fans_safely, parse_compatibility_v1, parse_config_v1,
    validate_config_v1,
};

mod system;
pub use system::{
    COMPATIBILITY_DECLARATION_PATH, EDITABLE_CONFIG_PATH, HWMON_ROOT, POWER_SUPPLY_ROOT,
    SystemSampleSources, SystemStartupDiscovery, discover_system_startup,
};

/// Immutable and editable inputs needed for one fail-closed production admission.
pub struct QualifiedStartupInputs<'a> {
    pub editable_config: &'a str,
    pub compatibility_declaration: &'a str,
    pub protected_policy: &'a str,
    pub qualification_record_path: &'a Path,
    pub compatibility_observations: &'a [CompatibilityObservation],
    pub hwmon_root: &'a Path,
}

/// The only successful production-startup result: exclusive ownership plus armed control.
#[must_use = "an admitted startup retains exclusive fan ownership until explicitly restored"]
pub struct QualifiedStartup<'a, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    ownership: ControllerOwnership<'a, P>,
    device: AcerHwmonDevice,
    armed: ArmedFanControl,
}

impl<P> fmt::Debug for QualifiedStartup<'_, P>
where
    P: RuntimeLockAccess + ?Sized,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedStartup")
            .field("device", &self.device)
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

impl<'a, P> QualifiedStartup<'a, P>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess + ?Sized,
{
    pub const fn ownership(&self) -> &ControllerOwnership<'a, P> {
        &self.ownership
    }

    pub const fn armed(&self) -> &ArmedFanControl {
        &self.armed
    }

    pub const fn device(&self) -> &AcerHwmonDevice {
        &self.device
    }

    pub fn into_parts(self) -> (ControllerOwnership<'a, P>, AcerHwmonDevice, ArmedFanControl) {
        (self.ownership, self.device, self.armed)
    }

    /// Safe interim handoff for callers that cannot yet enter the continuous loop.
    pub fn restore_and_release(mut self) -> Result<(), StartupError> {
        if let Err(error) = self.ownership.restore_firmware_auto(&self.device) {
            return Err(recover_after_restore_failure(
                self.ownership,
                &self.device,
                error.to_string(),
            ));
        }
        self.ownership
            .release()
            .map_err(|error| StartupError::Release(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupError {
    Configuration(String),
    Compatibility(String),
    Ownership(String),
    Device(String),
    Safing(String),
    Authority(String),
    Sampling(String),
    Arming(String),
    Release(String),
}

impl StartupError {
    pub const fn diagnostic_id(&self) -> &'static str {
        match self {
            Self::Configuration(_) | Self::Compatibility(_) | Self::Authority(_) => {
                "configuration-rejected"
            }
            Self::Ownership(_) => "ownership-denied",
            Self::Device(_) | Self::Sampling(_) => "sensor-unavailable",
            Self::Safing(_) => "firmware-auto-unconfirmed",
            Self::Arming(_) => "arming-rejected",
            Self::Release(_) => "platform-operation-failed",
        }
    }

    pub const fn runtime_fault(&self) -> RuntimeFault {
        match self {
            Self::Configuration(_) | Self::Compatibility(_) | Self::Authority(_) => {
                RuntimeFault::ConfigurationRejected
            }
            Self::Ownership(_) => RuntimeFault::OwnershipDenied,
            Self::Device(_) | Self::Sampling(_) => RuntimeFault::SensorUnavailable,
            Self::Safing(_) => RuntimeFault::FirmwareAutoUnconfirmed,
            Self::Arming(_) => RuntimeFault::ArmingRejected,
            Self::Release(_) => RuntimeFault::PlatformOperation,
        }
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (stage, reason) = match self {
            Self::Configuration(reason) => ("configuration", reason),
            Self::Compatibility(reason) => ("compatibility", reason),
            Self::Ownership(reason) => ("ownership", reason),
            Self::Device(reason) => ("device discovery", reason),
            Self::Safing(reason) => ("Firmware Auto", reason),
            Self::Authority(reason) => ("qualification authority", reason),
            Self::Sampling(reason) => ("startup sampling", reason),
            Self::Arming(reason) => ("arming", reason),
            Self::Release(reason) => ("ownership release", reason),
        };
        write!(formatter, "{stage} rejected: {reason}")
    }
}

impl Error for StartupError {}

/// Performs the complete admission sequence and is the only daemon path into Custom mode.
///
/// Configuration, compatibility, and discovery are validated before ownership. After ownership,
/// the fan device is rediscovered, Firmware Auto is restored and confirmed, qualification is
/// admitted, and two consecutive real samples are required before the atomic arming handover.
pub fn qualified_startup<'a, P>(
    platform: &'a mut P,
    discovered_device: &AcerHwmonDevice,
    sources: &mut dyn SampleSources,
    inputs: QualifiedStartupInputs<'_>,
) -> Result<QualifiedStartup<'a, P>, StartupError>
where
    P: BoundedIdentityBoundFileAccess
        + Clock
        + RootOwnedQualificationRecordAccess
        + RuntimeLockAccess
        + ServiceAccess,
{
    let candidate = parse_candidate(inputs.editable_config)?;
    let compatibility = parse_compatibility_v1(inputs.compatibility_declaration)
        .map_err(|error| StartupError::Compatibility(error.to_string()))?;
    admit_compatibility(&compatibility, inputs.compatibility_observations)
        .map_err(|error| StartupError::Compatibility(error.to_string()))?;

    let mut ownership = acquire_controller_ownership(platform)
        .map_err(|error| StartupError::Ownership(error.to_string()))?;
    let device = match ownership.discover_acer_hwmon(inputs.hwmon_root) {
        Ok(device) if device == *discovered_device => device,
        Ok(current_device) => {
            return Err(reject_owned(
                ownership,
                &current_device,
                StartupError::Device("Acer hwmon identity changed before ownership".into()),
            ));
        }
        Err(error) => {
            return Err(reject_owned(
                ownership,
                discovered_device,
                StartupError::Device(error.to_string()),
            ));
        }
    };
    if let Err(error) = ownership.restore_firmware_auto(&device) {
        return Err(recover_after_restore_failure(
            ownership,
            &device,
            error.to_string(),
        ));
    }

    let authority = match admit_policy_authority(
        &mut ownership,
        &device,
        inputs.protected_policy,
        inputs.qualification_record_path,
        inputs.compatibility_observations,
    ) {
        Ok(authority) => authority,
        Err(error) => {
            return Err(reject_owned(
                ownership,
                &device,
                StartupError::Authority(error.to_string()),
            ));
        }
    };

    let mut gate = FreshSampleGate::new();
    match ownership.collect_fresh_sample(&device, &mut gate, sources) {
        Ok(OwnershipSampleReadiness::AwaitingSecondSample) => {}
        Ok(OwnershipSampleReadiness::Ready(_)) => unreachable!("a new gate cannot start ready"),
        Err(error) => {
            return Err(reject_owned(
                ownership,
                &device,
                StartupError::Sampling(error.to_string()),
            ));
        }
    }
    if let Err(error) = ownership.wait_for_next_fresh_sample(&gate) {
        return Err(reject_owned(
            ownership,
            &device,
            StartupError::Sampling(error.to_string()),
        ));
    }
    let ready = match ownership.collect_fresh_sample(&device, &mut gate, sources) {
        Ok(OwnershipSampleReadiness::Ready(sample)) => sample,
        Ok(OwnershipSampleReadiness::AwaitingSecondSample) => {
            return Err(reject_owned(
                ownership,
                &device,
                StartupError::Sampling("second sample was not consecutive".into()),
            ));
        }
        Err(error) => {
            return Err(reject_owned(
                ownership,
                &device,
                StartupError::Sampling(error.to_string()),
            ));
        }
    };

    match arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, ready) {
        Ok(armed) => Ok(QualifiedStartup {
            ownership,
            device,
            armed,
        }),
        Err(error) => Err(reject_owned(
            ownership,
            &device,
            StartupError::Arming(error.to_string()),
        )),
    }
}

fn parse_candidate(source: &str) -> Result<ValidatedConfig, StartupError> {
    let config =
        parse_config_v1(source).map_err(|error| StartupError::Configuration(error.to_string()))?;
    validate_config_v1(config).map_err(|error| StartupError::Configuration(error.to_string()))
}

fn reject_owned<P>(
    mut ownership: ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    rejection: StartupError,
) -> StartupError
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess + ?Sized,
{
    if let Err(error) = ownership.restore_firmware_auto(device) {
        return recover_after_restore_failure(
            ownership,
            device,
            format!("{error}; rejection was {rejection}"),
        );
    }
    match ownership.release() {
        Ok(()) => rejection,
        Err(error) => StartupError::Release(format!("{error}; rejection was {rejection}")),
    }
}

fn recover_after_restore_failure<P>(
    mut ownership: ControllerOwnership<'_, P>,
    device: &AcerHwmonDevice,
    restoration: String,
) -> StartupError
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess + ?Sized,
{
    let containment = ownership.contain_custom_fans_at_maximum(device);
    ownership.recover_firmware_auto(device);
    match ownership.release() {
        Ok(()) => StartupError::Safing(format!(
            "{restoration}; emergency containment: {containment:?}; Firmware Auto recovered"
        )),
        Err(release) => {
            StartupError::Release(format!("{release}; restoration failure was {restoration}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use fan_control_core::{
        FakePlatform, FakeStep, FilePermissions, PlatformError, PlatformErrorKind,
        PlatformOperation, acquire_controller_ownership, discover_acer_hwmon,
    };

    use super::{StartupError, recover_after_restore_failure};

    #[test]
    fn restoration_failure_keeps_ownership_through_recovery() {
        let root = Path::new("/sys/class/hwmon/hwmon7");
        let mut platform = FakePlatform::new();
        platform.insert_file_with_permissions(
            root.join("name"),
            "acer\n",
            FilePermissions::READ_ONLY,
        );
        for (name, value, permissions) in [
            ("pwm1", "255\n", FilePermissions::READ_WRITE),
            ("pwm1_enable", "2\n", FilePermissions::READ_WRITE),
            ("fan1_input", "3500\n", FilePermissions::READ_ONLY),
            ("pwm2", "255\n", FilePermissions::READ_WRITE),
            ("pwm2_enable", "2\n", FilePermissions::READ_WRITE),
            ("fan2_input", "3500\n", FilePermissions::READ_ONLY),
        ] {
            platform.insert_file_with_permissions(root.join(name), value, permissions);
        }
        let device = discover_acer_hwmon(&mut platform, Path::new("/sys/class/hwmon")).unwrap();
        platform.queue_file_steps([FakeStep::Fail(PlatformError::new(
            PlatformErrorKind::Unavailable,
            "injected restoration failure",
        ))]);
        let ownership = acquire_controller_ownership(&mut platform).unwrap();

        let error = recover_after_restore_failure(ownership, &device, "restore failed".into());

        assert!(matches!(error, StartupError::Safing(_)));
        assert_eq!(platform.file_contents(root.join("pwm1_enable")), Some("2"));
        assert_eq!(platform.file_contents(root.join("pwm2_enable")), Some("2"));
        assert!(
            platform
                .operations()
                .iter()
                .any(|operation| matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)))
        );
    }
}
