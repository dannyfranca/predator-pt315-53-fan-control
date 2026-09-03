//! Qualified daemon startup orchestration.

use std::{error::Error, fmt, path::Path};

use fan_control_core::{
    AcerHwmonDevice, AdmittedPolicyAuthority, ArmedFanControl, BoundedIdentityBoundFileAccess,
    Clock, CompatibilityObservation, ControlLoopHeartbeat, ControllerOwnership, FreshSampleGate,
    GracefulShutdownFailure, NORMAL_SAMPLE_CADENCE, OwnershipSampleReadiness, PlatformError,
    RootOwnedQualificationRecordAccess, RuntimeFault, RuntimeLockAccess, SampleSources,
    SensorControlStep, SensorSourceDiscovery, ServiceAccess, ServiceNotifier, ShutdownController,
    ShutdownRequest, SupervisedControlIterationError, TransientSensorControl,
    TransientSensorControlError, ValidatedConfig, acquire_controller_ownership,
    admit_compatibility, admit_policy_authority, arm_both_fans_safely_until,
    parse_compatibility_v1, parse_config_v1, run_supervised_control_iteration, validate_config_v1,
};

#[cfg(feature = "acceptance-fixture")]
mod acceptance_fixture;
mod system;
#[cfg(feature = "acceptance-fixture")]
pub use acceptance_fixture::run_acceptance_fixture;
pub use system::{
    COMPATIBILITY_DECLARATION_PATH, EDITABLE_CONFIG_PATH, HWMON_ROOT, POWER_SUPPLY_ROOT,
    SystemSampleSources, SystemSensorSourceDiscovery, SystemStartupDiscovery,
    discover_system_startup,
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
    authority: AdmittedPolicyAuthority,
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

    fn into_parts(
        self,
    ) -> (
        ControllerOwnership<'a, P>,
        AcerHwmonDevice,
        AdmittedPolicyAuthority,
        ArmedFanControl,
    ) {
        (self.ownership, self.device, self.authority, self.armed)
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
    ShutdownRequested,
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
            Self::ShutdownRequested => "shutdown-requested",
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
            Self::ShutdownRequested => RuntimeFault::ShutdownRequested,
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
            Self::ShutdownRequested => {
                return formatter.write_str("shutdown requested during startup");
            }
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
    shutdown: &ShutdownRequest,
) -> Result<QualifiedStartup<'a, P>, StartupError>
where
    P: BoundedIdentityBoundFileAccess
        + Clock
        + RootOwnedQualificationRecordAccess
        + RuntimeLockAccess
        + ServiceAccess,
{
    if shutdown.is_requested() {
        return Err(StartupError::ShutdownRequested);
    }
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
    if shutdown.is_requested() {
        return Err(reject_owned(
            ownership,
            &device,
            StartupError::ShutdownRequested,
        ));
    }
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
    if shutdown.is_requested() {
        return Err(reject_owned(
            ownership,
            &device,
            StartupError::ShutdownRequested,
        ));
    }

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
    if shutdown.is_requested() {
        return Err(reject_owned(
            ownership,
            &device,
            StartupError::ShutdownRequested,
        ));
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
    if shutdown.is_requested() {
        return Err(reject_owned(
            ownership,
            &device,
            StartupError::ShutdownRequested,
        ));
    }

    match arm_both_fans_safely_until(
        &mut ownership,
        &device,
        &authority,
        &candidate,
        ready,
        shutdown,
    ) {
        Ok(armed) if shutdown.is_requested() => {
            drop(armed);
            Err(reject_owned(
                ownership,
                &device,
                StartupError::ShutdownRequested,
            ))
        }
        Ok(armed) => Ok(QualifiedStartup {
            ownership,
            device,
            authority,
            armed,
        }),
        Err(_) if shutdown.is_requested() => Err(reject_owned(
            ownership,
            &device,
            StartupError::ShutdownRequested,
        )),
        Err(error) => Err(reject_owned(
            ownership,
            &device,
            StartupError::Arming(error.to_string()),
        )),
    }
}

/// Runs the admitted production controller until shutdown or a latched fault.
///
/// The admitted authority and armed state stay in one capability chain. Every watchdog advance is
/// downstream of a successful real control/recovery iteration. All exits request permanent
/// cancellation, restore both fans to Firmware Auto, and only then release exclusive ownership.
pub fn run_production_control_loop<'a, P, D, N>(
    startup: QualifiedStartup<'a, P>,
    sources: D::Sources,
    discovery: D,
    shutdown: &mut ShutdownController,
    notifier: N,
) -> Result<(), ProductionControlLoopError<N::Error>>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
    D: SensorSourceDiscovery,
    N: ServiceNotifier,
    N::Error: fmt::Display,
{
    let (mut ownership, device, authority, armed) = startup.into_parts();
    let mut control = TransientSensorControl::from_armed(
        armed,
        authority,
        shutdown.request_handle(),
        discovery,
        sources,
    );
    let mut heartbeat = ControlLoopHeartbeat::new(notifier);

    let iteration_failure = loop {
        match run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat) {
            Ok(SensorControlStep::AwaitingRediscovery(_)) => {
                ownership.delay(NORMAL_SAMPLE_CADENCE);
            }
            Ok(_) => {}
            Err(SupervisedControlIterationError::Control(
                TransientSensorControlError::ShutdownRequested,
            )) if shutdown.is_requested() => break None,
            Err(error) => break Some(Box::new(error)),
        }
    };

    let cleanup_failure = shutdown.cleanup(&mut ownership, &device).err();
    if matches!(
        &cleanup_failure,
        Some(GracefulShutdownFailure::Critical { .. })
    ) {
        // A critical result means neither Firmware Auto nor emergency containment could be
        // confirmed. Never let the ownership guard (and its OS lock) drop in that state: retry
        // the bounded recovery cycle forever, holding maximum PWM whenever Custom is observed,
        // until both Firmware Auto readbacks are confirmed.
        // Only the exact controller admitted before entering Custom may authorize release. A
        // replacement singleton Acer hwmon cannot prove that the original controller is safe.
        ownership.recover_firmware_auto(&device);
    }
    if let Err(release) = ownership.release() {
        let source = release.platform_error().cloned();
        return Err(ProductionControlLoopError::Release {
            iteration: iteration_failure,
            cleanup: cleanup_failure,
            reason: release.to_string(),
            source,
        });
    }
    if let Some(cleanup) = cleanup_failure {
        return Err(ProductionControlLoopError::Cleanup {
            iteration: iteration_failure,
            cleanup,
        });
    }
    match iteration_failure {
        Some(error) => Err(ProductionControlLoopError::Iteration(error)),
        None => Ok(()),
    }
}

#[derive(Debug)]
pub enum ProductionControlLoopError<N> {
    Iteration(Box<SupervisedControlIterationError<N>>),
    Cleanup {
        iteration: Option<Box<SupervisedControlIterationError<N>>>,
        cleanup: GracefulShutdownFailure,
    },
    Release {
        iteration: Option<Box<SupervisedControlIterationError<N>>>,
        cleanup: Option<GracefulShutdownFailure>,
        reason: String,
        source: Option<PlatformError>,
    },
}

impl<N> ProductionControlLoopError<N> {
    pub const fn diagnostic_id(&self) -> &'static str {
        match self {
            Self::Cleanup {
                cleanup: GracefulShutdownFailure::Critical { .. },
                ..
            } => "firmware-auto-unconfirmed",
            Self::Cleanup {
                cleanup: GracefulShutdownFailure::Contained { .. },
                ..
            } => "platform-operation-failed",
            Self::Release {
                cleanup: Some(GracefulShutdownFailure::Critical { .. }),
                ..
            } => "firmware-auto-unconfirmed",
            Self::Iteration(_) | Self::Release { .. } => "platform-operation-failed",
        }
    }

    pub const fn runtime_fault(&self) -> RuntimeFault {
        match self {
            Self::Cleanup {
                cleanup: GracefulShutdownFailure::Critical { .. },
                ..
            } => RuntimeFault::FirmwareAutoUnconfirmed,
            Self::Cleanup {
                cleanup: GracefulShutdownFailure::Contained { .. },
                ..
            } => RuntimeFault::PlatformOperation,
            Self::Release {
                cleanup: Some(GracefulShutdownFailure::Critical { .. }),
                ..
            } => RuntimeFault::FirmwareAutoUnconfirmed,
            Self::Iteration(_) | Self::Release { .. } => RuntimeFault::PlatformOperation,
        }
    }
}

impl<N> fmt::Display for ProductionControlLoopError<N>
where
    N: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Iteration(error) => write!(formatter, "production control stopped: {error}"),
            Self::Cleanup { iteration, cleanup } => {
                if let Some(iteration) = iteration {
                    write!(formatter, "{iteration}; cleanup failed: {cleanup}")
                } else {
                    write!(formatter, "cleanup failed: {cleanup}")
                }
            }
            Self::Release {
                iteration,
                cleanup,
                reason,
                ..
            } => {
                if let Some(iteration) = iteration {
                    write!(formatter, "{iteration}; ")?;
                }
                if let Some(cleanup) = cleanup {
                    write!(formatter, "cleanup failed: {cleanup}; ")?;
                }
                write!(formatter, "ownership release failed: {reason}")
            }
        }
    }
}

impl<N> Error for ProductionControlLoopError<N>
where
    N: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cleanup { cleanup, .. } => Some(cleanup),
            Self::Iteration(error) => Some(error.as_ref()),
            Self::Release {
                source: Some(error),
                ..
            } => Some(error),
            Self::Release {
                iteration: Some(error),
                source: None,
                ..
            } => Some(error),
            Self::Release { .. } => None,
        }
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
