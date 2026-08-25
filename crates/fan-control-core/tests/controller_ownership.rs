use std::path::Path;

use fan_control_core::{
    COMPETING_FAN_CONTROL_SERVICES, ControllerOwnershipError, FakePlatform, FakeRuntimeLock,
    FakeRuntimeLockBackend, FakeStep, FilePermissions, PlatformError, PlatformErrorKind,
    PlatformOperation, RuntimeLockAccess, RuntimeLockError, ServiceAccess,
    acquire_controller_ownership, discover_acer_hwmon,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

#[test]
fn one_root_owned_lock_serializes_daemon_and_recovery_ownership() {
    let (mut daemon, device) = fixture("1\n", "1\n");
    let mut recovery = FakePlatform::with_runtime_lock_backend(daemon.runtime_lock_backend());
    let mut ownership = acquire_controller_ownership(&mut daemon).unwrap();

    assert!(matches!(
        acquire_controller_ownership(&mut recovery),
        Err(ControllerOwnershipError::RuntimeLock(
            RuntimeLockError::AlreadyHeld
        ))
    ));

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
    assert!(acquire_controller_ownership(&mut recovery).is_ok());
}

#[test]
fn second_instance_fails_without_writing_fan_state() {
    let (mut daemon, _) = fixture("1\n", "1\n");
    let mut recovery = FakePlatform::with_runtime_lock_backend(daemon.runtime_lock_backend());
    let ownership = acquire_controller_ownership(&mut daemon).unwrap();

    assert!(acquire_controller_ownership(&mut recovery).is_err());

    assert!(
        recovery
            .operations()
            .iter()
            .all(|operation| !matches!(operation, PlatformOperation::Write { .. }))
    );
    drop(ownership);
    assert_eq!(daemon.file_contents(cpu_enable()), Some("1\n"));
    assert_eq!(daemon.file_contents(gpu_enable()), Some("1\n"));
}

#[test]
fn non_root_owned_lock_blocks_admission_without_fan_writes() {
    let backend = FakeRuntimeLockBackend::new();
    backend.set_root_owned(false);
    let mut platform = FakePlatform::with_runtime_lock_backend(backend);

    assert!(matches!(
        acquire_controller_ownership(&mut platform),
        Err(ControllerOwnershipError::RuntimeLock(
            RuntimeLockError::NotRootOwned
        ))
    ));
    assert!(
        platform
            .operations()
            .iter()
            .all(|operation| !matches!(operation, PlatformOperation::Write { .. }))
    );
}

#[test]
fn every_known_competing_service_blocks_admission_before_lock_or_fan_writes() {
    for active_service in COMPETING_FAN_CONTROL_SERVICES {
        let (mut platform, _) = fixture("1\n", "1\n");
        platform.insert_service(active_service, true);
        let marker = platform.operations().len();

        assert_eq!(
            acquire_controller_ownership(&mut platform).unwrap_err(),
            ControllerOwnershipError::CompetingService {
                service: active_service
            }
        );
        assert!(platform.operations()[marker..].iter().all(|operation| {
            !matches!(
                operation,
                PlatformOperation::AcquireRuntimeLock(_) | PlatformOperation::Write { .. }
            )
        }));
    }
}

#[test]
fn uncertain_competing_service_state_fails_closed() {
    let (mut platform, _) = fixture("1\n", "1\n");
    platform.queue_steps([FakeStep::Fail(PlatformError::new(
        PlatformErrorKind::Unavailable,
        "system manager unavailable",
    ))]);

    assert!(matches!(
        acquire_controller_ownership(&mut platform),
        Err(ControllerOwnershipError::ServiceProbe {
            service: "fancontrol.service",
            ..
        })
    ));
    assert!(!platform.operations().iter().any(|operation| matches!(
        operation,
        PlatformOperation::AcquireRuntimeLock(_) | PlatformOperation::Write { .. }
    )));
}

#[test]
fn service_starting_during_lock_acquisition_is_rejected_by_locked_recheck() {
    let (platform, _) = fixture("1\n", "1\n");
    let mut platform = StartsCompetitorAfterLock { inner: platform };

    assert_eq!(
        acquire_controller_ownership(&mut platform).unwrap_err(),
        ControllerOwnershipError::CompetingService {
            service: "fancontrol.service"
        }
    );
    assert!(
        platform
            .inner
            .operations()
            .iter()
            .any(|operation| matches!(operation, PlatformOperation::AcquireRuntimeLock(_)))
    );
    assert!(
        platform
            .inner
            .operations()
            .iter()
            .any(|operation| matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)))
    );
    assert!(
        !platform
            .inner
            .operations()
            .iter()
            .any(|operation| matches!(operation, PlatformOperation::Write { .. }))
    );
}

#[test]
fn ownership_releases_only_after_restoration_writes_and_confirmed_readbacks() {
    let (mut platform, device) = fixture("1\n", "1\n");
    let marker = platform.operations().len();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();

    let operations = &platform.operations()[marker..];
    let release = operations
        .iter()
        .position(|operation| matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)))
        .unwrap();
    assert!(operations[..release].iter().any(|operation| matches!(
        operation,
        PlatformOperation::Write { path, contents }
            if (path == cpu_enable() || path == gpu_enable()) && contents == "2"
    )));
    assert_eq!(platform.file_contents(cpu_enable()), Some("2"));
    assert_eq!(platform.file_contents(gpu_enable()), Some("2"));
}

#[test]
fn failed_restoration_retains_ownership_for_retry() {
    let (mut daemon, device) = fixture("1\n", "1\n");
    let mut recovery = FakePlatform::with_runtime_lock_backend(daemon.runtime_lock_backend());
    daemon.set_file_permissions(cpu_enable(), FilePermissions::READ_ONLY);
    daemon.set_file_permissions(gpu_enable(), FilePermissions::READ_ONLY);
    let mut ownership = acquire_controller_ownership(&mut daemon).unwrap();

    ownership.restore_firmware_auto(&device).unwrap_err();

    assert!(matches!(
        acquire_controller_ownership(&mut recovery),
        Err(ControllerOwnershipError::RuntimeLock(
            RuntimeLockError::AlreadyHeld
        ))
    ));
    let _ownership = ownership;
}

#[test]
fn explicit_release_before_restoration_is_rejected_and_retains_lock() {
    let (mut daemon, device) = fixture("1\n", "1\n");
    let mut recovery = FakePlatform::with_runtime_lock_backend(daemon.runtime_lock_backend());
    let ownership = acquire_controller_ownership(&mut daemon).unwrap();

    let mut ownership = ownership.release().unwrap_err().into_ownership();
    assert!(matches!(
        acquire_controller_ownership(&mut recovery),
        Err(ControllerOwnershipError::RuntimeLock(
            RuntimeLockError::AlreadyHeld
        ))
    ));

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
    assert!(acquire_controller_ownership(&mut recovery).is_ok());
}

#[test]
fn confirmed_auto_containment_allows_explicit_cleanup() {
    let (mut platform, device) = fixture("2\n", "2\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();

    let report = ownership.contain_custom_fans_at_maximum(&device);

    assert!(report.restoration_confirmed());
    ownership.release().unwrap();
}

#[test]
fn unsuccessful_operation_clears_an_earlier_restoration_confirmation() {
    let (mut platform, device) = fixture("1\n", "1\n");
    platform.queue_file_steps([
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Fail(PlatformError::new(
            PlatformErrorKind::Unavailable,
            "CPU mode changed outside controller ownership",
        )),
    ]);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    ownership.restore_firmware_auto(&device).unwrap();

    let report = ownership.contain_custom_fans_at_maximum(&device);

    assert!(!report.restoration_confirmed());
    assert!(ownership.release().is_err());
}

fn fixture(cpu_mode: &str, gpu_mode: &str) -> (FakePlatform, fan_control_core::AcerHwmonDevice) {
    let root = Path::new(ACER_ROOT);
    let mut platform = FakePlatform::new();
    platform.insert_file_with_permissions(root.join("name"), "acer\n", FilePermissions::READ_ONLY);
    for channel in 1..=2 {
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}")),
            "128\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}_enable")),
            if channel == 1 { cpu_mode } else { gpu_mode },
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("fan{channel}_input")),
            "2400\n",
            FilePermissions::READ_ONLY,
        );
    }
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    (platform, device)
}

fn cpu_enable() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm1_enable")
}

fn gpu_enable() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm2_enable")
}

#[derive(Debug)]
struct StartsCompetitorAfterLock {
    inner: FakePlatform,
}

impl ServiceAccess for StartsCompetitorAfterLock {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        self.inner.is_service_active(service)
    }
}

impl RuntimeLockAccess for StartsCompetitorAfterLock {
    type RuntimeLock = FakeRuntimeLock;

    fn try_acquire_root_runtime_lock(
        &mut self,
        path: &Path,
    ) -> Result<Self::RuntimeLock, RuntimeLockError> {
        let lock = self.inner.try_acquire_root_runtime_lock(path)?;
        self.inner.insert_service("fancontrol.service", true);
        Ok(lock)
    }

    fn release_runtime_lock(
        &mut self,
        lock: Self::RuntimeLock,
    ) -> Result<(), (Self::RuntimeLock, PlatformError)> {
        self.inner.release_runtime_lock(lock)
    }
}
