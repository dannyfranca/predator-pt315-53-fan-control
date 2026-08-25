use std::{path::Path, time::Duration};

use fan_control_core::{
    BoundedFileAccess, Clock, EmergencyContainmentReport, EmergencyFanStatus, FakePlatform,
    FakeRuntimeLock, FakeStep, FanModeFailure, FilePermissions, MaximumPwmReadback, PlatformError,
    PlatformErrorKind, PlatformOperation, RuntimeLockAccess, RuntimeLockError, ServiceAccess,
    acquire_controller_ownership, discover_acer_hwmon,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

#[test]
fn confirmed_custom_fan_is_verified_at_maximum_while_auto_fan_is_untouched() {
    let (mut platform, device, marker) = fixture("1\n", "2\n");

    let report = contain_custom_fans_at_maximum(&mut platform, &device);

    assert_eq!(report.cpu(), &EmergencyFanStatus::MaximumConfirmed);
    assert_eq!(report.gpu(), &EmergencyFanStatus::FirmwareAuto);
    assert_eq!(platform.file_contents(cpu_pwm()), Some("255"));
    assert_eq!(platform.file_contents(gpu_pwm()), Some("128\n"));
    assert_eq!(pwm_writes(&platform, marker), vec![write(cpu_pwm(), "255")]);
}

#[test]
fn unreadable_mode_prevents_pwm_write_and_reports_unconfirmed() {
    let (mut platform, device, marker) = fixture("1\n", "2\n");
    let mode_error = PlatformError::new(PlatformErrorKind::Unavailable, "mode unavailable");
    platform.queue_file_steps([FakeStep::Fail(mode_error.clone()), FakeStep::Pass]);

    let report = contain_custom_fans_at_maximum(&mut platform, &device);

    assert_eq!(
        report.cpu(),
        &EmergencyFanStatus::ModeUnconfirmed(FanModeFailure::Unreadable(mode_error))
    );
    assert_eq!(report.gpu(), &EmergencyFanStatus::FirmwareAuto);
    assert!(pwm_writes(&platform, marker).is_empty());
}

#[test]
fn unexpected_mode_is_not_seized() {
    let (mut platform, device, marker) = fixture("3\n", "2\n");

    let report = contain_custom_fans_at_maximum(&mut platform, &device);

    assert_eq!(
        report.cpu(),
        &EmergencyFanStatus::ModeUnconfirmed(FanModeFailure::Unexpected("3\n".to_owned()))
    );
    assert!(pwm_writes(&platform, marker).is_empty());
}

#[test]
fn failed_maximum_write_is_not_reported_as_confirmed() {
    let (mut platform, device, _) = fixture("1\n", "2\n");
    platform.insert_file(cpu_pwm(), "255\n");
    let write_error = PlatformError::new(PlatformErrorKind::Unavailable, "PWM write rejected");
    platform.queue_file_steps([
        FakeStep::Pass,
        FakeStep::Fail(write_error.clone()),
        FakeStep::Pass,
        FakeStep::Pass,
    ]);

    let report = contain_custom_fans_at_maximum(&mut platform, &device);

    assert_eq!(
        report.cpu(),
        &EmergencyFanStatus::MaximumUnconfirmed {
            write_error: Some(write_error),
            readback: MaximumPwmReadback::Confirmed,
        }
    );
}

#[test]
fn failed_maximum_readback_is_reported_after_a_successful_write() {
    let (mut platform, device, _) = fixture("1\n", "2\n");
    let read_error = PlatformError::new(PlatformErrorKind::Unavailable, "PWM read unavailable");
    platform.queue_file_steps([
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Fail(read_error.clone()),
        FakeStep::Pass,
    ]);

    let report = contain_custom_fans_at_maximum(&mut platform, &device);

    assert_eq!(
        report.cpu(),
        &EmergencyFanStatus::MaximumUnconfirmed {
            write_error: None,
            readback: MaximumPwmReadback::Unreadable(read_error),
        }
    );
    assert_eq!(platform.file_contents(cpu_pwm()), Some("255"));
}

#[test]
fn custom_mode_at_its_deadline_still_has_time_for_write_and_readback() {
    let (mut platform, device, _) = fixture("1\n", "2\n");
    platform.queue_file_steps([
        FakeStep::Advance(Duration::from_secs(1) / 3),
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
    ]);

    let report = contain_custom_fans_at_maximum(&mut platform, &device);

    assert_eq!(report.cpu(), &EmergencyFanStatus::MaximumConfirmed);
    assert_eq!(platform.file_contents(cpu_pwm()), Some("255"));
}

#[test]
fn slow_failure_containment_does_not_postpone_the_next_auto_attempt() {
    let (mut platform, device, _) = fixture("1\n", "1\n");
    platform.queue_file_steps([
        FakeStep::Advance(Duration::from_secs(1)),
        FakeStep::Advance(Duration::from_millis(500)),
    ]);
    let mut platform = AutoAttemptRecorder::new(platform);

    recover_firmware_auto(&mut platform, &device);

    assert_eq!(
        &platform.cpu_auto_write_times[..2],
        &[Duration::ZERO, Duration::from_secs(2)]
    );
    assert_eq!(platform.inner.file_contents(gpu_pwm()), Some("255"));
}

#[test]
fn recovery_keeps_retrying_until_both_auto_readbacks_succeed() {
    let (mut platform, device, _) = fixture("1\n", "1\n");
    let mut steps = Vec::new();
    for _ in 0..3 {
        steps.extend([
            fail("cpu auto write rejected"),
            fail("gpu auto write rejected"),
            FakeStep::Pass,
            FakeStep::Pass,
        ]);
    }
    steps.extend((0..6).map(|_| FakeStep::Pass));
    platform.queue_file_steps(steps);
    recover_firmware_auto(&mut platform, &device);

    assert_eq!(platform.delays(), &[Duration::from_secs(2)]);
    assert_eq!(platform.file_contents(cpu_enable()), Some("2"));
    assert_eq!(platform.file_contents(gpu_enable()), Some("2"));
}

fn fixture(
    cpu_mode: &str,
    gpu_mode: &str,
) -> (FakePlatform, fan_control_core::AcerHwmonDevice, usize) {
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
    let marker = platform.operations().len();
    (platform, device, marker)
}

fn pwm_writes(platform: &FakePlatform, marker: usize) -> Vec<PlatformOperation> {
    platform.operations()[marker..]
        .iter()
        .filter(|operation| {
            matches!(operation, PlatformOperation::Write { path, .. } if path == cpu_pwm() || path == gpu_pwm())
        })
        .cloned()
        .collect()
}

fn contain_custom_fans_at_maximum(
    platform: &mut FakePlatform,
    device: &fan_control_core::AcerHwmonDevice,
) -> EmergencyContainmentReport {
    let mut ownership = acquire_controller_ownership(platform).unwrap();
    ownership.contain_custom_fans_at_maximum(device)
}

fn recover_firmware_auto<P>(platform: &mut P, device: &fan_control_core::AcerHwmonDevice)
where
    P: BoundedFileAccess + Clock + RuntimeLockAccess + ServiceAccess + ?Sized,
{
    let mut ownership = acquire_controller_ownership(platform).unwrap();
    ownership.recover_firmware_auto(device);
    ownership.release().unwrap();
}

fn write(path: &Path, contents: &str) -> PlatformOperation {
    PlatformOperation::Write {
        path: path.to_path_buf(),
        contents: contents.to_owned(),
    }
}

fn cpu_enable() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm1_enable")
}

fn gpu_enable() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm2_enable")
}

fn cpu_pwm() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm1")
}

fn gpu_pwm() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm2")
}

fn fail(message: &str) -> FakeStep {
    FakeStep::Fail(PlatformError::new(PlatformErrorKind::Unavailable, message))
}

struct AutoAttemptRecorder {
    inner: FakePlatform,
    cpu_auto_write_times: Vec<Duration>,
}

impl AutoAttemptRecorder {
    fn new(inner: FakePlatform) -> Self {
        Self {
            inner,
            cpu_auto_write_times: Vec::new(),
        }
    }
}

impl BoundedFileAccess for AutoAttemptRecorder {
    fn read_before(&mut self, path: &Path, deadline: Duration) -> Result<String, PlatformError> {
        self.inner.read_before(path, deadline)
    }

    fn write_before(
        &mut self,
        path: &Path,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        if path == cpu_enable() && contents == "2" {
            self.cpu_auto_write_times.push(self.inner.monotonic_now());
        }
        self.inner.write_before(path, contents, deadline)
    }
}

impl Clock for AutoAttemptRecorder {
    fn monotonic_now(&mut self) -> Duration {
        self.inner.monotonic_now()
    }

    fn delay(&mut self, duration: Duration) {
        self.inner.delay(duration);
    }
}

impl ServiceAccess for AutoAttemptRecorder {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        self.inner.is_service_active(service)
    }
}

impl RuntimeLockAccess for AutoAttemptRecorder {
    type RuntimeLock = FakeRuntimeLock;

    fn try_acquire_root_runtime_lock(
        &mut self,
        path: &Path,
    ) -> Result<Self::RuntimeLock, RuntimeLockError> {
        self.inner.try_acquire_root_runtime_lock(path)
    }

    fn release_runtime_lock(
        &mut self,
        lock: Self::RuntimeLock,
    ) -> Result<(), (Self::RuntimeLock, PlatformError)> {
        self.inner.release_runtime_lock(lock)
    }
}
