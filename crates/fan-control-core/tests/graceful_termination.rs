use std::{
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use fan_control_core::{
    FilePermissions, GracefulShutdownFailure, PlatformOperation, ShutdownController,
    TerminationSignalHandlers, acquire_controller_ownership, discover_acer_hwmon,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

#[test]
fn termination_and_watchdog_signals_permanently_request_shutdown() {
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGABRT] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "termination_signal_child"])
            .env("FAN_CONTROL_TEST_SIGNAL", signal.to_string())
            .status()
            .unwrap();
        assert!(status.success(), "signal child failed for {signal}");
    }
}

#[test]
fn termination_signal_child() {
    let Ok(signal) = std::env::var("FAN_CONTROL_TEST_SIGNAL") else {
        return;
    };
    let signal = signal.parse().unwrap();
    let shutdown = ShutdownController::new();
    {
        let _handlers = TerminationSignalHandlers::install(shutdown.request_handle()).unwrap();
    }

    assert_eq!(unsafe { libc::raise(signal) }, 0);
    let deadline = Instant::now() + Duration::from_secs(1);
    while !shutdown.is_requested() && Instant::now() < deadline {
        thread::yield_now();
    }

    assert!(shutdown.is_requested());
    shutdown.request();
    assert!(shutdown.is_requested());
}

#[test]
fn cleanup_is_idempotent_and_release_follows_confirmed_auto() {
    let (mut platform, device) = fixture("1\n", "1\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let mut shutdown = ShutdownController::new();

    shutdown.cleanup(&mut ownership, &device).unwrap();
    let cleanup_operations = ownership.platform().operations().len();
    shutdown.cleanup(&mut ownership, &device).unwrap();
    assert_eq!(ownership.platform().operations().len(), cleanup_operations);
    ownership.release().unwrap();

    let operations = platform.operations();
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
fn failed_auto_confirmation_returns_failure_after_containment_and_keeps_ownership() {
    let (mut platform, device) = fixture("1\n", "1\n");
    platform.set_file_permissions(cpu_enable(), FilePermissions::READ_ONLY);
    platform.set_file_permissions(gpu_enable(), FilePermissions::READ_ONLY);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let mut shutdown = ShutdownController::new();

    let failure = shutdown.cleanup(&mut ownership, &device).unwrap_err();

    assert!(matches!(failure, GracefulShutdownFailure::Critical { .. }));
    assert_eq!(ownership.platform().file_contents(cpu_pwm()), Some("255"));
    assert_eq!(ownership.platform().file_contents(gpu_pwm()), Some("255"));
    let operation_count = ownership.platform().operations().len();
    assert_eq!(shutdown.cleanup(&mut ownership, &device), Err(failure));
    assert_eq!(ownership.platform().operations().len(), operation_count);
    assert!(ownership.release().is_err());
}

fn fixture(
    cpu_mode: &str,
    gpu_mode: &str,
) -> (
    fan_control_core::FakePlatform,
    fan_control_core::AcerHwmonDevice,
) {
    let root = Path::new(ACER_ROOT);
    let mut platform = fan_control_core::FakePlatform::new();
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

fn cpu_pwm() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm1")
}

fn gpu_pwm() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm2")
}
