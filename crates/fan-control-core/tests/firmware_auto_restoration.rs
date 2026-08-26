use std::{path::Path, time::Duration};

use fan_control_core::{
    Clock, FakePlatform, FakeStep, Fan, FilePermissions, FirmwareAutoRestorationError,
    PlatformError, PlatformErrorKind, PlatformOperation, acquire_controller_ownership,
    discover_acer_hwmon,
};

mod support;

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

#[test]
fn restores_both_fans_and_confirms_both_readbacks() {
    let (mut platform, device, marker) = fixture("1\n", "1\n");

    restore_firmware_auto(&mut platform, &device).unwrap();

    assert_eq!(platform.file_contents(cpu_enable()), Some("2"));
    assert_eq!(platform.file_contents(gpu_enable()), Some("2"));
    assert!(platform.delays().is_empty());
    assert_eq!(
        restore_operations(&platform, marker),
        expected_successful_attempt()
    );
}

#[test]
fn attempts_both_enable_writes_when_each_other_write_fails() {
    let (mut platform, device, marker) = fixture("1\n", "1\n");
    platform.queue_file_steps([
        fail("cpu attempt 1"),
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        fail("cpu attempt 2"),
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        fail("cpu attempt 3"),
        fail("gpu attempt 3"),
        FakeStep::Pass,
        FakeStep::Pass,
    ]);

    let error = restore_firmware_auto(&mut platform, &device).unwrap_err();

    assert!(matches!(
        error,
        FirmwareAutoRestorationError::Unconfirmed { attempts: 3, .. }
    ));
    let writes = restore_operations(&platform, marker)
        .into_iter()
        .filter(|operation| matches!(operation, PlatformOperation::Write { .. }))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 6);
    assert_eq!(writes[4], write(cpu_enable()));
    assert_eq!(writes[5], write(gpu_enable()));
}

#[test]
fn a_single_fan_write_failure_never_skips_the_other_fan_or_the_next_attempt() {
    for failed_fan in [Fan::Cpu, Fan::Gpu] {
        let (mut platform, device, marker) = fixture("1\n", "1\n");
        platform.queue_file_steps([
            if failed_fan == Fan::Cpu {
                fail("cpu attempt 1")
            } else {
                FakeStep::Pass
            },
            if failed_fan == Fan::Gpu {
                fail("gpu attempt 1")
            } else {
                FakeStep::Pass
            },
            FakeStep::Pass,
            FakeStep::Pass,
        ]);

        restore_firmware_auto(&mut platform, &device).unwrap();

        let writes = restore_operations(&platform, marker)
            .into_iter()
            .filter(|operation| matches!(operation, PlatformOperation::Write { .. }))
            .collect::<Vec<_>>();
        assert_eq!(
            writes,
            vec![
                write(cpu_enable()),
                write(gpu_enable()),
                write(cpu_enable()),
                write(gpu_enable()),
            ],
            "{failed_fan:?} failure must not couple the two restoration attempts"
        );
    }
}

#[test]
fn one_auto_readback_never_counts_as_success() {
    let (mut platform, device, _) = fixture("2\n", "1\n");
    platform.queue_file_steps((0..12).map(|index| {
        if index % 4 < 2 {
            fail("write rejected")
        } else {
            FakeStep::Pass
        }
    }));

    let error = restore_firmware_auto(&mut platform, &device).unwrap_err();

    assert!(matches!(
        error,
        FirmwareAutoRestorationError::Unconfirmed { attempts: 3, .. }
    ));
    assert_eq!(platform.file_contents(cpu_enable()), Some("2\n"));
    assert_eq!(platform.file_contents(gpu_enable()), Some("1\n"));
}

#[test]
fn three_failed_attempts_finish_at_the_two_second_bound() {
    let (mut platform, device, marker) = fixture("1\n", "1\n");
    platform.queue_file_steps((0..12).map(|index| {
        if index % 4 < 2 {
            fail("write rejected")
        } else {
            FakeStep::Pass
        }
    }));

    restore_firmware_auto(&mut platform, &device).unwrap_err();

    assert!(platform.delays().is_empty());
    assert_eq!(
        restore_operations(&platform, marker)
            .iter()
            .filter(|operation| matches!(operation, PlatformOperation::MonotonicNow))
            .count(),
        4
    );
}

#[test]
fn third_failed_attempt_at_exact_deadline_is_unconfirmed_not_timed_out() {
    let (mut platform, device, _) = fixture("1\n", "1\n");
    platform.queue_file_steps([
        fail("cpu write rejected"),
        fail("gpu write rejected"),
        FakeStep::Advance(Duration::ZERO),
        FakeStep::Advance(Duration::from_millis(500)),
        fail("cpu write rejected"),
        fail("gpu write rejected"),
        FakeStep::Advance(Duration::ZERO),
        FakeStep::Advance(Duration::from_millis(500)),
        fail("cpu write rejected"),
        fail("gpu write rejected"),
        FakeStep::Advance(Duration::ZERO),
        FakeStep::Advance(Duration::from_secs(1)),
    ]);

    let error = restore_firmware_auto(&mut platform, &device).unwrap_err();

    assert!(matches!(
        error,
        FirmwareAutoRestorationError::Unconfirmed { attempts: 3, .. }
    ));
    assert_eq!(platform.monotonic_now(), Duration::from_secs(2));
}

#[test]
fn late_confirmation_is_rejected_and_stops_further_attempts() {
    let (mut platform, device, marker) = fixture("1\n", "1\n");
    platform.queue_file_steps((0..4).map(|_| FakeStep::Advance(Duration::from_millis(600))));

    let error = restore_firmware_auto(&mut platform, &device).unwrap_err();

    assert!(matches!(
        error,
        FirmwareAutoRestorationError::DeadlineExceeded { attempts: 1, .. }
    ));
    assert_eq!(platform.monotonic_now(), Duration::from_secs(2));
    assert_eq!(
        restore_operations(&platform, marker)
            .iter()
            .filter(|operation| matches!(operation, PlatformOperation::Write { .. }))
            .count(),
        2
    );
}

#[test]
fn unreadable_first_readback_can_recover_on_an_immediate_retry() {
    let (mut platform, device, marker) = fixture("1\n", "1\n");
    platform.queue_file_steps([
        fail("cpu write rejected"),
        fail("gpu write rejected"),
        fail("cpu read unavailable"),
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
    ]);

    restore_firmware_auto(&mut platform, &device).unwrap();

    let operations = restore_operations(&platform, marker);
    assert_eq!(
        operations
            .iter()
            .filter(|operation| matches!(operation, PlatformOperation::Read(_)))
            .count(),
        4
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| matches!(operation, PlatformOperation::Write { .. }))
            .count(),
        4
    );
}

#[test]
fn unreadable_gpu_readback_triggers_a_retry() {
    let (mut platform, device, marker) = fixture("1\n", "1\n");
    platform.queue_file_steps([
        fail("cpu write rejected"),
        fail("gpu write rejected"),
        FakeStep::Pass,
        fail("gpu read unavailable"),
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
    ]);

    restore_firmware_auto(&mut platform, &device).unwrap();

    assert_eq!(
        restore_operations(&platform, marker)
            .iter()
            .filter(|operation| matches!(operation, PlatformOperation::Write { .. }))
            .count(),
        4
    );
}

#[test]
fn write_errors_are_not_fatal_when_both_readbacks_confirm_auto() {
    let (mut platform, device, marker) = fixture("2\n", "2\n");
    platform.queue_file_steps([
        fail("cpu write rejected"),
        fail("gpu write rejected"),
        FakeStep::Pass,
        FakeStep::Pass,
    ]);

    restore_firmware_auto(&mut platform, &device).unwrap();

    assert_eq!(
        restore_operations(&platform, marker)
            .iter()
            .filter(|operation| matches!(operation, PlatformOperation::Write { .. }))
            .count(),
        2
    );
}

#[test]
fn repeating_a_successful_restoration_is_safe() {
    let (mut platform, device, marker) = fixture("1\n", "1\n");

    restore_firmware_auto(&mut platform, &device).unwrap();
    restore_firmware_auto(&mut platform, &device).unwrap();

    assert_eq!(platform.file_contents(cpu_enable()), Some("2"));
    assert_eq!(platform.file_contents(gpu_enable()), Some("2"));
    assert_eq!(
        restore_operations(&platform, marker)
            .iter()
            .filter(|operation| matches!(operation, PlatformOperation::Write { .. }))
            .count(),
        4
    );
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
    let operation_count = platform.operations().len();
    assert!(operation_count > 0);
    (platform, device, operation_count)
}

fn restore_operations(platform: &FakePlatform, marker: usize) -> Vec<PlatformOperation> {
    platform.operations()[marker..]
        .iter()
        .filter(|operation| {
            !matches!(
                operation,
                PlatformOperation::ServiceStatus(_)
                    | PlatformOperation::AcquireRuntimeLock(_)
                    | PlatformOperation::ReleaseRuntimeLock(_)
            )
        })
        .cloned()
        .collect()
}

fn restore_firmware_auto(
    platform: &mut FakePlatform,
    device: &fan_control_core::AcerHwmonDevice,
) -> Result<(), FirmwareAutoRestorationError> {
    let mut ownership = acquire_controller_ownership(platform).unwrap();
    match ownership.restore_firmware_auto(device) {
        Ok(()) => {
            ownership.release().unwrap();
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn expected_successful_attempt() -> Vec<PlatformOperation> {
    vec![
        PlatformOperation::MonotonicNow,
        write(cpu_enable()),
        write(gpu_enable()),
        PlatformOperation::Read(cpu_enable().to_path_buf()),
        PlatformOperation::Read(gpu_enable().to_path_buf()),
        PlatformOperation::MonotonicNow,
    ]
}

fn write(path: &Path) -> PlatformOperation {
    PlatformOperation::Write {
        path: path.to_path_buf(),
        contents: "2".to_owned(),
    }
}

fn cpu_enable() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm1_enable")
}

fn gpu_enable() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm2_enable")
}

fn fail(message: &str) -> FakeStep {
    FakeStep::Fail(PlatformError::new(PlatformErrorKind::Unavailable, message))
}
