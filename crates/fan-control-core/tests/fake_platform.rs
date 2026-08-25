use std::{path::Path, time::Duration};

use fan_control_core::{
    Clock, FakePlatform, FakeStep, FileAccess, PlatformError, PlatformErrorKind, PlatformOperation,
    ServiceAccess,
};

#[test]
fn fake_completes_a_two_fan_firmware_auto_round_trip_in_memory() {
    let cpu_enable = Path::new("/sys/class/hwmon/hwmon7/pwm1_enable");
    let gpu_enable = Path::new("/sys/class/hwmon/hwmon7/pwm2_enable");
    let mut platform = FakePlatform::new();
    platform.insert_file(cpu_enable, "1");
    platform.insert_file(gpu_enable, "1");

    for path in [cpu_enable, gpu_enable] {
        assert_eq!(platform.read(path).unwrap(), "1");
        platform.write(path, "2").unwrap();
        assert_eq!(platform.read(path).unwrap(), "2");
    }

    assert_eq!(
        platform.operations(),
        &[
            PlatformOperation::Read(cpu_enable.into()),
            PlatformOperation::Write {
                path: cpu_enable.into(),
                contents: "2".into(),
            },
            PlatformOperation::Read(cpu_enable.into()),
            PlatformOperation::Read(gpu_enable.into()),
            PlatformOperation::Write {
                path: gpu_enable.into(),
                contents: "2".into(),
            },
            PlatformOperation::Read(gpu_enable.into()),
        ]
    );
}

#[test]
fn fake_models_directory_reads_without_consulting_the_host() {
    let hwmon_root = Path::new("/sys/class/hwmon");
    let mut platform = FakePlatform::new();
    platform.insert_file(hwmon_root.join("hwmon7/name"), "acer");
    platform.insert_file(hwmon_root.join("hwmon7/pwm1"), "128");
    platform.insert_file(hwmon_root.join("hwmon8/name"), "coretemp");

    assert_eq!(
        platform.list(hwmon_root).unwrap(),
        vec![hwmon_root.join("hwmon7"), hwmon_root.join("hwmon8")]
    );
    assert!(matches!(
        platform.read(&hwmon_root.join("hwmon999/name")),
        Err(error) if error.kind() == PlatformErrorKind::NotFound
    ));
}

#[test]
fn fake_models_endpoint_disappearance_and_globally_ordered_failures() {
    let first = Path::new("/sys/class/hwmon/hwmon7/pwm1");
    let second = Path::new("/sys/class/hwmon/hwmon7/pwm2");
    let mut platform = FakePlatform::new();
    platform.insert_file(first, "128");
    platform.insert_file(second, "128");
    platform.queue_steps([
        FakeStep::Pass,
        FakeStep::Fail(PlatformError::new(
            PlatformErrorKind::PermissionDenied,
            "ordered write failure",
        )),
        FakeStep::Disappear(second.into()),
    ]);

    assert_eq!(platform.read(first).unwrap(), "128");
    assert!(matches!(
        platform.write(first, "255"),
        Err(error) if error.kind() == PlatformErrorKind::PermissionDenied
    ));
    assert_eq!(platform.file_contents(first), Some("128"));
    assert!(matches!(
        platform.read(second),
        Err(error) if error.kind() == PlatformErrorKind::NotFound
    ));
    assert_eq!(platform.pending_steps(), 0);
}

#[test]
fn fake_models_service_state_monotonic_time_and_delays() {
    let mut platform = FakePlatform::new();
    platform.insert_service("fancontrol.service", true);
    platform.advance_monotonic_time_to(Duration::from_secs(5));

    assert!(platform.is_service_active("fancontrol.service").unwrap());
    assert_eq!(platform.monotonic_now(), Duration::from_secs(5));
    platform.delay(Duration::from_millis(250));
    assert_eq!(platform.monotonic_now(), Duration::from_millis(5_250));
    assert_eq!(platform.delays(), &[Duration::from_millis(250)]);
    assert_eq!(
        platform.operations(),
        &[
            PlatformOperation::ServiceStatus("fancontrol.service".into()),
            PlatformOperation::MonotonicNow,
            PlatformOperation::Delay(Duration::from_millis(250)),
            PlatformOperation::MonotonicNow,
        ]
    );
}

#[test]
#[should_panic(expected = "fake monotonic time cannot move backwards")]
fn fake_monotonic_time_cannot_be_rewound() {
    let mut platform = FakePlatform::new();
    platform.advance_monotonic_time_to(Duration::from_secs(5));
    platform.delay(Duration::from_secs(1));

    platform.advance_monotonic_time_to(Duration::from_secs(4));
}

#[test]
fn failure_steps_are_ordered_across_directory_service_and_file_access() {
    let hwmon_root = Path::new("/sys/class/hwmon");
    let endpoint = hwmon_root.join("hwmon7/pwm1");
    let mut platform = FakePlatform::new();
    platform.insert_file(&endpoint, "128");
    platform.insert_service("fancontrol.service", true);
    platform.queue_steps([
        FakeStep::Pass,
        FakeStep::Fail(PlatformError::new(
            PlatformErrorKind::Unavailable,
            "ordered service failure",
        )),
        FakeStep::Disappear(endpoint.clone()),
    ]);

    assert_eq!(
        platform.list(hwmon_root).unwrap(),
        vec![hwmon_root.join("hwmon7")]
    );
    assert!(matches!(
        platform.is_service_active("fancontrol.service"),
        Err(error) if error.kind() == PlatformErrorKind::Unavailable
    ));
    assert!(matches!(
        platform.read(&endpoint),
        Err(error) if error.kind() == PlatformErrorKind::NotFound
    ));
    assert_eq!(platform.pending_steps(), 0);
    assert_eq!(
        platform.operations(),
        &[
            PlatformOperation::List(hwmon_root.into()),
            PlatformOperation::ServiceStatus("fancontrol.service".into()),
            PlatformOperation::Read(endpoint),
        ]
    );
}
