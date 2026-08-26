use std::path::Path;

use fan_control_core::{
    FakePlatform, FilePermissions, acquire_controller_ownership, discover_acer_hwmon,
};

mod support;
use support::{diagnostic_field, record_diagnostics};

#[test]
fn firmware_auto_restoration_attempt_is_observable() {
    let root = Path::new("/sys/class/hwmon/hwmon7");
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
            "1\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("fan{channel}_input")),
            "2400\n",
            FilePermissions::READ_ONLY,
        );
    }
    let device = discover_acer_hwmon(&mut platform, Path::new("/sys/class/hwmon")).unwrap();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();

    let (result, diagnostic_events) =
        record_diagnostics(|| ownership.restore_firmware_auto(&device));
    result.unwrap();
    ownership.release().unwrap();

    assert_eq!(diagnostic_events.len(), 1);
    assert_eq!(
        diagnostic_field(&diagnostic_events[0], "event_id"),
        "pt31553.restoration-attempt.v1"
    );
    assert_eq!(diagnostic_field(&diagnostic_events[0], "attempt"), "1");
    assert_eq!(
        diagnostic_field(&diagnostic_events[0], "cpu_enable_endpoint"),
        "acer:cpu:pwm1_enable"
    );
    assert_eq!(
        diagnostic_field(&diagnostic_events[0], "gpu_enable_endpoint"),
        "acer:gpu:pwm2_enable"
    );
}
