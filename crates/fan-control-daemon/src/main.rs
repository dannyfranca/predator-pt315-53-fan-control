use fan_control_core::StartupStatus;

fn main() {
    println!(
        "fan-control-daemon: {}; Custom fan control is disabled",
        StartupStatus::UnqualifiedNotConfigured
    );
}
