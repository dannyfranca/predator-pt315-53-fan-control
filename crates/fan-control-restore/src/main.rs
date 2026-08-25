use fan_control_core::StartupStatus;

fn main() {
    println!(
        "fan-control-restore: {}; no hardware restoration attempted",
        StartupStatus::UnqualifiedNotConfigured
    );
}
