use fan_control_core::StartupStatus;

fn main() {
    println!(
        "fan-control-qualify: {}; no qualification evidence exists",
        StartupStatus::UnqualifiedNotConfigured
    );
}
