use std::process::Command;

#[test]
fn daemon_reports_that_custom_control_is_unavailable() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-daemon"))
        .output()
        .expect("daemon executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "fan-control-daemon: unqualified/not configured; Custom fan control is disabled\n"
    );
    assert!(output.stderr.is_empty());
}
