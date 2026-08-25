use std::process::Command;

#[test]
fn restoration_reports_that_no_hardware_action_was_attempted() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-restore"))
        .output()
        .expect("restoration executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "fan-control-restore: unqualified/not configured; no hardware restoration attempted\n"
    );
    assert!(output.stderr.is_empty());
}
