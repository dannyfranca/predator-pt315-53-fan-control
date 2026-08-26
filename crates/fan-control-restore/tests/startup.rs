use std::process::Command;

#[test]
fn restoration_reports_its_independent_recovery_role_without_touching_hardware() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-restore"))
        .arg("--status")
        .output()
        .expect("restoration executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "fan-control-restore: independent Firmware Auto recovery command\n"
    );
    assert!(output.stderr.is_empty());
}
