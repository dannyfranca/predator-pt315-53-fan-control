use std::process::Command;

#[test]
fn qualification_reports_that_no_evidence_exists() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .output()
        .expect("qualification executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "fan-control-qualify: unqualified/not configured; run `fan-control-qualify supervised-endurance --help`\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn live_lifecycle_exposes_reboot_resume_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .args(["live-lifecycle", "--help"])
        .output()
        .expect("qualification executable should start");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--observer-approval I-AM-PHYSICALLY-OBSERVING"));
    assert!(stdout.contains("reboot normally"));
}

#[test]
fn supervised_endurance_requires_explicit_observer_approval() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .args(["supervised-endurance", "--help"])
        .output()
        .expect("qualification executable should start");

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("--observer-approval I-AM-PHYSICALLY-OBSERVING")
    );
}
