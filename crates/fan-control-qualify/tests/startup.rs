use std::process::Command;

#[test]
fn qualification_reports_that_no_evidence_exists() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .output()
        .expect("qualification executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "fan-control-qualify: unqualified/not configured; no qualification evidence exists\n"
    );
    assert!(output.stderr.is_empty());
}
