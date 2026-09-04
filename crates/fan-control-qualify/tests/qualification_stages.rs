use std::process::Command;

#[test]
fn exposes_all_available_qualification_stage_commands() {
    for (command, expected) in [
        ("preflight", "preflight --manifest FILE --harness FILE"),
        (
            "firmware-auto-baselines",
            "firmware-auto-baselines --manifest FILE --harness FILE",
        ),
        (
            "fan-calibration",
            "fan-calibration --fan cpu|gpu --manifest FILE",
        ),
        (
            "matched-workload",
            "matched-workload --manifest FILE --harness FILE",
        ),
        (
            "live-lifecycle",
            "live-lifecycle --manifest FILE --harness FILE",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout).unwrap().contains(expected));
    }
}

#[test]
fn stage_commands_reject_unknown_or_missing_arguments_before_hardware_access() {
    for arguments in [
        vec!["preflight", "--manifest", "/tmp/only-manifest"],
        vec!["firmware-auto-baselines", "--unexpected", "/tmp/value"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("required")
                || stderr.contains("unknown argument")
                || stderr.contains("must run as UID 0")
        );
    }
}
