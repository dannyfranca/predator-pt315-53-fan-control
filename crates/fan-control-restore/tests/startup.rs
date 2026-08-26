use std::{fs, process::Command};

#[path = "../../../tests/support/native_journal.rs"]
mod native_journal;
use native_journal::{assert_no_native_event, journal_receiver, receive_native_event};

#[test]
fn restoration_reports_its_independent_recovery_role_without_touching_hardware() {
    let (receiver, socket_path) = journal_receiver("restore-status");
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-restore"))
        .arg("--status")
        .env("PT31553_TEST_JOURNALD_SOCKET", &socket_path)
        .output()
        .expect("restoration executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "fan-control-restore: independent Firmware Auto recovery command\n"
    );
    assert!(output.stderr.is_empty());
    assert_no_native_event(&receiver);
    fs::remove_file(socket_path).unwrap();
}

#[test]
fn restoration_entrypoint_delivers_faults_to_native_journald() {
    let (receiver, socket_path) = journal_receiver("restore");
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-restore"))
        .arg("--unsupported-test-command")
        .env("PT31553_TEST_JOURNALD_SOCKET", &socket_path)
        .output()
        .expect("restoration executable should start");

    assert_eq!(output.status.code(), Some(2));
    let event = receive_native_event(&receiver);
    assert_eq!(
        event.get("PT31553_EVENT_ID").map(String::as_str),
        Some("pt31553.runtime-fault.v1")
    );
    assert_eq!(
        event.get("PT31553_FAULT_ID").map(String::as_str),
        Some("configuration-rejected")
    );
    assert_eq!(
        event.get("PT31553_ENDPOINT").map(String::as_str),
        Some("none")
    );
    fs::remove_file(socket_path).unwrap();
}
