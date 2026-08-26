use std::{fs, process::Command};

#[path = "../../../tests/support/native_journal.rs"]
mod native_journal;
use native_journal::{assert_no_native_event, journal_receiver, receive_native_event};

#[test]
fn daemon_reports_that_custom_control_is_unavailable() {
    let (receiver, socket_path) = journal_receiver("daemon-status");
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-daemon"))
        .env("PT31553_TEST_JOURNALD_SOCKET", &socket_path)
        .output()
        .expect("daemon executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "fan-control-daemon: unqualified/not configured; Custom fan control is disabled\n"
    );
    assert!(output.stderr.is_empty());
    assert_no_native_event(&receiver);
    fs::remove_file(socket_path).unwrap();
}

#[test]
fn daemon_entrypoint_delivers_faults_to_native_journald() {
    let (receiver, socket_path) = journal_receiver("daemon");
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-daemon"))
        .env("PT31553_TEST_JOURNALD_SOCKET", &socket_path)
        .env("NOTIFY_SOCKET", "relative-path-is-invalid")
        .output()
        .expect("daemon executable should start");

    assert!(!output.status.success());
    let event = receive_native_event(&receiver);
    assert_eq!(
        event.get("PT31553_EVENT_ID").map(String::as_str),
        Some("pt31553.runtime-fault.v1")
    );
    assert_eq!(
        event.get("PT31553_FAULT_ID").map(String::as_str),
        Some("platform-operation-failed")
    );
    assert_eq!(
        event.get("PT31553_ENDPOINT").map(String::as_str),
        Some("none")
    );
    fs::remove_file(socket_path).unwrap();
}
