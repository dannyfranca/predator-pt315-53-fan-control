use std::{
    collections::BTreeMap, fs, os::unix::net::UnixDatagram, process::Command, time::Duration,
};

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

fn journal_receiver(label: &str) -> (UnixDatagram, std::path::PathBuf) {
    let socket_path = std::env::temp_dir().join(format!(
        "pt31553-{label}-journal-{}.socket",
        std::process::id()
    ));
    let receiver = UnixDatagram::bind(&socket_path).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    (receiver, socket_path)
}

fn receive_native_event(receiver: &UnixDatagram) -> BTreeMap<String, String> {
    let mut payload = [0_u8; 2048];
    let length = receiver.recv(&mut payload).unwrap();
    let mut payload = &payload[..length];
    let mut fields = BTreeMap::new();
    while !payload.is_empty() {
        let name_end = payload.iter().position(|byte| *byte == b'\n').unwrap();
        let name = std::str::from_utf8(&payload[..name_end]).unwrap();
        payload = &payload[name_end + 1..];
        let length = u64::from_le_bytes(payload[..8].try_into().unwrap()) as usize;
        payload = &payload[8..];
        let value = std::str::from_utf8(&payload[..length]).unwrap();
        payload = &payload[length + 1..];
        fields.insert(name.to_owned(), value.to_owned());
    }
    fields
}
