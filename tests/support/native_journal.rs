use std::{collections::BTreeMap, os::unix::net::UnixDatagram, path::PathBuf, time::Duration};

pub fn journal_receiver(label: &str) -> (UnixDatagram, PathBuf) {
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

pub fn receive_native_event(receiver: &UnixDatagram) -> BTreeMap<String, String> {
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

pub fn assert_no_native_event(receiver: &UnixDatagram) {
    receiver
        .set_read_timeout(Some(Duration::from_millis(25)))
        .unwrap();
    let mut payload = [0_u8; 64];
    let error = receiver.recv(&mut payload).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
}
