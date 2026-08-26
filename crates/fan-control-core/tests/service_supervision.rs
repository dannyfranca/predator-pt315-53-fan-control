use std::{
    ffi::OsStr,
    fs,
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixDatagram},
    },
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use fan_control_core::{ServiceNotification, ServiceNotifier, SystemdNotifier};

#[test]
fn invalid_notification_address_fails_setup() {
    let error = SystemdNotifier::connect(OsStr::new("relative-notify-socket"), true).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn removed_notification_socket_fails_readiness_send() {
    let socket_path = unique_socket_path();
    let receiver = UnixDatagram::bind(&socket_path).unwrap();
    let mut notifier = SystemdNotifier::connect(socket_path.as_os_str(), true).unwrap();
    fs::remove_file(&socket_path).unwrap();

    assert!(notifier.notify(ServiceNotification::Ready).is_err());
    drop(receiver);
}

#[test]
fn filesystem_notify_socket_receives_ready_then_watchdog_datagrams() {
    let socket_path = unique_socket_path();
    let receiver = UnixDatagram::bind(&socket_path).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut notifier = SystemdNotifier::connect(socket_path.as_os_str(), true).unwrap();

    notifier.notify(ServiceNotification::Ready).unwrap();
    notifier.notify(ServiceNotification::Watchdog).unwrap();
    notifier.notify(ServiceNotification::Watchdog).unwrap();

    assert_eq!(receive(&receiver), b"READY=1");
    assert_eq!(receive(&receiver), b"WATCHDOG=1");
    assert_eq!(receive(&receiver), b"WATCHDOG=1");
    fs::remove_file(socket_path).unwrap();
}

#[test]
fn disabled_watchdog_still_reports_readiness_without_false_heartbeats() {
    let socket_path = unique_socket_path();
    let receiver = UnixDatagram::bind(&socket_path).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut notifier = SystemdNotifier::connect(socket_path.as_os_str(), false).unwrap();

    notifier.notify(ServiceNotification::Ready).unwrap();
    notifier.notify(ServiceNotification::Watchdog).unwrap();

    assert_eq!(receive(&receiver), b"READY=1");
    receiver.set_nonblocking(true).unwrap();
    let error = receiver.recv(&mut [0; 32]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    fs::remove_file(socket_path).unwrap();
}

#[test]
fn linux_abstract_notify_socket_is_supported() {
    let name = format!("pt31553-notify-{}-{}", std::process::id(), next_id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let receiver = UnixDatagram::bind_addr(&address).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let environment_address = format!("@{name}");
    let mut notifier = SystemdNotifier::connect(OsStr::new(&environment_address), true).unwrap();

    notifier.notify(ServiceNotification::Ready).unwrap();
    notifier.notify(ServiceNotification::Watchdog).unwrap();

    assert_eq!(receive(&receiver), b"READY=1");
    assert_eq!(receive(&receiver), b"WATCHDOG=1");
}

fn receive(socket: &UnixDatagram) -> Vec<u8> {
    let mut buffer = [0; 32];
    let received = socket.recv(&mut buffer).unwrap();
    buffer[..received].to_vec()
}

fn unique_socket_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "pt31553-notify-{}-{}.sock",
        std::process::id(),
        next_id()
    ))
}

fn next_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}
