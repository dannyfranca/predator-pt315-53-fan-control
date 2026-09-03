#![cfg(debug_assertions)]

use std::{
    os::unix::net::UnixDatagram,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHILD_TIMEOUT: Duration = Duration::from_secs(20);

#[test]
fn production_binary_runs_real_cycles_and_recovers_before_readiness() {
    for scenario in ["normal", "rediscovery"] {
        let harness = Harness::new(scenario);
        let output = harness.run();

        assert!(output.status.success(), "{scenario}: {}", stderr(&output));
        assert_eq!(harness.notifications(2), ["READY=1", "WATCHDOG=1"]);
        assert_state(
            &output,
            false,
            false,
            if scenario == "rediscovery" { 3 } else { 1 },
            if scenario == "rediscovery" { 2 } else { 1 },
            true,
            "ok",
        );
    }
}

#[test]
fn production_binary_signals_restore_before_release() {
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGABRT] {
        let harness = Harness::new("signal");
        let child = harness
            .command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        assert_eq!(harness.notifications(2), ["READY=1", "WATCHDOG=1"]);
        assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        let output = wait_with_output_deadline(child);

        assert!(
            output.status.success(),
            "signal {signal}: {}",
            stderr(&output)
        );
        assert_state(&output, false, false, 1, 1, true, "ok");
    }
}

#[test]
fn production_binary_systemd_stop_used_by_sleep_guard_restores_before_release() {
    let harness = Harness::new("sleep-stop");
    let child = harness
        .command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert_eq!(harness.notifications(2), ["READY=1", "WATCHDOG=1"]);
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = wait_with_output_deadline(child);

    assert!(output.status.success(), "{}", stderr(&output));
    // The sleep guard's systemd transaction and fresh-resume gate are covered in sleep_guard.rs;
    // this proves the production daemon side of its synchronous SIGTERM stop boundary.
    assert_state(&output, false, false, 1, 1, true, "ok");
}

#[test]
fn production_binary_restores_on_real_notification_transport_failures() {
    let initial = Harness::new("normal");
    initial.remove_notify_socket();
    let output = initial.run();
    assert!(
        !output.status.success(),
        "initial READY unexpectedly succeeded"
    );
    assert_state(&output, false, false, 1, 1, true, "error");

    let watchdog = Harness::new("notification-transport-failure");
    let child = watchdog
        .command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert_eq!(watchdog.notifications(1), ["READY=1"]);
    watchdog.remove_notify_socket();
    watchdog.release_ready_barrier();
    let output = wait_with_output_deadline(child);
    assert!(
        !output.status.success(),
        "WATCHDOG transport unexpectedly succeeded"
    );
    assert_state(&output, false, false, 1, 1, true, "error");
}

#[test]
fn production_binary_restores_on_control_notification_timeout_and_authority_faults() {
    for (scenario, completed_samples) in [
        ("sample-fault", 0),
        ("actuator-fault", 1),
        ("watchdog-failure", 1),
        ("timeout", 1),
        ("lost-authority", 0),
    ] {
        let harness = Harness::new(scenario);
        let output = harness.run();

        assert!(
            !output.status.success(),
            "{scenario} unexpectedly succeeded"
        );
        assert_state(&output, false, false, completed_samples, 1, true, "error");
        if scenario == "watchdog-failure" {
            assert_eq!(harness.notifications(1), ["READY=1"]);
        } else {
            harness.assert_no_notifications();
        }
    }
}

#[test]
fn production_binary_retains_ownership_when_the_controller_device_changes() {
    let harness = Harness::new("device-change");
    let mut child = harness
        .command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(250));
    assert!(
        child.try_wait().unwrap().is_none(),
        "device-change recovery released ownership and exited"
    );
    harness.assert_no_notifications();
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.stdout.is_empty(),
        "fixture reached release reporting"
    );
}

#[test]
fn production_binary_preserves_containment_and_release_ordering() {
    let cases = [
        ("cleanup-contained", false, false, true),
        ("cleanup-critical", true, false, true),
        ("cleanup-critical-release-failure", true, false, true),
        ("cleanup-containment-unconfirmed", false, true, true),
        ("cleanup-readback-unconfirmed", true, false, true),
        ("release-failure", false, false, true),
    ];

    for (scenario, maximum_containment, maximum_unconfirmed, release_attempted) in cases {
        let output = Harness::new(scenario).run();
        assert!(
            !output.status.success(),
            "{scenario} unexpectedly succeeded"
        );
        assert_state(
            &output,
            maximum_containment,
            maximum_unconfirmed,
            0,
            1,
            release_attempted,
            "error",
        );
        if scenario == "cleanup-critical-release-failure" {
            let diagnostic = stderr(&output);
            assert!(
                diagnostic.contains("Firmware Auto unconfirmed"),
                "{diagnostic}"
            );
            assert!(
                diagnostic.contains("ownership release failed"),
                "{diagnostic}"
            );
        }
    }
}

struct Harness {
    _directory: tempfile::TempDir,
    socket: UnixDatagram,
    socket_path: std::path::PathBuf,
    ready_ack: std::path::PathBuf,
    scenario: &'static str,
}

impl Harness {
    fn new(scenario: &'static str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("notify.sock");
        let ready_ack = directory.path().join("ready.ack");
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self {
            _directory: directory,
            socket,
            socket_path,
            ready_ack,
            scenario,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fan-control-daemon"));
        command
            .args(["--acceptance-fixture", self.scenario])
            .env("NOTIFY_SOCKET", &self.socket_path)
            .env("WATCHDOG_USEC", "6000000")
            .env_remove("WATCHDOG_PID");
        if self.scenario == "notification-transport-failure" {
            command.env("PT31553_ACCEPTANCE_READY_ACK", &self.ready_ack);
        }
        command
    }

    fn run(&self) -> Output {
        let child = self
            .command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_with_output_deadline(child)
    }

    fn remove_notify_socket(&self) {
        std::fs::remove_file(&self.socket_path).unwrap();
    }

    fn release_ready_barrier(&self) {
        std::fs::write(&self.ready_ack, b"continue\n").unwrap();
    }

    fn notifications(&self, count: usize) -> Vec<String> {
        let mut received = Vec::new();
        for _ in 0..count {
            let mut payload = [0_u8; 64];
            let length = self.socket.recv(&mut payload).unwrap();
            received.push(std::str::from_utf8(&payload[..length]).unwrap().to_owned());
        }
        received
    }

    fn assert_no_notifications(&self) {
        self.socket.set_nonblocking(true).unwrap();
        let mut payload = [0_u8; 64];
        match self.socket.recv(&mut payload) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("cannot inspect notification socket: {error}"),
            Ok(length) => panic!(
                "unexpected notification: {}",
                String::from_utf8_lossy(&payload[..length])
            ),
        }
    }
}

fn assert_state(
    output: &Output,
    maximum_containment: bool,
    maximum_unconfirmed: bool,
    completed_samples: usize,
    cpu_custom_writes: usize,
    release_attempted: bool,
    result: &str,
) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let expected = format!(
        "fixture-state cpu_auto=true gpu_auto=true cpu_max={maximum_containment} gpu_max={maximum_containment} cpu_max_unconfirmed={maximum_unconfirmed} gpu_max_unconfirmed={maximum_unconfirmed} completed_samples={completed_samples} cpu_custom_writes={cpu_custom_writes} release_attempted={release_attempted} release_ordered=true result={result}\n"
    );
    assert_eq!(stdout, expected, "stderr: {}", stderr(output));
}

fn wait_with_output_deadline(mut child: Child) -> Output {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("acceptance child timed out: {}", stderr(&output));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
