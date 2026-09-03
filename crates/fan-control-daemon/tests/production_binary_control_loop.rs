use std::{
    os::unix::net::UnixDatagram,
    process::{Command, Output, Stdio},
    time::Duration,
};

#[test]
fn production_binary_runs_real_cycles_and_recovers_before_readiness() {
    for scenario in ["normal", "rediscovery"] {
        let harness = Harness::new(scenario);
        let output = harness.run();

        assert!(output.status.success(), "{scenario}: {}", stderr(&output));
        assert_eq!(harness.notifications(2), ["READY=1", "WATCHDOG=1"]);
        assert_state(&output, true, true, false, false, true, "ok");
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
        let output = child.wait_with_output().unwrap();

        assert!(
            output.status.success(),
            "signal {signal}: {}",
            stderr(&output)
        );
        assert_state(&output, true, true, false, false, true, "ok");
    }
}

#[test]
fn production_binary_sleep_stop_restores_before_release() {
    let harness = Harness::new("sleep-stop");
    let child = harness
        .command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert_eq!(harness.notifications(2), ["READY=1", "WATCHDOG=1"]);
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert_state(&output, true, true, false, false, true, "ok");
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
    assert_state(&output, true, true, false, false, true, "error");

    let watchdog = Harness::new("notification-transport-failure");
    let child = watchdog
        .command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert_eq!(watchdog.notifications(1), ["READY=1"]);
    watchdog.remove_notify_socket();
    let output = child.wait_with_output().unwrap();
    assert!(
        !output.status.success(),
        "WATCHDOG transport unexpectedly succeeded"
    );
    assert_state(&output, true, true, false, false, true, "error");
}

#[test]
fn production_binary_restores_on_control_notification_timeout_and_authority_faults() {
    for scenario in [
        "control-fault",
        "watchdog-failure",
        "timeout",
        "lost-authority",
    ] {
        let harness = Harness::new(scenario);
        let output = harness.run();

        assert!(
            !output.status.success(),
            "{scenario} unexpectedly succeeded"
        );
        assert_state(&output, true, true, false, false, true, "error");
        if scenario == "watchdog-failure" {
            assert_eq!(harness.notifications(1), ["READY=1"]);
        } else {
            harness.assert_no_notifications();
        }
    }
}

#[test]
fn production_binary_preserves_containment_and_release_ordering() {
    let cases = [
        ("cleanup-contained", true, true, false, true),
        ("cleanup-critical", true, true, true, true),
        ("cleanup-readback-unconfirmed", true, true, true, true),
        ("device-change", true, true, false, true),
        ("release-failure", true, true, false, true),
    ];

    for (scenario, cpu_auto, gpu_auto, maximum_containment, release_attempted) in cases {
        let output = Harness::new(scenario).run();
        assert!(
            !output.status.success(),
            "{scenario} unexpectedly succeeded"
        );
        assert_state(
            &output,
            cpu_auto,
            gpu_auto,
            maximum_containment,
            maximum_containment,
            release_attempted,
            "error",
        );
    }
}

struct Harness {
    _directory: tempfile::TempDir,
    socket: UnixDatagram,
    socket_path: std::path::PathBuf,
    scenario: &'static str,
}

impl Harness {
    fn new(scenario: &'static str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("notify.sock");
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self {
            _directory: directory,
            socket,
            socket_path,
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
        command
    }

    fn run(&self) -> Output {
        self.command().output().unwrap()
    }

    fn remove_notify_socket(&self) {
        std::fs::remove_file(&self.socket_path).unwrap();
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
    cpu_auto: bool,
    gpu_auto: bool,
    cpu_max: bool,
    gpu_max: bool,
    release_attempted: bool,
    result: &str,
) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let expected = format!(
        "fixture-state cpu_auto={cpu_auto} gpu_auto={gpu_auto} cpu_max={cpu_max} gpu_max={gpu_max} release_attempted={release_attempted} release_ordered=true result={result}\n"
    );
    assert_eq!(stdout, expected, "stderr: {}", stderr(output));
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
