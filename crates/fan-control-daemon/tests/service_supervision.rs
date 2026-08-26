use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use fan_control_core::{ServiceNotification, ServiceNotifier, SystemdNotifier};

const UNIT: &str = include_str!("../../../systemd/pt31553-fand.service");
const SLEEP_GUARD_UNIT: &str = include_str!("../../../systemd/pt31553-fan-sleep-guard.service");
const INSTALL_PRESET: &str = include_str!("../../../systemd/90-pt31553-fan-control.preset");
const PROBE_ROLE: &str = "PT31553_LIFECYCLE_PROBE_ROLE";
const PROBE_BEHAVIOR: &str = "PT31553_LIFECYCLE_PROBE_BEHAVIOR";
const PROBE_LOG: &str = "PT31553_LIFECYCLE_PROBE_LOG";
const RUN_SYSTEMD_LIFECYCLE: &str = "PT31553_RUN_SYSTEMD_LIFECYCLE";
const USE_SYSTEM_MANAGER: &str = "PT31553_USE_SYSTEM_MANAGER";

#[test]
fn daemon_unit_encodes_the_watchdog_cleanup_and_bounded_crash_contract() {
    let directives = parse_unit(UNIT);

    assert_eq!(directives["Unit"]["StartLimitIntervalSec"], "infinity");
    assert_eq!(directives["Unit"]["StartLimitBurst"], "2");
    assert_eq!(directives["Service"]["Type"], "notify");
    assert_eq!(directives["Service"]["NotifyAccess"], "main");
    assert_eq!(directives["Service"]["WatchdogSec"], "6s");
    assert_eq!(directives["Service"]["Restart"], "on-failure");
    assert_eq!(directives["Service"]["RestartSec"], "2s");
    assert_eq!(directives["Service"]["TimeoutStartSec"], "6s");
    assert_eq!(directives["Service"]["TimeoutStopSec"], "infinity");
    assert_eq!(
        directives["Service"]["RuntimeDirectory"],
        "pt31553-fan-control"
    );
    assert_eq!(directives["Service"]["RuntimeDirectoryMode"], "0700");
    assert_eq!(directives["Service"]["RuntimeDirectoryPreserve"], "yes");
    assert_eq!(directives["Service"]["UMask"], "0077");
    assert_eq!(directives["Service"]["NoNewPrivileges"], "yes");
    assert_eq!(directives["Service"]["CapabilityBoundingSet"], "");
    assert_eq!(directives["Service"]["PrivateTmp"], "yes");
    assert_eq!(directives["Service"]["PrivateDevices"], "yes");
    assert_eq!(directives["Service"]["ProtectSystem"], "strict");
    assert_eq!(directives["Service"]["ProtectHome"], "yes");
    assert_eq!(directives["Service"]["RestrictAddressFamilies"], "AF_UNIX");
    assert_eq!(
        directives["Service"]["ReadWritePaths"],
        "/sys/class/hwmon /run/pt31553-fan-control"
    );
    assert!(!directives["Service"].contains_key("ExecStartPre"));
    assert_eq!(
        directives["Service"]["ExecStopPost"],
        "/usr/bin/pt31553-fan-restore --restore"
    );
}

#[test]
fn installation_keeps_both_units_disabled_until_the_daemon_is_explicitly_enabled() {
    let directives = parse_unit(UNIT);

    assert_eq!(directives["Install"]["WantedBy"], "multi-user.target");
    assert_eq!(
        directives["Install"]["Also"],
        "pt31553-fan-sleep-guard.service"
    );
    assert_eq!(
        INSTALL_PRESET.lines().collect::<Vec<_>>(),
        [
            "disable pt31553-fand.service",
            "disable pt31553-fan-sleep-guard.service",
        ]
    );
    assert!(!INSTALL_PRESET.contains("enable "));
    assert!(!INSTALL_PRESET.contains("start "));

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "pt31553-systemd-install-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let unit_directory = root.join("usr/lib/systemd/system");
    let preset_directory = root.join("usr/lib/systemd/system-preset");
    fs::create_dir_all(&unit_directory).unwrap();
    fs::create_dir_all(&preset_directory).unwrap();
    fs::write(unit_directory.join("pt31553-fand.service"), UNIT).unwrap();
    fs::write(
        unit_directory.join("pt31553-fan-sleep-guard.service"),
        SLEEP_GUARD_UNIT,
    )
    .unwrap();
    fs::write(
        preset_directory.join("90-pt31553-fan-control.preset"),
        INSTALL_PRESET,
    )
    .unwrap();

    assert!(
        Command::new("systemctl")
            .arg(format!("--root={}", root.display()))
            .arg("preset-all")
            .status()
            .unwrap()
            .success()
    );
    for unit in ["pt31553-fand.service", "pt31553-fan-sleep-guard.service"] {
        let output = Command::new("systemctl")
            .arg(format!("--root={}", root.display()))
            .args(["is-enabled", unit])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "disabled\n");
    }
    assert!(
        !root
            .join("etc/systemd/system/multi-user.target.wants/pt31553-fand.service")
            .exists()
    );
    assert!(
        !root
            .join("etc/systemd/system/sleep.target.requires/pt31553-fan-sleep-guard.service")
            .exists()
    );

    assert!(
        Command::new("systemctl")
            .arg(format!("--root={}", root.display()))
            .args(["enable", "pt31553-fand.service"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        fs::symlink_metadata(
            root.join("etc/systemd/system/multi-user.target.wants/pt31553-fand.service")
        )
        .unwrap()
        .file_type()
        .is_symlink()
    );
    assert!(
        fs::symlink_metadata(
            root.join("etc/systemd/system/sleep.target.requires/pt31553-fan-sleep-guard.service")
        )
        .unwrap()
        .file_type()
        .is_symlink()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn daemon_exits_nonzero_when_notification_setup_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-daemon"))
        .env("NOTIFY_SOCKET", "relative-notify-socket")
        .env("WATCHDOG_USEC", "6000000")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("supervision failed")
    );
}

#[test]
fn unqualified_daemon_never_reports_service_readiness() {
    let socket_path = std::env::temp_dir().join(format!(
        "pt31553-unqualified-notify-{}.sock",
        std::process::id()
    ));
    let socket = UnixDatagram::bind(&socket_path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-daemon"))
        .env("NOTIFY_SOCKET", &socket_path)
        .env("WATCHDOG_USEC", "6000000")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let mut payload = [0_u8; 64];
    let error = socket.recv(&mut payload).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    fs::remove_file(socket_path).unwrap();
}

#[test]
fn observable_watchdog_lifecycle_restores_before_restart_then_latches() {
    let directives = parse_unit(UNIT);
    let mut service = ObservableServiceManager::new(&directives);

    assert_eq!(service.start("hang"), ProcessOutcome::WatchdogFailure);
    assert_eq!(service.restore("ok"), ProcessOutcome::Success);
    assert_eq!(service.start("hang"), ProcessOutcome::WatchdogFailure);
    assert_eq!(service.restore("ok"), ProcessOutcome::Success);
    assert_eq!(service.start("hang"), ProcessOutcome::FaultLatched);

    assert_eq!(service.observed_log(), "daemon\nrestore\ndaemon\nrestore\n");
    service.cleanup();
}

#[test]
fn observable_failed_cleanup_blocks_the_next_daemon_command() {
    let directives = parse_unit(UNIT);
    let mut service = ObservableServiceManager::new(&directives);

    assert_eq!(service.start("fail"), ProcessOutcome::Failure);
    assert_eq!(service.restore("fail"), ProcessOutcome::Failure);
    assert_eq!(service.start("fail"), ProcessOutcome::RecoveryBlocked);

    assert_eq!(service.observed_log(), "daemon\nrestore\n");
    service.cleanup();
}

#[test]
#[ignore = "requires an isolated systemd manager; set PT31553_RUN_SYSTEMD_LIFECYCLE=1"]
fn actual_systemd_manager_runs_watchdog_cleanup_restart_and_start_limit() {
    if std::env::var(RUN_SYSTEMD_LIFECYCLE).as_deref() != Ok("1") {
        return;
    }
    assert_actual_systemd_failure_lifecycle("watchdog");
    assert_actual_systemd_failure_lifecycle("fail");
}

fn assert_actual_systemd_failure_lifecycle(daemon_behavior: &str) {
    let system_manager = std::env::var(USE_SYSTEM_MANAGER).as_deref() == Ok("1");
    let unit_directory = if system_manager {
        std::env::temp_dir()
    } else {
        PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").unwrap()).join("systemd/user")
    };
    fs::create_dir_all(&unit_directory).unwrap();
    let unit_name = format!(
        "pt31553-lifecycle-{}-{daemon_behavior}.service",
        std::process::id()
    );
    let unit_path = unit_directory.join(&unit_name);
    let log_directory = if system_manager {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let log = log_directory.join(format!(
        "pt31553-systemd-lifecycle-{}-{daemon_behavior}.log",
        std::process::id(),
    ));
    fs::write(&log, "").unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o666)).unwrap();
    let executable = std::env::current_exe().unwrap();
    let installed_probe = system_manager.then(|| {
        let path = PathBuf::from("/run").join(format!(
            "pt31553-lifecycle-{}-{daemon_behavior}-probe",
            std::process::id()
        ));
        assert!(
            Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/install", "-m", "0755"])
                .arg(&executable)
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        path
    });
    let executable = installed_probe.as_deref().unwrap_or(&executable);
    let probe = format!(
        "{} --exact lifecycle_command_probe --nocapture",
        executable.display()
    );
    let restore = format!(
        "/usr/bin/env {PROBE_ROLE}=restore {PROBE_BEHAVIOR}=delayed-ok {PROBE_LOG}={} {probe}",
        log.display()
    );
    let daemon = format!(
        "/usr/bin/env {PROBE_ROLE}=daemon {PROBE_BEHAVIOR}={daemon_behavior} {PROBE_LOG}={} {probe}",
        log.display(),
    );
    let unit = UNIT
        .replace(
            "ExecStart=/usr/bin/pt31553-fand",
            &format!("ExecStart={daemon}"),
        )
        .replace(
            "ExecStopPost=/usr/bin/pt31553-fan-restore --restore",
            &format!("ExecStopPost={restore}"),
        )
        .replace("WatchdogSec=6s", "WatchdogSec=1s")
        .replace("RestartSec=2s", "RestartSec=200ms")
        .replace("TimeoutStartSec=6s", "TimeoutStartSec=1s");
    // The user-manager probe lives in the checkout, so only that derived unit relaxes home
    // isolation. Both modes expose their host temporary observation log to the derived unit;
    // the production unit's hardening contract is asserted separately above.
    let unit = if system_manager {
        unit
    } else {
        unit.replace("ProtectHome=yes", "ProtectHome=no")
    };
    let unit = unit.replace("PrivateTmp=yes", "PrivateTmp=no").replace(
        "ReadWritePaths=/sys/class/hwmon /run/pt31553-fan-control",
        &format!(
            "ReadWritePaths=/sys/class/hwmon /run/pt31553-fan-control {}",
            log.display()
        ),
    );
    fs::write(&unit_path, unit).unwrap();

    if system_manager {
        let installed_path = PathBuf::from("/run/systemd/system").join(&unit_name);
        assert!(
            Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/install", "-m", "0644"])
                .arg(&unit_path)
                .arg(&installed_path)
                .status()
                .unwrap()
                .success()
        );
    }

    systemctl_manager(["daemon-reload"]);
    let start_status = systemctl_manager_status(["start", &unit_name]);
    if daemon_behavior == "watchdog" {
        assert!(
            start_status.success(),
            "watchdog service start failed:\n{}",
            systemctl_manager_diagnostics(&unit_name)
        );
    } else {
        assert!(!start_status.success());
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let state =
            systemctl_manager_output(["show", "--property=ActiveState", "--value", &unit_name]);
        if state.trim() == "failed" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "service did not reach its crash latch: {state}"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let observed = fs::read_to_string(&log).unwrap();
    assert_eq!(observed.matches("daemon\n").count(), 2);
    assert_eq!(
        observed,
        "daemon\nrestore\nrestore-complete\ndaemon\nrestore\nrestore-complete\n"
    );

    assert!(!systemctl_manager_status(["start", &unit_name]).success());
    assert_eq!(
        fs::read_to_string(&log)
            .unwrap()
            .matches("daemon\n")
            .count(),
        2,
        "the lifetime crash latch must reject starts until reset"
    );

    systemctl_manager(["reset-failed", &unit_name]);
    let reset_start_status = systemctl_manager_status(["start", &unit_name]);
    if daemon_behavior == "watchdog" {
        assert!(
            reset_start_status.success(),
            "watchdog service restart after reset failed:\n{}",
            systemctl_manager_diagnostics(&unit_name)
        );
    } else {
        assert!(!reset_start_status.success());
    }
    let reset_deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if fs::read_to_string(&log)
            .unwrap()
            .matches("daemon\n")
            .count()
            >= 3
        {
            break;
        }
        assert!(
            Instant::now() < reset_deadline,
            "reset-failed did not admit a new daemon start"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let _ = systemctl_manager_status(["stop", &unit_name]);
    let _ = systemctl_manager_status(["reset-failed", &unit_name]);
    if system_manager {
        let installed_path = PathBuf::from("/run/systemd/system").join(&unit_name);
        assert!(
            Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/rm", "-f", "--"])
                .arg(installed_path)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/rm", "-f", "--"])
                .arg(installed_probe.unwrap())
                .status()
                .unwrap()
                .success()
        );
    }
    fs::remove_file(unit_path).unwrap();
    fs::remove_file(log).unwrap();
    systemctl_manager(["daemon-reload"]);
}

#[test]
fn lifecycle_command_probe() {
    let Ok(role) = std::env::var(PROBE_ROLE) else {
        return;
    };
    let log = std::env::var_os(PROBE_LOG).expect("probe log path is required");
    append_probe_log(&log, &role);
    match std::env::var(PROBE_BEHAVIOR).as_deref() {
        Ok("ok") => {}
        Ok("delayed-ok") => {
            thread::sleep(Duration::from_millis(350));
            append_probe_log(&log, "restore-complete");
        }
        Ok("fail") => std::process::exit(1),
        Ok("hang") => thread::sleep(Duration::from_secs(60)),
        Ok("watchdog") => {
            let mut notifier = SystemdNotifier::from_environment().unwrap();
            notifier.notify(ServiceNotification::Ready).unwrap();
            notifier.notify(ServiceNotification::Watchdog).unwrap();
            thread::sleep(Duration::from_secs(60));
        }
        behavior => panic!("unknown probe behavior: {behavior:?}"),
    }
}

fn append_probe_log(log: impl AsRef<Path>, event: &str) {
    // The parent owns creation. Avoid O_CREAT here: protected_regular may otherwise reject a
    // root service appending to the runner-owned observation file in a sticky directory.
    writeln!(
        OpenOptions::new().append(true).open(log).unwrap(),
        "{event}"
    )
    .unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessOutcome {
    Success,
    Failure,
    WatchdogFailure,
    RecoveryBlocked,
    FaultLatched,
}

struct ObservableServiceManager {
    start_limit_burst: usize,
    starts: usize,
    restoration_complete: bool,
    log: PathBuf,
}

impl ObservableServiceManager {
    fn new(directives: &BTreeMap<String, BTreeMap<String, String>>) -> Self {
        assert_eq!(directives["Service"]["Restart"], "on-failure");
        let log = std::env::temp_dir().join(format!(
            "pt31553-lifecycle-{}-{}.log",
            std::process::id(),
            next_id()
        ));
        fs::write(&log, "").unwrap();
        Self {
            start_limit_burst: directives["Unit"]["StartLimitBurst"].parse().unwrap(),
            starts: 0,
            restoration_complete: true,
            log,
        }
    }

    fn start(&mut self, daemon_behavior: &str) -> ProcessOutcome {
        if self.starts >= self.start_limit_burst {
            return ProcessOutcome::FaultLatched;
        }
        if !self.restoration_complete {
            return ProcessOutcome::RecoveryBlocked;
        }
        self.starts += 1;
        let outcome = run_probe(
            "daemon",
            daemon_behavior,
            &self.log,
            Duration::from_millis(100),
        );
        if outcome != ProcessOutcome::Success {
            self.restoration_complete = false;
        }
        outcome
    }

    fn restore(&mut self, behavior: &str) -> ProcessOutcome {
        let outcome = run_probe("restore", behavior, &self.log, Duration::from_secs(2));
        self.restoration_complete = outcome == ProcessOutcome::Success;
        outcome
    }

    fn observed_log(&self) -> String {
        fs::read_to_string(&self.log).unwrap()
    }

    fn cleanup(&self) {
        fs::remove_file(&self.log).unwrap();
    }
}

fn run_probe(role: &str, behavior: &str, log: &Path, timeout: Duration) -> ProcessOutcome {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lifecycle_command_probe", "--nocapture"])
        .env(PROBE_ROLE, role)
        .env(PROBE_BEHAVIOR, behavior)
        .env(PROBE_LOG, log)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return if status.success() {
                ProcessOutcome::Success
            } else {
                ProcessOutcome::Failure
            };
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            return ProcessOutcome::WatchdogFailure;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn parse_unit(source: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut sections = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut section = None;
    for line in source.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = Some(name.to_owned());
            sections.entry(name.to_owned()).or_default();
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .expect("unit directive must use key=value");
        sections
            .get_mut(
                section
                    .as_deref()
                    .expect("directive must belong to a section"),
            )
            .unwrap()
            .insert(key.to_owned(), value.to_owned());
    }
    sections
}

fn next_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn systemctl_manager<const N: usize>(arguments: [&str; N]) {
    assert!(systemctl_manager_status(arguments).success());
}

fn systemctl_manager_status<const N: usize>(arguments: [&str; N]) -> std::process::ExitStatus {
    let mut command = systemctl_manager_command();
    command.args(arguments).status().unwrap()
}

fn systemctl_manager_output<const N: usize>(arguments: [&str; N]) -> String {
    let mut command = systemctl_manager_command();
    let output = command.args(arguments).output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn systemctl_manager_diagnostics(unit_name: &str) -> String {
    let mut status = systemctl_manager_command();
    let status = status
        .args(["status", "--no-pager", "--full", unit_name])
        .output()
        .unwrap();
    let mut journal = if std::env::var(USE_SYSTEM_MANAGER).as_deref() == Ok("1") {
        let mut command = Command::new("sudo");
        command.args(["--non-interactive", "journalctl"]);
        command
    } else {
        let mut command = Command::new("journalctl");
        command.arg("--user");
        command
    };
    let journal = journal
        .args(["--no-pager", "--unit", unit_name, "--lines", "100"])
        .output()
        .unwrap();
    format!(
        "systemctl status:\n{}{}\njournal:\n{}{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
        String::from_utf8_lossy(&journal.stdout),
        String::from_utf8_lossy(&journal.stderr)
    )
}

fn systemctl_manager_command() -> Command {
    if std::env::var(USE_SYSTEM_MANAGER).as_deref() == Ok("1") {
        let mut command = Command::new("sudo");
        command.args(["--non-interactive", "systemctl"]);
        command
    } else {
        let mut command = Command::new("systemctl");
        command.arg("--user");
        command
    }
}
