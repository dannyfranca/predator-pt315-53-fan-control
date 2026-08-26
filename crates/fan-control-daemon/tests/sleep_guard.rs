use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};

use fan_control_core::{ServiceNotification, ServiceNotifier, SystemdNotifier};

const UNIT: &str = include_str!("../../../systemd/pt31553-fan-sleep-guard.service");
const PROBE_LOG: &str = "PT31553_SLEEP_PROBE_LOG";
const PROBE_ROLE: &str = "PT31553_SLEEP_PROBE_ROLE";
const RUN_SYSTEMD_LIFECYCLE: &str = "PT31553_RUN_SYSTEMD_LIFECYCLE";
const SLEEP_HELPER: &str = "PT31553_SLEEP_HELPER";

#[test]
fn sleep_guard_is_a_required_gate_for_every_systemd_sleep_transaction() {
    let directives = parse_unit(UNIT);

    assert_eq!(directives["Unit"]["Before"], "sleep.target");
    assert_eq!(directives["Unit"]["StopWhenUnneeded"], "yes");
    assert!(!directives["Unit"].contains_key("After"));
    assert_eq!(directives["Install"]["RequiredBy"], "sleep.target");
    assert!(!directives["Install"].contains_key("WantedBy"));
}

#[test]
fn sleep_guard_confirms_auto_before_sleep_and_uses_a_fresh_process_after_resume() {
    let directives = parse_unit(UNIT);

    assert_eq!(directives["Service"]["Type"], "oneshot");
    assert_eq!(directives["Service"]["RemainAfterExit"], "yes");
    assert_eq!(directives["Service"]["TimeoutStartSec"], "infinity");
    assert_eq!(
        directives["Service"]["ExecStart"],
        "/usr/bin/pt31553-fan-restore --prepare-sleep"
    );
    assert_eq!(
        directives["Service"]["ExecStop"],
        "/usr/bin/pt31553-fan-restore --resume-after-sleep"
    );
    assert_eq!(
        directives["Service"]["ExecStopPost"],
        "/usr/bin/pt31553-fan-restore --restore-after-failed-sleep-guard"
    );
    assert_eq!(directives["Service"]["TimeoutStopSec"], "infinity");
    assert_eq!(
        directives["Service"]["RuntimeDirectory"],
        "pt31553-fan-sleep-guard"
    );
    assert_eq!(directives["Service"]["RuntimeDirectoryMode"], "0700");
}

#[test]
#[ignore = "requires the system manager; set PT31553_RUN_SYSTEMD_LIFECYCLE=1"]
fn actual_systemd_manager_blocks_sleep_failure_and_restarts_fresh_after_resume() {
    if std::env::var(RUN_SYSTEMD_LIFECYCLE).as_deref() != Ok("1") {
        return;
    }

    assert_actual_sleep_lifecycle(true);
    assert_actual_sleep_lifecycle(false);
}

#[test]
fn sleep_guard_command_probe() {
    let Ok(role) = std::env::var(PROBE_ROLE) else {
        return;
    };
    let log = std::env::var_os(PROBE_LOG).expect("probe log path is required");

    match role.as_str() {
        "daemon-ready" => {
            append_probe_log(&log, &format!("{role}:{}", std::process::id()));
            let mut notifier = SystemdNotifier::from_environment().unwrap();
            notifier.notify(ServiceNotification::Ready).unwrap();
            thread::sleep(Duration::from_secs(60));
        }
        _ => panic!("unknown sleep probe role {role}"),
    }
}

fn assert_actual_sleep_lifecycle(restoration_succeeds: bool) {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        if restoration_succeeds { "ok" } else { "fail" }
    );
    let daemon_name = format!("pt31553-sleep-test-daemon-{suffix}.service");
    let guard_name = format!("pt31553-sleep-test-guard-{suffix}.service");
    let target_name = format!("pt31553-sleep-test-{suffix}.target");
    let mut installation =
        TestUnitInstallation::new([daemon_name.clone(), guard_name.clone(), target_name.clone()]);

    let probe_path = PathBuf::from("/run").join(format!("pt31553-sleep-test-{suffix}-probe"));
    installation.install_executable(&probe_path, &std::env::current_exe().unwrap());
    let helper_path = PathBuf::from("/run").join(format!("pt31553-sleep-test-{suffix}-helper"));
    installation.install_executable(
        &helper_path,
        Path::new(
            &std::env::var_os(SLEEP_HELPER)
                .expect("PT31553_SLEEP_HELPER must name the feature-built recovery helper"),
        ),
    );
    let log = PathBuf::from("/tmp").join(format!("pt31553-sleep-test-{suffix}.log"));
    fs::write(&log, "").unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o666)).unwrap();
    installation.remove_after(&log);
    let probe = |role: &str| {
        format!(
            "/usr/bin/env {PROBE_ROLE}={role} {PROBE_LOG}={} {} --exact sleep_guard_command_probe --nocapture",
            log.display(),
            probe_path.display()
        )
    };
    let runtime_directory = format!("pt31553-sleep-test-{suffix}");
    let marker = format!("/run/{runtime_directory}/resume-daemon");
    let helper = |command: &str, recovery: Option<&str>, event: Option<&str>| {
        let recovery = recovery
            .map(|value| format!(" PT31553_TEST_RECOVERY={value}"))
            .unwrap_or_default();
        let event = event
            .map(|value| format!(" PT31553_TEST_RECOVERY_EVENT={value}"))
            .unwrap_or_default();
        format!(
            "/usr/bin/env PT31553_TEST_DAEMON_UNIT={daemon_name} PT31553_TEST_RESUME_MARKER={marker} PT31553_TEST_RECOVERY_LOG={}{}{} {} {command}",
            log.display(),
            recovery,
            event,
            helper_path.display()
        )
    };
    installation.install(
        &daemon_name,
        &format!(
            "[Unit]\nStartLimitIntervalSec=infinity\nStartLimitBurst=2\n\n[Service]\nType=notify\nNotifyAccess=main\nExecStart={}\nExecStopPost={}\nTimeoutStartSec=3s\nTimeoutStopSec=infinity\n",
            probe("daemon-ready"),
            helper("--restore", Some("auto-confirmed"), Some("daemon-cleanup"))
        ),
    );
    let prepare_recovery = if restoration_succeeds {
        "auto-confirmed"
    } else {
        "containment-retry"
    };
    let guard = UNIT
        .replace("Before=sleep.target", "")
        .replace(
            "ExecStart=/usr/bin/pt31553-fan-restore --prepare-sleep",
            &format!(
                "ExecStart={}",
                helper(
                    "--prepare-sleep",
                    Some(prepare_recovery),
                    Some(if restoration_succeeds {
                        "guard-prepare"
                    } else {
                        "guard-containment"
                    })
                )
            ),
        )
        .replace(
            "ExecStop=/usr/bin/pt31553-fan-restore --resume-after-sleep",
            &format!("ExecStop={}", helper("--resume-after-sleep", None, None)),
        )
        .replace(
            "ExecStopPost=/usr/bin/pt31553-fan-restore --restore-after-failed-sleep-guard",
            &format!(
                "ExecStopPost={}",
                helper(
                    "--restore-after-failed-sleep-guard",
                    Some("auto-confirmed"),
                    Some("guard-cancel-recovery")
                )
            ),
        )
        .replace(
            "RuntimeDirectory=pt31553-fan-sleep-guard",
            &format!("RuntimeDirectory={runtime_directory}"),
        );
    installation.install(&guard_name, &guard);
    installation.install(
        &target_name,
        &format!("[Unit]\nRequires={guard_name}\nAfter={guard_name}\n"),
    );
    systemctl(["daemon-reload"]);
    assert!(systemctl_status(["start", &daemon_name]).success());

    if !restoration_succeeds {
        let mut target_start = systemctl_command(["start", &target_name]).spawn().unwrap();
        wait_for_log(&log, "guard-containment");
        assert!(target_start.try_wait().unwrap().is_none());
        assert_eq!(active_state(&target_name), "activating");
        assert_eq!(active_state(&guard_name), "activating");
        assert_eq!(active_state(&daemon_name), "inactive");
        systemctl(["stop", &target_name]);
        wait_for_log(&log, "guard-cancel-recovery");
        let _ = target_start.wait();
        assert_cancelled_recovery_order(&log);
        return;
    }

    let target_start = systemctl_status(["start", &target_name]);
    assert!(target_start.success());
    let mut daemon_pids = Vec::new();
    for cycle in 0..3 {
        assert_eq!(active_state(&target_name), "active");
        assert_eq!(active_state(&guard_name), "active");
        assert_eq!(active_state(&daemon_name), "inactive");

        systemctl(["stop", &target_name]);
        wait_for_state(&guard_name, "inactive");
        wait_for_state(&daemon_name, "active");
        daemon_pids.push(unit_property(&daemon_name, "MainPID"));

        if cycle < 2 {
            systemctl(["start", &target_name]);
        }
    }
    daemon_pids.sort();
    daemon_pids.dedup();
    assert_eq!(
        daemon_pids.len(),
        3,
        "every resume must use a fresh process"
    );
    assert_recovery_order(
        &log,
        &[
            "daemon-cleanup",
            "guard-prepare",
            "daemon-cleanup",
            "guard-prepare",
            "daemon-cleanup",
            "guard-prepare",
        ],
    );
}

fn assert_recovery_order(log: &Path, expected: &[&str]) {
    let content = fs::read_to_string(log).unwrap();
    let actual = recovery_events(&content);
    assert_eq!(actual, expected, "unexpected restore-helper ordering");
}

fn assert_cancelled_recovery_order(log: &Path) {
    let content = fs::read_to_string(log).unwrap();
    let actual = recovery_events(&content);
    assert_eq!(actual.first(), Some(&"daemon-cleanup"));
    assert_eq!(actual.last(), Some(&"guard-cancel-recovery"));
    assert!(
        actual[1..actual.len() - 1]
            .iter()
            .all(|event| *event == "guard-containment")
    );
}

fn recovery_events(content: &str) -> Vec<&str> {
    content
        .lines()
        .filter(|line| !line.starts_with("daemon-ready:"))
        .collect()
}

struct TestUnitInstallation {
    names: Vec<String>,
    sources: Vec<PathBuf>,
    installed_files: Vec<PathBuf>,
}

impl TestUnitInstallation {
    fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            names: names.into_iter().collect(),
            sources: Vec::new(),
            installed_files: Vec::new(),
        }
    }

    fn install(&mut self, name: &str, source: &str) {
        let source_path = std::env::temp_dir().join(name);
        fs::write(&source_path, source).unwrap();
        assert!(
            Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/install", "-m", "0644"])
                .arg(&source_path)
                .arg(Path::new("/run/systemd/system").join(name))
                .status()
                .unwrap()
                .success()
        );
        self.sources.push(source_path);
    }

    fn install_executable(&mut self, destination: &Path, source: &Path) {
        assert!(
            Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/install", "-m", "0755"])
                .arg(source)
                .arg(destination)
                .status()
                .unwrap()
                .success()
        );
        self.installed_files.push(destination.to_owned());
    }

    fn remove_after(&mut self, path: &Path) {
        self.installed_files.push(path.to_owned());
    }
}

impl Drop for TestUnitInstallation {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = systemctl_status(["stop", name]);
            let _ = systemctl_status(["reset-failed", name]);
            let _ = Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/rm", "-f", "--"])
                .arg(Path::new("/run/systemd/system").join(name))
                .status();
        }
        for source in &self.sources {
            let _ = fs::remove_file(source);
        }
        for path in &self.installed_files {
            let _ = Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/rm", "-f", "--"])
                .arg(path)
                .status();
        }
        let _ = systemctl_status(["daemon-reload"]);
    }
}

fn systemctl<const N: usize>(arguments: [&str; N]) {
    assert!(systemctl_status(arguments).success());
}

fn systemctl_status<I, S>(arguments: I) -> ExitStatus
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    systemctl_command(arguments).status().unwrap()
}

fn systemctl_command<I, S>(arguments: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut command = Command::new("sudo");
    command
        .arg("--non-interactive")
        .arg("/usr/bin/systemctl")
        .args(arguments);
    command
}

fn active_state(name: &str) -> String {
    unit_property(name, "ActiveState")
}

fn unit_property(name: &str, property: &str) -> String {
    let output = Command::new("sudo")
        .args([
            "--non-interactive",
            "/usr/bin/systemctl",
            "show",
            &format!("--property={property}"),
            "--value",
            name,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn wait_for_state(name: &str, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let observed = active_state(name);
        if observed == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{name} remained {observed}, expected {expected}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_log(path: &Path, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let observed = fs::read_to_string(path).unwrap();
        if observed.contains(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "log never contained {expected:?}: {observed}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn append_probe_log(path: impl AsRef<Path>, event: &str) {
    writeln!(
        OpenOptions::new().append(true).open(path).unwrap(),
        "{event}"
    )
    .unwrap();
}

fn parse_unit(unit: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut directives = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut section = None;

    for line in unit.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = Some(name.to_owned());
            continue;
        }
        let (key, value) = line.split_once('=').expect("unit directive");
        directives
            .entry(section.clone().expect("unit section"))
            .or_default()
            .insert(key.to_owned(), value.to_owned());
    }

    directives
}
