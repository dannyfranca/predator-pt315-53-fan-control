use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};

use fan_control_core::{ServiceNotification, ServiceNotifier, SystemdNotifier};

#[path = "../../fan-control-restore/src/sleep_guard.rs"]
mod restore_sleep_guard;

const UNIT: &str = include_str!("../../../systemd/pt31553-fan-sleep-guard.service");
const DAEMON_UNIT: &str = include_str!("../../../systemd/pt31553-fand.service");
const PROBE_LOG: &str = "PT31553_SLEEP_PROBE_LOG";
const PROBE_READY_BLOCK: &str = "PT31553_SLEEP_PROBE_READY_BLOCK";
const PROBE_READY_DELAY: &str = "PT31553_SLEEP_PROBE_READY_DELAY";
const PROBE_ROLE: &str = "PT31553_SLEEP_PROBE_ROLE";
const RUN_SYSTEMD_LIFECYCLE: &str = "PT31553_RUN_SYSTEMD_LIFECYCLE";
const TEST_DAEMON_UNIT: &str = "PT31553_SLEEP_TEST_DAEMON_UNIT";
const TEST_RECOVERY: &str = "PT31553_SLEEP_TEST_RECOVERY";
const TEST_RECOVERY_EVENT: &str = "PT31553_SLEEP_TEST_RECOVERY_EVENT";
const TEST_RESUME_MARKER: &str = "PT31553_SLEEP_TEST_RESUME_MARKER";

#[test]
fn sleep_guard_is_a_required_gate_for_every_systemd_sleep_transaction() {
    let directives = parse_unit(UNIT);
    let daemon_directives = parse_unit(DAEMON_UNIT);

    assert_eq!(directives["Unit"]["Before"], "sleep.target");
    assert_eq!(directives["Unit"]["StopWhenUnneeded"], "yes");
    assert!(!directives["Unit"].contains_key("After"));
    assert_eq!(directives["Install"]["RequiredBy"], "sleep.target");
    assert!(!directives["Install"].contains_key("WantedBy"));
    assert_eq!(
        daemon_directives["Unit"]["ConditionPathExists"],
        "!/run/pt31553-fan-sleep-guard/resume-daemon-start-blocked"
    );
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
    assert_eq!(directives["Service"]["RuntimeDirectoryPreserve"], "yes");
}

#[test]
#[ignore = "requires the system manager; set PT31553_RUN_SYSTEMD_LIFECYCLE=1"]
fn actual_systemd_manager_blocks_sleep_failure_and_restarts_fresh_after_resume() {
    if std::env::var(RUN_SYSTEMD_LIFECYCLE).as_deref() != Ok("1") {
        return;
    }

    assert_actual_sleep_lifecycle(LifecycleCase::Success);
    assert_actual_sleep_lifecycle(LifecycleCase::RestorationFailure);
    assert_actual_sleep_lifecycle(LifecycleCase::ReadinessFailure);
    assert_actual_sleep_lifecycle(LifecycleCase::TransitioningIntervention);
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
            if probe_flag_exists(PROBE_READY_BLOCK) {
                thread::sleep(Duration::from_secs(60));
                return;
            }
            if probe_flag_exists(PROBE_READY_DELAY) {
                thread::sleep(Duration::from_millis(500));
            }
            let mut notifier = SystemdNotifier::from_environment().unwrap();
            notifier.notify(ServiceNotification::Ready).unwrap();
            thread::sleep(Duration::from_secs(60));
        }
        "daemon-restore" => run_test_recovery().unwrap(),
        "guard-prepare" => {
            let marker = test_resume_marker();
            restore_sleep_guard::prepare_sleep(
                &mut test_daemon_manager(),
                &marker,
                &prepared_marker(&marker),
                run_test_recovery,
            )
            .unwrap();
        }
        "guard-resume" => {
            restore_sleep_guard::resume_after_sleep(
                &mut test_daemon_manager(),
                &test_resume_marker(),
            )
            .unwrap();
        }
        "guard-failed" => {
            restore_sleep_guard::restore_after_failed_guard(
                &prepared_marker(&test_resume_marker()),
                run_test_recovery,
            )
            .unwrap();
        }
        _ => panic!("unknown sleep probe role {role}"),
    }
}

fn test_daemon_manager() -> restore_sleep_guard::SystemdDaemonManager {
    restore_sleep_guard::SystemdDaemonManager::for_unit(
        std::env::var(TEST_DAEMON_UNIT).expect("test daemon unit is required"),
    )
}

fn test_resume_marker() -> PathBuf {
    std::env::var_os(TEST_RESUME_MARKER)
        .expect("test resume marker is required")
        .into()
}

fn prepared_marker(marker: &Path) -> PathBuf {
    marker.with_file_name("resume-daemon-prepared")
}

fn run_test_recovery() -> io::Result<()> {
    let log = std::env::var_os(PROBE_LOG)
        .ok_or_else(|| io::Error::other("probe log path is required"))?;
    let behavior = std::env::var(TEST_RECOVERY)
        .map_err(|_| io::Error::other("test recovery behavior is required"))?;
    let event = std::env::var(TEST_RECOVERY_EVENT).unwrap_or_else(|_| behavior.clone());
    match behavior.as_str() {
        "auto-confirmed" => append_test_recovery_log(&log, &event),
        "containment-retry" => loop {
            append_test_recovery_log(&log, &event)?;
            thread::sleep(Duration::from_millis(100));
        },
        value => Err(io::Error::other(format!(
            "unknown test recovery behavior {value:?}"
        ))),
    }
}

fn append_test_recovery_log(path: &std::ffi::OsStr, event: &str) -> io::Result<()> {
    writeln!(OpenOptions::new().append(true).open(path)?, "{event}")
}

fn probe_flag_exists(variable: &str) -> bool {
    std::env::var_os(variable).is_some_and(|path| Path::new(&path).is_file())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LifecycleCase {
    Success,
    RestorationFailure,
    ReadinessFailure,
    TransitioningIntervention,
}

fn assert_actual_sleep_lifecycle(case: LifecycleCase) {
    let restoration_succeeds = case != LifecycleCase::RestorationFailure;
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        match case {
            LifecycleCase::Success => "ok",
            LifecycleCase::RestorationFailure => "restore-fail",
            LifecycleCase::ReadinessFailure => "ready-fail",
            LifecycleCase::TransitioningIntervention => "transitioning",
        }
    );
    let daemon_name = format!("pt31553-sleep-test-daemon-{suffix}.service");
    let guard_name = format!("pt31553-sleep-test-guard-{suffix}.service");
    let target_name = format!("pt31553-sleep-test-{suffix}.target");
    let mut installation =
        TestUnitInstallation::new([daemon_name.clone(), guard_name.clone(), target_name.clone()]);

    let probe_path = PathBuf::from("/run").join(format!("pt31553-sleep-test-{suffix}-probe"));
    installation.install_executable(&probe_path, &std::env::current_exe().unwrap());
    let log = PathBuf::from("/tmp").join(format!("pt31553-sleep-test-{suffix}.log"));
    fs::write(&log, "").unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o666)).unwrap();
    installation.remove_after(&log);
    let ready_delay = PathBuf::from("/tmp").join(format!("pt31553-sleep-test-{suffix}-delay"));
    let ready_block = PathBuf::from("/tmp").join(format!("pt31553-sleep-test-{suffix}-block"));
    installation.remove_after(&ready_delay);
    installation.remove_after(&ready_block);
    let probe = |role: &str| {
        format!(
            "/usr/bin/env {PROBE_ROLE}={role} {PROBE_LOG}={} {PROBE_READY_DELAY}={} {PROBE_READY_BLOCK}={} {} --exact sleep_guard_command_probe --nocapture",
            log.display(),
            ready_delay.display(),
            ready_block.display(),
            probe_path.display()
        )
    };
    let runtime_directory = format!("pt31553-sleep-test-{suffix}");
    let marker = format!("/run/{runtime_directory}/resume-daemon");
    let prepared_marker = format!("/run/{runtime_directory}/resume-daemon-prepared");
    let start_gate = format!("/run/{runtime_directory}/resume-daemon-start-blocked");
    installation.remove_after(Path::new(&marker));
    installation.remove_after(Path::new(&prepared_marker));
    installation.remove_after(Path::new(&start_gate));
    installation.remove_runtime_directory_after(Path::new("/run").join(&runtime_directory));
    let helper = |role: &str, recovery: Option<&str>, event: Option<&str>| {
        let recovery = recovery
            .map(|value| format!(" {TEST_RECOVERY}={value}"))
            .unwrap_or_default();
        let event = event
            .map(|value| format!(" {TEST_RECOVERY_EVENT}={value}"))
            .unwrap_or_default();
        format!(
            "/usr/bin/env {PROBE_ROLE}={role} {TEST_DAEMON_UNIT}={daemon_name} {TEST_RESUME_MARKER}={marker} {PROBE_LOG}={}{}{} {} --exact sleep_guard_command_probe --nocapture",
            log.display(),
            recovery,
            event,
            probe_path.display()
        )
    };
    installation.install(
        &daemon_name,
        &format!(
            "[Unit]\nStartLimitIntervalSec=infinity\nStartLimitBurst=2\nConditionPathExists=!{start_gate}\n\n[Service]\nType=notify\nNotifyAccess=main\nExecStart={}\nExecStopPost={}\nTimeoutStartSec=3s\nTimeoutStopSec=infinity\n",
            probe("daemon-ready"),
            helper(
                "daemon-restore",
                Some("auto-confirmed"),
                Some("daemon-cleanup")
            )
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
                    "guard-prepare",
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
            &format!("ExecStop={}", helper("guard-resume", None, None)),
        )
        .replace(
            "ExecStopPost=/usr/bin/pt31553-fan-restore --restore-after-failed-sleep-guard",
            &format!(
                "ExecStopPost={}",
                helper(
                    "guard-failed",
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

    if case == LifecycleCase::TransitioningIntervention {
        fs::write(&ready_delay, "delay readiness").unwrap();
        let mut intervening_start = systemctl_command(["restart", &daemon_name])
            .spawn()
            .unwrap();
        wait_for_state(&daemon_name, "activating");
        let target_start = systemctl_status(["start", &target_name]);
        assert!(target_start.success());
        fs::remove_file(&ready_delay).unwrap();
        let _ = intervening_start.wait();
        assert_eq!(active_state(&guard_name), "active");
        assert_eq!(active_state(&daemon_name), "inactive");
        assert!(!Path::new(&marker).exists());
        assert!(Path::new(&start_gate).is_file());
        systemctl(["stop", &target_name]);
        wait_for_state(&guard_name, "inactive");
        assert_eq!(active_state(&daemon_name), "inactive");
        assert!(!Path::new(&start_gate).exists());
        return;
    }

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

    if case == LifecycleCase::ReadinessFailure {
        fs::write(&ready_block, "block readiness").unwrap();
        let _ = systemctl_status(["stop", &target_name]);
        wait_for_state(&guard_name, "failed");
        wait_for_state(&daemon_name, "failed");
        assert!(
            Path::new(&marker).is_file(),
            "failed daemon readiness must preserve resume authorization for retry"
        );
        assert!(Path::new(&start_gate).is_file());
        return;
    }

    let mut daemon_pids = Vec::new();
    for cycle in 0..3 {
        assert_eq!(active_state(&target_name), "active");
        assert_eq!(active_state(&guard_name), "active");
        assert_eq!(active_state(&daemon_name), "inactive");

        if cycle == 1 {
            wait_for_unit_unloaded(&daemon_name);
        }
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
    runtime_directories: Vec<PathBuf>,
}

impl TestUnitInstallation {
    fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            names: names.into_iter().collect(),
            sources: Vec::new(),
            installed_files: Vec::new(),
            runtime_directories: Vec::new(),
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

    fn remove_runtime_directory_after(&mut self, path: PathBuf) {
        self.runtime_directories.push(path);
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
        for path in &self.runtime_directories {
            let _ = Command::new("sudo")
                .args(["--non-interactive", "/usr/bin/rmdir", "--"])
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
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        let observed = active_state(name);
        if observed == expected {
            return;
        }
        if Instant::now() >= deadline {
            let status = systemctl_output(["status", "--no-pager", name]);
            panic!(
                "{name} remained {observed}, expected {expected}:\n{}\n{}",
                String::from_utf8_lossy(&status.stdout),
                String::from_utf8_lossy(&status.stderr)
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_unit_unloaded(name: &str) {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        let reset = systemctl_output(["reset-failed", name]);
        let stderr = String::from_utf8_lossy(&reset.stderr);
        if !reset.status.success() && stderr.contains("not loaded") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{name} was not garbage-collected before resume: status={} stderr={stderr:?}",
            reset.status
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn systemctl_output<const N: usize>(arguments: [&str; N]) -> std::process::Output {
    systemctl_command(arguments).output().unwrap()
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
