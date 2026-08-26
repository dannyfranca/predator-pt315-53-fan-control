use std::{
    fs, io,
    path::Path,
    process::{Command, Output},
};

const DAEMON_UNIT: &str = "pt31553-fand.service";
const MARKER_PREFIX: &str = "resume:";
const PREPARED_MARKER_CONTENT: &[u8] = b"firmware-auto-confirmed\n";
const RESUME_COMPLETED_CONTENT: &[u8] = b"resume-completed\n";
const START_GATE_CONTENT: &[u8] = b"sleep-transaction\n";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DaemonActiveState {
    Active,
    Inactive,
    Failed,
    Transitioning,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PlannedStop {
    Clean,
    Faulted,
}

pub(crate) trait DaemonManager {
    fn active_state(&mut self) -> io::Result<DaemonActiveState>;
    fn invocation_id(&mut self) -> io::Result<String>;
    fn reset_planned_state(&mut self, invocation: &str) -> io::Result<()>;
    fn stop(&mut self) -> io::Result<PlannedStop>;
    fn restart_ready(&mut self) -> io::Result<()>;
}

pub(crate) struct SystemdDaemonManager;

impl DaemonManager for SystemdDaemonManager {
    fn active_state(&mut self) -> io::Result<DaemonActiveState> {
        let unit = daemon_unit();
        match unit_property(&unit, "ActiveState")?.as_str() {
            "active" => Ok(DaemonActiveState::Active),
            "inactive" => Ok(DaemonActiveState::Inactive),
            "failed" => Ok(DaemonActiveState::Failed),
            "activating" | "deactivating" => Ok(DaemonActiveState::Transitioning),
            state => Err(io::Error::other(format!(
                "{unit} has transitional or unsupported state {state:?}"
            ))),
        }
    }

    fn invocation_id(&mut self) -> io::Result<String> {
        unit_property(&daemon_unit(), "InvocationID")
    }

    fn stop(&mut self) -> io::Result<PlannedStop> {
        let unit = daemon_unit();
        systemctl(&["stop", &unit])?;
        let active_state = unit_property(&unit, "ActiveState")?;
        let result = unit_property(&unit, "Result")?;
        match (active_state.as_str(), result.as_str()) {
            ("inactive", "success") => Ok(PlannedStop::Clean),
            ("inactive" | "failed", _) => Ok(PlannedStop::Faulted),
            _ => Err(io::Error::other(format!(
                "{unit} did not complete a clean planned stop: state={active_state:?} result={result:?}"
            ))),
        }
    }

    fn reset_planned_state(&mut self, invocation: &str) -> io::Result<()> {
        let unit = daemon_unit();
        systemctl(&["reset-failed", &unit])?;
        let state = self.active_state()?;
        let observed = self.invocation_id()?;
        if state == DaemonActiveState::Active && observed == invocation {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "{unit} changed while resetting the planned invocation"
        )))
    }

    fn restart_ready(&mut self) -> io::Result<()> {
        systemctl(&["restart", &daemon_unit()])
    }
}

pub(crate) fn prepare_sleep(
    manager: &mut impl DaemonManager,
    marker: &Path,
    prepared_marker: &Path,
    restore: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    clear_marker(marker)?;
    clear_marker(prepared_marker)?;
    let start_gate = start_gate_marker(prepared_marker);
    clear_marker(&start_gate)?;
    fs::write(&start_gate, START_GATE_CONTENT)?;
    let planned_invocation = match manager.active_state()? {
        DaemonActiveState::Active => {
            let invocation = manager.invocation_id()?;
            validate_invocation_id(&invocation)?;
            manager.reset_planned_state(&invocation)?;
            (manager.stop()? == PlannedStop::Clean).then_some(invocation)
        }
        DaemonActiveState::Transitioning => {
            let _ = manager.stop()?;
            None
        }
        DaemonActiveState::Inactive | DaemonActiveState::Failed => None,
    };

    restore()?;
    fs::write(prepared_marker, PREPARED_MARKER_CONTENT)?;
    if let Some(invocation) = planned_invocation {
        fs::write(marker, format!("{MARKER_PREFIX}{invocation}\n"))?;
    }
    Ok(())
}

pub(crate) fn restore_after_failed_guard(
    prepared_marker: &Path,
    restore: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let start_gate = start_gate_marker(prepared_marker);
    match fs::read(prepared_marker) {
        Ok(content) if content == RESUME_COMPLETED_CONTENT => {
            fs::remove_file(prepared_marker)?;
            clear_marker(&start_gate)
        }
        Ok(content) if content == PREPARED_MARKER_CONTENT => restore(),
        Ok(_) => {
            restore()?;
            clear_marker(prepared_marker)?;
            clear_marker(&start_gate)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            restore()?;
            clear_marker(&start_gate)
        }
        Err(error) => {
            restore()?;
            Err(error)
        }
    }
}

pub(crate) fn resume_after_sleep(
    manager: &mut impl DaemonManager,
    marker: &Path,
) -> io::Result<()> {
    let start_gate = start_gate_marker(marker);
    let prepared_marker = prepared_marker(marker);
    let planned_invocation = match fs::read_to_string(marker) {
        Ok(content) => parse_resume_marker(&content)?.to_owned(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            clear_marker(&start_gate)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    match manager.active_state()? {
        DaemonActiveState::Inactive => {
            let observed = manager.invocation_id()?;
            if observed.is_empty() {
                // Garbage collection already discarded the planned invocation's state.
            } else {
                validate_invocation_id(&observed)?;
                if observed != planned_invocation {
                    return Err(io::Error::other(
                        "daemon invocation changed after sleep preparation; preserving its state",
                    ));
                }
            }
        }
        DaemonActiveState::Failed => {
            return Err(io::Error::other(
                "daemon faulted after sleep preparation; preserving fault latch",
            ));
        }
        DaemonActiveState::Active | DaemonActiveState::Transitioning => {
            if manager.stop()? != PlannedStop::Clean {
                return Err(io::Error::other(
                    "intervening daemon did not complete a clean stop",
                ));
            }
        }
    }
    // Restart is deliberate: if another start races resume, systemd must still replace that
    // process rather than accepting it as the fresh post-sleep controller.
    clear_marker(&start_gate)?;
    if let Err(error) = manager.restart_ready() {
        fs::write(&start_gate, START_GATE_CONTENT)?;
        return Err(error);
    }
    if let Err(error) = fs::remove_file(marker) {
        return contain_failed_resume(manager, &start_gate, &prepared_marker, error);
    }
    if let Err(error) = fs::write(&prepared_marker, RESUME_COMPLETED_CONTENT) {
        return contain_failed_resume(manager, &start_gate, &prepared_marker, error);
    }
    Ok(())
}

fn contain_failed_resume(
    manager: &mut impl DaemonManager,
    start_gate: &Path,
    prepared_marker: &Path,
    error: io::Error,
) -> io::Result<()> {
    let stop = manager.stop();
    let prepared = fs::write(prepared_marker, PREPARED_MARKER_CONTENT);
    let gate = fs::write(start_gate, START_GATE_CONTENT);
    stop?;
    prepared?;
    gate?;
    Err(error)
}

fn prepared_marker(marker: &Path) -> std::path::PathBuf {
    let name = marker
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("resume-daemon");
    let base = name.strip_suffix("-prepared").unwrap_or(name);
    marker.with_file_name(format!("{base}-prepared"))
}

fn start_gate_marker(marker: &Path) -> std::path::PathBuf {
    let name = marker
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("resume-daemon");
    let base = name.strip_suffix("-prepared").unwrap_or(name);
    marker.with_file_name(format!("{base}-start-blocked"))
}

fn parse_resume_marker(content: &str) -> io::Result<&str> {
    let invocation = content
        .strip_prefix(MARKER_PREFIX)
        .and_then(|content| content.strip_suffix('\n'))
        .ok_or_else(|| io::Error::other("invalid sleep-resume marker"))?;
    validate_invocation_id(invocation)?;
    Ok(invocation)
}

fn validate_invocation_id(invocation: &str) -> io::Result<()> {
    if invocation.len() == 32 && invocation.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(io::Error::other("invalid daemon invocation ID"))
}

fn clear_marker(marker: &Path) -> io::Result<()> {
    match fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn systemctl(arguments: &[&str]) -> io::Result<()> {
    systemctl_output(arguments).map(|_| ())
}

fn systemctl_output(arguments: &[&str]) -> io::Result<Output> {
    let output = Command::new(SYSTEMCTL).args(arguments).output()?;
    if output.status.success() {
        return Ok(output);
    }

    Err(io::Error::other(format!(
        "systemctl {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn unit_property(unit: &str, property: &str) -> io::Result<String> {
    let argument = format!("--property={property}");
    let output = systemctl_output(&["show", &argument, "--value", unit])?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn daemon_unit() -> String {
    #[cfg(feature = "systemd-test-probes")]
    if let Ok(unit) = std::env::var("PT31553_TEST_DAEMON_UNIT") {
        return unit;
    }
    DAEMON_UNIT.to_owned()
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fs, io, path::PathBuf, rc::Rc};

    use super::{
        DaemonActiveState, DaemonManager, PlannedStop, prepare_sleep, restore_after_failed_guard,
        resume_after_sleep,
    };

    const INTERVENING_INVOCATION: &str = "fedcba9876543210fedcba9876543210";
    const PLANNED_INVOCATION: &str = "0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct FakeDaemonManager {
        state: Option<io::Result<DaemonActiveState>>,
        invocation_id: Option<io::Result<String>>,
        stop_result: Option<io::Result<PlannedStop>>,
        start_result: Option<io::Result<()>>,
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakeDaemonManager {
        fn active() -> Self {
            Self {
                state: Some(Ok(DaemonActiveState::Active)),
                ..Self::default()
            }
        }

        fn inactive() -> Self {
            Self {
                state: Some(Ok(DaemonActiveState::Inactive)),
                ..Self::default()
            }
        }
    }

    impl DaemonManager for FakeDaemonManager {
        fn active_state(&mut self) -> io::Result<DaemonActiveState> {
            self.calls.borrow_mut().push("state");
            self.state.take().unwrap_or(Ok(DaemonActiveState::Inactive))
        }

        fn invocation_id(&mut self) -> io::Result<String> {
            self.calls.borrow_mut().push("invocation-id");
            self.invocation_id
                .take()
                .unwrap_or_else(|| Ok(PLANNED_INVOCATION.to_owned()))
        }

        fn stop(&mut self) -> io::Result<PlannedStop> {
            self.calls.borrow_mut().push("stop");
            self.stop_result.take().unwrap_or(Ok(PlannedStop::Clean))
        }

        fn reset_planned_state(&mut self, _invocation: &str) -> io::Result<()> {
            self.calls.borrow_mut().push("reset-planned");
            Ok(())
        }

        fn restart_ready(&mut self) -> io::Result<()> {
            self.calls.borrow_mut().push("restart");
            self.start_result.take().unwrap_or(Ok(()))
        }
    }

    #[test]
    fn healthy_daemon_is_stopped_restored_and_authorized_for_fresh_resume() {
        let marker = marker_path("healthy");
        let prepared_marker = marker_path("healthy-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();
        let calls = Rc::clone(&manager.calls);

        prepare_sleep(&mut manager, &marker, &prepared_marker, move || {
            calls.borrow_mut().push("restore");
            Ok(())
        })
        .unwrap();

        assert_eq!(
            &*manager.calls.borrow(),
            &["state", "invocation-id", "reset-planned", "stop", "restore"]
        );
        assert!(marker.is_file());
        assert!(prepared_marker.is_file());

        resume_after_sleep(&mut manager, &marker).unwrap();
        assert_eq!(
            &*manager.calls.borrow(),
            &[
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "restore",
                "state",
                "invocation-id",
                "restart"
            ]
        );
        assert!(!marker.exists());
    }

    #[test]
    fn inactive_or_fault_latched_daemon_is_never_restarted() {
        let marker = marker_path("inactive");
        let prepared_marker = marker_path("inactive-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::inactive();
        let calls = Rc::clone(&manager.calls);

        prepare_sleep(&mut manager, &marker, &prepared_marker, move || {
            calls.borrow_mut().push("restore");
            Ok(())
        })
        .unwrap();
        resume_after_sleep(&mut manager, &marker).unwrap();

        assert_eq!(&*manager.calls.borrow(), &["state", "restore"]);
    }

    #[test]
    fn transitioning_daemon_is_stopped_before_sleep_without_resume_authorization() {
        let marker = marker_path("prepare-transitioning");
        let prepared_marker = marker_path("prepare-transitioning-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager {
            state: Some(Ok(DaemonActiveState::Transitioning)),
            ..FakeDaemonManager::default()
        };
        let calls = Rc::clone(&manager.calls);

        prepare_sleep(&mut manager, &marker, &prepared_marker, move || {
            calls.borrow_mut().push("restore");
            Ok(())
        })
        .unwrap();

        assert_eq!(&*manager.calls.borrow(), &["state", "stop", "restore"]);
        assert!(!marker.exists());
        assert!(prepared_marker.is_file());
    }

    #[test]
    fn failed_restoration_does_not_authorize_resume() {
        let marker = marker_path("restore-failed");
        let prepared_marker = marker_path("restore-failed-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();

        let error = prepare_sleep(&mut manager, &marker, &prepared_marker, || {
            Err(io::Error::other("both fans did not confirm Auto"))
        })
        .unwrap_err();

        assert!(error.to_string().contains("both fans did not confirm Auto"));
        assert!(!marker.exists());
        assert!(!prepared_marker.exists());
        assert!(super::start_gate_marker(&marker).is_file());
        restore_after_failed_guard(&prepared_marker, || Ok(())).unwrap();
        assert!(!prepared_marker.exists());
        assert!(!super::start_gate_marker(&marker).exists());
        resume_after_sleep(&mut manager, &marker).unwrap();
        assert_eq!(
            &*manager.calls.borrow(),
            &["state", "invocation-id", "reset-planned", "stop"]
        );
    }

    #[test]
    fn repeated_cycles_reset_only_planned_starts() {
        let marker = marker_path("repeated");
        let prepared_marker = marker_path("repeated-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut all_calls = Vec::new();

        for _ in 0..3 {
            let mut manager = FakeDaemonManager::active();
            prepare_sleep(&mut manager, &marker, &prepared_marker, || Ok(())).unwrap();
            resume_after_sleep(&mut manager, &marker).unwrap();
            all_calls.extend(manager.calls.borrow().iter().copied());
        }

        assert_eq!(
            all_calls,
            [
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "state",
                "invocation-id",
                "restart",
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "state",
                "invocation-id",
                "restart",
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "state",
                "invocation-id",
                "restart",
            ]
        );
    }

    #[test]
    fn daemon_readiness_failure_retains_resume_authorization_for_retry() {
        let marker = marker_path("readiness-failed");
        let prepared_marker = marker_path("readiness-failed-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();
        prepare_sleep(&mut manager, &marker, &prepared_marker, || Ok(())).unwrap();
        manager.start_result = Some(Err(io::Error::other("daemon did not become ready")));

        assert!(resume_after_sleep(&mut manager, &marker).is_err());
        assert!(marker.is_file());
        assert!(super::start_gate_marker(&marker).is_file());
        assert_eq!(
            &*manager.calls.borrow(),
            &[
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "state",
                "invocation-id",
                "restart"
            ]
        );
        let recovery_calls = Rc::new(RefCell::new(Vec::new()));
        let stop_post_calls = Rc::clone(&recovery_calls);
        restore_after_failed_guard(&prepared_marker, move || {
            stop_post_calls.borrow_mut().push("restore");
            Ok(())
        })
        .unwrap();
        assert_eq!(&*recovery_calls.borrow(), &["restore"]);
        assert!(prepared_marker.is_file());
        assert!(super::start_gate_marker(&marker).is_file());
    }

    #[test]
    fn daemon_fault_during_planned_stop_is_not_authorized_for_resume() {
        let marker = marker_path("stop-race");
        let prepared_marker = marker_path("stop-race-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();
        manager.stop_result = Some(Ok(PlannedStop::Faulted));

        prepare_sleep(&mut manager, &marker, &prepared_marker, || Ok(())).unwrap();
        resume_after_sleep(&mut manager, &marker).unwrap();

        assert_eq!(
            &*manager.calls.borrow(),
            &["state", "invocation-id", "reset-planned", "stop"]
        );
        assert!(!marker.exists());
    }

    #[test]
    fn intervening_daemon_is_stopped_and_replaced_during_resume() {
        let marker = marker_path("intervening");
        let prepared_marker = marker_path("intervening-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();
        prepare_sleep(&mut manager, &marker, &prepared_marker, || Ok(())).unwrap();
        manager.state = Some(Ok(DaemonActiveState::Active));

        resume_after_sleep(&mut manager, &marker).unwrap();

        assert_eq!(
            &*manager.calls.borrow(),
            &[
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "state",
                "stop",
                "restart"
            ]
        );
        assert!(!marker.exists());
    }

    #[test]
    fn fault_after_preparation_preserves_latch_and_resume_authorization() {
        let marker = marker_path("resume-fault");
        let prepared_marker = marker_path("resume-fault-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();
        prepare_sleep(&mut manager, &marker, &prepared_marker, || Ok(())).unwrap();
        manager.state = Some(Ok(DaemonActiveState::Failed));

        assert!(resume_after_sleep(&mut manager, &marker).is_err());

        assert_eq!(
            &*manager.calls.borrow(),
            &["state", "invocation-id", "reset-planned", "stop", "state"]
        );
        assert!(marker.is_file());
    }

    #[test]
    fn cancelled_guard_without_auto_confirmation_hands_off_recovery() {
        let prepared_marker = marker_path("cancelled-prepared");
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let calls = Rc::new(RefCell::new(Vec::new()));
        let failed_calls = Rc::clone(&calls);
        restore_after_failed_guard(&prepared_marker, move || {
            failed_calls.borrow_mut().push("restore");
            Ok(())
        })
        .unwrap();

        assert_eq!(&*calls.borrow(), &["restore"]);
    }

    #[test]
    fn completed_resume_does_not_repeat_recovery_during_stop_post() {
        let prepared_marker = marker_path("completed-prepared");
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        fs::write(&prepared_marker, super::RESUME_COMPLETED_CONTENT).unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let successful_calls = Rc::clone(&calls);
        restore_after_failed_guard(&prepared_marker, move || {
            successful_calls.borrow_mut().push("unexpected");
            Ok(())
        })
        .unwrap();

        assert!(calls.borrow().is_empty());
        assert!(!prepared_marker.exists());
    }

    #[test]
    fn transitioning_daemon_is_serialized_through_stop_before_fresh_restart() {
        let marker = marker_path("transitioning");
        let prepared_marker = marker_path("transitioning-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();
        prepare_sleep(&mut manager, &marker, &prepared_marker, || Ok(())).unwrap();
        manager.state = Some(Ok(DaemonActiveState::Transitioning));

        resume_after_sleep(&mut manager, &marker).unwrap();

        assert_eq!(
            &*manager.calls.borrow(),
            &[
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "state",
                "stop",
                "restart"
            ]
        );
    }

    #[test]
    fn stopped_intervening_invocation_preserves_its_start_limit_state() {
        let marker = marker_path("stopped-intervening");
        let prepared_marker = marker_path("stopped-intervening-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();
        prepare_sleep(&mut manager, &marker, &prepared_marker, || Ok(())).unwrap();
        manager.state = Some(Ok(DaemonActiveState::Inactive));
        manager.invocation_id = Some(Ok(INTERVENING_INVOCATION.to_owned()));

        assert!(resume_after_sleep(&mut manager, &marker).is_err());

        assert_eq!(
            &*manager.calls.borrow(),
            &[
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "state",
                "invocation-id"
            ]
        );
        assert!(marker.is_file());
    }

    #[test]
    fn garbage_collected_planned_invocation_restarts_without_resetting_state() {
        let marker = marker_path("garbage-collected");
        let prepared_marker = marker_path("garbage-collected-prepared");
        let _cleanup = MarkerCleanup(marker.clone());
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        let mut manager = FakeDaemonManager::active();
        prepare_sleep(&mut manager, &marker, &prepared_marker, || Ok(())).unwrap();
        manager.state = Some(Ok(DaemonActiveState::Inactive));
        manager.invocation_id = Some(Ok(String::new()));

        resume_after_sleep(&mut manager, &marker).unwrap();

        assert_eq!(
            &*manager.calls.borrow(),
            &[
                "state",
                "invocation-id",
                "reset-planned",
                "stop",
                "state",
                "invocation-id",
                "restart"
            ]
        );
        assert!(!marker.exists());
    }

    #[test]
    fn corrupt_prepared_marker_runs_independent_recovery() {
        let prepared_marker = marker_path("corrupt-prepared");
        let _prepared_cleanup = MarkerCleanup(prepared_marker.clone());
        fs::write(&prepared_marker, b"firmware-auto-conf").unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let recovery_calls = Rc::clone(&calls);

        restore_after_failed_guard(&prepared_marker, move || {
            recovery_calls.borrow_mut().push("restore");
            Ok(())
        })
        .unwrap();

        assert_eq!(&*calls.borrow(), &["restore"]);
    }

    #[test]
    fn corrupt_resume_marker_never_resets_or_restarts_daemon() {
        let marker = marker_path("corrupt-resume");
        let _cleanup = MarkerCleanup(marker.clone());
        fs::write(&marker, b"res").unwrap();
        let mut manager = FakeDaemonManager::inactive();

        assert!(resume_after_sleep(&mut manager, &marker).is_err());

        assert!(manager.calls.borrow().is_empty());
        assert!(marker.is_file());
    }

    fn marker_path(case: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pt31553-sleep-guard-{}-{case}", std::process::id()))
    }

    struct MarkerCleanup(PathBuf);

    impl Drop for MarkerCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(super::start_gate_marker(&self.0));
        }
    }
}
