use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use fan_control_core::{
    Clock, EvidenceExternalPower, EvidenceFan, EvidenceProfile, EvidenceTimestamp, ExternalPower,
    FanCalibrationEvidence, GracefulShutdownFailure, LiveLifecycleCase,
    LiveLifecycleCaseObservation, LiveLifecycleFanAutoPair, LiveLifecycleObserved,
    LiveLifecycleObserverAttestation, LiveLifecyclePowerObservation,
    LiveLifecycleProfileObservation, LiveLifecycleRebootArmObservation,
    LiveLifecycleRebootContinuation, NvidiaGpuSelector, Profile, QualificationEnvelopeIdentityV1,
    ServiceNotification, ServiceNotifier, ShutdownController, SystemOwnershipPlatform,
    SystemdNotifier, TerminationSignalHandlers, acquire_controller_ownership,
    arm_both_fans_for_qualification_at_maximum_until, begin_qualification_control,
    discover_acer_hwmon, observe_fan_firmware_auto_before, parse_config_v1,
    prepare_qualification_control_policy, qualification_profile_for_power,
    run_healthy_control_cycle, validate_config_v1,
};
use fan_control_daemon::{HWMON_ROOT, SystemSampleSources, capture_system_qualification_sample};
use serde::{Deserialize, Serialize};

use crate::{
    evidence_timestamp, monotonic_millis, require_before_deadline, require_observer, write_response,
};

const RUNTIME_DIRECTORY: &str = "/run/pt31553-fan-lifecycle-qualification";
const STATE_PATH: &str = "/run/pt31553-fan-lifecycle-qualification/state.json";
const ACTIVE_PATH: &str = "/run/pt31553-fan-lifecycle-qualification/active.json";
const WATCHDOG_ONCE_PATH: &str = "/run/pt31553-fan-lifecycle-qualification/watchdog-once";
const ATTEMPT_PATH: &str = "/run/pt31553-fan-lifecycle-qualification/attempt.json";
const UNIT_NAME: &str = "pt31553-fan-lifecycle-qualification.service";
const UNIT_PATH: &str = "/run/systemd/system/pt31553-fan-lifecycle-qualification.service";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const OBSERVER_POLL_MILLIS: u64 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlInputs {
    protected_policy_source: String,
    qualification_envelope: QualificationEnvelopeIdentityV1,
    cpu_calibration: FanCalibrationEvidence,
    gpu_calibration: FanCalibrationEvidence,
    nvidia_gpu_uuid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunCaseRequest {
    case: LiveLifecycleCase,
    instruction: String,
    #[serde(flatten)]
    control: ControlInputs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreCaseRequest {
    case: LiveLifecycleCase,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResumeRebootRequest {
    boot_id_before: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArmRebootRequest {
    #[serde(flatten)]
    control: ControlInputs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyRequest {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ControllerBehavior {
    Normal,
    InvalidConfiguration,
    WatchdogOnce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerState {
    schema_version: u32,
    behavior: ControllerBehavior,
    executable: PathBuf,
    control: ControlInputs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveController {
    process_identity: String,
    armed_at: EvidenceTimestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessAttempt {
    process_identity: String,
}

pub(crate) fn run_case(request: RunCaseRequest, deadline: u64) -> Result<(), Box<dyn Error>> {
    require_before_deadline(deadline)?;
    if request.instruction != request.case.instruction() {
        return Err("lifecycle instruction differs from the fixed protocol".into());
    }
    if request.case == LiveLifecycleCase::Reboot {
        return Err("the reboot case must resume from a protected checkpoint".into());
    }
    validate_control_inputs(&request.control)?;
    let observed = match request.case {
        LiveLifecycleCase::InvalidConfiguration => {
            run_invalid_configuration(request.control, deadline)?
        }
        LiveLifecycleCase::DuplicateProcess => run_duplicate_process(request.control, deadline)?,
        LiveLifecycleCase::NormalStopRestart => run_normal_stop_restart(request.control, deadline)?,
        LiveLifecycleCase::ProcessKillRecovery => {
            run_process_kill_recovery(request.control, deadline)?
        }
        LiveLifecycleCase::WatchdogRecovery => run_watchdog_recovery(request.control, deadline)?,
        LiveLifecycleCase::AcToBatteryTransition => run_ac_transition(request.control, deadline)?,
        LiveLifecycleCase::SuspendResume => run_suspend_resume(request.control, deadline)?,
        LiveLifecycleCase::Reboot => unreachable!("rejected above"),
    };
    require_before_deadline(deadline)?;
    write_response(&observed)
}

pub(crate) fn restore_after_case(
    request: RestoreCaseRequest,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    if request.case == LiveLifecycleCase::Reboot {
        return Err("reboot restoration uses the post-reboot operation".into());
    }
    let action = cleanup_action(request.case)?;
    let observed = stop_and_restore_observed(action, deadline)?;
    write_response(&observed)
}

pub(crate) fn resume_after_reboot(
    request: ResumeRebootRequest,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    require_before_deadline(deadline)?;
    validate_boot_id(&request.boot_id_before)?;
    ensure_service_absent()?;
    let boot_id_after = current_boot_id()?;
    if request.boot_id_before == boot_id_after {
        return Err("reboot continuation has the same pre/post boot identity".into());
    }
    let response = LiveLifecycleObserved {
        observation: LiveLifecycleRebootContinuation {
            reboot_completed: true,
            boot_id_before: request.boot_id_before,
            boot_id_after,
            post_boot_at: evidence_timestamp()?,
        },
        observer_attestations: Vec::new(),
    };
    write_response(&response)
}

pub(crate) fn arm_after_reboot(
    request: ArmRebootRequest,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    validate_control_inputs(&request.control)?;
    let mut coverage = ObserverCoverage::start("post-reboot-arm", deadline)?;
    install_service(&request.control, ControllerBehavior::Normal)?;
    systemctl_observed(&["reset-failed", UNIT_NAME], &mut coverage, deadline)?;
    systemctl_observed(&["start", UNIT_NAME], &mut coverage, deadline)?;
    let active = wait_for_new_active(None, &mut coverage, deadline)?;
    coverage.check(deadline)?;
    write_response(&LiveLifecycleObserved {
        observation: LiveLifecycleRebootArmObservation {
            armed_at: active.armed_at,
            controller_process_identity: active.process_identity,
        },
        observer_attestations: vec![coverage.finish()?],
    })
}

pub(crate) fn restore_after_reboot(_: EmptyRequest, deadline: u64) -> Result<(), Box<dyn Error>> {
    write_response(&stop_and_restore_observed("post-reboot-restore", deadline)?)
}

fn validate_control_inputs(control: &ControlInputs) -> Result<(), Box<dyn Error>> {
    let _ = prepare_qualification_control_policy(
        &control.protected_policy_source,
        &control.qualification_envelope,
        control.cpu_calibration.clone(),
        control.gpu_calibration.clone(),
    )?;
    NvidiaGpuSelector::uuid(control.nvidia_gpu_uuid.clone())?;
    Ok(())
}

fn validate_boot_id(value: &str) -> Result<(), Box<dyn Error>> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    valid
        .then_some(())
        .ok_or_else(|| "invalid pre-reboot boot identity".into())
}

fn current_boot_id() -> Result<String, Box<dyn Error>> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim().to_owned();
    validate_boot_id(&value)?;
    Ok(value)
}

fn cleanup_action(case: LiveLifecycleCase) -> Result<&'static str, Box<dyn Error>> {
    match case {
        LiveLifecycleCase::InvalidConfiguration => Ok("invalid-configuration-cleanup"),
        LiveLifecycleCase::DuplicateProcess => Ok("duplicate-process-cleanup"),
        LiveLifecycleCase::NormalStopRestart => Ok("normal-stop-restart-cleanup"),
        LiveLifecycleCase::ProcessKillRecovery => Ok("process-kill-recovery-cleanup"),
        LiveLifecycleCase::WatchdogRecovery => Ok("watchdog-recovery-cleanup"),
        LiveLifecycleCase::AcToBatteryTransition => Ok("ac-to-battery-transition-cleanup"),
        LiveLifecycleCase::SuspendResume => Ok("suspend-resume-cleanup"),
        LiveLifecycleCase::Reboot => Err("reboot has a dedicated cleanup action".into()),
    }
}

fn run_invalid_configuration(
    control: ControlInputs,
    deadline: u64,
) -> Result<LiveLifecycleObserved<LiveLifecycleCaseObservation>, Box<dyn Error>> {
    install_service(&control, ControllerBehavior::InvalidConfiguration)?;
    systemctl(&["reset-failed", UNIT_NAME])?;
    let status = Command::new(SYSTEMCTL)
        .args(["start", UNIT_NAME])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    require_before_deadline(deadline)?;
    if status.success() {
        return Err("invalid lifecycle configuration unexpectedly started".into());
    }
    Ok(LiveLifecycleObserved {
        observation: LiveLifecycleCaseObservation::InvalidConfiguration {
            observed_at: evidence_timestamp()?,
            fresh: true,
            rejected_before_custom_control: !Path::new(ACTIVE_PATH).exists(),
        },
        observer_attestations: Vec::new(),
    })
}

fn run_duplicate_process(
    control: ControlInputs,
    deadline: u64,
) -> Result<LiveLifecycleObserved<LiveLifecycleCaseObservation>, Box<dyn Error>> {
    let mut coverage = ObserverCoverage::start("duplicate-owner-custom", deadline)?;
    install_service(&control, ControllerBehavior::Normal)?;
    systemctl_observed(&["reset-failed", UNIT_NAME], &mut coverage, deadline)?;
    systemctl_observed(&["start", UNIT_NAME], &mut coverage, deadline)?;
    let original = wait_for_new_active(None, &mut coverage, deadline)?;
    remove_if_exists(Path::new(ATTEMPT_PATH))?;
    let state = read_state()?;
    let mut duplicate = Command::new(&state.executable)
        .arg("lifecycle-controller-internal")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let rejected = wait_child_observed(&mut duplicate, &mut coverage, deadline)?;
    if rejected.success() {
        return Err("duplicate lifecycle controller unexpectedly acquired ownership".into());
    }
    let attempt: ProcessAttempt = read_secure_json(Path::new(ATTEMPT_PATH))?;
    let current = read_active()?;
    if current.process_identity != original.process_identity || !unit_is_active()? {
        return Err("duplicate attempt displaced the original lifecycle controller".into());
    }
    let observed_at = coverage.check(deadline)?;
    Ok(LiveLifecycleObserved {
        observation: LiveLifecycleCaseObservation::DuplicateProcess {
            observed_at,
            fresh: true,
            duplicate_rejected: true,
            original_owner_preserved: true,
            original_process_identity: original.process_identity,
            rejected_process_identity: attempt.process_identity,
        },
        observer_attestations: vec![coverage.finish()?],
    })
}

fn run_normal_stop_restart(
    control: ControlInputs,
    deadline: u64,
) -> Result<LiveLifecycleObserved<LiveLifecycleCaseObservation>, Box<dyn Error>> {
    let mut before_stop = ObserverCoverage::start("normal-owner-before-stop", deadline)?;
    install_service(&control, ControllerBehavior::Normal)?;
    systemctl_observed(&["reset-failed", UNIT_NAME], &mut before_stop, deadline)?;
    systemctl_observed(&["start", UNIT_NAME], &mut before_stop, deadline)?;
    let original = wait_for_new_active(None, &mut before_stop, deadline)?;
    systemctl_observed(&["stop", UNIT_NAME], &mut before_stop, deadline)?;
    let stopped_at = before_stop.check(deadline)?;
    let first_attestation = before_stop.finish()?;
    let auto_before_restart = wait_for_auto_pair(deadline, None)?;
    let mut restarted = ObserverCoverage::start("normal-restart-custom", deadline)?;
    remove_if_exists(Path::new(ACTIVE_PATH))?;
    systemctl_observed(&["start", UNIT_NAME], &mut restarted, deadline)?;
    let replacement =
        wait_for_new_active(Some(&original.process_identity), &mut restarted, deadline)?;
    restarted.check(deadline)?;
    Ok(LiveLifecycleObserved {
        observation: LiveLifecycleCaseObservation::NormalStopRestart {
            clean_stop: true,
            stopped_at,
            auto_before_restart,
            restarted_at: replacement.armed_at,
            fresh_process: true,
            process_identity_before: original.process_identity,
            process_identity_after: replacement.process_identity,
        },
        observer_attestations: vec![first_attestation, restarted.finish()?],
    })
}

fn run_process_kill_recovery(
    control: ControlInputs,
    deadline: u64,
) -> Result<LiveLifecycleObserved<LiveLifecycleCaseObservation>, Box<dyn Error>> {
    let mut before_kill = ObserverCoverage::start("process-before-kill", deadline)?;
    install_service(&control, ControllerBehavior::Normal)?;
    systemctl_observed(&["reset-failed", UNIT_NAME], &mut before_kill, deadline)?;
    let start_limit_reset_at = evidence_timestamp()?;
    systemctl_observed(&["start", UNIT_NAME], &mut before_kill, deadline)?;
    let original = wait_for_new_active(None, &mut before_kill, deadline)?;
    systemctl_observed(
        &["kill", "--kill-whom=main", "--signal=SIGKILL", UNIT_NAME],
        &mut before_kill,
        deadline,
    )?;
    let killed_at = before_kill.check(deadline)?;
    let first_attestation = before_kill.finish()?;
    let mut recovery = ObserverCoverage::start("bounded-restart-custom", deadline)?;
    let auto_before_restart = wait_for_auto_pair(deadline, Some(&mut recovery))?;
    let replacement =
        wait_for_new_active(Some(&original.process_identity), &mut recovery, deadline)?;
    recovery.check(deadline)?;
    Ok(LiveLifecycleObserved {
        observation: LiveLifecycleCaseObservation::ProcessKillRecovery {
            sigkill_observed: true,
            start_limit_reset_at,
            killed_at,
            auto_before_restart,
            restarted_at: replacement.armed_at,
            process_identity_before: original.process_identity,
            process_identity_after: replacement.process_identity,
            restart_delay_millis: fan_control_core::LIVE_RESTART_DELAY_MILLIS,
            start_limit_burst: fan_control_core::LIVE_START_LIMIT_BURST,
        },
        observer_attestations: vec![first_attestation, recovery.finish()?],
    })
}

fn run_watchdog_recovery(
    control: ControlInputs,
    deadline: u64,
) -> Result<LiveLifecycleObserved<LiveLifecycleCaseObservation>, Box<dyn Error>> {
    let mut monitored = ObserverCoverage::start("watchdog-monitored-custom", deadline)?;
    install_service(&control, ControllerBehavior::WatchdogOnce)?;
    systemctl_observed(&["reset-failed", UNIT_NAME], &mut monitored, deadline)?;
    let start_limit_reset_at = evidence_timestamp()?;
    systemctl_observed(&["start", UNIT_NAME], &mut monitored, deadline)?;
    let original = wait_for_new_active(None, &mut monitored, deadline)?;
    wait_for_process_exit(&original.process_identity, &mut monitored, deadline)?;
    let expired_at = monitored.check(deadline)?;
    let first_attestation = monitored.finish()?;
    let mut recovery = ObserverCoverage::start("bounded-restart-custom", deadline)?;
    let auto_before_restart = wait_for_auto_pair(deadline, Some(&mut recovery))?;
    let replacement =
        wait_for_new_active(Some(&original.process_identity), &mut recovery, deadline)?;
    recovery.check(deadline)?;
    Ok(LiveLifecycleObserved {
        observation: LiveLifecycleCaseObservation::WatchdogRecovery {
            watchdog_expired: true,
            start_limit_reset_at,
            expired_at,
            auto_before_restart,
            restarted_at: replacement.armed_at,
            process_identity_before: original.process_identity,
            process_identity_after: replacement.process_identity,
            restart_delay_millis: fan_control_core::LIVE_RESTART_DELAY_MILLIS,
            start_limit_burst: fan_control_core::LIVE_START_LIMIT_BURST,
        },
        observer_attestations: vec![first_attestation, recovery.finish()?],
    })
}

fn run_ac_transition(
    control: ControlInputs,
    deadline: u64,
) -> Result<LiveLifecycleObserved<LiveLifecycleCaseObservation>, Box<dyn Error>> {
    let mut coverage = ObserverCoverage::start("ac-transition-custom", deadline)?;
    install_service(&control, ControllerBehavior::Normal)?;
    systemctl_observed(&["reset-failed", UNIT_NAME], &mut coverage, deadline)?;
    systemctl_observed(&["start", UNIT_NAME], &mut coverage, deadline)?;
    wait_for_new_active(None, &mut coverage, deadline)?;
    let selector = NvidiaGpuSelector::uuid(control.nvidia_gpu_uuid)?;
    let first = capture_system_qualification_sample(&selector)?;
    if first.external_power != ExternalPower::Connected {
        return Err("AC transition case must begin with external power connected".into());
    }
    let before = LiveLifecyclePowerObservation {
        observed_at: evidence_timestamp()?,
        fresh: true,
        source: EvidenceExternalPower::Ac,
    };
    let after = loop {
        coverage.poll(deadline)?;
        let sample = capture_system_qualification_sample(&selector)?;
        match sample.external_power {
            ExternalPower::Disconnected => {
                break LiveLifecyclePowerObservation {
                    observed_at: evidence_timestamp()?,
                    fresh: true,
                    source: EvidenceExternalPower::Battery,
                };
            }
            ExternalPower::Connected => {}
            ExternalPower::Unknown => {
                return Err("external power identity became unavailable".into());
            }
        }
    };
    let profile = qualification_profile_for_power(ExternalPower::Disconnected);
    let selected_profile_after = LiveLifecycleProfileObservation {
        observed_at: evidence_timestamp()?,
        fresh: true,
        profile: match profile {
            Profile::Ac => EvidenceProfile::Ac,
            Profile::Battery => EvidenceProfile::Battery,
        },
    };
    coverage.check(deadline)?;
    Ok(LiveLifecycleObserved {
        observation: LiveLifecycleCaseObservation::AcToBatteryTransition {
            before,
            after,
            selected_profile_after,
        },
        observer_attestations: vec![coverage.finish()?],
    })
}

fn run_suspend_resume(
    control: ControlInputs,
    deadline: u64,
) -> Result<LiveLifecycleObserved<LiveLifecycleCaseObservation>, Box<dyn Error>> {
    let mut before_sleep = ObserverCoverage::start("pre-suspend-custom", deadline)?;
    install_service(&control, ControllerBehavior::Normal)?;
    systemctl_observed(&["reset-failed", UNIT_NAME], &mut before_sleep, deadline)?;
    systemctl_observed(&["start", UNIT_NAME], &mut before_sleep, deadline)?;
    let original = wait_for_new_active(None, &mut before_sleep, deadline)?;
    systemctl_observed(&["stop", UNIT_NAME], &mut before_sleep, deadline)?;
    let auto_before_sleep = wait_for_auto_pair(deadline, Some(&mut before_sleep))?;
    let suspended_at = before_sleep.check(deadline)?;
    let pre_attestation = before_sleep.finish()?;

    let status = Command::new(SYSTEMCTL)
        .arg("suspend")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("systemd rejected the normal suspend transaction".into());
    }
    require_before_deadline(deadline)?;
    let resumed_at = evidence_timestamp()?;
    let mut after_resume = ObserverCoverage::start("post-resume-custom", deadline)?;
    remove_if_exists(Path::new(ACTIVE_PATH))?;
    systemctl_observed(&["start", UNIT_NAME], &mut after_resume, deadline)?;
    let replacement = wait_for_new_active(
        Some(&original.process_identity),
        &mut after_resume,
        deadline,
    )?;
    after_resume.check(deadline)?;
    Ok(LiveLifecycleObserved {
        observation: LiveLifecycleCaseObservation::SuspendResume {
            auto_before_sleep,
            suspended_at,
            suspend_completed: true,
            resumed_at,
            process_started_at: replacement.armed_at,
            process_identity_before: original.process_identity,
            process_identity_after: replacement.process_identity,
        },
        observer_attestations: vec![pre_attestation, after_resume.finish()?],
    })
}

struct ObserverCoverage {
    action: &'static str,
    started_at: EvidenceTimestamp,
    checks: Vec<EvidenceTimestamp>,
    last_poll_millis: u64,
}

impl ObserverCoverage {
    fn start(action: &'static str, deadline: u64) -> Result<Self, Box<dyn Error>> {
        let first = observer_timestamp(deadline)?;
        Ok(Self {
            action,
            started_at: first,
            checks: vec![first],
            last_poll_millis: monotonic_millis()?,
        })
    }

    fn poll(&mut self, deadline: u64) -> Result<(), Box<dyn Error>> {
        require_before_deadline(deadline)?;
        let now = monotonic_millis()?;
        if now.saturating_sub(self.last_poll_millis) >= OBSERVER_POLL_MILLIS {
            self.check(deadline)?;
        }
        thread::sleep(Duration::from_millis(25));
        Ok(())
    }

    fn check(&mut self, deadline: u64) -> Result<EvidenceTimestamp, Box<dyn Error>> {
        let observed = observer_timestamp(deadline)?;
        if observed.monotonic_millis
            <= self
                .checks
                .last()
                .expect("coverage is nonempty")
                .monotonic_millis
        {
            thread::sleep(Duration::from_millis(1));
            let retry = observer_timestamp(deadline)?;
            if retry.monotonic_millis
                <= self
                    .checks
                    .last()
                    .expect("coverage is nonempty")
                    .monotonic_millis
            {
                return Err("observer check clock did not advance".into());
            }
            self.checks.push(retry);
            self.last_poll_millis = monotonic_millis()?;
            return Ok(retry);
        }
        self.checks.push(observed);
        self.last_poll_millis = monotonic_millis()?;
        Ok(observed)
    }

    fn finish(mut self) -> Result<LiveLifecycleObserverAttestation, Box<dyn Error>> {
        if self.checks.len() < 2 {
            self.check(u64::MAX)?;
        }
        let completed_at = *self.checks.last().expect("coverage is nonempty");
        Ok(LiveLifecycleObserverAttestation {
            action: self.action.to_owned(),
            started_at: self.started_at,
            completed_at,
            checks: self.checks,
        })
    }
}

fn observer_timestamp(deadline: u64) -> Result<EvidenceTimestamp, Box<dyn Error>> {
    let confirmation = require_observer(deadline)?;
    Ok(EvidenceTimestamp {
        monotonic_millis: confirmation.observed_at.monotonic_millis,
        wall_unix_millis: confirmation.observed_at.wall_unix_millis,
    })
}

fn stop_and_restore_observed(
    action: &'static str,
    deadline: u64,
) -> Result<LiveLifecycleObserved<EvidenceTimestamp>, Box<dyn Error>> {
    if action == "invalid-configuration-cleanup" {
        stop_and_remove_service(None, deadline)?;
        return Ok(LiveLifecycleObserved {
            observation: evidence_timestamp()?,
            observer_attestations: Vec::new(),
        });
    }
    let mut coverage = ObserverCoverage::start(action, deadline)?;
    stop_and_remove_service(Some(&mut coverage), deadline)?;
    let restored_at = coverage.check(deadline)?;
    Ok(LiveLifecycleObserved {
        observation: restored_at,
        observer_attestations: vec![coverage.finish()?],
    })
}

fn wait_for_auto_pair(
    deadline: u64,
    mut coverage: Option<&mut ObserverCoverage>,
) -> Result<LiveLifecycleFanAutoPair, Box<dyn Error>> {
    loop {
        if let Some(coverage) = coverage.as_deref_mut() {
            coverage.poll(deadline)?;
        } else {
            require_before_deadline(deadline)?;
        }
        let pair = observe_auto_pair(deadline)?;
        if pair.cpu.enable_readback == Some(2) && pair.gpu.enable_readback == Some(2) {
            return Ok(pair);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn observe_auto_pair(deadline: u64) -> Result<LiveLifecycleFanAutoPair, Box<dyn Error>> {
    let mut platform = SystemOwnershipPlatform::new();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT))?;
    let io_deadline = platform
        .monotonic_now()
        .checked_add(Duration::from_secs(1))
        .ok_or("fan observation deadline overflow")?;
    let cpu = observe_fan_firmware_auto_before(
        &mut platform,
        &device,
        EvidenceFan::Cpu,
        evidence_timestamp()?,
        io_deadline,
    )?;
    require_before_deadline(deadline)?;
    let io_deadline = platform
        .monotonic_now()
        .checked_add(Duration::from_secs(1))
        .ok_or("fan observation deadline overflow")?;
    let gpu = observe_fan_firmware_auto_before(
        &mut platform,
        &device,
        EvidenceFan::Gpu,
        evidence_timestamp()?,
        io_deadline,
    )?;
    Ok(LiveLifecycleFanAutoPair { cpu, gpu })
}

fn wait_for_new_active(
    previous: Option<&str>,
    coverage: &mut ObserverCoverage,
    deadline: u64,
) -> Result<ActiveController, Box<dyn Error>> {
    loop {
        coverage.poll(deadline)?;
        if let Ok(active) = read_active()
            && previous.is_none_or(|previous| previous != active.process_identity)
            && process_identity_is_live(&active.process_identity)
        {
            return Ok(active);
        }
    }
}

fn wait_for_process_exit(
    identity: &str,
    coverage: &mut ObserverCoverage,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    while process_identity_is_live(identity) {
        coverage.poll(deadline)?;
    }
    Ok(())
}

fn wait_child_observed(
    child: &mut std::process::Child,
    coverage: &mut ObserverCoverage,
    deadline: u64,
) -> Result<std::process::ExitStatus, Box<dyn Error>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        coverage.poll(deadline)?;
    }
}

fn process_identity_is_live(identity: &str) -> bool {
    let Some(pid) = identity
        .strip_prefix("pid-")
        .and_then(|value| value.split_once("-start-").map(|(pid, _)| pid))
        .and_then(|pid| pid.parse::<u32>().ok())
    else {
        return false;
    };
    process_identity_for(pid).is_ok_and(|current| current == identity)
}

fn process_identity_for(pid: u32) -> Result<String, Box<dyn Error>> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or("process stat has no command terminator")?;
    let tail = stat.get(end + 2..).ok_or("process stat is truncated")?;
    let start_ticks = tail
        .split_whitespace()
        .nth(19)
        .ok_or("process stat has no start time")?;
    Ok(format!("pid-{pid}-start-{start_ticks}"))
}

fn unit_is_active() -> Result<bool, Box<dyn Error>> {
    let output = Command::new(SYSTEMCTL)
        .args([
            "show",
            "--property=LoadState",
            "--property=ActiveState",
            "--value",
            UNIT_NAME,
        ])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cannot inspect {UNIT_NAME}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let state = String::from_utf8(output.stdout)?;
    let mut lines = state.lines();
    let load = lines
        .next()
        .ok_or("systemd omitted lifecycle unit load state")?;
    let active = lines
        .next()
        .ok_or("systemd omitted lifecycle unit active state")?;
    if lines.next().is_some() {
        return Err("systemd returned ambiguous lifecycle unit state".into());
    }
    if load == "not-found" {
        return Ok(false);
    }
    match active {
        "inactive" | "failed" => Ok(false),
        "active" | "activating" | "deactivating" | "reloading" | "maintenance" | "refreshing" => {
            Ok(true)
        }
        _ => Err(format!("systemd returned unknown lifecycle active state {active:?}").into()),
    }
}

fn systemctl(arguments: &[&str]) -> Result<(), Box<dyn Error>> {
    let output = Command::new(SYSTEMCTL)
        .args(arguments)
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into())
    }
}

fn systemctl_observed(
    arguments: &[&str],
    coverage: &mut ObserverCoverage,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new(SYSTEMCTL)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err(format!("systemctl {} failed with {status}", arguments.join(" "),).into());
        }
        if let Err(error) = coverage.poll(deadline) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
}

fn install_service(
    control: &ControlInputs,
    behavior: ControllerBehavior,
) -> Result<(), Box<dyn Error>> {
    ensure_service_absent()?;
    ensure_runtime_directory()?;
    for path in [ACTIVE_PATH, ATTEMPT_PATH, WATCHDOG_ONCE_PATH] {
        remove_if_exists(Path::new(path))?;
    }
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let state = ControllerState {
        schema_version: 1,
        behavior,
        executable: executable.clone(),
        control: control.clone(),
    };
    write_secure_json(Path::new(STATE_PATH), &state)?;
    write_secure_file(
        Path::new(UNIT_PATH),
        service_unit(&executable)?.as_bytes(),
        0o644,
    )?;
    systemctl(&["daemon-reload"])
}

fn ensure_service_absent() -> Result<(), Box<dyn Error>> {
    if Path::new(UNIT_PATH).exists() || unit_is_active()? {
        return Err(format!(
            "stale {UNIT_NAME} exists; run lifecycle restoration before continuing"
        )
        .into());
    }
    Ok(())
}

fn stop_and_remove_service(
    coverage: Option<&mut ObserverCoverage>,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    require_before_deadline(deadline)?;
    let mut stop_error = None;
    if Path::new(UNIT_PATH).exists() {
        let result = if let Some(coverage) = coverage {
            systemctl_observed(&["stop", UNIT_NAME], coverage, deadline)
        } else {
            systemctl(&["stop", UNIT_NAME])
        };
        if let Err(error) = result {
            stop_error = Some(error.to_string());
        }
    }
    if unit_is_active()? {
        return Err(format!(
            "refusing lifecycle unit removal while it remains active{}",
            stop_error
                .as_deref()
                .map(|error| format!(": {error}"))
                .unwrap_or_default()
        )
        .into());
    }
    restore_controller()?;
    if Path::new(UNIT_PATH).exists() {
        fs::remove_file(UNIT_PATH)?;
    }
    let _ = systemctl(&["reset-failed", UNIT_NAME]);
    systemctl(&["daemon-reload"])?;
    for path in [STATE_PATH, ACTIVE_PATH, ATTEMPT_PATH, WATCHDOG_ONCE_PATH] {
        remove_if_exists(Path::new(path))?;
    }
    require_before_deadline(deadline).map(|_| ())
}

fn service_unit(executable: &Path) -> Result<String, Box<dyn Error>> {
    let executable = executable
        .to_str()
        .ok_or("qualification harness path is not UTF-8")?;
    if executable.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("qualification harness path contains control characters".into());
    }
    let executable = executable.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!(
        r#"[Unit]
Description=PT315-53 transient lifecycle qualification controller
StartLimitIntervalSec=infinity
StartLimitBurst=2

[Service]
Type=notify
NotifyAccess=main
RuntimeDirectory=pt31553-fan-lifecycle-qualification
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ExecStart="{executable}" lifecycle-controller-internal
ExecStopPost="{executable}" lifecycle-restore-internal
WatchdogSec=6s
TimeoutAbortSec=5s
Restart=on-failure
RestartSec=2s
TimeoutStartSec=30s
TimeoutStopSec=infinity
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
PrivateTmp=yes
PrivateDevices=no
DevicePolicy=closed
DeviceAllow=/dev/nvidiactl rw
DeviceAllow=/dev/nvidia0 rw
ProtectSystem=strict
ProtectHome=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
ReadWritePaths=/sys/class/hwmon {RUNTIME_DIRECTORY}
"#
    ))
}

pub(crate) fn run_controller() -> Result<(), Box<dyn Error>> {
    require_root()?;
    ensure_runtime_directory()?;
    let state = read_state()?;
    if state.schema_version != 1 {
        return Err("unsupported lifecycle controller state schema".into());
    }
    let current_executable = fs::canonicalize(std::env::current_exe()?)?;
    if current_executable != state.executable {
        return Err("lifecycle controller executable differs from protected state".into());
    }

    let process_identity = process_identity_for(std::process::id())?;
    write_secure_json(
        Path::new(ATTEMPT_PATH),
        &ProcessAttempt {
            process_identity: process_identity.clone(),
        },
    )?;
    if state.behavior == ControllerBehavior::InvalidConfiguration {
        let invalid_was_accepted = parse_config_v1("schema_version = 1\n")
            .ok()
            .and_then(|config| validate_config_v1(config).ok())
            .is_some();
        if invalid_was_accepted {
            return Err("invalid lifecycle fixture configuration was accepted".into());
        }
        return Err(
            "invalid lifecycle fixture configuration rejected before Custom control".into(),
        );
    }

    let policy = prepare_qualification_control_policy(
        &state.control.protected_policy_source,
        &state.control.qualification_envelope,
        state.control.cpu_calibration,
        state.control.gpu_calibration,
    )?;
    let selector = NvidiaGpuSelector::uuid(state.control.nvidia_gpu_uuid)?;
    let mut sources = SystemSampleSources::discover_for_qualification(&selector)?;
    let mut notifier = SystemdNotifier::from_environment()?;
    // SAFETY: this single-threaded executable removes only its own inherited notification
    // variables before any child process can be created.
    unsafe {
        std::env::remove_var("NOTIFY_SOCKET");
        std::env::remove_var("WATCHDOG_USEC");
        std::env::remove_var("WATCHDOG_PID");
    }
    let mut shutdown = ShutdownController::new();
    let shutdown_request = shutdown.request_handle();
    let _signal_handlers = TerminationSignalHandlers::install(shutdown_request.clone())?;

    let mut platform = SystemOwnershipPlatform::new();
    let mut ownership = acquire_controller_ownership(&mut platform)?;
    let device = match ownership.discover_acer_hwmon(Path::new(HWMON_ROOT)) {
        Ok(device) => device,
        Err(error) => {
            return Err(format!(
                "lifecycle controller could not discover the owned Acer fan device: {error}"
            )
            .into());
        }
    };
    let suppress_watchdog = state.behavior == ControllerBehavior::WatchdogOnce
        && !Path::new(WATCHDOG_ONCE_PATH).exists();

    let operation = (|| -> Result<(), String> {
        ownership
            .confirm_firmware_auto_without_writes(&device)
            .map_err(|error| error.to_string())?;
        let armed = arm_both_fans_for_qualification_at_maximum_until(
            &mut ownership,
            &device,
            &shutdown_request,
        )
        .map_err(|error| error.to_string())?;
        if suppress_watchdog {
            write_secure_file(Path::new(WATCHDOG_ONCE_PATH), b"1\n", 0o600)
                .map_err(|error| error.to_string())?;
        }
        let armed_at = evidence_timestamp().map_err(|error| error.to_string())?;
        let mut control = begin_qualification_control(armed, policy, shutdown_request.clone());
        let mut published = false;
        loop {
            match run_healthy_control_cycle(&mut ownership, &mut control, &mut sources) {
                Ok(_) => {
                    if !published {
                        write_secure_json(
                            Path::new(ACTIVE_PATH),
                            &ActiveController {
                                process_identity: process_identity.clone(),
                                armed_at,
                            },
                        )
                        .map_err(|error| error.to_string())?;
                        notifier
                            .notify(ServiceNotification::Ready)
                            .map_err(|error| error.to_string())?;
                        published = true;
                    }
                    if !suppress_watchdog {
                        notifier
                            .notify(ServiceNotification::Watchdog)
                            .map_err(|error| error.to_string())?;
                    }
                }
                Err(_) if shutdown.is_requested() => return Ok(()),
                Err(error) => return Err(error.to_string()),
            }
        }
    })();

    let cleanup = shutdown.cleanup(&mut ownership, &device);
    if matches!(cleanup, Err(GracefulShutdownFailure::Critical { .. })) {
        ownership.recover_firmware_auto(&device);
    }
    ownership
        .release()
        .map_err(|error| format!("lifecycle controller could not release ownership: {error}"))?;
    if Path::new(ACTIVE_PATH).exists() {
        let active = read_active()?;
        if active.process_identity != process_identity {
            return Err("lifecycle active marker belongs to a different controller".into());
        }
        remove_if_exists(Path::new(ACTIVE_PATH))?;
    }
    if let Err(error) = cleanup {
        return Err(format!("lifecycle controller cleanup failed: {error}").into());
    }
    operation.map_err(Into::into)
}

pub(crate) fn restore_controller() -> Result<(), Box<dyn Error>> {
    require_root()?;
    let mut platform = SystemOwnershipPlatform::new();
    let mut ownership = acquire_controller_ownership(&mut platform)?;
    let device = ownership.discover_acer_hwmon(Path::new(HWMON_ROOT))?;
    let restoration = ownership.restore_firmware_auto(&device);
    if let Err(error) = &restoration {
        let containment = ownership.contain_custom_fans_at_maximum(&device);
        if !containment.restoration_confirmed() {
            ownership.recover_firmware_auto(&device);
        }
        ownership.release().map_err(|release| {
            format!("Firmware Auto recovered but ownership release failed: {release}")
        })?;
        return Err(format!(
            "initial Firmware Auto restoration failed: {error}; containment: {containment:?}"
        )
        .into());
    }
    ownership
        .release()
        .map_err(|error| format!("Firmware Auto restored but ownership release failed: {error}"))?;
    Ok(())
}

fn require_root() -> Result<(), Box<dyn Error>> {
    // SAFETY: geteuid has no preconditions and does not modify process state.
    if unsafe { libc::geteuid() } != 0 {
        return Err("lifecycle controller operations must run as root".into());
    }
    Ok(())
}

fn ensure_runtime_directory() -> Result<(), Box<dyn Error>> {
    let path = Path::new(RUNTIME_DIRECTORY);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
                return Err(format!(
                    "{} must be a root-owned directory with mode 0700",
                    path.display()
                )
                .into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn read_state() -> Result<ControllerState, Box<dyn Error>> {
    read_secure_json(Path::new(STATE_PATH))
}

fn read_active() -> Result<ActiveController, Box<dyn Error>> {
    read_secure_json(Path::new(ACTIVE_PATH))
}

fn read_secure_json<T>(path: &Path) -> Result<T, Box<dyn Error>>
where
    T: for<'de> Deserialize<'de>,
{
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 1024 * 1024
    {
        return Err(format!(
            "{} must be a protected root-owned regular file",
            path.display()
        )
        .into());
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(serde_json::from_str(&contents)?)
}

fn write_secure_json<T>(path: &Path, value: &T) -> Result<(), Box<dyn Error>>
where
    T: Serialize,
{
    let mut contents = serde_json::to_vec(value)?;
    contents.push(b'\n');
    write_secure_file(path, &contents, 0o600)
}

fn write_secure_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), Box<dyn Error>> {
    let parent = path
        .parent()
        .ok_or("protected output has no parent directory")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("protected output filename is not UTF-8")?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    remove_if_exists(&temporary)?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        OpenOptions::new().read(true).open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = remove_if_exists(&temporary);
    }
    result
}

fn remove_if_exists(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RUNTIME_DIRECTORY, UNIT_NAME, process_identity_for, process_identity_is_live, service_unit,
        validate_boot_id,
    };
    use std::path::Path;

    #[test]
    fn transient_unit_carries_the_production_supervision_and_sandbox_contract() {
        let unit = service_unit(Path::new("/usr/lib/pt31553-fan control/harness")).unwrap();

        for required in [
            "Type=notify",
            "WatchdogSec=6s",
            "Restart=on-failure",
            "RestartSec=2s",
            "StartLimitBurst=2",
            "TimeoutStopSec=infinity",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "DevicePolicy=closed",
            "ProtectSystem=strict",
            "ReadWritePaths=/sys/class/hwmon",
        ] {
            assert!(unit.contains(required), "missing unit property {required}");
        }
        assert!(unit.contains(
            "ExecStart=\"/usr/lib/pt31553-fan control/harness\" lifecycle-controller-internal"
        ));
        assert!(unit.contains(
            "ExecStopPost=\"/usr/lib/pt31553-fan control/harness\" lifecycle-restore-internal"
        ));
        assert!(unit.contains(&format!(" {RUNTIME_DIRECTORY}")));
        assert_eq!(UNIT_NAME, "pt31553-fan-lifecycle-qualification.service");
    }

    #[test]
    fn process_identity_binds_pid_to_linux_start_ticks() {
        let identity = process_identity_for(std::process::id()).unwrap();

        assert!(process_identity_is_live(&identity));
        assert!(!process_identity_is_live("pid-1-start-invalid"));
    }

    #[test]
    fn reboot_identity_accepts_only_bounded_kernel_style_tokens() {
        assert!(validate_boot_id("01234567-89ab-cdef-0123-456789abcdef").is_ok());
        assert!(validate_boot_id("").is_err());
        assert!(validate_boot_id("boot id with spaces").is_err());
        assert!(validate_boot_id(&"a".repeat(129)).is_err());
    }
}
