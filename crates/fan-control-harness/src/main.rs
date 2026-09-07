use std::{
    env,
    error::Error,
    io::{self, Read},
    os::unix::{fs::MetadataExt, fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fan_control_core::{
    CapturedMatchedWorkloadStartingConditions, Clock, EvidenceFan, EvidenceProfile,
    EvidenceTimestamp, ExternalPower, MatchedWorkloadStartingConditions, NvidiaGpuSelector,
    NvmlErrorKind, QUALIFICATION_CGROUP_PREFIX, SUPERVISED_ENDURANCE_WORKLOAD_ID,
    SystemOwnershipPlatform, TelemetrySampleEvidence, WorkloadEvidence, discover_acer_hwmon,
    observe_fan_firmware_auto_before,
};
use fan_control_daemon::{HWMON_ROOT, capture_system_qualification_sample, sample_system_nvidia};
use fan_control_observer::{DEFAULT_SOCKET_PATH, ObserverConfirmation, query_protected_observer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

mod telemetry;

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pt31553 qualification harness: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let operation = arguments.next().ok_or("operation is required")?;
    let deadline = arguments
        .next()
        .ok_or("absolute monotonic deadline is required")?
        .parse::<u64>()?;
    if arguments.next().is_some() {
        return Err("unexpected qualification harness argument".into());
    }
    require_before_deadline(deadline)?;
    match operation.as_str() {
        "sample-nvidia" => sample_nvidia(read_request()?, deadline),
        "capture-baseline-starting-conditions" => {
            capture_baseline_starting_conditions(read_request()?, deadline)
        }
        "capture-baseline-observation" => capture_baseline_observation(read_request()?, deadline),
        "capture-matched-starting-conditions" => {
            capture_matched_starting_conditions(read_request()?, deadline)
        }
        "capture-starting-conditions" => {
            capture_endurance_starting_conditions(read_request()?, deadline)
        }
        "confirm-endurance-observer" => confirm_endurance_observer(read_request()?, deadline),
        "confirm-endurance-firmware-auto" | "confirm-live-lifecycle-firmware-auto" => {
            confirm_firmware_auto(read_request()?, deadline)
        }
        "start-baseline-workload" => {
            start_workload(read_request()?, deadline, StartResponse::Plain)
        }
        "start-matched-workload" => {
            start_workload(read_request()?, deadline, StartResponse::Observed)
        }
        "start-workload" => start_workload(read_request()?, deadline, StartResponse::Plain),
        "stop-baseline-workload" => {
            stop_workload(deadline, StopMode::Graceful, StopResponse::Plain)
        }
        "contain-baseline-workload" => stop_workload(deadline, StopMode::Kill, StopResponse::Plain),
        "stop-matched-workload" => {
            stop_workload(deadline, StopMode::Graceful, StopResponse::Observed)
        }
        "stop-workload" => stop_workload(deadline, StopMode::Graceful, StopResponse::Endurance),
        "contain-workload" | "force-contain-workload" => {
            stop_workload(deadline, StopMode::Kill, StopResponse::Endurance)
        }
        "cleanup-baseline-workload" => cleanup_baseline(read_request()?, deadline),
        _ => Err(format!("unsupported qualification harness operation: {operation}").into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NvidiaRequest {
    uuid: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum NvidiaResponse {
    Sample {
        uuid: String,
        pci_bus_id: String,
        temperature_celsius: f64,
    },
    Error {
        error_kind: &'static str,
        error: String,
    },
}

fn sample_nvidia(request: NvidiaRequest, deadline: u64) -> Result<(), Box<dyn Error>> {
    let selector = NvidiaGpuSelector::uuid(request.uuid)?;
    let response = match sample_system_nvidia(&selector) {
        Ok(sample) => NvidiaResponse::Sample {
            uuid: sample.uuid().to_owned(),
            pci_bus_id: sample.pci_bus_id().to_owned(),
            temperature_celsius: sample.temperature_celsius(),
        },
        Err(error) => NvidiaResponse::Error {
            error_kind: nvidia_error_kind(error.kind()),
            error: error.to_string(),
        },
    };
    require_before_deadline(deadline)?;
    write_response(&response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineStartingRequest {
    nvidia_gpu_uuid: String,
}

struct StartingConditionsCapture {
    nvidia_gpu_uuid: String,
    observation: CapturedMatchedWorkloadStartingConditions,
    cpu_time_snapshot: telemetry::CpuTimeSnapshot,
    cpu_throttle_snapshot: telemetry::CpuThrottleSnapshot,
}

fn capture_starting_conditions(
    nvidia_gpu_uuid: &str,
    deadline: u64,
) -> Result<StartingConditionsCapture, Box<dyn Error>> {
    let selector = NvidiaGpuSelector::uuid(nvidia_gpu_uuid)?;
    require_observer(deadline)?;
    let sample = capture_system_qualification_sample(&selector)?;
    let observer = require_observer(deadline)?;
    let (cpu_time_snapshot, cpu_throttle_snapshot) = telemetry::starting_snapshots()?;
    let captured_at = evidence_timestamp()?;
    require_before_deadline(deadline)?;
    Ok(StartingConditionsCapture {
        nvidia_gpu_uuid: selector.value().to_owned(),
        observation: CapturedMatchedWorkloadStartingConditions {
            captured_at,
            conditions: MatchedWorkloadStartingConditions {
                ambient_millicelsius: observer.ambient_millicelsius,
                cpu_millicelsius: sample.cpu_millicelsius,
                gpu_millicelsius: sample.gpu_millicelsius,
                power_profile: evidence_profile(sample.external_power)?,
            },
        },
        cpu_time_snapshot,
        cpu_throttle_snapshot,
    })
}

#[derive(Serialize)]
struct BaselineStartingResponse {
    captured_at: EvidenceTimestamp,
    nvidia_gpu_uuid: String,
    ambient_millicelsius: i32,
    cpu_millicelsius: i32,
    gpu_millicelsius: i32,
    power_profile: EvidenceProfile,
    cpu_time_snapshot: telemetry::CpuTimeSnapshot,
    cpu_throttle_snapshot: telemetry::CpuThrottleSnapshot,
}

fn capture_baseline_starting_conditions(
    request: BaselineStartingRequest,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    let capture = capture_starting_conditions(&request.nvidia_gpu_uuid, deadline)?;
    let response = BaselineStartingResponse {
        captured_at: capture.observation.captured_at,
        nvidia_gpu_uuid: capture.nvidia_gpu_uuid,
        ambient_millicelsius: capture.observation.conditions.ambient_millicelsius,
        cpu_millicelsius: capture.observation.conditions.cpu_millicelsius,
        gpu_millicelsius: capture.observation.conditions.gpu_millicelsius,
        power_profile: capture.observation.conditions.power_profile,
        cpu_time_snapshot: capture.cpu_time_snapshot,
        cpu_throttle_snapshot: capture.cpu_throttle_snapshot,
    };
    require_before_deadline(deadline)?;
    write_response(&response)
}

#[derive(Serialize)]
struct MatchedStartingResponse {
    observer_present: bool,
    nvidia_gpu_uuid: String,
    observation: CapturedMatchedWorkloadStartingConditions,
    cpu_time_snapshot: telemetry::CpuTimeSnapshot,
    cpu_throttle_snapshot: telemetry::CpuThrottleSnapshot,
}

fn capture_matched_starting_conditions(
    request: BaselineStartingRequest,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    let capture = capture_starting_conditions(&request.nvidia_gpu_uuid, deadline)?;
    write_response(&MatchedStartingResponse {
        observer_present: true,
        nvidia_gpu_uuid: capture.nvidia_gpu_uuid,
        observation: capture.observation,
        cpu_time_snapshot: capture.cpu_time_snapshot,
        cpu_throttle_snapshot: capture.cpu_throttle_snapshot,
    })
}

#[derive(Serialize)]
struct EnduranceStartingResponse {
    nvidia_gpu_uuid: String,
    observation: CapturedMatchedWorkloadStartingConditions,
    cpu_time_snapshot: telemetry::CpuTimeSnapshot,
    cpu_throttle_snapshot: telemetry::CpuThrottleSnapshot,
}

fn capture_endurance_starting_conditions(
    request: BaselineStartingRequest,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    let capture = capture_starting_conditions(&request.nvidia_gpu_uuid, deadline)?;
    write_response(&EnduranceStartingResponse {
        nvidia_gpu_uuid: capture.nvidia_gpu_uuid,
        observation: capture.observation,
        cpu_time_snapshot: capture.cpu_time_snapshot,
        cpu_throttle_snapshot: capture.cpu_throttle_snapshot,
    })
}

#[derive(Serialize)]
struct BaselineObservationResponse {
    nvidia_gpu_uuid: String,
    sample: TelemetrySampleEvidence,
    cpu_time_snapshot: telemetry::CpuTimeSnapshot,
    cpu_throttle_snapshot: telemetry::CpuThrottleSnapshot,
}

fn capture_baseline_observation(
    request: telemetry::TelemetryRequest,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    let capture = telemetry::capture(request, deadline)?;
    require_before_deadline(deadline)?;
    write_response(&BaselineObservationResponse {
        nvidia_gpu_uuid: capture.nvidia_gpu_uuid,
        sample: capture.sample,
        cpu_time_snapshot: capture.cpu_time_snapshot,
        cpu_throttle_snapshot: capture.cpu_throttle_snapshot,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FanRequest {
    fan: EvidenceFan,
}

fn confirm_firmware_auto(request: FanRequest, deadline: u64) -> Result<(), Box<dyn Error>> {
    require_before_deadline(deadline)?;
    let mut platform = SystemOwnershipPlatform::new();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT))?;
    let io_deadline = platform
        .monotonic_now()
        .checked_add(Duration::from_secs(1))
        .ok_or("fan observation deadline overflow")?;
    let observation = observe_fan_firmware_auto_before(
        &mut platform,
        &device,
        request.fan,
        evidence_timestamp()?,
        io_deadline,
    )?;
    require_before_deadline(deadline)?;
    write_response(&observation)
}

#[derive(Serialize)]
struct ObserverResponse {
    observer_present: bool,
    confirmed: bool,
    observed_at: EvidenceTimestamp,
}

fn confirm_endurance_observer(_: EmptyRequest, deadline: u64) -> Result<(), Box<dyn Error>> {
    let confirmation = query_observer(deadline)?;
    let response = ObserverResponse {
        observer_present: confirmation.observer_present,
        confirmed: confirmation.confirmed,
        observed_at: EvidenceTimestamp {
            monotonic_millis: confirmation.observed_at.monotonic_millis,
            wall_unix_millis: confirmation.observed_at.wall_unix_millis,
        },
    };
    write_response(&response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartWorkloadRequest {
    workload: WorkloadEvidence,
}

#[derive(Clone, Copy)]
enum StartResponse {
    Plain,
    Observed,
}

#[derive(Serialize)]
struct ObservedWorkloadStart {
    observer_present: bool,
    started_at: EvidenceTimestamp,
}

fn start_workload(
    request: StartWorkloadRequest,
    deadline: u64,
    response: StartResponse,
) -> Result<(), Box<dyn Error>> {
    let executable = canonical_workload_executable(&request.workload)?;
    require_protected_workload(executable)?;
    if current_cgroup_processes()?
        .iter()
        .any(|pid| *pid != std::process::id())
    {
        return Err("qualification cgroup already contains a workload".into());
    }
    if matches!(response, StartResponse::Observed) {
        require_observer(deadline)?;
    }
    let mut child = Command::new(executable)
        .arg("--fixed")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let confirmation_at = match require_running_child(&mut child, deadline) {
        Ok(timestamp) => timestamp,
        Err(error) => {
            let _ = kill_other_cgroup_processes_once();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    match response {
        StartResponse::Plain => write_response(&confirmation_at),
        StartResponse::Observed => write_response(&ObservedWorkloadStart {
            observer_present: true,
            started_at: confirmation_at,
        }),
    }
}

fn canonical_workload_executable(workload: &WorkloadEvidence) -> Result<&Path, Box<dyn Error>> {
    let executable = match (workload.workload_id.as_str(), workload.power_profile) {
        ("idle-ac-v1", EvidenceProfile::Ac) | ("idle-battery-v1", EvidenceProfile::Battery) => {
            "idle"
        }
        ("cpu-ac-v1", EvidenceProfile::Ac) | ("cpu-battery-v1", EvidenceProfile::Battery) => "cpu",
        ("gpu-ac-v1", EvidenceProfile::Ac) | ("gpu-battery-v1", EvidenceProfile::Battery) => "gpu",
        ("combined-ac-v1", EvidenceProfile::Ac) => "combined",
        (SUPERVISED_ENDURANCE_WORKLOAD_ID, EvidenceProfile::Ac) => "mixed",
        _ => return Err("workload identity and power profile are not canonical".into()),
    };
    let path = match executable {
        "idle" => Path::new("/usr/lib/pt31553-fan-control/workloads/idle"),
        "cpu" => Path::new("/usr/lib/pt31553-fan-control/workloads/cpu"),
        "gpu" => Path::new("/usr/lib/pt31553-fan-control/workloads/gpu"),
        "combined" => Path::new("/usr/lib/pt31553-fan-control/workloads/combined"),
        "mixed" => Path::new("/usr/lib/pt31553-fan-control/workloads/mixed"),
        _ => unreachable!(),
    };
    let expected_command = [path.display().to_string(), "--fixed".into()];
    if workload.version != "1.0.0" || workload.command != expected_command {
        return Err("workload command or version is not canonical".into());
    }
    Ok(path)
}

fn require_protected_workload(path: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || mode & 0o022 != 0
        || mode & 0o111 == 0
    {
        return Err(format!("workload executable is not protected: {}", path.display()).into());
    }
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(format!(
                "workload executable ancestor is not protected: {}",
                ancestor.display()
            )
            .into());
        }
    }
    Ok(())
}

fn require_running_child(
    child: &mut std::process::Child,
    deadline: u64,
) -> Result<EvidenceTimestamp, Box<dyn Error>> {
    let confirm_after = require_before_deadline(deadline)?.saturating_add(100);
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("qualification workload exited during launch: {status}").into());
        }
        if !current_cgroup_processes()?.contains(&child.id()) {
            return Err("qualification workload escaped its cgroup".into());
        }
        let now = require_before_deadline(deadline)?;
        if now >= confirm_after {
            return evidence_timestamp();
        }
        thread::sleep(Duration::from_millis((confirm_after - now).min(10)));
    }
}

#[derive(Clone, Copy)]
enum StopMode {
    Graceful,
    Kill,
}

#[derive(Clone, Copy)]
enum StopResponse {
    Plain,
    Observed,
    Endurance,
}

#[derive(Serialize)]
struct StopConfirmation {
    confirmed: bool,
    observer_present: bool,
}

#[derive(Serialize)]
struct EnduranceStopConfirmation {
    observed_at: EvidenceTimestamp,
    process_identity: &'static str,
    running: bool,
}

fn stop_workload(
    deadline: u64,
    mode: StopMode,
    response: StopResponse,
) -> Result<(), Box<dyn Error>> {
    let signal = match mode {
        StopMode::Graceful => libc::SIGTERM,
        StopMode::Kill => libc::SIGKILL,
    };
    loop {
        let processes = current_cgroup_processes()?
            .into_iter()
            .filter(|pid| *pid != std::process::id())
            .collect::<Vec<_>>();
        if processes.is_empty() {
            break;
        }
        for pid in processes {
            let pid = i32::try_from(pid).map_err(|_| "workload PID cannot be represented")?;
            // SAFETY: the PID came from this harness's private cgroup; ESRCH is accepted only
            // because absence is rechecked from cgroup.procs on the next iteration.
            if unsafe { libc::kill(pid, signal) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error.into());
                }
            }
        }
        require_before_deadline(deadline)?;
        thread::sleep(Duration::from_millis(10));
    }
    let observed_at = evidence_timestamp()?;
    match response {
        StopResponse::Plain => write_response(&serde_json::json!({ "confirmed": true })),
        StopResponse::Observed => write_response(&StopConfirmation {
            confirmed: true,
            observer_present: query_observer(deadline)
                .is_ok_and(|confirmation| confirmation.observer_present),
        }),
        StopResponse::Endurance => write_response(&EnduranceStopConfirmation {
            observed_at,
            process_identity: "/usr/lib/pt31553-fan-control/workloads/mixed",
            running: false,
        }),
    }
}

fn kill_other_cgroup_processes_once() -> Result<(), Box<dyn Error>> {
    for pid in current_cgroup_processes()?
        .into_iter()
        .filter(|pid| *pid != std::process::id())
    {
        let pid = i32::try_from(pid).map_err(|_| "workload PID cannot be represented")?;
        // SAFETY: the PID came from this harness's exact private qualification cgroup.
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
    }
    Ok(())
}

fn current_cgroup_processes() -> Result<Vec<u32>, Box<dyn Error>> {
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    let relative = qualification_cgroup_relative_path(&membership)?;
    let source = std::fs::read_to_string(
        Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("cgroup.procs"),
    )?;
    source
        .lines()
        .map(|line| line.parse::<u32>().map_err(Into::into))
        .collect()
}

fn qualification_cgroup_relative_path(membership: &str) -> Result<&str, &'static str> {
    let mut paths = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"));
    let path = paths
        .next()
        .ok_or("unified cgroup membership is unavailable")?;
    if paths.next().is_some() {
        return Err("unified cgroup membership is malformed");
    }
    let relative = path
        .strip_prefix('/')
        .ok_or("unified cgroup membership is malformed")?;
    if relative.contains('/') {
        return Err("qualification harness is not in a private root cgroup");
    }
    let suffix = relative
        .strip_prefix(QUALIFICATION_CGROUP_PREFIX)
        .ok_or("qualification harness is outside a qualification cgroup")?;
    let (pid, counter) = suffix
        .split_once('-')
        .ok_or("qualification cgroup identity is malformed")?;
    if pid.is_empty()
        || counter.is_empty()
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !counter.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("qualification cgroup identity is malformed");
    }
    Ok(relative)
}

fn cleanup_baseline(_: EmptyRequest, deadline: u64) -> Result<(), Box<dyn Error>> {
    require_before_deadline(deadline)?;
    write_response(&serde_json::json!({ "fan_control_write_count": 0 }))
}

fn require_observer(deadline: u64) -> Result<ObserverConfirmation, Box<dyn Error>> {
    let confirmation = query_observer(deadline)?;
    if !confirmation.observer_present || !confirmation.confirmed {
        return Err("physical observer presence is not confirmed".into());
    }
    Ok(confirmation)
}

fn query_observer(deadline: u64) -> Result<ObserverConfirmation, Box<dyn Error>> {
    require_before_deadline(deadline)?;
    let confirmation = query_protected_observer(Path::new(DEFAULT_SOCKET_PATH))?;
    require_before_deadline(deadline)?;
    Ok(confirmation)
}

fn evidence_profile(power: ExternalPower) -> Result<EvidenceProfile, Box<dyn Error>> {
    match power {
        ExternalPower::Connected => Ok(EvidenceProfile::Ac),
        ExternalPower::Disconnected => Ok(EvidenceProfile::Battery),
        ExternalPower::Unknown => Err("external power state is unknown".into()),
    }
}

fn nvidia_error_kind(kind: NvmlErrorKind) -> &'static str {
    match kind {
        NvmlErrorKind::ResetRequired => "reset-required",
        NvmlErrorKind::GpuLost => "gpu-lost",
        NvmlErrorKind::NoData => "no-data",
        NvmlErrorKind::NotReady => "not-ready",
        NvmlErrorKind::TimedOut => "timed-out",
        NvmlErrorKind::InvalidState => "invalid-state",
        NvmlErrorKind::Unsupported => "unsupported",
        NvmlErrorKind::LibraryFailure => "library-failure",
        NvmlErrorKind::Other => "other",
    }
}

fn read_request<T: DeserializeOwned>() -> Result<T, Box<dyn Error>> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("qualification harness request has an invalid size".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_response(response: &impl Serialize) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(io::stdout().lock(), response)?;
    Ok(())
}

fn require_before_deadline(deadline: u64) -> Result<u64, Box<dyn Error>> {
    let now = monotonic_millis()?;
    if now >= deadline {
        return Err("qualification harness deadline expired".into());
    }
    Ok(now)
}

fn evidence_timestamp() -> Result<EvidenceTimestamp, Box<dyn Error>> {
    Ok(EvidenceTimestamp {
        monotonic_millis: monotonic_millis()?,
        wall_unix_millis: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()
            .map_err(|_| "wall clock cannot be represented")?,
    })
}

fn monotonic_millis() -> io::Result<u64> {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: timestamp points to writable storage for clock_gettime.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, timestamp.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful clock_gettime initialized timestamp.
    let timestamp = unsafe { timestamp.assume_init() };
    Ok(u64::try_from(timestamp.tv_sec)
        .unwrap_or(u64::MAX)
        .saturating_mul(1_000)
        .saturating_add(u64::try_from(timestamp.tv_nsec).unwrap_or(u64::MAX) / 1_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workload(
        workload_id: &str,
        executable: &str,
        power_profile: EvidenceProfile,
    ) -> WorkloadEvidence {
        WorkloadEvidence {
            workload_id: workload_id.into(),
            command: vec![
                format!("/usr/lib/pt31553-fan-control/workloads/{executable}"),
                "--fixed".into(),
            ],
            version: "1.0.0".into(),
            power_profile,
            ambient_millicelsius: 22_000,
            starting_cpu_millicelsius: 45_000,
            starting_gpu_millicelsius: 43_000,
        }
    }

    #[test]
    fn power_profile_requires_a_known_physical_state() {
        assert_eq!(
            evidence_profile(ExternalPower::Connected).unwrap(),
            EvidenceProfile::Ac
        );
        assert_eq!(
            evidence_profile(ExternalPower::Disconnected).unwrap(),
            EvidenceProfile::Battery
        );
        assert!(evidence_profile(ExternalPower::Unknown).is_err());
    }

    #[test]
    fn every_nvidia_failure_has_the_protocol_spelling() {
        assert_eq!(
            nvidia_error_kind(NvmlErrorKind::ResetRequired),
            "reset-required"
        );
        assert_eq!(nvidia_error_kind(NvmlErrorKind::GpuLost), "gpu-lost");
        assert_eq!(nvidia_error_kind(NvmlErrorKind::NoData), "no-data");
        assert_eq!(nvidia_error_kind(NvmlErrorKind::NotReady), "not-ready");
        assert_eq!(nvidia_error_kind(NvmlErrorKind::TimedOut), "timed-out");
        assert_eq!(
            nvidia_error_kind(NvmlErrorKind::InvalidState),
            "invalid-state"
        );
        assert_eq!(nvidia_error_kind(NvmlErrorKind::Unsupported), "unsupported");
        assert_eq!(
            nvidia_error_kind(NvmlErrorKind::LibraryFailure),
            "library-failure"
        );
        assert_eq!(nvidia_error_kind(NvmlErrorKind::Other), "other");
    }

    #[test]
    fn expired_deadline_is_rejected() {
        assert!(require_before_deadline(0).is_err());
    }

    #[test]
    fn canonical_workloads_map_to_fixed_protected_paths() {
        for (workload_id, executable, power_profile) in [
            ("idle-ac-v1", "idle", EvidenceProfile::Ac),
            ("idle-battery-v1", "idle", EvidenceProfile::Battery),
            ("cpu-ac-v1", "cpu", EvidenceProfile::Ac),
            ("cpu-battery-v1", "cpu", EvidenceProfile::Battery),
            ("gpu-ac-v1", "gpu", EvidenceProfile::Ac),
            ("gpu-battery-v1", "gpu", EvidenceProfile::Battery),
            ("combined-ac-v1", "combined", EvidenceProfile::Ac),
            (
                SUPERVISED_ENDURANCE_WORKLOAD_ID,
                "mixed",
                EvidenceProfile::Ac,
            ),
        ] {
            assert_eq!(
                canonical_workload_executable(&workload(workload_id, executable, power_profile))
                    .unwrap(),
                Path::new(&format!(
                    "/usr/lib/pt31553-fan-control/workloads/{executable}"
                ))
            );
        }
    }

    #[test]
    fn workload_identity_command_version_and_profile_must_match() {
        let canonical = workload("cpu-ac-v1", "cpu", EvidenceProfile::Ac);

        let mut wrong_command = canonical.clone();
        wrong_command.command[0] = "/usr/bin/stress".into();
        assert!(canonical_workload_executable(&wrong_command).is_err());

        let mut wrong_version = canonical.clone();
        wrong_version.version = "latest".into();
        assert!(canonical_workload_executable(&wrong_version).is_err());

        let mut wrong_profile = canonical;
        wrong_profile.power_profile = EvidenceProfile::Battery;
        assert!(canonical_workload_executable(&wrong_profile).is_err());
    }

    #[test]
    fn workload_management_requires_an_exact_private_qualification_cgroup() {
        assert_eq!(
            qualification_cgroup_relative_path("0::/pt31553-fan-qualify-123-4\n").unwrap(),
            "pt31553-fan-qualify-123-4"
        );
        for membership in [
            "0::/\n",
            "0::/user.slice/session.scope\n",
            "0::/pt31553-fan-qualify-123-4/nested\n",
            "0::/pt31553-fan-qualify--4\n",
            "0::/pt31553-fan-qualify-123-x\n",
            "0::/pt31553-fan-qualify-123-4\n0::/pt31553-fan-qualify-123-5\n",
        ] {
            assert!(qualification_cgroup_relative_path(membership).is_err());
        }
    }
}
