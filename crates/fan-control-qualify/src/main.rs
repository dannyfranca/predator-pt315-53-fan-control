use std::{
    env,
    error::Error,
    ffi::{CString, OsString},
    fs,
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fan_control_core::{
    BaselineCleanupAttestation, BaselineObservation, BaselineStartingConditions,
    CapturedBaselineStartingConditions, CapturedMatchedWorkloadStartingConditions,
    CompatibilityObservation, EvidenceFan, EvidenceProfile, EvidenceRecord, EvidenceTimestamp,
    FileAccess, FirmwareAutoBaselineEnvironment, FirmwareAutoBaselinePlan,
    MatchedWorkloadFanRestoration, MatchedWorkloadObservation,
    MatchedWorkloadTachometerCalibrations, NvidiaGpuSelector, NvmlAccess, NvmlError, NvmlErrorKind,
    NvmlGpuSample, PlatformError, PlatformErrorKind, PreflightArtifact, PreflightEnvironment,
    PreflightInputs, PreflightRequirements, ProtectedFileRequirement, QUALIFICATION_RECORD_PATH,
    QualificationEnvelopeIdentityV1, RestorationOutcome, RootOwnedQualificationRecordAccess,
    RunOutcomeStatus, SUPERVISED_ENDURANCE_WORKLOAD_ID, StartupStatus,
    SupervisedEnduranceEnvironment, SupervisedEndurancePlan,
    SupervisedEnduranceProcessStopConfirmation, SupervisedEnduranceSegment,
    SupervisedEnduranceSegmentConfirmation, SystemOwnershipPlatform, TelemetrySampleEvidence,
    WorkloadEvidence, discover_acer_hwmon, parse_compatibility_v1, parse_evidence_v2,
    path_has_extended_acl, run_firmware_auto_baseline, run_read_only_preflight,
    run_supervised_endurance, validate_firmware_auto_baseline_resume,
    validate_qualification_evidence_v2, validate_root_owned_output_destination,
    validate_root_owned_protected_file, write_qualification_record_after_endurance,
    write_root_owned_evidence_atomically,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static NEXT_HARNESS_CGROUP_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static TEST_HARNESS_INVOKE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndurancePlanManifest {
    preflight: PathBuf,
    baselines: Vec<PathBuf>,
    matched_workload_runs: Vec<PathBuf>,
    cpu_calibration: PathBuf,
    gpu_calibration: PathBuf,
    live_lifecycle: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationStagesManifest {
    qualification_envelope: QualificationEnvelopeIdentityV1,
    compatibility: PathBuf,
    config: PathBuf,
    protected_policy: PathBuf,
    qualification_record: PathBuf,
    nvidia_gpu_uuid: String,
    hwmon_root: PathBuf,
    evidence_root: PathBuf,
    minimum_available_bytes: u64,
}

struct StageArguments {
    manifest: PathBuf,
    harness: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessNvmlResponse {
    uuid: Option<String>,
    pci_bus_id: Option<String>,
    temperature_celsius: Option<f64>,
    error_kind: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessBaselineStartingConditions {
    captured_at: EvidenceTimestamp,
    nvidia_gpu_uuid: String,
    ambient_millicelsius: i32,
    cpu_millicelsius: i32,
    gpu_millicelsius: i32,
    power_profile: EvidenceProfile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessBaselineObservation {
    nvidia_gpu_uuid: String,
    sample: TelemetrySampleEvidence,
    system_stable: bool,
    kernel_faults: Vec<String>,
    nvidia_faults: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessQualificationReadiness {
    signing_trust_ready: bool,
    recovery_ready: bool,
    stock_boot_fallback_ready: bool,
    qualification_workload_absent: bool,
}

struct Arguments {
    manifest: PathBuf,
    harness: PathBuf,
    evidence_output: PathBuf,
    qualification_record: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fan-control-qualify: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut values = env::args_os().skip(1);
    let Some(command) = values.next() else {
        println!(
            "fan-control-qualify: {}; run `fan-control-qualify supervised-endurance --help`",
            StartupStatus::UnqualifiedNotConfigured
        );
        return Ok(());
    };
    let remaining = values.collect::<Vec<_>>();
    if command == "validate-records" {
        return validate_records(remaining.into_iter());
    }
    if command == "redact-evidence" {
        return redact_evidence(remaining.into_iter());
    }
    if command == "check-promotion" {
        return check_promotion(remaining.into_iter());
    }
    let command = command
        .into_string()
        .map_err(|_| "qualification command must be UTF-8")?;
    if command == "preflight" {
        return preflight_command(remaining);
    }
    if command == "firmware-auto-baselines" {
        return firmware_auto_baselines_command(remaining);
    }
    if command != "supervised-endurance" {
        return Err(format!("unknown qualification command: {command}").into());
    }
    if remaining.first().is_some_and(|value| value == "--help") {
        println!(
            "usage: fan-control-qualify supervised-endurance --manifest FILE --harness FILE \
             --evidence-output FILE [--qualification-record FILE]"
        );
        return Ok(());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("supervised endurance must run as UID 0".into());
    }
    let remaining = remaining
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| "supervised-endurance arguments must be UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let arguments = parse_arguments(remaining.into_iter())?;
    validate_root_owned_output_destination(&arguments.evidence_output)?;
    validate_root_owned_output_destination(&arguments.qualification_record)?;
    validate_protected_executable(&arguments.harness)?;
    let manifest: EndurancePlanManifest =
        serde_json::from_str(&read_protected_file(&arguments.manifest)?)?;
    let preflight = read_evidence(&manifest.preflight)?;
    let baselines = read_evidence_set(&manifest.baselines)?;
    let matched_runs = read_evidence_set(&manifest.matched_workload_runs)?;
    let cpu_calibration = read_evidence(&manifest.cpu_calibration)?;
    let gpu_calibration = read_evidence(&manifest.gpu_calibration)?;
    let live_lifecycle = read_evidence(&manifest.live_lifecycle)?;
    let baseline_refs = baselines.iter().collect::<Vec<_>>();
    let matched_refs = matched_runs.iter().collect::<Vec<_>>();
    let plan = SupervisedEndurancePlan {
        preflight: &preflight,
        baselines: &baseline_refs,
        matched_workload_runs: &matched_refs,
        tachometer_calibrations: MatchedWorkloadTachometerCalibrations {
            cpu: &cpu_calibration,
            gpu: &gpu_calibration,
        },
        live_lifecycle: &live_lifecycle,
        workload: WorkloadEvidence {
            workload_id: SUPERVISED_ENDURANCE_WORKLOAD_ID.into(),
            command: vec![
                "/usr/lib/pt31553-fan-control/workloads/mixed".into(),
                "--fixed".into(),
            ],
            version: "1.0.0".into(),
            power_profile: EvidenceProfile::Ac,
            ambient_millicelsius: 0,
            starting_cpu_millicelsius: 0,
            starting_gpu_millicelsius: 0,
        },
    };
    let mut environment = HarnessEnvironment::new(arguments.harness)?;
    let report = run_supervised_endurance(&mut environment, &plan)?;
    write_qualification_record_after_endurance(
        &arguments.qualification_record,
        &arguments.evidence_output,
        &plan,
        &report,
    )?;
    println!(
        "supervised endurance passed; authorization published at {}",
        arguments.qualification_record.display()
    );
    Ok(())
}

fn preflight_command(values: Vec<OsString>) -> Result<(), Box<dyn Error>> {
    if values.iter().any(|value| value == "--help") {
        println!("usage: pt31553-fan-qualify preflight --manifest FILE --harness FILE");
        return Ok(());
    }
    require_root("preflight")?;
    let arguments = parse_stage_arguments(values)?;
    validate_protected_executable(&arguments.harness)?;
    let manifest = read_stages_manifest(&arguments.manifest)?;
    let output = manifest.evidence_root.join("preflight.json");
    validate_root_owned_output_destination(&output)?;
    let mut harness = HarnessEnvironment::new(arguments.harness)?;
    harness.select_nvidia_gpu(manifest.nvidia_gpu_uuid.clone());
    let (record, report) = execute_read_only_preflight(&manifest, &harness)?;
    let passed = record.outcome.status == RunOutcomeStatus::Passed;
    write_root_owned_evidence_atomically(&output, &record)?;
    println!("{report}");
    if !passed {
        return Err(format!(
            "preflight failed; evidence: {}; recovery: {}",
            output.display(),
            firmware_auto_recovery(record.outcome.final_firmware_auto_confirmed)
        )
        .into());
    }
    println!(
        "preflight passed; Firmware Auto unchanged; evidence: {}",
        output.display()
    );
    Ok(())
}

fn firmware_auto_baselines_command(values: Vec<OsString>) -> Result<(), Box<dyn Error>> {
    if values.iter().any(|value| value == "--help") {
        println!(
            "usage: pt31553-fan-qualify firmware-auto-baselines --manifest FILE --harness FILE"
        );
        return Ok(());
    }
    require_root("Firmware Auto baselines")?;
    let arguments = parse_stage_arguments(values)?;
    validate_protected_executable(&arguments.harness)?;
    let manifest = read_stages_manifest(&arguments.manifest)?;
    let preflight_path = manifest.evidence_root.join("preflight.json");
    let preflight_source = read_protected_file(&preflight_path)?;
    let preflight = parse_evidence_v2(&preflight_source)?;
    require_matching_recent_preflight(&manifest, &preflight)?;
    let preflight_binding_sha256 = evidence_source_sha256(&preflight_source);

    let mut harness = HarnessEnvironment::new(arguments.harness)?;
    harness.select_nvidia_gpu(manifest.nvidia_gpu_uuid.clone());
    let (current_preflight, current_report) = execute_read_only_preflight(&manifest, &harness)?;
    if current_preflight.outcome.status != RunOutcomeStatus::Passed {
        return Err(format!(
            "baseline start aborted; live preflight no longer passes:\n{current_report}\nrecovery: {}",
            firmware_auto_recovery(current_preflight.outcome.final_firmware_auto_confirmed)
        )
        .into());
    }
    require_same_fan_endpoints(&preflight, &current_preflight)?;
    let expected_fan_endpoint_identities = preflight
        .fan_endpoint_identities
        .clone()
        .ok_or("complete fan endpoint identities are missing from preflight evidence")?;

    let mut platform = SystemOwnershipPlatform::new();
    for (index, spec) in required_baselines().iter().enumerate() {
        let output =
            manifest
                .evidence_root
                .join(format!("{:02}-{}.json", index + 1, spec.workload_id));
        let workload = WorkloadEvidence {
            workload_id: spec.workload_id.into(),
            command: vec![
                format!("/usr/lib/pt31553-fan-control/workloads/{}", spec.workload),
                "--fixed".into(),
            ],
            version: "1.0.0".into(),
            power_profile: spec.profile,
            ambient_millicelsius: 0,
            starting_cpu_millicelsius: 0,
            starting_gpu_millicelsius: 0,
        };
        let plan = FirmwareAutoBaselinePlan {
            hwmon_root: &manifest.hwmon_root,
            qualification_envelope: manifest.qualification_envelope.clone(),
            preflight_binding_sha256: preflight_binding_sha256.clone(),
            nvidia_gpu_uuid: manifest.nvidia_gpu_uuid.clone(),
            expected_fan_endpoint_identities: expected_fan_endpoint_identities.clone(),
            workload,
            samples_required: spec.samples,
        };
        if output.exists() {
            let record = read_evidence(&output)?;
            require_recent_stage(&record, &preflight, spec.workload_id)?;
            validate_firmware_auto_baseline_resume(&mut platform, &record, &plan).map_err(
                |error| {
                    format!(
                        "cannot resume {} from {}: {error}; recovery: preserve the rejected evidence; stop all qualification workloads, shut down immediately, and do not reboot into the candidate kernel until Firmware Auto is independently verified; then start a new protected evidence directory",
                        spec.workload_id,
                        output.display()
                    )
                },
            )?;
            println!("RESUME {}: complete matching evidence", spec.workload_id);
            continue;
        }
        validate_root_owned_output_destination(&output)?;
        let (live_preflight, report) = execute_read_only_preflight(&manifest, &harness)?;
        if live_preflight.outcome.status != RunOutcomeStatus::Passed {
            return Err(format!(
                "{} aborted before workload; live preflight failed:\n{report}\nrecovery: {}",
                spec.workload_id,
                firmware_auto_recovery(live_preflight.outcome.final_firmware_auto_confirmed)
            )
            .into());
        }
        require_same_fan_endpoints(&preflight, &live_preflight)?;
        println!(
            "START {}: Firmware Auto; {} samples at 2 s",
            spec.workload_id, spec.samples
        );
        let report = run_firmware_auto_baseline(&mut platform, &mut harness, &plan)?;
        let accepted = report.accepted();
        let record = report.into_record();
        write_root_owned_evidence_atomically(&output, &record)?;
        if !accepted {
            let recovery = firmware_auto_recovery(record.outcome.final_firmware_auto_confirmed);
            return Err(format!(
                "{} aborted: {}; workload stop/containment status recorded; final Firmware Auto confirmed={}; evidence: {}; recovery: {recovery}",
                spec.workload_id,
                record.outcome.reason,
                record.outcome.final_firmware_auto_confirmed,
                output.display()
            )
            .into());
        }
        println!("PASS {}: {}", spec.workload_id, output.display());
    }
    println!(
        "all seven Firmware Auto baselines passed; no Custom-control write was armed; evidence: {}",
        manifest.evidence_root.display()
    );
    Ok(())
}

fn firmware_auto_recovery(confirmed: bool) -> &'static str {
    if confirmed {
        "keep both fans in Firmware Auto; stop and repair the failed prerequisite; start a new protected evidence directory"
    } else {
        "stop all qualification workloads, shut down immediately, and do not reboot into the candidate kernel until independent Firmware Auto recovery is verified"
    }
}

fn require_root(command: &str) -> Result<(), Box<dyn Error>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(format!("{command} must run as UID 0").into());
    }
    Ok(())
}

fn parse_stage_arguments(values: Vec<OsString>) -> Result<StageArguments, Box<dyn Error>> {
    let values = values
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| "stage arguments must be UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut manifest = None;
    let mut harness = None;
    let mut values = values.into_iter();
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--manifest" if manifest.is_none() => manifest = Some(value.into()),
            "--harness" if harness.is_none() => harness = Some(value.into()),
            "--manifest" | "--harness" => {
                return Err(format!("duplicate argument: {flag}").into());
            }
            _ => return Err(format!("unknown argument: {flag}").into()),
        }
    }
    Ok(StageArguments {
        manifest: manifest.ok_or("--manifest is required")?,
        harness: harness.ok_or("--harness is required")?,
    })
}

fn read_stages_manifest(path: &Path) -> Result<QualificationStagesManifest, Box<dyn Error>> {
    let mut manifest: QualificationStagesManifest =
        serde_json::from_str(&read_protected_file(path)?)?;
    if !manifest.evidence_root.is_absolute() || !manifest.hwmon_root.is_absolute() {
        return Err("manifest hwmon_root and evidence_root must be absolute".into());
    }
    canonicalize_manifest_gpu_uuid(&mut manifest.nvidia_gpu_uuid);
    Ok(manifest)
}

fn canonicalize_manifest_gpu_uuid(uuid: &mut String) {
    if let Ok(selector) = NvidiaGpuSelector::uuid(&*uuid) {
        *uuid = selector.value().to_owned();
    }
}

fn execute_read_only_preflight(
    manifest: &QualificationStagesManifest,
    harness: &HarnessEnvironment,
) -> Result<(EvidenceRecord, String), Box<dyn Error>> {
    let started_at = harness.timestamp_now();
    let protected_inputs = (|| -> Result<_, Box<dyn Error>> {
        let compatibility_source = read_protected_file(&manifest.compatibility)?;
        let compatibility = parse_compatibility_v1(&compatibility_source)?;
        if compatibility != manifest.qualification_envelope.compatibility {
            return Err(
                "manifest envelope does not match the protected compatibility declaration".into(),
            );
        }
        let config = read_protected_file(&manifest.config)?;
        let protected_policy = read_protected_file(&manifest.protected_policy)?;
        let qualification_record = read_protected_file(&manifest.qualification_record)?;
        let selector = NvidiaGpuSelector::uuid(&manifest.nvidia_gpu_uuid)?;
        validate_sandbox_fan_boundary(manifest)?;
        Ok((
            compatibility,
            config,
            protected_policy,
            qualification_record,
            selector,
        ))
    })();
    let (compatibility, config, protected_policy, qualification_record, selector) =
        match protected_inputs {
            Ok(inputs) => inputs,
            Err(error) => {
                return failed_preflight_collection(
                    manifest,
                    harness,
                    started_at,
                    format!("protected preflight input collection failed: {error}"),
                );
            }
        };
    let observations: Vec<CompatibilityObservation> = match harness.invoke(
        "compatibility-observations",
        json!({}),
        harness.deadline(30_000),
    ) {
        Ok(observations) => observations,
        Err(error) => {
            return failed_preflight_collection(
                manifest,
                harness,
                started_at,
                format!("compatibility observation collection failed: {error}"),
            );
        }
    };
    let mut nvml = HarnessNvml { harness };
    let readiness: HarnessQualificationReadiness = match harness.invoke(
        "qualification-readiness",
        json!({}),
        harness.deadline(30_000),
    ) {
        Ok(readiness) => readiness,
        Err(error) => {
            return failed_preflight_collection(
                manifest,
                harness,
                started_at,
                format!("qualification readiness collection failed: {error}"),
            );
        }
    };
    let mut environment = SystemPreflightEnvironment { readiness };
    let mut platform = SystemOwnershipPlatform::new();
    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &compatibility,
            observations: &observations,
            config_source: &config,
            protected_policy_source: &protected_policy,
            qualification_record_source: &qualification_record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: &manifest.hwmon_root,
            evidence_root: &manifest.evidence_root,
            minimum_available_bytes: manifest.minimum_available_bytes,
        },
    );
    let plain = report.to_string();
    let completed_at = harness.timestamp_now();
    let record = report.into_evidence(
        manifest.qualification_envelope.clone(),
        Some(manifest.nvidia_gpu_uuid.clone()),
        started_at,
        completed_at,
    )?;
    Ok((record, plain))
}

fn validate_sandbox_fan_boundary(
    manifest: &QualificationStagesManifest,
) -> Result<(), Box<dyn Error>> {
    let mut platform = SystemOwnershipPlatform::new();
    let device = discover_acer_hwmon(&mut platform, &manifest.hwmon_root)?;
    for endpoint in [
        device.cpu().pwm(),
        device.cpu().enable(),
        device.cpu().tachometer(),
        device.gpu().pwm(),
        device.gpu().enable(),
        device.gpu().tachometer(),
    ] {
        let permissions = platform.permissions(endpoint)?;
        if permissions.owner_uid() != 0
            || permissions.mode() & 0o022 != 0
            || permissions.has_extended_acl()
        {
            return Err(format!(
                "fan endpoint is writable by the harness sandbox: {}",
                endpoint.display()
            )
            .into());
        }
    }
    Ok(())
}

fn failed_preflight_collection(
    manifest: &QualificationStagesManifest,
    harness: &HarnessEnvironment,
    started_at: EvidenceTimestamp,
    detail: String,
) -> Result<(EvidenceRecord, String), Box<dyn Error>> {
    let completed_at = harness.timestamp_now();
    let report = fan_control_core::PreflightReport::collection_failure(completed_at, detail);
    let plain = report.to_string();
    let record = report.into_evidence(
        manifest.qualification_envelope.clone(),
        NvidiaGpuSelector::uuid(&manifest.nvidia_gpu_uuid)
            .ok()
            .map(|selector| selector.value().to_owned()),
        started_at,
        completed_at,
    )?;
    Ok((record, plain))
}

const MAX_RESUME_AGE_MILLIS: i64 = 6 * 60 * 60 * 1_000;

fn require_matching_recent_preflight(
    manifest: &QualificationStagesManifest,
    record: &EvidenceRecord,
) -> Result<(), Box<dyn Error>> {
    if record.stage != "preflight"
        || record.qualification_envelope != manifest.qualification_envelope
        || record.nvidia_gpu_uuid.as_deref() != Some(manifest.nvidia_gpu_uuid.as_str())
        || record.outcome.status != RunOutcomeStatus::Passed
        || record.outcome.another_passing_run_required
    {
        return Err(
            "preflight evidence is incomplete, failed, or belongs to another identity".into(),
        );
    }
    require_fresh_wall_time(record.completed_at.wall_unix_millis, "preflight evidence")?;
    reject_future_evidence_timestamps(record, "preflight evidence")
}

fn require_recent_stage(
    record: &EvidenceRecord,
    preflight: &EvidenceRecord,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    if record.started_at.wall_unix_millis < preflight.completed_at.wall_unix_millis {
        return Err(format!("{label} predates the required preflight").into());
    }
    require_fresh_wall_time(record.completed_at.wall_unix_millis, label)?;
    reject_future_evidence_timestamps(record, label)
}

fn reject_future_evidence_timestamps(
    record: &EvidenceRecord,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let now: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system wall clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .map_err(|_| "system wall clock does not fit evidence timestamps")?;
    let value = serde_json::to_value(record)?;
    let mut timestamps = Vec::new();
    collect_wall_timestamps(&value, &mut timestamps);
    if timestamps.into_iter().any(|timestamp| timestamp > now) {
        return Err(format!("{label} contains a future evidence timestamp").into());
    }
    Ok(())
}

fn collect_wall_timestamps(value: &Value, timestamps: &mut Vec<i64>) {
    match value {
        Value::Object(object) => {
            if object.contains_key("monotonic_millis") {
                if let Some(timestamp) = object.get("wall_unix_millis").and_then(Value::as_i64) {
                    timestamps.push(timestamp);
                }
            }
            object
                .values()
                .for_each(|value| collect_wall_timestamps(value, timestamps));
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_wall_timestamps(value, timestamps)),
        _ => {}
    }
}

fn require_fresh_wall_time(timestamp: i64, label: &str) -> Result<(), Box<dyn Error>> {
    let now: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system wall clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .map_err(|_| "system wall clock does not fit evidence timestamps")?;
    let age = now
        .checked_sub(timestamp)
        .ok_or_else(|| format!("{label} timestamp is in the future"))?;
    if age > MAX_RESUME_AGE_MILLIS {
        return Err(format!("{label} is stale; start a new evidence session").into());
    }
    Ok(())
}

fn require_same_fan_endpoints(
    expected: &EvidenceRecord,
    current: &EvidenceRecord,
) -> Result<(), Box<dyn Error>> {
    let Some(expected_identities) = &expected.fan_endpoint_identities else {
        return Err("complete fan endpoint identities are missing from preflight evidence".into());
    };
    if current.fan_endpoint_identities.as_ref() != Some(expected_identities) {
        return Err(
            "fan endpoint identity changed since preflight; start a new evidence session".into(),
        );
    }
    Ok(())
}

struct BaselineSpec {
    workload_id: &'static str,
    workload: &'static str,
    profile: EvidenceProfile,
    samples: usize,
}

fn required_baselines() -> [BaselineSpec; 7] {
    [
        BaselineSpec {
            workload_id: "idle-ac-v1",
            workload: "idle",
            profile: EvidenceProfile::Ac,
            samples: 300,
        },
        BaselineSpec {
            workload_id: "cpu-ac-v1",
            workload: "cpu",
            profile: EvidenceProfile::Ac,
            samples: 600,
        },
        BaselineSpec {
            workload_id: "gpu-ac-v1",
            workload: "gpu",
            profile: EvidenceProfile::Ac,
            samples: 600,
        },
        BaselineSpec {
            workload_id: "combined-ac-v1",
            workload: "combined",
            profile: EvidenceProfile::Ac,
            samples: 900,
        },
        BaselineSpec {
            workload_id: "idle-battery-v1",
            workload: "idle",
            profile: EvidenceProfile::Battery,
            samples: 300,
        },
        BaselineSpec {
            workload_id: "cpu-battery-v1",
            workload: "cpu",
            profile: EvidenceProfile::Battery,
            samples: 300,
        },
        BaselineSpec {
            workload_id: "gpu-battery-v1",
            workload: "gpu",
            profile: EvidenceProfile::Battery,
            samples: 300,
        },
    ]
}

fn redact_evidence(values: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let values = values.collect::<Vec<_>>();
    if values.iter().any(|value| value == "--help") {
        println!(
            "usage: fan-control-qualify redact-evidence --qualification-record FILE \
             --evidence FILE --authorized-evidence-path FILE --output FILE"
        );
        return Ok(());
    }
    let mut io = fan_control_qualify::RootProtectedArtifactIo;
    let output = fan_control_qualify::redact_evidence_command(values.into_iter(), &mut io)?;
    println!(
        "sanitized qualification evidence published at {}",
        output.display()
    );
    Ok(())
}

fn check_promotion(values: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let values = values.collect::<Vec<_>>();
    if values.iter().any(|value| value == "--help") {
        println!(
            "usage: fan-control-qualify check-promotion --manifest FILE \
             --qualification-record FILE --evidence FILE \
             --authorized-evidence-path FILE --sanitized-evidence FILE \
             --protected-policy FILE --package-provenance FILE \
             --controller-package FILE --controller-signature FILE \
             --package-manifest-signature FILE --output FILE"
        );
        return Ok(());
    }
    let mut io = fan_control_qualify::RootProtectedArtifactIo;
    let output = fan_control_qualify::check_promotion_command(values.into_iter(), &mut io)?;
    println!(
        "qualified promotion manifest published at {}",
        output.display()
    );
    Ok(())
}

fn validate_records(mut values: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut qualification_record = None;
    let mut evidence = None;
    let mut authorized_evidence_path = None;
    while let Some(flag) = values.next() {
        if flag == "--help" {
            println!(
                "usage: fan-control-qualify validate-records --qualification-record FILE \
                 --evidence FILE [--authorized-evidence-path FILE]"
            );
            return Ok(());
        }
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {}", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--qualification-record") => qualification_record = Some(PathBuf::from(value)),
            Some("--evidence") => evidence = Some(PathBuf::from(value)),
            Some("--authorized-evidence-path") => {
                authorized_evidence_path = Some(PathBuf::from(value));
            }
            Some(flag) => return Err(format!("unknown argument: {flag}").into()),
            None => return Err("validate-records argument flags must be UTF-8".into()),
        }
    }
    let qualification_record = qualification_record.ok_or("--qualification-record is required")?;
    let evidence = evidence.ok_or("--evidence is required")?;
    let authorized_evidence_path = authorized_evidence_path.unwrap_or_else(|| evidence.clone());
    let qualification_source = std::fs::read_to_string(&qualification_record)?;
    let evidence_source = std::fs::read_to_string(&evidence)?;
    validate_qualification_evidence_v2(
        &qualification_source,
        &evidence_source,
        &authorized_evidence_path,
    )?;
    println!("qualification and supervised endurance records are valid");
    Ok(())
}

fn parse_arguments(mut values: impl Iterator<Item = String>) -> Result<Arguments, Box<dyn Error>> {
    let mut manifest = None;
    let mut harness = None;
    let mut evidence_output = None;
    let mut qualification_record = PathBuf::from(QUALIFICATION_RECORD_PATH);
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--manifest" => manifest = Some(value.into()),
            "--harness" => harness = Some(value.into()),
            "--evidence-output" => evidence_output = Some(value.into()),
            "--qualification-record" => qualification_record = value.into(),
            _ => return Err(format!("unknown argument: {flag}").into()),
        }
    }
    Ok(Arguments {
        manifest: manifest.ok_or("--manifest is required")?,
        harness: harness.ok_or("--harness is required")?,
        evidence_output: evidence_output.ok_or("--evidence-output is required")?,
        qualification_record,
    })
}

fn read_evidence(path: &Path) -> Result<EvidenceRecord, Box<dyn Error>> {
    Ok(parse_evidence_v2(&read_protected_file(path)?)?)
}

fn evidence_source_sha256(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
}

fn read_evidence_set(paths: &[PathBuf]) -> Result<Vec<EvidenceRecord>, Box<dyn Error>> {
    paths.iter().map(|path| read_evidence(path)).collect()
}

fn read_protected_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut platform = SystemOwnershipPlatform::new();
    Ok(platform.read_root_owned_qualification_record(path)?)
}

fn validate_protected_executable(path: &Path) -> Result<(), Box<dyn Error>> {
    validate_root_owned_protected_file(path, ProtectedFileRequirement::Executable)?;
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        if std::fs::metadata(ancestor)?.permissions().mode() & 0o001 == 0 {
            return Err(format!(
                "protected harness ancestor is not traversable by its sandbox UID: {}",
                ancestor.display()
            )
            .into());
        }
    }
    if std::fs::metadata(path)?.permissions().mode() & 0o005 != 0o005 {
        return Err("protected harness must be readable and executable by its sandbox UID".into());
    }
    Ok(())
}

struct HarnessEnvironment {
    harness: PathBuf,
    cgroup: Option<HarnessCgroup>,
    nvidia_gpu_uuid: Option<String>,
}

impl HarnessEnvironment {
    fn new(harness: PathBuf) -> std::io::Result<Self> {
        let cgroup = (unsafe { libc::geteuid() } == 0)
            .then(HarnessCgroup::create)
            .transpose()?;
        Ok(Self {
            harness,
            cgroup,
            nvidia_gpu_uuid: None,
        })
    }

    fn select_nvidia_gpu(&mut self, uuid: String) {
        self.nvidia_gpu_uuid = Some(uuid);
    }

    fn selected_nvidia_gpu(&self) -> Result<&str, String> {
        self.nvidia_gpu_uuid
            .as_deref()
            .ok_or_else(|| "qualification NVIDIA GPU identity is not selected".into())
    }

    fn now_millis(&self) -> u64 {
        system_monotonic_millis()
    }

    fn deadline(&self, budget_millis: u64) -> u64 {
        self.now_millis().saturating_add(budget_millis)
    }

    fn timestamp_now(&self) -> EvidenceTimestamp {
        system_timestamp()
    }

    fn wait_until_deadline(&self, target: u64, deadline: u64) -> Result<(), String> {
        let now = self.now_millis();
        let delay = wait_delay_millis(now, target, deadline)?;
        if delay > 0 {
            thread::sleep(Duration::from_millis(delay));
        }
        (self.now_millis() <= deadline)
            .then_some(())
            .ok_or_else(|| "wait exceeded deadline".into())
    }

    fn invoke<T: DeserializeOwned>(
        &self,
        operation: &str,
        request: Value,
        deadline: u64,
    ) -> Result<T, String> {
        #[cfg(test)]
        let _test_harness_guard = TEST_HARNESS_INVOKE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.now_millis() >= deadline {
            return Err(format!("{operation} deadline expired before launch"));
        }
        let mut command = Command::new(&self.harness);
        command
            .arg(operation)
            .arg(deadline.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        sandbox_harness_if_privileged(
            &mut command,
            self.cgroup
                .as_ref()
                .map(|cgroup| cgroup.processes_path.clone()),
        );
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot launch {operation}: {error}"))?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| format!("cannot open {operation} input"))
            .and_then(|mut input| {
                input
                    .write_all(request.to_string().as_bytes())
                    .map_err(|error| format!("cannot write {operation} input: {error}"))
            });
        if let Err(error) = write_result {
            return Err(self.terminate_process_tree(&mut child, error));
        }

        const MAX_HARNESS_OUTPUT_BYTES: u64 = 1024 * 1024;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("cannot open {operation} output"))?;
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut output = Vec::new();
            let result = stdout
                .take(MAX_HARNESS_OUTPUT_BYTES + 1)
                .read_to_end(&mut output)
                .map(|_| output)
                .map_err(|error| error.to_string());
            let _ = sender.send(result);
        });

        let mut status = None;
        let mut output = None;
        loop {
            if status.is_none() {
                status = match child.try_wait() {
                    Ok(status) => status,
                    Err(error) => {
                        return Err(self.terminate_process_tree(
                            &mut child,
                            format!("cannot wait for {operation}: {error}"),
                        ));
                    }
                };
                if status.is_some_and(|status| !status.success()) {
                    return Err(self.terminate_process_tree(
                        &mut child,
                        format!("{operation} exited with {}", status.unwrap()),
                    ));
                }
            }
            if output.is_none() {
                match receiver.try_recv() {
                    Ok(Ok(result)) => output = Some(result),
                    Ok(Err(error)) => {
                        return Err(self.terminate_process_tree(
                            &mut child,
                            format!("cannot read {operation} output: {error}"),
                        ));
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err(self.terminate_process_tree(
                            &mut child,
                            format!("cannot read {operation} output"),
                        ));
                    }
                }
            }
            if status.is_some() && output.is_some() {
                break;
            }
            if self.now_millis() >= deadline {
                return Err(self.terminate_process_tree(
                    &mut child,
                    format!("{operation} exceeded its absolute deadline"),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = output.expect("checked above");
        if output.len() as u64 > MAX_HARNESS_OUTPUT_BYTES {
            return Err(self.terminate_process_tree(
                &mut child,
                format!("{operation} response exceeds 1 MiB"),
            ));
        }
        serde_json::from_slice(&output).map_err(|error| {
            self.terminate_process_tree(
                &mut child,
                format!("invalid {operation} response: {error}"),
            )
        })
    }

    fn terminate_process_tree(&self, child: &mut std::process::Child, error: String) -> String {
        let containment_error = self.cgroup.as_ref().and_then(|cgroup| {
            cgroup
                .kill_all()
                .err()
                .map(|error| (cgroup.root.display().to_string(), error))
        });
        terminate_process_group(child);
        match containment_error {
            Some((cgroup, containment_error)) => format!(
                "{error}; CRITICAL: harness cgroup containment failed for {cgroup}: {containment_error}; recovery: stop qualification and kill every process in that cgroup"
            ),
            None => error,
        }
    }
}

fn wait_delay_millis(now: u64, target: u64, deadline: u64) -> Result<u64, String> {
    if target > deadline {
        return Err("wait target exceeds deadline".into());
    }
    if now > deadline {
        return Err("wait exceeded deadline".into());
    }
    Ok(target.saturating_sub(now))
}

struct HarnessCgroup {
    root: PathBuf,
    processes_path: CString,
}

impl HarnessCgroup {
    fn create() -> std::io::Result<Self> {
        let cgroup_root = Path::new("/sys/fs/cgroup");
        if !cgroup_root.join("cgroup.controllers").is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cgroup v2 is required for root qualification harness containment",
            ));
        }
        let root = cgroup_root.join(format!(
            "pt31553-fan-qualify-{}-{}",
            std::process::id(),
            NEXT_HARNESS_CGROUP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        if !root.join("cgroup.kill").is_file() {
            let _ = fs::remove_dir(&root);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cgroup.kill is required for qualification harness containment",
            ));
        }
        let processes_path = CString::new(root.join("cgroup.procs").as_os_str().as_bytes())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "cgroup path contains an interior NUL",
                )
            })?;
        Ok(Self {
            root,
            processes_path,
        })
    }

    fn kill_all(&self) -> std::io::Result<()> {
        fs::write(self.root.join("cgroup.kill"), b"1")
    }
}

impl Drop for HarnessCgroup {
    fn drop(&mut self) {
        let _ = self.kill_all();
        for _ in 0..100 {
            match fs::remove_dir(&self.root) {
                Ok(()) => break,
                Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    }
}

fn sandbox_harness_if_privileged(command: &mut Command, cgroup_procs: Option<CString>) {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    // The harness needs read access to system identity/telemetry and workload devices, never root
    // fan-control authority. Linux's overflow IDs are deliberately fixed and have no host files.
    unsafe {
        command.pre_exec(move || {
            let Some(cgroup_procs) = &cgroup_procs else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "root harness execution requires cgroup containment",
                ));
            };
            let file = libc::open(cgroup_procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if file < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let moved = libc::write(file, c"0".as_ptr().cast(), 1);
            let move_error = (moved != 1).then(std::io::Error::last_os_error);
            let close_error = (libc::close(file) != 0).then(std::io::Error::last_os_error);
            if let Some(error) = move_error.or(close_error) {
                return Err(error);
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(65_534) != 0
                || libc::setuid(65_534) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn system_monotonic_millis() -> u64 {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `timestamp` points to writable storage and CLOCK_MONOTONIC is process-independent.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, timestamp.as_mut_ptr()) } != 0 {
        return u64::MAX;
    }
    // SAFETY: a successful clock_gettime initialized `timestamp`.
    let timestamp = unsafe { timestamp.assume_init() };
    u64::try_from(timestamp.tv_sec)
        .unwrap_or(u64::MAX)
        .saturating_mul(1_000)
        .saturating_add(u64::try_from(timestamp.tv_nsec).unwrap_or(u64::MAX) / 1_000_000)
}

fn system_timestamp() -> EvidenceTimestamp {
    EvidenceTimestamp {
        monotonic_millis: system_monotonic_millis(),
        wall_unix_millis: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(i64::MAX),
    }
}

fn terminate_process_group(child: &mut std::process::Child) {
    if let Ok(process_group) = i32::try_from(child.id()) {
        // SAFETY: the child was created as leader of this process group; SIGKILL is fail-closed.
        let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

struct HarnessNvml<'a> {
    harness: &'a HarnessEnvironment,
}

impl NvmlAccess for HarnessNvml<'_> {
    fn sample_by_identity(
        &mut self,
        selector: &NvidiaGpuSelector,
    ) -> Result<NvmlGpuSample, NvmlError> {
        let response: HarnessNvmlResponse = self
            .harness
            .invoke(
                "sample-nvidia",
                json!({ "uuid": selector.value() }),
                self.harness.deadline(5_000),
            )
            .map_err(|error| NvmlError::new(NvmlErrorKind::LibraryFailure, error))?;
        match (
            response.error_kind,
            response.error,
            response.uuid,
            response.pci_bus_id,
            response.temperature_celsius,
        ) {
            (Some(error_kind), Some(error), None, None, None) => {
                let kind = match error_kind.as_str() {
                    "reset-required" => NvmlErrorKind::ResetRequired,
                    "gpu-lost" => NvmlErrorKind::GpuLost,
                    "no-data" => NvmlErrorKind::NoData,
                    "not-ready" => NvmlErrorKind::NotReady,
                    "timed-out" => NvmlErrorKind::TimedOut,
                    "invalid-state" => NvmlErrorKind::InvalidState,
                    "unsupported" => NvmlErrorKind::Unsupported,
                    "library-failure" => NvmlErrorKind::LibraryFailure,
                    _ => NvmlErrorKind::Other,
                };
                Err(NvmlError::new(kind, error))
            }
            (None, None, Some(uuid), Some(pci_bus_id), Some(temperature_celsius)) => {
                Ok(NvmlGpuSample::new(uuid, pci_bus_id, temperature_celsius))
            }
            _ => Err(NvmlError::new(
                NvmlErrorKind::NoData,
                "malformed NVIDIA response: expected either complete telemetry or error_kind plus error",
            )),
        }
    }
}

struct SystemPreflightEnvironment {
    readiness: HarnessQualificationReadiness,
}

impl PreflightEnvironment for SystemPreflightEnvironment {
    fn timestamp_now(&mut self) -> EvidenceTimestamp {
        system_timestamp()
    }

    fn signing_trust_is_ready(&mut self) -> Result<bool, PlatformError> {
        Ok(self.readiness.signing_trust_ready)
    }

    fn recovery_is_ready(&mut self) -> Result<bool, PlatformError> {
        Ok(self.readiness.recovery_ready)
    }

    fn stock_boot_fallback_is_ready(&mut self) -> Result<bool, PlatformError> {
        Ok(self.readiness.stock_boot_fallback_ready)
    }

    fn qualification_workload_is_absent(&mut self) -> Result<bool, PlatformError> {
        Ok(self.readiness.qualification_workload_absent)
    }

    fn artifact_is_ready(&mut self, artifact: PreflightArtifact) -> Result<bool, PlatformError> {
        let path = Path::new(artifact.path());
        match artifact {
            PreflightArtifact::QualificationTool
            | PreflightArtifact::RestorationTool
            | PreflightArtifact::Daemon => {
                validate_root_owned_protected_file(path, ProtectedFileRequirement::Executable)
            }
            PreflightArtifact::DaemonServiceUnit | PreflightArtifact::SleepGuardServiceUnit => {
                validate_root_owned_protected_file(path, ProtectedFileRequirement::Regular)
            }
            PreflightArtifact::Journald => validate_root_owned_socket(path),
        }
        .map(|()| true)
        .or_else(|error| match error.kind() {
            PlatformErrorKind::Unavailable | PlatformErrorKind::PermissionDenied => Ok(false),
            _ => Err(error),
        })
    }

    fn available_bytes(&mut self, path: &Path) -> Result<u64, PlatformError> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            PlatformError::new(
                PlatformErrorKind::Unavailable,
                "disk path contains a NUL byte",
            )
        })?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `path` is NUL-terminated and `stats` points to writable storage.
        if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("statvfs failed: {}", std::io::Error::last_os_error()),
            ));
        }
        // SAFETY: successful statvfs initialized the structure.
        let stats = unsafe { stats.assume_init() };
        Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
    }
}

fn validate_root_owned_socket(path: &Path) -> Result<(), PlatformError> {
    validate_owned_socket(path, 0)
}

fn validate_owned_socket(path: &Path, required_owner: u32) -> Result<(), PlatformError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|error| platform_io_error(&current, error))?;
        let has_extended_acl =
            path_has_extended_acl(&current).map_err(|error| platform_io_error(&current, error))?;
        let leaf = current == path;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != required_owner)
            || (!leaf && metadata.permissions().mode() & 0o022 != 0)
            || has_extended_acl
        {
            return Err(PlatformError::new(
                PlatformErrorKind::PermissionDenied,
                format!("unprotected artifact path: {}", current.display()),
            ));
        }
        if leaf && !metadata.file_type().is_socket() {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("artifact is not a socket: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn platform_io_error(path: &Path, error: std::io::Error) -> PlatformError {
    let kind = match error.kind() {
        std::io::ErrorKind::NotFound => PlatformErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => PlatformErrorKind::PermissionDenied,
        _ => PlatformErrorKind::Unavailable,
    };
    PlatformError::new(kind, format!("cannot inspect {}: {error}", path.display()))
}

impl FirmwareAutoBaselineEnvironment for HarnessEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        self.timestamp_now()
    }

    fn capture_starting_conditions(
        &mut self,
    ) -> Result<CapturedBaselineStartingConditions, String> {
        let nvidia_gpu_uuid = self.selected_nvidia_gpu()?;
        let response: HarnessBaselineStartingConditions = self.invoke(
            "capture-baseline-starting-conditions",
            json!({ "nvidia_gpu_uuid": nvidia_gpu_uuid }),
            self.deadline(5_000),
        )?;
        if response.nvidia_gpu_uuid != nvidia_gpu_uuid {
            return Err("baseline starting conditions belong to a different NVIDIA GPU".into());
        }
        Ok(CapturedBaselineStartingConditions {
            conditions: BaselineStartingConditions {
                ambient_millicelsius: response.ambient_millicelsius,
                cpu_millicelsius: response.cpu_millicelsius,
                gpu_millicelsius: response.gpu_millicelsius,
                power_profile: response.power_profile,
            },
            captured_at: response.captured_at,
        })
    }

    fn start_workload(
        &mut self,
        workload: &WorkloadEvidence,
        deadline_monotonic_millis: u64,
    ) -> Result<EvidenceTimestamp, String> {
        self.invoke(
            "start-baseline-workload",
            json!({ "workload": workload }),
            deadline_monotonic_millis,
        )
    }

    fn wait_until(
        &mut self,
        target_monotonic_millis: u64,
        deadline_monotonic_millis: u64,
    ) -> Result<(), String> {
        self.wait_until_deadline(target_monotonic_millis, deadline_monotonic_millis)
    }

    fn capture_observation(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<BaselineObservation, String> {
        let nvidia_gpu_uuid = self.selected_nvidia_gpu()?;
        let response: HarnessBaselineObservation = self.invoke(
            "capture-baseline-observation",
            json!({ "nvidia_gpu_uuid": nvidia_gpu_uuid }),
            deadline_monotonic_millis,
        )?;
        if response.nvidia_gpu_uuid != nvidia_gpu_uuid {
            return Err("baseline observation belongs to a different NVIDIA GPU".into());
        }
        Ok(BaselineObservation {
            sample: response.sample,
            system_stable: response.system_stable,
            kernel_faults: response.kernel_faults,
            nvidia_faults: response.nvidia_faults,
        })
    }

    fn stop_workload(&mut self, deadline_monotonic_millis: u64) -> Result<(), String> {
        self.invoke::<Value>(
            "stop-baseline-workload",
            json!({}),
            deadline_monotonic_millis,
        )
        .map(|_| ())
    }

    fn contain_workload(&mut self, deadline_monotonic_millis: u64) -> Result<(), String> {
        self.invoke::<Value>(
            "contain-baseline-workload",
            json!({}),
            deadline_monotonic_millis,
        )
        .map(|_| ())
    }

    fn cleanup_after_workload(&mut self) -> Result<BaselineCleanupAttestation, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            fan_control_write_count: u64,
        }
        let response: Response =
            self.invoke("cleanup-baseline-workload", json!({}), self.deadline(5_000))?;
        Ok(BaselineCleanupAttestation {
            fan_control_write_count: response.fan_control_write_count,
        })
    }
}

impl SupervisedEnduranceEnvironment for HarnessEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        self.timestamp_now()
    }

    fn capture_starting_conditions(
        &mut self,
        deadline: u64,
    ) -> Result<CapturedMatchedWorkloadStartingConditions, String> {
        self.invoke("capture-starting-conditions", json!({}), deadline)
    }

    fn enter_custom_control(&mut self, deadline: u64) -> Result<(), String> {
        self.invoke::<Value>("enter-custom-control", json!({}), deadline)
            .map(|_| ())
    }

    fn begin_segment(
        &mut self,
        segment: SupervisedEnduranceSegment,
        deadline: u64,
    ) -> Result<SupervisedEnduranceSegmentConfirmation, String> {
        self.invoke(
            "begin-segment",
            json!({
                "id": segment.id,
                "power_profile": segment.power_profile,
                "load": segment.load,
                "duration_millis": segment.duration_millis
            }),
            deadline,
        )
    }

    fn start_workload(
        &mut self,
        workload: &WorkloadEvidence,
        deadline: u64,
    ) -> Result<EvidenceTimestamp, String> {
        self.invoke("start-workload", json!({ "workload": workload }), deadline)
    }

    fn wait_until(&mut self, target: u64, deadline: u64) -> Result<(), String> {
        self.wait_until_deadline(target, deadline)
    }

    fn capture_observation(&mut self, deadline: u64) -> Result<MatchedWorkloadObservation, String> {
        self.invoke("capture-observation", json!({}), deadline)
    }

    fn stop_workload(
        &mut self,
        deadline: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.invoke("stop-workload", json!({}), deadline)
    }

    fn contain_workload(
        &mut self,
        deadline: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.invoke("contain-workload", json!({}), deadline)
    }

    fn force_contain_workload(
        &mut self,
        deadline: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.invoke("force-contain-workload", json!({}), deadline)
    }

    fn stop_service(
        &mut self,
        deadline: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.invoke("stop-service", json!({}), deadline)
    }

    fn contain_service(
        &mut self,
        deadline: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.invoke("contain-service", json!({}), deadline)
    }

    fn force_contain_service(
        &mut self,
        deadline: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.invoke("force-contain-service", json!({}), deadline)
    }

    fn restore_fan(&mut self, fan: EvidenceFan, deadline: u64) -> MatchedWorkloadFanRestoration {
        self.invoke("restore-fan", json!({ "fan": fan }), deadline)
            .unwrap_or(MatchedWorkloadFanRestoration {
                auto_write_succeeded: false,
                enable_readback: None,
                endpoint_identity: "unavailable".into(),
                outcome: RestorationOutcome::ContainmentFailed,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::CString,
        fs::{self, OpenOptions},
        io::Write,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt, net::UnixListener},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_HARNESS_ID: AtomicU64 = AtomicU64::new(0);

    fn set_default_acl(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let acl: [u8; 28] = [
            2, 0, 0, 0, // version
            1, 0, 7, 0, 255, 255, 255, 255, // user::rwx
            4, 0, 5, 0, 255, 255, 255, 255, // group::r-x
            32, 0, 5, 0, 255, 255, 255, 255, // other::r-x
        ];
        // SAFETY: both names are NUL-terminated and acl is valid for its byte length.
        let result = unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"system.posix_acl_default".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        assert_eq!(
            result,
            0,
            "cannot create default ACL: {}",
            std::io::Error::last_os_error()
        );
    }

    fn set_access_acl(path: &Path, named_uid: u32) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut acl = vec![
            2, 0, 0, 0, // version
            1, 0, 7, 0, 255, 255, 255, 255, // user::rwx
            2, 0, 7, 0, // user:<uid>:rwx
        ];
        acl.extend(named_uid.to_le_bytes());
        acl.extend([
            4, 0, 5, 0, 255, 255, 255, 255, // group::r-x
            16, 0, 7, 0, 255, 255, 255, 255, // mask::rwx
            32, 0, 5, 0, 255, 255, 255, 255, // other::r-x
        ]);
        // SAFETY: both names are NUL-terminated and acl is valid for its byte length.
        let result = unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        assert_eq!(
            result,
            0,
            "cannot create access ACL: {}",
            std::io::Error::last_os_error()
        );
    }

    struct TestHarness {
        root: PathBuf,
        path: PathBuf,
    }

    impl TestHarness {
        fn new(body: &str) -> Self {
            let root = env::temp_dir().join(format!(
                "fan-control-qualify-harness-{}-{}",
                process::id(),
                NEXT_HARNESS_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let path = root.join("harness");
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .unwrap();
            file.write_all(format!("#!/bin/sh\nset -eu\n{body}\n").as_bytes())
                .unwrap();
            file.sync_all().unwrap();
            drop(file);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            Self { root, path }
        }
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn manifest_gpu_uuid_is_canonicalized_before_stage_use() {
        let mut uuid = "GPU-AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".to_owned();
        canonicalize_manifest_gpu_uuid(&mut uuid);
        assert_eq!(uuid, "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    }

    #[test]
    fn unix_socket_validation_rejects_default_acl_ancestors() {
        let owner = unsafe { libc::geteuid() };
        let root = Path::new("target").join(format!(
            "fc-socket-acl-{}-{}",
            process::id(),
            NEXT_HARNESS_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("journal.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        set_default_acl(&root);

        assert!(matches!(
            validate_owned_socket(&socket, owner),
            Err(error) if error.kind() == PlatformErrorKind::PermissionDenied
        ));
        let root_name = CString::new(root.as_os_str().as_bytes()).unwrap();
        // SAFETY: both names are NUL-terminated.
        assert_eq!(
            unsafe { libc::removexattr(root_name.as_ptr(), c"system.posix_acl_default".as_ptr()) },
            0
        );
        set_access_acl(&socket, owner);
        assert!(matches!(
            validate_owned_socket(&socket, owner),
            Err(error) if error.kind() == PlatformErrorKind::PermissionDenied
        ));

        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn harness_deadline_uses_the_linux_boot_monotonic_clock() {
        let script = TestHarness::new(
            r#"now=$(awk '{printf "%.0f", $1 * 1000}' /proc/uptime)
test "$2" -gt "$now"
printf '{"deadline":%s}' "$2""#,
        );
        let harness = HarnessEnvironment::new(script.path.clone()).unwrap();
        let deadline = harness.deadline(5_000);
        let response: Value = harness.invoke("clock", json!({}), deadline).unwrap();
        assert_eq!(response["deadline"].as_u64(), Some(deadline));
    }

    #[test]
    fn inherited_stdout_descendant_cannot_bypass_the_deadline() {
        let script = TestHarness::new("(sleep 60) &\nprintf '{\"ok\":true}'");
        let harness = HarnessEnvironment::new(script.path.clone()).unwrap();
        let started = system_monotonic_millis();
        let error = harness
            .invoke::<Value>("hang", json!({}), harness.deadline(500))
            .unwrap_err();
        assert!(error.contains("exceeded its absolute deadline"), "{error}");
        assert!(system_monotonic_millis().saturating_sub(started) < 2_000);
    }

    #[test]
    fn harness_stderr_is_discarded_without_blocking_or_flooding_the_parent() {
        let script = TestHarness::new("head -c 2097152 /dev/zero >&2\nprintf '{\"ok\":true}'");
        let harness = HarnessEnvironment::new(script.path.clone()).unwrap();
        let response: Value = harness
            .invoke("stderr", json!({}), harness.deadline(5_000))
            .unwrap();
        assert_eq!(response, json!({"ok": true}));
    }

    #[test]
    fn malformed_response_kills_a_surviving_descendant() {
        let marker = env::temp_dir().join(format!(
            "fan-control-qualify-child-{}-{}",
            process::id(),
            NEXT_HARNESS_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let script = TestHarness::new(&format!(
            "sleep 60 >/dev/null 2>&1 &\nprintf '%s' \"$!\" > {}\nprintf 'not-json'",
            marker.display()
        ));
        let harness = HarnessEnvironment::new(script.path.clone()).unwrap();
        let error = harness
            .invoke::<Value>("malformed", json!({}), harness.deadline(5_000))
            .unwrap_err();
        assert!(error.contains("invalid malformed response"), "{error}");
        let pid: i32 = fs::read_to_string(&marker).unwrap().parse().unwrap();
        let mut absent = false;
        for _ in 0..100 {
            if unsafe { libc::kill(pid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                absent = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = fs::remove_file(marker);
        assert!(absent, "malformed-response descendant remained alive");
    }

    #[test]
    fn firmware_auto_matrix_is_fixed_and_complete() {
        let baselines = required_baselines();
        assert_eq!(
            baselines
                .iter()
                .map(|spec| (spec.workload_id, spec.profile, spec.samples))
                .collect::<Vec<_>>(),
            vec![
                ("idle-ac-v1", EvidenceProfile::Ac, 300),
                ("cpu-ac-v1", EvidenceProfile::Ac, 600),
                ("gpu-ac-v1", EvidenceProfile::Ac, 600),
                ("combined-ac-v1", EvidenceProfile::Ac, 900),
                ("idle-battery-v1", EvidenceProfile::Battery, 300),
                ("cpu-battery-v1", EvidenceProfile::Battery, 300),
                ("gpu-battery-v1", EvidenceProfile::Battery, 300),
            ]
        );
    }

    #[test]
    fn privileged_runner_executes_the_harness_without_root_authority() {
        let script = TestHarness::new("printf '{\"uid\":%s}' \"$(id -u)\"");
        let harness = HarnessEnvironment::new(script.path.clone()).unwrap();
        let response: Value = harness
            .invoke("identity", json!({}), harness.deadline(5_000))
            .unwrap();
        let expected = if unsafe { libc::geteuid() } == 0 {
            65_534
        } else {
            u64::from(unsafe { libc::geteuid() })
        };
        assert_eq!(response["uid"].as_u64(), Some(expected));
    }

    #[test]
    fn nvidia_error_kind_cannot_be_hidden_beside_telemetry() {
        let script = TestHarness::new(
            r#"printf '%s' '{"error_kind":"reset-required","uuid":"GPU-a","pci_bus_id":"0000:01:00.0","temperature_celsius":50}'"#,
        );
        let harness = HarnessEnvironment::new(script.path.clone()).unwrap();
        let selector = NvidiaGpuSelector::uuid("GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let error = HarnessNvml { harness: &harness }
            .sample_by_identity(&selector)
            .unwrap_err();
        assert_eq!(error.kind(), NvmlErrorKind::NoData, "{error}");
    }

    #[test]
    fn baseline_collection_rejects_a_different_nvidia_gpu_identity() {
        let script = TestHarness::new(
            r#"request=$(cat)
case "$request" in *GPU-selected*) ;; *) exit 9 ;; esac
printf '%s' '{"captured_at":{"monotonic_millis":1,"wall_unix_millis":1},"nvidia_gpu_uuid":"GPU-other","ambient_millicelsius":24000,"cpu_millicelsius":42000,"gpu_millicelsius":39000,"power_profile":"ac"}'"#,
        );
        let mut harness = HarnessEnvironment::new(script.path.clone()).unwrap();
        harness.select_nvidia_gpu("GPU-selected".into());
        let error =
            FirmwareAutoBaselineEnvironment::capture_starting_conditions(&mut harness).unwrap_err();
        assert!(error.contains("different NVIDIA GPU"));
    }

    #[test]
    fn preflight_binding_hashes_exact_file_bytes() {
        assert_ne!(
            evidence_source_sha256("{\"schema_version\":2}"),
            evidence_source_sha256("{\n  \"schema_version\": 2\n}\n")
        );
    }

    #[test]
    fn nested_future_evidence_timestamps_are_discovered() {
        let value = json!({
            "completed_at": { "monotonic_millis": 10, "wall_unix_millis": 100 },
            "samples": [{ "timestamp": { "monotonic_millis": 5, "wall_unix_millis": 999 } }]
        });
        let mut timestamps = Vec::new();
        collect_wall_timestamps(&value, &mut timestamps);
        assert_eq!(timestamps, vec![100, 999]);
    }

    #[test]
    fn wait_deadline_boundaries_are_overflow_safe_for_both_stage_adapters() {
        assert_eq!(wait_delay_millis(10, 10, 10), Ok(0));
        assert_eq!(
            wait_delay_millis(11, 10, 10),
            Err("wait exceeded deadline".into())
        );
        assert_eq!(
            wait_delay_millis(10, 12, 11),
            Err("wait target exceeds deadline".into())
        );
        assert_eq!(wait_delay_millis(u64::MAX, u64::MAX, u64::MAX), Ok(0));

        let mut baseline = HarnessEnvironment::new(PathBuf::from("/unused")).unwrap();
        assert!(
            FirmwareAutoBaselineEnvironment::wait_until(&mut baseline, u64::MAX, u64::MAX - 1)
                .is_err()
        );
        let mut endurance = HarnessEnvironment::new(PathBuf::from("/unused")).unwrap();
        assert!(
            SupervisedEnduranceEnvironment::wait_until(&mut endurance, u64::MAX, u64::MAX - 1,)
                .is_err()
        );
    }

    #[test]
    fn firmware_auto_recovery_escalates_when_auto_is_unconfirmed() {
        assert!(firmware_auto_recovery(true).contains("keep both fans in Firmware Auto"));
        let unconfirmed = firmware_auto_recovery(false);
        assert!(unconfirmed.contains("shut down immediately"));
        assert!(unconfirmed.contains("do not reboot"));
    }
}
