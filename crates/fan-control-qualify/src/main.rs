use std::{
    env,
    error::Error,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fan_control_core::{
    CapturedMatchedWorkloadStartingConditions, EvidenceFan, EvidenceProfile, EvidenceRecord,
    EvidenceTimestamp, MatchedWorkloadFanRestoration, MatchedWorkloadObservation,
    MatchedWorkloadTachometerCalibrations, ProtectedFileRequirement, QUALIFICATION_RECORD_PATH,
    RestorationOutcome, RootOwnedQualificationRecordAccess, SUPERVISED_ENDURANCE_WORKLOAD_ID,
    StartupStatus, SupervisedEnduranceEnvironment, SupervisedEndurancePlan,
    SupervisedEnduranceProcessStopConfirmation, SupervisedEnduranceSegment,
    SupervisedEnduranceSegmentConfirmation, SystemOwnershipPlatform, WorkloadEvidence,
    parse_evidence_v2, run_supervised_endurance, validate_root_owned_output_destination,
    validate_root_owned_protected_file, write_qualification_record_after_endurance,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

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
    let mut values = env::args().skip(1);
    let Some(command) = values.next() else {
        println!(
            "fan-control-qualify: {}; run `fan-control-qualify supervised-endurance --help`",
            StartupStatus::UnqualifiedNotConfigured
        );
        return Ok(());
    };
    if command != "supervised-endurance" {
        return Err(format!("unknown qualification command: {command}").into());
    }
    let remaining = values.collect::<Vec<_>>();
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
    let mut environment = HarnessEnvironment::new(arguments.harness);
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

fn read_evidence_set(paths: &[PathBuf]) -> Result<Vec<EvidenceRecord>, Box<dyn Error>> {
    paths.iter().map(|path| read_evidence(path)).collect()
}

fn read_protected_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut platform = SystemOwnershipPlatform::new();
    Ok(platform.read_root_owned_qualification_record(path)?)
}

fn validate_protected_executable(path: &Path) -> Result<(), Box<dyn Error>> {
    validate_root_owned_protected_file(path, ProtectedFileRequirement::Executable)?;
    Ok(())
}

struct HarnessEnvironment {
    harness: PathBuf,
    started: Instant,
    wall_started_millis: i64,
}

impl HarnessEnvironment {
    fn new(harness: PathBuf) -> Self {
        let wall_started_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(i64::MAX);
        Self {
            harness,
            started: Instant::now(),
            wall_started_millis,
        }
    }

    fn now_millis(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    fn invoke<T: DeserializeOwned>(
        &self,
        operation: &str,
        request: Value,
        deadline: u64,
    ) -> Result<T, String> {
        if self.now_millis() >= deadline {
            return Err(format!("{operation} deadline expired before launch"));
        }
        let mut child = Command::new(&self.harness)
            .arg(operation)
            .arg(deadline.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("cannot launch {operation}: {error}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| format!("cannot open {operation} input"))?
            .write_all(request.to_string().as_bytes())
            .map_err(|error| format!("cannot write {operation} input: {error}"))?;
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("cannot wait for {operation}: {error}"))?
            {
                break status;
            }
            if self.now_millis() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{operation} exceeded its absolute deadline"));
            }
            thread::sleep(Duration::from_millis(10));
        };
        if !status.success() {
            return Err(format!("{operation} exited with {status}"));
        }
        let mut output = String::new();
        child
            .stdout
            .take()
            .ok_or_else(|| format!("cannot open {operation} output"))?
            .read_to_string(&mut output)
            .map_err(|error| format!("cannot read {operation} output: {error}"))?;
        serde_json::from_str(&output)
            .map_err(|error| format!("invalid {operation} response: {error}"))
    }
}

impl SupervisedEnduranceEnvironment for HarnessEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        let monotonic_millis = self.now_millis();
        EvidenceTimestamp {
            monotonic_millis,
            wall_unix_millis: self
                .wall_started_millis
                .saturating_add(monotonic_millis.try_into().unwrap_or(i64::MAX)),
        }
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
        if target > deadline {
            return Err("wait target exceeds deadline".into());
        }
        let now = self.now_millis();
        if target > now {
            thread::sleep(Duration::from_millis(target - now));
        }
        (self.now_millis() <= deadline)
            .then_some(())
            .ok_or_else(|| "wait exceeded deadline".into())
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
