#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    io::Read,
    sync::{Arc, Mutex, Once, OnceLock},
};

use fan_control_core::{
    CalibrationLevelObservation, CalibrationReadbackSample, CalibrationStep,
    CompatibilityDeclarationV1, CompatibilityObservation, ConservativeFanCalibration,
    EvidenceCompleteness, EvidenceFan, EvidenceRecord, EvidenceTimestamp, Fan,
    FanCalibrationEvidence, FanCommandEvidence, FanControlField, FanHoldObservation,
    FanWriteBackend, ObservedFanAbi, RestorationAttemptEvidence, RestorationOutcome,
    RunOutcomeStatus, StateTransitionEvidence, ValidatedConfig, parse_compatibility_v1,
    parse_config_v1, validate_config_v1,
};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

static DIAGNOSTIC_CAPTURE_LOCK: Mutex<()> = Mutex::new(());
static DIAGNOSTIC_CAPTURE_SUBSCRIBER: Once = Once::new();

#[derive(Debug, Default)]
struct DiagnosticFields(BTreeMap<String, String>);

impl Visit for DiagnosticFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct DiagnosticRecordingLayer(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

impl<S> Layer<S> for DiagnosticRecordingLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = DiagnosticFields::default();
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

pub fn record_diagnostics<R>(action: impl FnOnce() -> R) -> (R, Vec<BTreeMap<String, String>>) {
    // Keep callsites enabled for the lifetime of this integration-test process. Otherwise another
    // test thread with no subscriber can globally cache the callsite as disabled mid-capture.
    DIAGNOSTIC_CAPTURE_SUBSCRIBER.call_once(|| {
        // Aggregate qualifier targets compile several existing suites, each with its own private
        // copy of this support module. The first copy installs the process-global subscriber; the
        // remaining copies can safely share it.
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry());
    });
    // Tracing's callsite interest cache is process-global. Keep thread-local test subscribers from
    // invalidating one another while Rust's test harness runs capture assertions in parallel.
    let _capture_guard = DIAGNOSTIC_CAPTURE_LOCK.lock().unwrap();
    let layer = DiagnosticRecordingLayer::default();
    let events = Arc::clone(&layer.0);
    let result =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), action);
    let events = Arc::try_unwrap(events).unwrap().into_inner().unwrap();
    (result, events)
}

pub fn diagnostic_field<'a>(event: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    event.get(name).unwrap().trim_matches('"')
}

pub const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub const PROTECTED_POLICY: &str = r#"schema_version = 2
qualification_id = "pt31553-v1"
policy_version = "1.0.0"

[compatibility]
schema_version = 1

[compatibility.hardware]
dmi_product_name = "Predator PT315-53"
dmi_board_name = "Civic_TLS"
bios_version = "V1.17"

[compatibility.kernel]
release = "7.1.8-cachyos-pt31553"
package = "linux-cachyos-pt31553"
source_commit = "0123456789abcdef0123456789abcdef01234567"
image_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
image_signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[compatibility.module]
name = "acer_wmi"
path = "/usr/lib/modules/7.1.8-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
vermagic = "7.1.8-cachyos-pt31553 SMP preempt mod_unload"
provenance = "in-tree"

[compatibility.secure_boot]
required = true

[compatibility.fan_control]
backend = "acer-hwmon"
hwmon_name = "acer"
endpoints = ["pwm1", "pwm1_enable", "fan1_input", "pwm2", "pwm2_enable", "fan2_input"]
forbidden_capabilities = [
  "force-caps",
  "ec-raw-mode",
  "predator-v4-override",
  "direct-wmi",
  "raw-ec",
  "replacement-wmi-module",
  "alternate-fan-write-backend",
]

[calibration.cpu]
floor_basis_points = 3000
response_deadline_millis = 4000
anchors = [
  { duty_basis_points = 3000, median_rpm = 2500 },
  { duty_basis_points = 10000, median_rpm = 3500 },
]

[calibration.gpu]
floor_basis_points = 2500
response_deadline_millis = 4000
anchors = [
  { duty_basis_points = 2500, median_rpm = 2500 },
  { duty_basis_points = 10000, median_rpm = 3500 },
]

[protected]
schema_version = 1

[protected.control]
hysteresis_celsius = 3
lower_demand_hold_seconds = 10
max_down_ramp_percent_per_second = 1.0

[protected.fans.cpu]
minimum_duty_percent = 30

[protected.fans.gpu]
minimum_duty_percent = 25

[protected.profiles.ac]
cpu_curve = [
  { temperature_c = 40, demand_percent = 30 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 35, demand_percent = 30 },
  { temperature_c = 82, demand_percent = 100 },
]

[protected.profiles.battery]
cpu_curve = [
  { temperature_c = 40, demand_percent = 30 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 35, demand_percent = 30 },
  { temperature_c = 82, demand_percent = 100 },
]
"#;

pub fn runtime_protected_policy() -> String {
    PROTECTED_POLICY.replacen(
        "[protected.profiles.battery]\ncpu_curve = [\n  { temperature_c = 40, demand_percent = 30 },\n  { temperature_c = 90, demand_percent = 100 },\n]\ngpu_curve = [\n  { temperature_c = 35, demand_percent = 30 },\n  { temperature_c = 82, demand_percent = 100 },\n]\n",
        "[protected.profiles.battery]\ncpu_curve = [\n  { temperature_c = 40, demand_percent = 30 },\n  { temperature_c = 70, demand_percent = 50 },\n  { temperature_c = 90, demand_percent = 100 },\n]\ngpu_curve = [\n  { temperature_c = 35, demand_percent = 30 },\n  { temperature_c = 65, demand_percent = 50 },\n  { temperature_c = 82, demand_percent = 100 },\n]\n",
        1,
    )
}

pub fn matching_observation_for_policy(policy: &str) -> CompatibilityObservation {
    matching_observation(&compatibility_declaration(policy))
}

pub fn compatibility_declaration(policy: &str) -> CompatibilityDeclarationV1 {
    fixture_compatibility_declaration(policy).unwrap()
}

fn fixture_compatibility_declaration(policy: &str) -> Option<CompatibilityDeclarationV1> {
    let source = policy
        .split_once("[compatibility]\n")?
        .1
        .split_once("\n[calibration.cpu]\n")?
        .0
        .replace("[compatibility.", "[");
    parse_compatibility_v1(&source).ok()
}

fn compatibility_for_fixture(policy: &str) -> CompatibilityDeclarationV1 {
    fixture_compatibility_declaration(policy)
        .unwrap_or_else(|| fixture_compatibility_declaration(PROTECTED_POLICY).unwrap())
}

pub fn protected_config(policy: &str) -> ValidatedConfig {
    let source = policy
        .split_once("[protected]\n")
        .unwrap()
        .1
        .replace("[protected.", "[");
    validate_config_v1(parse_config_v1(&source).unwrap()).unwrap()
}

pub fn matching_observation(declaration: &CompatibilityDeclarationV1) -> CompatibilityObservation {
    CompatibilityObservation {
        hardware: declaration.hardware.clone(),
        kernel: declaration.kernel.clone(),
        module: declaration.module.clone(),
        secure_boot_enabled: true,
        kernel_image_trusted: true,
        module_signature_trusted: true,
        fan_abi: ObservedFanAbi {
            hwmon_name: declaration.fan_control.hwmon_name.clone(),
            endpoints: declaration.fan_control.endpoints.clone(),
        },
        backend_evidence_completeness: EvidenceCompleteness::Complete,
        backends: vec![FanWriteBackend::AcerHwmon],
        capability_evidence_completeness: EvidenceCompleteness::Complete,
        enabled_capabilities: Vec::new(),
    }
}

pub fn matching_record(policy: &str) -> String {
    let evidence_sha256 = sha256(&matching_endurance_evidence(policy));
    serde_json::to_string(&serde_json::json!({
        "schema_version": 2,
        "qualification_id": "pt31553-v1",
        "policy_version": "1.0.0",
        "protected_policy_sha256": sha256(policy),
        "compatibility": compatibility_for_fixture(policy),
        "supervised_endurance": {
            "schema_version": 1,
            "evidence_sha256": evidence_sha256,
            "evidence_path": fan_control_core::SUPERVISED_ENDURANCE_EVIDENCE_PATH,
            "evidence_schema_version": 2,
            "stage": "supervised-endurance",
            "record_status": "complete",
            "outcome": "passed",
            "final_firmware_auto_confirmed": true,
            "workload_stopped": true,
            "service_stopped": true,
            "completed_at": {
                "monotonic_millis": 3_600_000,
                "wall_unix_millis": 3_600_000
            }
        }
    }))
    .expect("qualification fixture serializes")
}

pub fn matching_endurance_evidence(policy: &str) -> String {
    static CACHE: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();

    let protected_policy_sha256 = sha256(policy);
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(source) = cache.lock().unwrap().get(&protected_policy_sha256).cloned() {
        return source;
    }

    let mut compressed = GzDecoder::new(
        &include_bytes!("../../../../qualification/supervised-endurance-v2.json.gz")[..],
    );
    let mut source = String::new();
    compressed.read_to_string(&mut source).unwrap();
    let mut record: serde_json::Value = serde_json::from_str(&source).unwrap();
    record["qualification_envelope"]["protected_policy_sha256"] =
        protected_policy_sha256.clone().into();
    record["qualification_envelope"]["compatibility"] =
        serde_json::to_value(compatibility_for_fixture(policy)).unwrap();
    let source = serde_json::to_string(&record).unwrap();
    cache
        .lock()
        .unwrap()
        .insert(protected_policy_sha256, source.clone());
    source
}

pub fn sha256(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
}

pub fn bind_record_to_calibration_protocol(
    record: &mut EvidenceRecord,
    calibration: &FanCalibrationEvidence,
) {
    let checkpoint =
        serde_json::to_value(calibration.protocol_checkpoint.as_ref().unwrap()).unwrap();
    let events = checkpoint["events"].as_array().unwrap();
    let mut observed_times = Vec::new();
    let mut commands = Vec::new();
    for event in events {
        let event = &event["observation"];
        let observation = &event["observation"];
        if let Some(commanded_at) = observation["commanded_at_monotonic_millis"].as_u64() {
            observed_times.push(commanded_at);
            commands.push(FanCommandEvidence {
                timestamp: EvidenceTimestamp {
                    monotonic_millis: commanded_at,
                    wall_unix_millis: record.started_at.wall_unix_millis,
                },
                fan: calibration.fan,
                field: FanControlField::Pwm,
                value: event["step"]["pwm_value"].as_u64().unwrap() as u32,
            });
        }
        observed_times.extend(
            observation["samples"]
                .as_array()
                .unwrap()
                .iter()
                .map(|sample| sample["monotonic_millis"].as_u64().unwrap()),
        );
    }
    let first = *observed_times.iter().min().unwrap();
    let last = *observed_times.iter().max().unwrap();
    record.started_at.monotonic_millis = record.started_at.monotonic_millis.min(first);
    record.completed_at.monotonic_millis = last + 3;
    record.commands = commands;
    for attempt in &mut record.restoration_attempts {
        attempt.timestamp.monotonic_millis = last + 1;
    }
    record
        .state_transitions
        .last_mut()
        .unwrap()
        .timestamp
        .monotonic_millis = last + 2;
}

pub fn completed_calibration_evidence(fan: Fan) -> FanCalibrationEvidence {
    let mut session = ConservativeFanCalibration::start(fan);
    let mut clock = 1;
    for rpm in [5_000, 3_800, 3_300, 2_800] {
        record_stable_calibration_level(&mut session, rpm, 3_000, &mut clock);
    }
    let step = session.next_step();
    let mut unstable = calibration_level_observation(step, 900, 2_000, &mut clock);
    for (index, sample) in unstable.samples.iter_mut().enumerate() {
        sample.selected_rpm = Some(if index % 2 == 0 { 900 } else { 1_300 });
    }
    session.record_level(unstable).unwrap();
    for _ in 0..5 {
        record_stable_calibration_level(&mut session, 5_000, 4_000, &mut clock);
        record_stable_calibration_level(&mut session, 3_300, 5_000, &mut clock);
    }
    let hold_step = session.next_step();
    let hold_samples = (0..451)
        .map(|index| CalibrationReadbackSample {
            monotonic_millis: clock + index * 2_000,
            selected_enable_readback: 1,
            selected_pwm_readback: hold_step.pwm_value().unwrap(),
            other_enable_readback: 1,
            other_pwm_readback: u8::MAX,
            selected_rpm: Some(3_300),
        })
        .collect();
    clock += 451 * 2_000;
    session
        .record_hold(FanHoldObservation {
            samples: hold_samples,
            stall_observed: false,
            unexplained_rpm_collapse_observed: false,
        })
        .unwrap();
    for (rpm, response) in [
        (3_300, 3_000),
        (3_800, 4_000),
        (4_500, 5_000),
        (6_200, 6_000),
    ] {
        record_stable_calibration_level(&mut session, rpm, response, &mut clock);
    }
    session.evidence().unwrap().clone()
}

pub fn completed_calibration_record(mut record: EvidenceRecord, fan: Fan) -> EvidenceRecord {
    record.schema_version = 2;
    record.stage = "fan-calibration".into();
    record.baseline_binding_sha256 = None;
    record.faults.clear();
    if let Some(summary) = &mut record.thermal_summary {
        summary.kernel_faults.clear();
        summary.nvidia_faults.clear();
    }
    record.restoration_attempts = [EvidenceFan::Cpu, EvidenceFan::Gpu]
        .into_iter()
        .map(|fan| RestorationAttemptEvidence {
            timestamp: record.completed_at,
            fan,
            auto_write_succeeded: true,
            enable_readback: Some(2),
            outcome: RestorationOutcome::FirmwareAutoConfirmed,
        })
        .collect();
    record.state_transitions = vec![
        StateTransitionEvidence {
            timestamp: record.started_at,
            boot_id: None,
            from: "firmware-auto".into(),
            to: "custom-control".into(),
        },
        StateTransitionEvidence {
            timestamp: record.completed_at,
            boot_id: None,
            from: "custom-control".into(),
            to: "firmware-auto".into(),
        },
    ];
    record.outcome.status = RunOutcomeStatus::Passed;
    record.outcome.reason = "fan calibration passed".into();
    record.outcome.another_passing_run_required = false;
    let calibration = completed_calibration_evidence(fan);
    record.calibration = vec![calibration.clone()];
    bind_record_to_calibration_protocol(&mut record, &calibration);
    record
}

fn record_stable_calibration_level(
    session: &mut ConservativeFanCalibration,
    rpm: u32,
    response_millis: u64,
    clock: &mut u64,
) {
    let observation =
        calibration_level_observation(session.next_step(), rpm, response_millis, clock);
    session.record_level(observation).unwrap();
}

fn calibration_level_observation(
    step: CalibrationStep,
    rpm: u32,
    response_millis: u64,
    clock: &mut u64,
) -> CalibrationLevelObservation {
    let started_at = *clock;
    let intervals = response_millis.div_ceil(2_000).max(3);
    *clock += response_millis + 1;
    CalibrationLevelObservation {
        commanded_at_monotonic_millis: started_at,
        samples: (0..=intervals)
            .map(|index| CalibrationReadbackSample {
                monotonic_millis: started_at + response_millis * index / intervals,
                selected_enable_readback: 1,
                selected_pwm_readback: step.pwm_value().unwrap(),
                other_enable_readback: 1,
                other_pwm_readback: u8::MAX,
                selected_rpm: (index + 3 > intervals).then_some(rpm),
            })
            .collect(),
        stall_observed: false,
        unexplained_rpm_collapse_observed: false,
    }
}
