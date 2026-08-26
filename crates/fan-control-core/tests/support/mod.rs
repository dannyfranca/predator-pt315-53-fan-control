#![allow(dead_code)]

use fan_control_core::{
    CompatibilityDeclarationV1, CompatibilityObservation, EvidenceCompleteness, EvidenceRecord,
    EvidenceTimestamp, FanCalibrationEvidence, FanCommandEvidence, FanControlField,
    FanWriteBackend, ObservedFanAbi, ValidatedConfig, parse_compatibility_v1, parse_config_v1,
    validate_config_v1,
};
use sha2::{Digest, Sha256};

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
release = "7.1.8-1-cachyos-pt31553"
package = "linux-cachyos-pt31553"
source_commit = "0123456789abcdef0123456789abcdef01234567"
image_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
image_signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[compatibility.module]
name = "acer_wmi"
path = "/usr/lib/modules/7.1.8-1-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
vermagic = "7.1.8-1-cachyos-pt31553 SMP preempt mod_unload"
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
    let source = policy
        .split_once("[compatibility]\n")
        .unwrap()
        .1
        .split_once("\n[calibration.cpu]\n")
        .unwrap()
        .0
        .replace("[compatibility.", "[");
    parse_compatibility_v1(&source).unwrap()
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
    format!(
        r#"{{"schema_version":1,"qualification_id":"pt31553-v1","policy_version":"1.0.0","protected_policy_sha256":"{}","compatibility":{{"schema_version":1,"hardware":{{"dmi_product_name":"Predator PT315-53","dmi_board_name":"Civic_TLS","bios_version":"V1.17"}},"kernel":{{"release":"7.1.8-1-cachyos-pt31553","package":"linux-cachyos-pt31553","source_commit":"{}","image_sha256":"{}","image_signer_fingerprint":"{}"}},"module":{{"name":"acer_wmi","path":"/usr/lib/modules/7.1.8-1-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst","sha256":"{}","signer_fingerprint":"{}","vermagic":"7.1.8-1-cachyos-pt31553 SMP preempt mod_unload","provenance":"in-tree"}},"secure_boot":{{"required":true}},"fan_control":{{"backend":"acer-hwmon","hwmon_name":"acer","endpoints":["pwm1","pwm1_enable","fan1_input","pwm2","pwm2_enable","fan2_input"],"forbidden_capabilities":["force-caps","ec-raw-mode","predator-v4-override","direct-wmi","raw-ec","replacement-wmi-module","alternate-fan-write-backend"]}}}}}}"#,
        sha256(policy),
        SOURCE_COMMIT,
        HASH_A,
        HASH_B,
        HASH_A,
        HASH_B,
    )
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
