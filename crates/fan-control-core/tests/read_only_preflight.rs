mod support;

use std::{collections::BTreeMap, path::Path};

use fan_control_core::{
    EvidenceTimestamp, FakePlatform, FileIdentity, FilePermissions, IdentityBoundReadAccess,
    NvidiaGpuSelector, NvmlAccess, NvmlError, NvmlErrorKind, NvmlGpuSample, ObservationOutcome,
    PlatformError, PlatformErrorKind, PlatformOperation, PreflightArtifact, PreflightCheck,
    PreflightEnvironment, PreflightInputs, PreflightReport, PreflightRequirements,
    QualificationEnvelopeIdentityV1, ServiceAccess, parse_evidence_v2, run_read_only_preflight,
};
use support::{
    PROTECTED_POLICY, compatibility_declaration, matching_observation_for_policy, matching_record,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const EVIDENCE_ROOT: &str = "/var/lib/pt31553-fan-control/evidence";
const EXPECTED_UUID: &str = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const VALID_CONFIG: &str = r#"
schema_version = 1

[control]
hysteresis_celsius = 3
lower_demand_hold_seconds = 10
max_down_ramp_percent_per_second = 1.0

[fans.cpu]
minimum_duty_percent = 30

[fans.gpu]
minimum_duty_percent = 25

[profiles.ac]
cpu_curve = [{ temperature_c = 40, demand_percent = 30 }, { temperature_c = 90, demand_percent = 100 }]
gpu_curve = [{ temperature_c = 35, demand_percent = 25 }, { temperature_c = 82, demand_percent = 100 }]

[profiles.battery]
cpu_curve = [{ temperature_c = 40, demand_percent = 30 }, { temperature_c = 90, demand_percent = 100 }]
gpu_curve = [{ temperature_c = 35, demand_percent = 25 }, { temperature_c = 82, demand_percent = 100 }]
"#;
const JSON_SCHEMA_V2: &str = include_str!("../../../schemas/evidence-v2.json");

#[derive(Clone)]
struct StubNvml(Result<NvmlGpuSample, NvmlError>);

impl NvmlAccess for StubNvml {
    fn sample_by_identity(
        &mut self,
        _selector: &NvidiaGpuSelector,
    ) -> Result<NvmlGpuSample, NvmlError> {
        self.0.clone()
    }
}

struct StubEnvironment {
    artifacts: BTreeMap<PreflightArtifact, bool>,
    available_bytes: Result<u64, PlatformError>,
    requested_artifacts: Vec<PreflightArtifact>,
    signing_trust_ready: bool,
    recovery_ready: bool,
    stock_boot_fallback_ready: bool,
    qualification_workload_absent: bool,
    timestamp_millis: u64,
}

impl StubEnvironment {
    fn ready() -> Self {
        Self {
            artifacts: PreflightArtifact::ALL
                .into_iter()
                .map(|artifact| (artifact, true))
                .collect(),
            available_bytes: Ok(2_000_000),
            requested_artifacts: Vec::new(),
            signing_trust_ready: true,
            recovery_ready: true,
            stock_boot_fallback_ready: true,
            qualification_workload_absent: true,
            timestamp_millis: 10,
        }
    }
}

impl PreflightEnvironment for StubEnvironment {
    fn timestamp_now(&mut self) -> EvidenceTimestamp {
        let timestamp = EvidenceTimestamp {
            monotonic_millis: self.timestamp_millis,
            wall_unix_millis: 100 + i64::try_from(self.timestamp_millis).unwrap(),
        };
        self.timestamp_millis += 1;
        timestamp
    }

    fn signing_trust_is_ready(&mut self) -> Result<bool, PlatformError> {
        Ok(self.signing_trust_ready)
    }

    fn recovery_is_ready(&mut self) -> Result<bool, PlatformError> {
        Ok(self.recovery_ready)
    }

    fn stock_boot_fallback_is_ready(&mut self) -> Result<bool, PlatformError> {
        Ok(self.stock_boot_fallback_ready)
    }

    fn qualification_workload_is_absent(&mut self) -> Result<bool, PlatformError> {
        Ok(self.qualification_workload_absent)
    }

    fn artifact_is_ready(&mut self, artifact: PreflightArtifact) -> Result<bool, PlatformError> {
        self.requested_artifacts.push(artifact);
        Ok(self.artifacts.get(&artifact).copied().unwrap_or(false))
    }

    fn available_bytes(&mut self, _path: &Path) -> Result<u64, PlatformError> {
        self.available_bytes.clone()
    }
}

#[test]
fn reports_every_required_check_and_passes_without_any_write_or_lock() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();

    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    );

    assert!(report.passed());
    assert_eq!(
        report
            .checks()
            .iter()
            .map(|result| result.check())
            .collect::<Vec<_>>(),
        vec![
            PreflightCheck::Platform,
            PreflightCheck::Trust,
            PreflightCheck::FanAbi,
            PreflightCheck::Sensors,
            PreflightCheck::Configuration,
            PreflightCheck::Policy,
            PreflightCheck::Recovery,
            PreflightCheck::StockBootFallback,
            PreflightCheck::Tooling,
            PreflightCheck::DiskSpace,
            PreflightCheck::CompetingServices,
            PreflightCheck::FirmwareAuto,
        ]
    );
    assert!(report.checks().iter().all(|result| result.passed()));
    let plain = report.to_string();
    assert!(plain.lines().all(|line| line.starts_with("PASS ")));
    assert!(plain.contains("PASS firmware-auto: both fans are already in Firmware Auto"));
    let record_value: serde_json::Value = serde_json::from_str(&record).unwrap();
    let evidence = report
        .clone()
        .into_evidence(
            QualificationEnvelopeIdentityV1 {
                qualification_record_schema_version: 1,
                qualification_id: record_value["qualification_id"].as_str().unwrap().into(),
                policy_version: record_value["policy_version"].as_str().unwrap().into(),
                protected_policy_sha256: record_value["protected_policy_sha256"]
                    .as_str()
                    .unwrap()
                    .into(),
                compatibility: declaration.clone(),
            },
            EvidenceTimestamp {
                monotonic_millis: 10,
                wall_unix_millis: 100,
            },
            EvidenceTimestamp {
                monotonic_millis: 30,
                wall_unix_millis: 130,
            },
        )
        .unwrap();
    assert_eq!(evidence.stage, "preflight");
    assert_eq!(evidence.readbacks.len(), 2);
    let checks = evidence.preflight_checks.as_ref().unwrap();
    assert_eq!(checks.len(), 12);
    assert!(checks.iter().all(|check| check.passed));
    let check_times = checks
        .iter()
        .map(|check| check.timestamp.monotonic_millis)
        .collect::<Vec<_>>();
    assert!(check_times.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        check_times
            .iter()
            .all(|timestamp| (10..=30).contains(timestamp))
    );
    assert!(evidence.commands.is_empty());
    assert!(evidence.validate().is_ok());
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA_V2).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let evidence_json = serde_json::to_value(&evidence).unwrap();
    assert!(validator.is_valid(&evidence_json));
    let mut duplicate_check = evidence_json.clone();
    duplicate_check["preflight_checks"][0]["check"] =
        duplicate_check["preflight_checks"][1]["check"].clone();
    assert!(!validator.is_valid(&duplicate_check));
    let mut contradictory_check = evidence_json;
    contradictory_check["preflight_checks"][0]["passed"] = false.into();
    assert!(!validator.is_valid(&contradictory_check));
    let mut faultless_collection_failure = contradictory_check;
    faultless_collection_failure["preflight_checks"] = serde_json::json!([{
        "check": "evidence-collection",
        "passed": false,
        "detail": "collection failed",
        "timestamp": { "monotonic_millis": 20, "wall_unix_millis": 120 }
    }]);
    faultless_collection_failure["outcome"]["status"] = "failed".into();
    faultless_collection_failure["faults"] = serde_json::json!([]);
    assert!(!validator.is_valid(&faultless_collection_failure));
    let mut contradictory_failure = evidence.clone();
    contradictory_failure.outcome.status = fan_control_core::RunOutcomeStatus::Failed;
    contradictory_failure.outcome.reason = "claimed failure without a failed check".into();
    assert!(contradictory_failure.validate().is_err());
    let mut wall_clock_adjusted = evidence.clone();
    wall_clock_adjusted.started_at.wall_unix_millis = 10_000;
    wall_clock_adjusted.completed_at.wall_unix_millis = -10_000;
    assert!(wall_clock_adjusted.validate().is_ok());
    let mut too_many_checks = evidence.clone();
    let mut extra_check = too_many_checks.preflight_checks.as_ref().unwrap()[0].clone();
    extra_check.check = "unexpected-extra".into();
    too_many_checks
        .preflight_checks
        .as_mut()
        .unwrap()
        .push(extra_check);
    assert!(too_many_checks.validate().is_err());
    let mut malformed = evidence.clone();
    malformed.readbacks[0].phase = None;
    assert!(malformed.validate().is_err());
    let mut malformed_json = serde_json::to_value(&evidence).unwrap();
    malformed_json["readbacks"][0]
        .as_object_mut()
        .unwrap()
        .remove("phase");
    assert!(parse_evidence_v2(&malformed_json.to_string()).is_err());
    assert_eq!(
        environment.requested_artifacts,
        vec![
            PreflightArtifact::QualificationTool,
            PreflightArtifact::RestorationTool,
            PreflightArtifact::Daemon,
            PreflightArtifact::DaemonServiceUnit,
            PreflightArtifact::SleepGuardServiceUnit,
            PreflightArtifact::Journald,
        ]
    );
    assert!(platform.operations().iter().all(|operation| !matches!(
        operation,
        PlatformOperation::Write { .. }
            | PlatformOperation::AcquireRuntimeLock(_)
            | PlatformOperation::ReleaseRuntimeLock(_)
    )));
}

#[test]
fn nvidia_reset_required_is_a_clear_blocking_sensor_failure() {
    let (mut platform, _, mut environment) = passing_fixture();
    let mut nvml = StubNvml(Err(NvmlError::new(
        NvmlErrorKind::ResetRequired,
        "GPU requires reset",
    )));
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let inputs = PreflightInputs {
        compatibility: &declaration,
        observations: &observations,
        config_source: VALID_CONFIG,
        protected_policy_source: PROTECTED_POLICY,
        qualification_record_source: &record,
        nvidia_selector: &selector,
    };
    let requirements = PreflightRequirements {
        hwmon_root: Path::new(HWMON_ROOT),
        evidence_root: Path::new(EVIDENCE_ROOT),
        minimum_available_bytes: 1_000_000,
    };

    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &inputs,
        &requirements,
    );

    assert!(!report.passed());
    let sensor = report.result(PreflightCheck::Sensors).unwrap();
    assert!(!sensor.passed());
    assert!(sensor.detail().contains("NVIDIA reset-required"));
    assert!(sensor.detail().contains("blocks qualification"));
}

#[test]
fn missing_cpu_sensor_is_a_blocking_sensor_failure() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    platform.remove_path(Path::new(HWMON_ROOT).join("hwmon1"));
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    );

    let sensor = report.result(PreflightCheck::Sensors).unwrap();
    assert!(!sensor.passed());
    assert!(sensor.detail().contains("CPU sensor"));
    assert!(sensor.detail().contains("no coretemp hwmon device found"));
}

#[test]
fn temperatures_at_absolute_abort_limits_fail_safe_start() {
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);

    let (mut platform, mut nvml, mut environment) = passing_fixture();
    platform.insert_file_with_permissions(
        Path::new(HWMON_ROOT).join("hwmon1/temp1_input"),
        "95000\n",
        FilePermissions::READ_ONLY,
    );
    let report = run_fixture_report(
        &mut platform,
        &mut nvml,
        &mut environment,
        &declaration,
        &observations,
        &record,
    );
    assert!(
        report
            .result(PreflightCheck::Sensors)
            .unwrap()
            .detail()
            .contains("95 °C absolute abort limit")
    );

    let (mut platform, _, mut environment) = passing_fixture();
    let mut nvml = StubNvml(Ok(NvmlGpuSample::new(
        EXPECTED_UUID,
        "00000000:01:00.0",
        85.0,
    )));
    let report = run_fixture_report(
        &mut platform,
        &mut nvml,
        &mut environment,
        &declaration,
        &observations,
        &record,
    );
    assert!(
        report
            .result(PreflightCheck::Sensors)
            .unwrap()
            .detail()
            .contains("85 °C absolute abort limit")
    );
}

#[test]
fn incompatible_platform_trust_abi_and_policy_each_fail_their_reported_check() {
    for check in [
        PreflightCheck::Platform,
        PreflightCheck::Trust,
        PreflightCheck::FanAbi,
        PreflightCheck::Policy,
    ] {
        let (mut platform, mut nvml, mut environment) = passing_fixture();
        let declaration = compatibility_declaration(PROTECTED_POLICY);
        let mut observation = matching_observation_for_policy(PROTECTED_POLICY);
        let mut record = matching_record(PROTECTED_POLICY);
        match check {
            PreflightCheck::Platform => observation.hardware.bios_version = "V1.18".to_owned(),
            PreflightCheck::Trust => observation.module_signature_trusted = false,
            PreflightCheck::FanAbi => {
                observation.fan_abi.endpoints.pop();
            }
            PreflightCheck::Policy => {
                record = record.replacen(
                    "\"policy_version\":\"1.0.0\"",
                    "\"policy_version\":\"2.0.0\"",
                    1,
                );
            }
            _ => unreachable!(),
        }
        let observations = [observation];

        let report = run_fixture_report(
            &mut platform,
            &mut nvml,
            &mut environment,
            &declaration,
            &observations,
            &record,
        );

        assert!(!report.result(check).unwrap().passed(), "{check:?}");
        assert_eq!(report.checks().len(), 12);
        assert!(report.result(PreflightCheck::FirmwareAuto).is_some());
    }
}

#[test]
fn failures_are_all_reported_instead_of_short_circuiting() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    platform.insert_file(Path::new(HWMON_ROOT).join("hwmon0/pwm2_enable"), "1\n");
    platform.insert_service("fancontrol.service", true);
    platform.insert_service("nbfc.service", true);
    environment
        .artifacts
        .insert(PreflightArtifact::RestorationTool, false);
    environment.available_bytes = Ok(999);
    environment.signing_trust_ready = false;
    environment.recovery_ready = false;
    environment.stock_boot_fallback_ready = false;
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();

    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: "schema_version = 1",
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000,
        },
    );

    for check in [
        PreflightCheck::Configuration,
        PreflightCheck::Trust,
        PreflightCheck::Recovery,
        PreflightCheck::StockBootFallback,
        PreflightCheck::Tooling,
        PreflightCheck::DiskSpace,
        PreflightCheck::CompetingServices,
        PreflightCheck::FirmwareAuto,
    ] {
        assert!(!report.result(check).unwrap().passed(), "{check:?}");
    }
    assert_eq!(report.checks().len(), 12);
    assert_eq!(
        report.result(PreflightCheck::Tooling).unwrap().detail(),
        "missing /usr/bin/pt31553-fan-restore"
    );
    let competing = report
        .result(PreflightCheck::CompetingServices)
        .unwrap()
        .detail();
    assert!(competing.contains("fancontrol.service"));
    assert!(competing.contains("nbfc.service"));

    let trust_timestamp = report.result(PreflightCheck::Trust).unwrap().timestamp();
    let record_value: serde_json::Value = serde_json::from_str(&record).unwrap();
    let evidence = report
        .into_evidence(
            QualificationEnvelopeIdentityV1 {
                qualification_record_schema_version: 1,
                qualification_id: record_value["qualification_id"].as_str().unwrap().into(),
                policy_version: record_value["policy_version"].as_str().unwrap().into(),
                protected_policy_sha256: record_value["protected_policy_sha256"]
                    .as_str()
                    .unwrap()
                    .into(),
                compatibility: declaration,
            },
            EvidenceTimestamp {
                monotonic_millis: 1,
                wall_unix_millis: 1,
            },
            EvidenceTimestamp {
                monotonic_millis: 100,
                wall_unix_millis: 1_000,
            },
        )
        .unwrap();
    assert_eq!(
        evidence
            .faults
            .iter()
            .find(|fault| fault.code == "preflight-trust")
            .unwrap()
            .timestamp,
        trust_timestamp
    );
}

#[test]
fn either_fan_outside_firmware_auto_blocks_preflight() {
    for channel in 1..=2 {
        let (mut platform, mut nvml, mut environment) = passing_fixture();
        platform.insert_file(
            Path::new(HWMON_ROOT).join(format!("hwmon0/pwm{channel}_enable")),
            "1\n",
        );
        let declaration = compatibility_declaration(PROTECTED_POLICY);
        let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
        let record = matching_record(PROTECTED_POLICY);
        let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
        let report = run_read_only_preflight(
            &mut platform,
            &mut nvml,
            &mut environment,
            &PreflightInputs {
                compatibility: &declaration,
                observations: &observations,
                config_source: VALID_CONFIG,
                protected_policy_source: PROTECTED_POLICY,
                qualification_record_source: &record,
                nvidia_selector: &selector,
            },
            &PreflightRequirements {
                hwmon_root: Path::new(HWMON_ROOT),
                evidence_root: Path::new(EVIDENCE_ROOT),
                minimum_available_bytes: 1_000_000,
            },
        );

        assert!(
            !report
                .result(PreflightCheck::FirmwareAuto)
                .unwrap()
                .passed(),
            "fan channel {channel}"
        );
    }
}

#[test]
fn fan_mode_endpoints_writable_outside_root_block_the_sandbox() {
    for endpoint in ["pwm1", "pwm1_enable", "pwm2", "pwm2_enable"] {
        for permissions in [
            FilePermissions::from_mode(0o664),
            FilePermissions::from_mode(0o644).with_extended_acl(),
            FilePermissions::from_mode(0o600).with_owner_uid(65_534),
        ] {
            let (mut platform, mut nvml, mut environment) = passing_fixture();
            platform.insert_file_with_permissions(
                Path::new(HWMON_ROOT).join("hwmon0").join(endpoint),
                "2\n",
                permissions,
            );
            let declaration = compatibility_declaration(PROTECTED_POLICY);
            let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
            let record = matching_record(PROTECTED_POLICY);
            let report = run_fixture_report(
                &mut platform,
                &mut nvml,
                &mut environment,
                &declaration,
                &observations,
                &record,
            );
            assert!(
                !report.result(PreflightCheck::FanAbi).unwrap().passed()
                    || !report
                        .result(PreflightCheck::FirmwareAuto)
                        .unwrap()
                        .passed(),
                "endpoint={endpoint} permissions={permissions:?}"
            );
        }
    }
}

#[test]
fn project_writers_and_leftover_workloads_block_preflight() {
    for service in ["pt31553-fand.service", "pt31553-fan-sleep-guard.service"] {
        let (mut platform, mut nvml, mut environment) = passing_fixture();
        platform.insert_service(service, true);
        let declaration = compatibility_declaration(PROTECTED_POLICY);
        let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
        let record = matching_record(PROTECTED_POLICY);
        let report = run_fixture_report(
            &mut platform,
            &mut nvml,
            &mut environment,
            &declaration,
            &observations,
            &record,
        );
        assert!(
            report
                .result(PreflightCheck::CompetingServices)
                .unwrap()
                .detail()
                .contains(service)
        );
    }

    let (mut platform, mut nvml, mut environment) = passing_fixture();
    environment.qualification_workload_absent = false;
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let report = run_fixture_report(
        &mut platform,
        &mut nvml,
        &mut environment,
        &declaration,
        &observations,
        &record,
    );
    assert!(
        report
            .result(PreflightCheck::CompetingServices)
            .unwrap()
            .detail()
            .contains("qualification workload is still active")
    );
}

#[test]
fn final_fan_generation_rechecks_sandbox_write_boundary() {
    let (platform, mut nvml, mut environment) = passing_fixture();
    let mut platform = UnsafePermissionsAfterInitialFanAbi {
        inner: platform,
        fan_enable_permission_calls: 0,
    };
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let report = run_fixture_report(
        &mut platform,
        &mut nvml,
        &mut environment,
        &declaration,
        &observations,
        &record,
    );

    assert!(
        report.result(PreflightCheck::FanAbi).unwrap().passed(),
        "fan-enable permission calls={}\n{report}",
        platform.fan_enable_permission_calls
    );
    assert!(
        !report
            .result(PreflightCheck::FirmwareAuto)
            .unwrap()
            .passed()
    );
    assert_eq!(platform.fan_enable_permission_calls, 29);
}

#[test]
fn malformed_fan_mode_becomes_identity_bound_unreadable_valid_failed_evidence() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    platform.insert_file_with_permissions(
        Path::new(HWMON_ROOT).join("hwmon0/pwm1_enable"),
        "not-a-mode\n",
        FilePermissions::READ_WRITE,
    );
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let report = run_fixture_report(
        &mut platform,
        &mut nvml,
        &mut environment,
        &declaration,
        &observations,
        &record,
    );
    assert!(
        report
            .result(PreflightCheck::FirmwareAuto)
            .unwrap()
            .detail()
            .contains("invalid mode")
    );

    let record_value: serde_json::Value = serde_json::from_str(&record).unwrap();
    let evidence = report
        .into_evidence(
            QualificationEnvelopeIdentityV1 {
                qualification_record_schema_version: 1,
                qualification_id: record_value["qualification_id"].as_str().unwrap().into(),
                policy_version: record_value["policy_version"].as_str().unwrap().into(),
                protected_policy_sha256: record_value["protected_policy_sha256"]
                    .as_str()
                    .unwrap()
                    .into(),
                compatibility: declaration,
            },
            EvidenceTimestamp {
                monotonic_millis: 1,
                wall_unix_millis: 1,
            },
            EvidenceTimestamp {
                monotonic_millis: 100,
                wall_unix_millis: 1_000,
            },
        )
        .unwrap();
    let cpu = evidence
        .readbacks
        .iter()
        .find(|readback| readback.fan == fan_control_core::EvidenceFan::Cpu)
        .unwrap();
    assert_eq!(cpu.value, None);
    assert_eq!(cpu.outcome, ObservationOutcome::Unreadable);
    assert!(cpu.endpoint_identity.starts_with("device-"));
    assert!(evidence.validate().is_ok());
    let mut partial = evidence.clone();
    partial.preflight_checks.as_mut().unwrap().truncate(2);
    assert!(partial.validate().is_err());
    let mut mismatched_fault = evidence.clone();
    mismatched_fault
        .faults
        .iter_mut()
        .find(|fault| fault.code == "preflight-firmware-auto")
        .unwrap()
        .detail = "different fault detail".into();
    assert!(mismatched_fault.validate().is_err());
}

#[test]
fn fan_mode_reads_fail_closed_when_the_discovered_hwmon_identity_rebinds() {
    let (platform, mut nvml, mut environment) = passing_fixture();
    let mut platform = RebindOnCpuModeRead { inner: platform };
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    );

    assert!(
        !report
            .result(PreflightCheck::FirmwareAuto)
            .unwrap()
            .passed()
    );
    let record_value: serde_json::Value = serde_json::from_str(&record).unwrap();
    let evidence = report
        .into_evidence(
            QualificationEnvelopeIdentityV1 {
                qualification_record_schema_version: 1,
                qualification_id: record_value["qualification_id"].as_str().unwrap().into(),
                policy_version: record_value["policy_version"].as_str().unwrap().into(),
                protected_policy_sha256: record_value["protected_policy_sha256"]
                    .as_str()
                    .unwrap()
                    .into(),
                compatibility: declaration,
            },
            EvidenceTimestamp {
                monotonic_millis: 1,
                wall_unix_millis: 1,
            },
            EvidenceTimestamp {
                monotonic_millis: 100,
                wall_unix_millis: 1_000,
            },
        )
        .unwrap();
    assert!(!evidence.outcome.final_firmware_auto_confirmed);
    assert_eq!(evidence.readbacks.len(), 2);
    assert_eq!(
        evidence
            .readbacks
            .iter()
            .map(|readback| readback.timestamp.monotonic_millis)
            .collect::<Vec<_>>(),
        vec![21, 22]
    );
    assert!(
        evidence
            .readbacks
            .iter()
            .all(|readback| readback.outcome == ObservationOutcome::Unreadable)
    );
}

fn passing_fixture() -> (FakePlatform, StubNvml, StubEnvironment) {
    let mut platform = FakePlatform::new();
    let acer = Path::new(HWMON_ROOT).join("hwmon0");
    platform.insert_file_with_permissions(acer.join("name"), "acer\n", FilePermissions::READ_ONLY);
    for channel in 1..=2 {
        platform.insert_file_with_permissions(
            acer.join(format!("pwm{channel}")),
            "128\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            acer.join(format!("pwm{channel}_enable")),
            "2\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            acer.join(format!("fan{channel}_input")),
            "2500\n",
            FilePermissions::READ_ONLY,
        );
    }
    let coretemp = Path::new(HWMON_ROOT).join("hwmon1");
    for (name, contents) in [
        ("name", "coretemp\n"),
        ("temp1_label", "Package id 0\n"),
        ("temp1_input", "65000\n"),
        ("temp1_crit", "100000\n"),
    ] {
        platform.insert_file_with_permissions(
            coretemp.join(name),
            contents,
            FilePermissions::READ_ONLY,
        );
    }
    for service in fan_control_core::COMPETING_FAN_CONTROL_SERVICES {
        platform.insert_service(service, false);
    }

    let nvml = StubNvml(Ok(NvmlGpuSample::new(
        EXPECTED_UUID,
        "00000000:01:00.0",
        67.0,
    )));
    (platform, nvml, StubEnvironment::ready())
}

fn run_fixture_report(
    platform: &mut (impl IdentityBoundReadAccess + ServiceAccess),
    nvml: &mut dyn NvmlAccess,
    environment: &mut dyn PreflightEnvironment,
    declaration: &fan_control_core::CompatibilityDeclarationV1,
    observations: &[fan_control_core::CompatibilityObservation],
    record: &str,
) -> PreflightReport {
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    run_read_only_preflight(
        platform,
        nvml,
        environment,
        &PreflightInputs {
            compatibility: declaration,
            observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    )
}

struct RebindOnCpuModeRead {
    inner: FakePlatform,
}

impl IdentityBoundReadAccess for RebindOnCpuModeRead {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        IdentityBoundReadAccess::read(&mut self.inner, path)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        IdentityBoundReadAccess::list(&mut self.inner, directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        IdentityBoundReadAccess::permissions(&mut self.inner, path)
    }

    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        IdentityBoundReadAccess::identity(&mut self.inner, path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        if child == "pwm1_enable" {
            self.inner.rebind_path_identity(directory.join(child));
        }
        IdentityBoundReadAccess::read_bound(&mut self.inner, directory, expected, child)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        IdentityBoundReadAccess::list_bound(&mut self.inner, directory, expected)
    }
}

impl ServiceAccess for RebindOnCpuModeRead {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        self.inner.is_service_active(service)
    }
}

struct UnsafePermissionsAfterInitialFanAbi {
    inner: FakePlatform,
    fan_enable_permission_calls: usize,
}

impl IdentityBoundReadAccess for UnsafePermissionsAfterInitialFanAbi {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        IdentityBoundReadAccess::read(&mut self.inner, path)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        IdentityBoundReadAccess::list(&mut self.inner, directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        if path
            .file_name()
            .is_some_and(|name| name == "pwm1_enable" || name == "pwm2_enable")
        {
            self.fan_enable_permission_calls += 1;
        }
        if self.fan_enable_permission_calls > 28 {
            Ok(FilePermissions::from_mode(0o666))
        } else {
            IdentityBoundReadAccess::permissions(&mut self.inner, path)
        }
    }

    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        IdentityBoundReadAccess::identity(&mut self.inner, path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        IdentityBoundReadAccess::read_bound(&mut self.inner, directory, expected, child)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        IdentityBoundReadAccess::list_bound(&mut self.inner, directory, expected)
    }
}

impl ServiceAccess for UnsafePermissionsAfterInitialFanAbi {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        self.inner.is_service_active(service)
    }
}

#[test]
fn environment_errors_are_failures_not_panics() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    environment.available_bytes = Err(PlatformError::new(
        PlatformErrorKind::Unavailable,
        "statvfs unavailable",
    ));
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    );
    assert_eq!(
        report.result(PreflightCheck::DiskSpace).unwrap().detail(),
        "cannot inspect available disk space: statvfs unavailable"
    );
}
