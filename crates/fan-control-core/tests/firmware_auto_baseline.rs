mod support;

use std::{cell::Cell, collections::VecDeque, path::Path, rc::Rc, time::Duration};

use fan_control_core::{
    AcerHwmonDevice, AcerHwmonDiscoveryError, BaselineCleanupAttestation, BaselineObservation,
    BaselineStartingConditions, CapturedBaselineStartingConditions, Clock, EvidenceExternalPower,
    EvidenceProfile, EvidenceTimestamp, FakePlatform, FanReadbackPhase, FileIdentity,
    FilePermissions, FirmwareAutoBaselineAccess, FirmwareAutoBaselineEnvironment,
    FirmwareAutoBaselinePlan, IdentityBoundReadAccess, ObservationOutcome, PlatformError,
    PlatformOperation, RunOutcomeStatus, SampleFreshness, TelemetrySampleEvidence,
    WorkloadEvidence, parse_evidence_v1, parse_evidence_v2, run_firmware_auto_baseline,
    validate_firmware_auto_baseline_resume,
};
use support::{PROTECTED_POLICY, compatibility_declaration};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const EVIDENCE_V2_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/evidence-v2.json"
));

#[test]
fn passing_baseline_records_fixed_workload_conditions_telemetry_and_summary_without_writes() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 65_000, 54_000),
        observation(5_000, 67_000, 56_000),
    ]);
    let workload = workload();
    let envelope = envelope();

    let report = run_firmware_auto_baseline(
        &mut platform,
        &mut environment,
        &FirmwareAutoBaselinePlan {
            hwmon_root: Path::new(HWMON_ROOT),
            qualification_envelope: envelope,
            preflight_binding_sha256: "a".repeat(64),
            workload: workload.clone(),
            samples_required: 3,
        },
    )
    .expect("valid baseline plan");

    assert!(report.accepted());
    assert_eq!(report.record().schema_version, 2);
    assert_eq!(report.record().stage, "firmware-auto-baseline");
    assert_eq!(report.record().workload.as_ref(), Some(&workload));
    assert_eq!(report.record().samples.len(), 3);
    assert_eq!(
        report.record().starting_conditions_captured_at,
        Some(timestamp(500))
    );
    assert!(
        report
            .record()
            .starting_conditions_captured_at
            .unwrap()
            .monotonic_millis
            <= report
                .record()
                .workload_started_at
                .unwrap()
                .monotonic_millis
    );
    assert_eq!(report.record().commands, vec![]);
    assert_eq!(report.record().restoration_attempts, vec![]);
    assert_eq!(report.record().outcome.status, RunOutcomeStatus::Passed);
    let thermal = report.record().thermal_summary.as_ref().unwrap();
    assert_eq!(thermal.cpu_peak_millicelsius, 67_000);
    assert_eq!(thermal.gpu_peak_millicelsius, 56_000);
    assert_eq!(thermal.cpu_p95_millicelsius, 67_000);
    assert_eq!(thermal.gpu_p95_millicelsius, 56_000);
    assert_eq!(thermal.system_stable, Some(true));
    assert!(thermal.kernel_faults.is_empty());
    assert!(thermal.nvidia_faults.is_empty());
    assert_eq!(
        environment.events,
        [
            "conditions",
            "start",
            "wait",
            "capture",
            "wait",
            "capture",
            "wait",
            "capture",
            "stop",
            "cleanup"
        ]
    );
    assert!(report.record().validate().is_ok());
    let serialized = serde_json::to_string(report.record()).unwrap();
    assert!(parse_evidence_v2(&serialized).is_ok());
    assert!(parse_evidence_v1(&serialized).is_err());
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let instance: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&instance)
    );
    assert!(
        platform
            .operations()
            .iter()
            .all(|operation| !matches!(operation, PlatformOperation::Write { .. }))
    );
}

#[test]
fn resume_requires_the_exact_plan_and_current_endpoint_identities() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 65_000, 54_000),
        observation(5_000, 67_000, 56_000),
    ]);
    let plan = FirmwareAutoBaselinePlan {
        hwmon_root: Path::new(HWMON_ROOT),
        qualification_envelope: envelope(),
        preflight_binding_sha256: "a".repeat(64),
        workload: workload(),
        samples_required: 3,
    };
    let record = run_firmware_auto_baseline(&mut platform, &mut environment, &plan)
        .unwrap()
        .into_record();
    assert!(validate_firmware_auto_baseline_resume(&mut platform, &record, &plan).is_ok());

    let mut within_jitter = record.clone();
    for sample in &mut within_jitter.samples {
        sample.timestamp.monotonic_millis += 100;
        sample.timestamp.wall_unix_millis += 100;
    }
    for readback in &mut within_jitter.readbacks {
        if matches!(
            readback.phase,
            Some(FanReadbackPhase::Sample | FanReadbackPhase::Final)
        ) {
            readback.timestamp.monotonic_millis += 100;
            readback.timestamp.wall_unix_millis += 100;
        }
    }
    within_jitter.completed_at.monotonic_millis += 100;
    within_jitter.completed_at.wall_unix_millis += 100;
    validate_firmware_auto_baseline_resume(&mut platform, &within_jitter, &plan).unwrap();

    let substituted_plan = FirmwareAutoBaselinePlan {
        hwmon_root: Path::new(HWMON_ROOT),
        qualification_envelope: envelope(),
        preflight_binding_sha256: "a".repeat(64),
        workload: WorkloadEvidence {
            workload_id: "gpu-ac-v1".into(),
            ..workload()
        },
        samples_required: 3,
    };
    assert!(
        validate_firmware_auto_baseline_resume(&mut platform, &record, &substituted_plan).is_err()
    );

    let different_preflight = FirmwareAutoBaselinePlan {
        hwmon_root: Path::new(HWMON_ROOT),
        qualification_envelope: envelope(),
        preflight_binding_sha256: "b".repeat(64),
        workload: workload(),
        samples_required: 3,
    };
    assert!(
        validate_firmware_auto_baseline_resume(&mut platform, &record, &different_preflight)
            .is_err()
    );

    platform.rebind_path_identity(Path::new(HWMON_ROOT).join("hwmon0/pwm1_enable"));
    assert!(validate_firmware_auto_baseline_resume(&mut platform, &record, &plan).is_err());
}

#[test]
fn one_sample_plan_is_rejected_before_workload_start() {
    let mut platform = auto_platform();
    let mut environment =
        StubEnvironment::with_observations(vec![observation(1_000, 42_000, 39_000)]);

    let report = run(&mut platform, &mut environment, 1);

    assert!(!report.accepted());
    assert!(!environment.events.contains(&"start"));
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "invalid-baseline-plan")
    );
}

#[test]
fn either_fan_leaving_auto_aborts_before_the_next_sample_and_still_stops_before_cleanup() {
    let mut platform = ScriptedModes::new(
        auto_platform(),
        ["2", "2", "2", "2", "1", "2"],
        ["2", "2", "2", "2", "2", "2"],
    );
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 65_000, 54_000),
        observation(5_000, 67_000, 56_000),
    ]);
    environment.capture_elapsed_millis = 50;

    let report = run(&mut platform, &mut environment, 3);

    assert!(!report.accepted());
    assert_eq!(report.record().samples.len(), 2);
    let mode_fault = report
        .record()
        .faults
        .iter()
        .find(|fault| fault.code == "firmware-auto-lost")
        .unwrap();
    let failed_readback = report
        .record()
        .readbacks
        .iter()
        .find(|readback| {
            readback.phase == Some(FanReadbackPhase::Sample)
                && readback.outcome != ObservationOutcome::Confirmed
        })
        .unwrap();
    assert_eq!(mode_fault.timestamp, failed_readback.timestamp);
    assert_eq!(
        environment.events,
        [
            "conditions",
            "start",
            "wait",
            "capture",
            "wait",
            "capture",
            "stop",
            "cleanup"
        ]
    );
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| { fault.code == "firmware-auto-lost" && fault.detail.contains("CPU=1") })
    );
    assert!(report.record().readbacks.iter().any(|readback| {
        readback.value == Some(1) && readback.outcome == ObservationOutcome::Unexpected
    }));
}

#[test]
fn invalid_telemetry_throttling_absolute_abort_and_instability_each_block_acceptance() {
    let mut cases = vec![
        {
            let mut value = observation(1_000, 42_000, 39_000);
            value.sample.freshness = SampleFreshness::Invalid;
            (value, "invalid-telemetry")
        },
        {
            let mut value = observation(1_000, 42_000, 39_000);
            value.sample.cpu_thermal_throttling = Some(true);
            (value, "thermal-throttling")
        },
        (observation(1_000, 95_000, 39_000), "absolute-thermal-abort"),
        {
            let mut value = observation(1_000, 42_000, 39_000);
            value.system_stable = false;
            (value, "system-instability")
        },
    ];

    for (observation, expected_fault) in cases.drain(..) {
        let mut platform = auto_platform();
        let mut environment = StubEnvironment::with_observations(vec![observation]);
        let report = run(&mut platform, &mut environment, 2);

        assert!(!report.accepted(), "accepted {expected_fault}");
        assert!(
            report
                .record()
                .faults
                .iter()
                .any(|fault| fault.code == expected_fault),
            "missing {expected_fault}"
        );
        assert_eq!(environment.events.last(), Some(&"cleanup"));
        assert_eq!(environment.events[environment.events.len() - 2], "stop");
    }
}

#[test]
fn kernel_and_nvidia_faults_are_recorded_as_instability_and_block_acceptance() {
    let mut value = observation(1_000, 42_000, 39_000);
    value.kernel_faults.push("kernel oops".into());
    value.nvidia_faults.push("Xid 79".into());
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![value]);

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    let thermal = report.record().thermal_summary.as_ref().unwrap();
    assert_eq!(thermal.kernel_faults, ["kernel oops"]);
    assert_eq!(thermal.nvidia_faults, ["Xid 79"]);
}

#[test]
fn missed_two_second_cadence_and_workload_failures_are_evidence_not_panics() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_500, 45_000, 41_000),
    ]);
    environment.wait_drift_millis = 500;
    environment.stop_result = Err("workload would not exit".into());
    environment.cleanup_result = Err("temporary workspace busy".into());

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    for code in ["sample-cadence", "workload-stop"] {
        assert!(
            report
                .record()
                .faults
                .iter()
                .any(|fault| fault.code == code)
        );
    }
    assert!(
        environment
            .events
            .ends_with(&["stop", "contain", "cleanup"])
    );
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "cleanup")
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn final_auto_confirmation_is_required_after_cleanup() {
    let mut platform = ScriptedModes::new(
        auto_platform(),
        ["2", "2", "2", "2", "2", "1"],
        ["2", "2", "2", "2", "2", "2"],
    );
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 43_000, 40_000),
    ]);

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert!(!report.record().outcome.final_firmware_auto_confirmed);
    assert_eq!(
        environment.events,
        [
            "conditions",
            "start",
            "wait",
            "capture",
            "wait",
            "capture",
            "stop",
            "cleanup"
        ]
    );
}

#[test]
fn cleanup_failure_is_recorded_only_after_workload_stop_succeeds() {
    let mut platform = auto_platform();
    let mut environment =
        StubEnvironment::with_observations(vec![observation(1_000, 42_000, 39_000)]);
    environment.cleanup_result = Err("temporary workspace busy".into());

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "cleanup")
    );
    assert_eq!(
        environment.events[environment.events.len() - 2..],
        ["stop", "cleanup"]
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn measured_starting_conditions_replace_untrusted_plan_metadata() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 70_000, 60_000),
        observation(3_000, 71_000, 61_000),
    ]);
    environment.conditions = BaselineStartingConditions {
        ambient_millicelsius: 25_500,
        cpu_millicelsius: 70_000,
        gpu_millicelsius: 60_000,
        power_profile: EvidenceProfile::Ac,
    };

    let report = run(&mut platform, &mut environment, 2);

    assert!(report.accepted());
    let workload = report.record().workload.as_ref().unwrap();
    assert_eq!(workload.ambient_millicelsius, 25_500);
    assert_eq!(workload.starting_cpu_millicelsius, 70_000);
    assert_eq!(workload.starting_gpu_millicelsius, 60_000);
}

#[test]
fn malformed_workload_and_out_of_range_telemetry_cannot_pass() {
    let mut platform = auto_platform();
    let mut invalid_observation = observation(1_000, 42_000, 39_000);
    invalid_observation.sample.commanded_demand_basis_points = Some(10_001);
    let mut environment = StubEnvironment::with_observations(vec![invalid_observation]);

    let telemetry_report = run(&mut platform, &mut environment, 2);

    assert!(!telemetry_report.accepted());
    assert!(
        telemetry_report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "invalid-telemetry")
    );
    assert!(telemetry_report.record().validate().is_ok());

    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![]);
    let mut invalid_workload = workload();
    invalid_workload.workload_id.clear();
    let report = run_firmware_auto_baseline(
        &mut platform,
        &mut environment,
        &FirmwareAutoBaselinePlan {
            hwmon_root: Path::new(HWMON_ROOT),
            qualification_envelope: envelope(),
            preflight_binding_sha256: "a".repeat(64),
            workload: invalid_workload,
            samples_required: 1,
        },
    )
    .expect("valid qualification envelope");

    assert!(!report.accepted());
    assert!(report.record().workload.is_none());
    assert!(!environment.events.contains(&"start"));
    assert!(report.record().validate().is_ok());
}

#[test]
fn endpoint_identity_change_during_mode_read_fails_closed_before_workload_start() {
    let mut platform = RebindOnEndpointRead {
        inner: auto_platform(),
        rebound: false,
    };
    let mut environment = StubEnvironment::with_observations(vec![]);

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert!(!environment.events.contains(&"start"));
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "firmware-auto-unconfirmed")
    );
}

#[test]
fn invalid_qualification_envelope_is_rejected_before_any_baseline_action() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![]);
    let mut invalid_envelope = envelope();
    invalid_envelope.qualification_id.clear();

    let result = run_firmware_auto_baseline(
        &mut platform,
        &mut environment,
        &FirmwareAutoBaselinePlan {
            hwmon_root: Path::new(HWMON_ROOT),
            qualification_envelope: invalid_envelope,
            preflight_binding_sha256: "a".repeat(64),
            workload: workload(),
            samples_required: 2,
        },
    );

    assert!(matches!(
        result,
        Err(fan_control_core::FirmwareAutoBaselinePlanError::InvalidQualificationEnvelope(_))
    ));
    assert!(environment.events.is_empty());
    assert!(platform.operations().is_empty());
}

#[test]
fn firmware_auto_loss_at_workload_start_gate_stops_before_sampling() {
    let mut platform =
        ScriptedModes::new(auto_platform(), ["2", "2", "1", "2"], ["2", "2", "2", "2"]);
    let mut environment =
        StubEnvironment::with_observations(vec![observation(1_000, 42_000, 39_000)]);

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert_eq!(
        environment.events,
        ["conditions", "start", "stop", "cleanup"]
    );
    assert_eq!(report.record().samples, []);
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "firmware-auto-lost")
    );
}

#[test]
fn implausible_starting_conditions_and_sample_temperatures_block_acceptance() {
    for conditions in [
        BaselineStartingConditions {
            ambient_millicelsius: i32::MIN,
            ..default_conditions()
        },
        BaselineStartingConditions {
            cpu_millicelsius: 95_000,
            ..default_conditions()
        },
        BaselineStartingConditions {
            gpu_millicelsius: 85_000,
            ..default_conditions()
        },
    ] {
        let mut platform = auto_platform();
        let mut environment = StubEnvironment::with_observations(vec![]);
        environment.conditions = conditions;

        let report = run(&mut platform, &mut environment, 2);

        assert!(!report.accepted());
        assert!(!environment.events.contains(&"start"));
        assert!(report.record().workload.is_none());
    }

    let mut platform = auto_platform();
    let mut environment =
        StubEnvironment::with_observations(vec![observation(1_000, i32::MIN, 39_000)]);

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "invalid-telemetry")
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn passed_baseline_records_reject_semantically_incomplete_or_contradictory_evidence() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 65_000, 54_000),
    ]);
    let valid = run(&mut platform, &mut environment, 2).into_record();
    assert!(valid.validate().is_ok());

    let mut candidates = Vec::new();
    let mut one_sample = valid.clone();
    one_sample.samples.truncate(1);
    one_sample
        .readbacks
        .retain(|readback| readback.phase != Some(FanReadbackPhase::Sample));
    for fan in [
        fan_control_core::EvidenceFan::Cpu,
        fan_control_core::EvidenceFan::Gpu,
    ] {
        one_sample.readbacks.push(
            valid
                .readbacks
                .iter()
                .find(|readback| {
                    readback.fan == fan && readback.phase == Some(FanReadbackPhase::Sample)
                })
                .unwrap()
                .clone(),
        );
    }
    one_sample.thermal_summary = Some(fan_control_core::ThermalSummaryEvidence {
        cpu_peak_millicelsius: one_sample.samples[0].cpu_millicelsius.unwrap(),
        gpu_peak_millicelsius: one_sample.samples[0].gpu_millicelsius.unwrap(),
        cpu_p95_millicelsius: one_sample.samples[0].cpu_millicelsius.unwrap(),
        gpu_p95_millicelsius: one_sample.samples[0].gpu_millicelsius.unwrap(),
        cpu_final_slope_millicelsius_per_minute: 0,
        gpu_final_slope_millicelsius_per_minute: 0,
        system_stable: Some(true),
        kernel_faults: vec![],
        nvidia_faults: vec![],
    });
    candidates.push(one_sample);
    let mut missing_starting_conditions_time = valid.clone();
    missing_starting_conditions_time.starting_conditions_captured_at = None;
    candidates.push(missing_starting_conditions_time);
    let mut late_starting_conditions = valid.clone();
    late_starting_conditions.starting_conditions_captured_at = Some(timestamp(
        valid.workload_started_at.unwrap().monotonic_millis + 1,
    ));
    candidates.push(late_starting_conditions);
    let mut conditions_before_auto_confirmation = valid.clone();
    for readback in &mut conditions_before_auto_confirmation.readbacks {
        if matches!(
            readback.phase,
            Some(
                FanReadbackPhase::Initial
                    | FanReadbackPhase::StartGate
                    | FanReadbackPhase::WorkloadStarted
            )
        ) {
            readback.timestamp = timestamp(501);
        }
    }
    conditions_before_auto_confirmation.workload_started_at = Some(timestamp(501));
    candidates.push(conditions_before_auto_confirmation);
    let mut throttling = valid.clone();
    throttling.samples[0].cpu_thermal_throttling = Some(true);
    candidates.push(throttling);
    let mut invalid_sample = valid.clone();
    invalid_sample.samples[0].freshness = SampleFreshness::Invalid;
    candidates.push(invalid_sample);
    let mut wrong_profile = valid.clone();
    wrong_profile.samples[0].selected_profile = Some(EvidenceProfile::Battery);
    candidates.push(wrong_profile);
    let mut missed_cadence = valid.clone();
    missed_cadence.samples[1].timestamp.monotonic_millis += 500;
    missed_cadence.samples[1].timestamp.wall_unix_millis += 500;
    candidates.push(missed_cadence);
    let mut wrong_summary = valid.clone();
    wrong_summary
        .thermal_summary
        .as_mut()
        .unwrap()
        .cpu_peak_millicelsius += 1;
    candidates.push(wrong_summary);
    let mut missing_readback = valid.clone();
    missing_readback.readbacks.pop();
    candidates.push(missing_readback);
    let mut snapshot_only_readbacks = valid.clone();
    for readback in &mut snapshot_only_readbacks.readbacks {
        readback.timestamp = snapshot_only_readbacks.started_at;
    }
    candidates.push(snapshot_only_readbacks);
    let mut rebound_endpoint = valid.clone();
    rebound_endpoint
        .readbacks
        .iter_mut()
        .find(|readback| readback.phase == Some(FanReadbackPhase::Sample))
        .unwrap()
        .endpoint_identity = "different-device-999-inode-999".into();
    candidates.push(rebound_endpoint);

    for candidate in candidates {
        assert!(candidate.validate().is_err());
        assert!(serde_json::to_string(&candidate).is_err());
    }
}

#[test]
fn stale_source_timestamp_cannot_be_rewritten_into_a_fresh_sample() {
    let mut platform = auto_platform();
    let mut environment =
        StubEnvironment::with_observations(vec![observation(500, 42_000, 39_000)]);
    environment.preserve_observation_timestamp = true;

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert_eq!(report.record().samples[0].timestamp.monotonic_millis, 500);
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "sample-cadence")
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn out_of_run_source_timestamps_are_rejected_with_serializable_provenance() {
    for source_millis in [0, 99_999] {
        let mut platform = auto_platform();
        let mut environment =
            StubEnvironment::with_observations(vec![observation(source_millis, 42_000, 39_000)]);
        environment.preserve_observation_timestamp = true;

        let report = run(&mut platform, &mut environment, 2);

        assert!(!report.accepted());
        assert_eq!(report.record().samples[0].timestamp.monotonic_millis, 2_500);
        assert!(report.record().faults.iter().any(|fault| {
            fault.code == "invalid-telemetry" && fault.detail.contains(&source_millis.to_string())
        }));
        assert!(report.record().validate().is_ok());
        assert!(serde_json::to_string(report.record()).is_ok());
    }
}

#[test]
fn mode_readbacks_use_their_post_capture_observation_time() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 43_000, 40_000),
    ]);
    environment.capture_elapsed_millis = 50;

    let report = run(&mut platform, &mut environment, 2);

    assert!(report.accepted());
    for sample in &report.record().samples {
        assert_eq!(
            report
                .record()
                .readbacks
                .iter()
                .filter(|readback| {
                    readback.phase == Some(FanReadbackPhase::Sample)
                        && readback.timestamp.monotonic_millis
                            == sample.timestamp.monotonic_millis + 50
                })
                .count(),
            2
        );
    }
}

#[test]
fn source_measurement_and_workload_start_times_survive_callback_latency() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 43_000, 40_000),
    ]);
    environment.conditions_elapsed_millis = 75;
    environment.start_elapsed_millis = 50;

    let report = run(&mut platform, &mut environment, 2);

    assert!(report.accepted());
    assert_eq!(
        report.record().starting_conditions_captured_at,
        Some(timestamp(500))
    );
    assert_eq!(report.record().workload_started_at, Some(timestamp(575)));
    assert_eq!(report.record().samples[0].timestamp, timestamp(575 + 2_000));
}

#[test]
fn cleanup_fan_control_writes_are_attested_and_block_acceptance() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 43_000, 40_000),
    ]);
    environment.cleanup_fan_control_write_count = 1;

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert!(
        report.record().faults.iter().any(|fault| {
            fault.code == "cleanup-fan-control-write" && fault.detail.contains("1")
        })
    );
    assert_eq!(
        &environment.events[environment.events.len() - 2..],
        ["stop", "cleanup"]
    );
}

#[test]
fn telemetry_callback_exceeding_the_cadence_deadline_stops_workload_immediately() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 43_000, 40_000),
    ]);
    environment.capture_elapsed_millis = 101;

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert_eq!(
        environment.events,
        ["conditions", "start", "wait", "capture", "stop", "cleanup"]
    );
    assert!(report.record().faults.iter().any(|fault| {
        fault.code == "sample-cadence" && fault.detail.contains("capture exceeded")
    }));
}

#[test]
fn late_start_and_stop_callbacks_are_deadline_failures() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![]);
    environment.start_elapsed_millis = 10_001;

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert_eq!(
        environment.events,
        ["conditions", "start", "stop", "cleanup"]
    );
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| { fault.code == "workload-start" && fault.detail.contains("exceeded") })
    );

    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![
        observation(1_000, 42_000, 39_000),
        observation(3_000, 43_000, 40_000),
    ]);
    environment.stop_elapsed_millis = 5_001;

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| { fault.code == "workload-stop" && fault.detail.contains("exceeded") })
    );
}

#[test]
fn ambiguous_workload_start_failure_still_stops_before_cleanup() {
    let mut platform = auto_platform();
    let mut environment = StubEnvironment::with_observations(vec![]);
    environment.start_result = Err("launcher lost acknowledgement".into());

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert_eq!(
        environment.events,
        ["conditions", "start", "stop", "cleanup"]
    );
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "workload-start")
    );
}

#[test]
fn bounded_mode_check_failure_after_start_stops_workload_before_sampling() {
    let running = Rc::new(Cell::new(false));
    let mut platform = TimeoutWhileRunning {
        inner: auto_platform(),
        running: Rc::clone(&running),
    };
    let mut environment = StubEnvironment::with_observations(vec![]);
    environment.running = Some(running);

    let report = run(&mut platform, &mut environment, 2);

    assert!(!report.accepted());
    assert_eq!(
        environment.events,
        ["conditions", "start", "stop", "cleanup"]
    );
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "firmware-auto-lost" && fault.detail.contains("deadline"))
    );
}

fn run<P: FirmwareAutoBaselineAccess>(
    platform: &mut P,
    environment: &mut StubEnvironment,
    samples_required: usize,
) -> fan_control_core::FirmwareAutoBaselineReport {
    run_firmware_auto_baseline(
        platform,
        environment,
        &FirmwareAutoBaselinePlan {
            hwmon_root: Path::new(HWMON_ROOT),
            qualification_envelope: envelope(),
            preflight_binding_sha256: "a".repeat(64),
            workload: workload(),
            samples_required,
        },
    )
    .expect("valid baseline plan")
}

fn workload() -> WorkloadEvidence {
    WorkloadEvidence {
        workload_id: "cpu-ac-v1".into(),
        command: vec![
            "/usr/lib/pt31553-fan-control/workloads/cpu".into(),
            "--fixed".into(),
        ],
        version: "1.0.0".into(),
        power_profile: EvidenceProfile::Ac,
        ambient_millicelsius: 24_000,
        starting_cpu_millicelsius: 42_000,
        starting_gpu_millicelsius: 39_000,
    }
}

fn envelope() -> fan_control_core::QualificationEnvelopeIdentityV1 {
    fan_control_core::QualificationEnvelopeIdentityV1 {
        qualification_record_schema_version: 1,
        qualification_id: "pt31553-v1".into(),
        policy_version: "1.0.0".into(),
        protected_policy_sha256: "a".repeat(64),
        compatibility: compatibility_declaration(PROTECTED_POLICY),
    }
}

fn observation(
    monotonic_millis: u64,
    cpu_millicelsius: i32,
    gpu_millicelsius: i32,
) -> BaselineObservation {
    BaselineObservation {
        sample: TelemetrySampleEvidence {
            timestamp: timestamp(monotonic_millis),
            cpu_millicelsius: Some(cpu_millicelsius),
            gpu_millicelsius: Some(gpu_millicelsius),
            freshness: SampleFreshness::Fresh,
            external_power: Some(EvidenceExternalPower::Ac),
            selected_profile: Some(EvidenceProfile::Ac),
            cpu_source_demand_basis_points: Some(4_000),
            gpu_source_demand_basis_points: Some(3_000),
            cpu_utilization_basis_points: None,
            gpu_utilization_basis_points: None,
            commanded_demand_basis_points: Some(4_000),
            cpu_thermal_throttling: Some(false),
            gpu_thermal_throttling: Some(false),
        },
        system_stable: true,
        kernel_faults: vec![],
        nvidia_faults: vec![],
    }
}

fn timestamp(monotonic_millis: u64) -> EvidenceTimestamp {
    EvidenceTimestamp {
        monotonic_millis,
        wall_unix_millis: 1_787_691_600_000 + monotonic_millis as i64,
    }
}

fn default_conditions() -> BaselineStartingConditions {
    BaselineStartingConditions {
        ambient_millicelsius: 24_000,
        cpu_millicelsius: 42_000,
        gpu_millicelsius: 39_000,
        power_profile: EvidenceProfile::Ac,
    }
}

struct StubEnvironment {
    observations: VecDeque<BaselineObservation>,
    events: Vec<&'static str>,
    now: u64,
    conditions: BaselineStartingConditions,
    wait_drift_millis: u64,
    start_result: Result<(), String>,
    stop_result: Result<(), String>,
    containment_result: Result<(), String>,
    cleanup_result: Result<(), String>,
    cleanup_fan_control_write_count: u64,
    running: Option<Rc<Cell<bool>>>,
    preserve_observation_timestamp: bool,
    capture_elapsed_millis: u64,
    conditions_elapsed_millis: u64,
    start_elapsed_millis: u64,
    stop_elapsed_millis: u64,
}

impl StubEnvironment {
    fn with_observations(observations: Vec<BaselineObservation>) -> Self {
        Self {
            observations: observations.into(),
            events: vec![],
            now: 500,
            conditions: default_conditions(),
            wait_drift_millis: 0,
            start_result: Ok(()),
            stop_result: Ok(()),
            containment_result: Ok(()),
            cleanup_result: Ok(()),
            cleanup_fan_control_write_count: 0,
            running: None,
            preserve_observation_timestamp: false,
            capture_elapsed_millis: 0,
            conditions_elapsed_millis: 0,
            start_elapsed_millis: 0,
            stop_elapsed_millis: 0,
        }
    }
}

impl FirmwareAutoBaselineEnvironment for StubEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        timestamp(self.now)
    }

    fn capture_starting_conditions(
        &mut self,
    ) -> Result<CapturedBaselineStartingConditions, String> {
        self.events.push("conditions");
        let captured_at = timestamp(self.now);
        self.now = self.now.saturating_add(self.conditions_elapsed_millis);
        Ok(CapturedBaselineStartingConditions {
            conditions: self.conditions,
            captured_at,
        })
    }

    fn start_workload(
        &mut self,
        _workload: &WorkloadEvidence,
        _deadline_monotonic_millis: u64,
    ) -> Result<EvidenceTimestamp, String> {
        self.events.push("start");
        let started_at = timestamp(self.now);
        if self.start_result.is_ok() {
            if let Some(running) = &self.running {
                running.set(true);
            }
        }
        self.now = self.now.saturating_add(self.start_elapsed_millis);
        self.start_result.clone().map(|()| started_at)
    }

    fn wait_until(
        &mut self,
        monotonic_millis: u64,
        _deadline_monotonic_millis: u64,
    ) -> Result<(), String> {
        self.events.push("wait");
        self.now = monotonic_millis.saturating_add(self.wait_drift_millis);
        Ok(())
    }

    fn capture_observation(
        &mut self,
        _deadline_monotonic_millis: u64,
    ) -> Result<BaselineObservation, String> {
        self.events.push("capture");
        let mut observation = self
            .observations
            .pop_front()
            .ok_or_else(|| "telemetry source exhausted".to_owned())?;
        if !self.preserve_observation_timestamp {
            observation.sample.timestamp = timestamp(self.now);
        }
        self.now = self.now.saturating_add(self.capture_elapsed_millis);
        Ok(observation)
    }

    fn stop_workload(&mut self, _deadline_monotonic_millis: u64) -> Result<(), String> {
        self.events.push("stop");
        self.now = self.now.saturating_add(self.stop_elapsed_millis);
        if self.stop_result.is_ok() {
            if let Some(running) = &self.running {
                running.set(false);
            }
        }
        self.stop_result.clone()
    }

    fn contain_workload(&mut self, _deadline_monotonic_millis: u64) -> Result<(), String> {
        self.events.push("contain");
        if self.containment_result.is_ok() {
            if let Some(running) = &self.running {
                running.set(false);
            }
        }
        self.containment_result.clone()
    }

    fn cleanup_after_workload(&mut self) -> Result<BaselineCleanupAttestation, String> {
        self.events.push("cleanup");
        self.cleanup_result
            .clone()
            .map(|()| BaselineCleanupAttestation {
                fan_control_write_count: self.cleanup_fan_control_write_count,
            })
    }
}

struct ScriptedModes {
    inner: FakePlatform,
    cpu: VecDeque<String>,
    gpu: VecDeque<String>,
}

impl ScriptedModes {
    fn new(
        inner: FakePlatform,
        cpu: impl IntoIterator<Item = &'static str>,
        gpu: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        Self {
            inner,
            cpu: cpu.into_iter().map(str::to_owned).collect(),
            gpu: gpu.into_iter().map(str::to_owned).collect(),
        }
    }
}

impl IdentityBoundReadAccess for ScriptedModes {
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
        match child {
            "pwm1_enable" => self.cpu.pop_front().ok_or_else(|| exhausted("CPU mode")),
            "pwm2_enable" => self.gpu.pop_front().ok_or_else(|| exhausted("GPU mode")),
            _ => IdentityBoundReadAccess::read_bound(&mut self.inner, directory, expected, child),
        }
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        IdentityBoundReadAccess::list_bound(&mut self.inner, directory, expected)
    }
}

impl Clock for ScriptedModes {
    fn monotonic_now(&mut self) -> Duration {
        Clock::monotonic_now(&mut self.inner)
    }

    fn delay(&mut self, duration: Duration) {
        Clock::delay(&mut self.inner, duration);
    }
}

impl FirmwareAutoBaselineAccess for ScriptedModes {
    fn baseline_abi_is_current_before(
        &mut self,
        device: &AcerHwmonDevice,
        deadline: Duration,
    ) -> Result<bool, AcerHwmonDiscoveryError> {
        FirmwareAutoBaselineAccess::baseline_abi_is_current_before(
            &mut self.inner,
            device,
            deadline,
        )
    }

    fn baseline_read_endpoint_before(
        &mut self,
        device: &AcerHwmonDevice,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError> {
        match child {
            "pwm1_enable" => self.cpu.pop_front().ok_or_else(|| exhausted("CPU mode")),
            "pwm2_enable" => self.gpu.pop_front().ok_or_else(|| exhausted("GPU mode")),
            _ => FirmwareAutoBaselineAccess::baseline_read_endpoint_before(
                &mut self.inner,
                device,
                child,
                expected_child,
                deadline,
            ),
        }
    }
}

struct RebindOnEndpointRead {
    inner: FakePlatform,
    rebound: bool,
}

impl IdentityBoundReadAccess for RebindOnEndpointRead {
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

impl Clock for RebindOnEndpointRead {
    fn monotonic_now(&mut self) -> Duration {
        Clock::monotonic_now(&mut self.inner)
    }

    fn delay(&mut self, duration: Duration) {
        Clock::delay(&mut self.inner, duration);
    }
}

impl FirmwareAutoBaselineAccess for RebindOnEndpointRead {
    fn baseline_abi_is_current_before(
        &mut self,
        device: &AcerHwmonDevice,
        deadline: Duration,
    ) -> Result<bool, AcerHwmonDiscoveryError> {
        FirmwareAutoBaselineAccess::baseline_abi_is_current_before(
            &mut self.inner,
            device,
            deadline,
        )
    }

    fn baseline_read_endpoint_before(
        &mut self,
        device: &AcerHwmonDevice,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError> {
        if !self.rebound {
            self.inner.rebind_path_identity(device.root().join(child));
            self.rebound = true;
        }
        FirmwareAutoBaselineAccess::baseline_read_endpoint_before(
            &mut self.inner,
            device,
            child,
            expected_child,
            deadline,
        )
    }
}

struct TimeoutWhileRunning {
    inner: FakePlatform,
    running: Rc<Cell<bool>>,
}

impl IdentityBoundReadAccess for TimeoutWhileRunning {
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

impl Clock for TimeoutWhileRunning {
    fn monotonic_now(&mut self) -> Duration {
        Clock::monotonic_now(&mut self.inner)
    }

    fn delay(&mut self, duration: Duration) {
        Clock::delay(&mut self.inner, duration);
    }
}

impl FirmwareAutoBaselineAccess for TimeoutWhileRunning {
    fn baseline_abi_is_current_before(
        &mut self,
        device: &AcerHwmonDevice,
        deadline: Duration,
    ) -> Result<bool, AcerHwmonDiscoveryError> {
        if self.running.get() {
            Err(AcerHwmonDiscoveryError::Platform(PlatformError::new(
                fan_control_core::PlatformErrorKind::TimedOut,
                "mode check exceeded its deadline",
            )))
        } else {
            FirmwareAutoBaselineAccess::baseline_abi_is_current_before(
                &mut self.inner,
                device,
                deadline,
            )
        }
    }

    fn baseline_read_endpoint_before(
        &mut self,
        device: &AcerHwmonDevice,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError> {
        FirmwareAutoBaselineAccess::baseline_read_endpoint_before(
            &mut self.inner,
            device,
            child,
            expected_child,
            deadline,
        )
    }
}

fn exhausted(what: &str) -> PlatformError {
    PlatformError::new(
        fan_control_core::PlatformErrorKind::Unavailable,
        format!("{what} script exhausted"),
    )
}

fn auto_platform() -> FakePlatform {
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
    platform
}
