mod support;

use std::{collections::VecDeque, path::Path, sync::OnceLock};

use fan_control_core::{
    BaselineCleanupAttestation, BaselineObservation, BaselineStartingConditions,
    CapturedBaselineStartingConditions, CapturedMatchedWorkloadStartingConditions,
    EvidenceExternalPower, EvidenceFan, EvidenceProfile, EvidenceTimestamp, FakePlatform, Fan,
    FanCommandEvidence, FanControlField, FanReadbackEvidence, FanReadbackField, FaultEvidence,
    FilePermissions, FirmwareAutoBaselineEnvironment, FirmwareAutoBaselinePlan,
    MINIMUM_MATCHED_WORKLOAD_SAMPLES, MatchedWorkloadEnvironment, MatchedWorkloadFanRestoration,
    MatchedWorkloadObservation, MatchedWorkloadPlan, MatchedWorkloadStartingConditions,
    MatchedWorkloadTachometerCalibrations, ObservationOutcome, RestorationOutcome,
    RunOutcomeStatus, SampleFreshness, TelemetrySampleEvidence, WorkloadEvidence,
    parse_evidence_v2, run_firmware_auto_baseline, run_matched_custom_workload,
};
use support::{PROTECTED_POLICY, compatibility_declaration, completed_calibration_record};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const JSON_SCHEMA_V2: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/evidence-v2.json"
));

#[test]
fn passing_custom_run_is_compared_with_baseline_and_requests_its_required_repeat() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let report = run_matched_custom_workload(
        &mut environment,
        &MatchedWorkloadPlan {
            baseline: &baseline,
            previous_passing_runs: &[],
            tachometer_calibrations: tachometer_calibrations(),
        },
    )
    .expect("valid matched-workload plan");

    assert!(report.accepted(), "{:#?}", report.record());
    assert_eq!(report.record().stage, "matched-workload");
    assert_eq!(report.record().outcome.status, RunOutcomeStatus::Passed);
    assert!(report.record().outcome.another_passing_run_required);
    assert_eq!(
        &environment.events[..3],
        ["conditions", "enter-custom", "start"]
    );
    assert_eq!(
        &environment.events[environment.events.len() - 3..],
        ["stop", "restore-cpu", "restore-gpu"]
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn custom_run_must_cover_the_exact_baseline_sample_count() {
    let baseline = passing_baseline_with_samples(MINIMUM_MATCHED_WORKLOAD_SAMPLES + 1);
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert_eq!(
        report.record().samples.len(),
        MINIMUM_MATCHED_WORKLOAD_SAMPLES
    );
    assert!(report.record().faults.iter().any(|fault| {
        fault.code == "invalid-telemetry"
            && fault.detail.contains("cannot capture required telemetry")
    }));
    assert_eq!(report.record().restoration_attempts.len(), 2);
    assert!(report.record().validate().is_ok());
}

#[test]
fn custom_run_preserves_an_accepted_baseline_cadence_and_duration() {
    let baseline = passing_baseline_with_cadence(2_100);
    let observations = (1..=MINIMUM_MATCHED_WORKLOAD_SAMPLES)
        .map(|n| custom_observation(10_000 + n as u64 * 2_100, 65_000, 54_000))
        .collect();
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(report.accepted(), "{:#?}", report.record());
    let workload_started_at = report.record().workload_started_at.unwrap();
    assert_eq!(
        report
            .record()
            .samples
            .last()
            .unwrap()
            .timestamp
            .monotonic_millis
            - workload_started_at.monotonic_millis,
        baseline.samples.last().unwrap().timestamp.monotonic_millis
            - baseline.workload_started_at.unwrap().monotonic_millis
    );
}

#[test]
fn baseline_below_the_matched_sample_minimum_is_rejected_before_custom_control() {
    let baseline = valid_five_minute_baseline_below_matched_minimum();
    assert!(baseline.validate().is_ok());
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let result = run_matched_custom_workload(
        &mut environment,
        &MatchedWorkloadPlan {
            baseline: &baseline,
            previous_passing_runs: &[],
            tachometer_calibrations: tachometer_calibrations(),
        },
    );

    assert!(matches!(
        result,
        Err(fan_control_core::MatchedWorkloadPlanError::BaselineNotAccepted)
    ));
    assert!(environment.events.is_empty());
}

#[test]
fn settled_out_of_band_rpm_aborts_then_restores_both_fans() {
    let baseline = passing_baseline();
    let mut observations = passing_custom_observations();
    for observation in &mut observations {
        observation
            .readbacks
            .iter_mut()
            .find(|readback| {
                readback.fan == EvidenceFan::Cpu && readback.field == FanReadbackField::Rpm
            })
            .unwrap()
            .value = Some(20_000);
    }
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(report.record().faults.iter().any(|fault| {
        fault.code == "fan-feedback-loss" && fault.detail.contains("qualified ±30% band")
    }));
    assert!(report.record().samples.len() < baseline.samples.len());
    assert_eq!(
        &environment.events[environment.events.len() - 3..],
        ["stop", "restore-cpu", "restore-gpu"]
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn unqualified_tachometer_calibration_is_rejected_before_custom_control() {
    let baseline = passing_baseline();
    let mut cpu = tachometer_calibrations().cpu.clone();
    cpu.calibration[0].protocol_checkpoint = None;
    let calibrations = tachometer_calibrations();
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let result = run_matched_custom_workload(
        &mut environment,
        &MatchedWorkloadPlan {
            baseline: &baseline,
            previous_passing_runs: &[],
            tachometer_calibrations: MatchedWorkloadTachometerCalibrations {
                cpu: &cpu,
                gpu: calibrations.gpu,
            },
        },
    );

    assert!(matches!(
        result,
        Err(
            fan_control_core::MatchedWorkloadPlanError::InvalidCalibration {
                fan: EvidenceFan::Cpu
            }
        )
    ));
    assert!(environment.events.is_empty());
}

#[test]
fn calibration_record_must_match_the_qualification_envelope() {
    let baseline = passing_baseline();
    let calibrations = tachometer_calibrations();
    let mut cpu = calibrations.cpu.clone();
    cpu.qualification_envelope.protected_policy_sha256 = "b".repeat(64);
    assert!(cpu.validate().is_ok());
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let result = run_matched_custom_workload(
        &mut environment,
        &MatchedWorkloadPlan {
            baseline: &baseline,
            previous_passing_runs: &[],
            tachometer_calibrations: MatchedWorkloadTachometerCalibrations {
                cpu: &cpu,
                gpu: calibrations.gpu,
            },
        },
    );

    assert!(matches!(
        result,
        Err(
            fan_control_core::MatchedWorkloadPlanError::InvalidCalibration {
                fan: EvidenceFan::Cpu
            }
        )
    ));
    assert!(environment.events.is_empty());
}

#[test]
fn stale_precommand_readbacks_are_rejected() {
    let baseline = passing_baseline();
    let mut observation = custom_observation(11_950, 65_000, 54_000);
    for command in &mut observation.commands {
        command.timestamp = timestamp(12_000);
    }
    for readback in &mut observation.readbacks {
        readback.timestamp = timestamp(11_990);
    }
    let mut environment = CustomEnvironment::new(vec![observation]);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(report.record().faults.iter().any(|fault| {
        fault.code == "mode-pwm-mismatch" || fault.code == "invalid-control-evidence"
    }));
    assert!(report.record().validate().is_ok());
}

#[test]
fn pwm_below_the_qualified_floor_is_rejected() {
    let baseline = passing_baseline();
    let mut observation = custom_observation(12_000, 65_000, 54_000);
    observation.commands[0].value = 50;
    observation
        .readbacks
        .iter_mut()
        .find(|readback| {
            readback.fan == EvidenceFan::Cpu && readback.field == FanReadbackField::Pwm
        })
        .unwrap()
        .value = Some(50);
    let mut environment = CustomEnvironment::new(vec![observation]);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "invalid-control-evidence")
    );
}

#[test]
fn transient_zero_rpm_is_allowed_within_a_reissued_commands_response_window() {
    let baseline = passing_baseline();
    let mut observations = passing_custom_observations();
    observations[10]
        .commands
        .iter_mut()
        .find(|command| command.fan == EvidenceFan::Cpu)
        .unwrap()
        .value = 200;
    observations[10]
        .readbacks
        .iter_mut()
        .find(|readback| {
            readback.fan == EvidenceFan::Cpu && readback.field == FanReadbackField::Pwm
        })
        .unwrap()
        .value = Some(200);
    observations[10]
        .readbacks
        .iter_mut()
        .find(|readback| {
            readback.fan == EvidenceFan::Cpu && readback.field == FanReadbackField::Rpm
        })
        .unwrap()
        .value = Some(0);
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(report.accepted(), "{:#?}", report.record());
    assert!(report.record().validate().is_ok());
}

#[test]
fn a_new_confirmed_pwm_gets_its_own_tachometer_response_window() {
    let baseline = passing_baseline();
    let mut observations = passing_custom_observations();
    for observation in &mut observations[..5] {
        for command in &mut observation.commands {
            command.value = 200;
        }
        for readback in &mut observation.readbacks {
            match readback.field {
                FanReadbackField::Pwm => readback.value = Some(200),
                FanReadbackField::Rpm => readback.value = Some(0),
                FanReadbackField::Enable => {}
            }
        }
    }
    for observation in &mut observations[3..5] {
        for command in &mut observation.commands {
            command.value = 128;
        }
        for readback in &mut observation.readbacks {
            if readback.field == FanReadbackField::Pwm {
                readback.value = Some(128);
            }
        }
    }
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(report.accepted(), "{:#?}", report.record());
}

#[test]
fn changing_pwm_cannot_extend_an_unsettled_response_forever() {
    let baseline = passing_baseline();
    let mut observations = passing_custom_observations();
    for (index, observation) in observations.iter_mut().enumerate() {
        let pwm = if index % 2 == 0 { 128 } else { 200 };
        for command in &mut observation.commands {
            command.value = pwm;
        }
        for readback in &mut observation.readbacks {
            if readback.field == FanReadbackField::Pwm {
                readback.value = Some(pwm);
            } else if readback.field == FanReadbackField::Rpm {
                readback.value = Some(20_000);
            }
        }
    }
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "fan-feedback-loss")
    );
    assert_eq!(report.record().samples.len(), baseline.samples.len());
}

#[test]
fn unexpected_enable_commands_produce_a_failed_record() {
    let baseline = passing_baseline();
    let mut observations = passing_custom_observations();
    let mut enable = observations[0].commands[0].clone();
    enable.field = FanControlField::Enable;
    enable.value = 1;
    observations[0].commands.push(enable);
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(report.record().faults.iter().any(|fault| {
        fault.code == "invalid-control-evidence" && fault.detail.contains("malformed")
    }));
    assert!(report.record().validate().is_ok());
}

#[test]
fn matched_workload_evidence_round_trips_and_requires_a_valid_baseline_binding() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(passing_custom_observations());
    let record = run_custom(&baseline, &mut environment, &[]).into_record();
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA_V2).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let source = serde_json::to_string(&record).unwrap();
    let value: serde_json::Value = serde_json::from_str(&source).unwrap();

    assert_eq!(parse_evidence_v2(&source).unwrap(), record);
    assert!(validator.is_valid(&value));
    assert_eq!(record.calibration.len(), 2);

    let mut invalid_rpm = value.clone();
    let readbacks = invalid_rpm["readbacks"].as_array_mut().unwrap();
    let settled_rpm = readbacks
        .iter_mut()
        .rev()
        .find(|readback| readback["field"] == "rpm")
        .unwrap();
    settled_rpm["value"] = 0.into();
    assert!(parse_evidence_v2(&invalid_rpm.to_string()).is_err());

    let mut missing = value.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("baseline_binding_sha256");
    assert!(!validator.is_valid(&missing));
    assert!(parse_evidence_v2(&missing.to_string()).is_err());

    let mut unsuccessful_auto_write = value.clone();
    unsuccessful_auto_write["restoration_attempts"][0]["auto_write_succeeded"] = false.into();
    assert!(!validator.is_valid(&unsuccessful_auto_write));

    let mut malformed = value;
    malformed["baseline_binding_sha256"] = "not-a-sha256".into();
    assert!(!validator.is_valid(&malformed));
    assert!(parse_evidence_v2(&malformed.to_string()).is_err());
}

#[test]
fn starting_conditions_must_match_ambient_cpu_gpu_and_profile_before_custom_control() {
    let baseline = passing_baseline();
    let cases = [
        MatchedWorkloadStartingConditions {
            ambient_millicelsius: 26_001,
            ..default_custom_conditions()
        },
        MatchedWorkloadStartingConditions {
            cpu_millicelsius: 45_001,
            ..default_custom_conditions()
        },
        MatchedWorkloadStartingConditions {
            gpu_millicelsius: 42_001,
            ..default_custom_conditions()
        },
        MatchedWorkloadStartingConditions {
            power_profile: EvidenceProfile::Battery,
            ..default_custom_conditions()
        },
    ];

    for conditions in cases {
        let mut environment = CustomEnvironment::new(vec![]);
        environment.conditions = conditions;

        let report = run_custom(&baseline, &mut environment, &[]);

        assert!(!report.accepted());
        assert_eq!(environment.events, ["conditions"]);
        assert!(
            report
                .record()
                .faults
                .iter()
                .any(|fault| fault.code == "starting-conditions-not-comparable")
        );
        assert!(report.record().validate().is_ok());
    }
}

#[test]
fn late_starting_condition_capture_never_enters_custom_control() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(passing_custom_observations());
    environment.failure = Some(CallbackFailure::LateConditions);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert_eq!(environment.events, ["conditions"]);
    assert!(
        report.record().faults.iter().any(|fault| {
            fault.code == "starting-conditions" && fault.detail.contains("deadline")
        })
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn starting_condition_comparability_limits_are_inclusive() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(passing_custom_observations());
    environment.conditions = MatchedWorkloadStartingConditions {
        ambient_millicelsius: 26_000,
        cpu_millicelsius: 45_000,
        gpu_millicelsius: 42_000,
        power_profile: EvidenceProfile::Ac,
    };

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(report.accepted(), "{:#?}", report.record());
}

#[test]
fn absolute_abort_starting_temperature_never_enters_custom_control() {
    let baseline = passing_baseline_with_starting_temperatures(92_000, 82_000);
    for conditions in [
        MatchedWorkloadStartingConditions {
            cpu_millicelsius: 95_000,
            gpu_millicelsius: 82_000,
            ..default_custom_conditions()
        },
        MatchedWorkloadStartingConditions {
            cpu_millicelsius: 92_000,
            gpu_millicelsius: 85_000,
            ..default_custom_conditions()
        },
    ] {
        let mut environment = CustomEnvironment::new(vec![]);
        environment.conditions = conditions;

        let report = run_custom(&baseline, &mut environment, &[]);

        assert!(!report.accepted());
        assert_eq!(environment.events, ["conditions"]);
        assert!(
            report
                .record()
                .faults
                .iter()
                .any(|fault| fault.code == "starting-conditions")
        );
    }
}

#[test]
fn each_runtime_abort_stops_workload_before_restoring_both_fans() {
    let baseline = passing_baseline();
    let mut cases = Vec::new();

    let thermal = custom_observation(12_000, 95_000, 54_000);
    cases.push(("absolute-thermal-abort", thermal));
    let gpu_thermal = custom_observation(12_000, 65_000, 85_000);
    cases.push(("absolute-thermal-abort", gpu_thermal));
    let mut throttling = custom_observation(12_000, 65_000, 54_000);
    throttling.sample.cpu_thermal_throttling = Some(true);
    cases.push(("thermal-throttling", throttling));
    let mut gpu_throttling = custom_observation(12_000, 65_000, 54_000);
    gpu_throttling.sample.gpu_thermal_throttling = Some(true);
    cases.push(("thermal-throttling", gpu_throttling));
    let mut stale = custom_observation(12_000, 65_000, 54_000);
    stale.sample.freshness = SampleFreshness::Stale;
    cases.push(("invalid-telemetry", stale));
    let implausibly_low = custom_observation(12_000, -40_001, 54_000);
    cases.push(("invalid-telemetry", implausibly_low));
    let implausibly_high = custom_observation(12_000, 65_000, 150_001);
    cases.push(("invalid-telemetry", implausibly_high));
    let mut controller = custom_observation(12_000, 65_000, 54_000);
    controller.controller_fault = Some("control cycle failed".into());
    cases.push(("controller-fault", controller));
    let mut feedback = custom_observation(12_000, 65_000, 54_000);
    feedback.readbacks.retain(|readback| {
        !(readback.fan == EvidenceFan::Gpu && readback.field == FanReadbackField::Rpm)
    });
    cases.push(("fan-feedback-loss", feedback));
    let mut mismatch = custom_observation(12_000, 65_000, 54_000);
    mismatch
        .readbacks
        .iter_mut()
        .find(|readback| {
            readback.fan == EvidenceFan::Gpu && readback.field == FanReadbackField::Pwm
        })
        .unwrap()
        .value = Some(127);
    cases.push(("mode-pwm-mismatch", mismatch));
    let mut unstable = custom_observation(12_000, 65_000, 54_000);
    unstable.system_stable = false;
    cases.push(("system-instability", unstable));
    let mut kernel = custom_observation(12_000, 65_000, 54_000);
    kernel.kernel_faults.push("kernel oops".into());
    cases.push(("kernel-instability", kernel));
    let mut nvidia = custom_observation(12_000, 65_000, 54_000);
    nvidia.nvidia_faults.push("Xid 79".into());
    cases.push(("nvidia-instability", nvidia));

    for (expected_fault, observation) in cases {
        let mut environment = CustomEnvironment::new(vec![observation]);

        let report = run_custom(&baseline, &mut environment, &[]);

        assert!(!report.accepted(), "{expected_fault}");
        assert_eq!(
            environment.events,
            [
                "conditions",
                "enter-custom",
                "start",
                "wait",
                "capture",
                "stop",
                "restore-cpu",
                "restore-gpu",
            ],
            "{expected_fault}"
        );
        assert!(
            report
                .record()
                .faults
                .iter()
                .any(|fault| fault.code == expected_fault),
            "{expected_fault}"
        );
        assert!(report.record().outcome.another_passing_run_required);
        assert!(report.record().validate().is_ok(), "{expected_fault}");
    }
}

#[test]
fn endpoint_identity_change_aborts_after_the_first_authenticated_sample() {
    let baseline = passing_baseline();
    let first = custom_observation(12_000, 65_000, 54_000);
    let mut changed = custom_observation(14_000, 65_000, 54_000);
    changed
        .readbacks
        .iter_mut()
        .find(|readback| {
            readback.fan == EvidenceFan::Gpu && readback.field == FanReadbackField::Rpm
        })
        .unwrap()
        .endpoint_identity = "replacement-gpu-rpm".into();
    let mut environment = CustomEnvironment::new(vec![first, changed]);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "endpoint-identity-change")
    );
    assert_eq!(
        &environment.events[environment.events.len() - 3..],
        ["stop", "restore-cpu", "restore-gpu"]
    );
}

#[test]
fn callback_failures_and_late_callbacks_still_stop_then_restore() {
    let baseline = passing_baseline();
    for failure in [
        CallbackFailure::Start,
        CallbackFailure::LateStart,
        CallbackFailure::Entry,
        CallbackFailure::LateEntry,
        CallbackFailure::RollbackEntry,
        CallbackFailure::Wait,
        CallbackFailure::LateWait,
        CallbackFailure::Capture,
        CallbackFailure::LateCapture,
        CallbackFailure::RollbackCapture,
        CallbackFailure::Stop,
        CallbackFailure::RollbackStop,
        CallbackFailure::LateRestoration,
        CallbackFailure::RollbackRestoration,
        CallbackFailure::OverdueBeforeWait,
    ] {
        let mut environment = CustomEnvironment::new(passing_custom_observations());
        environment.failure = Some(failure);

        let report = run_custom(&baseline, &mut environment, &[]);

        assert!(!report.accepted(), "{failure:?}");
        if matches!(
            failure,
            CallbackFailure::Entry | CallbackFailure::LateEntry | CallbackFailure::RollbackEntry
        ) {
            assert_eq!(
                environment.events,
                ["conditions", "enter-custom", "restore-cpu", "restore-gpu"]
            );
        } else {
            assert_eq!(
                &environment.events[environment.events.len() - 3..],
                ["stop", "restore-cpu", "restore-gpu"],
                "{failure:?}"
            );
        }
        assert!(report.record().outcome.another_passing_run_required);
        assert!(report.record().validate().is_ok(), "{failure:?}");
        if matches!(
            failure,
            CallbackFailure::Entry | CallbackFailure::LateEntry | CallbackFailure::RollbackEntry
        ) {
            assert!(!environment.events.contains(&"start"));
            assert_eq!(report.record().restoration_attempts.len(), 2);
        }
    }
}

#[test]
fn capture_callback_clock_rollback_fails_closed() {
    let baseline = passing_baseline();
    let mut observations = passing_custom_observations();
    observations[0] = custom_observation(11_999, 65_000, 54_000);
    let mut environment = CustomEnvironment::new(observations);
    environment.failure = Some(CallbackFailure::RollbackCapture);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(report.record().faults.iter().any(|fault| {
        fault.code == "invalid-telemetry" && fault.detail.contains("completion time regressed")
    }));
    assert_eq!(
        &environment.events[environment.events.len() - 3..],
        ["stop", "restore-cpu", "restore-gpu"]
    );
}

#[test]
fn regressed_callback_requests_fail_closed_before_invocation() {
    let baseline = passing_baseline();
    for (failure, expected_events) in [
        (CallbackFailure::RollbackEntryRequest, &["conditions"][..]),
        (
            CallbackFailure::RollbackStartRequest,
            &["conditions", "enter-custom", "restore-cpu", "restore-gpu"][..],
        ),
        (
            CallbackFailure::RollbackWaitRequest,
            &[
                "conditions",
                "enter-custom",
                "start",
                "stop",
                "restore-cpu",
                "restore-gpu",
            ][..],
        ),
    ] {
        let mut environment = CustomEnvironment::new(passing_custom_observations());
        environment.failure = Some(failure);

        let report = run_custom(&baseline, &mut environment, &[]);

        assert!(!report.accepted(), "{failure:?}");
        assert_eq!(environment.events, expected_events, "{failure:?}");
        assert!(
            report
                .record()
                .faults
                .iter()
                .any(|fault| fault.detail.contains("request time regressed")),
            "{failure:?}"
        );
        assert!(report.record().validate().is_ok(), "{failure:?}");
    }
}

#[test]
fn workload_launch_completion_rollback_returns_a_valid_failed_record() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(passing_custom_observations());
    environment.failure = Some(CallbackFailure::RollbackStart);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(report.record().faults.iter().any(|fault| {
        fault.code == "workload-start" && fault.detail.contains("completion time regressed")
    }));
    assert_eq!(
        &environment.events[environment.events.len() - 3..],
        ["stop", "restore-cpu", "restore-gpu"]
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn out_of_run_source_timestamps_preserve_a_serializable_failed_report() {
    let baseline = passing_baseline();
    for source_millis in [0, 99_999] {
        let mut observations = passing_custom_observations();
        observations[0].sample.timestamp = timestamp(source_millis);
        let mut environment = CustomEnvironment::new(observations);

        let report = run_custom(&baseline, &mut environment, &[]);

        assert!(!report.accepted());
        assert_eq!(
            report.record().samples[0].timestamp.monotonic_millis,
            12_000
        );
        assert_eq!(
            report.record().samples[0].freshness,
            SampleFreshness::Invalid
        );
        assert!(report.record().faults.iter().any(|fault| {
            fault.code == "invalid-telemetry" && fault.detail.contains(&source_millis.to_string())
        }));
        assert_eq!(report.record().restoration_attempts.len(), 2);
        assert!(report.record().validate().is_ok());
        assert!(serde_json::to_string(report.record()).is_ok());
    }
}

#[test]
fn timestamp_overflow_fails_closed_and_restores_both_fans() {
    let baseline = passing_baseline();
    let start = u64::MAX - 20_000;
    let observations = (1..=MINIMUM_MATCHED_WORKLOAD_SAMPLES)
        .map(|n| custom_observation(start.saturating_add(n as u64 * 2_000), 65_000, 54_000))
        .collect();
    let mut environment = CustomEnvironment::new(observations);
    environment.now = start;

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.detail.contains("overflow"))
    );
    assert_eq!(
        &environment.events[environment.events.len() - 3..],
        ["stop", "restore-cpu", "restore-gpu"]
    );
}

#[test]
fn a_failed_cpu_restoration_does_not_skip_gpu_restoration() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(passing_custom_observations());
    environment.cpu_restoration = MatchedWorkloadFanRestoration {
        auto_write_succeeded: false,
        enable_readback: Some(1),
        endpoint_identity: "Cpu-Enable-endpoint".into(),
        outcome: RestorationOutcome::FirmwareAutoUnconfirmed,
    };

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert_eq!(
        &environment.events[environment.events.len() - 3..],
        ["stop", "restore-cpu", "restore-gpu"]
    );
    assert!(!report.record().outcome.final_firmware_auto_confirmed);
    assert!(report.record().validate().is_ok());
}

#[test]
fn unsuccessful_auto_write_cannot_be_reported_as_restored() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(passing_custom_observations());
    environment.cpu_restoration.auto_write_succeeded = false;

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(!report.record().outcome.final_firmware_auto_confirmed);
    assert_eq!(
        &environment.events[environment.events.len() - 3..],
        ["stop", "restore-cpu", "restore-gpu"]
    );
    assert_eq!(
        report.record().restoration_attempts[0].outcome,
        RestorationOutcome::FirmwareAutoUnconfirmed
    );
    assert!(report.record().validate().is_ok());
    let value = serde_json::to_value(report.record()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA_V2).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert!(parse_evidence_v2(&value.to_string()).is_ok());
}

#[test]
fn final_restoration_must_use_the_authenticated_enable_endpoint() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(passing_custom_observations());
    environment.gpu_restoration.endpoint_identity = "replacement-gpu-enable".into();

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(!report.record().outcome.final_firmware_auto_confirmed);
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "firmware-auto-unconfirmed")
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn peak_and_p95_must_each_stay_within_two_celsius_of_baseline() {
    let baseline = passing_baseline();
    let mut environment = CustomEnvironment::new(
        (1..=MINIMUM_MATCHED_WORKLOAD_SAMPLES)
            .map(|n| custom_observation(10_000 + n as u64 * 2_000, 67_001, 56_001))
            .collect(),
    );

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "peak-temperature-regression")
    );
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "p95-temperature-regression")
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn comparison_and_slope_limits_are_inclusive() {
    let baseline = passing_baseline();
    let observations = (1..=MINIMUM_MATCHED_WORKLOAD_SAMPLES)
        .map(|n| {
            let elapsed = (n - 1) as i32 * 2_000;
            custom_observation(
                10_000 + n as u64 * 2_000,
                62_000 + elapsed * 1_000 / 60_000,
                51_000 + elapsed * 1_000 / 60_000,
            )
        })
        .collect();
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(report.accepted(), "{:#?}", report.record());
    let summary = report.record().thermal_summary.as_ref().unwrap();
    assert_eq!(summary.cpu_peak_millicelsius, 67_000);
    assert_eq!(summary.gpu_peak_millicelsius, 56_000);
    assert_eq!(summary.cpu_final_slope_millicelsius_per_minute, 1_000);
    assert_eq!(summary.gpu_final_slope_millicelsius_per_minute, 1_000);
}

#[test]
fn cpu_peak_and_gpu_p95_are_checked_independently() {
    let baseline = passing_baseline();
    let mut cpu_peak = passing_custom_observations();
    cpu_peak[0].sample.cpu_millicelsius = Some(67_001);
    let mut environment = CustomEnvironment::new(cpu_peak);
    let report = run_custom(&baseline, &mut environment, &[]);
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "peak-temperature-regression")
    );
    assert!(
        !report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "p95-temperature-regression")
    );

    let mut gpu_p95 = passing_custom_observations();
    for observation in gpu_p95.iter_mut().rev().take(8) {
        observation.sample.gpu_millicelsius = Some(56_001);
    }
    let mut environment = CustomEnvironment::new(gpu_p95);
    let report = run_custom(&baseline, &mut environment, &[]);
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "p95-temperature-regression")
    );
}

#[test]
fn least_squares_final_five_minute_slope_must_not_exceed_one_celsius_per_minute() {
    let baseline = passing_baseline();
    let observations = (1..=151)
        .map(|sample_number| {
            let elapsed = sample_number * 2_000;
            custom_observation(10_000 + elapsed, 60_000 + sample_number as i32 * 40, 50_000)
        })
        .collect();
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "final-slope-regression")
    );
    assert!(report.record().validate().is_ok());
}

#[test]
fn a_slope_just_over_the_limit_is_not_rounded_down() {
    let baseline = passing_baseline();
    let observations = (1..=MINIMUM_MATCHED_WORKLOAD_SAMPLES)
        .map(|sample_number| {
            let elapsed_millis = (sample_number - 1) as i32 * 2_000;
            let final_perturbation = if sample_number == MINIMUM_MATCHED_WORKLOAD_SAMPLES {
                40
            } else {
                0
            };
            custom_observation(
                10_000 + sample_number as u64 * 2_000,
                61_000 + elapsed_millis * 1_000 / 60_000 + final_perturbation,
                50_000,
            )
        })
        .collect();
    let mut environment = CustomEnvironment::new(observations);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert_eq!(
        report
            .record()
            .thermal_summary
            .as_ref()
            .unwrap()
            .cpu_final_slope_millicelsius_per_minute,
        1_000
    );
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "final-slope-regression")
    );
}

#[test]
fn repeat_status_distinguishes_idle_first_runs_and_second_loaded_runs() {
    let idle_baseline = passing_baseline_for("idle-ac-v1");
    let mut idle_environment = CustomEnvironment::new(passing_custom_observations());
    let idle_report = run_custom(&idle_baseline, &mut idle_environment, &[]);
    assert!(idle_report.accepted());
    assert!(!idle_report.record().outcome.another_passing_run_required);

    for workload_id in ["cpu-ac-v1", "gpu-ac-v1", "combined-ac-v1"] {
        let baseline = passing_baseline_for(workload_id);
        let mut first_environment = CustomEnvironment::new(passing_custom_observations());
        let first = run_custom(&baseline, &mut first_environment, &[]).into_record();
        assert!(first.outcome.another_passing_run_required);

        let previous = [&first];
        let mut second_environment = CustomEnvironment::new(passing_custom_observations());
        let second = run_custom(&baseline, &mut second_environment, &previous);
        assert!(second.accepted());
        assert!(!second.record().outcome.another_passing_run_required);

        let duplicates = [&first, &first];
        let mut duplicate_environment = CustomEnvironment::new(passing_custom_observations());
        let duplicate_result = run_matched_custom_workload(
            &mut duplicate_environment,
            &MatchedWorkloadPlan {
                baseline: &baseline,
                previous_passing_runs: &duplicates,
                tachometer_calibrations: tachometer_calibrations(),
            },
        );
        assert!(matches!(
            duplicate_result,
            Err(fan_control_core::MatchedWorkloadPlanError::InvalidPriorRun { .. })
        ));
    }
}

#[test]
fn cosmetic_prior_run_changes_do_not_create_repeat_credit() {
    let baseline = passing_baseline();
    let mut first_environment = CustomEnvironment::new(passing_custom_observations());
    let first = run_custom(&baseline, &mut first_environment, &[]).into_record();
    let mut alias = first.clone();
    alias.outcome.reason = "same pass with edited presentation text".into();
    alias.outcome.another_passing_run_required = false;
    assert!(alias.validate().is_ok());
    let previous = [&first, &alias];
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let result = run_matched_custom_workload(
        &mut environment,
        &MatchedWorkloadPlan {
            baseline: &baseline,
            previous_passing_runs: &previous,
            tachometer_calibrations: tachometer_calibrations(),
        },
    );

    assert!(matches!(
        result,
        Err(fan_control_core::MatchedWorkloadPlanError::InvalidPriorRun { .. })
    ));
    assert!(environment.events.is_empty());
}

#[test]
fn mutable_completion_metadata_does_not_create_repeat_credit() {
    let baseline = passing_baseline();
    let mut first_environment = CustomEnvironment::new(passing_custom_observations());
    let first = run_custom(&baseline, &mut first_environment, &[]).into_record();
    let mut alias = first.clone();
    alias.completed_at.monotonic_millis += 1;
    alias.completed_at.wall_unix_millis += 1;
    assert!(alias.validate().is_ok());
    let previous = [&first, &alias];
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let result = run_matched_custom_workload(
        &mut environment,
        &MatchedWorkloadPlan {
            baseline: &baseline,
            previous_passing_runs: &previous,
            tachometer_calibrations: tachometer_calibrations(),
        },
    );

    assert!(matches!(
        result,
        Err(fan_control_core::MatchedWorkloadPlanError::InvalidPriorRun { .. })
    ));
    assert!(environment.events.is_empty());
}

#[test]
fn prior_run_with_unsettled_final_tachometer_response_gets_no_repeat_credit() {
    let baseline = passing_baseline();
    let mut first_environment = CustomEnvironment::new(passing_custom_observations());
    let mut prior = run_custom(&baseline, &mut first_environment, &[]).into_record();
    prior
        .readbacks
        .iter_mut()
        .rev()
        .find(|readback| {
            readback.fan == EvidenceFan::Cpu
                && readback.field == FanReadbackField::Rpm
                && readback.phase == Some(fan_control_core::FanReadbackPhase::Sample)
        })
        .unwrap()
        .value = Some(0);
    assert!(prior.validate().is_err());
    let previous = [&prior];
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let result = run_matched_custom_workload(
        &mut environment,
        &MatchedWorkloadPlan {
            baseline: &baseline,
            previous_passing_runs: &previous,
            tachometer_calibrations: tachometer_calibrations(),
        },
    );

    assert!(matches!(
        result,
        Err(fan_control_core::MatchedWorkloadPlanError::InvalidPriorRun { .. })
    ));
    assert!(environment.events.is_empty());
}

#[test]
fn repeat_credit_is_bound_to_the_exact_baseline_record() {
    let current_baseline = passing_baseline();
    let other_baseline = baseline_for(
        "cpu-ac-v1",
        BaselineStartingConditions {
            ambient_millicelsius: 24_000,
            cpu_millicelsius: 42_000,
            gpu_millicelsius: 39_000,
            power_profile: EvidenceProfile::Ac,
        },
        64_000,
        53_000,
    );
    let mut first_environment = CustomEnvironment::new(passing_custom_observations());
    let prior = run_custom(&other_baseline, &mut first_environment, &[]).into_record();
    let previous = [&prior];
    let mut environment = CustomEnvironment::new(passing_custom_observations());

    let result = run_matched_custom_workload(
        &mut environment,
        &MatchedWorkloadPlan {
            baseline: &current_baseline,
            previous_passing_runs: &previous,
            tachometer_calibrations: tachometer_calibrations(),
        },
    );

    assert!(matches!(
        result,
        Err(fan_control_core::MatchedWorkloadPlanError::InvalidPriorRun { .. })
    ));
}

#[test]
fn malformed_prior_passes_never_receive_repeat_credit() {
    let baseline = passing_baseline();
    let mut first_environment = CustomEnvironment::new(passing_custom_observations());
    let valid_prior = run_custom(&baseline, &mut first_environment, &[]).into_record();

    let mut faulted = valid_prior.clone();
    faulted.faults.push(FaultEvidence {
        timestamp: faulted.started_at,
        code: "controller-fault".into(),
        detail: "injected fault".into(),
    });
    let mut truncated = valid_prior;
    truncated.samples = vec![
        truncated.samples.first().unwrap().clone(),
        truncated.samples.last().unwrap().clone(),
    ];
    let mut late_start_gate = faulted.clone();
    late_start_gate.faults.clear();
    late_start_gate.starting_conditions_captured_at = Some(timestamp(10_001));
    late_start_gate.workload_started_at = Some(timestamp(10_002));

    for malformed in [&faulted, &truncated, &late_start_gate] {
        let previous = [malformed];
        let mut environment = CustomEnvironment::new(passing_custom_observations());
        let result = run_matched_custom_workload(
            &mut environment,
            &MatchedWorkloadPlan {
                baseline: &baseline,
                previous_passing_runs: &previous,
                tachometer_calibrations: tachometer_calibrations(),
            },
        );

        assert!(matches!(
            result,
            Err(fan_control_core::MatchedWorkloadPlanError::InvalidPriorRun { .. })
        ));
    }
}

#[test]
fn malformed_control_evidence_returns_a_valid_failed_record() {
    let baseline = passing_baseline();
    let mut malformed = custom_observation(12_000, 65_000, 54_000);
    malformed.commands[0].value = 256;
    malformed
        .readbacks
        .iter_mut()
        .find(|readback| {
            readback.fan == EvidenceFan::Cpu && readback.field == FanReadbackField::Pwm
        })
        .unwrap()
        .value = Some(256);
    malformed.readbacks[0].endpoint_identity.clear();
    let mut environment = CustomEnvironment::new(vec![malformed]);

    let report = run_custom(&baseline, &mut environment, &[]);

    assert!(!report.accepted());
    assert!(
        report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "invalid-control-evidence")
    );
    assert!(report.record().validate().is_ok());
}

fn run_custom<'a>(
    baseline: &fan_control_core::EvidenceRecord,
    environment: &mut CustomEnvironment,
    previous_passing_runs: &'a [&'a fan_control_core::EvidenceRecord],
) -> fan_control_core::MatchedWorkloadReport {
    run_matched_custom_workload(
        environment,
        &MatchedWorkloadPlan {
            baseline,
            previous_passing_runs,
            tachometer_calibrations: tachometer_calibrations(),
        },
    )
    .unwrap()
}

fn tachometer_calibrations() -> MatchedWorkloadTachometerCalibrations<'static> {
    static CALIBRATIONS: OnceLock<[fan_control_core::EvidenceRecord; 2]> = OnceLock::new();
    let calibrations = CALIBRATIONS.get_or_init(|| {
        [
            completed_calibration_record(passing_baseline(), Fan::Cpu),
            completed_calibration_record(passing_baseline(), Fan::Gpu),
        ]
    });
    MatchedWorkloadTachometerCalibrations {
        cpu: &calibrations[0],
        gpu: &calibrations[1],
    }
}

fn passing_baseline() -> fan_control_core::EvidenceRecord {
    passing_baseline_for("cpu-ac-v1")
}

fn passing_baseline_with_cadence(cadence_millis: u64) -> fan_control_core::EvidenceRecord {
    let mut record = passing_baseline();
    for (index, sample) in record.samples.iter_mut().enumerate() {
        sample.timestamp = timestamp((index as u64 + 1) * cadence_millis);
    }
    for fan in [EvidenceFan::Cpu, EvidenceFan::Gpu] {
        let mut sample_index = 0;
        for readback in record.readbacks.iter_mut().filter(|readback| {
            readback.fan == fan
                && readback.phase == Some(fan_control_core::FanReadbackPhase::Sample)
        }) {
            readback.timestamp = timestamp((sample_index as u64 + 1) * cadence_millis);
            sample_index += 1;
        }
    }
    record.completed_at = record.samples.last().unwrap().timestamp;
    for readback in &mut record.readbacks {
        if readback.phase == Some(fan_control_core::FanReadbackPhase::Final) {
            readback.timestamp = record.completed_at;
        }
    }
    assert!(record.validate().is_ok());
    record
}

fn valid_five_minute_baseline_below_matched_minimum() -> fan_control_core::EvidenceRecord {
    let mut record = passing_baseline();
    let sample_count = MINIMUM_MATCHED_WORKLOAD_SAMPLES - 7;
    record.samples.truncate(sample_count);
    for (index, sample) in record.samples.iter_mut().enumerate() {
        sample.timestamp = timestamp((index as u64 + 1) * 2_100);
    }
    for fan in [EvidenceFan::Cpu, EvidenceFan::Gpu] {
        let mut sample_index = 0;
        record.readbacks.retain_mut(|readback| {
            if readback.fan != fan
                || readback.phase != Some(fan_control_core::FanReadbackPhase::Sample)
            {
                return true;
            }
            if sample_index == sample_count {
                return false;
            }
            readback.timestamp = timestamp((sample_index as u64 + 1) * 2_100);
            sample_index += 1;
            true
        });
    }
    record.completed_at = record.samples.last().unwrap().timestamp;
    for readback in &mut record.readbacks {
        if readback.phase == Some(fan_control_core::FanReadbackPhase::Final) {
            readback.timestamp = record.completed_at;
        }
    }
    record
}

fn passing_baseline_with_samples(samples_required: usize) -> fan_control_core::EvidenceRecord {
    baseline_for_sample_count(
        "cpu-ac-v1",
        BaselineStartingConditions {
            ambient_millicelsius: 24_000,
            cpu_millicelsius: 42_000,
            gpu_millicelsius: 39_000,
            power_profile: EvidenceProfile::Ac,
        },
        65_000,
        54_000,
        samples_required,
    )
}

fn passing_baseline_for(workload_id: &str) -> fan_control_core::EvidenceRecord {
    baseline_for(
        workload_id,
        BaselineStartingConditions {
            ambient_millicelsius: 24_000,
            cpu_millicelsius: 42_000,
            gpu_millicelsius: 39_000,
            power_profile: EvidenceProfile::Ac,
        },
        65_000,
        54_000,
    )
}

fn passing_baseline_with_starting_temperatures(
    cpu_millicelsius: i32,
    gpu_millicelsius: i32,
) -> fan_control_core::EvidenceRecord {
    baseline_for(
        "cpu-ac-v1",
        BaselineStartingConditions {
            ambient_millicelsius: 24_000,
            cpu_millicelsius,
            gpu_millicelsius,
            power_profile: EvidenceProfile::Ac,
        },
        94_000,
        84_000,
    )
}

fn baseline_for(
    workload_id: &str,
    conditions: BaselineStartingConditions,
    cpu_millicelsius: i32,
    gpu_millicelsius: i32,
) -> fan_control_core::EvidenceRecord {
    baseline_for_sample_count(
        workload_id,
        conditions,
        cpu_millicelsius,
        gpu_millicelsius,
        MINIMUM_MATCHED_WORKLOAD_SAMPLES,
    )
}

fn baseline_for_sample_count(
    workload_id: &str,
    conditions: BaselineStartingConditions,
    cpu_millicelsius: i32,
    gpu_millicelsius: i32,
    samples_required: usize,
) -> fan_control_core::EvidenceRecord {
    let mut platform = auto_platform();
    let mut environment = BaselineEnvironment::new(
        (1..=samples_required)
            .map(|n| baseline_observation(n as u64 * 2_000, cpu_millicelsius, gpu_millicelsius))
            .collect(),
    );
    environment.conditions = conditions;
    let mut workload = workload();
    workload.workload_id = workload_id.into();
    run_firmware_auto_baseline(
        &mut platform,
        &mut environment,
        &FirmwareAutoBaselinePlan {
            hwmon_root: Path::new(HWMON_ROOT),
            qualification_envelope: envelope(),
            workload,
            samples_required,
        },
    )
    .unwrap()
    .into_record()
}

fn workload() -> WorkloadEvidence {
    WorkloadEvidence {
        workload_id: "cpu-ac-v1".into(),
        command: vec!["/usr/lib/pt31553/workloads/cpu".into(), "--fixed".into()],
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

fn timestamp(monotonic_millis: u64) -> EvidenceTimestamp {
    EvidenceTimestamp {
        monotonic_millis,
        wall_unix_millis: 1_787_691_600_000_i64
            .saturating_add(i64::try_from(monotonic_millis).unwrap_or(i64::MAX)),
    }
}

fn sample(monotonic_millis: u64, cpu: i32, gpu: i32) -> TelemetrySampleEvidence {
    TelemetrySampleEvidence {
        timestamp: timestamp(monotonic_millis),
        cpu_millicelsius: Some(cpu),
        gpu_millicelsius: Some(gpu),
        freshness: SampleFreshness::Fresh,
        external_power: Some(EvidenceExternalPower::Ac),
        selected_profile: Some(EvidenceProfile::Ac),
        cpu_source_demand_basis_points: Some(5_000),
        gpu_source_demand_basis_points: Some(4_000),
        commanded_demand_basis_points: Some(5_000),
        cpu_thermal_throttling: Some(false),
        gpu_thermal_throttling: Some(false),
    }
}

fn baseline_observation(monotonic_millis: u64, cpu: i32, gpu: i32) -> BaselineObservation {
    BaselineObservation {
        sample: sample(monotonic_millis, cpu, gpu),
        system_stable: true,
        kernel_faults: vec![],
        nvidia_faults: vec![],
    }
}

fn custom_observation(monotonic_millis: u64, cpu: i32, gpu: i32) -> MatchedWorkloadObservation {
    MatchedWorkloadObservation {
        sample: sample(monotonic_millis, cpu, gpu),
        commands: [EvidenceFan::Cpu, EvidenceFan::Gpu]
            .into_iter()
            .map(|fan| FanCommandEvidence {
                timestamp: timestamp(monotonic_millis),
                fan,
                field: FanControlField::Pwm,
                value: 128,
            })
            .collect(),
        readbacks: [EvidenceFan::Cpu, EvidenceFan::Gpu]
            .into_iter()
            .flat_map(|fan| {
                [
                    (FanReadbackField::Enable, 1),
                    (FanReadbackField::Pwm, 128),
                    (FanReadbackField::Rpm, 3_000),
                ]
                .into_iter()
                .map(move |(field, value)| FanReadbackEvidence {
                    timestamp: timestamp(monotonic_millis),
                    fan,
                    field,
                    value: Some(value),
                    endpoint_identity: format!("{fan:?}-{field:?}-endpoint"),
                    outcome: ObservationOutcome::Confirmed,
                    phase: Some(fan_control_core::FanReadbackPhase::Sample),
                })
            })
            .collect(),
        controller_fault: None,
        system_stable: true,
        kernel_faults: vec![],
        nvidia_faults: vec![],
    }
}

fn passing_custom_observations() -> Vec<MatchedWorkloadObservation> {
    (1..=MINIMUM_MATCHED_WORKLOAD_SAMPLES)
        .map(|n| custom_observation(10_000 + n as u64 * 2_000, 65_000, 54_000))
        .collect()
}

struct BaselineEnvironment {
    observations: VecDeque<BaselineObservation>,
    now: u64,
    conditions: BaselineStartingConditions,
}

impl BaselineEnvironment {
    fn new(observations: Vec<BaselineObservation>) -> Self {
        Self {
            observations: observations.into(),
            now: 0,
            conditions: BaselineStartingConditions {
                ambient_millicelsius: 24_000,
                cpu_millicelsius: 42_000,
                gpu_millicelsius: 39_000,
                power_profile: EvidenceProfile::Ac,
            },
        }
    }
}

impl FirmwareAutoBaselineEnvironment for BaselineEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        timestamp(self.now)
    }

    fn capture_starting_conditions(
        &mut self,
    ) -> Result<CapturedBaselineStartingConditions, String> {
        Ok(CapturedBaselineStartingConditions {
            conditions: self.conditions,
            captured_at: timestamp(self.now),
        })
    }

    fn start_workload(
        &mut self,
        _workload: &WorkloadEvidence,
        _deadline_monotonic_millis: u64,
    ) -> Result<EvidenceTimestamp, String> {
        Ok(timestamp(self.now))
    }

    fn wait_until(
        &mut self,
        target_monotonic_millis: u64,
        _deadline_monotonic_millis: u64,
    ) -> Result<(), String> {
        self.now = target_monotonic_millis;
        Ok(())
    }

    fn capture_observation(
        &mut self,
        _deadline_monotonic_millis: u64,
    ) -> Result<BaselineObservation, String> {
        self.observations
            .pop_front()
            .ok_or_else(|| "no observation".into())
    }

    fn stop_workload(&mut self, _deadline_monotonic_millis: u64) -> Result<(), String> {
        Ok(())
    }

    fn cleanup_after_workload(&mut self) -> Result<BaselineCleanupAttestation, String> {
        Ok(BaselineCleanupAttestation {
            fan_control_write_count: 0,
        })
    }
}

struct CustomEnvironment {
    observations: VecDeque<MatchedWorkloadObservation>,
    events: Vec<&'static str>,
    now: u64,
    conditions: MatchedWorkloadStartingConditions,
    cpu_restoration: MatchedWorkloadFanRestoration,
    gpu_restoration: MatchedWorkloadFanRestoration,
    failure: Option<CallbackFailure>,
    timestamp_calls: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackFailure {
    LateConditions,
    Entry,
    LateEntry,
    RollbackEntry,
    RollbackEntryRequest,
    Start,
    LateStart,
    RollbackStart,
    RollbackStartRequest,
    Wait,
    LateWait,
    RollbackWaitRequest,
    Capture,
    LateCapture,
    RollbackCapture,
    Stop,
    RollbackStop,
    LateRestoration,
    RollbackRestoration,
    OverdueBeforeWait,
}

impl CustomEnvironment {
    fn new(observations: Vec<MatchedWorkloadObservation>) -> Self {
        Self {
            observations: observations.into(),
            events: vec![],
            now: 10_000,
            conditions: default_custom_conditions(),
            cpu_restoration: successful_restoration(EvidenceFan::Cpu),
            gpu_restoration: successful_restoration(EvidenceFan::Gpu),
            failure: None,
            timestamp_calls: 0,
        }
    }
}

impl MatchedWorkloadEnvironment for CustomEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        self.timestamp_calls += 1;
        let regressed_request = matches!(
            (self.failure, self.timestamp_calls),
            (Some(CallbackFailure::RollbackEntryRequest), 3)
                | (Some(CallbackFailure::RollbackStartRequest), 5)
                | (Some(CallbackFailure::RollbackWaitRequest), 7)
        );
        timestamp(if regressed_request {
            self.now.saturating_sub(1)
        } else {
            self.now
        })
    }

    fn capture_starting_conditions(
        &mut self,
        deadline_monotonic_millis: u64,
    ) -> Result<CapturedMatchedWorkloadStartingConditions, String> {
        self.events.push("conditions");
        if self.failure == Some(CallbackFailure::LateConditions) {
            self.now = deadline_monotonic_millis.saturating_add(1);
        }
        Ok(CapturedMatchedWorkloadStartingConditions {
            conditions: self.conditions,
            captured_at: timestamp(self.now),
        })
    }

    fn enter_custom_control(&mut self, _deadline_monotonic_millis: u64) -> Result<(), String> {
        self.events.push("enter-custom");
        if self.failure == Some(CallbackFailure::LateEntry) {
            self.now = self.now.saturating_add(5_001);
        }
        if self.failure == Some(CallbackFailure::RollbackEntry) {
            self.now = self.now.saturating_sub(1);
        }
        if self.failure == Some(CallbackFailure::Entry) {
            Err("handover failed ambiguously".into())
        } else {
            Ok(())
        }
    }

    fn start_workload(
        &mut self,
        _workload: &WorkloadEvidence,
        _deadline_monotonic_millis: u64,
    ) -> Result<EvidenceTimestamp, String> {
        self.events.push("start");
        let started_at = timestamp(self.now);
        if self.failure == Some(CallbackFailure::LateStart) {
            self.now = self.now.saturating_add(10_001);
        }
        if self.failure == Some(CallbackFailure::RollbackStart) {
            self.now = self.now.saturating_sub(1);
        }
        if self.failure == Some(CallbackFailure::OverdueBeforeWait) {
            self.now = self.now.saturating_add(2_200);
        }
        if self.failure == Some(CallbackFailure::Start) {
            Err("launch failed ambiguously".into())
        } else {
            Ok(started_at)
        }
    }

    fn wait_until(
        &mut self,
        target_monotonic_millis: u64,
        _deadline_monotonic_millis: u64,
    ) -> Result<(), String> {
        self.events.push("wait");
        if self.failure == Some(CallbackFailure::Wait) {
            return Err("wait failed".into());
        }
        self.now = target_monotonic_millis;
        if self.failure == Some(CallbackFailure::LateWait) {
            self.now = self.now.saturating_add(101);
        }
        Ok(())
    }

    fn capture_observation(
        &mut self,
        _deadline_monotonic_millis: u64,
    ) -> Result<MatchedWorkloadObservation, String> {
        self.events.push("capture");
        if self.failure == Some(CallbackFailure::Capture) {
            return Err("capture failed".into());
        }
        if self.failure == Some(CallbackFailure::LateCapture) {
            self.now = self.now.saturating_add(101);
        }
        if self.failure == Some(CallbackFailure::RollbackCapture) {
            self.now = self.now.saturating_sub(1);
        }
        self.observations
            .pop_front()
            .ok_or_else(|| "no observation".into())
    }

    fn stop_workload(&mut self, _deadline_monotonic_millis: u64) -> Result<(), String> {
        self.events.push("stop");
        if self.failure == Some(CallbackFailure::RollbackStop) {
            self.now = self.now.saturating_sub(1);
        } else if self.failure == Some(CallbackFailure::RollbackRestoration) {
            self.now = self.now.saturating_add(10);
        } else {
            self.now = self.now.saturating_add(1);
        }
        if self.failure == Some(CallbackFailure::Stop) {
            Err("stop confirmation failed".into())
        } else {
            Ok(())
        }
    }

    fn restore_fan(
        &mut self,
        fan: EvidenceFan,
        deadline_monotonic_millis: u64,
    ) -> MatchedWorkloadFanRestoration {
        self.events.push(match fan {
            EvidenceFan::Cpu => "restore-cpu",
            EvidenceFan::Gpu => "restore-gpu",
        });
        if fan == EvidenceFan::Cpu && self.failure == Some(CallbackFailure::LateRestoration) {
            self.now = deadline_monotonic_millis.saturating_add(1);
        } else if fan == EvidenceFan::Cpu
            && self.failure == Some(CallbackFailure::RollbackRestoration)
        {
            self.now = self.now.saturating_sub(5);
        } else {
            self.now =
                self.now
                    .saturating_add(if self.failure == Some(CallbackFailure::RollbackStop) {
                        2
                    } else {
                        1
                    });
        }
        match fan {
            EvidenceFan::Cpu => self.cpu_restoration.clone(),
            EvidenceFan::Gpu => self.gpu_restoration.clone(),
        }
    }
}

fn default_custom_conditions() -> MatchedWorkloadStartingConditions {
    MatchedWorkloadStartingConditions {
        ambient_millicelsius: 25_000,
        cpu_millicelsius: 44_000,
        gpu_millicelsius: 41_000,
        power_profile: EvidenceProfile::Ac,
    }
}

fn successful_restoration(fan: EvidenceFan) -> MatchedWorkloadFanRestoration {
    MatchedWorkloadFanRestoration {
        auto_write_succeeded: true,
        enable_readback: Some(2),
        endpoint_identity: format!("{fan:?}-Enable-endpoint"),
        outcome: RestorationOutcome::FirmwareAutoConfirmed,
    }
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
