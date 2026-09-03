mod support;

use std::{collections::VecDeque, fs, os::unix::fs::PermissionsExt, path::Path, sync::OnceLock};

use fan_control_core::{
    BaselineCleanupAttestation, BaselineObservation, BaselineStartingConditions,
    CapturedBaselineStartingConditions, CapturedMatchedWorkloadStartingConditions,
    EvidenceExternalPower, EvidenceFan, EvidenceProfile, EvidenceRecord, EvidenceRecordStatus,
    EvidenceTimestamp, FakePlatform, Fan, FanCommandEvidence, FanControlField,
    FanEndpointIdentitiesEvidence, FanReadbackEvidence, FanReadbackField, FanReadbackPhase,
    FilePermissions, FirmwareAutoBaselineEnvironment, FirmwareAutoBaselinePlan, LiveLifecycleCase,
    LiveLifecycleCaseObservation, LiveLifecycleEnvironment, LiveLifecycleFanAutoObservation,
    LiveLifecycleFanAutoPair, LiveLifecyclePowerObservation, LiveLifecycleProfileObservation,
    LiveLifecycleRebootArmObservation, LiveLifecycleRebootContinuation, MatchedWorkloadEnvironment,
    MatchedWorkloadFanRestoration, MatchedWorkloadObservation, MatchedWorkloadPlan,
    MatchedWorkloadStartingConditions, MatchedWorkloadTachometerCalibrations, ObservationOutcome,
    PreflightCheckEvidence, QualificationAuthorizationError, QualificationEnvelopeIdentityV1,
    QualificationRecordV2, RestorationOutcome, RootOwnedQualificationRecordAccess,
    RunOutcomeEvidence, RunOutcomeStatus, SUPERVISED_ENDURANCE_SAMPLE_COUNT,
    SUPERVISED_ENDURANCE_SEGMENTS, SUPERVISED_ENDURANCE_WORKLOAD_ID, SampleFreshness,
    StoppedProcess, SupervisedEnduranceEnvironment, SupervisedEndurancePlan,
    SupervisedEnduranceProcessStopConfirmation, SupervisedEnduranceSegment,
    SupervisedEnduranceSegmentConfirmation, SystemOwnershipPlatform, TelemetrySampleEvidence,
    WorkloadEvidence, parse_evidence_v2, run_firmware_auto_baseline,
    run_live_lifecycle_qualification, run_matched_custom_workload, run_supervised_endurance,
    write_qualification_record_after_endurance,
};
use support::{
    PROTECTED_POLICY, compatibility_declaration, completed_calibration_record,
    fan_endpoint_identities, sha256,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";

struct QualificationFixture {
    baselines: Vec<EvidenceRecord>,
    matched: Vec<EvidenceRecord>,
    cpu_calibration: EvidenceRecord,
    gpu_calibration: EvidenceRecord,
    lifecycle: EvidenceRecord,
    preflight: EvidenceRecord,
    workload: WorkloadEvidence,
}

impl QualificationFixture {
    fn plan<'a>(
        &'a self,
        baseline_refs: &'a [&'a EvidenceRecord],
        matched_refs: &'a [&'a EvidenceRecord],
    ) -> SupervisedEndurancePlan<'a> {
        SupervisedEndurancePlan {
            preflight: &self.preflight,
            baselines: baseline_refs,
            matched_workload_runs: matched_refs,
            tachometer_calibrations: MatchedWorkloadTachometerCalibrations {
                cpu: &self.cpu_calibration,
                gpu: &self.gpu_calibration,
            },
            live_lifecycle: &self.lifecycle,
            workload: self.workload.clone(),
        }
    }
}

fn qualification_fixture() -> &'static QualificationFixture {
    static FIXTURE: OnceLock<QualificationFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let envelope = envelope();
        let specs = [
            ("idle-ac-v1", EvidenceProfile::Ac, 300usize),
            ("cpu-ac-v1", EvidenceProfile::Ac, 600),
            ("gpu-ac-v1", EvidenceProfile::Ac, 600),
            ("combined-ac-v1", EvidenceProfile::Ac, 900),
            ("idle-battery-v1", EvidenceProfile::Battery, 300),
            ("cpu-battery-v1", EvidenceProfile::Battery, 300),
            ("gpu-battery-v1", EvidenceProfile::Battery, 300),
        ];
        let baselines = specs
            .iter()
            .map(|(id, profile, samples)| baseline(&envelope, id, *profile, *samples))
            .collect::<Vec<_>>();
        let cpu_calibration = completed_calibration_record(baselines[0].clone(), Fan::Cpu);
        let gpu_calibration = completed_calibration_record(baselines[0].clone(), Fan::Gpu);
        let calibrations = MatchedWorkloadTachometerCalibrations {
            cpu: &cpu_calibration,
            gpu: &gpu_calibration,
        };
        let mut matched = Vec::new();
        for (baseline, (id, profile, samples)) in baselines.iter().zip(specs) {
            let repeats = if id.starts_with("idle-") { 1 } else { 2 };
            for repeat in 0..repeats {
                let run_offset = matched.len() as u64 * 10_000_000;
                let observations = (1..=samples)
                    .map(|sample| {
                        let mut observation = custom_observation(
                            10_000 + run_offset + sample as u64 * 2_000,
                            profile,
                        );
                        observation.sample.cpu_millicelsius = observation
                            .sample
                            .cpu_millicelsius
                            .map(|value| value + repeat as i32 * 100);
                        observation
                    })
                    .collect();
                let prior = matched
                    .iter()
                    .rev()
                    .take(repeat)
                    .collect::<Vec<&EvidenceRecord>>();
                let report = run_matched_custom_workload(
                    &mut CustomEnvironment::new(observations, profile),
                    &MatchedWorkloadPlan {
                        baseline,
                        previous_passing_runs: &prior,
                        tachometer_calibrations: calibrations,
                    },
                )
                .expect("matrix run plan is valid");
                assert!(report.accepted(), "{id} repeat {repeat} failed");
                matched.push(report.into_record());
            }
        }
        assert_eq!(matched.len(), 12);
        let lifecycle =
            run_live_lifecycle_qualification(&mut LifecycleEnvironment::default(), &envelope)
                .expect("lifecycle plan is valid")
                .into_record();
        QualificationFixture {
            baselines,
            matched,
            cpu_calibration,
            gpu_calibration,
            lifecycle,
            preflight: preflight(envelope),
            workload: workload(SUPERVISED_ENDURANCE_WORKLOAD_ID, EvidenceProfile::Ac),
        }
    })
}

#[test]
fn qualification_matrix_is_complete_before_endurance() {
    let fixture = qualification_fixture();
    let baselines = &fixture.baselines;
    let matched = &fixture.matched;
    let cpu_calibration = &fixture.cpu_calibration;
    let gpu_calibration = &fixture.gpu_calibration;
    let preflight = &fixture.preflight;
    let lifecycle = &fixture.lifecycle;
    let baseline_refs = baselines.iter().collect::<Vec<_>>();
    let matched_refs = matched.iter().collect::<Vec<_>>();
    let plan = fixture.plan(&baseline_refs, &matched_refs);

    let incomplete_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: plan.baselines,
        matched_workload_runs: &matched_refs[..matched_refs.len() - 1],
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: plan.live_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &incomplete_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    let mut duplicated_matched = matched.clone();
    duplicated_matched[2] = duplicated_matched[1].clone();
    duplicated_matched[2].started_at.monotonic_millis -= 1;
    duplicated_matched[2].started_at.wall_unix_millis -= 1;
    duplicated_matched[2]
        .starting_conditions_captured_at
        .as_mut()
        .unwrap()
        .monotonic_millis -= 1;
    duplicated_matched[2]
        .starting_conditions_captured_at
        .as_mut()
        .unwrap()
        .wall_unix_millis -= 1;
    duplicated_matched[2].outcome.reason = "cosmetically distinct copy".into();
    duplicated_matched[2].outcome.another_passing_run_required = false;
    let duplicated_refs = duplicated_matched.iter().collect::<Vec<_>>();
    let duplicated_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: plan.baselines,
        matched_workload_runs: &duplicated_refs,
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: plan.live_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &duplicated_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    let mut endpoint_relabeled_matched = matched.clone();
    endpoint_relabeled_matched[2] = endpoint_relabeled_matched[1].clone();
    endpoint_relabeled_matched[2]
        .readbacks
        .iter_mut()
        .for_each(|readback| {
            readback.endpoint_identity = format!("relabeled-{}", readback.endpoint_identity);
        });
    endpoint_relabeled_matched[2]
        .outcome
        .another_passing_run_required = false;
    let endpoint_relabeled_refs = endpoint_relabeled_matched.iter().collect::<Vec<_>>();
    let endpoint_relabeled_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: plan.baselines,
        matched_workload_runs: &endpoint_relabeled_refs,
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: plan.live_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &endpoint_relabeled_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    let mut shifted_matched = matched.clone();
    let mut shifted_json = serde_json::to_value(&shifted_matched[1]).unwrap();
    shift_all_timestamps(&mut shifted_json, 1_000_000);
    shifted_matched[2] = serde_json::from_value(shifted_json).unwrap();
    shifted_matched[2].outcome.another_passing_run_required = false;
    let shifted_refs = shifted_matched.iter().collect::<Vec<_>>();
    let shifted_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: plan.baselines,
        matched_workload_runs: &shifted_refs,
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: plan.live_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &shifted_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    for substituted_id in ["cpu-unreviewed-v9", "cpu-battery-v1"] {
        let mut substituted_baselines = baselines.clone();
        substituted_baselines[1]
            .workload
            .as_mut()
            .unwrap()
            .workload_id = substituted_id.into();
        let substituted_refs = substituted_baselines.iter().collect::<Vec<_>>();
        let substituted_plan = SupervisedEndurancePlan {
            preflight: plan.preflight,
            baselines: &substituted_refs,
            matched_workload_runs: plan.matched_workload_runs,
            tachometer_calibrations: plan.tachometer_calibrations,
            live_lifecycle: plan.live_lifecycle,
            workload: plan.workload.clone(),
        };
        let mut blocked_environment = EnduranceEnvironment::default();
        assert!(run_supervised_endurance(&mut blocked_environment, &substituted_plan).is_err());
        assert!(blocked_environment.events.is_empty());
    }

    let mut relabeled_baselines = baselines.clone();
    relabeled_baselines[2] = relabeled_baselines[1].clone();
    let relabeled_workload = relabeled_baselines[2].workload.as_mut().unwrap();
    relabeled_workload.workload_id = "gpu-ac-v1".into();
    relabeled_workload.command[0] = "/usr/lib/pt31553-fan-control/workloads/gpu".into();
    let relabeled_refs = relabeled_baselines.iter().collect::<Vec<_>>();
    let relabeled_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: &relabeled_refs,
        matched_workload_runs: plan.matched_workload_runs,
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: plan.live_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &relabeled_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    let mut retry_preflight = preflight.clone();
    retry_preflight.outcome.another_passing_run_required = true;
    let retry_preflight_plan = SupervisedEndurancePlan {
        preflight: &retry_preflight,
        baselines: plan.baselines,
        matched_workload_runs: plan.matched_workload_runs,
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: plan.live_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &retry_preflight_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    let mut retry_baselines = baselines.clone();
    retry_baselines[0].outcome.another_passing_run_required = true;
    let retry_baseline_refs = retry_baselines.iter().collect::<Vec<_>>();
    let retry_baseline_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: &retry_baseline_refs,
        matched_workload_runs: plan.matched_workload_runs,
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: plan.live_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &retry_baseline_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    let mut retry_lifecycle = lifecycle.clone();
    retry_lifecycle.outcome.another_passing_run_required = true;
    let retry_lifecycle_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: plan.baselines,
        matched_workload_runs: plan.matched_workload_runs,
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: &retry_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &retry_lifecycle_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    let mut retry_calibration = cpu_calibration.clone();
    retry_calibration.outcome.another_passing_run_required = true;
    let retry_calibration_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: plan.baselines,
        matched_workload_runs: plan.matched_workload_runs,
        tachometer_calibrations: MatchedWorkloadTachometerCalibrations {
            cpu: &retry_calibration,
            gpu: gpu_calibration,
        },
        live_lifecycle: plan.live_lifecycle,
        workload: plan.workload.clone(),
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &retry_calibration_plan).is_err());
    assert!(blocked_environment.events.is_empty());

    let mut mislabeled_workload = plan.workload.clone();
    mislabeled_workload.command = vec!["/usr/bin/true".into()];
    let mislabeled_workload_plan = SupervisedEndurancePlan {
        preflight: plan.preflight,
        baselines: plan.baselines,
        matched_workload_runs: plan.matched_workload_runs,
        tachometer_calibrations: plan.tachometer_calibrations,
        live_lifecycle: plan.live_lifecycle,
        workload: mislabeled_workload,
    };
    let mut blocked_environment = EnduranceEnvironment::default();
    assert!(run_supervised_endurance(&mut blocked_environment, &mislabeled_workload_plan).is_err());
    assert!(blocked_environment.events.is_empty());
}

#[test]
fn passing_endurance_publishes_evidence_before_authorization() {
    let fixture = qualification_fixture();
    let baseline_refs = fixture.baselines.iter().collect::<Vec<_>>();
    let matched_refs = fixture.matched.iter().collect::<Vec<_>>();
    let plan = fixture.plan(&baseline_refs, &matched_refs);
    let mut unsafe_environment = EnduranceEnvironment {
        overheat: true,
        ..EnduranceEnvironment::default()
    };
    let unsafe_report =
        run_supervised_endurance(&mut unsafe_environment, &plan).expect("failure is evidence");
    assert!(!unsafe_report.accepted());
    assert!(
        unsafe_report
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "absolute-thermal-abort")
    );
    assert_eq!(
        unsafe_environment.events[unsafe_environment.events.len() - 4..],
        [
            "stop-workload",
            "stop-service",
            "restore-cpu",
            "restore-gpu"
        ]
    );
    let rejected_destination = std::env::temp_dir().join(format!(
        "pt31553-rejected-qualification-{}.json",
        std::process::id()
    ));
    assert!(matches!(
        write_qualification_record_after_endurance(
            &rejected_destination,
            Path::new("/var/lib/pt31553-fan-control/evidence/endurance.json"),
            &plan,
            &unsafe_report,
        ),
        Err(QualificationAuthorizationError::EnduranceNotAccepted)
    ));
    assert!(!rejected_destination.exists());

    let mut environment = EnduranceEnvironment {
        stop_workload_delay_millis: 1,
        ..EnduranceEnvironment::default()
    };
    let report = run_supervised_endurance(&mut environment, &plan).expect("qualified plan runs");

    assert!(report.accepted(), "{:#?}", report.record().faults);
    assert_eq!(
        report.record().samples.len(),
        SUPERVISED_ENDURANCE_SAMPLE_COUNT
    );
    assert_eq!(
        environment.events[environment.events.len() - 4..],
        [
            "stop-workload",
            "stop-service",
            "restore-cpu",
            "restore-gpu"
        ]
    );
    assert!(environment.initial_confirmation_was_idle);
    assert_eq!(
        report.record().samples[0].cpu_utilization_basis_points,
        Some(8_000)
    );
    assert_eq!(
        report.record().samples[0].gpu_utilization_basis_points,
        Some(8_000)
    );
    assert!(report.record().validate().is_ok());

    // SAFETY: geteuid has no preconditions and does not mutate process state.
    let effective_user = unsafe { libc::geteuid() };
    let publication_directory = if effective_user == 0 {
        Path::new("/root").join(format!(
            "pt31553-qualification-publication-{}",
            std::process::id()
        ))
    } else {
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "pt31553-qualification-publication-{}",
                std::process::id()
            ))
    };
    fs::create_dir_all(&publication_directory).unwrap();
    fs::set_permissions(&publication_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let destination = publication_directory.join("qualification.json");
    let evidence_destination = publication_directory.join("endurance.json");
    if effective_user == 0 {
        let qualification = write_qualification_record_after_endurance(
            &destination,
            &evidence_destination,
            &plan,
            &report,
        )
        .expect("root can publish a passing qualification");
        let persisted: QualificationRecordV2 =
            serde_json::from_str(&fs::read_to_string(&destination).unwrap()).unwrap();
        assert_eq!(persisted, qualification);
        assert_eq!(
            fs::read_to_string(&evidence_destination).unwrap(),
            serde_json::to_string_pretty(report.record()).unwrap() + "\n"
        );
        assert_eq!(
            qualification.supervised_endurance().evidence_sha256(),
            sha256(&(serde_json::to_string_pretty(report.record()).unwrap() + "\n"))
        );
        let mut production_verifier = SystemOwnershipPlatform::new();
        production_verifier
            .verify_root_owned_supervised_endurance_evidence(
                &evidence_destination,
                qualification.supervised_endurance().evidence_sha256(),
                &plan.preflight.qualification_envelope,
            )
            .expect("production authority verifier accepts the published evidence");
        let tampered_destination = publication_directory.join("tampered-endurance.json");
        let mut tampered = serde_json::to_value(report.record()).unwrap();
        tampered["stage"] = "matched-workload".into();
        let tampered_source = serde_json::to_string_pretty(&tampered).unwrap() + "\n";
        fs::write(&tampered_destination, &tampered_source).unwrap();
        fs::set_permissions(&tampered_destination, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            production_verifier
                .verify_root_owned_supervised_endurance_evidence(
                    &tampered_destination,
                    &sha256(&tampered_source),
                    &plan.preflight.qualification_envelope,
                )
                .is_err()
        );
        assert_eq!(
            persisted.protected_policy_sha256(),
            plan.preflight
                .qualification_envelope
                .protected_policy_sha256
        );
        assert!(matches!(
            write_qualification_record_after_endurance(
                &destination,
                &evidence_destination,
                &plan,
                &report,
            ),
            Err(QualificationAuthorizationError::Write(_))
        ));
    } else {
        assert!(matches!(
            write_qualification_record_after_endurance(
                &destination,
                &evidence_destination,
                &plan,
                &report,
            ),
            Err(QualificationAuthorizationError::Write(_))
        ));
        assert!(!destination.exists());
    }
    fs::remove_dir_all(publication_directory).unwrap();
}

fn accepted_endurance_record() -> &'static EvidenceRecord {
    static ACCEPTED: OnceLock<EvidenceRecord> = OnceLock::new();
    ACCEPTED.get_or_init(|| {
        let fixture = qualification_fixture();
        let baseline_refs = fixture.baselines.iter().collect::<Vec<_>>();
        let matched_refs = fixture.matched.iter().collect::<Vec<_>>();
        let plan = fixture.plan(&baseline_refs, &matched_refs);
        let report = run_supervised_endurance(&mut EnduranceEnvironment::default(), &plan)
            .expect("qualified plan runs");
        assert!(report.accepted(), "{:#?}", report.record().faults);
        report.into_record()
    })
}

#[test]
fn schema_and_semantic_tampering_are_rejected() {
    let accepted = accepted_endurance_record().clone();
    let accepted_json = serde_json::to_value(&accepted).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/evidence-v2.json")).unwrap();
    let schema_validator = jsonschema::validator_for(&schema).unwrap();
    assert!(schema_validator.is_valid(&accepted_json));
    for schema_tampering in [
        {
            let mut value = accepted_json.clone();
            value["thermal_summary"]["system_stable"] = false.into();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["thermal_summary"]["kernel_faults"] = serde_json::json!(["fault"]);
            value
        },
        {
            let mut value = accepted_json.clone();
            value["outcome"]["another_passing_run_required"] = true.into();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["samples"][800]["external_power"] = "ac".into();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["restoration_attempts"][0]["fan"] = "gpu".into();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["restoration_attempts"][0]["outcome"] = "firmware-auto-unconfirmed".into();
            value
        },
        {
            let mut value = accepted_json.clone();
            let final_readback = value["readbacks"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|readback| readback["phase"] == "final" && readback["fan"] == "cpu")
                .unwrap();
            final_readback["fan"] = "gpu".into();
            value
        },
    ] {
        assert!(!schema_validator.is_valid(&schema_tampering));
    }
    for tampered in [
        {
            let mut value = accepted_json.clone();
            value["workload"]["power_profile"] = "battery".into();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["workload"]["command"] = serde_json::json!(["/usr/bin/true"]);
            value
        },
        {
            let mut value = accepted_json.clone();
            value["process_stops"][0]["process_identity"] = "/usr/bin/true".into();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["restoration_attempts"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
            value
        },
        {
            let mut value = accepted_json.clone();
            let before_service = value["process_stops"][0]["requested_at"].clone();
            for attempt in value["restoration_attempts"].as_array_mut().unwrap() {
                attempt["timestamp"] = before_service.clone();
            }
            for readback in value["readbacks"].as_array_mut().unwrap() {
                if readback["phase"] == "final" {
                    readback["timestamp"] = before_service.clone();
                }
            }
            value
        },
        {
            let mut value = accepted_json.clone();
            value["workload"]["ambient_millicelsius"] = (-50_000).into();
            value
        },
        {
            let mut value = accepted_json.clone();
            for sample in value["samples"].as_array_mut().unwrap() {
                sample["cpu_millicelsius"] = 95_000.into();
            }
            value["thermal_summary"]["cpu_peak_millicelsius"] = 95_000.into();
            value["thermal_summary"]["cpu_p95_millicelsius"] = 95_000.into();
            value["thermal_summary"]["cpu_final_slope_millicelsius_per_minute"] = 0.into();
            value
        },
        {
            let mut value = accepted_json.clone();
            let above_bound = value["endurance_thermal_envelope"]["cpu_peak_limit_millicelsius"]
                .as_i64()
                .unwrap()
                + 1;
            for sample in value["samples"].as_array_mut().unwrap() {
                sample["cpu_millicelsius"] = above_bound.into();
            }
            value["thermal_summary"]["cpu_peak_millicelsius"] = above_bound.into();
            value["thermal_summary"]["cpu_p95_millicelsius"] = above_bound.into();
            value["thermal_summary"]["cpu_final_slope_millicelsius_per_minute"] = 0.into();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["samples"][500]["cpu_utilization_basis_points"] = 8_000.into();
            value["samples"][500]["gpu_utilization_basis_points"] = 8_000.into();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["commands"][0]["timestamp"] = value["samples"][100]["timestamp"].clone();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["state_transitions"][2]["timestamp"] = value["workload_started_at"].clone();
            value
        },
        {
            let mut value = accepted_json.clone();
            value["completed_at"]["monotonic_millis"] = u64::MAX.into();
            value["completed_at"]["wall_unix_millis"] = i64::MAX.into();
            value["workload_started_at"]["monotonic_millis"] = (u64::MAX - 1_000).into();
            value
        },
    ] {
        let source = serde_json::to_string(&tampered).unwrap();
        assert!(parse_evidence_v2(&source).is_err());
    }
}

#[test]
fn runtime_failures_preserve_ordered_cleanup_evidence() {
    let fixture = qualification_fixture();
    let baseline_refs = fixture.baselines.iter().collect::<Vec<_>>();
    let matched_refs = fixture.matched.iter().collect::<Vec<_>>();
    let plan = fixture.plan(&baseline_refs, &matched_refs);
    let mut qualified_overheat_environment = EnduranceEnvironment {
        qualified_overheat: true,
        ..EnduranceEnvironment::default()
    };
    let qualified_overheat = run_supervised_endurance(&mut qualified_overheat_environment, &plan)
        .expect("qualified-envelope breach is retained as failed evidence");
    assert!(!qualified_overheat.accepted());
    assert_eq!(qualified_overheat.record().samples.len(), 1);
    assert!(
        qualified_overheat
            .record()
            .faults
            .iter()
            .any(|fault| { fault.code == "qualified-thermal-envelope-abort" })
    );

    let mut delayed_segment_environment = EnduranceEnvironment {
        segment_delay_millis: 101,
        ..EnduranceEnvironment::default()
    };
    let delayed_segment = run_supervised_endurance(&mut delayed_segment_environment, &plan)
        .expect("timing failure is evidence");
    assert!(!delayed_segment.accepted());
    assert!(delayed_segment_environment.events.contains(&"stop-service"));

    let mut invalid_segment_environment = EnduranceEnvironment {
        invalid_segment_confirmation: true,
        ..EnduranceEnvironment::default()
    };
    let invalid_segment = run_supervised_endurance(&mut invalid_segment_environment, &plan)
        .expect("invalid load confirmation is evidence");
    assert!(!invalid_segment.accepted());
    assert!(
        invalid_segment
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "endurance-segment")
    );

    let mut invalid_sample_environment = EnduranceEnvironment {
        invalid_sample_utilization: true,
        ..EnduranceEnvironment::default()
    };
    let invalid_sample = run_supervised_endurance(&mut invalid_sample_environment, &plan)
        .expect("continuous load failure is evidence");
    assert!(!invalid_sample.accepted());
    assert!(
        invalid_sample
            .record()
            .faults
            .iter()
            .any(|fault| fault.detail.contains("continuous workload utilization"))
    );

    let mut out_of_range_environment = EnduranceEnvironment {
        out_of_range_sample_utilization: true,
        ..EnduranceEnvironment::default()
    };
    let out_of_range = run_supervised_endurance(&mut out_of_range_environment, &plan)
        .expect("out-of-range utilization is retained as failed evidence");
    assert!(!out_of_range.accepted());
    assert!(
        out_of_range
            .record()
            .faults
            .iter()
            .any(|fault| fault.detail.contains("continuous workload utilization"))
    );

    let mut delayed_capture_environment = EnduranceEnvironment {
        capture_delay_millis: 101,
        ..EnduranceEnvironment::default()
    };
    let delayed_capture = run_supervised_endurance(&mut delayed_capture_environment, &plan)
        .expect("capture timing failure is evidence");
    assert!(!delayed_capture.accepted());
    assert!(delayed_capture.record().samples.is_empty());
    assert!(
        delayed_capture
            .record()
            .outcome
            .final_firmware_auto_confirmed
    );
    assert!(
        delayed_capture
            .record()
            .restoration_attempts
            .iter()
            .all(|attempt| {
                attempt.outcome == RestorationOutcome::FirmwareAutoConfirmed
                    && attempt.auto_write_succeeded
                    && attempt.enable_readback == Some(2)
            })
    );

    let mut failed_starting_conditions_environment = EnduranceEnvironment {
        fail_starting_conditions: true,
        ..EnduranceEnvironment::default()
    };
    let failed_starting_conditions =
        run_supervised_endurance(&mut failed_starting_conditions_environment, &plan)
            .expect("starting-condition failure is retained as failed evidence");
    assert!(!failed_starting_conditions.accepted());
    assert!(failed_starting_conditions.record().commands.is_empty());
    assert!(
        failed_starting_conditions
            .record()
            .restoration_attempts
            .is_empty()
    );
    assert!(
        !failed_starting_conditions
            .record()
            .outcome
            .final_firmware_auto_confirmed
    );
    assert!(failed_starting_conditions_environment.events.is_empty());

    let mut regressed_capture_environment = EnduranceEnvironment {
        regress_after_wait: true,
        ..EnduranceEnvironment::default()
    };
    let regressed_capture = run_supervised_endurance(&mut regressed_capture_environment, &plan)
        .expect("clock regression is retained as failed evidence");
    assert!(!regressed_capture.accepted());
    assert!(regressed_capture.record().faults.iter().any(|fault| {
        fault.code == "sample-cadence" && fault.detail.contains("completed wait")
    }));

    let mut delayed_stop_environment = EnduranceEnvironment {
        stop_workload_delay_millis: 10_001,
        ..EnduranceEnvironment::default()
    };
    let delayed_stop = run_supervised_endurance(&mut delayed_stop_environment, &plan)
        .expect("stop timing failure is evidence");
    assert!(!delayed_stop.accepted());
    assert!(
        delayed_stop
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "workload-stop")
    );

    let mut contained_environment = EnduranceEnvironment {
        stop_workload_running: true,
        ..EnduranceEnvironment::default()
    };
    let contained = run_supervised_endurance(&mut contained_environment, &plan)
        .expect("hard-stop containment is retained as failed evidence");
    assert!(!contained.accepted());
    assert_eq!(
        contained_environment.events[contained_environment.events.len() - 5..],
        [
            "stop-workload",
            "contain-workload",
            "stop-service",
            "restore-cpu",
            "restore-gpu"
        ]
    );

    let mut uncontained_environment = EnduranceEnvironment {
        stop_workload_running: true,
        containment_running: true,
        ..EnduranceEnvironment::default()
    };
    let uncontained = run_supervised_endurance(&mut uncontained_environment, &plan)
        .expect("uncontained workload is retained as failed evidence");
    assert!(!uncontained.accepted());
    assert_eq!(
        &uncontained_environment.events[uncontained_environment.events.len() - 6..],
        &[
            "stop-workload",
            "contain-workload",
            "force-contain-workload",
            "stop-service",
            "restore-cpu",
            "restore-gpu"
        ][..]
    );
    assert_eq!(uncontained.record().process_stops.len(), 2);
    assert_eq!(uncontained.record().restoration_attempts.len(), 2);
    serde_json::to_string(uncontained.record()).expect("failed containment evidence serializes");

    let mut unconfirmed_terminal_containment_environment = EnduranceEnvironment {
        stop_workload_running: true,
        containment_running: true,
        force_workload_running: true,
        ..EnduranceEnvironment::default()
    };
    let unconfirmed_terminal_containment =
        run_supervised_endurance(&mut unconfirmed_terminal_containment_environment, &plan)
            .expect("unconfirmed terminal containment is retained as failed evidence");
    assert!(!unconfirmed_terminal_containment.accepted());
    assert!(
        unconfirmed_terminal_containment
            .record()
            .process_stops
            .iter()
            .all(|stop| stop.process != StoppedProcess::Workload)
    );
    assert!(
        unconfirmed_terminal_containment
            .record()
            .faults
            .iter()
            .any(|fault| fault.code == "workload-terminal-containment")
    );

    let mut service_contained_environment = EnduranceEnvironment {
        stop_service_running: true,
        ..EnduranceEnvironment::default()
    };
    let service_contained = run_supervised_endurance(&mut service_contained_environment, &plan)
        .expect("service containment is retained as failed evidence");
    assert!(!service_contained.accepted());
    assert_eq!(
        &service_contained_environment.events[service_contained_environment.events.len() - 5..],
        &[
            "stop-workload",
            "stop-service",
            "contain-service",
            "restore-cpu",
            "restore-gpu"
        ]
    );

    let mut service_uncontained_environment = EnduranceEnvironment {
        stop_service_running: true,
        service_containment_running: true,
        ..EnduranceEnvironment::default()
    };
    let service_uncontained = run_supervised_endurance(&mut service_uncontained_environment, &plan)
        .expect("uncontained service is retained as failed evidence");
    assert!(!service_uncontained.accepted());
    assert_eq!(
        &service_uncontained_environment.events[service_uncontained_environment.events.len() - 6..],
        &[
            "stop-workload",
            "stop-service",
            "contain-service",
            "force-contain-service",
            "restore-cpu",
            "restore-gpu"
        ]
    );
    assert_eq!(service_uncontained.record().restoration_attempts.len(), 2);
    assert!(
        service_uncontained
            .record()
            .outcome
            .final_firmware_auto_confirmed
    );

    let mut all_stops_fail_environment = EnduranceEnvironment {
        stop_workload_running: true,
        containment_running: true,
        force_workload_failure: true,
        stop_service_running: true,
        service_containment_running: true,
        force_service_failure: true,
        ..EnduranceEnvironment::default()
    };
    let all_stops_fail = run_supervised_endurance(&mut all_stops_fail_environment, &plan)
        .expect("failed cleanup is retained as failed evidence");
    assert!(!all_stops_fail.accepted());
    assert_eq!(
        &all_stops_fail_environment.events[all_stops_fail_environment.events.len() - 8..],
        &[
            "stop-workload",
            "contain-workload",
            "force-contain-workload",
            "stop-service",
            "contain-service",
            "force-contain-service",
            "restore-cpu",
            "restore-gpu",
        ]
    );
    assert!(all_stops_fail.record().process_stops.is_empty());
    assert_eq!(all_stops_fail.record().restoration_attempts.len(), 2);
    assert!(
        all_stops_fail
            .record()
            .outcome
            .final_firmware_auto_confirmed
    );
}

fn baseline(
    envelope: &QualificationEnvelopeIdentityV1,
    id: &str,
    profile: EvidenceProfile,
    samples: usize,
) -> EvidenceRecord {
    let mut platform = auto_platform();
    let measurement_offset = match id {
        "idle-ac-v1" => 0,
        "cpu-ac-v1" => 100,
        "gpu-ac-v1" => 200,
        "combined-ac-v1" => 300,
        "idle-battery-v1" => 400,
        "cpu-battery-v1" => 500,
        "gpu-battery-v1" => 600,
        _ => 0,
    };
    let observations = (1..=samples)
        .map(|sample| {
            let mut sample = sample_evidence(sample as u64 * 2_000, profile);
            sample.cpu_millicelsius = sample
                .cpu_millicelsius
                .map(|value| value + measurement_offset);
            BaselineObservation {
                sample,
                system_stable: true,
                kernel_faults: vec![],
                nvidia_faults: vec![],
            }
        })
        .collect();
    run_firmware_auto_baseline(
        &mut platform,
        &mut BaselineEnvironment::new(observations, profile),
        &FirmwareAutoBaselinePlan {
            hwmon_root: Path::new(HWMON_ROOT),
            qualification_envelope: envelope.clone(),
            preflight_binding_sha256: "a".repeat(64),
            nvidia_gpu_uuid: "GPU-11111111-2222-3333-4444-555555555555".into(),
            expected_fan_endpoint_identities: fan_endpoint_identities(),
            workload: workload(id, profile),
            samples_required: samples,
        },
    )
    .expect("baseline plan is valid")
    .into_record()
}

fn preflight(envelope: QualificationEnvelopeIdentityV1) -> EvidenceRecord {
    let at = timestamp(1);
    EvidenceRecord {
        schema_version: 2,
        record_status: EvidenceRecordStatus::Complete,
        qualification_envelope: envelope,
        stage: "preflight".into(),
        started_at: at,
        completed_at: at,
        starting_conditions_captured_at: None,
        workload_started_at: None,
        baseline_binding_sha256: None,
        preflight_binding_sha256: None,
        nvidia_gpu_uuid: Some("GPU-11111111-2222-3333-4444-555555555555".into()),
        fan_endpoint_identities: Some(FanEndpointIdentitiesEvidence {
            cpu_pwm: "device-0-inode-7".into(),
            cpu_enable: "device-0-inode-8".into(),
            cpu_tachometer: "device-0-inode-9".into(),
            gpu_pwm: "device-0-inode-10".into(),
            gpu_enable: "device-0-inode-11".into(),
            gpu_tachometer: "device-0-inode-12".into(),
        }),
        preflight_checks: Some(
            [
                "platform",
                "trust",
                "fan-abi",
                "sensors",
                "configuration",
                "policy",
                "recovery",
                "stock-boot-fallback",
                "tooling",
                "disk-space",
                "competing-services",
                "firmware-auto",
            ]
            .into_iter()
            .map(|check| PreflightCheckEvidence {
                timestamp: at,
                check: check.into(),
                passed: true,
                detail: format!("{check} passed"),
            })
            .collect(),
        ),
        workload: None,
        samples: vec![],
        commands: vec![],
        readbacks: [EvidenceFan::Cpu, EvidenceFan::Gpu]
            .map(|fan| FanReadbackEvidence {
                timestamp: at,
                source_timestamp: None,
                fresh: None,
                boot_id: None,
                fan,
                field: FanReadbackField::Enable,
                value: Some(2),
                endpoint_identity: format!("{fan:?}-Enable-endpoint"),
                outcome: ObservationOutcome::Confirmed,
                phase: Some(FanReadbackPhase::Final),
            })
            .into(),
        state_transitions: vec![],
        faults: vec![],
        restoration_attempts: vec![],
        process_stops: vec![],
        calibration: vec![],
        firmware_auto_cleanup: None,
        thermal_summary: None,
        endurance_thermal_envelope: None,
        live_lifecycle_cases: None,
        outcome: RunOutcomeEvidence {
            status: RunOutcomeStatus::Passed,
            reason: "preflight passed".into(),
            another_passing_run_required: false,
            final_firmware_auto_confirmed: true,
        },
    }
}

fn workload(id: &str, profile: EvidenceProfile) -> WorkloadEvidence {
    let executable = match id {
        "idle-ac-v1" | "idle-battery-v1" => "idle",
        "cpu-ac-v1" | "cpu-battery-v1" => "cpu",
        "gpu-ac-v1" | "gpu-battery-v1" => "gpu",
        "combined-ac-v1" => "combined",
        SUPERVISED_ENDURANCE_WORKLOAD_ID => "mixed",
        _ => "unknown",
    };
    WorkloadEvidence {
        workload_id: id.into(),
        command: vec![
            format!("/usr/lib/pt31553-fan-control/workloads/{executable}"),
            "--fixed".into(),
        ],
        version: "1.0.0".into(),
        power_profile: profile,
        ambient_millicelsius: 24_000,
        starting_cpu_millicelsius: 42_000,
        starting_gpu_millicelsius: 39_000,
    }
}

fn envelope() -> QualificationEnvelopeIdentityV1 {
    QualificationEnvelopeIdentityV1 {
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
        wall_unix_millis: 1_787_691_600_000 + monotonic_millis as i64,
    }
}

fn sample_evidence(at: u64, profile: EvidenceProfile) -> TelemetrySampleEvidence {
    TelemetrySampleEvidence {
        timestamp: timestamp(at),
        cpu_millicelsius: Some(65_000),
        gpu_millicelsius: Some(54_000),
        freshness: SampleFreshness::Fresh,
        external_power: Some(match profile {
            EvidenceProfile::Ac => EvidenceExternalPower::Ac,
            EvidenceProfile::Battery => EvidenceExternalPower::Battery,
        }),
        selected_profile: Some(profile),
        cpu_source_demand_basis_points: Some(5_000),
        gpu_source_demand_basis_points: Some(4_000),
        cpu_utilization_basis_points: Some(6_000),
        gpu_utilization_basis_points: Some(5_000),
        commanded_demand_basis_points: Some(5_000),
        cpu_thermal_throttling: Some(false),
        gpu_thermal_throttling: Some(false),
    }
}

fn custom_observation(at: u64, profile: EvidenceProfile) -> MatchedWorkloadObservation {
    MatchedWorkloadObservation {
        sample: sample_evidence(at, profile),
        commands: [EvidenceFan::Cpu, EvidenceFan::Gpu]
            .map(|fan| FanCommandEvidence {
                timestamp: timestamp(at),
                fan,
                field: FanControlField::Pwm,
                value: 128,
            })
            .into(),
        readbacks: control_readbacks(at),
        controller_fault: None,
        system_stable: true,
        kernel_faults: vec![],
        nvidia_faults: vec![],
    }
}

fn control_readbacks(at: u64) -> Vec<FanReadbackEvidence> {
    [EvidenceFan::Cpu, EvidenceFan::Gpu]
        .into_iter()
        .flat_map(|fan| {
            [
                (FanReadbackField::Enable, 1),
                (FanReadbackField::Pwm, 128),
                (FanReadbackField::Rpm, 3_000),
            ]
            .map(move |(field, value)| FanReadbackEvidence {
                timestamp: timestamp(at),
                source_timestamp: None,
                fresh: None,
                boot_id: None,
                fan,
                field,
                value: Some(value),
                endpoint_identity: format!("{fan:?}-{field:?}-endpoint"),
                outcome: ObservationOutcome::Confirmed,
                phase: Some(FanReadbackPhase::Sample),
            })
        })
        .collect()
}

struct BaselineEnvironment {
    observations: VecDeque<BaselineObservation>,
    now: u64,
    profile: EvidenceProfile,
}

impl BaselineEnvironment {
    fn new(observations: Vec<BaselineObservation>, profile: EvidenceProfile) -> Self {
        Self {
            observations: observations.into(),
            now: 0,
            profile,
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
            conditions: BaselineStartingConditions {
                ambient_millicelsius: 24_000,
                cpu_millicelsius: 42_000,
                gpu_millicelsius: 39_000,
                power_profile: self.profile,
            },
            captured_at: timestamp(self.now),
        })
    }
    fn start_workload(
        &mut self,
        _: &WorkloadEvidence,
        _: u64,
    ) -> Result<EvidenceTimestamp, String> {
        Ok(timestamp(self.now))
    }
    fn wait_until(&mut self, target: u64, _: u64) -> Result<(), String> {
        self.now = target;
        Ok(())
    }
    fn capture_observation(&mut self, _: u64) -> Result<BaselineObservation, String> {
        self.observations
            .pop_front()
            .ok_or_else(|| "no observation".into())
    }
    fn stop_workload(&mut self, _: u64) -> Result<(), String> {
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
    now: u64,
    profile: EvidenceProfile,
}

impl CustomEnvironment {
    fn new(observations: Vec<MatchedWorkloadObservation>, profile: EvidenceProfile) -> Self {
        let now = observations.first().map_or(10_000, |observation| {
            observation.sample.timestamp.monotonic_millis - 2_000
        });
        Self {
            observations: observations.into(),
            now,
            profile,
        }
    }
}

impl MatchedWorkloadEnvironment for CustomEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        timestamp(self.now)
    }
    fn capture_starting_conditions(
        &mut self,
        _: u64,
    ) -> Result<CapturedMatchedWorkloadStartingConditions, String> {
        Ok(CapturedMatchedWorkloadStartingConditions {
            conditions: MatchedWorkloadStartingConditions {
                ambient_millicelsius: 24_000,
                cpu_millicelsius: 42_000,
                gpu_millicelsius: 39_000,
                power_profile: self.profile,
            },
            captured_at: timestamp(self.now),
        })
    }
    fn enter_custom_control(&mut self, _: u64) -> Result<(), String> {
        Ok(())
    }
    fn start_workload(
        &mut self,
        _: &WorkloadEvidence,
        _: u64,
    ) -> Result<EvidenceTimestamp, String> {
        Ok(timestamp(self.now))
    }
    fn wait_until(&mut self, target: u64, _: u64) -> Result<(), String> {
        self.now = target;
        Ok(())
    }
    fn capture_observation(&mut self, _: u64) -> Result<MatchedWorkloadObservation, String> {
        self.observations
            .pop_front()
            .ok_or_else(|| "no observation".into())
    }
    fn stop_workload(&mut self, _: u64) -> Result<(), String> {
        self.now += 1;
        Ok(())
    }
    fn restore_fan(&mut self, fan: EvidenceFan, _: u64) -> MatchedWorkloadFanRestoration {
        self.now += 1;
        successful_restoration(fan)
    }
}

#[derive(Default)]
struct LifecycleEnvironment {
    now: u64,
    after_reboot: bool,
}

impl LifecycleEnvironment {
    fn tick(&mut self) -> EvidenceTimestamp {
        self.now += 1;
        timestamp(self.now)
    }
    fn identity(&self, fan: EvidenceFan) -> String {
        format!(
            "{fan:?}-{}",
            if self.after_reboot {
                "postboot"
            } else {
                "enable"
            }
        )
    }
    fn pair(&mut self) -> LiveLifecycleFanAutoPair {
        let cpu_identity = self.identity(EvidenceFan::Cpu);
        let gpu_identity = self.identity(EvidenceFan::Gpu);
        LiveLifecycleFanAutoPair {
            cpu: LiveLifecycleFanAutoObservation {
                observed_at: self.tick(),
                fresh: true,
                enable_readback: Some(2),
                endpoint_identity: cpu_identity,
            },
            gpu: LiveLifecycleFanAutoObservation {
                observed_at: self.tick(),
                fresh: true,
                enable_readback: Some(2),
                endpoint_identity: gpu_identity,
            },
        }
    }
}

impl LiveLifecycleEnvironment for LifecycleEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        self.tick()
    }
    fn run_case(
        &mut self,
        case: LiveLifecycleCase,
    ) -> Result<LiveLifecycleCaseObservation, String> {
        Ok(match case {
            LiveLifecycleCase::InvalidConfiguration => {
                LiveLifecycleCaseObservation::InvalidConfiguration {
                    observed_at: self.tick(),
                    fresh: true,
                    rejected_before_custom_control: true,
                }
            }
            LiveLifecycleCase::DuplicateProcess => LiveLifecycleCaseObservation::DuplicateProcess {
                observed_at: self.tick(),
                fresh: true,
                duplicate_rejected: true,
                original_owner_preserved: true,
                original_process_identity: "owner".into(),
                rejected_process_identity: "duplicate".into(),
            },
            LiveLifecycleCase::NormalStopRestart => {
                let stopped_at = self.tick();
                let auto_before_restart = self.pair();
                let restarted_at = self.tick();
                LiveLifecycleCaseObservation::NormalStopRestart {
                    clean_stop: true,
                    stopped_at,
                    auto_before_restart,
                    restarted_at,
                    fresh_process: true,
                    process_identity_before: "before-stop".into(),
                    process_identity_after: "after-stop".into(),
                }
            }
            LiveLifecycleCase::ProcessKillRecovery => {
                let start_limit_reset_at = self.tick();
                let killed_at = self.tick();
                let auto_before_restart = self.pair();
                let restarted_at = self.tick();
                LiveLifecycleCaseObservation::ProcessKillRecovery {
                    sigkill_observed: true,
                    start_limit_reset_at,
                    killed_at,
                    auto_before_restart,
                    restarted_at,
                    process_identity_before: "before-kill".into(),
                    process_identity_after: "after-kill".into(),
                    restart_delay_millis: 2_000,
                    start_limit_burst: 2,
                }
            }
            LiveLifecycleCase::WatchdogRecovery => {
                let start_limit_reset_at = self.tick();
                let expired_at = self.tick();
                let auto_before_restart = self.pair();
                let restarted_at = self.tick();
                LiveLifecycleCaseObservation::WatchdogRecovery {
                    watchdog_expired: true,
                    start_limit_reset_at,
                    expired_at,
                    auto_before_restart,
                    restarted_at,
                    process_identity_before: "before-watchdog".into(),
                    process_identity_after: "after-watchdog".into(),
                    restart_delay_millis: 2_000,
                    start_limit_burst: 2,
                }
            }
            LiveLifecycleCase::AcToBatteryTransition => {
                let before = LiveLifecyclePowerObservation {
                    observed_at: self.tick(),
                    fresh: true,
                    source: EvidenceExternalPower::Ac,
                };
                let after = LiveLifecyclePowerObservation {
                    observed_at: self.tick(),
                    fresh: true,
                    source: EvidenceExternalPower::Battery,
                };
                let selected_profile_after = LiveLifecycleProfileObservation {
                    observed_at: self.tick(),
                    fresh: true,
                    profile: EvidenceProfile::Battery,
                };
                LiveLifecycleCaseObservation::AcToBatteryTransition {
                    before,
                    after,
                    selected_profile_after,
                }
            }
            LiveLifecycleCase::SuspendResume => {
                let auto_before_sleep = self.pair();
                let suspended_at = self.tick();
                let resumed_at = self.tick();
                let process_started_at = self.tick();
                LiveLifecycleCaseObservation::SuspendResume {
                    auto_before_sleep,
                    suspended_at,
                    suspend_completed: true,
                    resumed_at,
                    process_started_at,
                    process_identity_before: "before-suspend".into(),
                    process_identity_after: "after-suspend".into(),
                }
            }
            LiveLifecycleCase::Reboot => unreachable!(),
        })
    }
    fn resume_after_reboot(&mut self) -> Result<LiveLifecycleRebootContinuation, String> {
        self.after_reboot = true;
        Ok(LiveLifecycleRebootContinuation {
            reboot_completed: true,
            boot_id_before: "boot-before".into(),
            boot_id_after: "boot-after".into(),
            post_boot_at: self.tick(),
        })
    }
    fn arm_after_reboot(&mut self) -> Result<LiveLifecycleRebootArmObservation, String> {
        Ok(LiveLifecycleRebootArmObservation {
            armed_at: self.tick(),
            controller_process_identity: "after-reboot".into(),
        })
    }
    fn confirm_firmware_auto(
        &mut self,
        fan: EvidenceFan,
    ) -> Result<LiveLifecycleFanAutoObservation, String> {
        let identity = self.identity(fan);
        Ok(LiveLifecycleFanAutoObservation {
            observed_at: self.tick(),
            fresh: true,
            enable_readback: Some(2),
            endpoint_identity: identity,
        })
    }
}

#[derive(Default)]
struct EnduranceEnvironment {
    now: u64,
    profile: Option<EvidenceProfile>,
    load: Option<fan_control_core::SupervisedEnduranceLoad>,
    events: Vec<&'static str>,
    overheat: bool,
    qualified_overheat: bool,
    initial_confirmation_was_idle: bool,
    invalid_segment_confirmation: bool,
    invalid_sample_utilization: bool,
    out_of_range_sample_utilization: bool,
    segment_delay_millis: u64,
    capture_delay_millis: u64,
    fail_starting_conditions: bool,
    regress_after_wait: bool,
    stop_workload_delay_millis: u64,
    stop_workload_running: bool,
    containment_running: bool,
    force_workload_failure: bool,
    force_workload_running: bool,
    stop_service_running: bool,
    service_containment_running: bool,
    force_service_failure: bool,
    force_service_running: bool,
}

impl SupervisedEnduranceEnvironment for EnduranceEnvironment {
    fn timestamp(&mut self) -> EvidenceTimestamp {
        timestamp(self.now)
    }
    fn capture_starting_conditions(
        &mut self,
        _: u64,
    ) -> Result<CapturedMatchedWorkloadStartingConditions, String> {
        if self.fail_starting_conditions {
            return Err("starting conditions unavailable".into());
        }
        Ok(CapturedMatchedWorkloadStartingConditions {
            conditions: MatchedWorkloadStartingConditions {
                ambient_millicelsius: 24_000,
                cpu_millicelsius: 42_000,
                gpu_millicelsius: 39_000,
                power_profile: EvidenceProfile::Ac,
            },
            captured_at: timestamp(self.now),
        })
    }
    fn enter_custom_control(&mut self, _: u64) -> Result<(), String> {
        self.events.push("enter-custom");
        Ok(())
    }
    fn begin_segment(
        &mut self,
        segment: SupervisedEnduranceSegment,
        _: u64,
    ) -> Result<SupervisedEnduranceSegmentConfirmation, String> {
        let initial = segment.id == SUPERVISED_ENDURANCE_SEGMENTS[0].id;
        if !initial {
            self.now += self.segment_delay_millis;
        }
        self.profile = Some(segment.power_profile);
        self.load = Some(segment.load);
        self.events.push(segment.id);
        let utilization = match (initial, segment.load) {
            (true, _) => {
                self.initial_confirmation_was_idle = true;
                500
            }
            (false, fan_control_core::SupervisedEnduranceLoad::Load) => 8_000,
            (false, fan_control_core::SupervisedEnduranceLoad::Idle) => 500,
        };
        Ok(SupervisedEnduranceSegmentConfirmation {
            observed_at: timestamp(self.now),
            load: segment.load,
            external_power: match segment.power_profile {
                EvidenceProfile::Ac => EvidenceExternalPower::Ac,
                EvidenceProfile::Battery => EvidenceExternalPower::Battery,
            },
            selected_profile: segment.power_profile,
            cpu_utilization_basis_points: if self.invalid_segment_confirmation {
                10_001
            } else {
                utilization
            },
            gpu_utilization_basis_points: utilization,
        })
    }
    fn start_workload(
        &mut self,
        _: &WorkloadEvidence,
        _: u64,
    ) -> Result<EvidenceTimestamp, String> {
        self.events.push("start-workload");
        Ok(timestamp(self.now))
    }
    fn wait_until(&mut self, target: u64, _: u64) -> Result<(), String> {
        self.now = target;
        Ok(())
    }
    fn capture_observation(&mut self, _: u64) -> Result<MatchedWorkloadObservation, String> {
        let mut observation = custom_observation(self.now, self.profile.expect("active segment"));
        let utilization = match self.load.expect("active segment") {
            fan_control_core::SupervisedEnduranceLoad::Load => 8_000,
            fan_control_core::SupervisedEnduranceLoad::Idle => 500,
        };
        observation.sample.cpu_utilization_basis_points =
            Some(if self.out_of_range_sample_utilization {
                10_001
            } else if self.invalid_sample_utilization {
                500
            } else {
                utilization
            });
        observation.sample.gpu_utilization_basis_points = Some(utilization);
        self.now += self.capture_delay_millis;
        if self.regress_after_wait {
            self.now = self.now.saturating_sub(1);
        }
        if self.overheat {
            observation.sample.cpu_millicelsius = Some(95_000);
        } else if self.qualified_overheat {
            observation.sample.cpu_millicelsius = Some(90_000);
        }
        Ok(observation)
    }
    fn stop_workload(
        &mut self,
        _: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.events.push("stop-workload");
        self.now += self.stop_workload_delay_millis;
        Ok(SupervisedEnduranceProcessStopConfirmation {
            observed_at: timestamp(self.now),
            process_identity: "/usr/lib/pt31553-fan-control/workloads/mixed".into(),
            running: self.stop_workload_running,
        })
    }
    fn contain_workload(
        &mut self,
        _: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.events.push("contain-workload");
        self.now += 1;
        Ok(SupervisedEnduranceProcessStopConfirmation {
            observed_at: timestamp(self.now),
            process_identity: "/usr/lib/pt31553-fan-control/workloads/mixed".into(),
            running: self.containment_running,
        })
    }
    fn force_contain_workload(
        &mut self,
        _: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.events.push("force-contain-workload");
        self.now += 1;
        if self.force_workload_failure {
            Err("terminal workload containment failed".into())
        } else {
            Ok(SupervisedEnduranceProcessStopConfirmation {
                observed_at: timestamp(self.now),
                process_identity: "/usr/lib/pt31553-fan-control/workloads/mixed".into(),
                running: self.force_workload_running,
            })
        }
    }
    fn stop_service(
        &mut self,
        _: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.events.push("stop-service");
        self.now += 1;
        Ok(SupervisedEnduranceProcessStopConfirmation {
            observed_at: timestamp(self.now),
            process_identity: "pt31553-fan-control.service".into(),
            running: self.stop_service_running,
        })
    }
    fn contain_service(
        &mut self,
        _: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.events.push("contain-service");
        self.now += 1;
        Ok(SupervisedEnduranceProcessStopConfirmation {
            observed_at: timestamp(self.now),
            process_identity: "pt31553-fan-control.service".into(),
            running: self.service_containment_running,
        })
    }
    fn force_contain_service(
        &mut self,
        _: u64,
    ) -> Result<SupervisedEnduranceProcessStopConfirmation, String> {
        self.events.push("force-contain-service");
        self.now += 1;
        if self.force_service_failure {
            Err("terminal service containment failed".into())
        } else {
            Ok(SupervisedEnduranceProcessStopConfirmation {
                observed_at: timestamp(self.now),
                process_identity: "pt31553-fan-control.service".into(),
                running: self.force_service_running,
            })
        }
    }
    fn restore_fan(&mut self, fan: EvidenceFan, _: u64) -> MatchedWorkloadFanRestoration {
        self.events.push(match fan {
            EvidenceFan::Cpu => "restore-cpu",
            EvidenceFan::Gpu => "restore-gpu",
        });
        self.now += 1;
        successful_restoration(fan)
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

fn shift_all_timestamps(value: &mut serde_json::Value, offset: u64) {
    match value {
        serde_json::Value::Array(values) => {
            values
                .iter_mut()
                .for_each(|value| shift_all_timestamps(value, offset));
        }
        serde_json::Value::Object(object) => {
            if object.contains_key("monotonic_millis") && object.contains_key("wall_unix_millis") {
                let monotonic = object["monotonic_millis"].as_u64().unwrap();
                let wall = object["wall_unix_millis"].as_i64().unwrap();
                object.insert("monotonic_millis".into(), (monotonic + offset).into());
                object.insert("wall_unix_millis".into(), (wall + offset as i64).into());
            } else {
                object
                    .values_mut()
                    .for_each(|value| shift_all_timestamps(value, offset));
            }
        }
        _ => {}
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
