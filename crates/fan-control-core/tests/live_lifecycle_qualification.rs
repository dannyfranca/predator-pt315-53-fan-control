mod support;

use fan_control_core::{
    DangerousLiveFaultInjection, EvidenceExternalPower, EvidenceFan, EvidenceProfile,
    EvidenceTimestamp, LIVE_RESTART_DELAY_MILLIS, LIVE_START_LIMIT_BURST, LiveLifecycleCase,
    LiveLifecycleCaseObservation, LiveLifecycleEnvironment, LiveLifecycleFanAutoObservation,
    LiveLifecycleFanAutoPair, LiveLifecyclePlanError, LiveLifecyclePowerObservation,
    LiveLifecycleProfileObservation, LiveLifecycleRebootArmObservation,
    LiveLifecycleRebootContinuation, LiveLifecycleRequest, RunOutcomeStatus,
    classify_live_lifecycle_request, parse_evidence_v2, run_live_lifecycle_qualification,
};
use support::{PROTECTED_POLICY, compatibility_declaration};

const EVIDENCE_V2_SCHEMA: &str = include_str!("../../../schemas/evidence-v2.json");

#[test]
fn every_approved_case_runs_in_order_with_an_independent_auto_gate_between_cases() {
    let mut environment = LifecycleEnvironment::default();

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

    assert!(report.accepted(), "{:#?}", report.record());
    assert_eq!(report.record().outcome.status, RunOutcomeStatus::Passed);
    assert_eq!(report.cases().len(), LiveLifecycleCase::ALL.len());
    assert_eq!(
        report
            .cases()
            .iter()
            .map(|result| result.case())
            .collect::<Vec<_>>(),
        LiveLifecycleCase::ALL
    );
    assert!(report.cases().iter().all(|result| result.passed()));
    assert_eq!(
        report.record().readbacks.len(),
        2 + 2 * LiveLifecycleCase::ALL.len()
    );
    assert_eq!(
        report.record().state_transitions.len(),
        2 * LiveLifecycleCase::ALL.len()
    );
    for (index, result) in report.cases().iter().enumerate() {
        let preceding_gpu_gate = &report.record().readbacks[index * 2 + 1];
        assert!(
            preceding_gpu_gate.timestamp.monotonic_millis < result.started_at().monotonic_millis
        );
        if result.case() != LiveLifecycleCase::Reboot {
            let following_cpu_gate = &report.record().readbacks[(index + 1) * 2];
            assert!(result.started_at().monotonic_millis < result.completed_at().monotonic_millis);
            assert!(
                result.completed_at().monotonic_millis
                    < following_cpu_gate.timestamp.monotonic_millis
            );
        }
    }
    assert!(report.record().validate().is_ok());

    let mut expected = vec!["auto:cpu".to_owned(), "auto:gpu".to_owned()];
    for case in LiveLifecycleCase::ALL {
        expected.push(format!("case:{}", case.id()));
        expected.push("auto:cpu".to_owned());
        expected.push("auto:gpu".to_owned());
        if case == LiveLifecycleCase::Reboot {
            expected.push("arm:reboot".to_owned());
        }
    }
    assert_eq!(environment.events, expected);
}

#[test]
fn passing_report_round_trips_with_durable_case_proof_and_matches_the_v2_schema() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

    let json = serde_json::to_string(report.record()).unwrap();
    let parsed = parse_evidence_v2(&json).unwrap();
    let cases = parsed.live_lifecycle_cases.as_ref().unwrap();
    assert_eq!(cases.len(), LiveLifecycleCase::ALL.len());
    assert!(
        cases
            .iter()
            .all(|case| case.passed() && case.observation().is_some())
    );

    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));

    let mut stale_gate = value.clone();
    stale_gate["readbacks"][0]["fresh"] = false.into();
    assert!(parse_evidence_v2(&serde_json::to_string(&stale_gate).unwrap()).is_err());

    let mut forged_source_time = value;
    forged_source_time["readbacks"][0]["source_timestamp"]["monotonic_millis"] = 0.into();
    assert!(parse_evidence_v2(&serde_json::to_string(&forged_source_time).unwrap()).is_err());
}

#[test]
fn passing_lifecycle_identity_fields_reject_whitespace_only_values() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let value = serde_json::to_value(report.record()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    for blank_identity in ["\0", " \t ", "\u{0085}", "\u{2000}", "\u{feff}"] {
        for pointer in [
            "/readbacks/0/endpoint_identity",
            "/readbacks/3/endpoint_identity",
            "/live_lifecycle_cases/1/observation/original_process_identity",
            "/live_lifecycle_cases/2/observation/process_identity_before",
            "/live_lifecycle_cases/3/observation/process_identity_after",
            "/live_lifecycle_cases/4/observation/process_identity_before",
            "/live_lifecycle_cases/6/observation/process_identity_after",
            "/live_lifecycle_cases/7/observation/controller_process_identity",
            "/live_lifecycle_cases/2/observation/auto_before_restart/cpu/endpoint_identity",
        ] {
            let mut tampered = value.clone();
            *tampered.pointer_mut(pointer).unwrap() = blank_identity.into();
            assert!(
                !validator.is_valid(&tampered),
                "{pointer}: {blank_identity:?}"
            );
            assert!(
                parse_evidence_v2(&serde_json::to_string(&tampered).unwrap()).is_err(),
                "{pointer}: {blank_identity:?}"
            );
        }
    }
}

#[test]
fn visible_unicode_lifecycle_identities_remain_schema_and_parser_compatible() {
    let mut environment = LifecycleEnvironment {
        unicode_endpoint_identities: true,
        ..LifecycleEnvironment::default()
    };
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    assert!(report.accepted());

    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][1]["observation"]["original_process_identity"] = "管理器".into();
    value["live_lifecycle_cases"][7]["observation"]["controller_process_identity"] =
        "控制器".into();

    assert!(validator.is_valid(&value));
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_ok());
}

#[test]
fn fresh_auto_reads_in_the_request_millisecond_remain_ordered_and_valid() {
    let mut environment = LifecycleEnvironment {
        same_millisecond_auto: true,
        ..LifecycleEnvironment::default()
    };

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

    assert!(report.accepted());
    assert!(report.record().readbacks.iter().all(|readback| {
        readback
            .source_timestamp
            .is_some_and(|source| source.monotonic_millis <= readback.timestamp.monotonic_millis)
    }));
}

#[test]
fn live_readback_rejects_baseline_phase_in_schema_and_parser() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["readbacks"][0]["phase"] = "sample".into();
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();

    assert!(!jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());
}

#[test]
fn tampered_gate_ordering_cannot_be_reparsed_as_passing_evidence() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

    for transition_index in [0, 2] {
        let mut record = report.record().clone();
        record.state_transitions[transition_index].timestamp = record.started_at;
        assert!(record.validate().is_err(), "transition {transition_index}");
    }

    let mut equal_initial_gate = report.record().clone();
    equal_initial_gate.state_transitions[0].timestamp = equal_initial_gate.readbacks[1].timestamp;
    assert!(equal_initial_gate.validate().is_err());

    let mut equal_restoration = report.record().clone();
    equal_restoration.state_transitions[1].timestamp = equal_restoration.readbacks[3].timestamp;
    assert!(equal_restoration.validate().is_err());
}

#[test]
fn tampered_case_observation_cannot_be_reparsed_as_passing_evidence() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][0]["observation"]["rejected_before_custom_control"] =
        false.into();

    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][2]["observation"]["stopped_at"] = value["live_lifecycle_cases"]
        [2]["observation"]["auto_before_restart"]["cpu"]["observed_at"]
        .clone();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][0]["unsupported_proof"] = true.into();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][2]["observation"]["unsupported_proof"] = true.into();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][2]["started_at"]["wall_unix_millis"] =
        (report.record().state_transitions[4]
            .timestamp
            .wall_unix_millis
            - 1)
        .into();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][3]["observation"]["restart_delay_millis"] = 3_000.into();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][3]["observation"]["start_limit_reset_at"] =
        value["live_lifecycle_cases"][3]["started_at"].clone();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][6]["observation"]["process_identity_after"] =
        value["live_lifecycle_cases"][6]["observation"]["process_identity_before"].clone();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    let outside_record = report.record().completed_at.monotonic_millis + 100;
    value["live_lifecycle_cases"][0]["started_at"]["monotonic_millis"] = outside_record.into();
    value["live_lifecycle_cases"][0]["completed_at"]["monotonic_millis"] =
        (outside_record + 1).into();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());
}

#[test]
fn kill_and_watchdog_recovery_require_a_new_process_identity() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let value = serde_json::to_value(report.record()).unwrap();

    for case_index in [3, 4] {
        let mut forged = value.clone();
        forged["live_lifecycle_cases"][case_index]["observation"]["process_identity_after"] =
            forged["live_lifecycle_cases"][case_index]["observation"]["process_identity_before"]
                .clone();
        assert!(
            parse_evidence_v2(&serde_json::to_string(&forged).unwrap()).is_err(),
            "case index {case_index}"
        );
    }
}

#[test]
fn kill_and_watchdog_recovery_reject_every_shared_proof_boundary() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let value = serde_json::to_value(report.record()).unwrap();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_ok());

    for (case_index, event_field, discriminator) in [
        (3, "killed_at", "sigkill_observed"),
        (4, "expired_at", "watchdog_expired"),
    ] {
        let case_pointer = format!("/live_lifecycle_cases/{case_index}");
        let observation_pointer = format!("{case_pointer}/observation");
        let started_at = value
            .pointer(&format!("{case_pointer}/started_at"))
            .unwrap();
        let started_wall = started_at["wall_unix_millis"].as_u64().unwrap();
        let event_at = value
            .pointer(&format!("{observation_pointer}/{event_field}"))
            .unwrap();
        let event_wall = event_at["wall_unix_millis"].as_u64().unwrap();
        let identity_before = value
            .pointer(&format!("{observation_pointer}/process_identity_before"))
            .unwrap();

        let mut forged_records = Vec::new();

        let mut forged = value.clone();
        *forged
            .pointer_mut(&format!("{observation_pointer}/start_limit_reset_at"))
            .unwrap() = started_at.clone();
        forged_records.push(("reset at case start", forged));

        let mut forged = value.clone();
        *forged
            .pointer_mut(&format!("{observation_pointer}/start_limit_reset_at"))
            .unwrap() = event_at.clone();
        forged_records.push(("reset at recovery event", forged));

        let mut forged = value.clone();
        *forged
            .pointer_mut(&format!(
                "{observation_pointer}/start_limit_reset_at/wall_unix_millis"
            ))
            .unwrap() = (event_wall + 1).into();
        forged_records.push(("reset wall clock after event", forged));

        let mut forged = value.clone();
        *forged
            .pointer_mut(&format!(
                "{observation_pointer}/start_limit_reset_at/wall_unix_millis"
            ))
            .unwrap() = started_wall.saturating_sub(1).into();
        forged_records.push(("reset wall clock before case", forged));

        let mut forged = value.clone();
        *forged
            .pointer_mut(&format!("{observation_pointer}/restarted_at"))
            .unwrap() = value
            .pointer(&format!(
                "{observation_pointer}/auto_before_restart/cpu/observed_at"
            ))
            .unwrap()
            .clone();
        forged_records.push(("restart at CPU Auto boundary", forged));

        for fan in ["cpu", "gpu"] {
            let mut forged = value.clone();
            *forged
                .pointer_mut(&format!(
                    "{observation_pointer}/auto_before_restart/{fan}/fresh"
                ))
                .unwrap() = false.into();
            forged_records.push(("stale Auto observation", forged));

            let mut forged = value.clone();
            *forged
                .pointer_mut(&format!(
                    "{observation_pointer}/auto_before_restart/{fan}/observed_at"
                ))
                .unwrap() = event_at.clone();
            forged_records.push(("Auto observation at event boundary", forged));

            let mut forged = value.clone();
            *forged
                .pointer_mut(&format!(
                    "{observation_pointer}/auto_before_restart/{fan}/endpoint_identity"
                ))
                .unwrap() = format!("wrong-{fan}-endpoint").into();
            forged_records.push(("wrong Auto endpoint identity", forged));
        }

        let mut forged = value.clone();
        *forged
            .pointer_mut(&format!("{observation_pointer}/process_identity_before"))
            .unwrap() = " ".into();
        forged_records.push(("blank process identity", forged));

        let mut forged = value.clone();
        *forged
            .pointer_mut(&format!("{observation_pointer}/process_identity_after"))
            .unwrap() = " ".into();
        forged_records.push(("blank restarted process identity", forged));

        let mut forged = value.clone();
        *forged
            .pointer_mut(&format!("{observation_pointer}/process_identity_after"))
            .unwrap() = identity_before.clone();
        forged_records.push(("unchanged process identity", forged));

        let other_case_index = if case_index == 3 { 4 } else { 3 };
        let mut forged = value.clone();
        *forged.pointer_mut(&observation_pointer).unwrap() =
            value["live_lifecycle_cases"][other_case_index]["observation"].clone();
        forged_records.push(("other recovery case observation", forged));

        for (field, contract_value) in [
            (discriminator, serde_json::Value::Bool(false)),
            ("restart_delay_millis", 3_000.into()),
            ("start_limit_burst", 3.into()),
        ] {
            let mut forged = value.clone();
            *forged
                .pointer_mut(&format!("{observation_pointer}/{field}"))
                .unwrap() = contract_value;
            forged_records.push(("wrong recovery contract value", forged));
        }

        for (description, forged) in forged_records {
            assert!(
                parse_evidence_v2(&serde_json::to_string(&forged).unwrap()).is_err(),
                "case index {case_index}: {description}"
            );
        }
    }
}

#[test]
fn recovery_validation_failures_identify_the_failed_case_in_run_evidence() {
    for invalid_recovery_proof in [
        LiveLifecycleCase::ProcessKillRecovery,
        LiveLifecycleCase::WatchdogRecovery,
    ] {
        let mut environment = LifecycleEnvironment {
            invalid_recovery_proof: Some(invalid_recovery_proof),
            ..LifecycleEnvironment::default()
        };

        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

        assert!(!report.accepted());
        assert!(report.record().faults.iter().any(|fault| {
            fault.code == "live-lifecycle-case-failed"
                && fault.detail.contains(invalid_recovery_proof.id())
        }));
        assert!(
            report
                .record()
                .outcome
                .reason
                .contains(invalid_recovery_proof.id())
        );
        assert!(
            report
                .cases()
                .last()
                .unwrap()
                .detail()
                .contains(invalid_recovery_proof.id())
        );
    }
}

#[test]
fn early_cases_require_fresh_window_bound_and_identity_bound_proof() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let value = serde_json::to_value(report.record()).unwrap();

    let mut stale_invalid_config = value.clone();
    stale_invalid_config["live_lifecycle_cases"][0]["observation"]["observed_at"] =
        stale_invalid_config["live_lifecycle_cases"][0]["started_at"].clone();
    assert!(parse_evidence_v2(&serde_json::to_string(&stale_invalid_config).unwrap()).is_err());

    let mut cached_duplicate = value.clone();
    cached_duplicate["live_lifecycle_cases"][1]["observation"]["fresh"] = false.into();
    assert!(parse_evidence_v2(&serde_json::to_string(&cached_duplicate).unwrap()).is_err());

    for case_index in [1, 2] {
        let (before_field, after_field) = if case_index == 1 {
            ("original_process_identity", "rejected_process_identity")
        } else {
            ("process_identity_before", "process_identity_after")
        };
        let mut unchanged_process = value.clone();
        unchanged_process["live_lifecycle_cases"][case_index]["observation"][after_field] =
            unchanged_process["live_lifecycle_cases"][case_index]["observation"][before_field]
                .clone();
        assert!(
            parse_evidence_v2(&serde_json::to_string(&unchanged_process).unwrap()).is_err(),
            "case index {case_index}"
        );
    }
}

#[test]
fn nested_case_wall_timestamps_must_follow_the_case_clock() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let value = serde_json::to_value(report.record()).unwrap();
    let timestamp_paths = [
        (2, "/stopped_at"),
        (3, "/start_limit_reset_at"),
        (4, "/expired_at"),
        (5, "/before/observed_at"),
        (6, "/resumed_at"),
    ];

    for (case_index, timestamp_path) in timestamp_paths {
        let mut forged = value.clone();
        let impossible_wall =
            forged["live_lifecycle_cases"][case_index]["started_at"]["wall_unix_millis"]
                .as_i64()
                .unwrap()
                - 1;
        let pointer = format!(
            "/live_lifecycle_cases/{case_index}/observation{timestamp_path}/wall_unix_millis"
        );
        *forged.pointer_mut(&pointer).unwrap() = impossible_wall.into();
        assert!(
            parse_evidence_v2(&serde_json::to_string(&forged).unwrap()).is_err(),
            "case index {case_index}"
        );
    }
}

#[test]
fn auto_gate_source_timestamps_must_belong_to_the_gate_window() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut between_cases = serde_json::to_value(report.record()).unwrap();
    between_cases["readbacks"][2]["source_timestamp"] =
        between_cases["live_lifecycle_cases"][0]["started_at"].clone();
    assert!(parse_evidence_v2(&serde_json::to_string(&between_cases).unwrap()).is_err());

    let mut post_reboot = serde_json::to_value(report.record()).unwrap();
    let reboot_index = LiveLifecycleCase::ALL.len() - 1;
    let post_boot_at =
        post_reboot["live_lifecycle_cases"][reboot_index]["observation"]["post_boot_at"].clone();
    let reboot_cpu_gate = post_reboot["readbacks"].as_array().unwrap().len() - 2;
    post_reboot["readbacks"][reboot_cpu_gate]["source_timestamp"] = post_boot_at;
    assert!(parse_evidence_v2(&serde_json::to_string(&post_reboot).unwrap()).is_err());
}

#[test]
fn schema_rejects_wrong_ordered_lifecycle_proof() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    let mut wrong_readback = serde_json::to_value(report.record()).unwrap();
    wrong_readback["readbacks"][0]["fan"] = "gpu".into();
    assert!(!validator.is_valid(&wrong_readback));

    let mut wrong_case = serde_json::to_value(report.record()).unwrap();
    wrong_case["live_lifecycle_cases"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert!(!validator.is_valid(&wrong_case));
}

#[test]
fn schema_rejects_live_only_clock_fields_on_other_stages() {
    let mut environment = LifecycleEnvironment {
        failed_auto_call: Some(1),
        ..LifecycleEnvironment::default()
    };
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["stage"] = "preflight".into();
    value["samples"] = serde_json::json!([]);
    value["preflight_checks"] = serde_json::json!([{
        "timestamp": value["started_at"].clone(),
        "check": "evidence-collection",
        "passed": false,
        "detail": "fixture failure"
    }]);
    value
        .as_object_mut()
        .unwrap()
        .remove("live_lifecycle_cases");
    for readback in value["readbacks"].as_array_mut().unwrap() {
        let readback = readback.as_object_mut().unwrap();
        readback.remove("source_timestamp");
        readback.remove("fresh");
        readback.remove("boot_id");
    }
    assert!(validator.is_valid(&value));

    for field in ["source_timestamp", "fresh", "boot_id"] {
        let mut forged = value.clone();
        forged["readbacks"][0][field] = match field {
            "source_timestamp" => forged["readbacks"][0]["timestamp"].clone(),
            "fresh" => true.into(),
            "boot_id" => "boot-before".into(),
            _ => unreachable!(),
        };
        assert!(!validator.is_valid(&forged), "{field}");
    }

    let mut forged_transition = value.clone();
    forged_transition["state_transitions"] = serde_json::json!([{
        "timestamp": forged_transition["started_at"].clone(),
        "boot_id": "boot-before",
        "from": "one",
        "to": "two"
    }]);
    assert!(!validator.is_valid(&forged_transition));

    let mut forged_fault = value;
    forged_fault["faults"][0]["boot_id"] = "boot-before".into();
    assert!(!validator.is_valid(&forged_fault));
}

#[test]
fn initial_gate_failure_is_valid_v2_evidence_but_rejects_misplaced_stage_data() {
    let mut environment = LifecycleEnvironment {
        failed_auto_call: Some(1),
        ..LifecycleEnvironment::default()
    };
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let value = serde_json::to_value(report.record()).unwrap();

    assert!(validator.is_valid(&value));
    assert_eq!(value["live_lifecycle_cases"], serde_json::json!([]));

    let mut missing_initial_gate = value.clone();
    missing_initial_gate["readbacks"] = serde_json::json!([]);
    assert!(!validator.is_valid(&missing_initial_gate));
    assert!(parse_evidence_v2(&serde_json::to_string(&missing_initial_gate).unwrap()).is_err());

    let mut tampered = value;
    tampered["commands"] = serde_json::json!([{
        "timestamp": tampered["started_at"].clone(),
        "fan": "cpu",
        "field": "enable",
        "value": 2
    }]);
    assert!(!validator.is_valid(&tampered));
    assert!(parse_evidence_v2(&serde_json::to_string(&tampered).unwrap()).is_err());
}

#[test]
fn failed_case_observations_remain_typed_in_schema_and_parser() {
    let mut environment = LifecycleEnvironment {
        malformed_case: Some(LiveLifecycleCase::InvalidConfiguration),
        ..LifecycleEnvironment::default()
    };
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();

    assert!(validator.is_valid(&value));
    value["live_lifecycle_cases"][0]["observation"] = serde_json::json!({});
    assert!(!validator.is_valid(&value));
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());

    let mut environment = LifecycleEnvironment {
        malformed_case: Some(LiveLifecycleCase::NormalStopRestart),
        ..LifecycleEnvironment::default()
    };
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][2]["observation"]["auto_before_restart"]["cpu"]["enable_readback"] =
        3.into();
    assert!(!validator.is_valid(&value));
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());
}

#[test]
fn partial_lifecycle_proof_is_a_nonempty_ordered_prefix_with_at_most_eight_cases() {
    let mut environment = LifecycleEnvironment {
        case_error: Some(LiveLifecycleCase::DuplicateProcess),
        ..LifecycleEnvironment::default()
    };
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let value = serde_json::to_value(report.record()).unwrap();

    let mut missing_gate = value.clone();
    missing_gate["readbacks"].as_array_mut().unwrap().pop();
    assert!(!validator.is_valid(&missing_gate));
    assert!(parse_evidence_v2(&serde_json::to_string(&missing_gate).unwrap()).is_err());

    let mut missing_transition = value.clone();
    missing_transition["state_transitions"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(!validator.is_valid(&missing_transition));
    assert!(parse_evidence_v2(&serde_json::to_string(&missing_transition).unwrap()).is_err());

    let mut empty_detail = value.clone();
    empty_detail["live_lifecycle_cases"][1]["detail"] = "".into();
    assert!(!validator.is_valid(&empty_detail));
    assert!(parse_evidence_v2(&serde_json::to_string(&empty_detail).unwrap()).is_err());

    let mut whitespace_detail = value.clone();
    whitespace_detail["live_lifecycle_cases"][1]["detail"] = " \t ".into();
    assert!(!validator.is_valid(&whitespace_detail));
    assert!(parse_evidence_v2(&serde_json::to_string(&whitespace_detail).unwrap()).is_err());

    let mut forged_pass = value.clone();
    forged_pass["live_lifecycle_cases"][0]["observation"]["rejected_before_custom_control"] =
        false.into();
    assert!(!validator.is_valid(&forged_pass));
    assert!(parse_evidence_v2(&serde_json::to_string(&forged_pass).unwrap()).is_err());

    let mut failed_case_outside_record = value.clone();
    let outside = report.record().completed_at.monotonic_millis + 10;
    failed_case_outside_record["live_lifecycle_cases"][1]["completed_at"]["monotonic_millis"] =
        outside.into();
    assert!(
        parse_evidence_v2(&serde_json::to_string(&failed_case_outside_record).unwrap()).is_err()
    );

    let mut wrong_prefix = value.clone();
    wrong_prefix["live_lifecycle_cases"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert!(!validator.is_valid(&wrong_prefix));
    assert!(parse_evidence_v2(&serde_json::to_string(&wrong_prefix).unwrap()).is_err());

    let mut too_many = value;
    let duplicate = too_many["live_lifecycle_cases"][0].clone();
    while too_many["live_lifecycle_cases"].as_array().unwrap().len() < 9 {
        too_many["live_lifecycle_cases"]
            .as_array_mut()
            .unwrap()
            .push(duplicate.clone());
    }
    assert!(!validator.is_valid(&too_many));
    assert!(parse_evidence_v2(&serde_json::to_string(&too_many).unwrap()).is_err());
}

#[test]
fn every_case_failure_stops_the_stage_after_checking_both_fans() {
    for failed_case in LiveLifecycleCase::ALL {
        let mut environment = LifecycleEnvironment {
            case_error: Some(failed_case),
            ..LifecycleEnvironment::default()
        };

        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

        assert!(!report.accepted(), "{failed_case:?}");
        assert_eq!(report.cases().last().unwrap().case(), failed_case);
        assert!(!report.cases().last().unwrap().passed());
        assert_eq!(environment.events.last().unwrap(), "auto:gpu");
        assert_eq!(
            environment
                .events
                .iter()
                .filter(|event| event.starts_with("case:"))
                .count(),
            LiveLifecycleCase::ALL
                .iter()
                .position(|case| *case == failed_case)
                .unwrap()
                + 1
        );
        assert!(report.record().outcome.final_firmware_auto_confirmed);
        assert!(report.record().validate().is_ok());
    }
}

#[test]
fn malformed_case_specific_evidence_fails_each_case_closed() {
    for invalid_case in LiveLifecycleCase::ALL {
        let mut environment = LifecycleEnvironment {
            malformed_case: Some(invalid_case),
            ..LifecycleEnvironment::default()
        };

        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

        assert!(!report.accepted(), "{invalid_case:?}");
        assert_eq!(report.cases().last().unwrap().case(), invalid_case);
        assert!(!report.cases().last().unwrap().passed());
        assert!(report.record().faults.iter().any(|fault| {
            fault.code == "live-lifecycle-case-failed" && fault.detail.contains(invalid_case.id())
        }));
        assert!(report.record().validate().is_ok());
    }
}

#[test]
fn either_unconfirmed_fan_blocks_the_next_case_without_skipping_the_other_read() {
    for failed_auto_call in [1, 2, 3, 4] {
        let mut environment = LifecycleEnvironment {
            failed_auto_call: Some(failed_auto_call),
            ..LifecycleEnvironment::default()
        };

        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

        assert!(!report.accepted());
        if failed_auto_call <= 2 {
            assert!(report.cases().is_empty());
            assert_eq!(environment.events, ["auto:cpu", "auto:gpu"]);
        } else {
            assert_eq!(report.cases().len(), 1);
            assert_eq!(
                environment.events,
                [
                    "auto:cpu",
                    "auto:gpu",
                    "case:invalid-configuration",
                    "auto:cpu",
                    "auto:gpu",
                ]
            );
        }
        assert!(
            report
                .record()
                .faults
                .iter()
                .any(|fault| fault.code == "firmware-auto-unconfirmed")
        );
        assert!(report.record().validate().is_ok());
    }
}

#[test]
fn stale_auto_readback_blocks_progression() {
    let mut environment = LifecycleEnvironment {
        stale_auto_call: Some(1),
        ..LifecycleEnvironment::default()
    };

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

    assert!(!report.accepted());
    assert!(report.cases().is_empty());
    assert_eq!(environment.events, ["auto:cpu", "auto:gpu"]);
}

#[test]
fn stale_wall_clock_auto_evidence_blocks_progression_and_reboot_arming() {
    for stale_wall_auto_call in [3, 17] {
        let mut environment = LifecycleEnvironment {
            stale_wall_auto_call: Some(stale_wall_auto_call),
            ..LifecycleEnvironment::default()
        };

        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

        assert!(!report.accepted());
        assert!(report.record().validate().is_ok());
        if stale_wall_auto_call == 3 {
            assert_eq!(report.cases().len(), 1);
            assert!(
                !environment
                    .events
                    .iter()
                    .any(|event| event == "case:duplicate-process")
            );
        } else {
            assert_eq!(report.cases().len(), LiveLifecycleCase::ALL.len());
            assert!(!environment.events.iter().any(|event| event == "arm:reboot"));
        }
    }
}

#[test]
fn serialized_report_has_one_validated_source_of_case_results() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut value = serde_json::to_value(&report).unwrap();

    assert!(value.get("cases").is_none());
    assert_eq!(
        value["record"]["live_lifecycle_cases"]
            .as_array()
            .unwrap()
            .len(),
        LiveLifecycleCase::ALL.len()
    );
    value["record"]["live_lifecycle_cases"][0]["observation"]["rejected_before_custom_control"] =
        false.into();
    assert!(serde_json::from_value::<fan_control_core::LiveLifecycleReport>(value).is_err());

    let unrelated_record: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../qualification/evidence-example/evidence-v1.json"
    )))
    .unwrap();
    let substitution = serde_json::json!({ "record": unrelated_record });
    assert!(serde_json::from_value::<fan_control_core::LiveLifecycleReport>(substitution).is_err());
}

#[test]
fn failed_auto_gates_still_require_one_cpu_and_one_gpu_enable_attempt() {
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for failed_auto_call in [1, 3] {
        let mut environment = LifecycleEnvironment {
            failed_auto_call: Some(failed_auto_call),
            ..LifecycleEnvironment::default()
        };
        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
        let value = serde_json::to_value(report.record()).unwrap();
        let gate_start = if failed_auto_call == 1 { 0 } else { 2 };

        let mut duplicate_cpu = value.clone();
        duplicate_cpu["readbacks"][gate_start + 1]["fan"] = "cpu".into();
        assert!(!validator.is_valid(&duplicate_cpu));
        assert!(parse_evidence_v2(&serde_json::to_string(&duplicate_cpu).unwrap()).is_err());

        let mut unrelated_field = value;
        unrelated_field["readbacks"][gate_start]["field"] = "pwm".into();
        assert!(!validator.is_valid(&unrelated_field));
        assert!(parse_evidence_v2(&serde_json::to_string(&unrelated_field).unwrap()).is_err());
    }
}

#[test]
fn endpoint_identity_change_blocks_the_next_case() {
    let mut environment = LifecycleEnvironment {
        changed_identity_call: Some(3),
        ..LifecycleEnvironment::default()
    };

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

    assert!(!report.accepted());
    assert_eq!(report.cases().len(), 1);
    assert!(report.record().faults.iter().any(|fault| {
        fault.code == "firmware-auto-unconfirmed" && fault.detail.contains("identity")
    }));
}

#[test]
fn unreadable_or_identityless_auto_gate_is_recorded_and_fails_closed() {
    for (auto_error_call, empty_identity_call, whitespace_identity_call) in [
        (Some(3), None, None),
        (None, Some(3), None),
        (None, None, Some(3)),
    ] {
        let mut environment = LifecycleEnvironment {
            auto_error_call,
            empty_identity_call,
            whitespace_identity_call,
            ..LifecycleEnvironment::default()
        };

        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

        assert!(!report.accepted());
        assert_eq!(report.cases().len(), 1);
        assert_eq!(environment.events.last().unwrap(), "auto:gpu");
        assert!(!report.record().outcome.final_firmware_auto_confirmed);
        assert_eq!(report.record().readbacks.len(), 4);
        assert!(report.record().readbacks.iter().all(|attempt| {
            !attempt.endpoint_identity.is_empty()
                && !attempt.endpoint_identity.trim().is_empty()
                && (attempt.value.is_some()
                    || attempt.outcome == fan_control_core::ObservationOutcome::Unreadable)
        }));
        assert!(report.record().validate().is_ok());
    }
}

#[test]
fn initial_gate_records_both_typed_attempts_when_identity_or_read_fails() {
    for (auto_error_call, empty_identity_call, whitespace_identity_call) in [
        (Some(1), None, None),
        (None, Some(1), None),
        (None, None, Some(1)),
    ] {
        let mut environment = LifecycleEnvironment {
            auto_error_call,
            empty_identity_call,
            whitespace_identity_call,
            ..LifecycleEnvironment::default()
        };

        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

        assert!(!report.accepted());
        assert!(report.cases().is_empty());
        assert_eq!(report.record().readbacks.len(), 2);
        assert_eq!(report.record().readbacks[0].fan, EvidenceFan::Cpu);
        assert_eq!(report.record().readbacks[1].fan, EvidenceFan::Gpu);
        assert!(
            report.record().readbacks[0]
                .endpoint_identity
                .contains("cpu-enable")
        );
        assert!(report.record().validate().is_ok());

        for blank_identity in ["\0", "\u{0085}", "\u{2000}", "\u{feff}"] {
            let mut tampered = serde_json::to_value(report.record()).unwrap();
            tampered["readbacks"][0]["endpoint_identity"] = blank_identity.into();
            assert!(
                parse_evidence_v2(&serde_json::to_string(&tampered).unwrap()).is_err(),
                "partial initial gate accepted {blank_identity:?}"
            );
        }
    }
}

#[test]
fn reboot_requires_both_auto_confirmations_to_precede_arming() {
    for fault in [
        RebootFault::CpuCustom,
        RebootFault::ArmBeforeGpuConfirmation,
        RebootFault::UnchangedBootId,
        RebootFault::AutoBeforePostBootCheckpoint,
        RebootFault::EmptyPostBootId,
        RebootFault::ArmAtGpuConfirmation,
        RebootFault::FuturePostBootCheckpoint,
    ] {
        let mut environment = LifecycleEnvironment {
            reboot_fault: Some(fault),
            ..LifecycleEnvironment::default()
        };

        let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

        assert!(!report.accepted(), "{fault:?}");
        assert_eq!(
            report.cases().last().unwrap().case(),
            LiveLifecycleCase::Reboot
        );
        assert!(report.record().faults.iter().any(|fault| {
            fault.code == "live-lifecycle-case-failed"
                && fault.detail.contains("reboot")
                && (fault.detail.contains("Auto gate") || fault.detail.contains("arm"))
        }));
        assert_eq!(
            report.record().outcome.final_firmware_auto_confirmed,
            fault != RebootFault::CpuCustom
        );
        if fault == RebootFault::FuturePostBootCheckpoint {
            assert!(!environment.events.iter().any(|event| event == "arm:reboot"));
        }
    }
}

#[test]
fn passing_reboot_rejects_blank_boot_id_proof_and_scoped_evidence() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_V2_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let value = serde_json::to_value(report.record()).unwrap();

    let mut forged_proof = value.clone();
    forged_proof["live_lifecycle_cases"][7]["observation"]["boot_id_before"] = " ".into();
    forged_proof["live_lifecycle_cases"][7]["observation"]["boot_id_after"] = "  ".into();
    for collection in ["readbacks", "state_transitions"] {
        for item in forged_proof[collection].as_array_mut().unwrap() {
            if let Some(boot_id) = item.get_mut("boot_id") {
                *boot_id = match boot_id.as_str() {
                    Some("boot-before") => " ".into(),
                    Some("boot-after") => "  ".into(),
                    _ => continue,
                };
            }
        }
    }
    assert!(!validator.is_valid(&forged_proof));
    assert!(parse_evidence_v2(&serde_json::to_string(&forged_proof).unwrap()).is_err());

    let mut forged_scoped_id = value;
    forged_scoped_id["readbacks"][0]["boot_id"] = " ".into();
    assert!(!validator.is_valid(&forged_scoped_id));
    assert!(parse_evidence_v2(&serde_json::to_string(&forged_scoped_id).unwrap()).is_err());
}

#[test]
fn reboot_accepts_a_real_post_boot_monotonic_clock_reset() {
    let mut environment = LifecycleEnvironment {
        reset_monotonic_on_reboot: true,
        ..LifecycleEnvironment::default()
    };

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

    assert!(report.accepted(), "{:#?}", report.record());
    let reboot = report.cases().last().unwrap();
    assert!(reboot.completed_at().monotonic_millis < reboot.started_at().monotonic_millis);
    let LiveLifecycleCaseObservation::Reboot {
        boot_id_after,
        auto_before_arm: Some(auto_before_arm),
        ..
    } = reboot.observation().unwrap()
    else {
        panic!("last observation must be reboot");
    };
    let final_pair = &report.record().readbacks[report.record().readbacks.len() - 2..];
    assert!(final_pair[0].source_timestamp == Some(auto_before_arm.cpu.observed_at));
    assert!(final_pair[1].source_timestamp == Some(auto_before_arm.gpu.observed_at));
    assert!(final_pair[1].timestamp.monotonic_millis < reboot.started_at().monotonic_millis);
    assert_eq!(
        final_pair[0].source_timestamp,
        Some(final_pair[0].timestamp)
    );
    assert_eq!(
        final_pair[0].boot_id.as_deref(),
        Some(boot_id_after.as_str())
    );
    assert_eq!(
        report
            .record()
            .state_transitions
            .last()
            .unwrap()
            .boot_id
            .as_deref(),
        Some(boot_id_after.as_str())
    );
    let json = serde_json::to_string(report.record()).unwrap();
    assert!(parse_evidence_v2(&json).is_ok());
}

#[test]
fn reboot_execution_error_after_clock_reset_is_durable_failed_evidence() {
    let mut environment = LifecycleEnvironment {
        case_error: Some(LiveLifecycleCase::Reboot),
        reset_monotonic_on_reboot: true,
        ..LifecycleEnvironment::default()
    };

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();

    assert!(!report.accepted());
    assert!(report.record().validate().is_ok());
    assert!(
        report
            .record()
            .faults
            .iter()
            .filter(|fault| fault.boot_id.as_deref() == Some("unverified-post-reboot"))
            .count()
            >= 1
    );
    assert!(parse_evidence_v2(&serde_json::to_string(report.record()).unwrap()).is_ok());
}

#[test]
fn failed_final_gate_cannot_be_overridden_by_preboot_monotonic_order_or_outcome_flag() {
    let mut environment = LifecycleEnvironment {
        reset_monotonic_on_reboot: true,
        failed_auto_call: Some(17),
        ..LifecycleEnvironment::default()
    };
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    assert!(!report.record().outcome.final_firmware_auto_confirmed);

    let mut forged = report.record().clone();
    forged.outcome.final_firmware_auto_confirmed = true;
    assert!(forged.validate().is_err());
}

#[test]
fn preboot_boot_id_does_not_exempt_monotonic_timestamp_validation() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let mut forged = report.record().clone();
    forged.readbacks[0].timestamp.monotonic_millis =
        forged.started_at.monotonic_millis.saturating_sub(1);
    forged.readbacks[0].source_timestamp = Some(forged.readbacks[0].timestamp);

    assert!(forged.validate().is_err());
}

#[test]
fn non_reboot_clock_regression_is_reported_without_synthesizing_case_completion() {
    let mut environment = LifecycleEnvironment {
        regress_monotonic_after_case: Some(LiveLifecycleCase::DuplicateProcess),
        ..LifecycleEnvironment::default()
    };

    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let failed = report.cases().last().unwrap();
    assert_eq!(failed.case(), LiveLifecycleCase::DuplicateProcess);
    assert!(!failed.passed());
    assert!(failed.completed_at().monotonic_millis <= failed.started_at().monotonic_millis);
    assert!(failed.detail().contains("clock did not advance"));
    assert!(report.record().validate().is_ok());
}

#[test]
fn reboot_rebinds_distinct_post_boot_endpoints_and_rejects_swapped_roles() {
    let mut environment = LifecycleEnvironment::default();
    let report = run_live_lifecycle_qualification(&mut environment, &envelope()).unwrap();
    let reboot = report.cases().last().unwrap().observation().unwrap();
    let LiveLifecycleCaseObservation::Reboot {
        auto_before_arm: Some(auto_before_arm),
        ..
    } = reboot
    else {
        panic!("last observation must be reboot");
    };
    assert_eq!(auto_before_arm.cpu.endpoint_identity, "cpu-enable-postboot");
    assert_eq!(auto_before_arm.gpu.endpoint_identity, "gpu-enable-postboot");
    assert_eq!(
        report.record().readbacks.last().unwrap().endpoint_identity,
        "gpu-enable-postboot"
    );

    let mut value = serde_json::to_value(report.record()).unwrap();
    value["live_lifecycle_cases"][7]["observation"]["auto_before_arm"]["cpu"]["endpoint_identity"] =
        "gpu-enable".into();
    value["live_lifecycle_cases"][7]["observation"]["auto_before_arm"]["gpu"]["endpoint_identity"] =
        "cpu-enable".into();
    assert!(parse_evidence_v2(&serde_json::to_string(&value).unwrap()).is_err());
}

#[test]
fn dangerous_live_fault_injections_are_all_explicitly_refused() {
    for fault in DangerousLiveFaultInjection::ALL {
        let error =
            classify_live_lifecycle_request(LiveLifecycleRequest::Dangerous(fault)).unwrap_err();

        assert_eq!(error.fault(), fault);
        assert!(error.to_string().contains("refused on live hardware"));
    }

    for case in LiveLifecycleCase::ALL {
        assert_eq!(
            classify_live_lifecycle_request(LiveLifecycleRequest::Approved(case)).unwrap(),
            case
        );
    }
}

#[test]
fn invalid_envelope_is_rejected_before_any_live_action() {
    let mut invalid = envelope();
    invalid.qualification_id.clear();
    let mut environment = LifecycleEnvironment::default();

    let result = run_live_lifecycle_qualification(&mut environment, &invalid);

    assert!(matches!(
        result,
        Err(LiveLifecyclePlanError::InvalidEnvelope(_))
    ));
    assert!(environment.events.is_empty());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebootFault {
    CpuCustom,
    ArmBeforeGpuConfirmation,
    UnchangedBootId,
    AutoBeforePostBootCheckpoint,
    EmptyPostBootId,
    ArmAtGpuConfirmation,
    FuturePostBootCheckpoint,
}

#[derive(Default)]
struct LifecycleEnvironment {
    now: u64,
    events: Vec<String>,
    auto_calls: usize,
    failed_auto_call: Option<usize>,
    changed_identity_call: Option<usize>,
    auto_error_call: Option<usize>,
    stale_auto_call: Option<usize>,
    stale_wall_auto_call: Option<usize>,
    empty_identity_call: Option<usize>,
    whitespace_identity_call: Option<usize>,
    unicode_endpoint_identities: bool,
    case_error: Option<LiveLifecycleCase>,
    malformed_case: Option<LiveLifecycleCase>,
    invalid_recovery_proof: Option<LiveLifecycleCase>,
    reboot_fault: Option<RebootFault>,
    reset_monotonic_on_reboot: bool,
    regress_monotonic_after_case: Option<LiveLifecycleCase>,
    same_millisecond_auto: bool,
    after_reboot: bool,
    wall_now: u64,
}

impl LifecycleEnvironment {
    fn current_timestamp(&self) -> EvidenceTimestamp {
        timestamp_parts(self.now, self.wall_now)
    }

    fn tick(&mut self) -> EvidenceTimestamp {
        self.now += 1;
        self.wall_now += 1;
        self.current_timestamp()
    }

    fn auto_pair(&mut self) -> LiveLifecycleFanAutoPair {
        let cpu_identity = self.endpoint_identity(EvidenceFan::Cpu);
        let gpu_identity = self.endpoint_identity(EvidenceFan::Gpu);
        let cpu = LiveLifecycleFanAutoObservation {
            observed_at: self.tick(),
            fresh: true,
            enable_readback: Some(2),
            endpoint_identity: cpu_identity,
        };
        let gpu = LiveLifecycleFanAutoObservation {
            observed_at: self.tick(),
            fresh: true,
            enable_readback: Some(2),
            endpoint_identity: gpu_identity,
        };
        LiveLifecycleFanAutoPair { cpu, gpu }
    }

    fn endpoint_identity(&self, fan: EvidenceFan) -> String {
        match (fan, self.after_reboot, self.unicode_endpoint_identities) {
            (EvidenceFan::Cpu, false, true) => "处理器风扇".into(),
            (EvidenceFan::Gpu, false, true) => "图形风扇".into(),
            (EvidenceFan::Cpu, true, true) => "处理器风扇-重启后".into(),
            (EvidenceFan::Gpu, true, true) => "图形风扇-重启后".into(),
            (EvidenceFan::Cpu, false, false) => "cpu-enable".into(),
            (EvidenceFan::Gpu, false, false) => "gpu-enable".into(),
            (EvidenceFan::Cpu, true, false) => "cpu-enable-postboot".into(),
            (EvidenceFan::Gpu, true, false) => "gpu-enable-postboot".into(),
        }
    }

    fn passing_observation(&mut self, case: LiveLifecycleCase) -> LiveLifecycleCaseObservation {
        match case {
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
                original_process_identity: "daemon-original".into(),
                rejected_process_identity: "daemon-duplicate".into(),
            },
            LiveLifecycleCase::NormalStopRestart => {
                let stopped_at = self.tick();
                let auto_before_restart = self.auto_pair();
                let restarted_at = self.tick();
                LiveLifecycleCaseObservation::NormalStopRestart {
                    clean_stop: true,
                    stopped_at,
                    auto_before_restart,
                    restarted_at,
                    fresh_process: true,
                    process_identity_before: "daemon-before-stop".into(),
                    process_identity_after: "daemon-after-restart".into(),
                }
            }
            LiveLifecycleCase::ProcessKillRecovery => {
                let start_limit_reset_at = self.tick();
                let killed_at = self.tick();
                let auto_before_restart = self.auto_pair();
                let restarted_at = self.tick();
                LiveLifecycleCaseObservation::ProcessKillRecovery {
                    sigkill_observed: true,
                    start_limit_reset_at,
                    killed_at,
                    auto_before_restart,
                    restarted_at,
                    process_identity_before: "daemon-before-kill".into(),
                    process_identity_after: "daemon-after-kill".into(),
                    restart_delay_millis: LIVE_RESTART_DELAY_MILLIS,
                    start_limit_burst: LIVE_START_LIMIT_BURST,
                }
            }
            LiveLifecycleCase::WatchdogRecovery => {
                let start_limit_reset_at = self.tick();
                let expired_at = self.tick();
                let auto_before_restart = self.auto_pair();
                let restarted_at = self.tick();
                LiveLifecycleCaseObservation::WatchdogRecovery {
                    watchdog_expired: true,
                    start_limit_reset_at,
                    expired_at,
                    auto_before_restart,
                    restarted_at,
                    process_identity_before: "daemon-before-watchdog".into(),
                    process_identity_after: "daemon-after-watchdog".into(),
                    restart_delay_millis: LIVE_RESTART_DELAY_MILLIS,
                    start_limit_burst: LIVE_START_LIMIT_BURST,
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
                let auto_before_sleep = self.auto_pair();
                let suspended_at = self.tick();
                let resumed_at = self.tick();
                let process_started_at = self.tick();
                LiveLifecycleCaseObservation::SuspendResume {
                    auto_before_sleep,
                    suspended_at,
                    suspend_completed: true,
                    resumed_at,
                    process_started_at,
                    process_identity_before: "daemon-before-sleep".into(),
                    process_identity_after: "daemon-after-resume".into(),
                }
            }
            LiveLifecycleCase::Reboot => {
                if self.reset_monotonic_on_reboot {
                    self.now = 0;
                }
                self.after_reboot = true;
                let post_boot_at = self.tick();
                let mut auto_before_arm = self.auto_pair();
                let mut armed_at = self.tick();
                match self.reboot_fault {
                    Some(RebootFault::CpuCustom) => {
                        auto_before_arm.cpu.enable_readback = Some(1);
                    }
                    Some(RebootFault::ArmBeforeGpuConfirmation) => {
                        armed_at = timestamp(
                            auto_before_arm
                                .gpu
                                .observed_at
                                .monotonic_millis
                                .saturating_sub(1),
                        );
                    }
                    Some(RebootFault::UnchangedBootId) | None => {}
                    Some(RebootFault::AutoBeforePostBootCheckpoint) => {
                        auto_before_arm.cpu.observed_at = post_boot_at;
                    }
                    Some(RebootFault::EmptyPostBootId) => {}
                    Some(RebootFault::ArmAtGpuConfirmation) => {
                        armed_at = auto_before_arm.gpu.observed_at;
                    }
                    Some(RebootFault::FuturePostBootCheckpoint) => {}
                }
                LiveLifecycleCaseObservation::Reboot {
                    reboot_completed: true,
                    boot_id_before: "boot-before".into(),
                    boot_id_after: if self.reboot_fault == Some(RebootFault::UnchangedBootId) {
                        "boot-before".into()
                    } else if self.reboot_fault == Some(RebootFault::EmptyPostBootId) {
                        String::new()
                    } else {
                        "boot-after".into()
                    },
                    post_boot_at,
                    auto_before_arm: Some(auto_before_arm),
                    armed_at: Some(armed_at),
                    controller_process_identity: Some("daemon-after-reboot".into()),
                }
            }
        }
    }

    fn malformed_observation(&mut self, case: LiveLifecycleCase) -> LiveLifecycleCaseObservation {
        match self.passing_observation(case) {
            LiveLifecycleCaseObservation::InvalidConfiguration { observed_at, .. } => {
                LiveLifecycleCaseObservation::InvalidConfiguration {
                    observed_at,
                    fresh: true,
                    rejected_before_custom_control: false,
                }
            }
            LiveLifecycleCaseObservation::DuplicateProcess {
                observed_at,
                original_process_identity,
                rejected_process_identity,
                ..
            } => LiveLifecycleCaseObservation::DuplicateProcess {
                observed_at,
                fresh: true,
                duplicate_rejected: false,
                original_owner_preserved: true,
                original_process_identity,
                rejected_process_identity,
            },
            LiveLifecycleCaseObservation::NormalStopRestart {
                stopped_at,
                auto_before_restart,
                restarted_at,
                fresh_process,
                process_identity_before,
                process_identity_after,
                ..
            } => LiveLifecycleCaseObservation::NormalStopRestart {
                clean_stop: false,
                stopped_at,
                auto_before_restart,
                restarted_at,
                fresh_process,
                process_identity_before,
                process_identity_after,
            },
            LiveLifecycleCaseObservation::ProcessKillRecovery {
                start_limit_reset_at,
                killed_at,
                auto_before_restart,
                restarted_at,
                process_identity_before,
                process_identity_after,
                restart_delay_millis,
                start_limit_burst,
                ..
            } => LiveLifecycleCaseObservation::ProcessKillRecovery {
                sigkill_observed: false,
                start_limit_reset_at,
                killed_at,
                auto_before_restart,
                restarted_at,
                process_identity_before,
                process_identity_after,
                restart_delay_millis,
                start_limit_burst,
            },
            LiveLifecycleCaseObservation::WatchdogRecovery {
                start_limit_reset_at,
                expired_at,
                auto_before_restart,
                restarted_at,
                process_identity_before,
                process_identity_after,
                restart_delay_millis,
                start_limit_burst,
                ..
            } => LiveLifecycleCaseObservation::WatchdogRecovery {
                watchdog_expired: false,
                start_limit_reset_at,
                expired_at,
                auto_before_restart,
                restarted_at,
                process_identity_before,
                process_identity_after,
                restart_delay_millis,
                start_limit_burst,
            },
            LiveLifecycleCaseObservation::AcToBatteryTransition {
                before,
                mut after,
                selected_profile_after,
                ..
            } => {
                after.fresh = false;
                LiveLifecycleCaseObservation::AcToBatteryTransition {
                    before,
                    after,
                    selected_profile_after,
                }
            }
            LiveLifecycleCaseObservation::SuspendResume {
                auto_before_sleep,
                suspended_at,
                resumed_at,
                process_started_at,
                process_identity_before,
                process_identity_after,
                ..
            } => LiveLifecycleCaseObservation::SuspendResume {
                auto_before_sleep,
                suspended_at,
                suspend_completed: false,
                resumed_at,
                process_started_at,
                process_identity_before,
                process_identity_after,
            },
            LiveLifecycleCaseObservation::Reboot {
                boot_id_before,
                boot_id_after,
                post_boot_at,
                auto_before_arm,
                armed_at,
                controller_process_identity,
                ..
            } => LiveLifecycleCaseObservation::Reboot {
                reboot_completed: false,
                boot_id_before,
                boot_id_after,
                post_boot_at,
                auto_before_arm,
                armed_at,
                controller_process_identity,
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
        assert_ne!(case, LiveLifecycleCase::Reboot);
        self.events.push(format!("case:{}", case.id()));
        self.tick();
        if self.case_error == Some(case) {
            if case == LiveLifecycleCase::Reboot && self.reset_monotonic_on_reboot {
                self.now = 0;
                self.after_reboot = true;
            }
            return Err("guided case failed".into());
        }
        if self.malformed_case == Some(case) {
            return Ok(self.malformed_observation(case));
        }
        let mut observation = self.passing_observation(case);
        if self.invalid_recovery_proof == Some(case) {
            match &mut observation {
                LiveLifecycleCaseObservation::ProcessKillRecovery {
                    start_limit_reset_at,
                    killed_at,
                    ..
                } => *start_limit_reset_at = *killed_at,
                LiveLifecycleCaseObservation::WatchdogRecovery {
                    start_limit_reset_at,
                    expired_at,
                    ..
                } => *start_limit_reset_at = *expired_at,
                _ => unreachable!("only recovery cases can request invalid recovery proof"),
            }
        }
        if self.regress_monotonic_after_case == Some(case) {
            self.now = 0;
        }
        Ok(observation)
    }

    fn resume_after_reboot(&mut self) -> Result<LiveLifecycleRebootContinuation, String> {
        self.events.push("case:reboot".into());
        self.tick();
        if self.case_error == Some(LiveLifecycleCase::Reboot) {
            if self.reset_monotonic_on_reboot {
                self.now = 0;
                self.after_reboot = true;
            }
            return Err("guided case failed".into());
        }
        if self.reset_monotonic_on_reboot {
            self.now = 0;
        }
        self.after_reboot = true;
        let mut post_boot_at = self.tick();
        if self.reboot_fault == Some(RebootFault::FuturePostBootCheckpoint) {
            post_boot_at.wall_unix_millis = post_boot_at.wall_unix_millis.saturating_add(100);
        }
        Ok(LiveLifecycleRebootContinuation {
            reboot_completed: self.malformed_case != Some(LiveLifecycleCase::Reboot),
            boot_id_before: "boot-before".into(),
            boot_id_after: if self.reboot_fault == Some(RebootFault::UnchangedBootId) {
                "boot-before".into()
            } else if self.reboot_fault == Some(RebootFault::EmptyPostBootId) {
                String::new()
            } else {
                "boot-after".into()
            },
            post_boot_at,
        })
    }

    fn arm_after_reboot(&mut self) -> Result<LiveLifecycleRebootArmObservation, String> {
        self.events.push("arm:reboot".into());
        if self.reboot_fault == Some(RebootFault::AutoBeforePostBootCheckpoint) {
            return Err("injected stale post-boot checkpoint".into());
        }
        let armed_at = if matches!(
            self.reboot_fault,
            Some(RebootFault::ArmBeforeGpuConfirmation | RebootFault::ArmAtGpuConfirmation)
        ) {
            EvidenceTimestamp {
                monotonic_millis: self.now.saturating_sub(1),
                wall_unix_millis: self.current_timestamp().wall_unix_millis.saturating_sub(1),
            }
        } else {
            self.tick()
        };
        Ok(LiveLifecycleRebootArmObservation {
            armed_at,
            controller_process_identity: "daemon-after-reboot".into(),
        })
    }

    fn confirm_firmware_auto(
        &mut self,
        fan: EvidenceFan,
    ) -> Result<LiveLifecycleFanAutoObservation, String> {
        self.auto_calls += 1;
        self.events.push(format!(
            "auto:{}",
            match fan {
                EvidenceFan::Cpu => "cpu",
                EvidenceFan::Gpu => "gpu",
            }
        ));
        if self.auto_error_call == Some(self.auto_calls) {
            self.tick();
            return Err("read failed".into());
        }
        let mut observation = LiveLifecycleFanAutoObservation {
            observed_at: if self.same_millisecond_auto {
                self.current_timestamp()
            } else {
                self.tick()
            },
            fresh: self.stale_auto_call != Some(self.auto_calls),
            enable_readback: Some(
                if self.failed_auto_call == Some(self.auto_calls)
                    || (self.after_reboot && self.reboot_fault == Some(RebootFault::CpuCustom))
                {
                    1
                } else {
                    2
                },
            ),
            endpoint_identity: self.endpoint_identity(fan),
        };
        if self.changed_identity_call == Some(self.auto_calls) {
            observation.endpoint_identity.push_str("-changed");
        }
        if self.empty_identity_call == Some(self.auto_calls) {
            observation.endpoint_identity.clear();
        }
        if self.whitespace_identity_call == Some(self.auto_calls) {
            observation.endpoint_identity = " \t ".into();
        }
        if self.stale_wall_auto_call == Some(self.auto_calls) {
            observation.observed_at.wall_unix_millis = timestamp_parts(0, 1).wall_unix_millis;
        }
        Ok(observation)
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
    timestamp_parts(monotonic_millis, monotonic_millis)
}

fn timestamp_parts(monotonic_millis: u64, wall_offset_millis: u64) -> EvidenceTimestamp {
    EvidenceTimestamp {
        monotonic_millis,
        wall_unix_millis: 1_787_691_600_000_i64
            .saturating_add(i64::try_from(wall_offset_millis).unwrap_or(i64::MAX)),
    }
}
