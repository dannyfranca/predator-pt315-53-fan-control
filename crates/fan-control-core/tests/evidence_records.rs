use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

mod support;

use fan_control_core::{
    CalibrationLevelObservation, CalibrationReadbackSample, ConservativeFanCalibration,
    EvidenceFan, EvidenceValidationError, EvidenceWriteError, Fan, FanControlField,
    FanHoldObservation, FanReadbackField, ObservationOutcome, RunOutcomeStatus, SampleFreshness,
    parse_evidence_v1, parse_evidence_v2, write_evidence_atomically,
};

const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../qualification/evidence-example/evidence-v1.json"
));
const JSON_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/evidence.json"
));
const JSON_SCHEMA_V2: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/evidence-v2.json"
));
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

#[test]
fn deterministic_fixture_covers_the_complete_schema() {
    let record = parse_evidence_v1(FIXTURE).unwrap();

    assert_eq!(record.schema_version, 1);
    assert_eq!(
        record
            .qualification_envelope
            .qualification_record_schema_version,
        1
    );
    assert_eq!(
        record
            .qualification_envelope
            .compatibility
            .hardware
            .dmi_product_name,
        "Predator PT315-53"
    );
    assert!(record.workload.is_some());
    assert_eq!(record.samples.len(), 1);
    assert_eq!(record.commands.len(), 1);
    assert_eq!(record.readbacks.len(), 1);
    assert_eq!(record.state_transitions.len(), 2);
    assert_eq!(record.faults.len(), 1);
    assert_eq!(record.restoration_attempts.len(), 1);
    assert_eq!(record.calibration.len(), 1);
    assert!(record.thermal_summary.is_some());
    assert_eq!(record.outcome.status, RunOutcomeStatus::Failed);

    let rendered = format!("{}\n", serde_json::to_string_pretty(&record).unwrap());
    assert_eq!(rendered, FIXTURE);
}

#[test]
fn published_json_schema_requires_every_fixture_field() {
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();

    assert_all_object_fields_are_required(&schema, &schema, &fixture, "$");
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["properties"]["record_status"]["const"], "complete");
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&fixture)
    );
}

#[test]
fn published_json_schema_rejects_nested_incomplete_or_unsafe_records() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let mut candidates = Vec::new();

    let mut missing_bios = fixture.clone();
    missing_bios["qualification_envelope"]["compatibility"]["hardware"]
        .as_object_mut()
        .unwrap()
        .remove("bios_version");
    candidates.push(missing_bios);

    let mut unknown_hardware_field = fixture.clone();
    unknown_hardware_field["qualification_envelope"]["compatibility"]["hardware"]["unknown"] =
        true.into();
    candidates.push(unknown_hardware_field);

    let mut unsafe_enable_value = fixture.clone();
    unsafe_enable_value["commands"][0]["field"] = "enable".into();
    unsafe_enable_value["commands"][0]["value"] = 255.into();
    candidates.push(unsafe_enable_value);

    let mut unsafe_pwm_readback = fixture.clone();
    unsafe_pwm_readback["readbacks"][0]["field"] = "pwm".into();
    unsafe_pwm_readback["readbacks"][0]["value"] = 256.into();
    candidates.push(unsafe_pwm_readback);

    let mut unsafe_enable_readback = fixture.clone();
    unsafe_enable_readback["readbacks"][0]["field"] = "enable".into();
    unsafe_enable_readback["readbacks"][0]["value"] = 3.into();
    candidates.push(unsafe_enable_readback);

    let mut uncorroborated_readback = fixture.clone();
    uncorroborated_readback["readbacks"][0]["value"] = serde_json::Value::Null;
    candidates.push(uncorroborated_readback);

    let mut contradictory_unreadable = fixture.clone();
    contradictory_unreadable["readbacks"][0]["outcome"] = "unreadable".into();
    candidates.push(contradictory_unreadable);

    let mut uncorroborated_restoration = fixture.clone();
    uncorroborated_restoration["restoration_attempts"][0]["enable_readback"] =
        serde_json::Value::Null;
    candidates.push(uncorroborated_restoration);

    let mut contradictory_restoration = fixture.clone();
    contradictory_restoration["restoration_attempts"][0]["enable_readback"] = 1.into();
    candidates.push(contradictory_restoration);

    let mut missing_restoration = fixture.clone();
    missing_restoration["restoration_attempts"] = serde_json::json!([]);
    candidates.push(missing_restoration);

    let mut missing_final_state = fixture.clone();
    missing_final_state["state_transitions"] = serde_json::json!([]);
    candidates.push(missing_final_state);

    let mut evidence_free_pass = fixture.clone();
    evidence_free_pass["outcome"]["status"] = "passed".into();
    evidence_free_pass["outcome"]["final_firmware_auto_confirmed"] = true.into();
    evidence_free_pass["samples"] = serde_json::json!([]);
    evidence_free_pass["readbacks"] = serde_json::json!([]);
    candidates.push(evidence_free_pass);

    let mut unsafe_pass = fixture.clone();
    unsafe_pass["outcome"]["status"] = "passed".into();
    unsafe_pass["outcome"]["final_firmware_auto_confirmed"] = false.into();
    candidates.push(unsafe_pass);

    for field in [
        "cpu_millicelsius",
        "gpu_millicelsius",
        "external_power",
        "selected_profile",
        "cpu_source_demand_basis_points",
        "gpu_source_demand_basis_points",
        "commanded_demand_basis_points",
        "cpu_thermal_throttling",
        "gpu_thermal_throttling",
    ] {
        let mut empty_fresh_sample = fixture.clone();
        empty_fresh_sample["samples"][0][field] = serde_json::Value::Null;
        candidates.push(empty_fresh_sample);
    }

    for field in [
        "workload",
        "thermal_summary",
        "commands",
        "state_transitions",
        "restoration_attempts",
    ] {
        let mut incomplete_pass = fixture.clone();
        incomplete_pass["outcome"]["status"] = "passed".into();
        incomplete_pass["outcome"]["final_firmware_auto_confirmed"] = true.into();
        incomplete_pass[field] = if matches!(field, "workload" | "thermal_summary") {
            serde_json::Value::Null
        } else {
            serde_json::json!([])
        };
        candidates.push(incomplete_pass);
    }

    let mut empty_vermagic = fixture.clone();
    empty_vermagic["qualification_envelope"]["compatibility"]["module"]["vermagic"] =
        "7.1.8-1-cachyos-pt31553 ".into();
    candidates.push(empty_vermagic);

    let mut unsupported_kernel = fixture.clone();
    unsupported_kernel["qualification_envelope"]["compatibility"]["kernel"]["release"] =
        "6.18.12-generic".into();
    candidates.push(unsupported_kernel);

    let mut incomplete_sample = fixture;
    incomplete_sample["samples"][0]
        .as_object_mut()
        .unwrap()
        .remove("cpu_source_demand_basis_points");
    candidates.push(incomplete_sample);

    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for candidate in candidates {
        assert!(
            !validator.is_valid(&candidate),
            "schema accepted {candidate}"
        );
    }
}

#[test]
fn endpoint_order_is_not_part_of_the_qualification_identity() {
    let reordered = FIXTURE.replacen(
        "          \"pwm1\",\n          \"pwm1_enable\",\n          \"fan1_input\",",
        "          \"fan1_input\",\n          \"pwm1\",\n          \"pwm1_enable\",",
        1,
    );
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let candidate: serde_json::Value = serde_json::from_str(&reordered).unwrap();

    assert!(parse_evidence_v1(&reordered).is_ok());
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&candidate)
    );
}

#[test]
fn schema_contract_requires_semantic_release_binding_validation() {
    let mismatch = FIXTURE.replacen(
        "\"release\": \"7.1.8-1-cachyos-pt31553\"",
        "\"release\": \"7.2.0-cachyos-pt31553\"",
        1,
    );
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let candidate: serde_json::Value = serde_json::from_str(&mismatch).unwrap();

    assert!(
        schema["$comment"]
            .as_str()
            .unwrap()
            .contains("MUST be followed by semantic validation")
    );
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&candidate)
    );
    assert!(parse_evidence_v1(&mismatch).is_err());
}

#[test]
fn schema_and_parser_accept_the_same_supported_release_syntax() {
    let candidate = FIXTURE.replace(
        "7.1.8-1-cachyos-pt31553",
        "7.1+qualification-cachyos-pt31553",
    );
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let candidate_json: serde_json::Value = serde_json::from_str(&candidate).unwrap();

    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&candidate_json)
    );
    assert!(parse_evidence_v1(&candidate).is_ok());

    let overflow = FIXTURE.replace("7.1.8-1-cachyos-pt31553", "4294967296.1-cachyos-pt31553");
    let overflow_json: serde_json::Value = serde_json::from_str(&overflow).unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&overflow_json)
    );
    assert!(parse_evidence_v1(&overflow).is_ok());

    let nonnumeric_major = FIXTURE.replace("7.1.8-1-cachyos-pt31553", "7a.1-cachyos-pt31553");
    let nonnumeric_major_json: serde_json::Value = serde_json::from_str(&nonnumeric_major).unwrap();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&nonnumeric_major_json)
    );
    assert!(parse_evidence_v1(&nonnumeric_major).is_err());

    let invalid = FIXTURE.replace(
        "7.1.8-1-cachyos-pt31553",
        "6.19qualification-cachyos-pt31553",
    );
    let invalid_json: serde_json::Value = serde_json::from_str(&invalid).unwrap();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&invalid_json)
    );
    assert!(parse_evidence_v1(&invalid).is_err());

    let leading_zero = FIXTURE.replace("7.1.8-1-cachyos-pt31553", "6.019-cachyos-pt31553");
    let leading_zero_json: serde_json::Value = serde_json::from_str(&leading_zero).unwrap();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&leading_zero_json)
    );
    assert!(parse_evidence_v1(&leading_zero).is_err());

    let leading_zero = FIXTURE.replace("7.1.8-1-cachyos-pt31553", "7.01-cachyos-pt31553");
    let leading_zero_json: serde_json::Value = serde_json::from_str(&leading_zero).unwrap();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&leading_zero_json)
    );
    assert!(parse_evidence_v1(&leading_zero).is_err());
}

#[test]
fn omitted_nullable_fields_are_incomplete_not_null() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let mut candidates = Vec::new();

    for field in ["workload", "thermal_summary"] {
        let mut candidate = fixture.clone();
        candidate.as_object_mut().unwrap().remove(field);
        candidates.push(candidate);
    }
    for field in [
        "cpu_millicelsius",
        "gpu_millicelsius",
        "external_power",
        "selected_profile",
        "cpu_source_demand_basis_points",
        "gpu_source_demand_basis_points",
        "commanded_demand_basis_points",
        "cpu_thermal_throttling",
        "gpu_thermal_throttling",
    ] {
        let mut candidate = fixture.clone();
        candidate["samples"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        candidates.push(candidate);

        let mut candidate = fixture.clone();
        candidate["samples"][0][field] = serde_json::Value::Null;
        candidates.push(candidate);
    }
    let mut candidate = fixture.clone();
    candidate["readbacks"][0]
        .as_object_mut()
        .unwrap()
        .remove("value");
    candidates.push(candidate);

    let mut candidate = fixture;
    candidate["restoration_attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("enable_readback");
    candidates.push(candidate);

    for candidate in candidates {
        assert!(parse_evidence_v1(&candidate.to_string()).is_err());
    }
}

#[test]
fn passing_records_require_observations_and_confirmed_safe_restoration() {
    let mut record = parse_evidence_v1(FIXTURE).unwrap();
    record.outcome.status = RunOutcomeStatus::Passed;
    record.outcome.final_firmware_auto_confirmed = true;
    record.samples.clear();
    record.readbacks.clear();
    assert!(record.validate().is_err());

    let mut record = parse_evidence_v1(FIXTURE).unwrap();
    record.outcome.status = RunOutcomeStatus::Passed;
    record.outcome.final_firmware_auto_confirmed = false;
    assert!(record.validate().is_err());

    let mut active_control = parse_evidence_v1(FIXTURE).unwrap();
    active_control.outcome.status = RunOutcomeStatus::Passed;
    active_control.outcome.final_firmware_auto_confirmed = true;
    let mut gpu_restoration = active_control.restoration_attempts[0].clone();
    gpu_restoration.fan = EvidenceFan::Gpu;
    active_control.restoration_attempts.push(gpu_restoration);
    let mut restored_state = active_control.state_transitions[0].clone();
    restored_state.timestamp.monotonic_millis = 101_960;
    restored_state.from = "custom-control".into();
    restored_state.to = "firmware-auto".into();
    active_control.state_transitions.push(restored_state);
    assert!(active_control.validate().is_ok());
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&active_control).unwrap())
    );

    let mut stale = active_control.clone();
    stale.samples[0].freshness = SampleFreshness::Stale;
    assert!(stale.validate().is_err());
    let mut stale_json = serde_json::to_value(&active_control).unwrap();
    stale_json["samples"][0]["freshness"] = "stale".into();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&stale_json)
    );

    let mut post_restoration_command = active_control.commands[0].clone();
    post_restoration_command.timestamp.monotonic_millis = 101_975;
    post_restoration_command.field = FanControlField::Enable;
    post_restoration_command.value = 1;
    let mut contradictory = active_control.clone();
    contradictory.commands.push(post_restoration_command);
    assert!(contradictory.validate().is_err());

    let mut contradictory_json = serde_json::to_value(&active_control).unwrap();
    let mut command = contradictory_json["commands"][0].clone();
    command["timestamp"]["monotonic_millis"] = 101_975.into();
    command["field"] = "enable".into();
    command["value"] = 1.into();
    contradictory_json["commands"]
        .as_array_mut()
        .unwrap()
        .push(command);
    assert!(
        schema["$comment"]
            .as_str()
            .unwrap()
            .contains("after every fan command")
    );
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&contradictory_json)
    );
    assert!(parse_evidence_v1(&contradictory_json.to_string()).is_err());
    for clear in [
        "workload",
        "thermal",
        "commands",
        "transitions",
        "restoration",
    ] {
        let mut incomplete = active_control.clone();
        match clear {
            "workload" => incomplete.workload = None,
            "thermal" => incomplete.thermal_summary = None,
            "commands" => incomplete.commands.clear(),
            "transitions" => incomplete.state_transitions.clear(),
            "restoration" => incomplete.restoration_attempts.clear(),
            _ => unreachable!(),
        }
        assert!(incomplete.validate().is_err(), "accepted missing {clear}");
    }

    let mut preflight = active_control;
    preflight.stage = "preflight".into();
    preflight.workload = None;
    preflight.thermal_summary = None;
    preflight.commands.clear();
    preflight.state_transitions.clear();
    preflight.restoration_attempts.clear();
    preflight.calibration.clear();
    let mut cpu_auto = preflight.readbacks[0].clone();
    cpu_auto.fan = EvidenceFan::Cpu;
    cpu_auto.field = FanReadbackField::Enable;
    cpu_auto.value = Some(2);
    cpu_auto.outcome = ObservationOutcome::Confirmed;
    let mut gpu_auto = cpu_auto.clone();
    gpu_auto.fan = EvidenceFan::Gpu;
    preflight.readbacks = vec![cpu_auto, gpu_auto];
    assert!(preflight.validate().is_ok());
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&preflight).unwrap())
    );

    let trailing_space_vermagic = FIXTURE.replacen(
        "7.1.8-1-cachyos-pt31553 SMP preempt mod_unload",
        "7.1.8-1-cachyos-pt31553 ",
        1,
    );
    assert!(parse_evidence_v1(&trailing_space_vermagic).is_err());
}

#[test]
fn calibration_evidence_enforces_protected_runtime_invariants() {
    let record = passing_v2_calibration_record();
    let mut invalid = Vec::new();

    let mut zero_deadline = record.clone();
    zero_deadline.calibration[0].response_deadline_millis = 0;
    invalid.push(zero_deadline);

    let mut excessive_deadline = record.clone();
    excessive_deadline.calibration[0].response_deadline_millis = 10_001;
    invalid.push(excessive_deadline);

    let mut missing_span = record.clone();
    missing_span.calibration[0].anchors.pop();
    invalid.push(missing_span);

    let mut wrong_floor_anchor = record.clone();
    wrong_floor_anchor.calibration[0].anchors[0].duty_basis_points += 1;
    invalid.push(wrong_floor_anchor);

    let mut decreasing_rpm = record.clone();
    decreasing_rpm.calibration[0].anchors[1].median_rpm = 3_000;
    invalid.push(decreasing_rpm);

    let mut implausible_rpm = record.clone();
    implausible_rpm.calibration[0].anchors[0].median_rpm = 0;
    invalid.push(implausible_rpm);

    let mut duplicate_fan = record;
    duplicate_fan
        .calibration
        .push(duplicate_fan.calibration[0].clone());
    invalid.push(duplicate_fan);

    for candidate in invalid {
        assert!(candidate.validate().is_err());
    }

    let record = passing_v2_calibration_record();
    let mut serialized = serde_json::to_value(record).unwrap();
    serialized["calibration"][0]["protocol_checkpoint"]["events"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(parse_evidence_v2(&serde_json::to_string(&serialized).unwrap()).is_err());

    let record = passing_v2_calibration_record();
    let mut fan_swapped = serde_json::to_value(record).unwrap();
    fan_swapped["calibration"][0]["fan"] = "gpu".into();
    fan_swapped["calibration"][0]["protocol_checkpoint"]["fan"] = "gpu".into();
    assert!(parse_evidence_v2(&serde_json::to_string(&fan_swapped).unwrap()).is_err());
}

#[test]
fn calibration_checkpoint_is_bound_to_the_run_envelope_and_command_trace() {
    let record = passing_v2_calibration_record();
    assert!(record.validate().is_ok(), "{:?}", record.validate());

    let mut outside_run = record.clone();
    outside_run.started_at.monotonic_millis =
        outside_run.commands[0].timestamp.monotonic_millis + 1;
    assert!(outside_run.validate().is_err());

    let mut wrong_selected_command = record.clone();
    wrong_selected_command.commands[0].value ^= 1;
    assert!(wrong_selected_command.validate().is_err());

    let mut unrecorded_selected_command = record.clone();
    unrecorded_selected_command
        .commands
        .push(unrecorded_selected_command.commands[0].clone());
    assert!(unrecorded_selected_command.validate().is_err());

    let mut other_fan_not_at_maximum = record;
    let mut contradictory = other_fan_not_at_maximum.commands[0].clone();
    contradictory.fan = EvidenceFan::Gpu;
    contradictory.value = 254;
    other_fan_not_at_maximum.commands.push(contradictory);
    assert!(other_fan_not_at_maximum.validate().is_err());

    let mut safe_post_protocol_containment = passing_v2_calibration_record();
    let last_observation = safe_post_protocol_containment.completed_at.monotonic_millis - 3;
    let mut containment = safe_post_protocol_containment
        .commands
        .last()
        .unwrap()
        .clone();
    containment.timestamp.monotonic_millis = last_observation + 1;
    containment.value = 255;
    safe_post_protocol_containment.commands.push(containment);
    for attempt in &mut safe_post_protocol_containment.restoration_attempts {
        attempt.timestamp.monotonic_millis = last_observation + 2;
    }
    safe_post_protocol_containment
        .state_transitions
        .last_mut()
        .unwrap()
        .timestamp
        .monotonic_millis = last_observation + 3;
    safe_post_protocol_containment.completed_at.monotonic_millis = last_observation + 4;
    assert!(safe_post_protocol_containment.validate().is_ok());

    let mut unsafe_post_protocol_command = safe_post_protocol_containment;
    unsafe_post_protocol_command
        .commands
        .last_mut()
        .unwrap()
        .value = 254;
    assert!(unsafe_post_protocol_command.validate().is_err());
}

#[test]
fn legacy_v1_calibration_contract_remains_compatible() {
    let mut record = parse_evidence_v1(FIXTURE).unwrap();
    record.calibration[0].response_deadline_millis = 0;
    record.calibration[0].anchors.truncate(1);
    let mut gpu = record.calibration[0].clone();
    gpu.fan = EvidenceFan::Gpu;
    record.calibration.push(gpu);

    assert!(record.validate().is_ok());
    assert!(serde_json::to_string(&record).is_ok());
}

#[test]
fn legacy_v1_rejects_v2_only_calibration_provenance() {
    let mut fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    fixture["calibration"][0]["slowest_response_millis"] = 5_000.into();
    assert!(parse_evidence_v1(&serde_json::to_string(&fixture).unwrap()).is_err());

    fixture["calibration"][0]
        .as_object_mut()
        .unwrap()
        .remove("slowest_response_millis");
    fixture["calibration"][0]["protocol_checkpoint"] = serde_json::json!({
        "schema_version": 1,
        "fan": "cpu",
        "failed": false,
        "events": []
    });
    assert!(parse_evidence_v1(&serde_json::to_string(&fixture).unwrap()).is_err());
}

#[test]
fn legacy_v1_still_rejects_out_of_range_or_empty_calibration() {
    let mut empty = parse_evidence_v1(FIXTURE).unwrap();
    empty.calibration[0].anchors.clear();
    assert!(empty.validate().is_err());

    let mut floor = parse_evidence_v1(FIXTURE).unwrap();
    floor.calibration[0].floor_basis_points = 10_001;
    assert!(floor.validate().is_err());

    let mut duty = parse_evidence_v1(FIXTURE).unwrap();
    duty.calibration[0].anchors[0].duty_basis_points = 10_001;
    assert!(duty.validate().is_err());
}

#[test]
fn v2_calibration_requires_one_fan_and_the_exact_canonical_anchor_schedule() {
    let record = passing_v2_calibration_record();
    assert!(record.validate().is_ok(), "{:?}", record.validate());

    let mut stripped = record.clone();
    stripped.calibration.clear();
    assert!(stripped.validate().is_err());

    for removed in [1, 2] {
        let mut missing = record.clone();
        missing.calibration[0].anchors.remove(removed);
        assert!(missing.validate().is_err());
    }

    let mut substituted = record.clone();
    substituted.calibration[0].anchors[1].duty_basis_points = 6_000;
    assert!(substituted.validate().is_err());

    for invalid_floor in [0, 4_001, 7_500] {
        let mut invalid = record.clone();
        invalid.calibration[0].floor_basis_points = invalid_floor;
        invalid.calibration[0].anchors[0].duty_basis_points = invalid_floor;
        assert!(invalid.validate().is_err());
    }

    let mut both_fans = record;
    let mut gpu = both_fans.calibration[0].clone();
    gpu.fan = EvidenceFan::Gpu;
    both_fans.calibration.push(gpu);
    assert!(both_fans.validate().is_err());
}

fn passing_v2_calibration_record() -> fan_control_core::EvidenceRecord {
    let mut record = parse_evidence_v1(FIXTURE).unwrap();
    record.schema_version = 2;
    record.stage = "fan-calibration".into();
    record.faults.clear();
    record
        .thermal_summary
        .as_mut()
        .unwrap()
        .nvidia_faults
        .clear();
    let mut gpu_restoration = record.restoration_attempts[0].clone();
    gpu_restoration.fan = EvidenceFan::Gpu;
    record.restoration_attempts.push(gpu_restoration);
    record.outcome.status = RunOutcomeStatus::Passed;
    record.outcome.reason = "fan calibration passed".into();
    record.outcome.another_passing_run_required = false;
    record.calibration[0] = completed_calibration_evidence();
    let calibration = record.calibration[0].clone();
    support::bind_record_to_calibration_protocol(&mut record, &calibration);
    record
}

fn completed_calibration_evidence() -> fan_control_core::FanCalibrationEvidence {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let mut clock = 1;
    for rpm in [5_000, 3_800, 3_300, 2_800] {
        record_stable_level(&mut session, rpm, 3_000, &mut clock);
    }
    let step = session.next_step();
    let mut unstable = level_observation(step, 900, 2_000, &mut clock);
    for (index, sample) in unstable.samples.iter_mut().enumerate() {
        sample.selected_rpm = Some(if index % 2 == 0 { 900 } else { 1_300 });
    }
    session.record_level(unstable).unwrap();
    for _ in 0..5 {
        record_stable_level(&mut session, 5_000, 4_000, &mut clock);
        record_stable_level(&mut session, 3_300, 5_000, &mut clock);
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
        record_stable_level(&mut session, rpm, response, &mut clock);
    }
    session.evidence().unwrap().clone()
}

fn record_stable_level(
    session: &mut ConservativeFanCalibration,
    rpm: u32,
    response_millis: u64,
    clock: &mut u64,
) {
    let observation = level_observation(session.next_step(), rpm, response_millis, clock);
    session.record_level(observation).unwrap();
}

fn level_observation(
    step: fan_control_core::CalibrationStep,
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

#[test]
fn v2_schema_rejects_noncanonical_calibration_anchor_duties() {
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA_V2).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut fixture = serde_json::to_value(passing_v2_calibration_record()).unwrap();
    assert!(validator.is_valid(&fixture));

    fixture["calibration"][0]["anchors"][1]["duty_basis_points"] = 6_000.into();
    assert!(!validator.is_valid(&fixture));

    fixture["calibration"][0]["anchors"][1]["duty_basis_points"] = 6_250.into();
    fixture["calibration"][0]["anchors"][1]["median_rpm"] = 3_000.into();
    assert!(validator.is_valid(&fixture));
    assert!(parse_evidence_v2(&serde_json::to_string(&fixture).unwrap()).is_err());

    fixture["calibration"][0]["anchors"][1]["median_rpm"] = 3_800.into();
    fixture["calibration"][0]["response_deadline_millis"] = 1.into();
    assert!(parse_evidence_v2(&serde_json::to_string(&fixture).unwrap()).is_err());
}

#[test]
fn v2_schema_and_parser_reject_unknown_checkpoint_fields() {
    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA_V2).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut fixture = serde_json::to_value(passing_v2_calibration_record()).unwrap();
    fixture["calibration"][0]["protocol_checkpoint"]["events"][0]["unexpected"] = true.into();

    assert!(!validator.is_valid(&fixture));
    assert!(parse_evidence_v2(&serde_json::to_string(&fixture).unwrap()).is_err());
}

#[test]
fn unsupported_incomplete_and_ambiguous_records_are_rejected() {
    for candidate in [
        FIXTURE.replacen("\"schema_version\": 1", "\"schema_version\": 2", 1),
        FIXTURE.replacen("\"record_status\": \"complete\",\n", "", 1),
        FIXTURE.replacen(
            "\"record_status\": \"complete\"",
            "\"record_status\": \"partial\"",
            1,
        ),
        FIXTURE.replacen(
            "\"qualification_id\": \"pt31553-v1\"",
            "\"qualification_id\": \"\"",
            1,
        ),
        FIXTURE.replacen(
            "\"stage\": \"matched-workload\"",
            "\"stage\": \"contains spaces\"",
            1,
        ),
        FIXTURE.replacen(
            "\"monotonic_millis\": 101900",
            "\"monotonic_millis\": 103000",
            1,
        ),
        FIXTURE.replacen(
            "\"stage\": \"matched-workload\",",
            "\"stage\": \"matched-workload\",\n  \"unknown\": true,",
            1,
        ),
        FIXTURE.replacen("\"value\": 4200,", "\"value\": null,", 1),
        FIXTURE.replacen(
            "\"outcome\": \"confirmed\"",
            "\"outcome\": \"unreadable\"",
            1,
        ),
        FIXTURE.replacen("\"enable_readback\": 2", "\"enable_readback\": null", 1),
        FIXTURE.replacen("\"enable_readback\": 2", "\"enable_readback\": 1", 1),
    ] {
        assert!(parse_evidence_v1(&candidate).is_err(), "{candidate}");
    }

    assert!(
        parse_evidence_v1(&FIXTURE.replacen("\"schema_version\": 1", "\"schema_version\": 2", 1))
            .is_err()
    );

    assert!(
        serde_json::from_str::<fan_control_core::EvidenceRecord>(&FIXTURE.replacen(
            "\"schema_version\": 1",
            "\"schema_version\": 2",
            1
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<fan_control_core::EvidenceRecord>(&FIXTURE.replacen(
            "\"qualification_record_schema_version\": 1",
            "\"qualification_record_schema_version\": 2",
            1
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<fan_control_core::EvidenceRecord>(&FIXTURE.replacen(
            "\"monotonic_millis\": 101900",
            "\"monotonic_millis\": 103000",
            1
        ))
        .is_err()
    );

    let mut unsupported = parse_evidence_v1(FIXTURE).unwrap();
    unsupported.schema_version = 3;
    assert!(serde_json::to_string(&unsupported).is_err());

    let mut unsupported = parse_evidence_v1(FIXTURE).unwrap();
    unsupported
        .qualification_envelope
        .qualification_record_schema_version = 2;
    assert!(serde_json::to_string(&unsupported).is_err());

    let mut unsupported = parse_evidence_v1(FIXTURE).unwrap();
    unsupported
        .qualification_envelope
        .compatibility
        .schema_version = 2;
    assert!(serde_json::to_string(&unsupported).is_err());

    let mut invalid = parse_evidence_v1(FIXTURE).unwrap();
    invalid.stage.clear();
    assert!(serde_json::to_string(&invalid).is_err());

    let mut invalid = parse_evidence_v1(FIXTURE).unwrap();
    invalid.commands[0].timestamp.monotonic_millis = invalid.completed_at.monotonic_millis + 1;
    assert!(serde_json::to_string(&invalid).is_err());
}

#[test]
fn atomic_publication_never_replaces_an_existing_record() {
    let directory = temporary_directory("publish");
    fs::create_dir(&directory).unwrap();
    let destination = directory.join("run.json");
    let record = parse_evidence_v1(FIXTURE).unwrap();

    write_evidence_atomically(&destination, &record).unwrap();
    assert_eq!(fs::read_to_string(&destination).unwrap(), FIXTURE);
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let error = write_evidence_atomically(&destination, &record).unwrap_err();
    assert!(matches!(
        error,
        EvidenceWriteError::Io {
            operation: "publish evidence",
            ..
        }
    ));
    assert_eq!(fs::read_to_string(&destination).unwrap(), FIXTURE);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn interrupted_partial_files_cannot_be_mistaken_for_complete_evidence() {
    let directory = temporary_directory("partial");
    fs::create_dir(&directory).unwrap();
    let destination = directory.join("run.json");
    let partial = directory.join(".run.json.partial-interrupted");
    fs::write(&partial, &FIXTURE[..FIXTURE.len() / 2]).unwrap();

    assert!(!destination.exists());
    assert!(parse_evidence_v1(&fs::read_to_string(partial).unwrap()).is_err());

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn invalid_records_and_destinations_are_never_published() {
    let directory = temporary_directory("invalid");
    fs::create_dir(&directory).unwrap();
    let destination = directory.join("run.json");
    let mut record = parse_evidence_v1(FIXTURE).unwrap();
    record.schema_version = 3;

    assert!(matches!(
        write_evidence_atomically(&destination, &record),
        Err(EvidenceWriteError::Invalid(
            EvidenceValidationError::UnsupportedSchemaVersion
        ))
    ));
    assert!(!destination.exists());
    assert!(matches!(
        write_evidence_atomically(
            PathBuf::from("run.json").as_path(),
            &parse_evidence_v1(FIXTURE).unwrap()
        ),
        Err(EvidenceWriteError::InvalidDestination)
    ));

    fs::remove_dir_all(directory).unwrap();
}

fn temporary_directory(label: &str) -> PathBuf {
    let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "pt31553-evidence-{label}-{}-{id}",
        std::process::id()
    ))
}

fn assert_all_object_fields_are_required(
    root: &serde_json::Value,
    schema: &serde_json::Value,
    instance: &serde_json::Value,
    path: &str,
) {
    let schema = if let Some(reference) = schema.get("$ref").and_then(|value| value.as_str()) {
        let definition = reference.strip_prefix("#/$defs/").unwrap();
        &root["$defs"][definition]
    } else if let Some(variants) = schema.get("anyOf").and_then(|value| value.as_array()) {
        variants
            .iter()
            .find(|variant| {
                (variant.get("type").and_then(|value| value.as_str()) == Some("null"))
                    == instance.is_null()
            })
            .unwrap()
    } else {
        schema
    };

    if schema.get("type").and_then(|value| value.as_str()) == Some("object") {
        let properties = schema["properties"].as_object().unwrap();
        let required = schema["required"].as_array().unwrap();
        for (field, field_instance) in instance.as_object().unwrap() {
            let field_schema = properties
                .get(field)
                .unwrap_or_else(|| panic!("schema omits {path}.{field}"));
            assert!(
                required.iter().any(|required| required == field),
                "{path}.{field} is not required"
            );
            assert_all_object_fields_are_required(
                root,
                field_schema,
                field_instance,
                &format!("{path}.{field}"),
            );
        }
    } else if schema.get("type").and_then(|value| value.as_str()) == Some("array") {
        for (index, item) in instance.as_array().unwrap().iter().enumerate() {
            assert_all_object_fields_are_required(
                root,
                &schema["items"],
                item,
                &format!("{path}[{index}]"),
            );
        }
    }
}
