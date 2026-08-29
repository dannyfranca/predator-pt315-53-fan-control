use std::path::Path;

#[cfg(unix)]
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use fan_control_core::{
    CompatibilityAdmissionError, CompatibilityObservation, FakePlatform, FilePermissions,
    PolicyAuthorityAdmissionError, PolicyAuthorityError, QUALIFICATION_RECORD_PATH,
    SUPERVISED_ENDURANCE_EVIDENCE_PATH, TachometerCalibrationError, acquire_controller_ownership,
    admit_policy_authority, discover_acer_hwmon, validate_qualification_evidence_v2,
};

mod support;
use support::{
    PROTECTED_POLICY, SOURCE_COMMIT, compatibility_declaration, matching_endurance_evidence,
    matching_observation, matching_observation_for_policy, matching_record, protected_config,
    sha256,
};

const OTHER_SOURCE_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

#[test]
fn retained_record_validation_rejects_incomplete_or_rebound_authorization() {
    let record = matching_record(PROTECTED_POLICY);
    let evidence = matching_endurance_evidence(PROTECTED_POLICY);
    let path = Path::new(SUPERVISED_ENDURANCE_EVIDENCE_PATH);
    validate_qualification_evidence_v2(&record, &evidence, path).unwrap();

    for invalid in [
        record.replacen("\"schema_version\":2", "\"schema_version\":3", 1),
        record.replacen(
            "\"stage\":\"supervised-endurance\"",
            "\"stage\":\"other\"",
            1,
        ),
        record.replacen("\"policy_version\":\"1.0.0\",", "", 1),
        record.replacen(&sha256(PROTECTED_POLICY), &"0".repeat(64), 1),
    ] {
        assert!(
            validate_qualification_evidence_v2(&invalid, &evidence, path).is_err(),
            "invalid retained authorization was accepted: {invalid}"
        );
    }
    assert!(
        validate_qualification_evidence_v2(&record, &evidence, Path::new("/other/evidence.json"))
            .is_err()
    );

    let original: serde_json::Value = serde_json::from_str(&evidence).unwrap();
    let mut altered_evidence = Vec::new();

    let mut wrong_stage = original.clone();
    wrong_stage["stage"] = "other".into();
    altered_evidence.push(("stage", wrong_stage, false));

    let mut failed = original.clone();
    failed["outcome"]["status"] = "failed".into();
    altered_evidence.push(("outcome", failed, false));

    let mut rebound_envelope = original.clone();
    rebound_envelope["qualification_envelope"]["policy_version"] = "2.0.0".into();
    altered_evidence.push(("envelope", rebound_envelope, false));

    let mut rebound_completion = original.clone();
    rebound_completion["completed_at"]["wall_unix_millis"] = 1_787_695_200_005_i64.into();
    altered_evidence.push(("completed_at", rebound_completion, false));

    let mut invalid_bound_completion = original.clone();
    invalid_bound_completion["completed_at"]["monotonic_millis"] = 0.into();
    invalid_bound_completion["completed_at"]["wall_unix_millis"] = 0.into();
    altered_evidence.push(("bound invalid completion", invalid_bound_completion, true));

    let mut incomplete = original;
    incomplete["process_stops"].as_array_mut().unwrap().pop();
    altered_evidence.push(("completeness", incomplete, false));

    for (field, altered, bind_completed_at) in altered_evidence {
        let altered = serde_json::to_string(&altered).unwrap();
        let rebound_record = record_bound_to_evidence(&record, &altered, bind_completed_at);
        assert!(
            validate_qualification_evidence_v2(&rebound_record, &altered, path).is_err(),
            "altered evidence field was accepted after digest rebinding: {field}"
        );
    }
}

fn record_bound_to_evidence(record: &str, evidence: &str, bind_completed_at: bool) -> String {
    let mut record: serde_json::Value = serde_json::from_str(record).unwrap();
    let evidence_value: serde_json::Value = serde_json::from_str(evidence).unwrap();
    record["supervised_endurance"]["evidence_sha256"] = sha256(evidence).into();
    if bind_completed_at {
        record["supervised_endurance"]["completed_at"] = evidence_value["completed_at"].clone();
    }
    serde_json::to_string(&record).unwrap()
}

#[cfg(unix)]
#[test]
fn retained_record_validation_rejects_non_utf8_evidence_paths() {
    let record = matching_record(PROTECTED_POLICY);
    let evidence = matching_endurance_evidence(PROTECTED_POLICY);
    let path = Path::new(OsStr::from_bytes(
        b"/var/lib/pt31553-fan-control/evidence/\xff.json",
    ));

    assert!(matches!(
        validate_qualification_evidence_v2(&record, &evidence, path),
        Err(PolicyAuthorityError::InvalidIdentity {
            artifact: "supervised endurance evidence",
            field: "evidence_path",
        })
    ));
}

#[test]
fn exact_policy_record_and_live_envelope_are_admitted_together() {
    let record = matching_record(PROTECTED_POLICY);
    let observation = matching_observation_for_policy(PROTECTED_POLICY);

    let (result, _) = admit(PROTECTED_POLICY, &record, &[observation]);
    let authority = result.unwrap();

    assert_eq!(authority.qualification_id(), "pt31553-v1");
    assert_eq!(authority.policy_version(), "1.0.0");
    assert_eq!(
        authority.protected_policy_sha256(),
        sha256(PROTECTED_POLICY)
    );
    let evidence_identity = authority.evidence_identity();
    assert_eq!(evidence_identity.qualification_record_schema_version, 1);
    assert_eq!(evidence_identity.qualification_id, "pt31553-v1");
    assert_eq!(evidence_identity.policy_version, "1.0.0");
    assert_eq!(
        evidence_identity.protected_policy_sha256,
        sha256(PROTECTED_POLICY)
    );
    assert_eq!(
        evidence_identity.compatibility,
        compatibility_declaration(PROTECTED_POLICY)
    );
    assert!(
        authority
            .validate_candidate(&protected_config(PROTECTED_POLICY))
            .is_ok()
    );
}

#[test]
fn unsafe_or_incomplete_tachometer_calibration_never_becomes_authority() {
    for (policy, expected_fan) in [
        (
            PROTECTED_POLICY.replacen("floor_basis_points = 3000", "floor_basis_points = 2999", 1),
            fan_control_core::Fan::Cpu,
        ),
        (
            PROTECTED_POLICY.replacen(
                "[calibration.gpu]\nfloor_basis_points = 2500\nresponse_deadline_millis = 4000",
                "[calibration.gpu]\nfloor_basis_points = 2500\nresponse_deadline_millis = 0",
                1,
            ),
            fan_control_core::Fan::Gpu,
        ),
        (
            PROTECTED_POLICY.replacen(
                "[calibration.gpu]\nfloor_basis_points = 2500\nresponse_deadline_millis = 4000",
                "[calibration.gpu]\nfloor_basis_points = 2500\nresponse_deadline_millis = 30001",
                1,
            ),
            fan_control_core::Fan::Gpu,
        ),
        (
            PROTECTED_POLICY.replacen(
                "{ duty_basis_points = 10000, median_rpm = 3500 }",
                "{ duty_basis_points = 3000, median_rpm = 3500 }",
                1,
            ),
            fan_control_core::Fan::Cpu,
        ),
        (
            PROTECTED_POLICY.replacen("median_rpm = 3500", "median_rpm = 2000", 1),
            fan_control_core::Fan::Cpu,
        ),
        (
            PROTECTED_POLICY.replacen("median_rpm = 2500", "median_rpm = 99", 1),
            fan_control_core::Fan::Cpu,
        ),
        (
            PROTECTED_POLICY.replacen("median_rpm = 3500", "median_rpm = 20001", 1),
            fan_control_core::Fan::Cpu,
        ),
    ] {
        let record = matching_record(&policy);
        let observation = matching_observation_for_policy(&policy);
        let (result, _) = admit(&policy, &record, &[observation]);

        let error = result.unwrap_err();
        assert!(
            matches!(
                error.reason(),
                PolicyAuthorityError::InvalidTachometerCalibration(
                    TachometerCalibrationError::FloorMismatch { fan, .. }
                        | TachometerCalibrationError::ZeroResponseDeadline { fan }
                        | TachometerCalibrationError::ResponseDeadlineTooLong { fan, .. }
                        | TachometerCalibrationError::AnchorRangeMismatch { fan }
                        | TachometerCalibrationError::AnchorsNotStrictlyIncreasing { fan }
                        | TachometerCalibrationError::RpmZeroOrDecreasing { fan }
                        | TachometerCalibrationError::RpmOutOfRange { fan, .. }
                ) if *fan == expected_fan
            ),
            "expected {expected_fan:?}, got {:?}",
            error.reason()
        );
    }
}

#[test]
fn both_formats_reject_unsupported_missing_unknown_and_malformed_fields() {
    for policy in [
        PROTECTED_POLICY.replacen("schema_version = 2", "schema_version = 3", 1),
        PROTECTED_POLICY.replacen("qualification_id = \"pt31553-v1\"\n", "", 1),
        PROTECTED_POLICY.replacen(
            "policy_version = \"1.0.0\"",
            "policy_version = \"1.0.0\"\nunexpected = true",
            1,
        ),
        PROTECTED_POLICY.replacen("hysteresis_celsius = 3", "hysteresis_celsius = nope", 1),
    ] {
        let observation = matching_observation_for_policy(PROTECTED_POLICY);
        let (result, platform) = admit(&policy, &matching_record(&policy), &[observation]);
        assert!(result.is_err(), "{policy}");
        assert_firmware_auto(&platform);
    }

    let record = matching_record(PROTECTED_POLICY);
    for candidate in [
        record.replacen("\"schema_version\":2", "\"schema_version\":1", 1),
        record.replacen("\"qualification_id\":\"pt31553-v1\",", "", 1),
        record.replacen("{", "{\"unexpected\":true,", 1),
        record.replacen(
            "\"policy_version\":\"1.0.0\"",
            "\"policy_version\":false",
            1,
        ),
    ] {
        let observation = matching_observation_for_policy(PROTECTED_POLICY);
        let (result, platform) = admit(PROTECTED_POLICY, &candidate, &[observation]);
        assert!(result.is_err(), "{candidate}");
        assert_firmware_auto(&platform);
    }
}

#[test]
fn legacy_or_unbound_records_never_admit_authority() {
    let record = matching_record(PROTECTED_POLICY);
    let evidence_sha256 = sha256(&matching_endurance_evidence(PROTECTED_POLICY));
    for candidate in [
        record.replacen("\"schema_version\":2", "\"schema_version\":1", 1),
        record.replacen(
            &format!("\"evidence_sha256\":\"{evidence_sha256}\""),
            "\"evidence_sha256\":\"unbound\"",
            1,
        ),
        record.replacen(
            "\"stage\":\"supervised-endurance\"",
            "\"stage\":\"matched-workload\"",
            1,
        ),
        record.replacen("\"outcome\":\"passed\"", "\"outcome\":\"failed\"", 1),
        record.replacen("\"service_stopped\":true", "\"service_stopped\":false", 1),
    ] {
        let observation = matching_observation_for_policy(PROTECTED_POLICY);
        let (result, platform) = admit(PROTECTED_POLICY, &candidate, &[observation]);
        assert!(result.is_err(), "{candidate}");
        assert_firmware_auto(&platform);
    }
}

#[test]
fn pre_calibration_v1_manifest_requires_explicit_requalification() {
    let calibration_start = PROTECTED_POLICY.find("[calibration.cpu]").unwrap();
    let protected_start = PROTECTED_POLICY.find("[protected]\n").unwrap();
    let policy = format!(
        "{}{}",
        &PROTECTED_POLICY[..calibration_start],
        &PROTECTED_POLICY[protected_start..]
    )
    .replacen("schema_version = 2", "schema_version = 1", 1);
    let observation = matching_observation_for_policy(PROTECTED_POLICY);
    let (result, platform) = admit(&policy, &matching_record(&policy), &[observation]);

    assert!(matches!(
        result.unwrap_err().reason(),
        PolicyAuthorityError::ProtectedPolicyParse(error)
            if error.to_string().contains("V1 manifests require requalification")
    ));
    assert_firmware_auto(&platform);
}

#[test]
fn incomplete_artifact_and_envelope_identities_are_rejected() {
    for policy in [
        PROTECTED_POLICY.replacen("pt31553-v1", "", 1),
        PROTECTED_POLICY.replacen("1.0.0", "contains space", 1),
        PROTECTED_POLICY.replacen("V1.17", "V1.18", 1),
    ] {
        let observation = matching_observation_for_policy(PROTECTED_POLICY);
        let (result, platform) = admit(&policy, &matching_record(&policy), &[observation]);
        assert!(result.is_err(), "{policy}");
        assert_firmware_auto(&platform);
    }

    let record = matching_record(PROTECTED_POLICY);
    for candidate in [
        record.replacen("pt31553-v1", "", 1),
        record.replacen("1.0.0", "contains space", 1),
        record.replacen(&sha256(PROTECTED_POLICY), "ABC", 1),
        record.replacen("V1.17", "V1.18", 1),
    ] {
        let observation = matching_observation_for_policy(PROTECTED_POLICY);
        let (result, platform) = admit(PROTECTED_POLICY, &candidate, &[observation]);
        assert!(result.is_err(), "{candidate}");
        assert_firmware_auto(&platform);
    }
}

#[test]
fn exact_policy_bytes_are_pinned_by_the_record_hash() {
    let record = matching_record(PROTECTED_POLICY);
    let observation = matching_observation_for_policy(PROTECTED_POLICY);
    let reformatted_policy = format!("{PROTECTED_POLICY}\n");

    let (result, platform) = admit(&reformatted_policy, &record, &[observation]);
    assert!(matches!(
        result.unwrap_err().reason(),
        PolicyAuthorityError::Mismatch {
            field: "protected_policy_sha256"
        }
    ));
    assert_firmware_auto(&platform);
}

#[test]
fn every_cross_artifact_identity_mismatch_fails_closed() {
    let observation = matching_observation_for_policy(PROTECTED_POLICY);
    let record = matching_record(PROTECTED_POLICY);

    for (field, candidate) in [
        (
            "qualification_id",
            record.replacen("pt31553-v1", "pt31553-v2", 1),
        ),
        ("policy_version", record.replacen("1.0.0", "1.0.1", 1)),
        (
            "compatibility",
            record.replacen(SOURCE_COMMIT, OTHER_SOURCE_COMMIT, 1),
        ),
    ] {
        let (result, platform) = admit(
            PROTECTED_POLICY,
            &candidate,
            std::slice::from_ref(&observation),
        );
        assert!(matches!(
            result.unwrap_err().reason(),
            PolicyAuthorityError::Mismatch { field: actual } if *actual == field
        ));
        assert_firmware_auto(&platform);
    }
}

#[test]
fn stale_authority_is_rejected_against_current_compatibility_observation() {
    let record = matching_record(PROTECTED_POLICY);
    let mut current = compatibility_declaration(PROTECTED_POLICY);
    current.kernel.source_commit = OTHER_SOURCE_COMMIT.into();
    let observation = matching_observation(&current);

    let (result, platform) = admit(PROTECTED_POLICY, &record, &[observation]);
    assert!(matches!(
        result.unwrap_err().reason(),
        PolicyAuthorityError::CompatibilityAdmission(CompatibilityAdmissionError::Mismatch {
            field: "kernel.source_commit"
        })
    ));
    assert_firmware_auto(&platform);
}

#[test]
fn missing_or_ambiguous_live_observations_never_admit_authority() {
    let record = matching_record(PROTECTED_POLICY);
    let (result, platform) = admit(PROTECTED_POLICY, &record, &[]);
    assert!(matches!(
        result.unwrap_err().reason(),
        PolicyAuthorityError::CompatibilityAdmission(
            CompatibilityAdmissionError::MissingObservation
        )
    ));
    assert_firmware_auto(&platform);

    let observation = matching_observation_for_policy(PROTECTED_POLICY);
    let (result, platform) = admit(
        PROTECTED_POLICY,
        &record,
        &[observation.clone(), observation],
    );
    assert!(matches!(
        result.unwrap_err().reason(),
        PolicyAuthorityError::CompatibilityAdmission(
            CompatibilityAdmissionError::AmbiguousObservations { count: 2 }
        )
    ));
    assert_firmware_auto(&platform);
}

#[test]
fn invalid_protected_content_never_becomes_authority() {
    let invalid_policy =
        PROTECTED_POLICY.replacen("minimum_duty_percent = 30", "minimum_duty_percent = 0", 1);
    let record = matching_record(&invalid_policy);
    let observation = matching_observation_for_policy(&invalid_policy);

    let (result, platform) = admit(&invalid_policy, &record, &[observation]);
    assert!(matches!(
        result.unwrap_err().reason(),
        PolicyAuthorityError::InvalidProtectedPolicy(_)
    ));
    assert_firmware_auto(&platform);
}

#[test]
fn policy_admission_requires_confirmed_firmware_auto() {
    let record = matching_record(PROTECTED_POLICY);
    let observation = matching_observation_for_policy(PROTECTED_POLICY);
    let (mut platform, device) = fan_fixture();
    platform.insert_file_with_permissions(
        QUALIFICATION_RECORD_PATH,
        record,
        FilePermissions::READ_ONLY,
    );
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();

    let error = admit_policy_authority(
        &mut ownership,
        &device,
        PROTECTED_POLICY,
        Path::new(QUALIFICATION_RECORD_PATH),
        &[observation],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        PolicyAuthorityAdmissionError::Rejected(PolicyAuthorityError::FirmwareAutoUnconfirmed)
    ));
    ownership.release().unwrap();
    assert_firmware_auto(&platform);
}

#[test]
fn policy_admission_rejects_unprotected_or_non_root_qualification_records() {
    for (permissions, root_owned) in [
        (FilePermissions::from_mode(0o664), true),
        (FilePermissions::READ_ONLY, false),
    ] {
        let record = matching_record(PROTECTED_POLICY);
        let observation = matching_observation_for_policy(PROTECTED_POLICY);
        let (mut platform, device) = fan_fixture();
        platform.insert_file_with_permissions(QUALIFICATION_RECORD_PATH, record, permissions);
        platform.set_file_root_owned(QUALIFICATION_RECORD_PATH, root_owned);
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        ownership.restore_firmware_auto(&device).unwrap();

        let error = admit_policy_authority(
            &mut ownership,
            &device,
            PROTECTED_POLICY,
            Path::new(QUALIFICATION_RECORD_PATH),
            &[observation],
        )
        .unwrap_err();

        assert!(matches!(
            error.reason(),
            PolicyAuthorityError::QualificationRecordRead(_)
        ));
        ownership.release().unwrap();
        assert_firmware_auto(&platform);
    }
}

#[test]
fn policy_admission_rejects_missing_or_digest_mismatched_endurance_evidence() {
    for evidence in [None, Some("not-the-authorized-digest")] {
        let record = matching_record(PROTECTED_POLICY);
        let observation = matching_observation_for_policy(PROTECTED_POLICY);
        let (mut platform, device) = fan_fixture();
        match evidence {
            Some(contents) => platform.insert_file_with_permissions(
                SUPERVISED_ENDURANCE_EVIDENCE_PATH,
                contents,
                FilePermissions::READ_ONLY,
            ),
            None => platform.remove_path(SUPERVISED_ENDURANCE_EVIDENCE_PATH),
        }
        platform.insert_file_with_permissions(
            QUALIFICATION_RECORD_PATH,
            record,
            FilePermissions::READ_ONLY,
        );
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        ownership.restore_firmware_auto(&device).unwrap();

        let error = admit_policy_authority(
            &mut ownership,
            &device,
            PROTECTED_POLICY,
            Path::new(QUALIFICATION_RECORD_PATH),
            &[observation],
        )
        .unwrap_err();

        assert!(matches!(
            error.reason(),
            PolicyAuthorityError::QualificationRecordRead(_)
        ));
        ownership.release().unwrap();
        assert_firmware_auto(&platform);
    }
}

fn admit(
    policy: &str,
    record: &str,
    observations: &[CompatibilityObservation],
) -> (
    Result<fan_control_core::AdmittedPolicyAuthority, PolicyAuthorityAdmissionError>,
    FakePlatform,
) {
    let (mut platform, device) = fan_fixture();
    platform.insert_file_with_permissions(
        SUPERVISED_ENDURANCE_EVIDENCE_PATH,
        matching_endurance_evidence(policy),
        FilePermissions::READ_ONLY,
    );
    platform.insert_file_with_permissions(
        QUALIFICATION_RECORD_PATH,
        record,
        FilePermissions::READ_ONLY,
    );
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    ownership.restore_firmware_auto(&device).unwrap();
    let result = admit_policy_authority(
        &mut ownership,
        &device,
        policy,
        Path::new(QUALIFICATION_RECORD_PATH),
        observations,
    );
    ownership.release().unwrap();
    (result, platform)
}

fn fan_fixture() -> (FakePlatform, fan_control_core::AcerHwmonDevice) {
    let root = Path::new(ACER_ROOT);
    let mut platform = FakePlatform::new();
    platform.insert_file_with_permissions(
        SUPERVISED_ENDURANCE_EVIDENCE_PATH,
        matching_endurance_evidence(PROTECTED_POLICY),
        FilePermissions::READ_ONLY,
    );
    platform.insert_file_with_permissions(root.join("name"), "acer\n", FilePermissions::READ_ONLY);
    for channel in 1..=2 {
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}")),
            "128\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}_enable")),
            "1\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("fan{channel}_input")),
            "2400\n",
            FilePermissions::READ_ONLY,
        );
    }
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    (platform, device)
}

fn assert_firmware_auto(platform: &FakePlatform) {
    assert_eq!(
        platform.file_contents(Path::new(ACER_ROOT).join("pwm1_enable")),
        Some("2")
    );
    assert_eq!(
        platform.file_contents(Path::new(ACER_ROOT).join("pwm2_enable")),
        Some("2")
    );
}
