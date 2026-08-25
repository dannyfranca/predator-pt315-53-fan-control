use std::path::Path;

use fan_control_core::{
    CompatibilityAdmissionError, CompatibilityDeclarationV1, CompatibilityObservation,
    EvidenceCompleteness, FakePlatform, FanWriteBackend, FilePermissions, ObservedFanAbi,
    PolicyAuthorityAdmissionError, PolicyAuthorityError, ValidatedConfig,
    acquire_controller_ownership, admit_policy_authority, discover_acer_hwmon,
    parse_compatibility_v1, parse_config_v1, validate_config_v1,
};
use sha2::{Digest, Sha256};

const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_SOURCE_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

const PROTECTED_POLICY: &str = r#"schema_version = 1
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
fn both_formats_reject_unsupported_missing_unknown_and_malformed_fields() {
    for policy in [
        PROTECTED_POLICY.replacen("schema_version = 1", "schema_version = 2", 1),
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
        record.replacen("\"schema_version\":1", "\"schema_version\":2", 1),
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
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();

    let error = admit_policy_authority(
        &mut ownership,
        &device,
        PROTECTED_POLICY,
        &record,
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

fn admit(
    policy: &str,
    record: &str,
    observations: &[CompatibilityObservation],
) -> (
    Result<fan_control_core::AdmittedPolicyAuthority, PolicyAuthorityAdmissionError>,
    FakePlatform,
) {
    let (mut platform, device) = fan_fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    ownership.restore_firmware_auto(&device).unwrap();
    let result = admit_policy_authority(&mut ownership, &device, policy, record, observations);
    ownership.release().unwrap();
    (result, platform)
}

fn fan_fixture() -> (FakePlatform, fan_control_core::AcerHwmonDevice) {
    let root = Path::new(ACER_ROOT);
    let mut platform = FakePlatform::new();
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

fn matching_observation_for_policy(policy: &str) -> CompatibilityObservation {
    matching_observation(&compatibility_declaration(policy))
}

fn compatibility_declaration(policy: &str) -> CompatibilityDeclarationV1 {
    let start = policy.find("[compatibility]\n").unwrap();
    let end = policy.find("\n[protected]\n").unwrap();
    let source = policy[start..end]
        .replacen("[compatibility]\n", "", 1)
        .replace("[compatibility.", "[");
    parse_compatibility_v1(&source).unwrap()
}

fn protected_config(policy: &str) -> ValidatedConfig {
    let start = policy.find("[protected]\n").unwrap();
    let source = policy[start..]
        .replacen("[protected]\n", "", 1)
        .replace("[protected.", "[");
    validate_config_v1(parse_config_v1(&source).unwrap()).unwrap()
}

fn matching_observation(declaration: &CompatibilityDeclarationV1) -> CompatibilityObservation {
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

fn matching_record(policy: &str) -> String {
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

fn sha256(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
}
