use fan_control_core::{
    CompatibilityAdmissionError, CompatibilityObservation, EscapeHatchCapability,
    EvidenceCompleteness, FanWriteBackend, HardwareIdentity, KernelIdentity, ModuleIdentity,
    ModuleProvenance, ObservedFanAbi, admit_compatibility, parse_compatibility_v1,
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const RELEASE: &str = "7.1.8-cachyos-pt31553";

const DECLARATION: &str = r#"
schema_version = 1

[hardware]
dmi_product_name = "Predator PT315-53"
dmi_board_name = "Civic_TLS"
bios_version = "V1.17"

[kernel]
release = "7.1.8-cachyos-pt31553"
package = "linux-cachyos-pt31553"
source_commit = "0123456789abcdef0123456789abcdef01234567"
image_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
image_signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[module]
name = "acer_wmi"
path = "/usr/lib/modules/7.1.8-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
vermagic = "7.1.8-cachyos-pt31553 SMP preempt mod_unload"
provenance = "in-tree"

[secure_boot]
required = true

[fan_control]
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
"#;

#[test]
fn exact_declared_envelope_is_admitted() {
    let declaration = parse_compatibility_v1(DECLARATION).unwrap();
    let observation = matching_observation();

    admit_compatibility(&declaration, &[observation]).unwrap();
}

#[test]
fn unsupported_missing_unknown_and_malformed_declarations_are_rejected() {
    for candidate in [
        DECLARATION.replacen("schema_version = 1", "schema_version = 2", 1),
        DECLARATION.replacen("bios_version = \"V1.17\"\n", "", 1),
        DECLARATION.replacen(
            "dmi_product_name = \"Predator PT315-53\"",
            "dmi_product_name = \"Predator PT315-53\"\nunexpected = true",
            1,
        ),
        DECLARATION.replacen(SOURCE_COMMIT, "not-a-commit", 1),
    ] {
        assert!(parse_compatibility_v1(&candidate).is_err(), "{candidate}");
    }
}

#[test]
fn admission_revalidates_programmatically_mutated_schema_version() {
    let mut declaration = parse_compatibility_v1(DECLARATION).unwrap();
    declaration.schema_version = 2;

    assert_eq!(
        admit_compatibility(&declaration, &[matching_observation()]).unwrap_err(),
        CompatibilityAdmissionError::UnsafeDeclaration {
            field: "schema_version"
        }
    );
}

#[test]
fn malformed_provenance_boundaries_are_rejected() {
    let commits = [
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];
    for commit in commits {
        assert!(
            parse_compatibility_v1(&DECLARATION.replacen(SOURCE_COMMIT, commit, 1)).is_err(),
            "accepted malformed source commit: {commit}"
        );
    }

    for release in [
        "6.19-../../..",
        "6.19-",
        "6.19-other",
        "7.1.8--cachyos-pt31553",
    ] {
        let candidate = DECLARATION.replace(RELEASE, release);
        assert!(
            parse_compatibility_v1(&candidate).is_err(),
            "accepted malformed kernel release: {release}"
        );
    }

    let prefix_collision = DECLARATION.replacen(
        "vermagic = \"7.1.8-cachyos-pt31553 ",
        "vermagic = \"7.1.8-cachyos-pt315530 ",
        1,
    );
    assert!(parse_compatibility_v1(&prefix_collision).is_err());
}

#[test]
fn declaration_cannot_broaden_the_qualified_envelope() {
    let mutations = [
        ("Predator PT315-53", "Predator PH315-53"),
        ("Civic_TLS", "Other_Board"),
        ("V1.17", "V1.18"),
        ("linux-cachyos-pt31553", "linux"),
        ("acer_wmi", "vendor_acer_wmi"),
        ("in-tree", "external"),
        ("required = true", "required = false"),
        ("backend = \"acer-hwmon\"", "backend = \"direct-wmi\""),
        ("hwmon_name = \"acer\"", "hwmon_name = \"custom\""),
        ("\"fan2_input\"", "\"fan3_input\""),
        ("  \"force-caps\",\n", ""),
    ];

    for (from, to) in mutations {
        let candidate = DECLARATION.replacen(from, to, 1);
        assert!(
            parse_compatibility_v1(&candidate).is_err(),
            "unsafe mutation was accepted: {from} -> {to}"
        );
    }
}

#[test]
fn missing_or_ambiguous_observation_is_rejected() {
    let declaration = parse_compatibility_v1(DECLARATION).unwrap();

    assert_eq!(
        admit_compatibility(&declaration, &[]).unwrap_err(),
        CompatibilityAdmissionError::MissingObservation
    );
    assert_eq!(
        admit_compatibility(
            &declaration,
            &[matching_observation(), matching_observation()]
        )
        .unwrap_err(),
        CompatibilityAdmissionError::AmbiguousObservations { count: 2 }
    );
}

#[test]
fn every_identity_and_provenance_mismatch_is_rejected() {
    let declaration = parse_compatibility_v1(DECLARATION).unwrap();
    let mut candidates: Vec<(&str, CompatibilityObservation)> = Vec::new();

    let mut product = matching_observation();
    product.hardware.dmi_product_name = "Predator PT315-52".into();
    candidates.push(("hardware.dmi_product_name", product));

    let mut board = matching_observation();
    board.hardware.dmi_board_name = "Other_Board".into();
    candidates.push(("hardware.dmi_board_name", board));

    let mut bios = matching_observation();
    bios.hardware.bios_version = "V1.16".into();
    candidates.push(("hardware.bios_version", bios));

    let mut kernel_release = matching_observation();
    kernel_release.kernel.release = "7.1.7-1-cachyos-pt31553".into();
    candidates.push(("kernel.release", kernel_release));

    let mut kernel_package = matching_observation();
    kernel_package.kernel.package = "linux-cachyos".into();
    candidates.push(("kernel.package", kernel_package));

    let mut kernel_source = matching_observation();
    kernel_source.kernel.source_commit = "fedcba9876543210fedcba9876543210fedcba98".into();
    candidates.push(("kernel.source_commit", kernel_source));

    let mut kernel_image = matching_observation();
    kernel_image.kernel.image_sha256 = HASH_B.into();
    candidates.push(("kernel.image_sha256", kernel_image));

    let mut kernel_signer = matching_observation();
    kernel_signer.kernel.image_signer_fingerprint = HASH_A.into();
    candidates.push(("kernel.image_signer_fingerprint", kernel_signer));

    let mut module_name = matching_observation();
    module_name.module.name = "vendor_acer_wmi".into();
    candidates.push(("module.name", module_name));

    let mut module_path = matching_observation();
    module_path.module.path = "/usr/lib/modules/override/acer-wmi.ko".into();
    candidates.push(("module.path", module_path));

    let mut module_hash = matching_observation();
    module_hash.module.sha256 = HASH_B.into();
    candidates.push(("module.sha256", module_hash));

    let mut module_signer = matching_observation();
    module_signer.module.signer_fingerprint = HASH_A.into();
    candidates.push(("module.signer_fingerprint", module_signer));

    let mut vermagic = matching_observation();
    vermagic.module.vermagic = "wrong vermagic".into();
    candidates.push(("module.vermagic", vermagic));

    let mut provenance = matching_observation();
    provenance.module.provenance = ModuleProvenance::External;
    candidates.push(("module.provenance", provenance));

    let mut hwmon_name = matching_observation();
    hwmon_name.fan_abi.hwmon_name = "custom".into();
    candidates.push(("fan_control.hwmon_name", hwmon_name));

    let mut endpoints = matching_observation();
    endpoints.fan_abi.endpoints.pop();
    candidates.push(("fan_control.endpoints", endpoints));

    for (field, observation) in candidates {
        assert_eq!(
            admit_compatibility(&declaration, &[observation]).unwrap_err(),
            CompatibilityAdmissionError::Mismatch { field },
        );
    }
}

#[test]
fn secure_boot_and_both_trust_chains_are_required() {
    let declaration = parse_compatibility_v1(DECLARATION).unwrap();

    for (field, mutate) in [
        (
            "secure_boot.enabled",
            disable_secure_boot as fn(&mut CompatibilityObservation),
        ),
        ("secure_boot.kernel_image_trusted", distrust_kernel_image),
        ("secure_boot.module_signature_trusted", distrust_module),
    ] {
        let mut observation = matching_observation();
        mutate(&mut observation);
        assert_eq!(
            admit_compatibility(&declaration, &[observation]).unwrap_err(),
            CompatibilityAdmissionError::Untrusted { field },
        );
    }
}

#[test]
fn every_escape_hatch_and_alternate_backend_is_rejected() {
    let declaration = parse_compatibility_v1(DECLARATION).unwrap();
    let capabilities = [
        EscapeHatchCapability::ForceCaps,
        EscapeHatchCapability::EcRawMode,
        EscapeHatchCapability::PredatorV4Override,
        EscapeHatchCapability::DirectWmi,
        EscapeHatchCapability::RawEc,
        EscapeHatchCapability::ReplacementWmiModule,
        EscapeHatchCapability::AlternateFanWriteBackend,
    ];

    for capability in capabilities {
        let mut observation = matching_observation();
        observation.enabled_capabilities.push(capability);
        assert_eq!(
            admit_compatibility(&declaration, &[observation]).unwrap_err(),
            CompatibilityAdmissionError::ForbiddenCapability { capability },
        );
    }

    for backend in [
        FanWriteBackend::DirectWmi,
        FanWriteBackend::RawEc,
        FanWriteBackend::ReplacementModule,
    ] {
        let mut observation = matching_observation();
        observation.backends = vec![backend];
        assert_eq!(
            admit_compatibility(&declaration, &[observation]).unwrap_err(),
            CompatibilityAdmissionError::UnsupportedBackend { backend },
        );
    }

    for backends in [
        Vec::new(),
        vec![FanWriteBackend::AcerHwmon, FanWriteBackend::AcerHwmon],
    ] {
        let mut observation = matching_observation();
        observation.backends = backends;
        assert!(admit_compatibility(&declaration, &[observation]).is_err());
    }

    for alternate in [
        FanWriteBackend::DirectWmi,
        FanWriteBackend::RawEc,
        FanWriteBackend::ReplacementModule,
    ] {
        let mut observation = matching_observation();
        observation.backends.push(alternate);
        assert_eq!(
            admit_compatibility(&declaration, &[observation]).unwrap_err(),
            CompatibilityAdmissionError::UnsupportedBackend { backend: alternate },
        );
    }
}

#[test]
fn incomplete_capability_or_backend_probe_is_rejected() {
    let declaration = parse_compatibility_v1(DECLARATION).unwrap();

    let mut capabilities = matching_observation();
    capabilities.capability_evidence_completeness = EvidenceCompleteness::Incomplete;
    assert_eq!(
        admit_compatibility(&declaration, &[capabilities]).unwrap_err(),
        CompatibilityAdmissionError::IncompleteEvidence {
            field: "fan_control.capabilities"
        }
    );

    let mut backends = matching_observation();
    backends.backend_evidence_completeness = EvidenceCompleteness::Incomplete;
    assert_eq!(
        admit_compatibility(&declaration, &[backends]).unwrap_err(),
        CompatibilityAdmissionError::IncompleteEvidence {
            field: "fan_control.backends"
        }
    );
}

#[test]
fn duplicate_declared_or_observed_abi_evidence_is_rejected() {
    let duplicate_declaration =
        DECLARATION.replacen("\"fan2_input\"]", "\"fan2_input\", \"fan2_input\"]", 1);
    assert!(parse_compatibility_v1(&duplicate_declaration).is_err());

    let declaration = parse_compatibility_v1(DECLARATION).unwrap();
    let mut observation = matching_observation();
    observation.fan_abi.endpoints.push("fan2_input".into());
    assert_eq!(
        admit_compatibility(&declaration, &[observation]).unwrap_err(),
        CompatibilityAdmissionError::Mismatch {
            field: "fan_control.endpoints"
        }
    );
}

fn matching_observation() -> CompatibilityObservation {
    CompatibilityObservation {
        hardware: HardwareIdentity {
            dmi_product_name: "Predator PT315-53".into(),
            dmi_board_name: "Civic_TLS".into(),
            bios_version: "V1.17".into(),
        },
        kernel: KernelIdentity {
            release: RELEASE.into(),
            package: "linux-cachyos-pt31553".into(),
            source_commit: SOURCE_COMMIT.into(),
            image_sha256: HASH_A.into(),
            image_signer_fingerprint: HASH_B.into(),
        },
        module: ModuleIdentity {
            name: "acer_wmi".into(),
            path: format!("/usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
            sha256: HASH_A.into(),
            signer_fingerprint: HASH_B.into(),
            vermagic: format!("{RELEASE} SMP preempt mod_unload"),
            provenance: ModuleProvenance::InTree,
        },
        secure_boot_enabled: true,
        kernel_image_trusted: true,
        module_signature_trusted: true,
        fan_abi: ObservedFanAbi {
            hwmon_name: "acer".into(),
            endpoints: [
                "pwm1",
                "pwm1_enable",
                "fan1_input",
                "pwm2",
                "pwm2_enable",
                "fan2_input",
            ]
            .map(String::from)
            .into(),
        },
        backend_evidence_completeness: EvidenceCompleteness::Complete,
        backends: vec![FanWriteBackend::AcerHwmon],
        capability_evidence_completeness: EvidenceCompleteness::Complete,
        enabled_capabilities: Vec::new(),
    }
}

fn disable_secure_boot(observation: &mut CompatibilityObservation) {
    observation.secure_boot_enabled = false;
}

fn distrust_kernel_image(observation: &mut CompatibilityObservation) {
    observation.kernel_image_trusted = false;
}

fn distrust_module(observation: &mut CompatibilityObservation) {
    observation.module_signature_trusted = false;
}
