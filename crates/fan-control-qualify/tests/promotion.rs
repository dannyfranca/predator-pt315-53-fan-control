use std::{
    error::Error,
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use fan_control_core::{
    PromotionInputs, sanitize_qualification_evidence_v1, validate_promotion_manifest_v1,
};
use fan_control_qualify::{PromotionArtifactIo, check_promotion_command, redact_evidence_command};
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const AUTHORIZED_EVIDENCE_PATH: &str =
    "/var/lib/pt31553-fan-control/evidence/supervised-endurance.json";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    qualification: PathBuf,
    evidence: PathBuf,
    sanitized: PathBuf,
    policy: PathBuf,
    provenance: PathBuf,
    controller: PathBuf,
    controller_signature: PathBuf,
    package_signature: PathBuf,
    manifest: PathBuf,
    promoted: PathBuf,
}

struct FixtureIo<'a> {
    evidence: &'a Path,
}

impl PromotionArtifactIo for FixtureIo<'_> {
    fn read_bytes(&mut self, path: &Path, _label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let actual = if path == Path::new(AUTHORIZED_EVIDENCE_PATH) {
            self.evidence
        } else {
            path
        };
        Ok(fs::read(actual)?)
    }

    fn publish(&mut self, path: &Path, payload: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(path)?;
        output.write_all(payload)?;
        output.sync_all()?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
    )
    .unwrap();
}

fn qualify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .args(args)
        .output()
        .unwrap()
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "pt31553-promotion-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let qualification = root.join("qualification.json");
        let evidence = root.join("supervised-endurance.json");
        let sanitized = root.join("sanitized-evidence.json");
        let policy = root.join("protected-policy.toml");
        let provenance = root.join("package-provenance-v1.json");
        let controller = root.join("pt31553-fan-control.pkg.tar.zst");
        let controller_signature = root.join("pt31553-fan-control.pkg.tar.zst.sig");
        let package_signature = root.join("package-set-manifest.p7s");
        let manifest = root.join("promotion.json");
        let promoted = root.join("promoted.json");

        let policy_bytes = b"schema_version = 2\nqualification_id = \"pt31553-v1\"\n";
        fs::write(&policy, policy_bytes).unwrap();
        let mut compressed = GzDecoder::new(
            &include_bytes!("../../../qualification/supervised-endurance-v2.json.gz")[..],
        );
        let mut evidence_source = String::new();
        compressed.read_to_string(&mut evidence_source).unwrap();
        let mut evidence_value: Value = serde_json::from_str(&evidence_source).unwrap();
        evidence_value["qualification_envelope"]["protected_policy_sha256"] =
            sha(policy_bytes).into();
        let compatibility = &mut evidence_value["qualification_envelope"]["compatibility"];
        compatibility["kernel"]["release"] = "7.1.8-cachyos-pt31553".into();
        compatibility["kernel"]["source_commit"] =
            "7a84732fd5e4350c1312fd0ed0c72ffa139fb766".into();
        compatibility["kernel"]["image_signer_fingerprint"] =
            "1c549f6b61cc97b1673e9a73b974b63160bea16357be93a533d93382086f17bc".into();
        compatibility["module"]["path"] =
            "/usr/lib/modules/7.1.8-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst"
                .into();
        compatibility["module"]["signer_fingerprint"] = "0".repeat(64).into();
        compatibility["module"]["vermagic"] = "7.1.8-cachyos-pt31553 SMP preempt mod_unload".into();
        evidence_value["outcome"]["reason"] =
            "token=private hostname=predator /home/operator serial=private".into();
        write_json(&evidence, &evidence_value);
        let evidence_bytes = fs::read(&evidence).unwrap();
        let envelope = &evidence_value["qualification_envelope"];
        let record = json!({
            "schema_version": 2,
            "qualification_id": envelope["qualification_id"],
            "policy_version": envelope["policy_version"],
            "protected_policy_sha256": envelope["protected_policy_sha256"],
            "compatibility": envelope["compatibility"],
            "supervised_endurance": {
                "schema_version": 1,
                "evidence_sha256": sha(&evidence_bytes),
                "evidence_path": AUTHORIZED_EVIDENCE_PATH,
                "evidence_schema_version": 2,
                "stage": "supervised-endurance",
                "record_status": "complete",
                "outcome": "passed",
                "final_firmware_auto_confirmed": true,
                "workload_stopped": true,
                "service_stopped": true,
                "completed_at": evidence_value["completed_at"]
            }
        });
        write_json(&qualification, &record);

        let sanitized_source = sanitize_qualification_evidence_v1(
            &fs::read_to_string(&qualification).unwrap(),
            &fs::read_to_string(&evidence).unwrap(),
            Path::new(AUTHORIZED_EVIDENCE_PATH),
        )
        .unwrap();
        fs::write(&sanitized, sanitized_source).unwrap();

        fs::write(&controller, b"signed controller package").unwrap();
        fs::write(&controller_signature, b"controller package signature").unwrap();
        fs::write(&package_signature, b"kernel package-set signature").unwrap();
        let compatibility = &record["compatibility"];
        let package_signer = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let modules = [
            ("acer_wmi", "/usr/lib/modules/7.1.8-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst", "in-tree", "linux-cachyos-pt31553", "kernel-tree", "7a84732fd5e4350c1312fd0ed0c72ffa139fb766"),
            ("nvidia", "/usr/lib/modules/7.1.8-cachyos-pt31553/extramodules/nvidia.ko.zst", "nvidia-open", "linux-cachyos-pt31553-nvidia-open", "nvidia-open", "610.57.04"),
            ("nvidia_drm", "/usr/lib/modules/7.1.8-cachyos-pt31553/extramodules/nvidia-drm.ko.zst", "nvidia-open", "linux-cachyos-pt31553-nvidia-open", "nvidia-open", "610.57.04"),
            ("nvidia_modeset", "/usr/lib/modules/7.1.8-cachyos-pt31553/extramodules/nvidia-modeset.ko.zst", "nvidia-open", "linux-cachyos-pt31553-nvidia-open", "nvidia-open", "610.57.04"),
            ("nvidia_peermem", "/usr/lib/modules/7.1.8-cachyos-pt31553/extramodules/nvidia-peermem.ko.zst", "nvidia-open", "linux-cachyos-pt31553-nvidia-open", "nvidia-open", "610.57.04"),
            ("nvidia_uvm", "/usr/lib/modules/7.1.8-cachyos-pt31553/extramodules/nvidia-uvm.ko.zst", "nvidia-open", "linux-cachyos-pt31553-nvidia-open", "nvidia-open", "610.57.04"),
        ]
        .into_iter()
        .map(|(name, path, provenance, package, kind, revision)| {
            json!({
                "name": name,
                "path": path,
                "sha256": compatibility["module"]["sha256"],
                "signer_fingerprint": compatibility["module"]["signer_fingerprint"],
                "vermagic": compatibility["module"]["vermagic"],
                "provenance": provenance,
                "package": package,
                "source": { "kind": kind, "revision": revision }
            })
        })
        .collect::<Vec<_>>();
        let packages = json!([
            { "name": "linux-cachyos-pt31553", "version": "7.1.8-1", "architecture": "x86_64", "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" },
            { "name": "linux-cachyos-pt31553-headers", "version": "7.1.8-1", "architecture": "x86_64", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" },
            { "name": "linux-cachyos-pt31553-nvidia-open", "version": "7.1.8-1", "architecture": "x86_64", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
        ]);
        let provenance_value = json!({
            "schema_version": 1,
            "candidate": "linux-cachyos-pt31553-7.1.8-1-package-set",
            "build": {
                "source_commit": "7a84732fd5e4350c1312fd0ed0c72ffa139fb766",
                "source_lock_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "build_environment_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "build_attestation_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "pkgbuild_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "package_set_srcinfo_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "package_manifest_signer_fingerprint": package_signer
            },
            "kernel": {
                "release": compatibility["kernel"]["release"],
                "package": compatibility["kernel"]["package"],
                "image_path": "/usr/lib/modules/7.1.8-cachyos-pt31553/vmlinuz",
                "image_sha256": compatibility["kernel"]["image_sha256"],
                "image_signer_fingerprint": compatibility["kernel"]["image_signer_fingerprint"],
                "config_path": "/usr/lib/modules/7.1.8-cachyos-pt31553/build/.config",
                "config_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "module_trust_certificate_path": "/usr/lib/modules/7.1.8-cachyos-pt31553/build/certs/signing_key.x509",
                "module_trust_certificate_fingerprint": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "modules": modules,
            "packages": packages
        });
        write_json(&provenance, &provenance_value);

        let promotion = json!({
            "schema_version": 1,
            "qualification_record_sha256": sha(&fs::read(&qualification).unwrap()),
            "controller": {
                "package_sha256": sha(&fs::read(&controller).unwrap()),
                "signature_sha256": sha(&fs::read(&controller_signature).unwrap())
            },
            "policy": { "sha256": sha(policy_bytes) },
            "kernel": {
                "release": compatibility["kernel"]["release"],
                "image_sha256": compatibility["kernel"]["image_sha256"],
                "image_signer_fingerprint": compatibility["kernel"]["image_signer_fingerprint"],
                "module_sha256": compatibility["module"]["sha256"],
                "module_signer_fingerprint": compatibility["module"]["signer_fingerprint"]
            },
            "packages": {
                "provenance_sha256": sha(&fs::read(&provenance).unwrap()),
                "manifest_signature_sha256": sha(&fs::read(&package_signature).unwrap()),
                "manifest_signer_fingerprint": package_signer,
                "artifacts": provenance_value["packages"]
            },
            "sanitized_evidence_sha256": sha(&fs::read(&sanitized).unwrap())
        });
        write_json(&manifest, &promotion);

        Self {
            root,
            qualification,
            evidence,
            sanitized,
            policy,
            provenance,
            controller,
            controller_signature,
            package_signature,
            manifest,
            promoted,
        }
    }

    fn promotion_args(&self) -> Vec<&str> {
        vec![
            "check-promotion",
            "--manifest",
            self.manifest.to_str().unwrap(),
            "--qualification-record",
            self.qualification.to_str().unwrap(),
            "--evidence",
            self.evidence.to_str().unwrap(),
            "--authorized-evidence-path",
            AUTHORIZED_EVIDENCE_PATH,
            "--sanitized-evidence",
            self.sanitized.to_str().unwrap(),
            "--protected-policy",
            self.policy.to_str().unwrap(),
            "--package-provenance",
            self.provenance.to_str().unwrap(),
            "--controller-package",
            self.controller.to_str().unwrap(),
            "--controller-signature",
            self.controller_signature.to_str().unwrap(),
            "--package-manifest-signature",
            self.package_signature.to_str().unwrap(),
            "--output",
            self.promoted.to_str().unwrap(),
        ]
    }

    fn virtual_promotion_args(&self) -> Vec<OsString> {
        let mut arguments = self
            .promotion_args()
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        arguments[6] = AUTHORIZED_EVIDENCE_PATH.into();
        arguments
    }

    fn validate(&self) -> Result<(), fan_control_core::PromotionValidationError> {
        validate_promotion_manifest_v1(PromotionInputs {
            manifest_source: &fs::read_to_string(&self.manifest).unwrap(),
            qualification_record_source: &fs::read_to_string(&self.qualification).unwrap(),
            evidence_source: &fs::read_to_string(&self.evidence).unwrap(),
            authorized_evidence_path: Path::new(AUTHORIZED_EVIDENCE_PATH),
            sanitized_evidence_source: &fs::read_to_string(&self.sanitized).unwrap(),
            protected_policy: &fs::read(&self.policy).unwrap(),
            package_provenance_source: &fs::read(&self.provenance).unwrap(),
            controller_package: &fs::read(&self.controller).unwrap(),
            controller_signature: &fs::read(&self.controller_signature).unwrap(),
            package_manifest_signature: &fs::read(&self.package_signature).unwrap(),
        })
    }

    fn replace_provenance(&self, provenance: &Value, synchronize_artifacts: bool) {
        write_json(&self.provenance, provenance);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&self.manifest).unwrap()).unwrap();
        manifest["packages"]["provenance_sha256"] =
            sha(&fs::read(&self.provenance).unwrap()).into();
        if synchronize_artifacts {
            manifest["packages"]["artifacts"] = provenance["packages"].clone();
        }
        write_json(&self.manifest, &manifest);
    }
}

#[test]
fn redaction_emits_only_the_sanitized_qualification_summary() {
    let fixture = Fixture::new();
    let summary: Value = serde_json::from_slice(&fs::read(&fixture.sanitized).unwrap()).unwrap();

    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["record_status"], "complete");
    assert_eq!(summary["outcome"], "passed");
    assert_eq!(summary["stage"], "supervised-endurance");
    assert!(summary["final_firmware_auto_confirmed"].as_bool().unwrap());
    assert!(summary["workload_stopped"].as_bool().unwrap());
    assert!(summary["service_stopped"].as_bool().unwrap());
    assert!(summary["compatibility"]["hardware"]["product_name"].is_string());
    assert!(summary["compatibility"]["hardware"]["board_name"].is_string());
    assert!(summary["compatibility"]["hardware"]["bios_version"].is_string());
    let rendered = serde_json::to_string(&summary).unwrap();
    for prohibited in [
        "samples",
        "commands",
        "readbacks",
        "faults",
        "process_stops",
        "workload",
    ] {
        assert!(summary.get(prohibited).is_none(), "retained {prohibited}");
    }
    for prohibited in [
        "monotonic_millis",
        "wall_unix_millis",
        "serial",
        "hostname",
        "/home/",
        "token",
    ] {
        assert!(!rendered.contains(prohibited), "leaked {prohibited}");
    }
}

#[test]
fn redaction_does_not_publish_free_form_vermagic_content() {
    let fixture = Fixture::new();
    let private_vermagic = "7.1.8-cachyos-pt31553 SMP /home/alice/private-host";
    let mut evidence: Value =
        serde_json::from_slice(&fs::read(&fixture.evidence).unwrap()).unwrap();
    evidence["qualification_envelope"]["compatibility"]["module"]["vermagic"] =
        private_vermagic.into();
    write_json(&fixture.evidence, &evidence);
    let mut record: Value =
        serde_json::from_slice(&fs::read(&fixture.qualification).unwrap()).unwrap();
    record["compatibility"]["module"]["vermagic"] = private_vermagic.into();
    record["supervised_endurance"]["evidence_sha256"] =
        sha(&fs::read(&fixture.evidence).unwrap()).into();
    write_json(&fixture.qualification, &record);

    let sanitized = sanitize_qualification_evidence_v1(
        &fs::read_to_string(&fixture.qualification).unwrap(),
        &fs::read_to_string(&fixture.evidence).unwrap(),
        Path::new(AUTHORIZED_EVIDENCE_PATH),
    )
    .unwrap();
    assert!(!sanitized.contains("vermagic"));
    assert!(!sanitized.contains("/home/alice"));
    assert!(!sanitized.contains("private-host"));
}

#[test]
fn redaction_does_not_publish_free_form_qualification_identifiers() {
    let fixture = Fixture::new();
    let mut evidence: Value =
        serde_json::from_slice(&fs::read(&fixture.evidence).unwrap()).unwrap();
    evidence["qualification_envelope"]["qualification_id"] = "alice".into();
    evidence["qualification_envelope"]["policy_version"] = "private-host-17".into();
    write_json(&fixture.evidence, &evidence);
    let mut record: Value =
        serde_json::from_slice(&fs::read(&fixture.qualification).unwrap()).unwrap();
    record["qualification_id"] = "alice".into();
    record["policy_version"] = "private-host-17".into();
    record["supervised_endurance"]["evidence_sha256"] =
        sha(&fs::read(&fixture.evidence).unwrap()).into();
    write_json(&fixture.qualification, &record);

    let sanitized = sanitize_qualification_evidence_v1(
        &fs::read_to_string(&fixture.qualification).unwrap(),
        &fs::read_to_string(&fixture.evidence).unwrap(),
        Path::new(AUTHORIZED_EVIDENCE_PATH),
    )
    .unwrap();
    assert!(!sanitized.contains("qualification_id"));
    assert!(!sanitized.contains("policy_version"));
    assert!(!sanitized.contains("alice"));
    assert!(!sanitized.contains("private-host-17"));
}

#[test]
fn exact_qualified_cross_component_identities_publish_one_manifest() {
    let fixture = Fixture::new();
    assert!(fixture.validate().is_ok());
    assert!(!fixture.promoted.exists());
}

#[test]
fn commands_publish_exact_outputs_and_never_clobber() {
    let fixture = Fixture::new();
    let redacted = fixture.root.join("redacted-by-command.json");
    let mut io = FixtureIo {
        evidence: &fixture.evidence,
    };
    let redaction_arguments = [
        "--qualification-record",
        fixture.qualification.to_str().unwrap(),
        "--evidence",
        AUTHORIZED_EVIDENCE_PATH,
        "--authorized-evidence-path",
        AUTHORIZED_EVIDENCE_PATH,
        "--output",
        redacted.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from);

    assert_eq!(
        redact_evidence_command(redaction_arguments, &mut io).unwrap(),
        redacted
    );
    assert_eq!(
        fs::read(&redacted).unwrap(),
        fs::read(&fixture.sanitized).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&redacted).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let arguments = fixture.virtual_promotion_args();
    assert_eq!(
        check_promotion_command(arguments.into_iter().skip(1), &mut io).unwrap(),
        fixture.promoted
    );
    assert_eq!(
        fs::read(&fixture.promoted).unwrap(),
        fs::read(&fixture.manifest).unwrap()
    );
    assert!(
        check_promotion_command(
            fixture.virtual_promotion_args().into_iter().skip(1),
            &mut io
        )
        .is_err()
    );
    assert_eq!(
        fs::read(&fixture.promoted).unwrap(),
        fs::read(&fixture.manifest).unwrap()
    );
}

#[test]
fn command_validation_failure_publishes_nothing() {
    let fixture = Fixture::new();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    manifest["policy"]["sha256"] = "0".repeat(64).into();
    write_json(&fixture.manifest, &manifest);
    let mut io = FixtureIo {
        evidence: &fixture.evidence,
    };

    assert!(
        check_promotion_command(
            fixture.virtual_promotion_args().into_iter().skip(1),
            &mut io
        )
        .is_err()
    );
    assert!(!fixture.promoted.exists());
}

#[test]
fn promotion_rejects_raw_evidence_changed_after_qualification() {
    let fixture = Fixture::new();
    let mut evidence: Value =
        serde_json::from_slice(&fs::read(&fixture.evidence).unwrap()).unwrap();
    evidence["outcome"]["reason"] = "changed after qualification".into();
    write_json(&fixture.evidence, &evidence);
    let mut io = FixtureIo {
        evidence: &fixture.evidence,
    };

    assert!(
        check_promotion_command(
            fixture.virtual_promotion_args().into_iter().skip(1),
            &mut io
        )
        .is_err()
    );
    assert!(!fixture.promoted.exists());
}

#[test]
fn promotion_rejects_evidence_outside_the_authorized_path() {
    let fixture = Fixture::new();
    let mut arguments = fixture.virtual_promotion_args();
    arguments[6] = fixture.evidence.as_os_str().into();
    let mut io = FixtureIo {
        evidence: &fixture.evidence,
    };

    let error = check_promotion_command(arguments.into_iter().skip(1), &mut io)
        .unwrap_err()
        .to_string();
    assert!(error.contains("exact authorized evidence path"));
    assert!(!fixture.promoted.exists());
}

#[test]
fn commands_reject_duplicate_flags_before_publication() {
    let fixture = Fixture::new();
    let mut io = FixtureIo {
        evidence: &fixture.evidence,
    };
    let arguments = [
        "--qualification-record",
        fixture.qualification.to_str().unwrap(),
        "--evidence",
        AUTHORIZED_EVIDENCE_PATH,
        "--authorized-evidence-path",
        AUTHORIZED_EVIDENCE_PATH,
        "--output",
        fixture.promoted.to_str().unwrap(),
        "--output",
        fixture.sanitized.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from);

    let error = redact_evidence_command(arguments, &mut io)
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate argument: --output"));
    assert!(!fixture.promoted.exists());
}

#[test]
fn published_schema_accepts_only_the_complete_promotion_contract() {
    let fixture = Fixture::new();
    let schema: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/promotion-manifest.json"
    )))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let manifest: Value = serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    assert!(validator.is_valid(&manifest));

    for pointer in [
        "/qualification_record_sha256",
        "/controller",
        "/policy",
        "/kernel",
        "/packages",
        "/sanitized_evidence_sha256",
    ] {
        let mut incomplete = manifest.clone();
        incomplete
            .as_object_mut()
            .unwrap()
            .remove(pointer.trim_start_matches('/'));
        assert!(
            !validator.is_valid(&incomplete),
            "accepted missing {pointer}"
        );
    }
    let mut source_only = manifest;
    source_only["ci_passed"] = true.into();
    assert!(!validator.is_valid(&source_only));

    let mut numeric_digest: Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    numeric_digest["controller"]["package_sha256"] = 1.into();
    assert!(!validator.is_valid(&numeric_digest));
}

#[test]
fn any_hash_mismatch_or_unqualified_record_produces_no_artifact() {
    for pointer in [
        "/qualification_record_sha256",
        "/controller/package_sha256",
        "/controller/signature_sha256",
        "/policy/sha256",
        "/kernel/image_sha256",
        "/kernel/module_sha256",
        "/packages/provenance_sha256",
        "/packages/manifest_signature_sha256",
        "/packages/artifacts/0/sha256",
        "/sanitized_evidence_sha256",
    ] {
        let fixture = Fixture::new();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
        *manifest.pointer_mut(pointer).unwrap() = "0".repeat(64).into();
        write_json(&fixture.manifest, &manifest);

        let mut io = FixtureIo {
            evidence: &fixture.evidence,
        };
        assert!(
            check_promotion_command(
                fixture.virtual_promotion_args().into_iter().skip(1),
                &mut io
            )
            .is_err(),
            "{pointer}"
        );
        assert!(
            !fixture.promoted.exists(),
            "{pointer} published an artifact"
        );
    }

    let fixture = Fixture::new();
    let mut record: Value =
        serde_json::from_slice(&fs::read(&fixture.qualification).unwrap()).unwrap();
    record["supervised_endurance"]["outcome"] = "no-go".into();
    write_json(&fixture.qualification, &record);
    let mut io = FixtureIo {
        evidence: &fixture.evidence,
    };
    assert!(
        check_promotion_command(
            fixture.virtual_promotion_args().into_iter().skip(1),
            &mut io
        )
        .is_err()
    );
    assert!(!fixture.promoted.exists());

    let fixture = Fixture::new();
    let mut evidence: Value =
        serde_json::from_slice(&fs::read(&fixture.evidence).unwrap()).unwrap();
    evidence["process_stops"].as_array_mut().unwrap().pop();
    write_json(&fixture.evidence, &evidence);
    let mut record: Value =
        serde_json::from_slice(&fs::read(&fixture.qualification).unwrap()).unwrap();
    record["supervised_endurance"]["evidence_sha256"] =
        sha(&fs::read(&fixture.evidence).unwrap()).into();
    write_json(&fixture.qualification, &record);
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    manifest["qualification_record_sha256"] =
        sha(&fs::read(&fixture.qualification).unwrap()).into();
    write_json(&fixture.manifest, &manifest);
    let mut io = FixtureIo {
        evidence: &fixture.evidence,
    };
    assert!(
        check_promotion_command(
            fixture.virtual_promotion_args().into_iter().skip(1),
            &mut io
        )
        .is_err()
    );
    assert!(!fixture.promoted.exists());

    let fixture = Fixture::new();
    fs::remove_file(&fixture.package_signature).unwrap();
    let mut io = FixtureIo {
        evidence: &fixture.evidence,
    };
    assert!(
        check_promotion_command(
            fixture.virtual_promotion_args().into_iter().skip(1),
            &mut io
        )
        .is_err()
    );
    assert!(!fixture.promoted.exists());
}

#[test]
fn ci_tag_release_or_public_source_claims_cannot_replace_qualification() {
    let fixture = Fixture::new();
    let claims = json!({
        "schema_version": 1,
        "ci_passed": true,
        "tag": "v0.1.0",
        "release": "published",
        "public_source": true
    });
    write_json(&fixture.manifest, &claims);

    assert!(fixture.validate().is_err());
    assert!(!fixture.promoted.exists());
}

#[test]
fn sanitized_evidence_with_raw_or_private_fields_is_rejected() {
    let fixture = Fixture::new();
    let mut summary: Value =
        serde_json::from_slice(&fs::read(&fixture.sanitized).unwrap()).unwrap();
    summary["samples"] = json!([{ "hostname": "private-machine" }]);
    write_json(&fixture.sanitized, &summary);
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    manifest["sanitized_evidence_sha256"] = sha(&fs::read(&fixture.sanitized).unwrap()).into();
    write_json(&fixture.manifest, &manifest);

    assert!(fixture.validate().is_err());
    assert!(!fixture.promoted.exists());
}

#[test]
fn package_provenance_must_match_the_exact_schema_and_order() {
    for mutation in ["missing-package", "reordered-packages", "unknown-field"] {
        let fixture = Fixture::new();
        let mut provenance: Value =
            serde_json::from_slice(&fs::read(&fixture.provenance).unwrap()).unwrap();
        match mutation {
            "missing-package" => {
                provenance["packages"].as_array_mut().unwrap().pop();
            }
            "reordered-packages" => {
                provenance["packages"].as_array_mut().unwrap().swap(0, 1);
            }
            "unknown-field" => provenance["release"] = "public".into(),
            _ => unreachable!(),
        }
        fixture.replace_provenance(&provenance, true);

        let error = fixture.validate().unwrap_err().to_string();
        assert!(
            error.contains("package provenance field: schema"),
            "{mutation}: {error}"
        );
        assert!(!fixture.promoted.exists());
    }
}

#[test]
fn kernel_and_signature_identities_must_match_across_artifacts() {
    for pointer in [
        "/kernel/release",
        "/kernel/image_signer_fingerprint",
        "/kernel/module_signer_fingerprint",
        "/packages/manifest_signer_fingerprint",
    ] {
        let fixture = Fixture::new();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
        *manifest.pointer_mut(pointer).unwrap() = match pointer {
            "/kernel/release" => "7.1.8-cachyos-pt31553-other".into(),
            _ => "a".repeat(64).into(),
        };
        write_json(&fixture.manifest, &manifest);

        assert!(fixture.validate().is_err(), "{pointer}");
        assert!(!fixture.promoted.exists());
    }

    let fixture = Fixture::new();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    manifest["packages"]["manifest_signer_fingerprint"] = "not-hex".into();
    write_json(&fixture.manifest, &manifest);
    assert!(fixture.validate().is_err());
}

#[test]
fn qualified_source_commit_must_match_package_provenance() {
    let fixture = Fixture::new();
    let different_commit = "0123456789abcdef0123456789abcdef01234567";
    let mut evidence: Value =
        serde_json::from_slice(&fs::read(&fixture.evidence).unwrap()).unwrap();
    evidence["qualification_envelope"]["compatibility"]["kernel"]["source_commit"] =
        different_commit.into();
    write_json(&fixture.evidence, &evidence);
    let mut record: Value =
        serde_json::from_slice(&fs::read(&fixture.qualification).unwrap()).unwrap();
    record["compatibility"]["kernel"]["source_commit"] = different_commit.into();
    record["supervised_endurance"]["evidence_sha256"] =
        sha(&fs::read(&fixture.evidence).unwrap()).into();
    write_json(&fixture.qualification, &record);
    let sanitized = sanitize_qualification_evidence_v1(
        &fs::read_to_string(&fixture.qualification).unwrap(),
        &fs::read_to_string(&fixture.evidence).unwrap(),
        Path::new(AUTHORIZED_EVIDENCE_PATH),
    )
    .unwrap();
    fs::write(&fixture.sanitized, sanitized).unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    manifest["qualification_record_sha256"] =
        sha(&fs::read(&fixture.qualification).unwrap()).into();
    manifest["sanitized_evidence_sha256"] = sha(&fs::read(&fixture.sanitized).unwrap()).into();
    write_json(&fixture.manifest, &manifest);

    let error = fixture.validate().unwrap_err().to_string();
    assert!(error.contains("build.source_commit"), "{error}");
    assert!(!fixture.promoted.exists());
}

#[test]
fn cli_rejects_unprotected_inputs_and_never_publishes() {
    let fixture = Fixture::new();
    let mut arguments = fixture.promotion_args();
    arguments[8] = fixture.evidence.to_str().unwrap();
    let output = qualify(&arguments);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("root"));
    assert!(!fixture.promoted.exists());
}

#[test]
fn cli_rejects_an_evidence_path_other_than_the_authorized_path() {
    let fixture = Fixture::new();
    let output = qualify(&[
        "redact-evidence",
        "--qualification-record",
        fixture.qualification.to_str().unwrap(),
        "--evidence",
        fixture.evidence.to_str().unwrap(),
        "--authorized-evidence-path",
        AUTHORIZED_EVIDENCE_PATH,
        "--output",
        fixture.promoted.to_str().unwrap(),
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exact authorized evidence path"));
    assert!(!fixture.promoted.exists());
}

#[cfg(unix)]
#[test]
fn cli_rejects_a_fifo_before_opening_it() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let fixture = Fixture::new();
    let fifo = fixture.root.join("qualification.fifo");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo_name is a valid NUL-terminated path and mode has no invalid bits.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let output = qualify(&[
        "redact-evidence",
        "--qualification-record",
        fifo.to_str().unwrap(),
        "--evidence",
        fixture.evidence.to_str().unwrap(),
        "--authorized-evidence-path",
        fixture.evidence.to_str().unwrap(),
        "--output",
        fixture.promoted.to_str().unwrap(),
    ]);

    assert!(!output.status.success());
    assert!(!fixture.promoted.exists());
}
