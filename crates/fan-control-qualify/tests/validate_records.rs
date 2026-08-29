use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

const AUTHORIZED_EVIDENCE_PATH: &str =
    "/var/lib/pt31553-fan-control/evidence/supervised-endurance.json";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pt31553-validate-records-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn matching_sources() -> (String, String) {
    let mut compressed = GzDecoder::new(
        &include_bytes!("../../../qualification/supervised-endurance-v2.json.gz")[..],
    );
    let mut evidence = String::new();
    compressed.read_to_string(&mut evidence).unwrap();
    let evidence_value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
    let envelope = &evidence_value["qualification_envelope"];
    let record = serde_json::json!({
        "schema_version": 2,
        "qualification_id": envelope["qualification_id"],
        "policy_version": envelope["policy_version"],
        "protected_policy_sha256": envelope["protected_policy_sha256"],
        "compatibility": envelope["compatibility"],
        "supervised_endurance": {
            "schema_version": 1,
            "evidence_sha256": format!("{:x}", Sha256::digest(evidence.as_bytes())),
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
    (serde_json::to_string(&record).unwrap(), evidence)
}

fn write_sources(directory: &Path, record: &str, evidence: &str) -> (PathBuf, PathBuf) {
    let record_path = directory.join("qualification.json");
    let evidence_path = directory.join("archived-evidence.json");
    fs::write(&record_path, record).unwrap();
    fs::write(&evidence_path, evidence).unwrap();
    (record_path, evidence_path)
}

#[test]
fn archived_records_validate_through_the_cli_with_the_original_authorized_path() {
    let directory = TestDirectory::new();
    let (record, evidence) = matching_sources();
    let (record_path, evidence_path) = write_sources(&directory.0, &record, &evidence);

    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .args([
            "validate-records",
            "--qualification-record",
            record_path.to_str().unwrap(),
            "--evidence",
            evidence_path.to_str().unwrap(),
            "--authorized-evidence-path",
            AUTHORIZED_EVIDENCE_PATH,
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("records are valid"));

    let without_authorized_path = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .args([
            "validate-records",
            "--qualification-record",
            record_path.to_str().unwrap(),
            "--evidence",
            evidence_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!without_authorized_path.success());
}

#[test]
fn cli_rejects_failed_evidence_even_when_its_digest_is_rebound() {
    let directory = TestDirectory::new();
    let (record, evidence) = matching_sources();
    let mut evidence: serde_json::Value = serde_json::from_str(&evidence).unwrap();
    evidence["outcome"]["status"] = "failed".into();
    let evidence = serde_json::to_string(&evidence).unwrap();
    let mut record: serde_json::Value = serde_json::from_str(&record).unwrap();
    record["supervised_endurance"]["evidence_sha256"] =
        format!("{:x}", Sha256::digest(evidence.as_bytes())).into();
    let record = serde_json::to_string(&record).unwrap();
    let (record_path, evidence_path) = write_sources(&directory.0, &record, &evidence);

    let status = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .args([
            "validate-records",
            "--qualification-record",
            record_path.to_str().unwrap(),
            "--evidence",
            evidence_path.to_str().unwrap(),
            "--authorized-evidence-path",
            AUTHORIZED_EVIDENCE_PATH,
        ])
        .status()
        .unwrap();

    assert!(!status.success());
}

#[cfg(unix)]
#[test]
fn cli_reads_an_archive_path_that_is_not_utf8() {
    use std::os::unix::ffi::OsStringExt;

    let directory = TestDirectory::new();
    let (record, evidence) = matching_sources();
    let record_path = directory.0.join("qualification.json");
    let evidence_path = directory
        .0
        .join(std::ffi::OsString::from_vec(b"evidence-\xff.json".to_vec()));
    fs::write(&record_path, record).unwrap();
    fs::write(&evidence_path, evidence).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .arg("validate-records")
        .arg("--qualification-record")
        .arg(record_path)
        .arg("--evidence")
        .arg(evidence_path)
        .arg("--authorized-evidence-path")
        .arg(AUTHORIZED_EVIDENCE_PATH)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
