use sha2::Digest;
use std::fs;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn private_key_fixture(payload: &[u8]) -> Vec<u8> {
    [
        b"-----BEGIN PRI".as_slice(),
        b"VATE KEY-----\n",
        payload,
        b"\n-----END PRIVATE KEY-----\n",
    ]
    .concat()
}

fn certificate_fixture(payload: &[u8]) -> Vec<u8> {
    [
        b"-----BEGIN CERT".as_slice(),
        b"IFICATE-----\n",
        payload,
        b"\n-----END CERTIFICATE-----\n",
    ]
    .concat()
}

fn age_secret_fixture() -> Vec<u8> {
    [
        b"AGE-SECRET-".as_slice(),
        b"KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ".as_slice(),
    ]
    .concat()
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn repository() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "fan-control-sensitive-history-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.name", "Sensitive History Test"]);
    git(
        &root,
        &["config", "user.email", "sensitive-history@example.invalid"],
    );
    git(&root, &["config", "commit.gpgSign", "false"]);
    git(&root, &["config", "tag.gpgSign", "false"]);
    fs::write(root.join("safe.txt"), b"safe source\n").unwrap();
    git(&root, &["add", "safe.txt"]);
    git(&root, &["commit", "-q", "-m", "safe"]);
    root
}

fn gate(root: &Path) -> std::process::ExitStatus {
    gate_command(root).status().unwrap()
}

fn gate_command(root: &Path) -> Command {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let mut command = Command::new(workspace.join("scripts/check-sensitive-history"));
    command
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn tree_gate(root: &Path, allowed_certificates: &[&Path]) -> std::process::Output {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let mut command = Command::new(workspace.join("scripts/check-sensitive-history"));
    command.arg("--tree").arg(root);
    for certificate in allowed_certificates {
        command.arg("--allow-public-certificate").arg(certificate);
    }
    command.output().unwrap()
}

#[test]
fn accepts_public_openpgp_signature_checksum_in_commit_payloads() {
    let root = repository();
    let mut signature_packet = vec![0xc2, 78];
    signature_packet.extend([0_u8; 78]);
    let encoded = base64_bytes(&signature_packet);
    let payload = format!(
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n {}\n {}\n =AAAA\n -----END PGP SIGNATURE-----\n",
        String::from_utf8_lossy(&encoded[..64]),
        String::from_utf8_lossy(&encoded[64..]),
    );
    fs::write(root.join("public-signature.commit"), payload).unwrap();
    git(&root, &["add", "public-signature.commit"]);
    git(&root, &["commit", "-q", "-m", "retain public signature"]);

    assert!(gate(&root).success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepts_digest_info_inside_a_valid_ssh_signature() {
    let digest_info = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let mut sshsig = b"SSHSIG".to_vec();
    sshsig.extend(1_u32.to_be_bytes());
    for field in [
        b"public-key".as_slice(),
        b"git".as_slice(),
        b"".as_slice(),
        b"sha256".as_slice(),
        digest_info.as_slice(),
    ] {
        sshsig.extend(u32::try_from(field.len()).unwrap().to_be_bytes());
        sshsig.extend(field);
    }
    let encoded = base64_bytes(&sshsig);
    let payload = format!(
        "gpgsig -----BEGIN SSH SIGNATURE-----\n {}\n -----END SSH SIGNATURE-----\n",
        String::from_utf8_lossy(&encoded)
    );
    let root = repository();
    fs::write(root.join("public-signature.commit"), payload).unwrap();
    git(&root, &["add", "public-signature.commit"]);
    git(
        &root,
        &["commit", "-q", "-m", "retain public SSH signature"],
    );
    let output = gate_command(&root).output().unwrap();
    assert!(
        output.status.success(),
        "history rejected SSH signature: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn module_signature_masking_requires_successful_verification() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import sys
loader = importlib.machinery.SourceFileLoader("history_scanner", sys.argv[1])
spec = importlib.util.spec_from_loader("history_scanner", loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
payload = b"module payload"
signer = b"signer"
key_id = b"key-id"
signature = b"\x1f\x8bpublic detached signature"
trailer = bytes((0, 6, 2, len(signer), len(key_id), 0, 0, 0))
trailer += len(signature).to_bytes(4, "big")
content = payload + signer + key_id + signature + trailer + module.MODULE_SIGNATURE_MAGIC
signature_at = len(payload) + len(signer) + len(key_id)

class Result:
    def __init__(self, returncode):
        self.returncode = returncode

module.probe = lambda command, budget: Result(0)
masked = module.mask_verified_module_signature(
    content, frozenset((b"certificate",)), module.inspection_budget()
)
module.probe = lambda command, budget: Result(1)
unverified = module.mask_verified_module_signature(
    content, frozenset((b"certificate",)), module.inspection_budget()
)
print(
    int(masked[signature_at:signature_at + len(signature)] == b"\0" * len(signature)),
    int(unverified == content),
)
"#;
    let output = Command::new("python3")
        .args(["-I", "-c", source])
        .arg(workspace.join("scripts/check-sensitive-history"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "module signature masking harness failed"
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "1 1",
        "only a verified detached module signature may be masked"
    );
}

#[test]
fn ignores_git_object_ids_only_in_structural_headers() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import sys
loader = importlib.machinery.SourceFileLoader("history_scanner", sys.argv[1])
spec = importlib.util.spec_from_loader("history_scanner", loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
tree = bytes((99, 53, 56, 54, 49, 102, 56, 98, 57, 99, 54, 57, 53, 49, 52, 57, 48, 99, 54, 50, 52, 102, 54, 99, 48, 49, 57, 98, 100, 102, 55, 100, 52, 53, 50, 102, 54, 56, 51, 50))
parent = bytes((100, 102, 99, 56, 51, 49, 50, 101, 100, 100, 52, 51, 53, 50, 97, 101, 49, 51, 48, 102, 51, 48, 98, 101, 51, 101, 100, 54, 52, 48, 49, 97, 54, 98, 53, 99, 97, 97, 101, 57))
header = b"tree " + tree + b"\nparent " + parent + b"\n\nsafe\n"
message = b"tree " + b"0" * 40 + b"\nparent " + b"0" * 40 + b"\n\n" + tree + b"\n" + parent + b"\n"
print(
    int(module.sensitive(header)),
    int(module.sensitive(module.mask_git_object_identifier_headers(header, "commit"))),
    int(module.sensitive(module.mask_git_object_identifier_headers(message, "commit"))),
)
"#;
    let output = Command::new("python3")
        .args(["-I", "-c", source])
        .arg(workspace.join("scripts/check-sensitive-history"))
        .output()
        .unwrap();
    assert!(output.status.success(), "Git object masking harness failed");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "1 0 1",
        "structural identifiers must be masked without masking commit messages"
    );
}

#[test]
fn rejects_sensitive_commit_and_annotated_tag_payloads() {
    let commit_root = repository();
    let commit_message = String::from_utf8(private_key_fixture(b"secret")).unwrap();
    git(
        &commit_root,
        &["commit", "--allow-empty", "-q", "-m", &commit_message],
    );
    assert!(!gate(&commit_root).success());
    fs::remove_dir_all(commit_root).unwrap();

    let tag_root = repository();
    let tag_message = String::from_utf8(certificate_fixture(b"secret")).unwrap();
    git(
        &tag_root,
        &["tag", "-a", "sensitive-tag", "-m", &tag_message],
    );
    assert!(!gate(&tag_root).success());
    fs::remove_dir_all(tag_root).unwrap();
}

#[test]
fn output_tree_allows_public_certificates_only_at_documented_artifact_paths() {
    let root = temporary_fixture("output-tree-certificate-paths");
    let certificate = legacy_x509_certificate_pem();
    let allowed_pem = root.with_extension("allowed.pem");
    fs::write(&allowed_pem, &certificate).unwrap();
    fs::create_dir_all(root.join("usr/lib/modules/test")).unwrap();
    fs::write(root.join("usr/lib/modules/test/vmlinuz"), &certificate).unwrap();
    assert!(tree_gate(&root, &[&allowed_pem]).status.success());

    let certificate_der = large_rsa_certificate_der();
    let mut certificate_with_public_padding = certificate_der.clone();
    let allowed_der = root.with_extension("allowed.der");
    fs::write(&allowed_der, &certificate_der).unwrap();
    certificate_with_public_padding.extend([0xff; 60]);
    let encoded_certificate = base64_bytes(&certificate_with_public_padding);
    assert!(
        encoded_certificate
            .iter()
            .filter(|byte| **byte == b'/')
            .count()
            > 17,
        "fixture needs more than 17 literal Base64 slashes"
    );
    fs::write(
        root.join("usr/lib/modules/test/vmlinuz"),
        encoded_certificate,
    )
    .unwrap();
    let padded_certificate_result = tree_gate(&root, &[&allowed_der]);
    assert!(
        padded_certificate_result.status.success(),
        "{}",
        String::from_utf8_lossy(&padded_certificate_result.stderr)
    );

    fs::write(root.join("build.log"), &certificate).unwrap();
    assert!(
        !tree_gate(&root, &[&allowed_pem, &allowed_der])
            .status
            .success()
    );
    fs::remove_file(root.join("build.log")).unwrap();

    let mut prefixed_certificate = b"benign public material prefix\n".to_vec();
    prefixed_certificate.extend(certificate_der);
    let ambiguous_certificate = long_irregular_path_base64(&prefixed_certificate);
    assert!(assert_scanner_parity(
        "ambiguous-path-certificate.txt",
        &ambiguous_certificate,
    ));
    fs::write(root.join("build.log"), &ambiguous_certificate).unwrap();
    assert!(
        !tree_gate(&root, &[&allowed_pem, &allowed_der])
            .status
            .success(),
        "accepted an ambiguous path-shaped certificate"
    );
    fs::remove_file(root.join("build.log")).unwrap();
    historical_blob_is_rejected("ambiguous-path-certificate.txt", &ambiguous_certificate);

    for path in [
        "docs/vmlinuz",
        "tmp/certs/signing_key.x509",
        "tmp/payload.ko",
    ] {
        let candidate = root.join(path);
        fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        fs::write(&candidate, &certificate).unwrap();
        assert!(
            !tree_gate(&root, &[&allowed_pem, &allowed_der])
                .status
                .success(),
            "accepted certificate at suffix-matching non-artifact path {path}"
        );
        fs::remove_file(candidate).unwrap();
    }

    let mut unexpected_store = certificate.clone();
    unexpected_store.extend(large_rsa_certificate_der());
    fs::write(root.join("usr/lib/modules/test/vmlinuz"), unexpected_store).unwrap();
    assert!(
        !tree_gate(&root, &[&allowed_pem]).status.success(),
        "accepted an additional trust-store certificate in vmlinuz"
    );

    fs::write(root.join("usr/lib/modules/test/vmlinuz"), &certificate).unwrap();
    fs::create_dir_all(root.join("usr/share/doc")).unwrap();
    fs::write(
        root.join("usr/share/doc/extra.zip"),
        zip_bytes("usr/lib/modules/test/vmlinuz", &certificate),
    )
    .unwrap();
    assert!(
        !tree_gate(&root, &[&allowed_pem]).status.success(),
        "accepted a certificate whose documented-looking path came from a nested archive"
    );
    fs::remove_file(root.join("usr/share/doc/extra.zip")).unwrap();

    let package = root.join("linux-test.pkg.tar.zst");
    fs::write(
        &package,
        zstd_bytes(&tar_bytes(
            "usr/lib/modules/test/build/certs/signing_key.x509",
            &certificate,
        )),
    )
    .unwrap();
    let packaged_certificate_result = tree_gate(&root, &[&allowed_pem]);
    assert!(
        packaged_certificate_result.status.success(),
        "rejected an allowed certificate at its documented package path: {}",
        String::from_utf8_lossy(&packaged_certificate_result.stderr)
    );
    fs::write(
        &package,
        zstd_bytes(&tar_bytes("usr/share/doc/unapproved.pem", &certificate)),
    )
    .unwrap();
    assert!(
        !tree_gate(&root, &[&allowed_pem]).status.success(),
        "accepted an allowed certificate at an undocumented package path"
    );
    fs::remove_file(package).unwrap();

    let malformed_certificate = String::from_utf8(certificate.clone())
        .unwrap()
        .replace("BEGIN X509 CERTIFICATE", "BEGIN EXTRA CERTIFICATE")
        .into_bytes();
    fs::write(
        root.join("usr/lib/modules/test/vmlinuz"),
        malformed_certificate,
    )
    .unwrap();
    assert!(
        !tree_gate(&root, &[&allowed_pem]).status.success(),
        "accepted a malformed certificate envelope at an allowed artifact path"
    );

    fs::write(
        root.join("usr/lib/modules/test/vmlinuz"),
        unencrypted_pkcs8_der(),
    )
    .unwrap();
    assert!(!tree_gate(&root, &[&allowed_pem]).status.success());
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(allowed_pem).unwrap();
    fs::remove_file(allowed_der).unwrap();
}

#[test]
fn output_tree_normalizes_mtree_digests_without_skipping_encoded_secrets() {
    let root = temporary_fixture("mtree-sensitive-scanning");
    let mut mtree = format!(
        "#mtree\n./one type=file md5={} sha256={}\n./two type=file md5digest={} sha256digest={}\n",
        "a".repeat(32),
        "b".repeat(64),
        "c".repeat(32),
        "d".repeat(64),
    )
    .into_bytes();
    let harmless_asn1_decoy = b"\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    mtree.extend_from_slice(harmless_asn1_decoy);
    mtree.push(b'\n');
    let valid_mtree = mtree.clone();
    fs::write(root.join(".MTREE"), gzip_bytes(&mtree)).unwrap();
    let output = tree_gate(&root, &[]);
    assert!(
        output.status.success(),
        "rejected valid MTREE digest spellings: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    mtree.extend(base64_bytes(&unencrypted_pkcs8_der()));
    mtree.push(b'\n');
    fs::write(root.join(".MTREE"), gzip_bytes(&mtree)).unwrap();
    assert!(
        !tree_gate(&root, &[]).status.success(),
        "ASN.1 decoy hid a trailing Base64 private key"
    );

    let mut non_attribute_digest = valid_mtree;
    non_attribute_digest.extend_from_slice(b"# sha256=");
    non_attribute_digest
        .extend_from_slice(format!("06092a864886f70d01050d{}\n", "00".repeat(21)).as_bytes());
    fs::write(root.join(".MTREE"), gzip_bytes(&non_attribute_digest)).unwrap();
    assert!(
        !tree_gate(&root, &[]).status.success(),
        "masked a digest-like private-key marker outside an MTREE attribute"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn output_tree_masks_only_sha256_digests_verified_against_tree_files() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import sys
loader = importlib.machinery.SourceFileLoader("history_scanner", sys.argv[1])
spec = importlib.util.spec_from_loader("history_scanner", loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
secret = b"-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n"
secret += b"\n" * (-len(secret) % 32)
chunks = [secret[index:index + 32].hex().encode() for index in range(0, len(secret), 32)]
content = b"".join(
    digest + b"  file-" + str(index).encode() + b"\n"
    for index, digest in enumerate(chunks)
)
verified = {b"file-" + str(index).encode(): digest for index, digest in enumerate(chunks)}
mismatched = dict(verified)
mismatched[b"file-0"] = b"0" * 64
print(
    int(module.sensitive(content)),
    int(module.sensitive(module.mask_verified_sha256sum_digests(content, verified))),
    int(module.sensitive(module.mask_verified_sha256sum_digests(content, mismatched))),
)
"#;
    let output = Command::new("python3")
        .args(["-I", "-c", source])
        .arg(workspace.join("scripts/check-sensitive-history"))
        .output()
        .unwrap();
    assert!(output.status.success(), "SHA256SUMS masking harness failed");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "1 0 1",
        "only digests matching stable tree files may be masked"
    );

    let root = temporary_fixture("sha256sum-sensitive-scanning");
    fs::write(root.join("payload"), b"safe payload\n").unwrap();
    let digest = sha2::Sha256::digest(b"safe payload\n");
    fs::write(root.join("SHA256SUMS"), format!("{digest:x}  payload\n")).unwrap();
    let accepted = tree_gate(&root, &[]);
    assert!(
        accepted.status.success(),
        "rejected a verified checksum manifest: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn output_tree_inspects_archive_members_without_scanning_container_bytes_as_payload() {
    let root = temporary_fixture("archive-container-scanning");
    let harmless_asn1_decoy = b"\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    for (name, archive) in [
        ("benign.tar", tar_bytes("payload.bin", harmless_asn1_decoy)),
        ("benign.zip", zip_bytes("payload.bin", harmless_asn1_decoy)),
    ] {
        fs::write(root.join(name), archive).unwrap();
    }
    let output = tree_gate(&root, &[]);
    assert!(
        output.status.success(),
        "rejected benign archive container bytes: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    fs::write(
        root.join("sensitive.tar"),
        tar_bytes("payload.bin", &private_key_fixture(b"secret")),
    )
    .unwrap();
    assert!(
        !tree_gate(&root, &[]).status.success(),
        "archive member recursion skipped a private key"
    );
    fs::remove_file(root.join("sensitive.tar")).unwrap();

    let encoded_name = String::from_utf8(irregular_path_base64(&unencrypted_pkcs8_der()))
        .unwrap()
        .trim()
        .to_string();
    fs::write(
        root.join("encoded-name.tar"),
        tar_bytes(&encoded_name, b"benign member content\n"),
    )
    .unwrap();
    assert!(
        !tree_gate(&root, &[]).status.success(),
        "accepted Base64-encoded private material in an archive member name"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn output_tree_base64_candidate_budget_accepts_provenance_workloads_but_remains_bounded() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source_lock = fs::read(workspace.join("packaging/kernel/source-lock.toml")).unwrap();

    let accepted = temporary_fixture("base64-candidate-allowance");
    for index in 0..3 {
        fs::write(
            accepted.join(format!("source-lock-{index}.toml")),
            &source_lock,
        )
        .unwrap();
    }
    let output = tree_gate(&accepted, &[]);
    assert!(
        output.status.success(),
        "rejected a bounded provenance workload above the old allowance: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(accepted).unwrap();

    let exhausted = temporary_fixture("base64-candidate-exhaustion");
    for index in 0..11 {
        fs::write(
            exhausted.join(format!("source-lock-{index}.toml")),
            &source_lock,
        )
        .unwrap();
    }
    assert!(
        !tree_gate(&exhausted, &[]).status.success(),
        "accepted a tree beyond the Base64 candidate bound"
    );
    fs::remove_dir_all(exhausted).unwrap();
}

#[test]
fn output_tree_bounds_openssl_probes_for_distinct_base64_candidates() {
    fn encoded_decoy(unique: u8) -> Vec<u8> {
        let mut der = b"\x30\x2e\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01".to_vec();
        der.resize(48, 0);
        *der.last_mut().unwrap() = unique;
        base64_bytes(&der)
    }

    let accepted = temporary_fixture("openssl-probe-allowance");
    for index in 0_u8..85 {
        fs::write(
            accepted.join(format!("candidate-{index:02}.txt")),
            encoded_decoy(index),
        )
        .unwrap();
    }
    let output = tree_gate(&accepted, &[]);
    assert!(
        output.status.success(),
        "rejected input within the OpenSSL probe bound: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(accepted).unwrap();

    let exhausted = temporary_fixture("openssl-probe-exhaustion");
    for index in 0_u8..86 {
        fs::write(
            exhausted.join(format!("candidate-{index:02}.txt")),
            encoded_decoy(index),
        )
        .unwrap();
    }
    assert!(
        !tree_gate(&exhausted, &[]).status.success(),
        "accepted input beyond the shared OpenSSL probe bound"
    );
    fs::remove_dir_all(exhausted).unwrap();
}

#[test]
fn rejects_unreadable_tree_directories() {
    let root = temporary_fixture("unreadable-output-directory");
    let hidden = root.join("unreadable");
    fs::create_dir(&hidden).unwrap();
    fs::write(
        hidden.join("private-key.pem"),
        private_key_fixture(b"secret"),
    )
    .unwrap();
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o000)).unwrap();

    let output = tree_gate(&root, &[]);

    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(
        !output.status.success(),
        "accepted an unreadable tree directory"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("tree directory is unavailable"),
        "tree gate failed for the wrong reason: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_zip_directory_entries_that_contain_payload_bytes() {
    historical_blob_is_rejected(
        "directory-entry.zip",
        &zip_directory_payload(&private_key_fixture(b"secret")),
    );
}

#[test]
fn rejects_malformed_certificate_envelopes_in_history() {
    let certificate = String::from_utf8(legacy_x509_certificate_pem())
        .unwrap()
        .replace("BEGIN X509 CERTIFICATE", "BEGIN EXTRA CERTIFICATE")
        .into_bytes();
    historical_blob_is_rejected("malformed-certificate.pem", &certificate);
}

#[test]
fn rejects_short_fragmented_urlsafe_archived_and_overlapping_sensitive_content() {
    let encoded_key = base64_bytes(&unencrypted_pkcs8_der());
    let short_fragmented = encoded_key
        .chunks(4)
        .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
        .collect::<Vec<_>>()
        .join(":")
        .into_bytes();
    let urlsafe = encoded_key
        .iter()
        .map(|byte| match byte {
            b'+' => b'-',
            b'/' => b'_',
            byte => *byte,
        })
        .collect::<Vec<_>>();
    let cpio = cpio_newc("etc/ssl/certs/machine-trust.conf", b"trust policy\n");
    let overlapping_ber = overlapping_ber_sequences();

    for (name, content) in [
        ("short-fragmented-key.txt", short_fragmented),
        ("urlsafe-key.txt", urlsafe),
        ("machine-trust.cpio", cpio),
        ("overlapping-ber.bin", overlapping_ber),
    ] {
        assert!(
            assert_scanner_parity(name, &content),
            "both scanners accepted {name}"
        );
        historical_blob_is_rejected(name, &content);

        let tree = temporary_fixture("new-sensitive-regression");
        fs::write(tree.join(name), content).unwrap();
        assert!(
            !tree_gate(&tree, &[]).status.success(),
            "tree accepted {name}"
        );
        fs::remove_dir_all(tree).unwrap();
    }
}

#[test]
fn accepts_incidental_legacy_cpio_magic_without_a_valid_header() {
    let mut content = b"\x71\xc7".to_vec();
    content.resize(64, 0);
    assert!(!assert_scanner_parity(
        "incidental-cpio-magic.bin",
        &content
    ));

    let tree = temporary_fixture("incidental-cpio-magic");
    fs::write(tree.join("content.bin"), &content).unwrap();
    let output = tree_gate(&tree, &[]);
    assert!(
        output.status.success(),
        "tree rejected incidental CPIO magic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(tree).unwrap();

    let root = repository();
    fs::write(root.join("content.bin"), content).unwrap();
    git(&root, &["add", "content.bin"]);
    git(&root, &["commit", "-q", "-m", "add benign binary"]);
    let output = gate_command(&root).output().unwrap();
    assert!(
        output.status.success(),
        "history rejected incidental CPIO magic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepts_digest_info_without_treating_it_as_an_encrypted_private_key() {
    let digest_info = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let tree = temporary_fixture("digest-info-tree");
    fs::write(tree.join("digest-info.der"), digest_info).unwrap();
    let output = tree_gate(&tree, &[]);
    assert!(
        output.status.success(),
        "tree rejected DigestInfo: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(tree).unwrap();

    let root = repository();
    fs::write(root.join("digest-info.der"), digest_info).unwrap();
    git(&root, &["add", "digest-info.der"]);
    git(&root, &["commit", "-q", "-m", "add public digest"]);
    let output = gate_command(&root).output().unwrap();
    assert!(
        output.status.success(),
        "history rejected DigestInfo: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepts_empty_zip_directory_entries() {
    let archive = zip_directory_entry_bytes();

    let tree = temporary_fixture("empty-zip-directory-tree");
    fs::write(tree.join("archive.zip"), &archive).unwrap();
    let output = tree_gate(&tree, &[]);
    assert!(
        output.status.success(),
        "tree scan rejected an empty ZIP directory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(tree).unwrap();

    let root = repository();
    fs::write(root.join("archive.zip"), archive).unwrap();
    git(&root, &["add", "archive.zip"]);
    git(&root, &["commit", "-q", "-m", "empty ZIP directory"]);
    assert!(gate(&root).success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_binary_private_keys_even_after_the_worktree_deletes_them() {
    let root = repository();
    assert!(gate(&root).success());

    let key = root.join("innocent-build-note.bin");
    let status = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .args(["-outform", "DER", "-out"])
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let key_bytes = fs::read(&key).unwrap();
    let mut wrapped = b"innocent prefix\n".to_vec();
    wrapped.extend(key_bytes);
    fs::write(&key, wrapped).unwrap();
    git(&root, &["add", "innocent-build-note.bin"]);
    git(&root, &["commit", "-q", "-m", "add binary key"]);
    fs::remove_file(&key).unwrap();
    git(&root, &["add", "-u"]);
    git(&root, &["commit", "-q", "-m", "delete binary key"]);

    assert!(!gate(&root).success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_machine_trust_store_paths_in_history() {
    let root = repository();
    let trust = root.join("etc/ssl/certs");
    fs::create_dir_all(&trust).unwrap();
    fs::write(trust.join("machine.pem"), b"not even certificate bytes\n").unwrap();
    git(&root, &["add", "etc/ssl/certs/machine.pem"]);
    git(&root, &["commit", "-q", "-m", "add trust store"]);
    fs::remove_dir_all(root.join("etc")).unwrap();
    git(&root, &["add", "-u"]);
    git(&root, &["commit", "-q", "-m", "delete trust store"]);

    assert!(!gate(&root).success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepts_benign_deep_base64_alphabet_path_content() {
    let root = repository();
    let structured = (0..17)
        .map(|index| format!("field{index:04}: value{index:04}"))
        .collect::<Vec<_>>()
        .join(" ");
    let deep_path = std::iter::once("src".to_string())
        .chain(std::iter::once("a".to_string()))
        .chain((0..20).map(|index| format!("Module{index:02}")))
        .collect::<Vec<_>>()
        .join("/");
    let long_deep_path = (0..20)
        .map(|index| format!("DirectoryName{index:02}"))
        .collect::<Vec<_>>()
        .join("/");
    let boundary_path = (0..18)
        .map(|index| format!("DirectoryName{index:03}"))
        .collect::<Vec<_>>()
        .join("/");
    fs::write(
        root.join("safe-path.txt"),
        format!("{deep_path}\n{structured}\n{long_deep_path}\n{structured}\n{boundary_path}\n"),
    )
    .unwrap();
    git(&root, &["add", "safe-path.txt"]);
    git(&root, &["commit", "-q", "-m", "add benign deep path"]);
    let output = gate_command(&root).output().unwrap();
    assert!(
        output.status.success(),
        "history gate rejected benign path: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_cumulative_path_shaped_base64_candidate_budgets() {
    let root = repository();
    let ambiguous = (0..56)
        .map(|index| format!("{index:04}{}AAAA\n", "AAAA/".repeat(14)))
        .collect::<String>();
    fs::write(root.join("ambiguous-path-record.txt"), ambiguous).unwrap();
    git(&root, &["add", "ambiguous-path-record.txt"]);
    git(
        &root,
        &["commit", "-q", "-m", "add cumulative ambiguous paths"],
    );

    assert!(!gate(&root).success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unsafe_historical_paths_containing_newlines() {
    let root = repository();
    let name = "release\nnotes.ppk";
    fs::write(root.join(name), b"ordinary bytes\n").unwrap();
    git(&root, &["add", "--", name]);
    git(&root, &["commit", "-q", "-m", "add newline path"]);

    let output = gate_command(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "accepted newline-containing .ppk path"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("forbidden historical path"),
        "history gate rejected newline path for the wrong reason: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_pkcs11_references_in_ordinary_historical_files() {
    let root = repository();
    fs::write(
        root.join("build-notes.txt"),
        &[
            b"signer = pkcs".as_slice(),
            b"11:token=machine-trust;object=release-key\n",
        ]
        .concat(),
    )
    .unwrap();
    git(&root, &["add", "build-notes.txt"]);
    git(
        &root,
        &["commit", "-q", "-m", "add machine trust reference"],
    );
    fs::remove_file(root.join("build-notes.txt")).unwrap();
    git(&root, &["add", "-u"]);
    git(
        &root,
        &["commit", "-q", "-m", "delete machine trust reference"],
    );

    assert!(!gate(&root).success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_private_jwks_even_after_the_worktree_deletes_them() {
    let root = repository();
    let jwk = [
        b"{\"k".as_slice(),
        b"ty\":\"RSA\",\"n\":\"public-modulus\",\"e\":\"AQAB\",".as_slice(),
        b"\"d".as_slice(),
        b"\":\"private-exponent\"}\n".as_slice(),
    ]
    .concat();
    fs::write(root.join("release.json"), jwk).unwrap();
    git(&root, &["add", "release.json"]);
    git(&root, &["commit", "-q", "-m", "add private JWK"]);
    fs::remove_file(root.join("release.json")).unwrap();
    git(&root, &["add", "-u"]);
    git(&root, &["commit", "-q", "-m", "delete private JWK"]);

    assert!(!gate(&root).success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_binary_prefixed_jwks_and_exhausted_json_scan_budgets() {
    for (name, mut content) in [
        ("binary.json", vec![0xff]),
        ("exhausted.json", b"[".repeat(4096)),
    ] {
        content.extend(
            [
                b"{\"k".as_slice(),
                b"ty\":\"oct\",\"k".as_slice(),
                b"\":\"private-secret\"}\n".as_slice(),
            ]
            .concat(),
        );
        let root = repository();
        fs::write(root.join(name), content).unwrap();
        git(&root, &["add", name]);
        git(&root, &["commit", "-q", "-m", "add adversarial JWK"]);
        assert!(!gate(&root).success(), "accepted {name}");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn rejects_putty_private_keys_by_path_and_content_in_history() {
    for (name, content) in [
        ("release.ppk", b"ordinary-looking bytes".to_vec()),
        (
            "release.txt",
            [
                b"\xff".as_slice(),
                b"PuTTY-User-Key-".as_slice(),
                b"File-3: ssh-rsa\nEncryption: none\nPrivate-Lines: 1\nsecret\n",
            ]
            .concat(),
        ),
    ] {
        let root = repository();
        fs::write(root.join(name), content).unwrap();
        git(&root, &["add", name]);
        git(&root, &["commit", "-q", "-m", "add PuTTY private key"]);
        fs::remove_file(root.join(name)).unwrap();
        git(&root, &["add", "-u"]);
        git(&root, &["commit", "-q", "-m", "delete PuTTY private key"]);
        assert!(
            !gate(&root).success(),
            "accepted historical PuTTY key {name}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    let root = repository();
    let source = root.join("release-key.txt");
    fs::write(
        &source,
        b"PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nPrivate-Lines: 1\nsecret\n",
    )
    .unwrap();
    let compressed = root.join("release-notes.gz");
    assert!(
        Command::new("gzip")
            .args(["-c"])
            .arg(&source)
            .stdout(fs::File::create(&compressed).unwrap())
            .status()
            .unwrap()
            .success()
    );
    fs::remove_file(source).unwrap();
    git(&root, &["add", "release-notes.gz"]);
    git(
        &root,
        &["commit", "-q", "-m", "add compressed PuTTY private key"],
    );
    fs::remove_file(compressed).unwrap();
    git(&root, &["add", "-u"]);
    git(
        &root,
        &["commit", "-q", "-m", "delete compressed PuTTY private key"],
    );
    assert!(
        !gate(&root).success(),
        "accepted compressed historical PuTTY key"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn history_gate_ignores_ambient_tool_and_openssl_configuration() {
    let root = repository();
    let key = root.join("private-key.bin");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "X25519", "-outform", "DER", "-out"])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    git(&root, &["add", "private-key.bin"]);
    git(&root, &["commit", "-q", "-m", "add private key"]);
    let hostile = root.join("hostile-bin");
    fs::create_dir(&hostile).unwrap();
    let marker = root.join("ambient-openssl-ran");
    let hostile_config = root.join("hostile-openssl.cnf");
    fs::write(&hostile_config, "openssl_conf = absent_section\n").unwrap();
    let fake_openssl = hostile.join("openssl");
    fs::write(
        &fake_openssl,
        format!("#!/bin/sh\n: > '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_openssl).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_openssl, permissions).unwrap();
    let git_marker = root.join("ambient-git-ran");
    let fake_git = hostile.join("git");
    fs::write(
        &fake_git,
        format!(
            "#!/bin/sh\n: > '{}'\nexec /usr/bin/git \"$@\"\n",
            git_marker.display()
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_git).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_git, permissions).unwrap();
    let output = gate_command(&root)
        .env("PATH", &hostile)
        .env("OPENSSL_CONF", &hostile_config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "ambient configuration hid a real private key"
    );
    assert!(
        output.stdout.is_empty(),
        "history gate wrote failure output to stdout"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("sensitive historical blob"),
        "history gate failed before completing sensitive-history inspection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "history gate invoked ambient OpenSSL");
    assert!(!git_marker.exists(), "history gate invoked ambient Git");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ci_invocation_uses_isolated_python_and_ignores_script_directory_shadowing() {
    let workflow = include_str!("../../../.github/workflows/sensitive-history.yml");
    assert!(workflow.contains("run: scripts/check-sensitive-history"));
    assert!(!workflow.contains("run: python3 scripts/check-sensitive-history"));

    let root = repository();
    let scripts = root.join("scripts");
    fs::create_dir(&scripts).unwrap();
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let gate = scripts.join("check-sensitive-history");
    fs::copy(workspace.join("scripts/check-sensitive-history"), &gate).unwrap();
    let mut permissions = fs::metadata(&gate).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&gate, permissions).unwrap();
    fs::write(
        scripts.join("json.py"),
        "raise RuntimeError('attacker-controlled json module loaded')\n",
    )
    .unwrap();
    git(&root, &["add", "scripts"]);
    git(
        &root,
        &["commit", "-q", "-m", "add CI gate and shadow module"],
    );
    assert!(
        Command::new(&gate)
            .current_dir(&root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "CI gate loaded a shadow standard-library module"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unlisted_private_key_algorithms_after_deletion() {
    let root = repository();
    let key = root.join("ordinary-build-record.bin");
    assert!(
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "DH",
                "-pkeyopt",
                "group:ffdhe2048",
                "-outform",
                "DER",
                "-out",
            ])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let key_bytes = fs::read(&key).unwrap();
    let mut embedded_key = b"ordinary build-record prefix\n".to_vec();
    embedded_key.extend(key_bytes);
    fs::write(&key, embedded_key).unwrap();
    git(&root, &["add", "ordinary-build-record.bin"]);
    git(&root, &["commit", "-q", "-m", "add DH private key"]);
    fs::remove_file(&key).unwrap();
    git(&root, &["add", "-u"]);
    git(&root, &["commit", "-q", "-m", "delete DH private key"]);
    assert!(!gate(&root).success(), "accepted historical DH PKCS#8 key");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_compressed_and_wrapped_modern_private_keys() {
    let root = repository();
    let key = root.join("x25519.der");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "X25519", "-outform", "DER", "-out"])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let mut wrapped = b"ordinary prefix\n".to_vec();
    wrapped.extend(fs::read(&key).unwrap());
    fs::write(&key, wrapped).unwrap();
    let compressed = root.join("release-notes.gz");
    let output = fs::File::create(&compressed).unwrap();
    assert!(
        Command::new("gzip")
            .args(["-c"])
            .arg(&key)
            .stdout(output)
            .status()
            .unwrap()
            .success()
    );
    fs::remove_file(&key).unwrap();
    git(&root, &["add", "release-notes.gz"]);
    git(&root, &["commit", "-q", "-m", "add compressed modern key"]);
    fs::remove_file(&compressed).unwrap();
    git(&root, &["add", "-u"]);
    git(
        &root,
        &["commit", "-q", "-m", "delete compressed modern key"],
    );

    assert!(!gate(&root).success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_whitespace_tolerant_pem_and_bzip2_private_keys() {
    let root = repository();
    let pem = root.join("release-notes.txt");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "X25519", "-out"])
            .arg(&pem)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let modified = String::from_utf8(fs::read(&pem).unwrap())
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("-----") {
                format!("{line} ")
            } else {
                format!(" {line} ")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&pem, modified).unwrap();
    assert!(
        Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(&pem)
            .arg("-noout")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "OpenSSL did not accept the whitespace-tolerant PEM fixture"
    );
    git(&root, &["add", "release-notes.txt"]);
    git(&root, &["commit", "-q", "-m", "add whitespace PEM key"]);
    fs::remove_file(&pem).unwrap();
    git(&root, &["add", "-u"]);
    git(&root, &["commit", "-q", "-m", "delete whitespace PEM key"]);
    assert!(
        !gate(&root).success(),
        "accepted whitespace-tolerant PEM key"
    );
    fs::remove_dir_all(root).unwrap();

    let root = repository();
    let key = root.join("x25519.der");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "X25519", "-outform", "DER", "-out"])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let compressed = root.join("release-notes.bin");
    assert!(
        Command::new("bzip2")
            .args(["-c"])
            .arg(&key)
            .stdout(fs::File::create(&compressed).unwrap())
            .status()
            .unwrap()
            .success()
    );
    fs::remove_file(key).unwrap();
    git(&root, &["add", "release-notes.bin"]);
    git(&root, &["commit", "-q", "-m", "add bzip2 private key"]);
    fs::remove_file(compressed).unwrap();
    git(&root, &["add", "-u"]);
    git(&root, &["commit", "-q", "-m", "delete bzip2 private key"]);
    assert!(
        !gate(&root).success(),
        "accepted BZip2 historical private key"
    );
    fs::remove_dir_all(root).unwrap();

    let root = repository();
    let encrypted = root.join("release-notes.txt");
    assert!(
        Command::new("openssl")
            .args([
                "genrsa",
                "-traditional",
                "-aes256",
                "-passout",
                "pass:review-fixture",
                "-out",
            ])
            .arg(&encrypted)
            .arg("2048")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let encrypted_content = fs::read_to_string(&encrypted).unwrap();
    assert!(encrypted_content.contains("Proc-Type: 4,ENCRYPTED"));
    assert!(encrypted_content.contains("DEK-Info:"));
    assert!(
        Command::new("openssl")
            .args(["rsa", "-in"])
            .arg(&encrypted)
            .args(["-passin", "pass:review-fixture", "-out", "/dev/null"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    git(&root, &["add", "release-notes.txt"]);
    git(
        &root,
        &["commit", "-q", "-m", "add traditional encrypted PEM"],
    );
    fs::remove_file(encrypted).unwrap();
    git(&root, &["add", "-u"]);
    git(
        &root,
        &["commit", "-q", "-m", "delete traditional encrypted PEM"],
    );
    assert!(
        !gate(&root).success(),
        "accepted traditional encrypted PEM private key"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_legacy_encrypted_pkcs8_openpgp_and_certificate_encodings() {
    let encrypted = encrypted_pkcs8_der();
    let base64_encrypted = base64_bytes(&encrypted);
    let prefixed_base64_encrypted = [b"AAA".as_slice(), base64_encrypted.as_slice()].concat();
    let suffixed_base64_encrypted = [base64_encrypted.as_slice(), b"AAA".as_slice()].concat();
    let long_suffixed_base64_encrypted =
        [base64_encrypted.as_slice(), b"AAAAAAAA".as_slice()].concat();
    let internal_padding_base64_encrypted =
        [b"AAAA=".as_slice(), base64_encrypted.as_slice()].concat();
    let mut fragmented_padding_base64_encrypted = Vec::new();
    for (index, chunk) in base64_encrypted.chunks(32).enumerate() {
        if index > 0 {
            fragmented_padding_base64_encrypted.push(b'=');
        }
        fragmented_padding_base64_encrypted.extend_from_slice(chunk);
    }
    let independently_padded_chunks = encrypted.chunks(23).map(base64_bytes).collect::<Vec<_>>();
    let independently_padded_base64_encrypted = independently_padded_chunks.join(&b'\n');
    let prefixed_independently_padded_base64_encrypted = independently_padded_chunks
        .iter()
        .map(|chunk| [b"A".as_slice(), chunk.as_slice()].concat())
        .collect::<Vec<_>>()
        .join(&b'\n');
    let suffixed_independently_padded_base64_encrypted = independently_padded_chunks
        .iter()
        .map(|chunk| [chunk.as_slice(), b"A".as_slice()].concat())
        .collect::<Vec<_>>()
        .join(&b'\n');
    let junk_fragmented_base64_encrypted = encrypted
        .chunks(23)
        .map(base64_bytes)
        .collect::<Vec<_>>()
        .join(b"AA==".as_slice());
    let variably_prefixed_independently_padded_base64_private = unencrypted_pkcs8_der()
        .chunks(23)
        .enumerate()
        .map(|(index, chunk)| {
            let prefix = if index % 2 == 0 {
                b"A".as_slice()
            } else {
                b"AA"
            };
            [prefix, base64_bytes(chunk).as_slice()].concat()
        })
        .collect::<Vec<_>>()
        .join(&b'\n');
    let variably_prefixed_unpadded_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            let prefix = if index % 2 == 0 {
                b"A".as_slice()
            } else {
                b"AA"
            };
            [prefix, base64_bytes(chunk).as_slice()].concat()
        })
        .collect::<Vec<_>>()
        .join(&b'\n');
    let checksum_separated_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .map(base64_bytes)
        .collect::<Vec<_>>()
        .join(b"\n=AAAA\n".as_slice());
    let assignment_wrapped_base64_private = unencrypted_pkcs8_der()
        .chunks(23)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "Key{index}={}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let punctuation_wrapped_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "chunk-{}:{}",
                index * 24,
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let differently_labeled_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            let label = if index % 2 == 0 { "x:" } else { "yy|" };
            format!("{label}{}", String::from_utf8_lossy(&base64_bytes(chunk)))
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let long_labeled_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "longlabel{index}:{}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let whitespace_labeled_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "longlabel{index} {}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let hash_labeled_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "longlabel{index}#{}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let hash_suffix_labeled_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "{}#longlabel{index}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let middle_labeled_base64_private = unencrypted_pkcs8_der()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "prefix{index:03}:{}:suffix{index:03}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let path_shaped_base64_private = {
        let mut encoded = base64_bytes(&unencrypted_pkcs8_der());
        while encoded.last() == Some(&b'=') {
            encoded.pop();
        }
        let path = encoded
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk))
            .collect::<Vec<_>>()
            .join("/");
        format!("{path}\n").into_bytes()
    };
    let irregular_path_base64_private = irregular_path_base64(&unencrypted_pkcs8_der());
    let arbitrary_short_path_base64_private = {
        let mut content = unencrypted_pkcs8_der();
        content.extend([0xff; 12]);
        arbitrary_short_path_base64(&content)
    };
    let long_prefixed_path_base64_private = {
        let mut content = vec![b'X'; 1_600];
        content.extend(unencrypted_pkcs8_der());
        content.extend([0xff; 12]);
        long_irregular_path_base64(&content)
    };
    let medium_prefixed_path_base64_private = {
        let mut content = vec![b'X'; 600];
        content.extend(unencrypted_pkcs8_der());
        content.extend([0xff; 12]);
        medium_irregular_path_base64(&content)
    };
    let ordered_multifield_base64_private = ordered_multifield_base64(&unencrypted_pkcs8_der());
    let variable_field_count_base64_private = variable_field_count_base64(&unencrypted_pkcs8_der());
    let over_limit_structured_base64_private =
        over_limit_structured_base64(&unencrypted_pkcs8_der());
    let ordered_over_limit_structured_base64_private =
        ordered_over_limit_structured_base64(&unencrypted_pkcs8_der());
    let openpgp_path_base64_private = {
        let mut content = vec![0xff; 48];
        content.extend(binary_openpgp_secret_key(5));
        arbitrary_short_path_base64(&content)
    };
    let mixed_path_base64_private = {
        let mut encoded = base64_bytes(&unencrypted_pkcs8_der());
        while encoded.last() == Some(&b'=') {
            encoded.pop();
        }
        let mut cursor = 0;
        let mut chunks = Vec::new();
        for width in [3, 5, 4].into_iter().cycle() {
            if cursor >= encoded.len() {
                break;
            }
            let end = (cursor + width).min(encoded.len());
            chunks.push(String::from_utf8_lossy(&encoded[cursor..end]));
            cursor = end;
        }
        format!("{}\n", chunks.join("/")).into_bytes()
    };
    let long_fragment_path_base64_private = {
        let mut encoded = base64_bytes(&unencrypted_pkcs8_der());
        while encoded.last() == Some(&b'=') {
            encoded.pop();
        }
        let mut chunks = encoded.chunks(4).map(Vec::from).collect::<Vec<_>>();
        let combined = [
            chunks[4].as_slice(),
            chunks[5].as_slice(),
            chunks[6].as_slice(),
        ]
        .concat();
        chunks.splice(4..7, [combined]);
        format!(
            "{}\n",
            chunks
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk))
                .collect::<Vec<_>>()
                .join("/")
        )
        .into_bytes()
    };
    let import_wrapped_base64_private = unencrypted_pkcs8_der()
        .chunks(6)
        .map(|chunk| format!("import A{}", String::from_utf8_lossy(&base64_bytes(chunk))))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let interleaved_assignment_base64_private = unencrypted_pkcs8_der()
        .chunks(6)
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|pair| {
            let name = base64_bytes(pair[0]);
            let value = pair
                .get(1)
                .map_or_else(Vec::new, |chunk| base64_bytes(chunk));
            format!(
                "A{}={}",
                String::from_utf8_lossy(&name),
                String::from_utf8_lossy(&value)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let irregular_base64_encrypted = base64_wrapped_at(&encrypted, 65);
    let ber_encrypted = ber_encrypted_pkcs8(&encrypted);
    let ber_nonminimal = ber_nonminimal_encrypted_pkcs8(&encrypted);
    let ber_indefinite_algorithm = ber_indefinite_algorithm_pkcs8(&encrypted);
    let ber_unencrypted = ber_unencrypted_pkcs8(&unencrypted_pkcs8_der());
    let ber_fragmented = ber_fragmented_encrypted_pkcs8(&encrypted);
    let mut trailing_zip = zip_bytes("safe.txt", b"safe\n");
    trailing_zip.extend(gzip_bytes(&private_key_fixture(b"secret")));
    let mut trailing_bzip2 = bzip2_bytes(b"safe\n");
    trailing_bzip2.extend(gzip_bytes(&private_key_fixture(b"secret")));
    let mut trailing_xz = xz_bytes(b"safe\n");
    trailing_xz.extend(gzip_bytes(&private_key_fixture(b"secret")));
    let mut embedded = b"ordinary build record\n".to_vec();
    embedded.extend(&encrypted);
    let mut prefixed_gzip = b"ordinary prefix\n".to_vec();
    prefixed_gzip.extend(gzip_bytes(&private_key_fixture(b"secret")));
    let rsa_pss_certificate = rsa_pss_certificate_der();
    let mut base64_certificate = b"QQ==\n".to_vec();
    base64_certificate.extend(base64_wrapped_bytes(&rsa_pss_certificate));
    let irregular_base64_certificate = base64_wrapped_at(&rsa_pss_certificate, 65);
    let prefixed_base64_certificate = [
        b"AAA".as_slice(),
        base64_wrapped_bytes(&rsa_pss_certificate).as_slice(),
    ]
    .concat();
    let mut cumulative_zstd_blocks = b"ordinary prefix\n".to_vec();
    cumulative_zstd_blocks.extend(zstd_many_empty_blocks(32_769));
    cumulative_zstd_blocks.extend(zstd_many_empty_blocks(32_769));
    for prefix in [b"A".as_slice(), b"AA".as_slice(), b"AAA".as_slice()] {
        let mut content = prefix.to_vec();
        content.extend(&base64_encrypted);
        historical_blob_is_rejected(
            &format!("base64-private-key-prefix-{}.txt", prefix.len()),
            &content,
        );
    }
    for suffix in [b"A".as_slice(), b"AA".as_slice(), b"AAA".as_slice()] {
        let mut content = base64_encrypted.clone();
        content.extend(suffix);
        historical_blob_is_rejected(
            &format!("base64-private-key-suffix-{}.txt", suffix.len()),
            &content,
        );
    }
    historical_blob_is_rejected(
        "base64-private-key-long-suffix.txt",
        &long_suffixed_base64_encrypted,
    );
    historical_blob_is_rejected(
        "base64-private-key-internal-padding.txt",
        &internal_padding_base64_encrypted,
    );
    historical_blob_is_rejected(
        "base64-private-key-fragmented-padding.txt",
        &fragmented_padding_base64_encrypted,
    );
    historical_blob_is_rejected(
        "base64-private-key-independent-padding.txt",
        &independently_padded_base64_encrypted,
    );
    historical_blob_is_rejected(
        "base64-private-key-prefixed-independent-padding.txt",
        &prefixed_independently_padded_base64_encrypted,
    );
    historical_blob_is_rejected(
        "base64-private-key-suffixed-independent-padding.txt",
        &suffixed_independently_padded_base64_encrypted,
    );
    historical_blob_is_rejected(
        "base64-private-key-junk-fragment.txt",
        &junk_fragmented_base64_encrypted,
    );
    historical_blob_is_rejected(
        "base64-private-key-variable-independent-padding.txt",
        &variably_prefixed_independently_padded_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-variable-unpadded.txt",
        &variably_prefixed_unpadded_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-checksum-separators.txt",
        &checksum_separated_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-assignments.txt",
        &assignment_wrapped_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-punctuation-fields.txt",
        &punctuation_wrapped_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-different-labels.txt",
        &differently_labeled_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-long-labels.txt",
        &long_labeled_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-whitespace-labels.txt",
        &whitespace_labeled_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-hash-labels.txt",
        &hash_labeled_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-hash-suffix-labels.txt",
        &hash_suffix_labeled_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-middle-labels.txt",
        &middle_labeled_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-path-shaped.txt",
        &path_shaped_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-irregular-path.txt",
        &irregular_path_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-arbitrary-short-path.txt",
        &arbitrary_short_path_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-long-prefixed-path.txt",
        &long_prefixed_path_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-medium-prefixed-path.txt",
        &medium_prefixed_path_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-ordered-multifield.txt",
        &ordered_multifield_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-variable-field-count.txt",
        &variable_field_count_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-over-limit-structured-fields.txt",
        &over_limit_structured_base64_private,
    );
    assert!(assert_scanner_parity(
        "base64-private-key-ordered-over-limit-fields.txt",
        &ordered_over_limit_structured_base64_private,
    ));
    historical_blob_is_rejected(
        "base64-private-key-ordered-over-limit-fields.txt",
        &ordered_over_limit_structured_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-openpgp-irregular-path.txt",
        &openpgp_path_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-mixed-path.txt",
        &mixed_path_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-long-fragment-path.txt",
        &long_fragment_path_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-import-fields.txt",
        &import_wrapped_base64_private,
    );
    historical_blob_is_rejected(
        "base64-private-key-interleaved-assignments.txt",
        &interleaved_assignment_base64_private,
    );
    for (name, content) in [
        ("encrypted-key.bin", encrypted),
        ("ber-encrypted-key.bin", ber_encrypted.clone()),
        ("ber-nonminimal-key.bin", ber_nonminimal),
        ("ber-indefinite-algorithm-key.bin", ber_indefinite_algorithm),
        ("ber-unencrypted-key.bin", ber_unencrypted),
        ("ber-fragmented-key.bin", ber_fragmented),
        ("compressed-ber-key.bin", gzip_bytes(&ber_encrypted)),
        ("embedded-key.bin", embedded.clone()),
        ("compressed-key.bin", gzip_bytes(&embedded)),
        ("secret-key-export.bin", binary_openpgp_secret_key(5)),
        ("secret-subkey-export.bin", binary_openpgp_secret_key(7)),
        ("legacy-certificate.txt", legacy_x509_certificate_pem()),
        ("rsa-pss-certificate.der", rsa_pss_certificate),
        ("base64-private-key.txt", base64_encrypted),
        ("prefixed-base64-private-key.txt", prefixed_base64_encrypted),
        ("suffixed-base64-private-key.txt", suffixed_base64_encrypted),
        (
            "long-suffixed-base64-private-key.txt",
            long_suffixed_base64_encrypted,
        ),
        (
            "internal-padding-base64-private-key.txt",
            internal_padding_base64_encrypted,
        ),
        (
            "fragmented-padding-base64-private-key.txt",
            fragmented_padding_base64_encrypted,
        ),
        (
            "independently-padded-base64-private-key.txt",
            independently_padded_base64_encrypted,
        ),
        (
            "prefixed-independently-padded-base64-private-key.txt",
            prefixed_independently_padded_base64_encrypted,
        ),
        (
            "suffixed-independently-padded-base64-private-key.txt",
            suffixed_independently_padded_base64_encrypted,
        ),
        (
            "junk-fragmented-base64-private-key.txt",
            junk_fragmented_base64_encrypted,
        ),
        (
            "variably-prefixed-independently-padded-base64-private-key.txt",
            variably_prefixed_independently_padded_base64_private,
        ),
        (
            "variably-prefixed-unpadded-base64-private-key.txt",
            variably_prefixed_unpadded_base64_private,
        ),
        (
            "checksum-separated-base64-private-key.txt",
            checksum_separated_base64_private,
        ),
        (
            "assignment-wrapped-base64-private-key.txt",
            assignment_wrapped_base64_private,
        ),
        (
            "punctuation-wrapped-base64-private-key.txt",
            punctuation_wrapped_base64_private,
        ),
        (
            "import-wrapped-base64-private-key.txt",
            import_wrapped_base64_private,
        ),
        (
            "interleaved-assignment-base64-private-key.txt",
            interleaved_assignment_base64_private,
        ),
        ("base64-certificate.txt", base64_certificate),
        (
            "prefixed-base64-certificate.txt",
            prefixed_base64_certificate,
        ),
        (
            "irregular-base64-private-key.txt",
            irregular_base64_encrypted,
        ),
        (
            "irregular-base64-certificate.txt",
            irregular_base64_certificate,
        ),
        ("certificate-bundle.bin", pkcs7_certificate_pem()),
        ("prefixed-gzip.bin", prefixed_gzip),
        ("zstd-block-bomb.bin", zstd_block_bomb()),
        ("cumulative-zstd-blocks.bin", cumulative_zstd_blocks),
        (
            "neutral-container.bin",
            v7_tar_with_compressed_private_key(),
        ),
        (
            "trailing-container.bin",
            tar_with_trailing_compressed_private_key(),
        ),
        ("trailing-zip.bin", trailing_zip),
        ("trailing-bzip2.bin", trailing_bzip2),
        ("trailing-xz.bin", trailing_xz),
        ("gnu-extension.tar", gnu_tar_with_longname()),
        ("tar-padding.bin", tar_with_sensitive_padding()),
    ] {
        historical_blob_is_rejected(name, &content);
    }
}

#[test]
fn rejects_archives_that_exceed_the_shared_zstd_process_budget() {
    historical_blob_is_rejected("many-zstd-members.zip", &zip_many_zstd_members(65));
}

#[test]
fn rejects_prefixed_zstd_and_self_extracting_zip_containers() {
    let key = encrypted_pkcs8_der();
    let mut skippable_zstd = [
        b"\x50\x2a\x4d\x18".as_slice(),
        (15_u32.to_le_bytes()).as_slice(),
        b"ordinary-prefix",
    ]
    .concat();
    skippable_zstd.extend(zstd_bytes(&key));
    historical_blob_is_rejected("prefixed-zstd.bin", &skippable_zstd);

    let mut hidden_zstd = zstd_bytes(b"safe\n");
    hidden_zstd.extend(zstd_skippable_frame(&gzip_bytes(&private_key_fixture(
        b"secret",
    ))));
    historical_blob_is_rejected("hidden-zstd-frame.bin", &hidden_zstd);

    let mut self_extracting_zip = b"ordinary executable stub\n".to_vec();
    self_extracting_zip.extend(zip_bytes("private-key.bin", &key));
    historical_blob_is_rejected("self-extracting.bin", &self_extracting_zip);

    let commented_zip = zip_with_comment(
        "safe.txt",
        b"safe\n",
        &gzip_bytes(&private_key_fixture(b"secret")),
    );
    historical_blob_is_rejected("commented.zip", &commented_zip);
}

#[test]
fn rejects_noncanonical_trust_store_paths_in_nested_archives() {
    let archive = zip_bytes("etc//ssl/certs/store.conf", b"ordinary trust policy\n");
    historical_blob_is_rejected("nested-trust-store.gz", &gzip_bytes(&archive));
}

#[test]
fn sensitive_scanners_remain_in_parity_for_shared_policy_corpus() {
    let private_pem = private_key_fixture(b"c2VjcmV0");
    let age_secret = age_secret_fixture();
    let ambiguous = format!("{}AAAA\n", "QUFB/".repeat(18)).into_bytes();
    for (name, content) in [
        ("safe", b"ordinary build evidence\n".to_vec()),
        ("private-pem", private_pem.clone()),
        ("base64-private", base64_bytes(&private_pem)),
        ("compressed-private", gzip_bytes(&private_pem)),
        ("age-secret", age_secret.clone()),
        ("base64-age-secret", base64_bytes(&age_secret)),
        ("ambiguous-path-base64", ambiguous),
    ] {
        assert_scanner_parity(name, &content);
    }
}

#[test]
fn accepts_whitespace_separated_absolute_tool_paths() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let content = fs::read(workspace.join("packaging/kernel/build-candidate")).unwrap();
    assert!(
        !assert_scanner_parity("build-candidate-tool-paths", &content),
        "rejected the checked-in build script as ambiguous base64"
    );
}

#[test]
fn rejects_sensitive_base64_disguised_as_an_absolute_path() {
    let mut disguised = vec![b'/'];
    disguised.extend(irregular_path_base64(&unencrypted_pkcs8_der()));
    assert!(
        assert_scanner_parity("path-shaped-base64", &disguised),
        "both scanners accepted path-shaped base64 private material"
    );
    historical_blob_is_rejected("path-shaped-base64.txt", &disguised);
}

#[test]
fn rejects_age_secret_identities_in_history_and_output_trees() {
    let age_secret = age_secret_fixture();
    historical_blob_is_rejected("release-notes.txt", &age_secret);
    historical_blob_is_rejected("encoded-release-notes.txt", &base64_bytes(&age_secret));

    let tree = temporary_fixture("age-secret-output-tree");
    fs::write(tree.join("build.log"), &age_secret).unwrap();
    let output = tree_gate(&tree, &[]);
    assert!(
        !output.status.success(),
        "accepted an age secret identity in the output tree"
    );
    fs::remove_dir_all(tree).unwrap();
}

fn assert_scanner_parity(name: &str, content: &[u8]) -> bool {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let root = temporary_fixture("scanner-parity");
    let input = root.join("input.bin");
    fs::write(&input, content).unwrap();
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
import tempfile
def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module
history = load("history_scanner", sys.argv[1])
provenance = load("provenance_scanner", sys.argv[2])
content = pathlib.Path(sys.argv[3]).read_bytes()
history_rejects = history.sensitive(content)
with tempfile.TemporaryDirectory() as temporary:
    try:
        provenance.reject_sensitive_blob(content, "parity fixture", pathlib.Path(temporary))
        provenance_rejects = False
    except provenance.VerificationError:
        provenance_rejects = True
print(f"{int(history_rejects)} {int(provenance_rejects)}")
"#;
    let output = Command::new("python3")
        .args(["-I", "-c", source])
        .arg(workspace.join("scripts/check-sensitive-history"))
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(&input)
        .output()
        .unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(output.status.success(), "parity harness failed for {name}");
    let verdict = String::from_utf8(output.stdout).unwrap();
    let verdict = verdict.trim();
    assert!(
        verdict == "0 0" || verdict == "1 1",
        "sensitive scanners disagreed for shared-policy fixture {name}: {verdict}"
    );
    verdict == "1 1"
}

fn historical_blob_is_rejected(name: &str, content: &[u8]) {
    let root = repository();
    fs::write(root.join(name), content).unwrap();
    git(&root, &["add", name]);
    git(&root, &["commit", "-q", "-m", "add sensitive fixture"]);
    fs::remove_file(root.join(name)).unwrap();
    git(&root, &["add", "-u"]);
    git(&root, &["commit", "-q", "-m", "delete sensitive fixture"]);
    let output = gate_command(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success(), "accepted historical {name}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("sensitive historical blob"),
        "history gate rejected {name} for the wrong reason: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

fn encrypted_pkcs8_der() -> Vec<u8> {
    let root = temporary_fixture("encrypted-pkcs8");
    let key = root.join("key.pem");
    let encrypted = root.join("encrypted.der");
    assert!(
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["pkcs8", "-topk8", "-in"])
            .arg(&key)
            .args([
                "-outform",
                "DER",
                "-v1",
                "PBE-SHA1-3DES",
                "-passout",
                "pass:review-fixture",
                "-out",
            ])
            .arg(&encrypted)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["pkcs8", "-inform", "DER", "-in"])
            .arg(&encrypted)
            .args(["-passin", "pass:review-fixture", "-out", "/dev/null"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(encrypted).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn unencrypted_pkcs8_der() -> Vec<u8> {
    let root = temporary_fixture("unencrypted-pkcs8");
    let key = root.join("private.der");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "X25519", "-outform", "DER", "-out"])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(key).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn ber_encrypted_pkcs8(der: &[u8]) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    let header = if der[1] < 0x80 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    };
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[header..]);
    ber.extend_from_slice(&[0, 0]);

    let root = temporary_fixture("ber-encrypted-pkcs8");
    let path = root.join("encrypted.ber");
    fs::write(&path, &ber).unwrap();
    assert!(
        Command::new("openssl")
            .args(["pkcs8", "-inform", "DER", "-in"])
            .arg(&path)
            .args(["-passin", "pass:review-fixture", "-out", "/dev/null"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "OpenSSL did not accept the BER encrypted PKCS#8 fixture"
    );
    fs::remove_dir_all(root).unwrap();
    ber
}

fn ber_nonminimal_encrypted_pkcs8(der: &[u8]) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    let length_octets = usize::from(der[1] & 0x7f);
    assert!(der[1] > 0x80 && length_octets < 126);
    let mut ber = vec![0x30, 0x80 | ((length_octets + 1) as u8), 0];
    ber.extend_from_slice(&der[2..]);
    ber
}

fn ber_indefinite_algorithm_pkcs8(der: &[u8]) -> Vec<u8> {
    let outer_header = der_header_len(der);
    let algorithm = &der[outer_header..];
    assert_eq!(algorithm[0], 0x30);
    let algorithm_header = der_header_len(algorithm);
    let algorithm_length = der_value_len(algorithm);
    let algorithm_end = algorithm_header + algorithm_length;
    let mut value = vec![0x30, 0x80];
    value.extend_from_slice(&algorithm[algorithm_header..algorithm_end]);
    value.extend_from_slice(&[0, 0]);
    value.extend_from_slice(&algorithm[algorithm_end..]);
    let mut ber = vec![0x30];
    ber.extend(der_length(value.len()));
    ber.extend(value);
    ber
}

fn ber_unencrypted_pkcs8(der: &[u8]) -> Vec<u8> {
    let outer_header = der_header_len(der);
    let value = &der[outer_header..];
    let version_end = der_header_len(value) + der_value_len(value);
    let algorithm = &value[version_end..];
    let algorithm_header = der_header_len(algorithm);
    let algorithm_end = algorithm_header + der_value_len(algorithm);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&value[..version_end]);
    ber.extend_from_slice(&[0x30, 0x80]);
    ber.extend_from_slice(&algorithm[algorithm_header..algorithm_end]);
    ber.extend_from_slice(&[0, 0]);
    ber.extend_from_slice(&algorithm[algorithm_end..]);
    ber.extend_from_slice(&[0, 0]);
    assert_openssl_accepts_pkey(&ber);
    ber
}

fn ber_fragmented_encrypted_pkcs8(der: &[u8]) -> Vec<u8> {
    let outer_header = der_header_len(der);
    let value = &der[outer_header..];
    let algorithm_end = der_header_len(value) + der_value_len(value);
    let encrypted = &value[algorithm_end..];
    let encrypted_header = der_header_len(encrypted);
    let encrypted_end = encrypted_header + der_value_len(encrypted);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&value[..algorithm_end]);
    ber.extend_from_slice(&[0x24, 0x80]);
    for _ in 0..4097 {
        ber.extend_from_slice(&[0x04, 0x00]);
    }
    ber.push(0x04);
    ber.extend(der_length(encrypted_end - encrypted_header));
    ber.extend_from_slice(&encrypted[encrypted_header..encrypted_end]);
    ber.extend_from_slice(&[0, 0, 0, 0]);
    ber
}

fn assert_openssl_accepts_pkey(content: &[u8]) {
    let root = temporary_fixture("ber-private-key");
    let path = root.join("private.ber");
    fs::write(&path, content).unwrap();
    assert!(
        Command::new("openssl")
            .args(["pkey", "-inform", "DER", "-in"])
            .arg(&path)
            .arg("-noout")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "OpenSSL did not accept the BER private-key fixture"
    );
    fs::remove_dir_all(root).unwrap();
}

fn der_header_len(content: &[u8]) -> usize {
    if content[1] < 0x80 {
        2
    } else {
        2 + usize::from(content[1] & 0x7f)
    }
}

fn der_value_len(content: &[u8]) -> usize {
    if content[1] < 0x80 {
        usize::from(content[1])
    } else {
        let octets = usize::from(content[1] & 0x7f);
        usize::from_be_bytes({
            let mut encoded = [0; size_of::<usize>()];
            encoded[size_of::<usize>() - octets..].copy_from_slice(&content[2..2 + octets]);
            encoded
        })
    }
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let encoded = length.to_be_bytes();
    let first = encoded.iter().position(|byte| *byte != 0).unwrap();
    let octets = &encoded[first..];
    let mut result = vec![0x80 | (octets.len() as u8)];
    result.extend_from_slice(octets);
    result
}

fn binary_openpgp_secret_key(tag: u8) -> Vec<u8> {
    let body = [4, 0, 0, 0, 0, 1, 0, 8, 0x81, 0, 2, 3, 0, 0, 1, 1, 0, 0];
    let mut packet = vec![0xC0 | tag, body.len() as u8];
    packet.extend(body);
    packet
}

fn legacy_x509_certificate_pem() -> Vec<u8> {
    let root = temporary_fixture("legacy-x509-certificate");
    let key = root.join("key.pem");
    let certificate = root.join("certificate.pem");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=legacy-certificate-fixture",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read_to_string(certificate)
        .unwrap()
        .replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE")
        .replace("END CERTIFICATE", "END X509 CERTIFICATE")
        .into_bytes();
    fs::remove_dir_all(root).unwrap();
    content
}

fn pkcs7_certificate_pem() -> Vec<u8> {
    let root = temporary_fixture("pkcs7-certificate");
    let key = root.join("key.pem");
    let certificate = root.join("certificate.pem");
    let bundle = root.join("bundle.pem");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=pkcs7-certificate-fixture",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["crl2pkcs7", "-nocrl", "-certfile"])
            .arg(&certificate)
            .arg("-out")
            .arg(&bundle)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(bundle).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn rsa_pss_certificate_der() -> Vec<u8> {
    let root = temporary_fixture("rsa-pss-certificate");
    let key = root.join("key.pem");
    let certificate = root.join("certificate.der");
    assert!(
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA-PSS",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&key)
            .args(["-subj", "/CN=rsa-pss-certificate-fixture", "-days", "1"])
            .args(["-outform", "DER", "-out"])
            .arg(&certificate)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(certificate).unwrap();
    assert!(
        !content
            .windows(11)
            .any(|window| { window == b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" })
    );
    fs::remove_dir_all(root).unwrap();
    content
}

fn large_rsa_certificate_der() -> Vec<u8> {
    let root = temporary_fixture("large-rsa-certificate");
    let key = root.join("key.pem");
    let certificate = root.join("certificate.der");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-nodes",
                "-subj",
                "/CN=large-public-certificate-fixture",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&key)
            .args(["-outform", "DER", "-out"])
            .arg(&certificate)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(certificate).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn gzip_bytes(content: &[u8]) -> Vec<u8> {
    filtered_bytes("gzip", &["-c"], content)
}

fn base64_bytes(content: &[u8]) -> Vec<u8> {
    filtered_bytes("openssl", &["base64", "-A"], content)
}

fn irregular_path_base64(content: &[u8]) -> Vec<u8> {
    let mut encoded = base64_bytes(content);
    while encoded.last() == Some(&b'=') {
        encoded.pop();
    }
    let widths = [9, 11, 13, 10, 12];
    let mut output = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let end = (offset + widths[index % widths.len()]).min(encoded.len());
        if !output.is_empty() {
            output.push(b'/');
        }
        output.extend_from_slice(&encoded[offset..end]);
        offset = end;
        index += 1;
    }
    output.push(b'\n');
    output
}

fn long_irregular_path_base64(content: &[u8]) -> Vec<u8> {
    let encoded = base64_bytes(content);
    assert!(
        encoded.contains(&b'/'),
        "fixture needs a native Base64 slash"
    );
    let widths = [105, 109, 113, 107, 111];
    let mut output = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let end = (offset + widths[index % widths.len()]).min(encoded.len());
        if !output.is_empty() {
            output.push(b'/');
        }
        output.extend_from_slice(&encoded[offset..end]);
        offset = end;
        index += 1;
    }
    output.push(b'\n');
    output
}

fn medium_irregular_path_base64(content: &[u8]) -> Vec<u8> {
    let encoded = base64_bytes(content);
    assert!(
        encoded.contains(&b'/'),
        "fixture needs a native Base64 slash"
    );
    let widths = [14, 19, 23, 17, 29];
    let mut output = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let end = (offset + widths[index % widths.len()]).min(encoded.len());
        if !output.is_empty() {
            output.push(b'/');
        }
        output.extend_from_slice(&encoded[offset..end]);
        offset = end;
        index += 1;
    }
    output.push(b'\n');
    output
}

fn arbitrary_short_path_base64(content: &[u8]) -> Vec<u8> {
    let encoded = base64_bytes(content);
    assert!(
        encoded.contains(&b'/'),
        "fixture needs a native Base64 slash"
    );
    let widths = [5, 3, 2, 2, 2, 4];
    let mut output = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let end = (offset + widths[index % widths.len()]).min(encoded.len());
        if !output.is_empty() {
            output.push(b'/');
        }
        output.extend_from_slice(&encoded[offset..end]);
        offset = end;
        index += 1;
    }
    output.push(b'\n');
    output
}

fn ordered_multifield_base64(content: &[u8]) -> Vec<u8> {
    let mut padded = content.to_vec();
    padded.resize(content.len().next_multiple_of(12), 0);
    if !padded.len().div_ceil(12).is_multiple_of(2) {
        padded.resize(padded.len() + 12, 0);
    }
    padded
        .chunks(12)
        .collect::<Vec<_>>()
        .chunks(2)
        .enumerate()
        .map(|(index, pair)| {
            let left = base64_bytes(pair[0]);
            let right = pair
                .get(1)
                .map_or_else(Vec::new, |chunk| base64_bytes(chunk));
            format!(
                "left-{index:03}:{};right-{index:03}:{}",
                String::from_utf8_lossy(&left),
                String::from_utf8_lossy(&right)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn over_limit_structured_base64(content: &[u8]) -> Vec<u8> {
    content
        .chunks(12)
        .map(|chunk| {
            let mut fields = vec!["QUFBQUFB".to_string(); 65];
            fields[32] = String::from_utf8(base64_bytes(chunk)).unwrap();
            fields.join(":")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn ordered_over_limit_structured_base64(content: &[u8]) -> Vec<u8> {
    let mut padded = vec![b'X'; 32 * 1024];
    padded.extend_from_slice(content);
    base64_bytes(&padded)
        .chunks(8)
        .map(|chunk| String::from_utf8_lossy(chunk))
        .collect::<Vec<_>>()
        .join(":")
        .into_bytes()
}

fn variable_field_count_base64(content: &[u8]) -> Vec<u8> {
    base64_bytes(content)
        .chunks(32)
        .enumerate()
        .map(|(index, chunk)| {
            let labels = if index.is_multiple_of(2) {
                "HarmlessLabelA"
            } else {
                "HarmlessLabelA HarmlessLabelB"
            };
            format!("{labels} {}", String::from_utf8_lossy(chunk))
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn base64_wrapped_bytes(content: &[u8]) -> Vec<u8> {
    filtered_bytes("openssl", &["base64"], content)
}

fn base64_wrapped_at(content: &[u8], width: usize) -> Vec<u8> {
    let encoded = base64_bytes(content);
    encoded
        .chunks(width)
        .flat_map(|chunk| chunk.iter().copied().chain(std::iter::once(b'\n')))
        .collect()
}

fn bzip2_bytes(content: &[u8]) -> Vec<u8> {
    filtered_bytes("bzip2", &["-c"], content)
}

fn xz_bytes(content: &[u8]) -> Vec<u8> {
    filtered_bytes("xz", &["-c"], content)
}

fn zstd_bytes(content: &[u8]) -> Vec<u8> {
    filtered_bytes("zstd", &["-q", "-c"], content)
}

fn zstd_skippable_frame(content: &[u8]) -> Vec<u8> {
    let mut frame = b"\x50\x2a\x4d\x18".to_vec();
    frame.extend(u32::try_from(content.len()).unwrap().to_le_bytes());
    frame.extend(content);
    frame
}

fn zstd_block_bomb() -> Vec<u8> {
    let mut frame = b"\x28\xb5\x2f\xfd\x20\x00".to_vec();
    frame.extend([0, 0, 0].repeat(65_537));
    frame.extend([1, 0, 0]);
    frame
}

fn zstd_many_empty_blocks(blocks: usize) -> Vec<u8> {
    assert!(blocks > 0);
    let mut frame = b"\x28\xb5\x2f\xfd\x20\x00".to_vec();
    frame.extend([0, 0, 0].repeat(blocks - 1));
    frame.extend([1, 0, 0]);
    frame
}

fn filtered_bytes(tool: &str, args: &[&str], content: &[u8]) -> Vec<u8> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(content).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    output.stdout
}

fn zip_bytes(name: &str, content: &[u8]) -> Vec<u8> {
    let root = temporary_fixture("zip-container");
    let member = root.join("payload.bin");
    let archive = root.join("archive.zip");
    fs::write(&member, content).unwrap();
    assert!(
        Command::new("python3")
            .arg("-c")
            .arg("import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED); z.write(sys.argv[2],sys.argv[3]); z.close()")
            .arg(&archive)
            .arg(&member)
            .arg(name)
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(archive).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn tar_bytes(name: &str, content: &[u8]) -> Vec<u8> {
    let root = temporary_fixture("tar-container");
    let member = root.join("payload.bin");
    let archive = root.join("archive.tar");
    fs::write(&member, content).unwrap();
    assert!(
        Command::new("python3")
            .arg("-c")
            .arg("import io,sys,tarfile; data=open(sys.argv[2],'rb').read(); t=tarfile.open(sys.argv[1],'w'); i=tarfile.TarInfo(sys.argv[3]); i.size=len(data); i.mode=0o644; t.addfile(i,io.BytesIO(data)); t.close()")
            .arg(&archive)
            .arg(&member)
            .arg(name)
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(archive).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn zip_directory_payload(content: &[u8]) -> Vec<u8> {
    let root = temporary_fixture("zip-directory-payload");
    let payload = root.join("payload.bin");
    let archive = root.join("archive.zip");
    fs::write(&payload, content).unwrap();
    let status = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg("import sys,zipfile; data=open(sys.argv[2],'rb').read(); z=zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED); z.writestr('private-material/',data); z.close()")
        .arg(&archive)
        .arg(&payload)
        .status()
        .unwrap();
    assert!(status.success());
    let content = fs::read(archive).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn zip_directory_entry_bytes() -> Vec<u8> {
    let root = temporary_fixture("zip-directory-entry");
    let archive = root.join("archive.zip");
    let status = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg("import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_STORED); z.writestr('docs/',b''); z.writestr('docs/safe.txt',b'safe'); z.close()")
        .arg(&archive)
        .status()
        .unwrap();
    assert!(status.success());
    let content = fs::read(archive).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn cpio_newc(name: &str, content: &[u8]) -> Vec<u8> {
    fn append_entry(archive: &mut Vec<u8>, name: &str, mode: u32, content: &[u8]) {
        let namesize = name.len() + 1;
        archive.extend_from_slice(
            format!(
                "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{size:08x}{devmajor:08x}{devminor:08x}{rdevmajor:08x}{rdevminor:08x}{namesize:08x}{check:08x}",
                ino = 1,
                uid = 0,
                gid = 0,
                nlink = 1,
                mtime = 0,
                size = content.len(),
                devmajor = 0,
                devminor = 0,
                rdevmajor = 0,
                rdevminor = 0,
                check = 0,
            )
            .as_bytes(),
        );
        archive.extend_from_slice(name.as_bytes());
        archive.push(0);
        archive.resize((archive.len() + 3) & !3, 0);
        archive.extend_from_slice(content);
        archive.resize((archive.len() + 3) & !3, 0);
    }

    let mut archive = Vec::new();
    append_entry(&mut archive, name, 0o100644, content);
    append_entry(&mut archive, "TRAILER!!!", 0, &[]);
    archive
}

fn overlapping_ber_sequences() -> Vec<u8> {
    let mut content = vec![0_u8; 1024 * 1024];
    for offset in (0..640 * 1024).step_by(4096) {
        let length = content.len() - offset - 5;
        content[offset] = 0x30;
        content[offset + 1] = 0x83;
        content[offset + 2] = ((length >> 16) & 0xff) as u8;
        content[offset + 3] = ((length >> 8) & 0xff) as u8;
        content[offset + 4] = (length & 0xff) as u8;
    }
    let rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    let oid_offset = content.len() - rsa_oid.len();
    content[oid_offset..].copy_from_slice(rsa_oid);
    content
}

fn zip_many_zstd_members(count: usize) -> Vec<u8> {
    let root = temporary_fixture("many-zstd-members");
    let member = root.join("member.zst");
    let archive = root.join("archive.zip");
    fs::write(&member, zstd_bytes(b"safe\n")).unwrap();
    assert!(
        Command::new("python3")
            .arg("-c")
            .arg("import sys,zipfile; data=open(sys.argv[2],'rb').read(); z=zipfile.ZipFile(sys.argv[1],'w'); [z.writestr(f'member-{i}.zst',data) for i in range(int(sys.argv[3]))]; z.close()")
            .arg(&archive)
            .arg(&member)
            .arg(count.to_string())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(archive).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn zip_with_comment(name: &str, content: &[u8], comment: &[u8]) -> Vec<u8> {
    let mut archive = zip_bytes(name, content);
    let eocd = archive.len() - 22;
    assert_eq!(&archive[eocd..eocd + 4], b"PK\x05\x06");
    archive[eocd + 20..eocd + 22]
        .copy_from_slice(&u16::try_from(comment.len()).unwrap().to_le_bytes());
    archive.extend(comment);
    archive
}

fn v7_tar_with_compressed_private_key() -> Vec<u8> {
    let root = temporary_fixture("v7-tar-container");
    let member = root.join("private-key.pem.gz");
    let archive = root.join("neutral-container.bin");
    fs::write(
        &member,
        gzip_bytes(
            &[
                b"-----BEGIN PRI".as_slice(),
                b"VATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n".as_slice(),
            ]
            .concat(),
        ),
    )
    .unwrap();
    assert!(
        Command::new("tar")
            .args(["--format=v7", "-cf"])
            .arg(&archive)
            .arg("-C")
            .arg(&root)
            .arg("private-key.pem.gz")
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(archive).unwrap();
    assert_ne!(&content[257..262], b"ustar");
    fs::remove_dir_all(root).unwrap();
    content
}

fn gnu_tar_with_longname() -> Vec<u8> {
    let root = temporary_fixture("gnu-longname-container");
    let long_name = format!("{}.txt", "a".repeat(140));
    fs::write(root.join(&long_name), b"safe\n").unwrap();
    let archive = root.join("longname.tar");
    assert!(
        Command::new("tar")
            .args(["--format=gnu", "-cf"])
            .arg(&archive)
            .arg("-C")
            .arg(&root)
            .arg(&long_name)
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(archive).unwrap();
    assert!(content.chunks_exact(512).any(|header| header[156] == b'L'));
    fs::remove_dir_all(root).unwrap();
    content
}

fn tar_with_sensitive_padding() -> Vec<u8> {
    let root = temporary_fixture("tar-padding-container");
    let member = root.join("safe.txt");
    let archive = root.join("padding.tar");
    fs::write(&member, b"safe\n").unwrap();
    assert!(
        Command::new("tar")
            .args(["--format=v7", "-cf"])
            .arg(&archive)
            .arg("-C")
            .arg(&root)
            .arg("safe.txt")
            .status()
            .unwrap()
            .success()
    );
    let mut content = fs::read(archive).unwrap();
    let hidden = gzip_bytes(&private_key_fixture(b"secret"));
    assert!(hidden.len() <= 507);
    content[517..517 + hidden.len()].copy_from_slice(&hidden);
    fs::remove_dir_all(root).unwrap();
    content
}

fn tar_with_trailing_compressed_private_key() -> Vec<u8> {
    let root = temporary_fixture("tar-trailing-container");
    let member = root.join("safe.txt");
    let archive = root.join("neutral-container.bin");
    fs::write(&member, b"safe source\n").unwrap();
    assert!(
        Command::new("tar")
            .args(["--format=v7", "-cf"])
            .arg(&archive)
            .arg("-C")
            .arg(&root)
            .arg("safe.txt")
            .status()
            .unwrap()
            .success()
    );
    let mut content = fs::read(archive).unwrap();
    content.extend(gzip_bytes(
        &[
            b"-----BEGIN PRI".as_slice(),
            b"VATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n".as_slice(),
        ]
        .concat(),
    ));
    fs::remove_dir_all(root).unwrap();
    content
}

fn temporary_fixture(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "fan-control-{label}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    root
}
