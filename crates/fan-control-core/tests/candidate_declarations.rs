use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const RELEASE: &str = "7.1.8-cachyos-pt31553";
const SOURCE_COMMIT: &str = "7a84732fd5e4350c1312fd0ed0c72ffa139fb766";

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repeated(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn write_executable(path: &Path, source: &str) {
    fs::write(path, source).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn module(
    name: &str,
    path: &str,
    provenance: &str,
    package: &str,
    source: serde_json::Value,
    hash_character: char,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "path": path,
        "sha256": repeated(hash_character),
        "signer_fingerprint": repeated('b'),
        "vermagic": format!("{RELEASE} SMP preempt mod_unload"),
        "provenance": provenance,
        "package": package,
        "source": source,
    })
}

fn provenance() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "candidate": "linux-cachyos-pt31553-7.1.8-1-package-set",
        "build": {
            "source_commit": SOURCE_COMMIT,
            "source_lock_sha256": repeated('1'),
            "build_environment_sha256": repeated('2'),
            "build_attestation_sha256": repeated('3'),
            "pkgbuild_sha256": repeated('4'),
            "package_set_srcinfo_sha256": repeated('5'),
            "package_manifest_signature_sha256": format!("{:x}", Sha256::digest(b"package manifest signature bytes")),
            "package_manifest_signer_fingerprint": repeated('a'),
        },
        "kernel": {
            "release": RELEASE,
            "package": "linux-cachyos-pt31553",
            "image_path": format!("/usr/lib/modules/{RELEASE}/vmlinuz"),
            "image_sha256": repeated('6'),
            "image_signer_fingerprint": repeated('c'),
            "config_path": format!("/usr/lib/modules/{RELEASE}/build/.config"),
            "config_sha256": repeated('7'),
            "module_trust_certificate_path": format!("/usr/lib/modules/{RELEASE}/build/certs/signing_key.x509"),
            "module_trust_certificate_fingerprint": repeated('b'),
        },
        "modules": [
            module(
                "acer_wmi",
                &format!("/usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
                "in-tree",
                "linux-cachyos-pt31553",
                serde_json::json!({"kind": "kernel-tree", "revision": SOURCE_COMMIT}),
                '8',
            ),
            module(
                "nvidia",
                &format!("/usr/lib/modules/{RELEASE}/extramodules/nvidia.ko.zst"),
                "nvidia-open",
                "linux-cachyos-pt31553-nvidia-open",
                serde_json::json!({"kind": "nvidia-open", "revision": "610.57.04"}),
                '9',
            ),
            module(
                "nvidia_drm",
                &format!("/usr/lib/modules/{RELEASE}/extramodules/nvidia-drm.ko.zst"),
                "nvidia-open",
                "linux-cachyos-pt31553-nvidia-open",
                serde_json::json!({"kind": "nvidia-open", "revision": "610.57.04"}),
                'd',
            ),
            module(
                "nvidia_modeset",
                &format!("/usr/lib/modules/{RELEASE}/extramodules/nvidia-modeset.ko.zst"),
                "nvidia-open",
                "linux-cachyos-pt31553-nvidia-open",
                serde_json::json!({"kind": "nvidia-open", "revision": "610.57.04"}),
                'e',
            ),
            module(
                "nvidia_peermem",
                &format!("/usr/lib/modules/{RELEASE}/extramodules/nvidia-peermem.ko.zst"),
                "nvidia-open",
                "linux-cachyos-pt31553-nvidia-open",
                serde_json::json!({"kind": "nvidia-open", "revision": "610.57.04"}),
                '1',
            ),
            module(
                "nvidia_uvm",
                &format!("/usr/lib/modules/{RELEASE}/extramodules/nvidia-uvm.ko.zst"),
                "nvidia-open",
                "linux-cachyos-pt31553-nvidia-open",
                serde_json::json!({"kind": "nvidia-open", "revision": "610.57.04"}),
                '2',
            ),
        ],
        "packages": [
            {"name": "linux-cachyos-pt31553", "version": "7.1.8-1", "architecture": "x86_64", "sha256": repeated('3')},
            {"name": "linux-cachyos-pt31553-headers", "version": "7.1.8-1", "architecture": "x86_64", "sha256": repeated('4')},
            {"name": "linux-cachyos-pt31553-nvidia-open", "version": "7.1.8-1", "architecture": "x86_64", "sha256": repeated('5')},
        ],
    })
}

struct Fixture {
    root: TempDir,
    provenance: PathBuf,
    compatibility: PathBuf,
    manifest: PathBuf,
    controller_package: PathBuf,
    controller_signature: PathBuf,
    package_manifest_signature: PathBuf,
    harness: PathBuf,
    tools: PathBuf,
}

impl Fixture {
    fn new(value: &serde_json::Value) -> Self {
        let root = tempfile::Builder::new()
            .prefix("pt31553-candidate-declarations-")
            .tempdir()
            .unwrap();
        let provenance = root.path().join("package-provenance-v1.json");
        let compatibility = root.path().join("compatibility.toml");
        let manifest = root.path().join("candidate-identity-v1.json");
        let controller_package = root.path().join("controller.pkg.tar.zst");
        let controller_signature = root.path().join("controller.pkg.tar.zst.sig");
        let package_manifest_signature = root.path().join("package-set.p7s");
        let harness = root.path().join("generate-candidate-declarations-harness");
        let tools = root.path().join("tools");
        fs::create_dir(&tools).unwrap();
        fs::write(&provenance, serde_json::to_vec(value).unwrap()).unwrap();
        fs::write(&controller_package, b"controller package bytes").unwrap();
        fs::write(&controller_signature, b"controller signature bytes").unwrap();
        fs::write(
            &package_manifest_signature,
            b"package manifest signature bytes",
        )
        .unwrap();
        write_executable(
            &tools.join("bsdtar"),
            r#"#!/usr/bin/python3
import os, pathlib, sys
member = sys.argv[-1]
if swap := os.environ.get("FAKE_SWAP_PACKAGE"):
    pathlib.Path(swap).write_bytes(b"replaced controller package")
if os.environ.get("FAKE_OVERSIZE_MEMBER") == member:
    sys.stdout.buffer.write(b"x" * (1024 * 1024 + 1))
elif member == ".PKGINFO":
    sys.stdout.write("pkgname = pt31553-fan-control\npkgver = 0.1.0-1\narch = x86_64\n")
elif member == "usr/lib/pt31553-fan-control/compatibility.toml":
    sys.stdout.buffer.write(pathlib.Path(os.environ["FAKE_COMPATIBILITY"]).read_bytes())
elif member == "usr/share/pt31553-fan-control/source-commit":
    sys.stdout.write(os.environ.get("FAKE_SOURCE_COMMIT", "1234567890abcdef1234567890abcdef12345678") + "\n")
else:
    raise SystemExit(1)
"#,
        );
        write_executable(
            &tools.join("pacman-key"),
            r#"#!/usr/bin/python3
import os
import pathlib
if swap := os.environ.get("FAKE_SWAP_SIGNATURE"):
    pathlib.Path(swap).write_bytes(b"replaced controller signature")
raise SystemExit(0 if os.environ.get("FAKE_SIGNATURE_VALID", "1") == "1" else 1)
"#,
        );
        write_executable(
            &tools.join("gpg"),
            r#"#!/usr/bin/python3
import os
fingerprint = os.environ.get("FAKE_SIGNER", "ABCDEF0123456789ABCDEF0123456789ABCDEF01")
print(f"[GNUPG:] VALIDSIG {fingerprint} 2026-09-02 0 0 4 0 1 10 00 {fingerprint}")
"#,
        );
        write_executable(
            &harness,
            r#"#!/usr/bin/python3
import importlib.machinery, importlib.util, os, pathlib, sys
script = pathlib.Path(os.environ["GENERATOR_SCRIPT"])
loader = importlib.machinery.SourceFileLoader("candidate_generator", str(script))
spec = importlib.util.spec_from_loader(loader.name, loader)
loaded = importlib.util.module_from_spec(spec)
loader.exec_module(loaded)
loaded.trusted_tool = lambda name: pathlib.Path(os.environ["FAKE_TOOLS"]) / name
try:
    raise SystemExit(loaded.main())
except loaded.DeclarationError as error:
    print(f"generate-candidate-declarations: {error}", file=sys.stderr)
    raise SystemExit(1)
"#,
        );
        Self {
            root,
            provenance,
            compatibility,
            manifest,
            controller_package,
            controller_signature,
            package_manifest_signature,
            harness,
            tools,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.harness);
        command
            .env(
                "GENERATOR_SCRIPT",
                workspace().join("scripts/generate-candidate-declarations"),
            )
            .env("FAKE_TOOLS", &self.tools)
            .env("FAKE_COMPATIBILITY", &self.compatibility);
        command
    }

    fn generate_compatibility(&self) -> Output {
        self.command()
            .args(["compatibility", "--provenance"])
            .arg(&self.provenance)
            .arg("--output")
            .arg(&self.compatibility)
            .output()
            .unwrap()
    }

    fn generate_manifest(&self) -> Output {
        self.generate_manifest_with(self.command())
    }

    fn generate_manifest_with(&self, mut command: Command) -> Output {
        command
            .args(["manifest", "--provenance"])
            .arg(&self.provenance)
            .arg("--compatibility")
            .arg(&self.compatibility)
            .arg("--controller-package")
            .arg(&self.controller_package)
            .arg("--controller-signature")
            .arg(&self.controller_signature)
            .args([
                "--controller-signer-fingerprint",
                "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            ])
            .arg("--package-manifest-signature")
            .arg(&self.package_manifest_signature)
            .arg("--output")
            .arg(&self.manifest)
            .output()
            .unwrap()
    }
}

#[test]
fn generates_actual_unqualified_immutable_candidate_declarations() {
    let fixture = Fixture::new(&provenance());
    let output = fixture.generate_compatibility();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let compatibility = fs::read_to_string(&fixture.compatibility).unwrap();
    assert!(compatibility.contains("QUALIFICATION STATUS: UNQUALIFIED"));
    assert!(compatibility.contains(&repeated('6')));
    assert!(compatibility.contains(&repeated('8')));
    assert!(!compatibility.contains(&repeated('0')));

    let output = fixture.generate_manifest();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    let schema: serde_json::Value = serde_json::from_slice(
        &fs::read(workspace().join("schemas/candidate-identity-v1.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&manifest));
    assert_eq!(manifest["qualification_status"], "unqualified");
    assert_eq!(manifest["installation"]["candidate_default"], false);
    assert_eq!(
        manifest["controller"]["signer_fingerprint"],
        "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    );
    assert_eq!(manifest["kernel"]["image_sha256"], repeated('6'));
    let expected_package_hash = format!("{:x}", Sha256::digest(b"controller package bytes"));
    assert_eq!(
        manifest["controller"]["package_sha256"],
        expected_package_hash
    );
    assert_eq!(
        fs::metadata(&fixture.manifest)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444
    );
    let mut invalid = manifest.clone();
    invalid["kernel"]["image_sha256"] = repeated('0').into();
    assert!(!validator.is_valid(&invalid));
    let mut invalid = manifest.clone();
    invalid["package_set"]["artifacts"][1] = invalid["package_set"]["artifacts"][0].clone();
    assert!(!validator.is_valid(&invalid));
    let original_manifest = fs::read(&fixture.manifest).unwrap();
    assert!(
        !fixture.generate_manifest().status.success(),
        "overwrote an existing declaration"
    );
    assert_eq!(fs::read(&fixture.manifest).unwrap(), original_manifest);
    assert!(fixture.root.path().is_dir());

    let real_parent = fixture.root.path().join("real-output-parent");
    let linked_parent = fixture.root.path().join("linked-output-parent");
    fs::create_dir(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();
    let output = fixture
        .command()
        .args(["compatibility", "--provenance"])
        .arg(&fixture.provenance)
        .arg("--output")
        .arg(linked_parent.join("declaration.toml"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!real_parent.join("declaration.toml").exists());
}

#[test]
fn rejects_placeholder_or_incoherent_verified_inputs_before_publication() {
    let mut placeholder = provenance();
    placeholder["build"]["build_environment_sha256"] = repeated('0').into();
    let fixture = Fixture::new(&placeholder);
    assert!(!fixture.generate_compatibility().status.success());
    assert!(!fixture.compatibility.exists());

    let mut incoherent = provenance();
    incoherent["modules"][1]["path"] =
        format!("/usr/lib/modules/{RELEASE}/extramodules/wrong.ko.zst").into();
    let fixture = Fixture::new(&incoherent);
    assert!(!fixture.generate_compatibility().status.success());
    assert!(!fixture.compatibility.exists());
}

#[test]
fn manifest_rejects_modified_compatibility_and_false_controller_provenance() {
    let fixture = Fixture::new(&provenance());
    assert!(fixture.generate_compatibility().status.success());
    let mut compatibility = fs::read_to_string(&fixture.compatibility).unwrap();
    compatibility.push_str("\n# altered after generation\n");
    let mut permissions = fs::metadata(&fixture.compatibility).unwrap().permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&fixture.compatibility, permissions).unwrap();
    fs::write(&fixture.compatibility, compatibility).unwrap();
    assert!(!fixture.generate_manifest().status.success());
    assert!(!fixture.manifest.exists());

    fs::remove_file(&fixture.compatibility).unwrap();
    assert!(fixture.generate_compatibility().status.success());
    let output = fixture
        .command()
        .args(["manifest", "--provenance"])
        .arg(&fixture.provenance)
        .arg("--compatibility")
        .arg(&fixture.compatibility)
        .arg("--controller-package")
        .arg(&fixture.controller_package)
        .arg("--controller-signature")
        .arg(&fixture.controller_signature)
        .args([
            "--controller-signer-fingerprint",
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        ])
        .arg("--package-manifest-signature")
        .arg(&fixture.package_manifest_signature)
        .arg("--output")
        .arg(&fixture.manifest)
        .env(
            "FAKE_SOURCE_COMMIT",
            "0000000000000000000000000000000000000000",
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!fixture.manifest.exists());

    let mut invalid_signature = fixture.command();
    invalid_signature.env("FAKE_SIGNATURE_VALID", "0");
    let output = fixture.generate_manifest_with(invalid_signature);
    assert!(!output.status.success());
    assert!(!fixture.manifest.exists());

    let mut wrong_signer = fixture.command();
    wrong_signer.env("FAKE_SIGNER", "1111111111111111111111111111111111111111");
    let output = fixture.generate_manifest_with(wrong_signer);
    assert!(!output.status.success());
    assert!(!fixture.manifest.exists());

    let mut oversized_member = fixture.command();
    oversized_member.env("FAKE_OVERSIZE_MEMBER", ".PKGINFO");
    let output = fixture.generate_manifest_with(oversized_member);
    assert!(!output.status.success());
    assert!(!fixture.manifest.exists());

    fs::write(
        &fixture.package_manifest_signature,
        b"substituted signature",
    )
    .unwrap();
    assert!(!fixture.generate_manifest().status.success());
    assert!(!fixture.manifest.exists());
}

#[test]
fn manifest_hashes_the_same_snapshots_that_it_verifies() {
    let fixture = Fixture::new(&provenance());
    assert!(fixture.generate_compatibility().status.success());
    let original_package_hash = format!("{:x}", Sha256::digest(b"controller package bytes"));
    let original_signature_hash = format!("{:x}", Sha256::digest(b"controller signature bytes"));
    let output = fixture.generate_manifest_with({
        let mut command = fixture.command();
        command
            .env("FAKE_SWAP_PACKAGE", &fixture.controller_package)
            .env("FAKE_SWAP_SIGNATURE", &fixture.controller_signature);
        command
    });
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    assert_eq!(
        manifest["controller"]["package_sha256"],
        original_package_hash
    );
    assert_eq!(
        manifest["controller"]["signature_sha256"],
        original_signature_hash
    );
    assert_ne!(
        format!(
            "{:x}",
            Sha256::digest(fs::read(&fixture.controller_package).unwrap())
        ),
        original_package_hash
    );
}

#[test]
fn source_candidate_wrapper_is_local_non_installing_and_fail_closed() {
    let path = workspace().join("scripts/build-source-candidate");
    let source = fs::read_to_string(&path).unwrap();
    for required in [
        "#!/usr/bin/bash -p",
        "unsafe inherited environment",
        "run_git -C \"$source_root\" status --porcelain=v1 --untracked-files=all",
        "verify-source-lock\" --inputs \"$bundle\" --exec-verified",
        "verify-package-provenance\"",
        "generate-candidate-declarations\" compatibility",
        "generate-candidate-declarations\" manifest",
        "check-sensitive-history\" --tree \"$payload\"",
        "--package-cert-sha256 \"$package_cert_sha256\"",
        "--module-cert-sha256 \"$module_cert_sha256\"",
        "--kernel-cert-sha256 \"$kernel_cert_sha256\"",
        "CARGO_NET_OFFLINE=true",
        "CARGO_HOME=\"$cargo_home\"",
        "GNUPGHOME=\"$controller_gnupg_home\"",
        "PKGDEST=\"$controller_build\"",
        "mapfile -t packages < <(run_controller_makepkg --packagelist)",
        "run_git -C \"$source_root\" archive",
        "cat-file -e \"$controller_source_commit^{commit}\"",
        "--output \"$controller_archive\" \"$controller_source_commit\"",
        "--controller-signer-fingerprint \"$controller_signer\"",
        "/usr/bin/mv -T \"$payload\" \"$output\"",
    ] {
        assert!(
            source.contains(required),
            "missing wrapper gate: {required}"
        );
    }
    for forbidden in [
        "pacman -U",
        "systemctl",
        "bootctl",
        "grub-set-default",
        "gh workflow",
        "gh release",
        "--syncdeps",
        "package_cert_sha256=$(certificate_sha256",
        "--output \"$controller_archive\" \"$revision\"",
        "printf \"\\n_commit='%s'\\n\"",
    ] {
        assert!(!source.contains(forbidden), "wrapper contains {forbidden}");
    }
    let output = Command::new(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(64));

    let hostile = tempfile::tempdir().unwrap();
    let bash_env = hostile.path().join("bash-env");
    let marker = hostile.path().join("executed");
    fs::write(&bash_env, format!("touch {}\n", marker.display())).unwrap();
    let output = Command::new(&path)
        .env("BASH_ENV", &bash_env)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64));
    assert!(!marker.exists(), "BASH_ENV executed before the wrapper");

    let required_args = [
        "--bundle",
        "x",
        "--kernel-signing-dir",
        "x",
        "--package-cert",
        "x",
        "--package-cert-sha256",
        "x",
        "--package-key",
        "x",
        "--module-cert-sha256",
        "x",
        "--kernel-cert",
        "x",
        "--kernel-cert-sha256",
        "x",
        "--cargo-home",
        "x",
        "--controller-gnupg-home",
        "x",
        "--controller-key",
        "x",
        "--output",
        "x",
    ];
    for (name, value) in [
        ("OPENSSL_CONF", hostile.path().join("openssl.cnf")),
        ("PKGDEST", hostile.path().join("attacker-package-output")),
    ] {
        let output = Command::new(&path)
            .args(required_args)
            .env(name, value)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "unsafe variable: {name}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsafe inherited environment"));
    }

    let fsmonitor = hostile.path().join("fsmonitor");
    let fsmonitor_marker = hostile.path().join("fsmonitor-executed");
    write_executable(
        &fsmonitor,
        &format!("#!/bin/sh\ntouch {}\n", fsmonitor_marker.display()),
    );
    let output = Command::new(&path)
        .args(required_args)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", &fsmonitor)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !fsmonitor_marker.exists(),
        "injected Git fsmonitor executed"
    );
}

#[test]
fn source_candidate_wrapper_rejects_hidden_index_mutations_before_publication() {
    let sandbox = tempfile::tempdir().unwrap();
    let repository = sandbox.path().join("repository");
    fs::create_dir_all(repository.join("scripts")).unwrap();
    let wrapper = repository.join("scripts/build-source-candidate");
    fs::copy(workspace().join("scripts/build-source-candidate"), &wrapper).unwrap();
    let mut permissions = fs::metadata(&wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&wrapper, permissions).unwrap();
    fs::write(repository.join("README.md"), "reviewed\n").unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["add", "README.md", "scripts/build-source-candidate"],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "reviewed source",
        ],
        vec!["update-index", "--assume-unchanged", "README.md"],
    ] {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(&repository)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(repository.join("README.md"), "hidden mutation\n").unwrap();

    let bundle = sandbox.path().join("bundle");
    let kernel_signing = sandbox.path().join("kernel-signing");
    let cargo_home = sandbox.path().join("cargo-home");
    let gnupg_home = sandbox.path().join("gnupg-home");
    let output_parent = sandbox.path().join("output");
    for directory in [
        &bundle,
        &kernel_signing,
        &cargo_home,
        &gnupg_home,
        &output_parent,
    ] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let package_cert = sandbox.path().join("package.pem");
    let package_key = sandbox.path().join("package.key");
    let kernel_cert = sandbox.path().join("kernel.pem");
    fs::write(&package_cert, "certificate").unwrap();
    fs::write(&package_key, "private key").unwrap();
    fs::set_permissions(&package_key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&kernel_cert, "certificate").unwrap();
    let output = output_parent.join("candidate");
    let mut command = Command::new(&wrapper);
    command
        .args(["--bundle"])
        .arg(&bundle)
        .args(["--kernel-signing-dir"])
        .arg(&kernel_signing)
        .args(["--package-cert"])
        .arg(&package_cert)
        .args(["--package-cert-sha256", &repeated('1')])
        .args(["--package-key"])
        .arg(&package_key)
        .args(["--module-cert-sha256", &repeated('2')])
        .args(["--kernel-cert"])
        .arg(&kernel_cert)
        .args(["--kernel-cert-sha256", &repeated('3')])
        .args(["--cargo-home"])
        .arg(&cargo_home)
        .args(["--controller-gnupg-home"])
        .arg(&gnupg_home)
        .args([
            "--controller-key",
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "--output",
        ])
        .arg(&output);
    for variable in [
        "BASH_ENV",
        "ENV",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "CARGO_HOME",
        "GNUPGHOME",
        "PKGDEST",
    ] {
        command.env_remove(variable);
    }
    let result = command.output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("nondefault Git index flag"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());
}

#[test]
fn source_candidate_wrapper_orchestrates_complete_publish_and_late_failure() {
    let sandbox = tempfile::tempdir().unwrap();
    let repository = sandbox.path().join("repository");
    let tools = sandbox.path().join("tools");
    let late_failure = sandbox.path().join("reject-late-stage");
    fs::create_dir_all(repository.join("scripts")).unwrap();
    fs::create_dir_all(repository.join("packaging/controller")).unwrap();
    fs::create_dir(&tools).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success()
    );
    fs::write(repository.join("README.md"), "initial source\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "README.md"])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "source revision",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success()
    );
    let pinned_revision = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&repository)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    fs::write(
        repository.join("packaging/controller/PKGBUILD"),
        format!("_commit='{}'\n", pinned_revision.trim()),
    )
    .unwrap();

    let original = fs::read_to_string(workspace().join("scripts/build-source-candidate")).unwrap();
    let validation_start = original.find("for tool in \\\n").unwrap();
    let validation_tail = original[validation_start..]
        .find("\ndone\n\n[[ \"$output\"")
        .unwrap();
    let mut harness_source = original;
    harness_source.replace_range(
        validation_start..validation_start + validation_tail + "\ndone".len(),
        ":",
    );
    harness_source = harness_source.replace("/usr/bin", &tools.display().to_string());
    let wrapper = repository.join("scripts/build-source-candidate");
    write_executable(&wrapper, &harness_source);

    for tool in [
        "bash",
        "cat",
        "chmod",
        "cmp",
        "cp",
        "cut",
        "env",
        "find",
        "git",
        "gzip",
        "install",
        "mkdir",
        "mktemp",
        "mv",
        "python3",
        "realpath",
        "rm",
        "sed",
        "sha256sum",
        "stat",
    ] {
        symlink(Path::new("/usr/bin").join(tool), tools.join(tool)).unwrap();
    }
    write_executable(
        &tools.join("openssl"),
        r#"#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  if [ "$1" = -out ]; then printf 'manifest signature\n' >"$2"; exit 0; fi
  shift
done
exit 1
"#,
    );
    write_executable(
        &tools.join("makepkg"),
        r#"#!/bin/sh
set -eu
package="$PKGDEST/pt31553-fan-control-0.1.0-1-x86_64.pkg.tar.zst"
if [ "${1:-}" = --packagelist ]; then printf '%s\n' "$package"; exit 0; fi
printf 'controller package\n' >"$package"
printf 'controller signature\n' >"$package.sig"
"#,
    );
    write_executable(&tools.join("pacman-key"), "#!/bin/sh\nexit 0\n");
    write_executable(
        &tools.join("gpg"),
        "#!/bin/sh\nprintf '%s\\n' '[GNUPG:] VALIDSIG ABCDEF0123456789ABCDEF0123456789ABCDEF01 2026-09-02 0 0 4 0 1 10 00 ABCDEF0123456789ABCDEF0123456789ABCDEF01'\n",
    );
    write_executable(
        &tools.join("bsdtar"),
        r#"#!/bin/sh
set -eu
member=$3
case "$member" in
  usr/lib/pt31553-fan-control/compatibility.toml) cat candidate-compatibility.toml ;;
  usr/share/pt31553-fan-control/source-commit) cat controller-source-commit ;;
  *) exit 1 ;;
esac
"#,
    );
    write_executable(
        &repository.join("scripts/verify-source-lock"),
        "#!/bin/sh\nset -eu\nmkdir -p \"$SOURCE_LOCK_OUTPUT\"\nprintf 'kernel packages\\n' >\"$SOURCE_LOCK_OUTPUT/SHA256SUMS\"\n",
    );
    write_executable(
        &repository.join("scripts/verify-package-provenance"),
        r#"#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then printf '{"verified":true}\n' >"$2"; exit 0; fi
  shift
done
exit 1
"#,
    );
    write_executable(
        &repository.join("scripts/generate-candidate-declarations"),
        r#"#!/bin/sh
set -eu
kind=$1
shift
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then output=$2; shift 2; continue; fi
  shift
done
case "$kind" in
  compatibility) printf 'qualification = "unqualified"\n' >"$output" ;;
  manifest) printf '{"qualification_status":"unqualified","installation":{"allowed_state":"disabled-only"}}\n' >"$output" ;;
  *) exit 1 ;;
esac
chmod 0444 "$output"
"#,
    );
    write_executable(
        &repository.join("scripts/check-sensitive-history"),
        &format!(
            "#!/usr/bin/python3\nimport pathlib, sys\nassert not pathlib.Path({:?}).exists()\ntree = pathlib.Path(sys.argv[sys.argv.index('--tree') + 1])\nassert (tree / 'declarations/candidate-identity-v1.json').is_file()\nassert (tree / 'controller/pt31553-fan-control-0.1.0-1-x86_64.pkg.tar.zst.sig').is_file()\n",
            late_failure.display()
        ),
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "candidate harness",
            ])
            .current_dir(&repository)
            .status()
            .unwrap()
            .success()
    );

    let bundle = sandbox.path().join("bundle");
    let kernel_signing = sandbox.path().join("kernel-signing");
    let cargo_home = sandbox.path().join("cargo-home");
    let gnupg_home = sandbox.path().join("gnupg-home");
    let output_parent = sandbox.path().join("output");
    for directory in [
        &bundle,
        &kernel_signing,
        &cargo_home,
        &gnupg_home,
        &output_parent,
    ] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let package_cert = sandbox.path().join("package.pem");
    let package_key = sandbox.path().join("package.key");
    let kernel_cert = sandbox.path().join("kernel.pem");
    fs::write(&package_cert, "certificate").unwrap();
    fs::write(&package_key, "private key").unwrap();
    fs::set_permissions(&package_key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&kernel_cert, "certificate").unwrap();

    let run = |output: &Path| {
        let mut command = Command::new(&wrapper);
        command
            .env_clear()
            .args(["--bundle"])
            .arg(&bundle)
            .args(["--kernel-signing-dir"])
            .arg(&kernel_signing)
            .args(["--package-cert"])
            .arg(&package_cert)
            .args(["--package-cert-sha256", &repeated('1')])
            .args(["--package-key"])
            .arg(&package_key)
            .args(["--module-cert-sha256", &repeated('2')])
            .args(["--kernel-cert"])
            .arg(&kernel_cert)
            .args(["--kernel-cert-sha256", &repeated('3')])
            .args(["--cargo-home"])
            .arg(&cargo_home)
            .args(["--controller-gnupg-home"])
            .arg(&gnupg_home)
            .args([
                "--controller-key",
                "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
                "--output",
            ])
            .arg(output)
            .output()
            .unwrap()
    };
    let published = output_parent.join("published");
    let result = run(&published);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for path in [
        "controller/pt31553-fan-control-0.1.0-1-x86_64.pkg.tar.zst",
        "controller/pt31553-fan-control-0.1.0-1-x86_64.pkg.tar.zst.sig",
        "declarations/package-provenance-v1.json",
        "declarations/compatibility.toml",
        "declarations/candidate-identity-v1.json",
        "signatures/package-set.p7s",
    ] {
        let artifact = published.join(path);
        assert!(artifact.is_file(), "missing published artifact: {path}");
        assert_eq!(
            fs::metadata(artifact).unwrap().permissions().mode() & 0o222,
            0
        );
    }

    fs::write(&late_failure, "reject").unwrap();
    let rejected = output_parent.join("rejected");
    let result = run(&rejected);
    assert!(!result.status.success());
    assert!(!rejected.exists(), "late failure published partial output");
}
