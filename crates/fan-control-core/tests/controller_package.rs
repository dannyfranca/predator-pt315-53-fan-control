use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use fan_control_core::{parse_compatibility_v1, parse_config_v1, validate_config_v1};

const SOURCE_COMMIT: &str = "530f5ea19f46df841e39325580d221d2d64fac7b";
const SOURCE_SHA256: &str = "ddc12609732c40c13aac1db3b9a1c0d32b3698fc2ef97fb559c0d9d7e871562e";
const EXPECTED_TMPFILES: &str = "\
# Type Path                                           Mode User Group Age Argument
d /var/lib/pt31553-fan-control                        0700 root root -   -
d /var/lib/pt31553-fan-control/evidence               0700 root root -   -
";
static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn package_root() -> PathBuf {
    repository_root().join("packaging/controller")
}

fn contract_source_root() -> PathBuf {
    std::env::var_os("PT31553_LOCKED_SOURCE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(repository_root)
}

fn mode(path: impl AsRef<Path>) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn copy(source: impl AsRef<Path>, destination: impl AsRef<Path>) {
    let destination = destination.as_ref();
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::copy(source, destination).unwrap();
}

fn collect_files(root: &Path, relative: &Path, files: &mut Vec<String>) {
    let directory = root.join(relative);
    if !directory.exists() {
        return;
    }
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let child = relative.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            collect_files(root, &child, files);
        } else {
            files.push(child.to_string_lossy().into_owned());
        }
    }
}

#[test]
fn source_metadata_is_exact_and_reproducible() {
    let package = package_root();
    let pkgbuild = fs::read_to_string(package.join("PKGBUILD")).unwrap();
    let srcinfo = fs::read_to_string(package.join(".SRCINFO")).unwrap();

    assert!(pkgbuild.contains(&format!("_commit='{SOURCE_COMMIT}'")));
    assert!(pkgbuild.contains(SOURCE_SHA256));
    assert!(pkgbuild.contains("pkgrel=7"));
    assert!(srcinfo.lines().any(|line| line.trim() == "pkgrel = 7"));
    assert!(pkgbuild.contains(
        "depends=('bash' 'coreutils' 'gcc-libs' 'glibc' 'glmark2' 'kmod' 'nvidia-utils' 'openssl' 'pacman' 'sbsigntools' 'stress-ng' 'systemd')"
    ));
    assert!(!pkgbuild.contains("SKIP"));
    assert!(!pkgbuild.contains("pkgver()"));
    assert!(pkgbuild.contains("cargo build --frozen --release --workspace --bins"));
    assert!(pkgbuild.contains("for git_config_variable in \"${!GIT_CONFIG@}\""));
    assert!(pkgbuild.contains("export GIT_CONFIG_NOSYSTEM=1"));
    assert!(pkgbuild.contains("export RUSTFLAGS=\"${RUSTFLAGS:-} -C debug-assertions=yes\""));
    assert!(pkgbuild.contains("cargo test --frozen --workspace --exclude fan-control-core"));
    assert!(pkgbuild.contains("[[ $test_name == source_complete_handoff ]] && continue"));
    assert!(pkgbuild.contains("cargo test --frozen -p fan-control-core --lib"));
    assert!(pkgbuild.contains("cargo test --frozen -p fan-control-core --doc"));
    assert!(srcinfo.contains(&format!("archive/{SOURCE_COMMIT}.tar.gz")));
    assert!(srcinfo.contains(SOURCE_SHA256));
    assert!(
        srcinfo
            .lines()
            .any(|line| line.trim() == "options = !debug")
    );
    assert!(srcinfo.lines().any(|line| line.trim() == "options = !lto"));
    let output = Command::new("/bin/bash")
        .args([
            "-c",
            "set -euo pipefail; source \"$1\"; test \"${#options[@]}\" -eq 2; test \"${options[0]}\" = '!debug'; test \"${options[1]}\" = '!lto'",
            "package-metadata-test",
        ])
        .arg(package.join("PKGBUILD"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let dependencies = srcinfo
        .lines()
        .filter_map(|line| line.trim().strip_prefix("depends = "))
        .collect::<Vec<_>>();
    assert_eq!(
        dependencies,
        [
            "bash",
            "coreutils",
            "gcc-libs",
            "glibc",
            "glmark2",
            "kmod",
            "nvidia-utils",
            "openssl",
            "pacman",
            "sbsigntools",
            "stress-ng",
            "systemd"
        ]
    );
    assert!(
        !srcinfo
            .lines()
            .any(|line| line.trim_start().starts_with("install ="))
    );
    assert_eq!(
        fs::read_to_string(
            contract_source_root().join("packaging/controller/pt31553-fan-control.tmpfiles")
        )
        .unwrap(),
        EXPECTED_TMPFILES
    );
}

#[cfg(unix)]
#[test]
fn archive_checks_ignore_ambient_git_configuration() {
    let root = std::env::temp_dir().join(format!(
        "pt31553-controller-git-config-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let srcdir = root.join("src");
    let source_root = srcdir.join(format!("predator-pt315-53-fan-control-{SOURCE_COMMIT}"));
    let hostile_home = root.join("hostile-home");
    let cargo_calls = root.join("cargo-calls");
    fs::create_dir_all(source_root.join("crates/fan-control-core/tests")).unwrap();
    fs::create_dir_all(&hostile_home).unwrap();
    for test_target in [
        "controller_package.rs",
        "policy_authority.rs",
        "source_complete_handoff.rs",
    ] {
        fs::write(
            source_root
                .join("crates/fan-control-core/tests")
                .join(test_target),
            "",
        )
        .unwrap();
    }
    fs::write(
        hostile_home.join(".gitconfig"),
        "[core]\n\thooksPath = /hostile/hooks\n",
    )
    .unwrap();

    let output = Command::new("/bin/bash")
        .args([
            "-c",
            "set -euo pipefail; source \"$1\"; cargo() { test -z \"${GIT_CONFIG_GLOBAL+x}\"; test -z \"${GIT_CONFIG_SYSTEM+x}\"; test -z \"${GIT_CONFIG_COUNT+x}\"; test -z \"${GIT_CONFIG_KEY_0+x}\"; test -z \"${GIT_CONFIG_VALUE_0+x}\"; test \"$GIT_CONFIG_NOSYSTEM\" = 1; case \"$HOME\" in \"$srcdir\"/.pt31553-test-home.*) ;; *) return 1 ;; esac; test \"$XDG_CONFIG_HOME\" = \"$HOME/.config\"; test -z \"$(/usr/bin/git config --global --get core.hooksPath || true)\"; printf '%s\\n' \"$*\" >>\"$cargo_calls\"; }; check",
            "package-git-config-test",
        ])
        .arg(package_root().join("PKGBUILD"))
        .current_dir(&srcdir)
        .env("srcdir", &srcdir)
        .env("cargo_calls", &cargo_calls)
        .env("HOME", &hostile_home)
        .env("GIT_CONFIG_GLOBAL", hostile_home.join(".gitconfig"))
        .env("GIT_CONFIG_SYSTEM", hostile_home.join("system.gitconfig"))
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/hostile/injected-hooks")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&cargo_calls).unwrap(),
        "test --frozen --workspace --exclude fan-control-core\n\
test --frozen -p fan-control-core --lib --test controller_package --test policy_authority\n\
test --frozen -p fan-control-core --doc\n"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ci_rehardens_the_build_prefix_after_copying_archived_recipe_metadata() {
    let workflow =
        fs::read_to_string(repository_root().join(".github/workflows/controller-package.yml"))
            .unwrap();
    let copy = workflow
        .find("cp -a \"$GITHUB_WORKSPACE/packaging/controller/.\" /opt/controller-package/")
        .unwrap();
    let harden = workflow.find("chmod 0755 /opt/controller-package").unwrap();
    let locked_package_build = workflow
        .find("su builder -c 'cd /opt/controller-package && makepkg --noconfirm --cleanbuild'")
        .unwrap();

    assert_eq!(
        workflow
            .matches("chmod 0755 /opt/controller-package")
            .count(),
        1
    );
    assert!(copy < harden && harden < locked_package_build);
    assert!(workflow.contains("--test controller_package --test source_complete_handoff"));
}

#[test]
fn editable_example_is_valid_but_explicitly_not_authority() {
    let source = fs::read_to_string(contract_source_root().join("config/example.toml")).unwrap();
    validate_config_v1(parse_config_v1(&source).unwrap()).unwrap();
    for warning in [
        "not a protected policy",
        "qualification record",
        "promotion claim",
        "authorization",
        "remains disabled",
    ] {
        assert!(source.contains(warning), "missing warning: {warning}");
    }
}

#[test]
fn compatibility_declaration_is_exact_model_but_cannot_claim_qualified_artifacts() {
    let source =
        fs::read_to_string(contract_source_root().join("compatibility/pt315-53.toml")).unwrap();
    let declaration = parse_compatibility_v1(&source).unwrap();

    assert_eq!(declaration.hardware.dmi_product_name, "Predator PT315-53");
    assert_eq!(declaration.hardware.dmi_board_name, "Civic_TLS");
    assert_eq!(declaration.hardware.bios_version, "V1.17");
    assert_eq!(
        declaration.kernel.source_commit,
        "7a84732fd5e4350c1312fd0ed0c72ffa139fb766"
    );
    for identity in [declaration.kernel.image_sha256, declaration.module.sha256] {
        assert_eq!(identity, "0".repeat(64));
    }
    assert_eq!(declaration.kernel.image_signer_fingerprint, "0".repeat(64));
    assert_eq!(declaration.module.signer_fingerprint, "0".repeat(64));
    for warning in ["unqualified", "zero", "cannot authorize Custom mode"] {
        assert!(source.contains(warning), "missing warning: {warning}");
    }
}

#[cfg(unix)]
#[test]
fn prepare_hardens_reused_source_ancestors() {
    let root = std::env::temp_dir().join(format!(
        "pt31553-controller-prepare-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let srcdir = root.join("src");
    let source_root = srcdir.join(format!("predator-pt315-53-fan-control-{SOURCE_COMMIT}"));
    let nested_crate = source_root.join("crates/fan-control-core");
    fs::create_dir_all(&nested_crate).unwrap();
    fs::set_permissions(&srcdir, fs::Permissions::from_mode(0o775)).unwrap();
    fs::set_permissions(&source_root, fs::Permissions::from_mode(0o775)).unwrap();
    fs::set_permissions(
        source_root.join("crates"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    fs::set_permissions(&nested_crate, fs::Permissions::from_mode(0o775)).unwrap();

    let output = Command::new("/bin/bash")
        .args([
            "-c",
            "set -euo pipefail; source \"$1\"; cargo() { test \"$(umask)\" = 0022; test \"$(stat -c %a \"$srcdir\")\" = 755; test \"$(stat -c %a \"$PWD\")\" = 755; test \"$(stat -c %a \"$PWD/crates/fan-control-core\")\" = 755; if test \"$1\" = build; then install -d -m 0775 target; elif test \"$1\" = test; then test \"$(stat -c %a target)\" = 755; fi; }; (umask 0002; prepare); (umask 0002; build); (umask 0002; check)",
            "package-prepare-test",
        ])
        .arg(package_root().join("PKGBUILD"))
        .current_dir(&srcdir)
        .env("srcdir", &srcdir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(mode(&srcdir), 0o755);
    assert_eq!(mode(&source_root), 0o755);
    assert_eq!(mode(&nested_crate), 0o755);
    assert_eq!(mode(source_root.join("target")), 0o755);
    assert_eq!(mode(nested_crate.join("target")), 0o755);

    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn package_layout_keeps_authority_and_state_boundaries_separate() {
    let root = std::env::temp_dir().join(format!(
        "pt31553-controller-package-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let srcdir = root.join("src");
    let pkgdir = root.join("pkg");
    let source_root = srcdir.join(format!("predator-pt315-53-fan-control-{SOURCE_COMMIT}"));
    let repository = contract_source_root();
    let package = package_root();

    for binary in [
        "fan-control-daemon",
        "fan-control-restore",
        "fan-control-qualify",
    ] {
        let path = source_root.join("target/release").join(binary);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("fixture:{binary}\n")).unwrap();
    }
    let pinned_assets = [
        "systemd/pt31553-fand.service",
        "systemd/pt31553-fan-sleep-guard.service",
        "systemd/90-pt31553-fan-control.preset",
        "schemas/evidence.json",
        "schemas/evidence-v2.json",
        "schemas/candidate-identity-v1.json",
        "schemas/package-provenance-v1.json",
        "schemas/promotion-manifest.json",
        "schemas/qualification-record.json",
        "config/example.toml",
        "policy/qualified-envelope.example.toml",
        "compatibility/pt315-53.toml",
        "packaging/controller/pt31553-fan-control.tmpfiles",
        "qualification/workloads/VERSION",
        "qualification/workloads/common",
        "qualification/workloads/idle",
        "qualification/workloads/cpu",
        "qualification/workloads/gpu",
        "qualification/workloads/combined",
        "qualification/workloads/mixed",
        "LICENSE",
    ];
    for relative in pinned_assets {
        copy(repository.join(relative), source_root.join(relative));
    }
    let output = Command::new("/bin/bash")
        .args([
            "-c",
            "set -euo pipefail; source \"$1\"; package",
            "package-layout-test",
        ])
        .arg(package.join("PKGBUILD"))
        .env("srcdir", &srcdir)
        .env("pkgdir", &pkgdir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    for binary in [
        "usr/bin/pt31553-fand",
        "usr/bin/pt31553-fan-restore",
        "usr/bin/pt31553-fan-qualify",
    ] {
        assert_eq!(mode(pkgdir.join(binary)), 0o755);
    }
    assert_eq!(
        mode(pkgdir.join("etc/pt31553-fan-control/config.toml")),
        0o640
    );
    assert_eq!(mode(pkgdir.join("var/lib/pt31553-fan-control")), 0o700);
    assert_eq!(
        mode(pkgdir.join("var/lib/pt31553-fan-control/evidence")),
        0o700
    );
    assert!(!pkgdir.join("run").exists());
    assert!(!pkgdir.join("etc/systemd/system").exists());
    assert_eq!(
        fs::read_to_string(
            pkgdir.join("usr/lib/systemd/system-preset/90-pt31553-fan-control.preset")
        )
        .unwrap(),
        "disable pt31553-fand.service\ndisable pt31553-fan-sleep-guard.service\n"
    );
    for (installed, source) in [
        (
            "usr/lib/pt31553-fan-control/compatibility.toml",
            "compatibility/pt315-53.toml",
        ),
        (
            "usr/lib/systemd/system/pt31553-fand.service",
            "systemd/pt31553-fand.service",
        ),
        (
            "usr/lib/systemd/system/pt31553-fan-sleep-guard.service",
            "systemd/pt31553-fan-sleep-guard.service",
        ),
        (
            "usr/lib/systemd/system-preset/90-pt31553-fan-control.preset",
            "systemd/90-pt31553-fan-control.preset",
        ),
        (
            "usr/share/pt31553-fan-control/schemas/candidate-identity-v1.json",
            "schemas/candidate-identity-v1.json",
        ),
        (
            "usr/share/pt31553-fan-control/schemas/evidence.json",
            "schemas/evidence.json",
        ),
        (
            "usr/share/pt31553-fan-control/schemas/evidence-v2.json",
            "schemas/evidence-v2.json",
        ),
        (
            "usr/share/pt31553-fan-control/schemas/package-provenance-v1.json",
            "schemas/package-provenance-v1.json",
        ),
        (
            "usr/share/pt31553-fan-control/schemas/promotion-manifest.json",
            "schemas/promotion-manifest.json",
        ),
        (
            "usr/share/pt31553-fan-control/schemas/qualification-record.json",
            "schemas/qualification-record.json",
        ),
        (
            "usr/share/pt31553-fan-control/examples/qualified-envelope.example.toml",
            "policy/qualified-envelope.example.toml",
        ),
        ("usr/share/licenses/pt31553-fan-control/LICENSE", "LICENSE"),
        (
            "usr/lib/pt31553-fan-control/workloads/VERSION",
            "qualification/workloads/VERSION",
        ),
        (
            "usr/lib/pt31553-fan-control/workloads/common",
            "qualification/workloads/common",
        ),
    ] {
        assert_eq!(
            fs::read(pkgdir.join(installed)).unwrap(),
            fs::read(repository.join(source)).unwrap()
        );
    }
    assert_eq!(
        fs::read(pkgdir.join("etc/pt31553-fan-control/config.toml")).unwrap(),
        fs::read(repository.join("config/example.toml")).unwrap()
    );
    assert_eq!(
        fs::read(pkgdir.join("usr/lib/tmpfiles.d/pt31553-fan-control.conf")).unwrap(),
        fs::read(repository.join("packaging/controller/pt31553-fan-control.tmpfiles")).unwrap()
    );
    assert_eq!(
        fs::read_to_string(pkgdir.join("usr/share/pt31553-fan-control/source-commit")).unwrap(),
        format!("{SOURCE_COMMIT}\n")
    );
    for asset in [
        "usr/lib/pt31553-fan-control/compatibility.toml",
        "usr/lib/systemd/system/pt31553-fand.service",
        "usr/lib/systemd/system/pt31553-fan-sleep-guard.service",
        "usr/lib/systemd/system-preset/90-pt31553-fan-control.preset",
        "usr/lib/tmpfiles.d/pt31553-fan-control.conf",
        "usr/lib/pt31553-fan-control/workloads/VERSION",
        "usr/lib/pt31553-fan-control/workloads/common",
        "usr/share/pt31553-fan-control/examples/qualified-envelope.example.toml",
        "usr/share/pt31553-fan-control/schemas/candidate-identity-v1.json",
        "usr/share/pt31553-fan-control/schemas/evidence.json",
        "usr/share/pt31553-fan-control/schemas/evidence-v2.json",
        "usr/share/pt31553-fan-control/schemas/package-provenance-v1.json",
        "usr/share/pt31553-fan-control/schemas/promotion-manifest.json",
        "usr/share/pt31553-fan-control/schemas/qualification-record.json",
        "usr/share/pt31553-fan-control/source-commit",
        "usr/share/licenses/pt31553-fan-control/LICENSE",
    ] {
        assert_eq!(mode(pkgdir.join(asset)), 0o644, "unsafe mode for {asset}");
    }
    for workload in ["idle", "cpu", "gpu", "combined", "mixed"] {
        let installed = format!("usr/lib/pt31553-fan-control/workloads/{workload}");
        let source = format!("qualification/workloads/{workload}");
        assert_eq!(mode(pkgdir.join(&installed)), 0o755);
        assert_eq!(
            fs::read(pkgdir.join(&installed)).unwrap(),
            fs::read(repository.join(source)).unwrap()
        );
        assert_eq!(
            Command::new(pkgdir.join(&installed))
                .arg("--not-fixed")
                .current_dir(&root)
                .status()
                .unwrap()
                .code(),
            Some(64),
            "{workload} accepted a non-canonical invocation"
        );
        assert_eq!(
            Command::new(pkgdir.join(&installed))
                .args(["--fixed", "extra"])
                .current_dir(&root)
                .status()
                .unwrap()
                .code(),
            Some(64),
            "{workload} accepted extra arguments"
        );
    }
    assert_eq!(
        fs::read_to_string(pkgdir.join("usr/lib/pt31553-fan-control/workloads/VERSION")).unwrap(),
        "1.0.0\n"
    );
    assert!(
        fs::read_dir(pkgdir.join("var/lib/pt31553-fan-control/evidence"))
            .unwrap()
            .next()
            .is_none()
    );

    let mut files = Vec::new();
    collect_files(&pkgdir, Path::new(""), &mut files);
    files.sort();
    assert_eq!(
        files,
        [
            "etc/pt31553-fan-control/config.toml",
            "usr/bin/pt31553-fan-qualify",
            "usr/bin/pt31553-fan-restore",
            "usr/bin/pt31553-fand",
            "usr/lib/pt31553-fan-control/compatibility.toml",
            "usr/lib/pt31553-fan-control/workloads/VERSION",
            "usr/lib/pt31553-fan-control/workloads/combined",
            "usr/lib/pt31553-fan-control/workloads/common",
            "usr/lib/pt31553-fan-control/workloads/cpu",
            "usr/lib/pt31553-fan-control/workloads/gpu",
            "usr/lib/pt31553-fan-control/workloads/idle",
            "usr/lib/pt31553-fan-control/workloads/mixed",
            "usr/lib/systemd/system-preset/90-pt31553-fan-control.preset",
            "usr/lib/systemd/system/pt31553-fan-sleep-guard.service",
            "usr/lib/systemd/system/pt31553-fand.service",
            "usr/lib/tmpfiles.d/pt31553-fan-control.conf",
            "usr/share/licenses/pt31553-fan-control/LICENSE",
            "usr/share/pt31553-fan-control/examples/qualified-envelope.example.toml",
            "usr/share/pt31553-fan-control/schemas/candidate-identity-v1.json",
            "usr/share/pt31553-fan-control/schemas/evidence-v2.json",
            "usr/share/pt31553-fan-control/schemas/evidence.json",
            "usr/share/pt31553-fan-control/schemas/package-provenance-v1.json",
            "usr/share/pt31553-fan-control/schemas/promotion-manifest.json",
            "usr/share/pt31553-fan-control/schemas/qualification-record.json",
            "usr/share/pt31553-fan-control/source-commit",
        ]
    );

    for package_owned_recovery_path in [
        "boot",
        "usr/lib/modules",
        "var/lib/pt31553-fan-control/rollback",
    ] {
        assert!(!pkgdir.join(package_owned_recovery_path).exists());
    }

    let pkgbuild = fs::read_to_string(package.join("PKGBUILD")).unwrap();
    for forbidden in [
        "install=",
        "pre_install",
        "post_install",
        "pre_upgrade",
        "post_upgrade",
        "pre_remove",
        "post_remove",
        "systemctl enable",
        "systemctl start",
        "systemctl restart",
    ] {
        assert!(!pkgbuild.contains(forbidden));
    }

    fs::remove_dir_all(root).unwrap();
}
