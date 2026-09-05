use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use fan_control_core::{
    QUALIFICATION_CGROUP_PREFIX, parse_compatibility_v1, parse_config_v1, validate_config_v1,
};

const SOURCE_COMMIT: &str = "6df66e2ecb2ecf45cd8b4eb3955762d03f26563c";
const SOURCE_SHA256: &str = "1616992a0374664455f230e7d1d496b59339b38e2eb744dbc4d366f8754f85ce";
const README: &str = include_str!("../../../README.md");
const SKILL: &str = include_str!("../../../skills/predator-fan-control/SKILL.md");
const OPERATIONS: &str =
    include_str!("../../../skills/predator-fan-control/references/operations.md");
const RECOVERY: &str = include_str!("../../../skills/predator-fan-control/references/recovery.md");
const SAFETY: &str = include_str!("../../../skills/predator-fan-control/references/safety.md");
const CONFIGURATION: &str =
    include_str!("../../../skills/predator-fan-control/references/configuration.md");
const SUPPORT: &str = include_str!("../../../skills/predator-fan-control/references/support.md");
const OPENAI_YAML: &str = include_str!("../../../skills/predator-fan-control/agents/openai.yaml");
const EXPECTED_TMPFILES: &str = "\
# Type Path                                           Mode User Group Age Argument
d /run/pt31553-fan-control                            0755 root root -   -
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

#[cfg(unix)]
fn stage_package_fixture() -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "pt31553-controller-package-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let srcdir = root.join("src");
    let pkgdir = root.join("pkg");
    let source_root = srcdir.join(format!("predator-pt315-53-fan-control-{SOURCE_COMMIT}"));
    let repository = contract_source_root();

    for binary in [
        "fan-control-daemon",
        "fan-control-restore",
        "fan-control-qualify",
        "fan-control-observer",
    ] {
        let path = source_root.join("target/release").join(binary);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("fixture:{binary}\n")).unwrap();
    }
    for relative in [
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
    ] {
        copy(repository.join(relative), source_root.join(relative));
    }
    let output = Command::new("/bin/bash")
        .args([
            "-c",
            "set -euo pipefail; source \"$1\"; package",
            "package-layout-test",
        ])
        .arg(package_root().join("PKGBUILD"))
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
    (root, pkgdir)
}

fn canonical_operator_entries(surface: &str) -> Vec<String> {
    let normalized = surface.replace("\n  ", " ");
    let mut entries = normalized
        .lines()
        .filter_map(|line| line.strip_prefix("- "))
        .flat_map(|bullet| {
            bullet
                .split(';')
                .next()
                .unwrap()
                .split('`')
                .skip(1)
                .step_by(2)
                .filter(|entry| entry.starts_with('/') || entry.ends_with(".service"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
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
    let pkgrel = pkgbuild
        .lines()
        .find_map(|line| line.strip_prefix("pkgrel="))
        .expect("PKGBUILD must declare pkgrel");
    assert!(
        srcinfo
            .lines()
            .any(|line| line.trim() == format!("pkgrel = {pkgrel}"))
    );
    let package_filename = format!("pt31553-fan-control-0.1.0-{pkgrel}-x86_64.pkg.tar.zst");
    assert!(README.contains(&format!(
        "controller_package=/absolute/path/to/{package_filename}"
    )));
    assert!(README.contains(&format!(
        "controller_package_signature=/absolute/path/to/{package_filename}.sig"
    )));
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
    assert!(workflow.contains("source /opt/controller-package/PKGBUILD"));
    assert!(workflow.contains("cmp - <(printf '%s\\n' \"$_commit\")"));
    assert!(!workflow.contains("530f5ea19f46df841e39325580d221d2d64fac7b"));
}

#[test]
fn every_github_workflow_is_manual_only_and_does_not_publish_releases() {
    let workflows = repository_root().join(".github/workflows");
    let mut checked = 0;
    for entry in fs::read_dir(workflows).unwrap() {
        let path = entry.unwrap().path();
        if !matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        let triggers = source
            .split_once("\non:\n")
            .unwrap_or_else(|| panic!("{} has no trigger block", path.display()))
            .1
            .split_once("\npermissions:")
            .unwrap_or_else(|| panic!("{} has no permissions boundary", path.display()))
            .0;
        assert_eq!(
            triggers.trim(),
            "workflow_dispatch:",
            "{} is not manual-only",
            path.display()
        );
        assert_eq!(
            source.matches("permissions:").count(),
            1,
            "{} overrides the read-only token permission",
            path.display()
        );
        let permissions = source
            .split_once("\npermissions:\n")
            .unwrap()
            .1
            .split_once("\njobs:")
            .unwrap_or_else(|| panic!("{} has no jobs boundary", path.display()))
            .0;
        assert_eq!(
            permissions.trim(),
            "contents: read",
            "{} has permissions beyond read-only contents",
            path.display()
        );
        for line in source.lines().map(str::trim) {
            if let Some(action) = line.strip_prefix("- uses: ") {
                assert_eq!(
                    action,
                    "actions/checkout@v4",
                    "{} uses non-allowlisted action {action}",
                    path.display()
                );
            }
        }
        for credential_surface in ["${{ secrets.", "GH_TOKEN", "GITHUB_TOKEN"] {
            assert!(
                !source.contains(credential_surface),
                "{} exposes workflow credentials via {credential_surface}",
                path.display()
            );
        }
        checked += 1;
    }
    assert!(checked > 0, "no GitHub workflows were checked");
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
    let (root, pkgdir) = stage_package_fixture();
    let repository = contract_source_root();
    let package = package_root();

    for (binary, source_binary) in [
        ("usr/bin/pt31553-fand", "fan-control-daemon"),
        ("usr/bin/pt31553-fan-restore", "fan-control-restore"),
        ("usr/bin/pt31553-fan-qualify", "fan-control-qualify"),
        ("usr/bin/pt31553-fan-observer", "fan-control-observer"),
    ] {
        assert_eq!(mode(pkgdir.join(binary)), 0o755);
        assert_eq!(
            fs::read_to_string(pkgdir.join(binary)).unwrap(),
            format!("fixture:{source_binary}\n"),
            "package mapped the wrong executable to {binary}"
        );
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
    assert!(
        !pkgdir
            .join("var/lib/pt31553-fan-control/qualification.json")
            .exists(),
        "the package must not pre-authorize the machine"
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
            "usr/bin/pt31553-fan-observer",
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

#[cfg(unix)]
#[test]
fn operator_documentation_matches_the_packaged_surface() {
    let (staging_root, pkgdir) = stage_package_fixture();
    let readme_surface = README
        .split_once(
            "The package's operator entrypoints, authority inputs, and state locations used below are:",
        )
        .expect("runbook lost installed package surface")
        .1
        .split_once("First obtain the approved candidate-manifest")
        .expect("runbook package surface lost its boundary")
        .0;
    let operations_surface = OPERATIONS
        .split_once("## Inspect installed status")
        .expect("operations lost installed status surface")
        .1
        .split_once("## Prepare and install disabled")
        .expect("operations package surface lost its boundary")
        .0;
    let routed_operations = [
        ("runbook package surface", readme_surface),
        ("operations package surface", operations_surface),
    ];
    let routed_documents = [("runbook", README), ("operations", OPERATIONS)];
    let surface = [
        ("usr/bin/pt31553-fand", "/usr/bin/pt31553-fand"),
        (
            "usr/bin/pt31553-fan-restore",
            "/usr/bin/pt31553-fan-restore",
        ),
        (
            "usr/bin/pt31553-fan-qualify",
            "/usr/bin/pt31553-fan-qualify",
        ),
        (
            "usr/bin/pt31553-fan-observer",
            "/usr/bin/pt31553-fan-observer",
        ),
        (
            "etc/pt31553-fan-control/config.toml",
            "/etc/pt31553-fan-control/config.toml",
        ),
        (
            "usr/lib/pt31553-fan-control/compatibility.toml",
            "/usr/lib/pt31553-fan-control/compatibility.toml",
        ),
        (
            "var/lib/pt31553-fan-control",
            "/var/lib/pt31553-fan-control/",
        ),
        (
            "var/lib/pt31553-fan-control/evidence",
            "/var/lib/pt31553-fan-control/evidence/",
        ),
        (
            "usr/lib/systemd/system/pt31553-fand.service",
            "pt31553-fand.service",
        ),
        (
            "usr/lib/systemd/system/pt31553-fan-sleep-guard.service",
            "pt31553-fan-sleep-guard.service",
        ),
    ];
    let mut documented_surface = surface
        .iter()
        .map(|(_, documented)| (*documented).to_owned())
        .collect::<Vec<_>>();
    documented_surface.sort();
    for (name, document) in routed_operations {
        assert_eq!(
            canonical_operator_entries(document),
            documented_surface,
            "{name} drifted from the canonical packaged operator surface"
        );
    }
    for (packaged, documented) in surface {
        assert!(
            pkgdir.join(packaged).exists(),
            "documented package surface {documented} was not staged at {packaged}"
        );
    }
    for forbidden in [
        "var/lib/pt31553-fan-control/qualification.json",
        "run/pt31553-fan-control",
    ] {
        assert!(
            !pkgdir.join(forbidden).exists(),
            "staged package unexpectedly created authority/runtime state {forbidden}"
        );
    }
    for exact in [
        "cargo run -p fan-control-daemon -- --status",
        "cargo run -p fan-control-restore -- --status",
        "cargo run -p fan-control-qualify",
        "scripts/check-repository-policy",
        "scripts/build-source-candidate",
        "GitHub Actions are manual",
        "releases are optional",
    ] {
        for (name, document) in routed_documents {
            assert!(
                document.contains(exact),
                "{name} lost current contract: {exact}"
            );
        }
    }
    for exact in [
        "pt31553-source-candidate-$source_revision/{kernel,controller,declarations,signatures}",
        "approval only at privileged or live",
        "/sys/fs/cgroup/pt31553-fan-qualify-<pid>-<counter>",
    ] {
        assert!(
            README.contains(exact),
            "runbook lost current contract: {exact}"
        );
    }
    for exact in [
        "pt31553-source-candidate-<40-hex-HEAD>/{kernel,controller,declarations,signatures}",
        "/var/lib/pt31553-fan-control/qualification.json",
        "supervised-endurance run later creates",
    ] {
        assert!(
            OPERATIONS.contains(exact),
            "operations reference lost current contract: {exact}"
        );
    }
    assert!(SKILL.contains("Before any privileged or live-control operation"));
    let documented_cgroup = format!("/sys/fs/cgroup/{QUALIFICATION_CGROUP_PREFIX}<pid>-<counter>");
    assert!(README.contains(&documented_cgroup));
    assert!(RECOVERY.contains(&documented_cgroup));
    assert!(README.contains(&format!("-name '{QUALIFICATION_CGROUP_PREFIX}*'")));

    for stale in [
        "future automatic controller",
        "daemon is deliberately status-only",
        "current status-only revision",
        "/usr/bin/pt31553-fan-workload-launcher",
        "/sys/fs/cgroup/pt31553-qualification",
        "REPLACE_WITH_REVIEWED_40_HEX_COMMIT",
    ] {
        for (name, document) in [
            ("runbook", README),
            ("skill", SKILL),
            ("operations", OPERATIONS),
            ("recovery", RECOVERY),
            ("safety", SAFETY),
        ] {
            assert!(
                !document.contains(stale),
                "stale contract remains in {name}: {stale}"
            );
        }
    }

    fs::remove_dir_all(staging_root).unwrap();
}

#[test]
fn skill_entrypoint_and_routed_references_preserve_safety_boundaries() {
    for contract in [
        "working autonomously until a privileged or live-control boundary",
        "allow_implicit_invocation: true",
    ] {
        assert!(OPENAI_YAML.contains(contract), "metadata lost: {contract}");
    }
    for contract in [
        "Draft and validate a candidate in an unprivileged temporary path autonomously",
        "Before writing a privileged destination or restarting a service",
        "Wait for explicit approval at that privileged/live boundary",
    ] {
        assert!(
            CONFIGURATION.contains(contract),
            "configuration route lost: {contract}"
        );
    }
    for contract in [
        "Compatibility inspection is read-only",
        "Never write a PWM or enable endpoint",
        "preliminary match",
    ] {
        assert!(SUPPORT.contains(contract), "support route lost: {contract}");
    }

    let approval_gate = SAFETY
        .split_once("## Approval gate")
        .expect("safety reference lost approval gate")
        .1
        .split_once("## Authority ladder")
        .expect("safety approval gate lost its boundary")
        .0
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for autonomous in [
        "Unprivileged source inspection",
        "dependency fetch",
        "tests",
        "builds",
        "package preparation",
        "configuration drafts",
        "read-only status",
        "may proceed autonomously",
    ] {
        assert!(
            approval_gate.contains(autonomous),
            "safety route lost autonomous category: {autonomous}"
        );
    }
    for approval_required in [
        "Present and obtain approval for the exact operation immediately",
        "package installation, update, downgrade, or removal",
        "write to `/etc`, `/usr`, `/var/lib`, a protected artifact",
        "service enable, disable, start, stop, restart, or reset",
        "boot entry, boot default, kernel, module, or Secure Boot change",
        "live qualification, restoration, workload, or other hardware-affecting",
        "A later or materially different mutation needs a new approval",
    ] {
        assert!(
            approval_gate.contains(approval_required),
            "safety route lost approval category: {approval_required}"
        );
    }
}
