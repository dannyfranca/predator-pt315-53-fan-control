use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use fan_control_core::{parse_config_v1, validate_config_v1};

const SOURCE_COMMIT: &str = "c75d72cb17c8503644799accb286e70c42d3cee7";
const SOURCE_SHA256: &str = "4385d64c6cf6dc7ac675c194076a6a89f09c19fc04651ae48951a8cc3abc784a";
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
    assert!(!pkgbuild.contains("SKIP"));
    assert!(!pkgbuild.contains("pkgver()"));
    assert!(pkgbuild.contains("cargo build --frozen --release --workspace --bins"));
    assert!(pkgbuild.contains(
        "RUSTFLAGS=\"${RUSTFLAGS:-} -C debug-assertions=yes\" cargo test --frozen --workspace"
    ));
    assert!(srcinfo.contains(&format!("archive/{SOURCE_COMMIT}.tar.gz")));
    assert!(srcinfo.contains(SOURCE_SHA256));
    assert!(
        !srcinfo
            .lines()
            .any(|line| line.trim_start().starts_with("install ="))
    );
    assert_eq!(
        fs::read_to_string(package.join("pt31553-fan-control.tmpfiles")).unwrap(),
        EXPECTED_TMPFILES
    );
}

#[test]
fn editable_example_is_valid_but_explicitly_not_authority() {
    let source = fs::read_to_string(package_root().join("controller.toml")).unwrap();
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
    let repository = repository_root();
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
        "LICENSE",
    ];
    for relative in pinned_assets {
        copy(repository.join(relative), source_root.join(relative));
    }
    copy(
        package.join("controller.toml"),
        srcdir.join("controller.toml"),
    );
    copy(
        package.join("pt31553-fan-control.tmpfiles"),
        srcdir.join("pt31553-fan-control.tmpfiles"),
    );

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
        mode(pkgdir.join("etc/pt31553-fan-control/controller.toml")),
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
            "usr/share/pt31553-fan-control/schemas/evidence.json",
            "schemas/evidence.json",
        ),
        (
            "usr/share/pt31553-fan-control/schemas/evidence-v2.json",
            "schemas/evidence-v2.json",
        ),
        ("usr/share/licenses/pt31553-fan-control/LICENSE", "LICENSE"),
    ] {
        assert_eq!(
            fs::read(pkgdir.join(installed)).unwrap(),
            fs::read(repository.join(source)).unwrap()
        );
    }
    assert_eq!(
        fs::read(pkgdir.join("etc/pt31553-fan-control/controller.toml")).unwrap(),
        fs::read(package.join("controller.toml")).unwrap()
    );
    assert_eq!(
        fs::read(pkgdir.join("usr/lib/tmpfiles.d/pt31553-fan-control.conf")).unwrap(),
        fs::read(package.join("pt31553-fan-control.tmpfiles")).unwrap()
    );
    for asset in [
        "usr/lib/systemd/system/pt31553-fand.service",
        "usr/lib/systemd/system/pt31553-fan-sleep-guard.service",
        "usr/lib/systemd/system-preset/90-pt31553-fan-control.preset",
        "usr/lib/tmpfiles.d/pt31553-fan-control.conf",
        "usr/share/pt31553-fan-control/schemas/evidence.json",
        "usr/share/pt31553-fan-control/schemas/evidence-v2.json",
        "usr/share/licenses/pt31553-fan-control/LICENSE",
    ] {
        assert_eq!(mode(pkgdir.join(asset)), 0o644, "unsafe mode for {asset}");
    }
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
            "etc/pt31553-fan-control/controller.toml",
            "usr/bin/pt31553-fan-qualify",
            "usr/bin/pt31553-fan-restore",
            "usr/bin/pt31553-fand",
            "usr/lib/systemd/system-preset/90-pt31553-fan-control.preset",
            "usr/lib/systemd/system/pt31553-fan-sleep-guard.service",
            "usr/lib/systemd/system/pt31553-fand.service",
            "usr/lib/tmpfiles.d/pt31553-fan-control.conf",
            "usr/share/licenses/pt31553-fan-control/LICENSE",
            "usr/share/pt31553-fan-control/schemas/evidence-v2.json",
            "usr/share/pt31553-fan-control/schemas/evidence.json",
        ]
    );

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
