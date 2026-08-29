use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn workflow_runs_the_complete_policy_for_every_change() {
    let workflow = fs::read_to_string(workspace().join(".github/workflows/repository-policy.yml"))
        .expect("read repository policy workflow");

    assert!(workflow.contains("pull_request:\n"));
    assert!(workflow.contains("push:\n    branches: [main]"));
    assert!(!workflow.contains("paths:"));
    assert!(workflow.contains("permissions:\n  contents: read"));
    assert!(workflow.contains("fetch-depth: 0"));
    assert!(workflow.contains("cargo fetch --locked"));
    assert!(workflow.contains("cargo deny fetch"));
    assert!(workflow.contains("useradd --create-home builder"));
    assert!(workflow.contains("su builder -c"));
    assert!(workflow.contains("rustup toolchain install 1.85.0"));
    assert!(workflow.contains("rustup override set 1.85.0"));
    assert!(workflow.contains("CARGO_NET_OFFLINE=true scripts/check-repository-policy"));

    let install = workflow.find("name: Install policy tooling").unwrap();
    let checkout = workflow.find("uses: actions/checkout@v4").unwrap();
    let chown = workflow.find("chown -R builder:builder").unwrap();
    assert!(install < checkout, "Git must exist before checkout");
    assert!(
        checkout < chown,
        "checkout must be owned by the non-root runner"
    );
}

#[test]
fn policy_is_offline_complete_and_explicitly_not_hardware_qualification() {
    let policy = fs::read_to_string(workspace().join("scripts/check-repository-policy"))
        .expect("read repository policy gate");

    for required in [
        "cargo fmt --all -- --check",
        "cargo clippy --frozen --workspace --all-targets --all-features -- -D warnings",
        "cargo test --frozen --workspace --all-targets --all-features",
        "cargo deny --frozen check advisories bans licenses sources",
        "scripts/check-sensitive-history",
        "lychee --offline --no-progress",
        "schema/example, source-lock, patch-scope, and fake-platform lifecycle tests",
        "source checks only; not hardware qualification",
    ] {
        assert!(policy.contains(required), "missing policy gate: {required}");
    }

    assert!(policy.contains("export CARGO_NET_OFFLINE=true"));
    assert!(policy.contains("PT31553_RUN_SYSTEMD_LIFECYCLE"));
    assert!(policy.contains("PT31553_USE_SYSTEM_MANAGER"));
    assert!(!policy.contains("/sys/class/hwmon"));
}

#[test]
fn policy_rejects_live_lifecycle_opt_ins_before_invoking_tools() {
    let root = workspace();
    let output = Command::new("/usr/bin/bash")
        .arg(root.join("scripts/check-repository-policy"))
        .current_dir(&root)
        .env("PT31553_RUN_SYSTEMD_LIFECYCLE", "1")
        .env("PATH", "")
        .output()
        .expect("run repository policy gate");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("refusing live-hardware opt-in PT31553_RUN_SYSTEMD_LIFECYCLE")
    );
}
