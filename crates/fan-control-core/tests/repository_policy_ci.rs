use serde_yaml::{Mapping, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn field<'a>(mapping: &'a Mapping, name: &str) -> &'a Value {
    mapping
        .get(Value::String(name.to_owned()))
        .unwrap_or_else(|| panic!("missing workflow field: {name}"))
}

fn assert_fields(mapping: &Mapping, expected: &[&str]) {
    assert_eq!(mapping.len(), expected.len(), "unexpected workflow fields");
    for name in expected {
        assert!(
            mapping.contains_key(Value::String((*name).to_owned())),
            "missing workflow field: {name}"
        );
    }
}

fn named_step<'a>(steps: &'a [Value], index: usize, name: &str) -> &'a Mapping {
    let step = steps[index]
        .as_mapping()
        .unwrap_or_else(|| panic!("workflow step {index} is a mapping"));
    assert_fields(step, &["name", "run"]);
    assert_eq!(field(step, "name").as_str(), Some(name));
    step
}

fn script_lines(value: &Value) -> Vec<&str> {
    value
        .as_str()
        .expect("workflow script is a string")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

#[test]
fn workflow_runs_the_complete_policy_only_when_manually_requested() {
    let source = fs::read_to_string(workspace().join(".github/workflows/repository-policy.yml"))
        .expect("read repository policy workflow");
    let workflow: Value = serde_yaml::from_str(&source).expect("parse repository policy workflow");
    let workflow = workflow.as_mapping().expect("workflow root is a mapping");
    assert_fields(workflow, &["name", "on", "permissions", "jobs"]);

    let triggers = field(workflow, "on")
        .as_mapping()
        .expect("workflow triggers are a mapping");
    assert_eq!(triggers.len(), 1, "repository policy must be manual-only");
    assert!(triggers.contains_key(Value::String("workflow_dispatch".into())));

    let permissions = field(workflow, "permissions")
        .as_mapping()
        .expect("workflow permissions are a mapping");
    assert_eq!(permissions.len(), 1, "workflow has only read access");
    assert_eq!(field(permissions, "contents").as_str(), Some("read"));

    let jobs = field(workflow, "jobs")
        .as_mapping()
        .expect("workflow jobs are a mapping");
    assert_eq!(jobs.len(), 1, "repository policy is the only job");
    let policy = field(jobs, "policy")
        .as_mapping()
        .expect("policy job is a mapping");
    assert_fields(policy, &["runs-on", "container", "steps"]);
    assert_eq!(field(policy, "runs-on").as_str(), Some("ubuntu-latest"));
    assert_eq!(
        field(policy, "container").as_str(),
        Some("archlinux:base-devel")
    );
    assert!(!policy.contains_key(Value::String("permissions".into())));

    let steps = field(policy, "steps")
        .as_sequence()
        .expect("policy steps are a sequence");
    assert_eq!(steps.len(), 6, "policy job has only the required steps");

    let install = named_step(steps, 0, "Install policy tooling");
    assert_eq!(
        script_lines(field(install, "run")),
        vec![
            "pacman -Syu --noconfirm cargo-deny git gnupg kmod libarchive lychee openssl \\",
            "python rustup sbsigntools systemd zstd",
            "useradd --create-home builder",
        ]
    );

    let checkout = steps[1].as_mapping().expect("checkout step is a mapping");
    assert_eq!(checkout.len(), 2, "checkout has only uses and with fields");
    assert_eq!(
        field(checkout, "uses").as_str(),
        Some("actions/checkout@v4")
    );
    let checkout_options = field(checkout, "with")
        .as_mapping()
        .expect("checkout options are a mapping");
    assert_eq!(checkout_options.len(), 1);
    assert_eq!(field(checkout_options, "fetch-depth").as_i64(), Some(0));

    let chown = named_step(steps, 2, "Prepare non-root checkout");
    assert_eq!(
        field(chown, "run").as_str().map(str::trim),
        Some("chown -R builder:builder \"$GITHUB_WORKSPACE\"")
    );

    let toolchain = named_step(steps, 3, "Select the supported Rust toolchain");
    assert_eq!(
        script_lines(field(toolchain, "run")),
        vec![
            "su builder -c 'rustup toolchain install 1.85.0 --profile minimal --component clippy --component rustfmt'",
            "su builder -c \"cd '$GITHUB_WORKSPACE' && rustup override set 1.85.0\"",
        ]
    );

    let prepare = named_step(steps, 4, "Prepare locked dependency and advisory inputs");
    assert_eq!(
        script_lines(field(prepare, "run")),
        vec![
            "su builder -c \"cd '$GITHUB_WORKSPACE' && cargo fetch --locked\"",
            "su builder -c \"cd '$GITHUB_WORKSPACE' && cargo deny fetch\"",
        ]
    );

    let run = named_step(steps, 5, "Run offline read-only repository policy");
    assert_eq!(
        field(run, "run").as_str().map(str::trim),
        Some(
            "su builder -c \"cd '$GITHUB_WORKSPACE' && CARGO_NET_OFFLINE=true scripts/check-repository-policy\""
        )
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
