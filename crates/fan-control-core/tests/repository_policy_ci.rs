use serde_yaml::{Mapping, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

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

fn encoded_command(program: &str, arguments: &[&str]) -> String {
    let mut command = program.to_owned();
    for argument in arguments {
        command.push('\u{1f}');
        command.push_str(argument);
    }
    command
}

struct PolicySandbox {
    root: TempDir,
    log: PathBuf,
    markdown_output: String,
}

impl PolicySandbox {
    fn new(markdown_output: &str) -> Self {
        let root = tempfile::Builder::new()
            .prefix("pt31553-policy-")
            .tempdir()
            .expect("create policy sandbox");
        let bin = root.path().join("bin");
        let scripts = root.path().join("scripts");
        fs::create_dir_all(&bin).expect("create policy stub bin directory");
        fs::create_dir_all(&scripts).expect("create policy stub scripts directory");
        fs::create_dir(root.path().join("launch")).expect("create policy launch directory");

        write_executable(
            &bin.join("git"),
            r#"#!/usr/bin/bash
command=git
for argument in "$@"; do
    command+=$'\x1f'"$argument"
done
event="$command cwd=$PWD"
printf '%s\n' "$event" >> "$POLICY_TEST_LOG"
[[ ${POLICY_TEST_FAIL:-} != "$event" ]] || exit 1
if [[ $command == "git"$'\x1f'"rev-parse"$'\x1f'"--show-toplevel" ]]; then
    printf '%s\n' "$POLICY_TEST_ROOT"
elif [[ $command == "git"$'\x1f'"ls-files"$'\x1f'"*.md" ]]; then
    printf '%s' "$POLICY_TEST_MARKDOWN_OUTPUT"
else
    exit 2
fi
"#,
        );
        write_executable(
            &bin.join("cargo"),
            r#"#!/usr/bin/bash
command=cargo
for argument in "$@"; do
    command+=$'\x1f'"$argument"
done
printf '%s\n' "$command" >> "$POLICY_TEST_LOG"
[[ ${POLICY_TEST_FAIL:-} != "$command" ]]
"#,
        );
        write_executable(
            &bin.join("lychee"),
            r#"#!/usr/bin/bash
command=lychee
for argument in "$@"; do
    command+=$'\x1f'"$argument"
done
printf '%s\n' "$command" >> "$POLICY_TEST_LOG"
[[ ${POLICY_TEST_FAIL:-} != "$command" ]]
"#,
        );
        write_executable(
            &scripts.join("check-sensitive-history"),
            r#"#!/usr/bin/bash
command=sensitive-history
printf '%s\n' "$command" >> "$POLICY_TEST_LOG"
[[ ${POLICY_TEST_FAIL:-} != "$command" ]]
"#,
        );

        Self {
            log: root.path().join("commands.log"),
            root,
            markdown_output: markdown_output.to_owned(),
        }
    }

    fn run(&self, failure: Option<&str>) -> std::process::Output {
        let mut command = Command::new("/usr/bin/bash");
        command
            .env_clear()
            .arg(workspace().join("scripts/check-repository-policy"))
            .current_dir(self.root.path().join("launch"))
            .env("PATH", self.root.path().join("bin"))
            .env("POLICY_TEST_ROOT", self.root.path())
            .env("POLICY_TEST_LOG", &self.log)
            .env("POLICY_TEST_MARKDOWN_OUTPUT", &self.markdown_output)
            .env_remove("PT31553_RUN_SYSTEMD_LIFECYCLE")
            .env_remove("PT31553_USE_SYSTEM_MANAGER");
        if let Some(failure) = failure {
            command.env("POLICY_TEST_FAIL", failure);
        }
        command.output().expect("run instrumented policy gate")
    }

    fn commands(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .expect("read policy command log")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn expected_commands(&self) -> Vec<String> {
        let markdown_files = self.markdown_output.lines().collect::<Vec<_>>();
        let lychee_arguments = ["--offline", "--no-progress"]
            .into_iter()
            .chain(markdown_files)
            .collect::<Vec<_>>();

        vec![
            format!(
                "{} cwd={}",
                encoded_command("git", &["rev-parse", "--show-toplevel"]),
                self.root.path().join("launch").display()
            ),
            encoded_command("cargo", &["fmt", "--all", "--", "--check"]),
            encoded_command(
                "cargo",
                &[
                    "clippy",
                    "--frozen",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
            encoded_command(
                "cargo",
                &[
                    "test",
                    "--frozen",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                ],
            ),
            encoded_command(
                "cargo",
                &[
                    "deny",
                    "--frozen",
                    "check",
                    "advisories",
                    "bans",
                    "licenses",
                    "sources",
                ],
            ),
            "sensitive-history".into(),
            format!(
                "{} cwd={}",
                encoded_command("git", &["ls-files", "*.md"]),
                self.root.path().display()
            ),
            encoded_command("lychee", &lychee_arguments),
        ]
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write policy stub");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("make policy stub executable");
}

#[test]
fn every_github_workflow_is_manual_only() {
    let workflows = workspace().join(".github/workflows");
    let mut paths = fs::read_dir(&workflows)
        .expect("read workflow directory")
        .filter_map(|entry| {
            let entry = entry.expect("read workflow entry");
            let file_type = entry.file_type().expect("read workflow entry type");
            let path = entry.path();
            (file_type.is_file()
                && matches!(
                    path.extension().and_then(|value| value.to_str()),
                    Some("yml" | "yaml")
                ))
            .then_some(path)
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert!(!paths.is_empty(), "repository has no workflows to verify");

    for path in paths {
        let display = path.display();
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read workflow {display}: {error}"));
        let workflow: Value = serde_yaml::from_str(&source)
            .unwrap_or_else(|error| panic!("parse workflow {display}: {error}"));
        let workflow = workflow
            .as_mapping()
            .unwrap_or_else(|| panic!("workflow root is a mapping: {display}"));
        let trigger_value = workflow
            .get(Value::String("on".into()))
            .unwrap_or_else(|| panic!("workflow has an on field: {display}"));
        let mut triggers = match trigger_value {
            Value::String(trigger) => vec![trigger.as_str()],
            Value::Sequence(triggers) => triggers
                .iter()
                .map(|trigger| {
                    trigger
                        .as_str()
                        .unwrap_or_else(|| panic!("workflow trigger is a string: {display}"))
                })
                .collect(),
            Value::Mapping(triggers) => triggers
                .keys()
                .map(|trigger| {
                    trigger
                        .as_str()
                        .unwrap_or_else(|| panic!("workflow trigger is a string: {display}"))
                })
                .collect(),
            _ => panic!("workflow triggers use a supported YAML form: {display}"),
        };
        triggers.sort_unstable();
        assert_eq!(triggers, ["workflow_dispatch"], "{display} is manual-only");
    }
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
    assert_eq!(checkout_options.len(), 2);
    assert_eq!(field(checkout_options, "fetch-depth").as_i64(), Some(0));
    assert_eq!(
        field(checkout_options, "persist-credentials").as_bool(),
        Some(false)
    );

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
fn dependency_policy_is_fail_closed_and_explicit() {
    let source = fs::read_to_string(workspace().join("deny.toml")).expect("read dependency policy");
    let actual: toml::Value = toml::from_str(&source).expect("parse dependency policy");
    let expected: toml::Value = toml::from_str(
        r#"
[graph]
targets = ["x86_64-unknown-linux-gnu"]
all-features = true

[advisories]
ignore = []

[licenses]
allow = ["Apache-2.0", "MIT", "MIT-0", "Unicode-3.0"]
confidence-threshold = 0.8

[licenses.private]
ignore = false

[bans]
multiple-versions = "warn"
wildcards = "deny"
allow-wildcard-paths = true
highlight = "all"
allow = []
deny = []
skip = []
skip-tree = []

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
"#,
    )
    .expect("parse expected dependency policy");

    assert_eq!(actual, expected, "deny.toml policy changed");
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
fn policy_executes_every_gate_in_order_and_stops_at_the_first_failure() {
    let success = PolicySandbox::new("README.md\n");
    let expected = success.expected_commands();
    let output = success.run(None);
    assert!(output.status.success());
    assert_eq!(success.commands(), expected);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).lines().last(),
        Some("repository policy passed: source checks only; not hardware qualification")
    );

    for failed_index in 0..expected.len() {
        let failure = PolicySandbox::new("README.md\n");
        let expected = failure.expected_commands();
        let output = failure.run(Some(&expected[failed_index]));
        assert!(
            !output.status.success(),
            "policy accepted failed command: {}",
            expected[failed_index]
        );
        assert_eq!(failure.commands(), expected[..=failed_index]);
    }
}

#[test]
fn policy_preserves_empty_and_space_containing_markdown_lists() {
    for markdown_output in ["", "README.md\ndocs/a b.md\n"] {
        let sandbox = PolicySandbox::new(markdown_output);
        let output = sandbox.run(None);
        assert!(output.status.success());
        assert_eq!(sandbox.commands(), sandbox.expected_commands());
    }
}

#[test]
fn policy_rejects_live_lifecycle_opt_ins_before_invoking_tools() {
    let root = workspace();
    for live_opt_in in [
        "PT31553_RUN_SYSTEMD_LIFECYCLE",
        "PT31553_USE_SYSTEM_MANAGER",
    ] {
        let output = Command::new("/usr/bin/bash")
            .arg(root.join("scripts/check-repository-policy"))
            .current_dir(&root)
            .env_clear()
            .env(live_opt_in, "1")
            .env("PATH", "")
            .output()
            .expect("run repository policy gate");

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains(&format!("refusing live-hardware opt-in {live_opt_in}"))
        );
    }
}
