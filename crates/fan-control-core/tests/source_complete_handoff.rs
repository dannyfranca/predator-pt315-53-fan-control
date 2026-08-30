use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

mod support;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(command: &mut Command, context: &str) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("{context}: {error}"))
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable fixture");
    let mut permissions = fs::metadata(path)
        .expect("stat executable fixture")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod executable fixture");
}

struct HandoffSandbox {
    root: TempDir,
    repository: PathBuf,
    command_path: PathBuf,
}

impl HandoffSandbox {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("pt31553-source-complete-")
            .tempdir()
            .expect("create source-complete sandbox");
        let repository = root.path().join("repository");
        let archive = root.path().join("source.tar");
        let command_path = root.path().join("test-bin");
        fs::create_dir(&repository).expect("create sandbox repository");
        fs::create_dir(&command_path).expect("create command fixture directory");

        let archived = run(
            Command::new("git")
                .current_dir(workspace())
                .args(["archive", "--format=tar", "HEAD", "-o"])
                .arg(&archive),
            "archive repository",
        );
        assert!(archived.status.success(), "git archive failed");
        let extracted = run(
            Command::new("tar")
                .args(["-xf"])
                .arg(&archive)
                .args(["-C"])
                .arg(&repository),
            "extract repository",
        );
        assert!(extracted.status.success(), "tar extraction failed");

        for overlay in [
            "crates/fan-control-core/tests/source_complete_handoff.rs",
            "handoff/source-complete-files.txt",
            "policy/README.md",
            "policy/qualified-envelope.example.toml",
            "schemas/qualification-record.json",
            "scripts/verify-source-complete-handoff",
            "skills/predator-fan-control/SKILL.md",
            "skills/predator-fan-control/agents/openai.yaml",
            "skills/predator-fan-control/references/configuration.md",
            "skills/predator-fan-control/references/operations.md",
            "skills/predator-fan-control/references/recovery.md",
            "skills/predator-fan-control/references/safety.md",
            "skills/predator-fan-control/references/support.md",
            "upstream/README.md",
        ] {
            let destination = repository.join(overlay);
            fs::create_dir_all(destination.parent().unwrap()).expect("create overlay parent");
            fs::copy(workspace().join(overlay), destination).expect("copy implementation overlay");
        }
        let handoff_command = repository.join("scripts/verify-source-complete-handoff");
        let mut permissions = fs::metadata(&handoff_command).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&handoff_command, permissions).unwrap();
        write_executable(
            &command_path.join("cargo"),
            "#!/bin/sh\nset -eu\ntest \"${CARGO_NET_OFFLINE:-}\" = true\ntest -n \"${CARGO_TARGET_DIR:-}\"\ntest -z \"$(find \"$CARGO_TARGET_DIR\" -mindepth 1 -print -quit)\"\nprintf '%s\\n' 'clean-build-stub-ran'\ntouch \"$CARGO_TARGET_DIR/clean-build-stub\"\n",
        );
        write_executable(
            &repository.join("scripts/check-repository-policy"),
            "#!/bin/sh\nset -eu\ntest \"${CARGO_NET_OFFLINE:-}\" = true\ntest -f \"${CARGO_TARGET_DIR:?}/clean-build-stub\"\nprintf '%s\\n' 'policy-stub-ran'\n",
        );

        for arguments in [
            vec!["init", "-q"],
            vec!["config", "user.name", "Source Complete Test"],
            vec!["config", "user.email", "source-complete@example.invalid"],
            vec!["add", "-A"],
            vec!["commit", "-q", "-m", "fixture"],
        ] {
            let output = run(
                Command::new("git").current_dir(&repository).args(arguments),
                "initialize sandbox repository",
            );
            assert!(output.status.success(), "sandbox git command failed");
        }

        Self {
            root,
            repository,
            command_path,
        }
    }

    fn verify(&self) -> Output {
        run(
            Command::new(
                self.repository
                    .join("scripts/verify-source-complete-handoff"),
            )
            .current_dir(&self.repository)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.command_path.display(),
                    env::var("PATH").expect("PATH is set")
                ),
            )
            .env_remove("PT31553_RUN_SYSTEMD_LIFECYCLE")
            .env_remove("PT31553_USE_SYSTEM_MANAGER"),
            "run source-complete handoff command",
        )
    }

    fn replace_policy(&self, contents: &str) {
        write_executable(
            &self.repository.join("scripts/check-repository-policy"),
            contents,
        );
        for arguments in [
            vec!["add", "scripts/check-repository-policy"],
            vec!["commit", "-q", "-m", "replace policy fixture"],
        ] {
            let output = run(
                Command::new("git")
                    .current_dir(&self.repository)
                    .args(arguments),
                "commit replacement policy fixture",
            );
            assert!(output.status.success());
        }
    }

    fn commit(&self, arguments: &[&str], message: &str) {
        let output = run(
            Command::new("git")
                .current_dir(&self.repository)
                .args(arguments),
            message,
        );
        assert!(output.status.success(), "{message}");
    }
}

#[test]
fn clean_handoff_runs_the_full_policy_and_labels_only_source_completeness() {
    let sandbox = HandoffSandbox::new();
    let output = sandbox.verify();
    assert!(
        output.status.success(),
        "clean handoff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("clean-build-stub-ran"));
    assert!(stdout.contains("policy-stub-ran"));
    assert!(stdout.contains("Source-complete handoff passed"));
    assert!(stdout.contains("not hardware qualification"));
    assert!(stdout.contains("not Custom-control authorization"));
    assert!(stdout.contains("not artifact promotion"));

    fs::write(
        sandbox.repository.join("untracked-source.txt"),
        "dirty source-complete fixture\n",
    )
    .expect("write untracked dirtiness");
    let dirty = sandbox.verify();
    assert!(!dirty.status.success());
    assert!(String::from_utf8_lossy(&dirty.stderr).contains("source tree is not clean"));
    assert!(!String::from_utf8_lossy(&dirty.stdout).contains("policy-stub-ran"));

    assert!(sandbox.root.path().is_dir());
}

#[test]
fn missing_required_public_component_fails_before_the_policy() {
    let sandbox = HandoffSandbox::new();
    fs::remove_file(sandbox.repository.join("systemd/pt31553-fand.service"))
        .expect("remove required unit");
    for arguments in [
        vec!["add", "-u"],
        vec!["commit", "-q", "-m", "remove required unit"],
    ] {
        let output = run(
            Command::new("git")
                .current_dir(&sandbox.repository)
                .args(arguments),
            "commit missing component fixture",
        );
        assert!(output.status.success());
    }

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("tracked file set does not exactly match")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("policy-stub-ran"));
}

#[test]
fn unexpected_tracked_file_fails_before_the_policy() {
    let sandbox = HandoffSandbox::new();
    fs::write(sandbox.repository.join("schemas/unreviewed.json"), "{}\n")
        .expect("write unexpected schema");
    sandbox.commit(
        &["add", "schemas/unreviewed.json"],
        "stage unexpected schema",
    );
    sandbox.commit(
        &["commit", "-q", "-m", "add unexpected schema"],
        "commit unexpected schema",
    );

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("tracked file set does not exactly match")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("clean-build-stub-ran"));
}

#[test]
fn manifest_without_final_newline_is_rejected() {
    let sandbox = HandoffSandbox::new();
    let manifest = sandbox.repository.join("handoff/source-complete-files.txt");
    let source = fs::read_to_string(&manifest).unwrap();
    fs::write(&manifest, source.strip_suffix('\n').unwrap()).unwrap();
    sandbox.commit(
        &["add", "handoff/source-complete-files.txt"],
        "stage manifest",
    );
    sandbox.commit(
        &["commit", "-q", "-m", "remove manifest newline"],
        "commit manifest without newline",
    );

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must end with a newline"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("clean-build-stub-ran"));
}

#[test]
fn assume_unchanged_cannot_hide_modified_handoff_content() {
    let sandbox = HandoffSandbox::new();
    sandbox.commit(
        &["update-index", "--assume-unchanged", "README.md"],
        "mark README assume-unchanged",
    );
    fs::write(sandbox.repository.join("README.md"), "hidden mutation\n").unwrap();

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nondefault Git index flag"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("clean-build-stub-ran"));
}

#[test]
fn policy_cannot_hide_mutation_with_an_index_flag() {
    let sandbox = HandoffSandbox::new();
    sandbox.replace_policy(
        "#!/bin/sh\nset -eu\ngit update-index --assume-unchanged README.md\nprintf '%s\\n' hidden >> README.md\n",
    );

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nondefault Git index flag"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Source-complete handoff passed"));
}

#[test]
fn policy_failure_prevents_source_complete_success() {
    let sandbox = HandoffSandbox::new();
    sandbox.replace_policy("#!/bin/sh\nset -eu\nprintf '%s\\n' 'policy-stub-ran'\nexit 23\n");

    let output = sandbox.verify();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("policy-stub-ran"));
    assert!(!stdout.contains("Source-complete handoff passed"));
}

#[test]
fn policy_that_dirties_the_tree_prevents_source_complete_success() {
    let sandbox = HandoffSandbox::new();
    sandbox.replace_policy(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' 'policy-stub-ran'\nprintf '%s\\n' dirty >> README.md\n",
    );

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source tree is not clean"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("policy-stub-ran"));
    assert!(!stdout.contains("Source-complete handoff passed"));
}

#[test]
fn policy_that_commits_a_tree_change_prevents_source_complete_success() {
    let sandbox = HandoffSandbox::new();
    sandbox.replace_policy(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' committed >> README.md\ngit add README.md\ngit commit -q -m committed-policy-mutation\n",
    );

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("repository revision changed during verification")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Source-complete handoff passed"));
}

#[test]
fn shallow_repository_cannot_claim_source_completeness() {
    let sandbox = HandoffSandbox::new();
    let head = run(
        Command::new("git")
            .current_dir(&sandbox.repository)
            .args(["rev-parse", "HEAD"]),
        "read fixture revision",
    );
    assert!(head.status.success());
    fs::write(sandbox.repository.join(".git/shallow"), head.stdout)
        .expect("mark fixture repository shallow");

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("repository is shallow"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("clean-build-stub-ran"));
}

#[test]
fn non_executable_index_mode_cannot_be_hidden_by_worktree_permissions() {
    let sandbox = HandoffSandbox::new();
    sandbox.commit(
        &[
            "update-index",
            "--chmod=-x",
            "scripts/check-sensitive-history",
        ],
        "remove executable index mode",
    );
    sandbox.commit(
        &["commit", "-q", "-m", "remove executable mode"],
        "commit mode drift",
    );
    sandbox.commit(
        &["config", "core.fileMode", "false"],
        "ignore worktree executable mode",
    );

    let path = sandbox.repository.join("scripts/check-sensitive-history");
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();

    let output = sandbox.verify();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not executable in Git"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("clean-build-stub-ran"));
}

#[test]
fn qualification_record_schema_matches_the_runtime_record_shape() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/qualification-record.json"
    )))
    .unwrap();
    let record: serde_json::Value =
        serde_json::from_str(&support::matching_record(support::PROTECTED_POLICY)).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(&record)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "{errors:#?}");

    let mut incomplete = record;
    incomplete
        .as_object_mut()
        .unwrap()
        .remove("supervised_endurance");
    assert!(!validator.is_valid(&incomplete));
}

#[test]
fn protected_policy_example_is_parseable_and_explicitly_non_authoritative() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../policy/qualified-envelope.example.toml"
    ));
    let example: toml::Value = toml::from_str(source).unwrap();
    assert_eq!(example["schema_version"].as_integer(), Some(2));
    assert!(source.contains("FORMAT EXAMPLE ONLY"));
    assert!(source.contains("cannot authorize Custom control"));
    assert!(source.contains(&"0".repeat(64)));
}
