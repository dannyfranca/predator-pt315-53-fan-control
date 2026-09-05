const README: &str = include_str!("../../../README.md");
const KERNEL_README: &str = include_str!("../../../packaging/kernel/README.md");

fn runbook() -> &'static str {
    README
        .split_once("## Canonical runbook: status, build, and disabled install")
        .expect("README must contain the canonical status/build/install runbook")
        .1
        .split_once("## Side-by-side candidate install and recovery")
        .expect("the canonical first section must precede the detailed recovery runbook")
        .0
}

fn assert_ordered(haystack: &str, needles: &[&str]) {
    let mut cursor = 0;
    for needle in needles {
        let offset = haystack[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered runbook step: {needle}"));
        cursor += offset + needle.len();
    }
}

fn section<'a>(runbook: &'a str, start: &str, end: &str) -> &'a str {
    runbook
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"))
        .0
}

fn command_arguments(source: &str) -> Vec<(String, String)> {
    let tokens = source
        .split_whitespace()
        .filter(|token| *token != "\\")
        .map(|token| token.trim_matches(['`', '"', '\'', ',', ';']).to_owned())
        .collect::<Vec<_>>();
    let mut arguments = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index].starts_with("--") {
            let value = tokens
                .get(index + 1)
                .unwrap_or_else(|| panic!("{} has no value", tokens[index]));
            assert!(
                !value.starts_with("--"),
                "{} is incorrectly bound to option {value}",
                tokens[index]
            );
            arguments.push((tokens[index].clone(), value.clone()));
            index += 2;
        } else {
            index += 1;
        }
    }
    arguments
}

#[test]
fn status_and_no_escape_hatch_boundary_are_conspicuous() {
    let runbook = runbook();
    let normalized = runbook.split_whitespace().collect::<Vec<_>>().join(" ");
    let opening = README
        .split_once("## Workspace")
        .expect("README must have an opening status before the workspace")
        .0
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        opening.contains("qualification-ready; this checkout is unqualified and not configured")
    );
    assert!(opening.contains("implements the production controller"));
    for statement in [
        "QUALIFICATION STATUS: UNQUALIFIED",
        "Firmware Auto (`2`)",
        "no escape hatch",
        "does not authorize Custom control",
        "Predator PT315-53",
        "Civic_TLS",
        "standard in-tree `acer_wmi` hwmon ABI",
        "no raw EC",
        "forced capabilities",
        "replacement module",
        "manual fan mode",
        "module unload",
    ] {
        assert!(runbook.contains(statement), "missing boundary: {statement}");
    }
    for statement in [
        "No fan controller, recovery helper, or Custom-control attempt may have run during the boot",
        "is permitted and required only after booting the candidate",
    ] {
        assert!(
            normalized.contains(statement),
            "missing normalized boundary: {statement}"
        );
    }
    assert!(runbook.contains("cargo run -p fan-control-daemon -- --status"));
    assert!(runbook.contains("cargo run -p fan-control-qualify\n"));
    assert!(!runbook.contains("cargo run -p fan-control-qualify -- supervised-endurance --help"));
}

#[test]
fn clean_controller_and_kernel_builds_are_checkable() {
    let runbook = runbook();
    for command in [
        "source_revision=$(git rev-parse HEAD)",
        "git status --porcelain=v1 --untracked-files=all",
        "scripts/check-repository-policy",
        "scripts/build-source-candidate",
        "pacman-key --verify",
        "candidate-identity-v1.json",
        "--controller-key \"$PT31553_CONTROLLER_KEY\"",
    ] {
        assert!(runbook.contains(command), "missing build check: {command}");
    }
    assert!(runbook.contains("CARGO_NET_OFFLINE=true"));

    let clean_source = section(
        runbook,
        "### 3. Build and verify from a clean source state",
        "Assemble `/bundle` exactly as specified",
    );
    assert_ordered(
        clean_source,
        &[
            "source_root=$(git rev-parse --show-toplevel)",
            "source_revision=$(git rev-parse HEAD)",
            "test \"$(git rev-parse --is-shallow-repository)\" = false",
            "test -z \"$(git status --porcelain=v1 --untracked-files=all)\"",
            "cargo fetch --locked",
            "cargo deny fetch",
            "CARGO_NET_OFFLINE=true scripts/check-repository-policy",
            "controller_source_revision=$(/usr/bin/sed -n",
            "/usr/bin/realpath --canonicalize-existing --no-symlinks \"$controller_cargo_home\"",
            "/usr/bin/stat -c %u \"$controller_cargo_home\"",
            "8#$controller_cargo_home_mode & 8#077",
            "cleanup_controller_worktree()",
            "trap cleanup_controller_worktree EXIT HUP INT TERM",
            "git worktree add --detach \"$controller_source_checkout\" \"$controller_source_revision\"",
            "CARGO_HOME=\"$controller_cargo_home\" cargo fetch --locked",
            "--manifest-path \"$controller_source_checkout/Cargo.toml\"",
            "git worktree remove \"$controller_source_checkout\"",
            "/usr/bin/rmdir \"$controller_worktree_parent\"",
            "trap - EXIT HUP INT TERM",
        ],
    );
    assert!(clean_source.contains(
        "git -C \"$source_root\" worktree remove --force \"$controller_source_checkout\""
    ));
    assert!(KERNEL_README.contains("Top-level README step 3 is the sole canonical"));
    assert!(
        KERNEL_README
            .contains("$(dirname \"$source_root\")/pt31553-source-candidate-$source_revision")
    );
    assert!(!KERNEL_README.contains("/absolute/path/to/new-source-candidate"));

    let candidate = section(
        runbook,
        "Assemble `/bundle` exactly as specified",
        "The command fails before publication",
    );
    assert_ordered(
        candidate,
        &[
            "source_root=$(git rev-parse --show-toplevel)",
            "source_revision=$(git rev-parse HEAD)",
            "PT31553_PACKAGE_CERT_SHA256",
            "PT31553_MODULE_CERT_SHA256",
            "PT31553_KERNEL_CERT_SHA256",
            "test -d \"$PT31553_BUNDLE\"",
            "candidate_output=\"$(dirname \"$source_root\")/pt31553-source-candidate-$source_revision\"",
            "test ! -e \"$candidate_output\"",
            "scripts/build-source-candidate",
            "--bundle \"$PT31553_BUNDLE\"",
            "--kernel-signing-dir \"$PT31553_KERNEL_SIGNING_DIR\"",
            "--package-cert \"$PT31553_PACKAGE_CERT\"",
            "--package-cert-sha256 \"$PT31553_PACKAGE_CERT_SHA256\"",
            "--package-key \"$PT31553_PACKAGE_KEY\"",
            "--module-cert-sha256 \"$PT31553_MODULE_CERT_SHA256\"",
            "--kernel-cert \"$PT31553_KERNEL_CERT\"",
            "--kernel-cert-sha256 \"$PT31553_KERNEL_CERT_SHA256\"",
            "--cargo-home \"$controller_cargo_home\"",
            "--controller-gnupg-home \"$PT31553_CONTROLLER_GNUPG_HOME\"",
            "--controller-key \"$PT31553_CONTROLLER_KEY\"",
            "--output \"$candidate_output\"",
        ],
    );
    let documented_command = candidate
        .split_once("scripts/build-source-candidate")
        .unwrap()
        .1
        .split_once("\n```")
        .unwrap()
        .0;
    let builder = include_str!("../../../scripts/build-source-candidate");
    let executable_usage = builder
        .split_once("usage: scripts/build-source-candidate")
        .unwrap()
        .1
        .split_once("\n\nBuilds")
        .unwrap()
        .0;
    let documented_arguments = command_arguments(documented_command);
    let usage_arguments = command_arguments(executable_usage);
    assert_eq!(
        documented_arguments
            .iter()
            .map(|(flag, _)| flag)
            .collect::<Vec<_>>(),
        usage_arguments
            .iter()
            .map(|(flag, _)| flag)
            .collect::<Vec<_>>(),
        "README candidate command drifted from the executable interface"
    );
    assert_eq!(
        documented_arguments,
        [
            ("--bundle".into(), "$PT31553_BUNDLE".into()),
            (
                "--kernel-signing-dir".into(),
                "$PT31553_KERNEL_SIGNING_DIR".into(),
            ),
            ("--package-cert".into(), "$PT31553_PACKAGE_CERT".into()),
            (
                "--package-cert-sha256".into(),
                "$PT31553_PACKAGE_CERT_SHA256".into(),
            ),
            ("--package-key".into(), "$PT31553_PACKAGE_KEY".into()),
            (
                "--module-cert-sha256".into(),
                "$PT31553_MODULE_CERT_SHA256".into(),
            ),
            ("--kernel-cert".into(), "$PT31553_KERNEL_CERT".into()),
            (
                "--kernel-cert-sha256".into(),
                "$PT31553_KERNEL_CERT_SHA256".into(),
            ),
            ("--cargo-home".into(), "$controller_cargo_home".into()),
            (
                "--controller-gnupg-home".into(),
                "$PT31553_CONTROLLER_GNUPG_HOME".into(),
            ),
            ("--controller-key".into(), "$PT31553_CONTROLLER_KEY".into(),),
            ("--output".into(), "$candidate_output".into()),
        ],
        "README candidate values drifted or became misbound"
    );
    assert!(candidate.contains(
        "pt31553-source-candidate-$source_revision/{kernel,controller,declarations,signatures}"
    ));
    for boundary in [
        "dirty source revision",
        "placeholder identity",
        "reused signer",
        "never installs a package",
        "runs Cargo offline",
        "environment overrides are rejected",
        "invokes GitHub Actions",
        "All hashes, signer fingerprints",
        "explicitly **UNQUALIFIED**",
        "`disabled-only`",
    ] {
        assert!(
            runbook.contains(boundary),
            "missing candidate boundary: {boundary}"
        );
    }
    assert!(
        runbook
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("changes a boot default")
    );
}

#[test]
fn first_install_and_boot_preserve_recovery_and_disabled_units() {
    let runbook = runbook();
    let install = section(
        runbook,
        "### 4. Install the controller disabled",
        "### 5. Perform the first disabled candidate boot",
    );
    assert_ordered(
        runbook,
        &[
            "### 4. Install the controller disabled",
            "pacman -U \"$controller_package\"",
            "systemctl is-enabled \"$unit\"",
            "### 5. Perform the first disabled candidate boot",
            "Record the stock recovery entries",
            "Install without changing the default",
            "Boot the candidate once",
        ],
    );
    assert!(runbook.contains("linux-cachyos-lts"));
    assert!(runbook.contains("pt31553-fand.service"));
    assert!(runbook.contains("pt31553-fan-sleep-guard.service"));
    assert!(
        runbook.contains("for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do")
    );
    assert_ordered(
        install,
        &[
            "source_root=$(git rev-parse --show-toplevel)",
            "source_revision=$(git -C \"$source_root\" rev-parse HEAD)",
            "candidate_output=\"$(dirname \"$source_root\")/pt31553-source-candidate-$source_revision\"",
            "approved_candidate_manifest_sha256=REPLACE_WITH_APPROVED_CANDIDATE_MANIFEST_SHA256",
            "approved_controller_signer_fingerprint=REPLACE_WITH_APPROVED_CONTROLLER_SIGNER_FINGERPRINT",
            "candidate_manifest=\"$candidate_output/declarations/candidate-identity-v1.json\"",
            "sha256sum \"$candidate_manifest\"",
            "assert record[\"qualification_status\"] == \"unqualified\"",
            "\"allowed_state\": \"disabled-only\"",
            "test \"$(/usr/bin/sha256sum \"$controller_package\"",
            "test \"$(/usr/bin/sha256sum \"$controller_signature\"",
            "test \"$(/usr/bin/pacman -Qp \"$controller_package\")\"",
            "/usr/bin/pacman-key --verify \"$controller_signature\" \"$controller_package\"",
            "--homedir /etc/pacman.d/gnupg --status-fd 1",
            "test \"$actual_controller_signer\" = \"$controller_signer_fingerprint\"",
            "usr/share/pt31553-fan-control/source-commit",
            "cmp \"$candidate_compatibility\" \"$controller_check/compatibility.toml\"",
            "enabled_state=$(/usr/bin/systemctl is-enabled \"$unit\" 2>/dev/null || true)",
            "not-found) ;;",
            "disabled)",
            "test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive",
            "sudo /usr/bin/pacman -U \"$controller_package\"",
            "test \"$(/usr/bin/systemctl is-enabled \"$unit\")\" = disabled",
            "test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive",
            "! /usr/bin/pgrep -x pt31553-fand >/dev/null",
        ],
    );
    assert!(runbook.contains("test \"$(/usr/bin/systemctl is-enabled \"$unit\")\" = disabled"));
    assert!(
        runbook.contains("test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive")
    );
    assert!(!runbook.contains("systemctl enable pt31553-fand.service"));
    assert!(!runbook.contains("systemctl start pt31553-fand.service"));
    assert!(!install.contains("pt31553-fan-restore --restore"));

    let stock_recording = section(
        README,
        "### Record the stock recovery entries",
        "### Install without changing the default",
    );
    assert!(!stock_recording.contains("pt31553-fan-restore --restore"));

    let kernel_install = section(
        README,
        "### Install without changing the default",
        "## Canonical runbook: qualification and operation",
    );
    assert_ordered(
        kernel_install,
        &[
            "source_root=$(git rev-parse --show-toplevel)",
            "source_revision=$(git -C \"$source_root\" rev-parse HEAD)",
            "candidate_output=\"$(dirname \"$source_root\")/pt31553-source-candidate-$source_revision\"",
            "artifact_dir=\"$candidate_output/kernel\"",
            "provenance_record=\"$candidate_output/declarations/package-provenance-v1.json\"",
            "package_manifest_signature=\"$candidate_output/signatures/package-set.p7s\"",
            "assert candidate[\"qualification_status\"] == \"unqualified\"",
            "candidate[\"package_set\"][\"provenance_sha256\"]",
            "candidate[\"package_set\"][\"manifest_signature_sha256\"]",
            "scripts/verify-package-provenance",
            "/usr/bin/cmp \"$provenance_record\"",
        ],
    );
}

#[test]
fn editable_and_authority_artifacts_have_distinct_roles() {
    let runbook = runbook();
    for (artifact, classification) in [
        (
            "/etc/pt31553-fan-control/config.toml",
            "Editable, never authority",
        ),
        (
            "/usr/lib/pt31553-fan-control/compatibility.toml",
            "Static declaration only; it is not observed qualification",
        ),
        ("protected policy snapshot", "Safety authority"),
        (
            "/var/lib/pt31553-fan-control/qualification.json",
            "Safety authority",
        ),
        (
            "/var/lib/pt31553-fan-control/evidence/supervised-endurance.json",
            "Safety authority input; private by default",
        ),
        ("package-provenance-v1.json", "Prerequisite, not authority"),
        ("promotion.json", "Public claim, not runtime authority"),
    ] {
        let row = runbook
            .lines()
            .find(|line| line.starts_with('|') && line.contains(artifact))
            .unwrap_or_else(|| panic!("missing artifact row: {artifact}"));
        assert!(
            row.contains(classification),
            "artifact row for {artifact} lacks classification: {classification}"
        );
    }
}
