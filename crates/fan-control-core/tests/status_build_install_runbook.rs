const README: &str = include_str!("../../../README.md");

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
    assert!(opening.contains(
        "supports only the documented build and disabled package installation; it does not yet authorize Custom fan control or service enablement"
    ));
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
    assert!(runbook.contains("cargo run -p fan-control-qualify\n"));
    assert!(!runbook.contains("cargo run -p fan-control-qualify -- supervised-endurance --help"));
}

#[test]
fn clean_controller_and_kernel_builds_are_checkable() {
    let runbook = runbook();
    for command in [
        "git clone --no-checkout",
        "git status --porcelain=v1 --untracked-files=all",
        "scripts/check-repository-policy",
        "scripts/build-source-candidate",
        "pacman-key --verify",
        "candidate-identity-v1.json",
        "--controller-key REPLACE_WITH_CONTROLLER_PRIMARY_KEY_FINGERPRINT",
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
            "case \"$source_parent\" in /absolute/path/*|'') exit 1 ;; esac",
            "test ! -e \"$source_parent\"",
            "git clone --no-checkout",
            "git checkout --detach \"$source_revision\"",
            "test \"$(git rev-parse HEAD)\" = \"$source_revision\"",
            "test -z \"$(git status --porcelain=v1 --untracked-files=all)\"",
            "cargo fetch --locked",
            "cargo deny fetch",
            "CARGO_NET_OFFLINE=true scripts/check-repository-policy",
            "controller_source_revision=$(/usr/bin/sed -n",
            "git worktree add --detach \"$controller_source_checkout\" \"$controller_source_revision\"",
            "CARGO_HOME=\"$controller_cargo_home\" cargo fetch --locked",
            "--manifest-path \"$controller_source_checkout/Cargo.toml\"",
            "git worktree remove \"$controller_source_checkout\"",
        ],
    );

    let candidate = section(
        runbook,
        "Assemble `/bundle` exactly as specified",
        "The command fails before publication",
    );
    assert_ordered(
        candidate,
        &[
            "source_root=$PWD",
            "test -d /bundle",
            "candidate_output=/absolute/path/to/new-source-candidate",
            "test ! -e \"$candidate_output\"",
            "scripts/build-source-candidate",
            "--bundle /bundle",
            "--kernel-signing-dir /secure/signing",
            "--package-cert-sha256 REPLACE_WITH_APPROVED_PACKAGE_CERT_SHA256",
            "--package-key /secure/private/package-signing-key.pem",
            "--module-cert-sha256 REPLACE_WITH_APPROVED_MODULE_CERT_SHA256",
            "--kernel-cert-sha256 REPLACE_WITH_APPROVED_IMAGE_CERT_SHA256",
            "--cargo-home /secure/controller-cargo-home",
            "--controller-gnupg-home /secure/controller-gnupg",
            "--controller-key REPLACE_WITH_CONTROLLER_PRIMARY_KEY_FINGERPRINT",
            "--output \"$candidate_output\"",
        ],
    );
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
            "candidate_output=/absolute/path/to/source-candidate",
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
