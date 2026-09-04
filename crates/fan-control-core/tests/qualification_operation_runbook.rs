const README: &str = include_str!("../../../README.md");

fn runbook() -> &'static str {
    README
        .split_once("## Canonical runbook: qualification and operation")
        .expect("README must contain the canonical qualification and operation runbook")
        .1
        .split_once("### Sanitize qualification evidence and check promotion")
        .expect("qualification and operation must precede promotion")
        .0
}

fn assert_ordered(haystack: &str, needles: &[&str]) {
    let mut remaining = haystack;
    for needle in needles {
        let offset = remaining
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered runbook step: {needle}"));
        remaining = &remaining[offset + needle.len()..];
    }
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"))
        .0
}

#[test]
fn qualification_ladder_and_abort_boundary_are_explicit_and_ordered() {
    let runbook = runbook();
    let boundary = section(
        runbook,
        "Every successful stage boundary",
        "### 1. Establish the qualification prerequisites",
    );
    assert_ordered(
        runbook,
        &[
            "CURRENT REVISION: DO NOT ENABLE OR START",
            "### 1. Establish the qualification prerequisites",
            "### 2. Run read-only preflight",
            "### 3. Record Firmware Auto baselines",
            "### 4. Calibrate one fan at a time",
            "### 5. Run matched thermal workloads",
            "### 6. Exercise lifecycle and fault handling",
            "### 7. Complete supervised endurance and authorization",
            "### 8. Enable, start, and inspect an authorized build",
        ],
    );
    assert_ordered(
        boundary,
        &[
            "stop the workload",
            "stop normal fan writes",
            "request Firmware Auto independently for both fans",
            "read back `2` from both enable endpoints",
            "An abort performs steps 1 through 4",
            "preserves the failure evidence",
            "blocks the next stage",
            "If step 4 fails",
            "shut down the machine",
            "do not reboot into any kernel",
            "emergency maximum containment",
        ],
    );
    assert!(boundary.contains("Preflight itself never requests Auto"));
    assert!(runbook.contains("Source-complete is not qualification"));
    assert!(runbook.contains("CI success is not qualification"));
    assert!(runbook.contains("An abort performs steps 1 through 4"));
    assert!(runbook.contains("A successful handoff advances only after"));
    let normalized = runbook.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("If both fans cannot be confirmed in Auto immediately, shut down"));
    assert!(runbook.contains("IMPLEMENTATION BLOCK"));
    assert!(runbook.contains("this source revision exposes preflight, all seven"));
    assert!(runbook.contains("Firmware Auto baselines, one-fan calibration, and all twelve"));
    assert!(runbook.contains("matched workloads"));
    assert!(runbook.contains("does not yet package"));
    assert!(runbook.contains("reviewed hardware"));
    assert!(runbook.contains("Live lifecycle remains unavailable"));
    assert!(runbook.contains("do not replace it with ad-hoc shell scripts"));
    assert!(runbook.contains("direct sysfs writes"));
    for limit in [
        "AC idle for 10 minutes",
        "AC CPU for 20",
        "AC combined for 30",
        "twelve-run matrix",
        "no more than `2°C` above baseline",
        "`1°C/min`",
        "within 10 seconds",
        "plausible RPM bands of plus or minus 30%",
        "slowest successful response plus two seconds",
        "Stop at the first unstable level and never test below it",
        "five maximum-to-floor transitions",
    ] {
        assert!(
            normalized.contains(limit),
            "missing qualification limit: {limit}"
        );
    }
}

#[test]
fn configuration_changes_are_atomic_restart_only_operations() {
    let runbook = runbook();
    let configuration = section(
        runbook,
        "The daemon validates the complete TOML atomically during startup",
        "On any runtime fault",
    );
    for statement in [
        "sudo /usr/bin/systemctl restart pt31553-fand.service",
        "There is no live reload",
        "There is no manual or fixed-output mode",
        "quieter change requires full requalification",
    ] {
        assert!(
            configuration.contains(statement),
            "missing configuration rule: {statement}"
        );
    }
    assert_ordered(
        configuration,
        &[
            "publish the complete candidate",
            "/etc/pt31553-fan-control/config.toml",
            "sudo /usr/bin/systemctl restart pt31553-fand.service",
            "/usr/bin/systemctl status --no-pager pt31553-fand.service",
            "sudo /usr/bin/journalctl -b -u pt31553-fand.service --no-pager",
        ],
    );
    assert!(!configuration.contains("systemctl reload pt31553-fand.service"));
}

#[test]
fn operation_covers_enablement_inspection_evidence_and_fault_latch_recovery() {
    let runbook = runbook();
    let operation = section(
        runbook,
        "### 8. Enable, start, and inspect an authorized build",
        "On any runtime fault",
    );
    for command in [
        "pt31553-fan-qualify validate-records",
        "systemctl enable --now pt31553-fand.service",
        "systemctl status --no-pager pt31553-fand.service",
        "journalctl -b -u pt31553-fand.service --no-pager",
        "PT31553_FAULT_ID",
        "/var/lib/pt31553-fan-control/evidence/",
        "/var/lib/pt31553-fan-control/qualification.json",
        "sudo /usr/bin/pt31553-fan-restore --restore",
        "sudo /usr/bin/systemctl restart pt31553-fand.service",
    ] {
        assert!(
            runbook.contains(command),
            "missing operation step: {command}"
        );
    }
    assert!(operation.contains("sudo /usr/bin/systemctl enable pt31553-fan-sleep-guard.service"));
    assert!(!operation.contains("enable --now pt31553-fan-sleep-guard.service"));
    assert!(!operation.contains("start pt31553-fan-sleep-guard.service"));

    let fault_recovery = section(
        runbook,
        "On any runtime fault",
        "Do not reset or restart around an unresolved",
    );
    assert_ordered(
        fault_recovery,
        &[
            "stop the workload",
            "sudo /usr/bin/systemctl stop pt31553-fand.service",
            "sudo /usr/bin/pt31553-fan-restore --restore",
            "Correct and revalidate the reported cause",
            "sudo /usr/bin/systemctl reset-failed pt31553-fand.service",
            "sudo /usr/bin/systemctl restart pt31553-fand.service",
        ],
    );
}
