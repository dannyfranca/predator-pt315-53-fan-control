const README: &str = include_str!("../../../README.md");

fn runbook() -> &'static str {
    README
        .split_once("## Canonical runbook: maintenance, rollback, and retirement")
        .expect("README must contain the canonical maintenance runbook")
        .1
        .split_once("## Project boundary")
        .expect("maintenance runbook must precede the project boundary")
        .0
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let remainder = source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .1;
    if end.is_empty() {
        remainder
    } else {
        remainder
            .split_once(end)
            .unwrap_or_else(|| panic!("missing section end: {end}"))
            .0
    }
}

fn normalized(source: &str) -> String {
    source
        .lines()
        .map(|line| line.strip_prefix("> ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn assert_ordered(haystack: &str, needles: &[&str]) {
    let normalized = normalized(haystack);
    let mut remaining = normalized.as_str();
    for needle in needles {
        let offset = remaining
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered maintenance step: {needle}"));
        remaining = &remaining[offset + needle.len()..];
    }
}

#[test]
fn recovery_commands_disable_control_before_any_change() {
    let recovery = section(
        runbook(),
        "### Recover before changing anything",
        "### Classify every kernel and controller update",
    );
    let commands = section(recovery, "```sh", "```");
    assert_ordered(
        commands,
        &[
            "qualification_cgroups=$(/usr/bin/find /sys/fs/cgroup",
            "-name 'pt31553-fan-qualify-*' -print)",
            "test -z \"$qualification_cgroups\"",
            "sudo /usr/bin/systemctl stop pt31553-fan-sleep-guard.service",
            "sudo /usr/bin/systemctl stop pt31553-fand.service || true",
            "sudo /usr/bin/pt31553-fan-restore --restore",
            "sudo /usr/bin/systemctl disable",
            "sudo /usr/bin/systemctl stop pt31553-fand.service",
            "sudo /usr/bin/systemctl reset-failed pt31553-fand.service",
            "sudo /usr/bin/pt31553-fan-restore --restore",
            "systemctl is-active",
            "systemctl is-enabled",
        ],
    );
    assert_ordered(
        recovery,
        &[
            "If either readback cannot be confirmed immediately",
            "Shut down the machine immediately",
            "After a later cold firmware initialization into a known stock boot",
            "preserve the prior-boot journal and failure evidence",
        ],
    );
    for requirement in [
        "maximum containment",
        "Any residual qualifier cgroup or failed cgroup traversal",
        "workload cleanup is unproven",
        "power the machine off immediately",
        "do not remove either the controller or candidate kernel",
        "do not reboot",
        "Removal is forbidden unless both fans have confirmed Firmware Auto",
        "stock LTS recovery boot",
        "without recursive dependency removal",
    ] {
        assert!(
            normalized(recovery).contains(requirement),
            "missing recovery/removal rule: {requirement}"
        );
    }
}

#[test]
fn updates_select_ordered_checks_or_full_requalification() {
    let updates = section(
        runbook(),
        "### Classify every kernel and controller update",
        "### Sanitize qualification evidence and check promotion",
    );
    let normalized = normalized(updates);
    for requirement in [
        "Same-code kernel rebuild:",
        "Any controller executable or controller source change",
        "BIOS, fan or board, fan mapping or control path",
        "changed or weakened protected policy",
        "Full requalification through stages 1–7",
        "Unknown, ambiguous, incompletely evidenced, failed, or different result",
        "Any abbreviated-check difference or failure expands to full requalification",
        "ABBREVIATED PATH BLOCKED IN THIS REVISION",
        "Do not execute them manually",
        "No successor is authorized until one exact path completes",
    ] {
        assert!(
            normalized.contains(requirement),
            "missing update/requalification rule: {requirement}"
        );
    }
    let checks = section(
        updates,
        "The same-code kernel rebuild path contains exactly these ordered checks:",
        "Any abbreviated-check difference or failure expands to full requalification.",
    );
    assert_ordered(
        checks,
        &[
            "1. offline identity and ABI",
            "2. Firmware Auto restoration",
            "3. arming maximum and tachometer",
            "4. one uninterrupted 20-minute combined AC workload",
            "5. service-stop restoration",
            "6. reboot restoration",
        ],
    );
}

#[test]
fn rollback_reinstalls_only_reverified_archived_artifacts() {
    let rollback = section(
        runbook(),
        "### Roll back to the retained candidate",
        "### Exit through upstream",
    );
    assert_ordered(
        rollback,
        &[
            "Recover before changing anything",
            "Return to stock before removal",
            "proven stock LTS recovery boot",
            "Reverify the retained candidate before a successor",
            "kernel_package=",
            "headers_package=",
            "nvidia_package=",
            "Record the stock recovery entries",
            "Install without changing the default",
            "from its first `set -eu`",
            "stock-default EFI guard",
            "immutable flag",
            "cleanup trap",
            "exact three-file `pacman -U` transaction",
            "recreate and verify the candidate image, initramfs, and BLS entry",
            "validate-records",
            "sudo /usr/bin/pt31553-fan-restore --restore",
            "Keep it disabled",
        ],
    );
    for requirement in [
        "do not use a glob or recursive package operation",
        "Do not run the archive recheck or guarded install below",
        "rollback from this state is blocked",
        "removal and replacement remain forbidden",
        "separately named, recovery-capable candidate",
        "before successor installation",
        "require both Auto readbacks to be `2`",
        "checked LTS entry and image validation",
        "no candidate boot or control attempt occurred",
    ] {
        assert!(
            normalized(rollback).contains(requirement),
            "missing failed-successor rollback rule: {requirement}"
        );
    }
}

#[test]
fn promotion_retirement_and_upstream_exit_remain_exact_model() {
    let runbook = runbook();
    assert_ordered(
        runbook,
        &[
            "### Sanitize qualification evidence and check promotion",
            "### Retain the last qualified candidate",
            "### Return to stock before removal",
            "### Reverify the retained candidate before a successor",
            "### Roll back to the retained candidate",
            "### Exit through upstream",
        ],
    );
    let upstream = normalized(section(runbook, "### Exit through upstream", ""));
    for requirement in [
        "exact Acer Predator `PT315-53`, board `Civic_TLS`, and BIOS V1.17",
        "passed both ordered local gates",
        "telemetry-only Predator-v4 stage",
        "separate PWM stage",
        "squash the qualified delta into one narrow upstream patch",
        "`.predator_v4 = 1`",
        "`.pwm = 1`",
        "Do not generalize the DMI match",
        "promotion does not authorize another machine",
        "Upstream acceptance does not preserve qualification",
        "passes full requalification",
        "Only then retire the local-patch candidate",
    ] {
        assert!(
            upstream.contains(requirement),
            "missing promotion/upstream boundary: {requirement}"
        );
    }
}
