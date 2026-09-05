use std::process::Command;

#[test]
fn qualification_reports_that_no_evidence_exists() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .output()
        .expect("qualification executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "pt31553-fan-qualify: unqualified/not configured; run `pt31553-fan-qualify supervised-endurance --help`\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn live_lifecycle_exposes_reboot_resume_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .args(["live-lifecycle", "--help"])
        .output()
        .expect("qualification executable should start");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--observer-approval I-AM-PHYSICALLY-OBSERVING"));
    assert!(stdout.contains("reboot normally"));
}

#[test]
fn supervised_endurance_requires_explicit_observer_approval() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .args(["supervised-endurance", "--help"])
        .output()
        .expect("qualification executable should start");

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("--observer-approval I-AM-PHYSICALLY-OBSERVING")
    );
}

#[test]
fn top_level_help_publishes_the_complete_command_inventory() {
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .arg("--help")
        .output()
        .expect("qualification executable should start");

    assert!(output.status.success());
    assert_eq!(
        commands_from_help(&String::from_utf8(output.stdout).unwrap()),
        [
            "preflight",
            "firmware-auto-baselines",
            "fan-calibration",
            "matched-workload",
            "live-lifecycle",
            "supervised-endurance",
            "validate-records",
            "redact-evidence",
            "check-promotion",
        ]
    );
    assert!(output.stderr.is_empty());
}

fn normalized(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn logical_lines(source: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for physical in source.lines() {
        let trimmed = physical.trim_end();
        let (content, shell_continues) = match trimmed.strip_suffix('\\') {
            Some(continued) => (continued, true),
            None => (physical, false),
        };
        current.push_str(content);
        if shell_continues || current.matches('`').count() == 1 {
            current.push(' ');
        } else {
            lines.push(normalized(&current));
            current.clear();
        }
    }
    if !current.is_empty() {
        lines.push(normalized(&current));
    }
    lines
}

fn command_contract(help: &str, command: &str) -> String {
    exact_command_contract(help, command).replace(['[', ']'], "")
}

fn exact_command_contract(help: &str, command: &str) -> String {
    let usage = help.lines().next().expect("help should start with usage");
    assert!(
        usage.starts_with("usage: pt31553-fan-qualify "),
        "help uses a name other than the packaged executable: {usage}"
    );
    let (_, arguments) = usage
        .split_once(command)
        .unwrap_or_else(|| panic!("usage omitted command `{command}`: {usage}"));
    normalized(&format!("{command}{arguments}"))
}

fn documented_stage_line(source: &str, command: &str) -> String {
    documented_contract_line(source, command).replace(['[', ']'], "")
}

fn documented_contract_line(source: &str, command: &str) -> String {
    let executable = format!("/usr/bin/pt31553-fan-qualify {command}");
    let line = source
        .lines()
        .find(|line| line.contains(&executable))
        .unwrap_or_else(|| panic!("documentation omitted the `{command}` stage line"));
    assert!(
        line.contains(&format!("sudo {executable}")),
        "documentation removed the privilege boundary from `{command}`: {line}"
    );
    let start = line.find(&executable).unwrap();
    let contract = line[start..].split('`').next().unwrap();
    normalized(contract)
        .trim_start_matches("/usr/bin/pt31553-fan-qualify ")
        .trim_end_matches([';', '.'])
        .to_owned()
}

fn documented_invocations(source: &str, command: &str) -> Vec<String> {
    let privileged = format!("sudo /usr/bin/pt31553-fan-qualify {command}");
    let mut invocations = Vec::new();
    for line in logical_lines(source) {
        for (privileged_start, _) in line.match_indices(&privileged) {
            let start = privileged_start + "sudo ".len();
            let invocation = line[start..].split('`').next().unwrap();
            invocations.push(normalized(invocation));
        }
    }
    invocations
}

fn commands_from_help(help: &str) -> Vec<&str> {
    help.split_once("commands:\n")
        .expect("top-level help must publish commands")
        .1
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

fn documented_commands(source: &str) -> Vec<String> {
    let executable = "sudo /usr/bin/pt31553-fan-qualify ";
    let mut commands = logical_lines(source)
        .into_iter()
        .flat_map(|line| {
            line.match_indices(executable)
                .filter_map(|(start, _)| {
                    line[start + executable.len()..]
                        .split_whitespace()
                        .next()
                        .map(str::to_owned)
                })
                .collect::<Vec<_>>()
        })
        .map(|command| command.trim_matches(['`', ',', ';', '.']).to_owned())
        .filter(|command| *command != "\\")
        .collect::<Vec<_>>();
    commands.sort();
    commands.dedup();
    commands
}

fn assert_all_command_forms_are_privileged(source: &str, commands: &[&str]) {
    let executable = "pt31553-fan-qualify ";
    for line in logical_lines(source) {
        for (start, _) in line.match_indices(executable) {
            let prefix = &line[..start];
            let suffix = &line[start + executable.len()..];
            let Some(command) = suffix.split_whitespace().next() else {
                continue;
            };
            let command = command.trim_matches(['`', ',', ';', '.']);
            if commands.contains(&command) {
                assert!(
                    prefix.ends_with("sudo /usr/bin/"),
                    "documented `{command}` form lost its privilege boundary: {line}"
                );
            }
        }
    }
}

fn arguments(contract: &str) -> Vec<(String, String)> {
    let tokens = contract
        .split_whitespace()
        .filter(|token| *token != "\\")
        .map(|token| {
            token
                .trim_matches(['`', '[', ']', '"', '\'', ',', ';', '.', ':'])
                .to_owned()
        })
        .collect::<Vec<_>>();
    let mut arguments = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index].starts_with("--") {
            let value = tokens
                .get(index + 1)
                .unwrap_or_else(|| panic!("{} has no value in: {contract}", tokens[index]));
            assert!(
                !value.starts_with("--"),
                "{} is incorrectly bound to option {value} in: {contract}",
                tokens[index]
            );
            assert!(
                !arguments
                    .iter()
                    .any(|(existing, _)| existing == &tokens[index]),
                "duplicate option {} in: {contract}",
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

fn assert_documented_values(invocation: &str, arguments: &[(String, String)]) {
    for (flag, allowed) in [
        ("--fan", &["cpu|gpu", "cpu"][..]),
        (
            "--manifest",
            &[
                "FILE",
                "/absolute/path/to/root-owned-qualification-stages.json",
                "/absolute/path/to/root-owned-endurance-plan.json",
                "/absolute/path/to/candidate-promotion.json",
                "/etc/pt31553-fan-control/qualification-stages.json",
                "/etc/pt31553-fan-control/endurance-plan.json",
            ][..],
        ),
        (
            "--harness",
            &[
                "FILE",
                "/absolute/path/to/reviewed-root-owned-qualification-harness",
                "/usr/lib/pt31553-fan-control/qualification-harness",
                "/usr/lib/pt31553-fan-control/endurance-harness",
            ][..],
        ),
        ("--observer-approval", &["I-AM-PHYSICALLY-OBSERVING"][..]),
        (
            "--qualification-record",
            &["FILE", "/var/lib/pt31553-fan-control/qualification.json"][..],
        ),
        (
            "--evidence",
            &[
                "FILE",
                "/var/lib/pt31553-fan-control/evidence/supervised-endurance.json",
            ][..],
        ),
        (
            "--authorized-evidence-path",
            &[
                "FILE",
                "/var/lib/pt31553-fan-control/evidence/supervised-endurance.json",
            ][..],
        ),
        (
            "--evidence-output",
            &[
                "FILE",
                "/var/lib/pt31553-fan-control/evidence/supervised-endurance.json",
            ][..],
        ),
    ] {
        if let Some((_, value)) = arguments.iter().find(|(candidate, _)| candidate == flag) {
            assert!(
                allowed.contains(&value.as_str()),
                "unexpected {flag} value `{value}` in: {invocation}"
            );
        }
    }
}

#[test]
fn runbook_and_skill_cover_every_actual_qualification_command() {
    let runbook = include_str!("../../../README.md");
    let operations = include_str!("../../../skills/predator-fan-control/references/operations.md");
    let inventory_output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(inventory_output.status.success());
    let inventory_source = String::from_utf8(inventory_output.stdout).unwrap();
    let commands = commands_from_help(&inventory_source);
    let mut sorted_commands = commands
        .iter()
        .map(|command| (*command).to_owned())
        .collect::<Vec<_>>();
    sorted_commands.sort();
    for (name, docs) in [("runbook", runbook), ("skill operations", operations)] {
        assert_all_command_forms_are_privileged(docs, &commands);
        assert_eq!(
            documented_commands(docs),
            sorted_commands,
            "{name} command inventory drifted from top-level help"
        );
    }

    for command in commands {
        let output = Command::new(env!("CARGO_BIN_EXE_fan-control-qualify"))
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{command} --help failed");
        let help = String::from_utf8(output.stdout).unwrap();
        let contract = command_contract(&help, command);
        let exact_contract = exact_command_contract(&help, command);
        let expected_options = arguments(&contract)
            .into_iter()
            .map(|(flag, _)| flag)
            .collect::<Vec<_>>();
        let runbook_contract = documented_contract_line(runbook, command);
        assert_eq!(
            runbook_contract, exact_contract,
            "runbook changed CLI requiredness for `{command}`"
        );
        let operations_contract = documented_contract_line(operations, command);
        assert_eq!(
            operations_contract, exact_contract,
            "skill operations changed CLI requiredness for `{command}`"
        );
        for (name, docs) in [("runbook", runbook), ("skill operations", operations)] {
            let stage_line = documented_stage_line(docs, command);
            assert!(
                stage_line.contains(&contract),
                "{name} omitted actual CLI contract `{contract}`"
            );
            let invocations = documented_invocations(docs, command);
            assert!(
                !invocations.is_empty(),
                "{name} has no privileged `{command}` invocation"
            );
            for invocation in invocations {
                let documented_arguments = arguments(&invocation);
                assert_eq!(
                    documented_arguments
                        .iter()
                        .map(|(flag, _)| flag.clone())
                        .collect::<Vec<_>>(),
                    expected_options,
                    "{name} has a stale `{command}` invocation: {invocation}"
                );
                assert_documented_values(&invocation, &documented_arguments);
            }
        }
    }
}
