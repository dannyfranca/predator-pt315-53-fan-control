use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn command_path() -> PathBuf {
    workspace().join("scripts/verify-fake-platform-flow")
}

fn run(command: &mut Command, context: &str) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("{context}: {error}"))
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable fixture");
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("make fixture executable");
}

#[test]
fn command_covers_the_complete_qualification_ready_fake_platform_flow() {
    let source = fs::read_to_string(command_path()).expect("read fake-platform flow command");

    for required in [
        "run_fake_platform_cargo build --frozen --workspace --all-targets --all-features",
        "controller_package",
        "compatibility_admission",
        "config_validation",
        "policy_authority",
        "evidence_records",
        "requalification",
        "read_only_preflight",
        "firmware_auto_baseline",
        "conservative_calibration",
        "matched_custom_workload",
        "live_lifecycle_qualification",
        "supervised_endurance",
        "healthy_control_cycle",
        "simulated_fault_orderings",
        "runtime_restoration_diagnostics",
        "firmware_auto_restoration",
        "qualified_startup",
        "production_control_loop",
        "production_binary_control_loop",
        "service_supervision",
        "sleep_guard",
        "qualification_stages",
        "validate_records",
        "PT31553_RUN_SYSTEMD_LIFECYCLE",
        "PT31553_USE_SYSTEM_MANAGER",
        "export CARGO_NET_OFFLINE=true",
        "qualification-ready source handoff passed",
        "not hardware qualification",
        "not Custom-control authorization",
        "/usr/bin/bwrap",
        "--unshare-pid",
        "--dev /dev",
        "--tmpfs /sys",
        "--tmpfs /run",
        "--tmpfs /tmp",
        "--bind \"$repository_root\" \"$repository_root\"",
        "--unsetenv PT31553_SLEEP_PROBE_ROLE",
        "--unsetenv PT31553_TEST_WRITABLE_ROOT",
        "--unsetenv PT31553_LOCKED_SOURCE_ROOT",
        "--unsetenv PT31553_LIFECYCLE_PROBE_ROLE",
        "--unsetenv PT31553_LIFECYCLE_PROBE_BEHAVIOR",
        "--unsetenv PT31553_LIFECYCLE_PROBE_LOG",
        "--unsetenv NOTIFY_SOCKET",
        "--unsetenv WATCHDOG_USEC",
        "--bin fan-control-qualify",
        "--bin fan-control-restore",
    ] {
        assert!(source.contains(required), "missing flow gate: {required}");
    }

    for forbidden in ["/sys/class/hwmon", "nvidia-smi", "systemctl start"] {
        assert!(
            !source.contains(forbidden),
            "fake-platform command contains live access: {forbidden}"
        );
    }
}

#[test]
fn command_runs_offline_gates_in_order_and_emits_only_the_source_handoff_claim() {
    let sandbox = tempfile::Builder::new()
        .prefix(".fake-platform-flow-test-")
        .tempdir_in(workspace())
        .expect("create command sandbox");
    let bin = sandbox.path().join("bin");
    let log = sandbox.path().join("cargo.log");
    fs::create_dir(&bin).expect("create fixture bin");
    write_executable(
        &bin.join("cargo"),
        "#!/bin/sh\nset -eu\ntest \"${CARGO_NET_OFFLINE:-}\" = true\ntest \"${PPID:-}\" = 1\ntest -z \"$(find /sys -mindepth 1 -maxdepth 1 -print -quit)\"\ntest -z \"$(find /run -mindepth 1 -maxdepth 1 -print -quit)\"\ntest -z \"$(find /dev -mindepth 1 -maxdepth 1 -name 'nvidia*' -print -quit)\"\ntest ! -e /run/systemd/system\ntest -z \"${PT31553_SLEEP_PROBE_ROLE+x}\"\ntest -z \"${PT31553_SLEEP_TEST_RECOVERY+x}\"\ntest -z \"${PT31553_TEST_WRITABLE_ROOT+x}\"\ntest -z \"${PT31553_LOCKED_SOURCE_ROOT+x}\"\ntest -z \"${PT31553_LIFECYCLE_PROBE_ROLE+x}\"\ntest -z \"${PT31553_LIFECYCLE_PROBE_BEHAVIOR+x}\"\ntest -z \"${PT31553_LIFECYCLE_PROBE_LOG+x}\"\ntest -z \"${NOTIFY_SOCKET+x}\"\ntest -z \"${WATCHDOG_USEC+x}\"\nprintf '%s\\n' \"$*\" >> \"${PT31553_FAKE_GATE_LOG:?}\"\n",
    );

    let output = run(
        Command::new(command_path())
            .current_dir(workspace())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    env::var("PATH").expect("PATH is set")
                ),
            )
            .env("PT31553_FAKE_GATE_LOG", &log)
            .env("PT31553_SLEEP_PROBE_ROLE", "daemon-ready")
            .env("PT31553_SLEEP_TEST_RECOVERY", "/host/recovery")
            .env("PT31553_TEST_WRITABLE_ROOT", "/host/writable-root")
            .env("PT31553_LOCKED_SOURCE_ROOT", "/host/locked-source")
            .env("PT31553_LIFECYCLE_PROBE_ROLE", "daemon")
            .env("PT31553_LIFECYCLE_PROBE_BEHAVIOR", "hang")
            .env("PT31553_LIFECYCLE_PROBE_LOG", "/host/lifecycle.log")
            .env("NOTIFY_SOCKET", "/host/notify.socket")
            .env("WATCHDOG_USEC", "1")
            .env_remove("PT31553_RUN_SYSTEMD_LIFECYCLE")
            .env_remove("PT31553_USE_SYSTEM_MANAGER"),
        "run fake-platform flow command",
    );

    assert!(
        output.status.success(),
        "flow command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let commands = fs::read_to_string(log).expect("read cargo command log");
    let lines = commands.lines().collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        5,
        "unexpected cargo command sequence: {lines:#?}"
    );
    assert_eq!(
        lines[0],
        "build --frozen --workspace --all-targets --all-features"
    );
    assert_eq!(
        lines[1],
        "test --frozen -p fan-control-core --test controller_package --test compatibility_admission --test config_validation --test policy_authority --test evidence_records --test requalification --test read_only_preflight --test firmware_auto_baseline --test conservative_calibration --test matched_custom_workload --test live_lifecycle_qualification --test supervised_endurance --test healthy_control_cycle --test simulated_fault_orderings --test runtime_restoration_diagnostics --test firmware_auto_restoration --test qualification_ready_fake_platform"
    );
    assert_eq!(
        lines[2],
        "test --frozen -p fan-control-daemon --features acceptance-fixture --test startup --test qualified_startup --test production_control_loop --test production_binary_control_loop --test service_supervision --test sleep_guard"
    );
    assert_eq!(
        lines[3],
        "test --frozen -p fan-control-qualify --bin fan-control-qualify --test startup --test qualification_stages --test validate_records"
    );
    assert_eq!(
        lines[4],
        "test --frozen -p fan-control-restore --bin fan-control-restore --test startup"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            "==> clean qualification-ready workspace build",
            "==> core package, admission, qualification, control, fault, and restoration flow",
            "==> daemon startup, readiness, healthy control, signals, watchdog, and sleep flow",
            "==> qualification CLI startup, stage surface, and evidence validation",
            "==> independent restoration command ownership, retry, and Firmware Auto flow",
            "qualification-ready source handoff passed: fake-platform software readiness only; not hardware qualification; not Custom-control authorization",
        ]
    );
}

#[test]
fn command_stops_after_the_first_failed_gate_and_suppresses_the_success_claim() {
    let sandbox = tempfile::Builder::new()
        .prefix(".fake-platform-flow-failure-test-")
        .tempdir_in(workspace())
        .expect("create command sandbox");
    let bin = sandbox.path().join("bin");
    let log = sandbox.path().join("cargo.log");
    fs::create_dir(&bin).expect("create fixture bin");
    write_executable(
        &bin.join("cargo"),
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"${PT31553_FAKE_GATE_LOG:?}\"\ncase \" $* \" in\n  *\" -p fan-control-daemon \"*) exit 23 ;;\nesac\n",
    );

    let output = run(
        Command::new(command_path())
            .current_dir(workspace())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    env::var("PATH").expect("PATH is set")
                ),
            )
            .env("PT31553_FAKE_GATE_LOG", &log)
            .env_remove("PT31553_RUN_SYSTEMD_LIFECYCLE")
            .env_remove("PT31553_USE_SYSTEM_MANAGER"),
        "run failing fake-platform flow command",
    );

    assert_eq!(output.status.code(), Some(23));
    let commands = fs::read_to_string(log).expect("read cargo command log");
    let lines = commands.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "gate did not fail fast: {lines:#?}");
    assert!(lines[2].contains("-p fan-control-daemon"));
    assert!(!commands.contains("fan-control-qualify"));
    assert!(!commands.contains("fan-control-restore"));
    assert!(
        !String::from_utf8_lossy(&output.stdout)
            .contains("qualification-ready source handoff passed")
    );
}

#[test]
fn command_refuses_every_live_systemd_opt_in_before_invoking_tools() {
    for variable in [
        "PT31553_RUN_SYSTEMD_LIFECYCLE",
        "PT31553_USE_SYSTEM_MANAGER",
    ] {
        let output = run(
            Command::new("/usr/bin/bash")
                .arg(command_path())
                .current_dir(workspace())
                .env_clear()
                .env(variable, "1")
                .env("PATH", ""),
            "run guarded fake-platform flow command",
        );

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains(&format!("refusing live-hardware opt-in {variable}"))
        );
    }
}
