use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixDatagram},
    path::{Path, PathBuf},
    process::Command,
};

#[path = "../../../tests/support/native_journal.rs"]
mod native_journal;
use native_journal::{assert_no_native_event, journal_receiver, receive_native_event};

#[test]
fn restoration_reports_its_independent_recovery_role_without_touching_hardware() {
    let (receiver, socket_path) = journal_receiver("restore-status");
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-restore"))
        .arg("--status")
        .env("PT31553_TEST_JOURNALD_SOCKET", &socket_path)
        .output()
        .expect("restoration executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        "fan-control-restore: independent Firmware Auto recovery command\n"
    );
    assert!(output.stderr.is_empty());
    assert_no_native_event(&receiver);
    fs::remove_file(socket_path).unwrap();
}

#[test]
fn restoration_entrypoint_delivers_faults_to_native_journald() {
    let (receiver, socket_path) = journal_receiver("restore");
    let output = Command::new(env!("CARGO_BIN_EXE_fan-control-restore"))
        .arg("--unsupported-test-command")
        .env("PT31553_TEST_JOURNALD_SOCKET", &socket_path)
        .output()
        .expect("restoration executable should start");

    assert_eq!(output.status.code(), Some(2));
    let event = receive_native_event(&receiver);
    assert_eq!(
        event.get("PT31553_EVENT_ID").map(String::as_str),
        Some("pt31553.runtime-fault.v1")
    );
    assert_eq!(
        event.get("PT31553_FAULT_ID").map(String::as_str),
        Some("configuration-rejected")
    );
    assert_eq!(
        event.get("PT31553_ENDPOINT").map(String::as_str),
        Some("none")
    );
    fs::remove_file(socket_path).unwrap();
}

#[test]
fn restore_command_retries_ownership_then_restores_both_fake_platform_fans() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sandbox = tempfile::Builder::new()
        .prefix(".restore-command-test-")
        .tempdir_in(&workspace)
        .expect("create restore command sandbox");
    let hwmon_root = sandbox.path().join("hwmon");
    let acer_root = hwmon_root.join("hwmon7");
    let bin = sandbox.path().join("bin");
    fs::create_dir_all(&acer_root).expect("create fake hwmon");
    fs::create_dir(&bin).expect("create fake command directory");
    fs::write(acer_root.join("name"), "acer\n").expect("write hwmon name");
    set_mode(&acer_root.join("name"), 0o444);
    for channel in 1..=2 {
        fs::write(acer_root.join(format!("pwm{channel}")), "128\n").expect("write fake PWM");
        fs::write(acer_root.join(format!("pwm{channel}_enable")), "1\n").expect("write fake mode");
        fs::write(acer_root.join(format!("fan{channel}_input")), "2400\n")
            .expect("write fake tachometer");
        set_mode(&acer_root.join(format!("fan{channel}_input")), 0o444);
    }

    let service_probe_marker = sandbox.path().join("service-probe.marker");
    write_executable(
        &bin.join("systemctl"),
        &format!(
            "#!/bin/sh\nset -eu\nif [ ! -e '{}' ]; then\n  : > '{}'\n  printf 'LoadState=loaded\\nActiveState=active\\n'\nelse\n  printf 'LoadState=not-found\\nActiveState=inactive\\n'\nfi\n",
            service_probe_marker.display(),
            service_probe_marker.display()
        ),
    );

    let (journal, journal_path) = journal_receiver("restore-fake-platform");

    let output = Command::new("/usr/bin/bwrap")
        .args([
            "--die-with-parent",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/sys",
            "--dir",
            "/sys/class",
            "--dir",
            "/sys/class/hwmon",
        ])
        .arg("--bind")
        .arg(&hwmon_root)
        .arg("/sys/class/hwmon")
        .args(["--tmpfs", "/run"])
        .arg("--bind")
        .arg(&workspace)
        .arg(&workspace)
        .arg("--chdir")
        .arg(&workspace)
        .args(["--setenv", "PATH"])
        .arg(format!("{}:/usr/bin", bin.display()))
        .args(["--setenv", "PT31553_TEST_JOURNALD_SOCKET"])
        .arg(&journal_path)
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_fan-control-restore"))
        .arg("--restore")
        .output()
        .expect("run restore command on fake platform");

    assert!(
        output.status.success(),
        "restore command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("waiting for recovery ownership"));
    assert_eq!(read_trimmed(acer_root.join("pwm1_enable")), "2");
    assert_eq!(read_trimmed(acer_root.join("pwm2_enable")), "2");

    let event_ids = receive_event_ids(&journal);
    assert_eq!(
        event_ids,
        [
            "pt31553.runtime-fault.v1",
            "pt31553.restoration-attempt.v1",
            "pt31553.state-transition.v1",
        ]
    );
    fs::remove_file(journal_path).expect("remove fake journal");
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable fixture");
    set_mode(path, 0o755);
}

fn set_mode(path: &Path, mode: u32) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("make fixture executable");
}

fn read_trimmed(path: PathBuf) -> String {
    fs::read_to_string(path)
        .expect("read fake fan mode")
        .trim()
        .to_owned()
}

fn receive_event_ids(receiver: &UnixDatagram) -> Vec<String> {
    let mut event_ids = Vec::new();
    loop {
        let mut payload = [0_u8; 2048];
        let Ok(length) = receiver.recv(&mut payload) else {
            break;
        };
        let mut payload = &payload[..length];
        while !payload.is_empty() {
            let name_end = payload.iter().position(|byte| *byte == b'\n').unwrap();
            let name = std::str::from_utf8(&payload[..name_end]).unwrap();
            payload = &payload[name_end + 1..];
            let length = u64::from_le_bytes(payload[..8].try_into().unwrap()) as usize;
            payload = &payload[8..];
            let value = std::str::from_utf8(&payload[..length]).unwrap();
            payload = &payload[length + 1..];
            if name == "PT31553_EVENT_ID" {
                event_ids.push(value.to_owned());
            }
        }
    }
    event_ids
}
