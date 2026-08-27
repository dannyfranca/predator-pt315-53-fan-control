use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn workload_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../qualification/workloads")
}

fn scratch_directory(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("pt31553-{name}-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    directory
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[test]
fn every_workload_rejects_non_canonical_arguments_without_starting_load() {
    for workload in ["idle", "cpu", "gpu", "combined", "mixed"] {
        let executable = workload_root().join(workload);
        for arguments in [
            Vec::<&str>::new(),
            vec!["--not-fixed"],
            vec!["--fixed", "extra"],
        ] {
            assert_eq!(
                Command::new(&executable)
                    .args(arguments)
                    .status()
                    .unwrap()
                    .code(),
                Some(64),
                "{workload} accepted non-canonical arguments"
            );
        }
    }
}

#[test]
fn workload_helper_contains_surviving_children_after_an_early_exit() {
    let output = Command::new("/bin/bash")
        .args([
            "-c",
            "set -u; source \"$1\"; /usr/bin/sleep 30 & CPU_WORKLOAD_PID=$!; (/usr/bin/sleep 0.01; exit 7) & GPU_WORKLOAD_PID=$!; survivor=$CPU_WORKLOAD_PID; set +e; wait_for_fixed_workload; status=$?; set -e; ! kill -0 \"$survivor\" 2>/dev/null; test \"$status\" -eq 7",
            "workload-cleanup-test",
        ])
        .arg(workload_root().join("common"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn workload_helper_contains_a_child_before_its_pid_is_recorded() {
    let output = Command::new("/bin/bash")
        .args([
            "-c",
            "set -u; source \"$1\"; /usr/bin/sleep 30 & child=$!; printf '%s\\n' \"$child\"; kill -TERM $$",
            "workload-startup-signal-test",
        ])
        .arg(workload_root().join("common"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let child = String::from_utf8(output.stdout).unwrap();
    let status = Command::new("/bin/kill")
        .args(["-0", child.trim()])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "startup child survived wrapper termination"
    );
}

#[test]
fn mixed_contains_a_segment_signaled_before_its_pid_is_recorded() {
    let directory = scratch_directory("mixed-startup-signal");
    let marker = directory.join("segment-pid");
    fs::copy(workload_root().join("common"), directory.join("common")).unwrap();
    fs::copy(workload_root().join("mixed"), directory.join("mixed")).unwrap();
    write_executable(
        &directory.join("combined"),
        "#!/usr/bin/bash\nprintf '%s\\n' \"$$\" > \"$MIXED_START_MARKER\"\nexec /usr/bin/sleep 30\n",
    );
    let bash_env = directory.join("bash-env");
    fs::write(
        &bash_env,
        "set -T\ntrap 'if [[ ${BASH_COMMAND:-} == \"ACTIVE_WORKLOAD_PID=\\$!\" ]]; then while [[ ! -s $MIXED_START_MARKER ]]; do /usr/bin/sleep 0.001; done; trap - DEBUG; kill -TERM $$; fi' DEBUG\n",
    )
    .unwrap();

    let output = Command::new("/usr/bin/bash")
        .arg(directory.join("mixed"))
        .arg("--fixed")
        .env("BASH_ENV", &bash_env)
        .env("MIXED_START_MARKER", &marker)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let child = fs::read_to_string(&marker).unwrap();
    let status = Command::new("/bin/kill")
        .args(["-0", child.trim()])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "mixed startup child survived termination"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn mixed_propagates_a_signaled_segment_failure_without_busy_looping() {
    let directory = scratch_directory("mixed-segment-failure");
    fs::copy(workload_root().join("common"), directory.join("common")).unwrap();
    fs::copy(workload_root().join("mixed"), directory.join("mixed")).unwrap();
    write_executable(
        &directory.join("combined"),
        "#!/usr/bin/bash\nkill -TERM $$\n",
    );

    let status = Command::new("/usr/bin/timeout")
        .args([
            "2",
            "/usr/bin/bash",
            directory.join("mixed").to_str().unwrap(),
            "--fixed",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(143));
    fs::remove_dir_all(directory).unwrap();
}
