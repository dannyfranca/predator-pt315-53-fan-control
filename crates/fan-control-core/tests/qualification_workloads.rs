use std::{path::PathBuf, process::Command};

fn workload_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../qualification/workloads")
}

#[test]
fn every_workload_rejects_non_canonical_arguments_without_starting_load() {
    for workload in ["idle", "cpu", "gpu", "combined", "mixed"] {
        let executable = workload_root().join(workload);
        for arguments in [Vec::<&str>::new(), vec!["--not-fixed"], vec!["--fixed", "extra"]] {
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
