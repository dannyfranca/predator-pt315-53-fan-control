# Preflight and Firmware Auto baseline harness protocol

`pt31553-fan-qualify preflight` and `pt31553-fan-qualify firmware-auto-baselines` are UID-0,
fail-closed stage entrypoints. The core owns validation, the fixed seven-run matrix, deadlines,
thermal aborts, Firmware Auto checks, immutable evidence, and resume decisions. Neither command
has a fan-write capability.

Both commands accept the same protected, root-owned JSON manifest:

```json
{
  "qualification_harness_sha256": "lowercase SHA-256 of the reviewed harness executable",
  "qualification_envelope": { "use": "the exact qualification-envelope-v1 object" },
  "compatibility": "/usr/lib/pt31553-fan-control/compatibility.toml",
  "config": "/etc/pt31553-fan-control/config.toml",
  "protected_policy": "/var/lib/pt31553-fan-control/candidate-policy.toml",
  "candidate_archive": "/var/lib/pt31553-fan-control/candidate",
  "nvidia_gpu_uuid": "GPU-REPLACE_WITH_EXACT_UUID",
  "hwmon_root": "/sys/class/hwmon",
  "evidence_root": "/var/lib/pt31553-fan-control/evidence/SESSION",
  "minimum_available_bytes": 1073741824
}
```

The absolute evidence root must already be a protected root-owned directory. The harness and every
ancestor are protected/root-owned and its bytes must match `qualification_harness_sha256`; the
executable must be readable/executable by the fixed sandbox
UID/GID 65534. When the qualifier runs as root, every harness operation runs as 65534 with no
supplementary groups and `no_new_privs`, inside a private cgroup v2 session. Any deadline or runner
failure uses `cgroup.kill`, so descendants cannot escape cleanup with a new process group/session.
Preflight also rejects fan mode endpoints writable by that identity (including group/other mode
bits or an extended ACL), so collectors and workloads cannot arm Custom control.

Preflight publishes
`preflight.json`. Baselines publish `01-idle-ac-v1.json` through `07-gpu-battery-v1.json` and never
replace an existing file.

Invocation:

```text
pt31553-fan-qualify preflight --manifest FILE --harness FILE
pt31553-fan-qualify firmware-auto-baselines --manifest FILE --harness FILE
```

For each operation the runner executes `HARNESS OPERATION ABSOLUTE_MONOTONIC_DEADLINE`, writes one
JSON request to stdin, and expects exactly one JSON response on stdout. Deadlines and every
`monotonic_millis` field use Linux `CLOCK_MONOTONIC`: milliseconds since boot, shared by the runner
and every harness process. Stdout is capped at 1 MiB and stderr is discarded, so failures must use
a nonzero exit status or a bounded JSON response. The protected executable must support:

- `qualification-readiness`: return booleans `signing_trust_ready`, `recovery_ready`,
  `stock_boot_fallback_ready`, and `qualification_workload_absent` after verifying the exact
  package/signers, independent restoration, present bootable stock + stock-LTS entries with a stock
  persistent default, and no leftover qualification workload/cgroup.
- `sample-nvidia`: request `{"uuid":"..."}`; return `uuid`, `pci_bus_id`, and
  `temperature_celsius`, or `error_kind` plus `error`. `reset-required` is a blocking result.
- `capture-baseline-starting-conditions`: request the manifest's exact `nvidia_gpu_uuid`; return
  that same `nvidia_gpu_uuid`, `captured_at`, ambient/CPU/GPU temperatures, and `power_profile`.
- `start-baseline-workload`: start only the exact requested packaged workload and return its
  `EvidenceTimestamp`.
- `capture-baseline-observation`: request the manifest's exact `nvidia_gpu_uuid`; return that same
  identity with `sample`, `system_stable`, `kernel_faults`, and `nvidia_faults`.
- `stop-baseline-workload`: confirm the workload is absent; return any JSON value.
- `contain-baseline-workload`: independently kill/verify the fixed workload after a failed or timed
  out stop; return any JSON value only after it is absent.
- `cleanup-baseline-workload`: return `{"fan_control_write_count":0}`. Any other count fails.

The root coordinator verifies the protected candidate archive, signed package set, installed
packages, running kernel image, loaded modules, Secure Boot, and live hardware before it invokes
the sandbox. The archive must contain `protected-policy.toml`, `package-provenance-v1.json`,
`enrolled-image-signing-certificate.pem`, `package-set-manifest.p7s`,
`package-signing-certificate.pem`, and the signed package-set files under `build-output/`.

Passing preflight evidence includes the timestamped result and detail for all 12 checks. Each
baseline contains the SHA-256 binding of the exact serialized `preflight.json` it follows.

Resume accepts only complete, passing evidence from the same envelope, preflight binding, workload,
two-second cadence, and currently unchanged fan endpoint identities. Evidence older than six hours,
future-dated evidence, substitutions, retries, changed endpoints, or any non-Auto readback aborts the
session. Start a new protected evidence directory after such an abort.
