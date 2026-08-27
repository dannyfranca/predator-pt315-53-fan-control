# Predator PT315-53 fan control

Source status: **unqualified and not configured**. This repository does not yet
support Custom fan control, install a service, or enable one.

## Workspace

- `fan-control-core`: shared library
- `fan-control-daemon`: future automatic controller
- `fan-control-restore`: independent Firmware Auto restoration tool
- `fan-control-qualify`: privileged supervised qualification runner

Build and test every workspace member:

```console
cargo build --workspace
cargo test --workspace
```

Run the complete offline simulated-fault qualification gate without host hardware or services:

```console
cargo test -p fan-control-core --test simulated_fault_orderings
```

The guided live-lifecycle stage is exposed through
`run_live_lifecycle_qualification`. It orders invalid-configuration, duplicate-process,
normal stop/restart, `SIGKILL`, watchdog, AC-to-battery, suspend/resume, and reboot checks.
Every case must finish with independent CPU and GPU Firmware Auto (`2`) readbacks before
the next case. Its environment supplies fresh typed observations; a persisted outer
qualification coordinator must resume after reboot with distinct boot IDs and confirm both
fans in Auto before arming. The reboot boundary is deliberately split: `resume_after_reboot`
cannot arm the controller, and `arm_after_reboot` is called only after the core runner's fresh
CPU/GPU Auto gate succeeds. Suspend/resume evidence records ordered resume and process-start
times plus distinct pre-sleep and post-resume process identities. Invalid-configuration and
duplicate-process results carry fresh case-window timestamps; duplicate, normal restart, crash,
watchdog, and resume checks bind distinct before/after process identities. Raw WMI/EC access,
module unload, fan disconnection, kernel crash,
power cut, and real hardware-write failure injection are explicitly refused; those cases
belong only in the simulated gate. Before each crash case, the coordinator must safely run
`systemctl reset-failed pt31553-fand.service` while the healthy owner remains active; the recorded
reset preserves a fresh two-start budget. Crash cases pin the installed two-second restart delay
and two-start lifetime limit; Firmware Auto restoration itself remains unbounded and blocks
restart until safe.

Status invocations do no hardware or service work and exit after reporting the
current source role:

```console
cargo run -p fan-control-daemon
cargo run -p fan-control-restore -- --status
cargo run -p fan-control-qualify -- supervised-endurance --help
```

`fan-control-restore --restore` is the explicit root service recovery mode. It
discovers the exact Acer hwmon device, owns the controller lock, requests and
confirms Firmware Auto for both fans, contains any confirmed-Custom fan at
maximum if restoration fails, and retries until Auto is confirmed.

## Project boundary

This project is limited to safe fan-control qualification for the exact Acer Predator PT315-53 on CachyOS through the standard in-tree `acer_wmi`/Acer hwmon interface. GUI work, other laptop models, other distributions, bypass backends, and unrelated system tuning are out of scope. See [CONTRIBUTING.md](CONTRIBUTING.md) for the required exact-model evidence.

Original repository work is [MIT-licensed](LICENSE). Linux-derived material remains `GPL-2.0-only`; see [LICENSING.md](LICENSING.md) for the boundary and provenance rules. Report vulnerabilities, unsafe fan behavior, and sensitive qualification evidence privately according to [SECURITY.md](SECURITY.md).
