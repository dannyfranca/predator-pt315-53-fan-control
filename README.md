# Predator PT315-53 fan control

Source status: **unqualified and not configured**. This repository does not yet
support Custom fan control, install a service, or enable one.

## Workspace

- `fan-control-core`: shared library
- `fan-control-daemon`: future automatic controller
- `fan-control-restore`: independent Firmware Auto restoration tool
- `fan-control-qualify`: future qualification tool

Build and test every workspace member:

```console
cargo build --workspace
cargo test --workspace
```

Status invocations do no hardware or service work and exit after reporting the
current source role:

```console
cargo run -p fan-control-daemon
cargo run -p fan-control-restore -- --status
cargo run -p fan-control-qualify
```

`fan-control-restore --restore` is the explicit root service recovery mode. It
discovers the exact Acer hwmon device, owns the controller lock, requests and
confirms Firmware Auto for both fans, contains any confirmed-Custom fan at
maximum if restoration fails, and retries until Auto is confirmed.

## Project boundary

This project is limited to safe fan-control qualification for the exact Acer Predator PT315-53 on CachyOS through the standard in-tree `acer_wmi`/Acer hwmon interface. GUI work, other laptop models, other distributions, bypass backends, and unrelated system tuning are out of scope. See [CONTRIBUTING.md](CONTRIBUTING.md) for the required exact-model evidence.

Original repository work is [MIT-licensed](LICENSE). Linux-derived material remains `GPL-2.0-only`; see [LICENSING.md](LICENSING.md) for the boundary and provenance rules. Report vulnerabilities, unsafe fan behavior, and sensitive qualification evidence privately according to [SECURITY.md](SECURITY.md).
