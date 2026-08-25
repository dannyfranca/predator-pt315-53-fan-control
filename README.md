# Predator PT315-53 fan control

Source status: **unqualified and not configured**. This repository does not yet
support Custom fan control, install a service, or enable one.

## Workspace

- `fan-control-core`: shared library
- `fan-control-daemon`: future automatic controller
- `fan-control-restore`: future Firmware Auto restoration tool
- `fan-control-qualify`: future qualification tool

Build and test every workspace member:

```console
cargo build --workspace
cargo test --workspace
```

The three executables currently do no hardware or service work. Each exits
successfully after printing its explicit unqualified/not-configured status:

```console
cargo run -p fan-control-daemon
cargo run -p fan-control-restore
cargo run -p fan-control-qualify
```
