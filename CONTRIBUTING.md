# Contributing

## Supported scope

Contributions must serve the exact Acer Predator `PT315-53` qualification and safe automatic fan-control path on CachyOS, using the standard in-tree `acer_wmi`/Acer hwmon interface and the repository's fail-closed safety model.

The following are explicitly out of scope:

- GUI or desktop-control applications;
- other laptop models, including similar Predator model numbers;
- other Linux distributions;
- direct WMI, raw embedded-controller access, force-capability flags, replacement modules, or any other bypass backend; and
- unrelated performance, overclocking, undervolting, acoustic, or general system tuning.

Use a fork for those goals. A request does not enter scope merely because it could share code.

## Evidence required

Issues and behavior-changing pull requests must include redacted, exact-model evidence gathered without bypassing safeguards:

- DMI product name, board name, and BIOS version;
- CachyOS and kernel release/package/source identity;
- `acer_wmi` path, hash, signer, vermagic, and Secure Boot state;
- discovered Acer hwmon identity and the exact two-fan endpoint set;
- initial and restored mode readbacks for both fans; and
- the relevant qualification record or the smallest redacted evidence excerpt.

State the commit tested and the expected versus observed result. Do not perform unsafe writes solely to collect evidence. Follow [SECURITY.md](SECURITY.md) for private reports and sensitive evidence.

## Changes

Keep changes narrow, fail closed on missing or ambiguous evidence, preserve Firmware Auto restoration, and add tests for behavioral changes. Run:

```console
cargo fmt --all -- --check
cargo build --workspace
cargo test --workspace
```

Original contributions are accepted under the repository's MIT license. Linux-derived material must follow the `GPL-2.0-only` boundary and provenance rules in [LICENSING.md](LICENSING.md). Submit only work you have the right to license.
