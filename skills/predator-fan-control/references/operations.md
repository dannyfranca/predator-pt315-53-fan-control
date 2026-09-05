# Check, build, install, qualify, and operate

The current clean checkout owns every command. Read its top-level status,
`SECURITY.md`, package recipe, and complete relevant canonical runbook section.
GitHub Actions are manual-only and releases are optional/out of scope; never
trigger Actions or download a release as part of this flow.

## Check and build autonomously

Resolve and record `git rev-parse HEAD`; reject a dirty or shallow checkout.
These source-only commands are safe to run without approval:

```sh
cargo run -p fan-control-daemon -- --status
cargo run -p fan-control-restore -- --status
cargo run -p fan-control-qualify
cargo fetch --locked
cargo build --locked --workspace --bins
cargo test --locked --workspace
```

For a candidate, follow README step 3 exactly. It derives the source identity
from `HEAD`, runs `scripts/check-repository-policy`, and then runs
`scripts/build-source-candidate` with externally reviewed trust inputs. Its
generated output is
`pt31553-source-candidate-<40-hex-HEAD>/{kernel,controller,declarations,signatures}`.
Do not invent placeholder identities or silently rebuild a recipe for another
commit.

## Inspect installed status

The package installs these operator entrypoints and creates these state locations:

- `/usr/bin/pt31553-fand` (`--status` is read-only; no argument starts the
  production controller);
- `/usr/bin/pt31553-fan-restore` (`--status` is read-only; `--restore` writes
  fan mode and is privileged);
- `/usr/bin/pt31553-fan-qualify`;
- `/usr/bin/pt31553-fan-observer` (foreground human-presence and measured-ambient companion);
- `/etc/pt31553-fan-control/config.toml`;
- `/usr/lib/pt31553-fan-control/compatibility.toml`;
- `/var/lib/pt31553-fan-control/` and
  `/var/lib/pt31553-fan-control/evidence/`; a successful
  supervised-endurance run later creates the authority record at
  `/var/lib/pt31553-fan-control/qualification.json`;
- `pt31553-fand.service` and `pt31553-fan-sleep-guard.service`, both packaged
  disabled.

Inspect the builder-checkout identity, the separately pinned controller-payload
identity in the package's `source-commit`, running kernel/module, processes, unit enabled
and active states, and authority files. A zero exit status does not raise the
authority state. Never run `/usr/bin/pt31553-fand` without `--status` as a
probe, or use `--restore` as status.

## Prepare and install disabled

Run unprivileged artifact verification and package inspection autonomously.
Pause immediately before the README's first `sudo` package, boot, or service
mutation. Show exact artifacts, effect, and recovery path. After approval,
follow the disabled-install and side-by-side boot commands without translation.
Keep stock and stock-LTS entries, the stock persistent default, and both units
disabled/inactive.

## Qualify under supervision

The package includes the qualification executable and fixed workloads, but no
machine-specific harness or manifests. A reviewed digest-pinned harness and
root-owned manifests must be provisioned from the repository protocols. Never
improvise them. Run stages only in README order:

1. `sudo /usr/bin/pt31553-fan-qualify preflight --manifest FILE --harness FILE`;
2. `sudo /usr/bin/pt31553-fan-qualify firmware-auto-baselines --manifest FILE --harness FILE`;
3. `sudo /usr/bin/pt31553-fan-qualify fan-calibration --fan cpu|gpu --manifest FILE --harness FILE --observer-approval I-AM-PHYSICALLY-OBSERVING`;
4. `sudo /usr/bin/pt31553-fan-qualify matched-workload --manifest FILE --harness FILE --observer-approval I-AM-PHYSICALLY-OBSERVING`, twelve fresh invocations;
5. `sudo /usr/bin/pt31553-fan-qualify live-lifecycle --manifest FILE --harness FILE --observer-approval I-AM-PHYSICALLY-OBSERVING`, across its reboot boundary;
6. `sudo /usr/bin/pt31553-fan-qualify supervised-endurance --manifest FILE --harness FILE --observer-approval I-AM-PHYSICALLY-OBSERVING --evidence-output FILE [--qualification-record FILE]`;
7. `sudo /usr/bin/pt31553-fan-qualify validate-records --qualification-record FILE --evidence FILE [--authorized-evidence-path FILE]`.

Every form above is privileged: show the exact command and obtain approval
immediately before it. Preflight performs no fan write, but it still requires
UID 0 for protected inputs and output. The human must remain physically present
for every workload or fan-control stage,
watch mode/RPM, fan sound/operation, temperatures, throttling, telemetry,
workload control, smell/smoke, instability, and ability to intervene, then
withdraw approval on any surprise.

## Activate only with authority

An installed production daemon is not authorization. After stages 1–7,
reverify exact package, protected policy, record, evidence, machine,
kernel/module, both Auto readbacks, recovery default, and absent fault latch.
Only then, with approval, run README step 8. Inspect readiness and structured
journal events. Any mismatch or runtime fault returns to recovery.

Completion requires a compact ledger: source revision, package identity,
machine classification, authority state, commands/files changed, service/fan
state, validation evidence, blocker, and recovery path.

## Maintain and promote later

Promotion is not a qualification stage and does not precede initial activation.
For a later successor or public claim, follow the README maintenance runbook in
its stated order. After fresh qualification and artifact verification, run:

1. `sudo /usr/bin/pt31553-fan-qualify redact-evidence --qualification-record FILE --evidence FILE --authorized-evidence-path FILE --output FILE`;
2. `sudo /usr/bin/pt31553-fan-qualify check-promotion --manifest FILE --qualification-record FILE --evidence FILE --authorized-evidence-path FILE --sanitized-evidence FILE --protected-policy FILE --package-provenance FILE --controller-package FILE --controller-signature FILE --package-manifest-signature FILE --output FILE`.

Both commands are privileged. Obtain approval immediately before each one.
