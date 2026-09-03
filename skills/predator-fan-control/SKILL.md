---
name: predator-fan-control
description: Safely inspect, install, configure, operate, recover, or remove Predator PT315-53 fan control. Use for device compatibility checks, fan-curve changes, service status, installation, restoration, rollback, and uninstall requests for this project.
license: MIT
compatibility: Requires shell and Git access to the exact target revision. Host requirements, supported hardware, packaging, and service interfaces come from that revision.
---

# Predator PT315-53 fan control

Operate through the target revision's documented interfaces. Treat its source,
installed artifacts, machine observations, and qualification authority as four
separate facts. Agreement is required; one never substitutes for another.

## Establish the contract

1. Classify the request as support inspection, status/use, installation,
   configuration, recovery, rollback, or removal.
2. Resolve an exact source revision. Prefer a source checkout supplied by the
   user. Otherwise obtain the official repository at
   `https://github.com/dannyfranca/predator-pt315-53-fan-control`, resolve a
   release tag or commit, and work from a clean detached checkout. Record the
   40-character commit before using its instructions. Build every executable
   and package locally from this checkout; do not install prebuilt release
   assets.
3. Read that checkout's `SECURITY.md`, the status declaration at the start of
   `README.md`, and the relevant canonical runbook section. Inspect
   `compatibility/`, packaging, and command source when the runbook points to
   them. These files are authoritative for the selected revision; this skill
   supplies process and safety invariants, not cached commands.
4. Compare the selected source identity with installed package, executable,
   kernel, module, service, configuration, and authority identities. Treat a
   missing fact, placeholder identity, stale record, or contradiction as a
   blocker.

This step is complete only when the report names the exact source revision,
observed installation state, host classification, and one authority state:
`disabled-only`, `authorized`, or `blocked`.

## Route the request

- For compatibility, read [support checks](references/support.md).
- For acquisition, installation, status, or ordinary use, read
  [operations](references/operations.md).
- For exact-value or goal-based configuration changes, read
  [configuration](references/configuration.md).
- For unsafe behavior, restoration, rollback, or removal, read
  [recovery](references/recovery.md).
- Before any package, configuration, service, boot, hardware, recovery, or
  removal mutation, also read [safety boundaries](references/safety.md).

Load only the references reached by the request.

## Authorization boundary

Run unprivileged, read-only inspection autonomously. Before a privileged or
mutating command, show the exact command or diff, its target, expected effect,
and rollback path; obtain explicit approval immediately before execution.
Never request, receive, log, or store a password. Let the user's terminal own
any credential prompt.

A request to install, configure, or operate the tool authorizes only that
requested mutation. It does not authorize service enablement, a boot-default
change, qualification, hardware writes, or weaker cooling.

## Fail closed

- Keep both fans in Firmware Auto unless the exact revision and machine have
  complete, matching qualification authority that explicitly permits Custom
  control.
- Never enable or start an unqualified/status-only build. A build, test,
  signature, release, package, boot, CI result, or preliminary hardware match
  is not runtime authority.
- Use only the in-tree `acer_wmi` hwmon interface authorized by the target
  revision. Raw EC/WMI writes, forced capabilities, replacement modules,
  manual output, module unload, and alternate write backends are outside the
  operating path.
- Stop at the first failed or ambiguous gate. If Firmware Auto cannot be
  confirmed immediately after unsafe behavior, stop load and shut the machine
  down; do not reboot or continue experimenting.

## Completion

Finish with a compact ledger: revision, support classification, authority
state, commands and files changed, service/fan state, validation evidence,
remaining blockers, and recovery path. Never describe a preliminary match or
disabled installation as supported or operational.
