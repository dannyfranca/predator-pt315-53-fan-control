# Safety boundaries

Read the selected revision's `SECURITY.md` and canonical runbook before every
mutation. When they conflict with this reference, choose the path that leaves
the controller stopped and both fans in Firmware Auto, then report the
contradiction.

## Approval gate

Read-only, unprivileged inspection may proceed autonomously. Present and obtain
approval for the exact operation immediately before any of these:

- package installation, update, downgrade, or removal;
- configuration or protected-artifact write;
- service enable, disable, start, stop, restart, or reset;
- boot entry, boot default, kernel, module, or Secure Boot change;
- qualification, restoration, or other hardware-affecting command.

Batch only mutations that share one stated outcome and rollback. A later or
materially different mutation needs a new approval. Credential entry belongs
in the user's terminal; secrets and raw private evidence stay out of chat and
logs.

## Authority ladder

Use these states:

- `disabled-only`: source or installation is explicitly unqualified,
  status-only, missing authority, or prohibited from enable/start.
- `authorized`: the exact revision's documented verifier accepts matching
  protected policy, qualification, evidence, package, kernel/module, machine,
  and Firmware Auto observations, and its runbook explicitly permits the
  requested action.
- `blocked`: observations conflict, a required verifier/entrypoint is absent,
  identities are placeholders, or safe state cannot be established.

Default to `blocked`. Never infer `authorized` from nearby model names, a
successful build, release status, signatures alone, or records from another
machine or revision.

## Firmware Auto boundary

Before an authorized path can enter Custom control, require the exact
revision's fresh read-only gate and both fan enable endpoints in Firmware Auto.
After every fault or hardware-writing stage, stop the workload and normal fan
writes, stop the controller as ordered by the runbook, restore independently,
and confirm both endpoints in Auto.

The restoration helper is not a support probe. Run it only in the boot and
state explicitly permitted by the selected revision. In particular, never run
a candidate-only restoration helper from a stock kernel.

If either Auto readback is unavailable or not confirmed after unsafe behavior,
stop load, keep AC connected when safe, and shut down. Do not reboot, change
packages, clear a fault, or try an alternate write path.

## Fixed exclusions

Use only the standard in-tree `acer_wmi` Acer hwmon ABI admitted by the target
revision. Refuse raw EC or WMI access, forced capability flags, replacement or
out-of-tree control modules, module unload, manual/fixed fan output, alternate
backends, qualification shortcuts, and ad-hoc substitutes for missing stage
commands.
