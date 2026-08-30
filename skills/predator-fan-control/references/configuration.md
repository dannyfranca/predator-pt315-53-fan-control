# Configuration

Support exact requested values and goal-based requests such as quieter battery
operation. A goal-based request produces a proposal, never implicit permission
to apply it.

## Establish inputs

Read from the exact target revision:

- `config/example.toml`;
- its configuration parser and validator;
- its protected-envelope comparison implementation and tests;
- the canonical configuration-change runbook.

Then read the complete active editable configuration and, when an authorized
installation exists, its exact protected policy and qualification binding.
Operator configuration is never authority. Do not edit a protected policy,
qualification record, evidence, or compatibility declaration in place.

## Build and validate the candidate

For exact values, preserve all unrequested fields. For a goal, translate the
goal into explicit controls and complete AC/battery CPU/GPU curves, explaining
the cooling/noise tradeoff and every assumption.

Validate the complete candidate with the selected revision's own parser and
validator. Prefer a packaged read-only validator when present. Otherwise use a
temporary harness outside the checkout that calls that revision's exported
configuration parse and validation functions. TOML syntax alone is
insufficient. Remove the harness after validation and leave the source tree
unchanged.

When a protected policy exists, use the revision's protected-envelope
comparison rather than visual curve inspection. Classify the candidate as:

- `equivalent` or `more aggressive` only when the revision proves it never
  weakens the protected envelope; or
- `quieter/weaker` or `unproven` when any point, minimum, timing control, or
  identity fails that proof.

A quieter/weaker candidate requires the full requalification path declared by
the target revision. Keep the last working configuration active until that
qualification succeeds.

## Review and apply

Before writing, show:

- the complete unified diff and destination;
- parser/validator result and protected-envelope classification;
- whether the target revision consumes configuration at runtime;
- expected service effect, required requalification, backup, and rollback;
- the exact privileged write and service commands.

Wait for explicit approval. Then write a complete candidate atomically while
preserving the revision's required ownership and mode. Retain the protected
copy or backup required by the runbook; never overwrite the only known-working
copy.

For a `disabled-only` or status-only revision, an approved edit is offline
preparation only. State that it has no runtime effect, and do not start or
restart services.

For an `authorized` revision, use only its documented restart/reload contract.
Do not infer live reload. Afterward, rerun validation and inspect service,
journal, authority, and Firmware Auto/arming state exactly as the runbook
requires. On failure, restore the last working file through the recovery path.

The change is complete only when the on-disk file equals the approved diff,
validation still passes, runtime effect is truthfully stated, and rollback
remains available.
