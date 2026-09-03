# Acquisition, installation, status, and use

The exact target checkout owns all commands. Read its top-level status,
`SECURITY.md`, packaging recipes, and the complete relevant canonical runbook
section before proposing a command.

## Acquire and build a target revision

Acquire source from the official repository. Use a user-selected release tag
or reviewed pinned commit, resolve it to a 40-character commit, clone into a
new directory, check out that commit detached, and require a clean tree. Never
install a prebuilt release asset or substitute a floating branch at execution
time.

Fetch locked dependencies as documented, run the revision's local repository
policy, and build every executable and package locally with that revision's
documented commands. Retain the resolved source identity and locally built
artifact hashes in the ledger. Do not trigger remote CI unless the user
separately requests it; CI is not qualification authority.

If source, packaging, or installed identities disagree, stop. Never silently
rebuild a package recipe for a different commit.

## Inspect status

Use only status invocations documented by the target revision. Also inspect
package identity, running kernel/module, process presence, and each service's
enabled and active states. A command's zero exit status does not raise the
authority state.

Inspect command source when an interface is unclear. Do not assume `--help`,
`check-device`, `preflight`, live reload, or other conventional subcommands
exist. Never use a recovery command as a status query unless the revision
documents a separate read-only status mode.

## Install

1. Complete the support classification and establish the safe starting state.
2. Follow the selected revision's build/provenance and install runbook exactly.
   Missing signer enrollment, artifact identities, tools, recovery entries, or
   production stage commands are blockers, not placeholders to fill ad hoc.
3. Show the verified artifact identities, every package/boot/service mutation,
   and rollback path. Obtain approval immediately before the first mutation.
4. After installation, recheck package hashes, processes, unit enablement and
   activity, persistent boot default, and the fan state allowed by that boot.

For a `disabled-only` revision, install only the disabled candidate artifacts
explicitly allowed by its runbook. Keep controller units disabled and inactive,
keep the stock recovery kernels/entries and stock default, and stop at the
runbook's disabled-candidate boundary. Do not enable, start, qualify, promote,
or claim working fan control.

## Operate

For `disabled-only`, ordinary use consists only of documented source/status
commands and offline configuration preparation. State that active fan control
is unavailable.

For `authorized`, re-run the exact revision's authority verifier immediately
before enable/start or rearm. Follow its canonical operation commands without
translation, require fresh Firmware Auto, inspect service readiness and
structured faults, and preserve the documented stock recovery default. Any
missing verifier, failed check, stale record, or runtime fault returns to the
recovery path.

Installation/use is complete only when observed package, process, service,
boot, and fan states match the declared authority state and the user receives
the exact safe next boundary.
