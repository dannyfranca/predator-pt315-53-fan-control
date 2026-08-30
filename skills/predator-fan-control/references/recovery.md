# Recovery, rollback, and removal

Unsafe behavior, an unexpected mode/RPM, missing telemetry, thermal risk,
service fault, planned update, rollback, and uninstall all enter the selected
revision's canonical maintenance/recovery boundary.

## Immediate response

Stop the exact dedicated workload using the revision's trusted ownership
record and prove it absent. Do not guess process names or kill unrelated work.
Then follow the documented service-stop order and independent Firmware Auto
restoration path for the current boot.

If the revision lacks the trusted workload launcher/record or the record is
invalid, do not improvise one. If either fan cannot be confirmed in Firmware
Auto immediately, stop load, keep AC connected when safe, and shut down. Do
not reboot, remove packages, clear faults, terminate an active restoration
helper, or try another backend.

Never invoke a candidate-only restoration helper from a stock kernel. Use only
normal firmware/operating-system restoration there.

## Recover or rearm

Preserve the smallest private evidence needed to diagnose the failure. Inspect
the revision's structured fault and correct its cause before clearing a latch
or restarting. Rearm only when the exact authority verifier passes again and
the operation runbook explicitly permits it. A restored Auto state is safety,
not authorization.

## Roll back or remove

Read the target revision's entire maintenance, rollback, retirement, and
return-to-stock sections before proposing mutations. Show the full sequence
and obtain approval before changing services, packages, kernels, modules, or
boot entries.

Require the documented cold/stock recovery boot, correct stock module/backend,
controller absence, disabled/inactive services, and Firmware Auto evidence
before package or candidate removal. Retain every stock recovery path and the
last-qualified archive until the revision's successor/removal criteria say it
may be retired.

Remove only exact package identities with the package manager's nonrecursive
operation documented by the revision. Do not invent cleanup for configuration,
package backups, authority, evidence, or state directories when the runbook
does not specify it. Report retained files instead.

Recovery/removal is complete only when both fan states, process/service states,
running/default boot identities, removed package identities, retained recovery
artifacts, and any blocked cleanup are explicitly verified and reported.
