# Live lifecycle harness protocol

`pt31553-fan-qualify live-lifecycle` is the root-only coordinator for the approved live
lifecycle sequence. It revalidates the protected preflight, seven baselines, CPU/GPU
calibrations, and exact twelve matched runs before either phase. The operator must pass
`--observer-approval I-AM-PHYSICALLY-OBSERVING` on every invocation.
The protected stages manifest must include `qualification_harness_sha256`, the lowercase SHA-256
of the exact reviewed harness executable; a different executable is rejected before invocation.

The runner invokes `HARNESS OPERATION ABSOLUTE_MONOTONIC_DEADLINE`, writes one JSON request to
stdin, and reads one JSON response from stdout. The reviewed root-owned harness implements:

- `run-live-lifecycle-case`: request contains the serialized `case` and fixed `instruction`;
  response is `LiveLifecycleObserved<LiveLifecycleCaseObservation>`.
- `restore-live-lifecycle-after-case`: signal-safe stop/containment and firmware-ownership restore
  after every non-reboot case; response is `LiveLifecycleObserved<EvidenceTimestamp>`. It is always
  invoked before the independent terminal Auto reads, even when the case harness failed.
- `confirm-live-lifecycle-firmware-auto`: request contains `fan`; response is
  `LiveLifecycleFanAutoObservation`. This cleanup operation must remain available after a signal.
- `resume-live-lifecycle-reboot`: response is
  `LiveLifecycleObserved<LiveLifecycleRebootContinuation>` with distinct pre/post boot IDs and no
  Custom-control observer attestations.
- `arm-live-lifecycle-after-reboot`: response is
  `LiveLifecycleObserved<LiveLifecycleRebootArmObservation>`.
- `restore-live-lifecycle-after-reboot`: stops the post-boot controller and restores firmware
  ownership; response is `LiveLifecycleObserved<EvidenceTimestamp>`. This cleanup operation must
  remain available after a signal.

`LiveLifecycleObserved<T>` is `{ "observation": T, "observer_attestations": [...] }`. Each
attestation contains `action`, `started_at`, `completed_at`, and `checks`. `checks` includes both
endpoints and has no monotonic or wall-clock gap over 5 seconds. The first and last attestations
must also bridge the complete live case boundary within 5 seconds. The exact ordered live actions are:

- duplicate process: `duplicate-owner-custom`, `duplicate-process-cleanup`
- normal stop/restart: `normal-owner-before-stop`, `normal-restart-custom`, `normal-stop-restart-cleanup`
- SIGKILL recovery: `process-before-kill`, `bounded-restart-custom`, `process-kill-recovery-cleanup`
- watchdog recovery: `watchdog-monitored-custom`, `bounded-restart-custom`, `watchdog-recovery-cleanup`
- AC transition: `ac-transition-custom`, `ac-to-battery-transition-cleanup`
- suspend/resume: `pre-suspend-custom`, `post-resume-custom`, `suspend-resume-cleanup`
- reboot arm/restore: `post-reboot-arm`, `post-reboot-restore`

Invalid configuration has no Custom action and returns an empty list. A missing, stale, reordered,
or gapped attestation, or coverage that misses its typed action timestamp, fails the case; cleanup
and terminal Auto verification still run.

The first invocation rejects any initial fan enable endpoint that differs from the protected
preflight identities, runs the seven pre-reboot cases, independently confirms both fans in Auto
between cases, captures `/proc/sys/kernel/random/boot_id`, and atomically publishes
`live-lifecycle-checkpoint.json`. The checkpoint includes a hash of the exact prerequisite records.
Reboot normally; do not arm Custom during boot. The second invocation revalidates every nested
timestamp and that prerequisite hash before any live action, and requires the continuation's
pre-reboot ID to equal the captured ID. It then confirms a distinct current boot and both fan
endpoints in Auto before post-boot arming. The coordinator stops that controller and independently
reconfirms both fans in Auto before publishing. Only a complete passing sequence publishes
`live-lifecycle.json`; after that durable publication, the coordinator durably removes the
checkpoint. A crash between those operations leaves a residual checkpoint; the next lifecycle
invocation validates it against the accepted evidence before removing it, and endurance refuses to
start while it remains. A partial, stale, failed, reordered, identity-mismatched, substituted, or
no-reboot checkpoint is a no-go.

Never implement dangerous live sensor, write, tachometer, or restoration fault injection. Those
faults belong to the deterministic fake-platform suites.
