# Supervised calibration and matched-workload harness protocol

`pt31553-fan-qualify fan-calibration` and `pt31553-fan-qualify matched-workload` are UID-0,
fail-closed entrypoints. Use only the protected manifest and harness described by
[`preflight-baseline-harness.md`](preflight-baseline-harness.md). The runner revalidates the fresh
preflight, all seven exact Firmware Auto baselines, live fan endpoint identities, and stage order
before any Custom write. Calibration additionally requires CPU before GPU. Matched runs require
both accepted calibrations.

Invocation:

```text
pt31553-fan-qualify fan-calibration --fan cpu --manifest FILE --harness FILE --observer-approval I-AM-PHYSICALLY-OBSERVING
pt31553-fan-qualify fan-calibration --fan gpu --manifest FILE --harness FILE --observer-approval I-AM-PHYSICALLY-OBSERVING
pt31553-fan-qualify matched-workload --manifest FILE --harness FILE --observer-approval I-AM-PHYSICALLY-OBSERVING
```

Each invocation grants approval for exactly one physical stage. `matched-workload` selects only the
next stage in the fixed twelve-stage matrix; invoke it twelve times and approve each invocation.
Existing evidence is resumed only when it is fresh, complete, passing, correctly ordered, and an
exact match for the envelope, baseline, workload, calibrations, and prior passing run.

The root-owned harness runs with `no_new_privs` in a private cgroup v2. Unlike read-only collection,
these operations retain UID 0 because they perform the direct fan writes. For each operation the
runner executes `HARNESS OPERATION ABSOLUTE_MONOTONIC_DEADLINE`, sends one JSON request on stdin,
and accepts one JSON response on stdout. The core fixes every calibration step, workload, cadence,
deadline, thermal limit, repeat count, and evidence decision. The harness must never choose or
weaken them.

Calibration operations:

- `begin-fan-calibration`: request `fan`; capture two fresh temperature/tachometer samples, confirm
  Auto, set both fans to maximum, then confirm Custom readbacks. Return `observer_present` and
  `confirmed`.
- `observe-calibration-level`: request `fan` and the exact serialized `CalibrationStep`. Execute
  only that step. Return `observer_present` and a serialized `CalibrationLevelObservation` as
  `observation`.
- `observe-calibration-hold`: same request; return `observer_present` plus a serialized
  `FanHoldObservation`. The hold must cover the required 15 minutes at no more than two-second
  sample gaps.
- `restore-fan-calibration`: request one `fan`; restore it to enable value `2` and return a
  serialized `MatchedWorkloadFanRestoration`. The runner calls it separately for CPU and GPU even
  if one fails. This operation must work after an error, timeout, observer abort, or signal.
- `finalize-fan-calibration`: after restoration, accept `fan`, the exact validated `calibration`,
  and `qualification_envelope`; return a complete schema-v2 `fan-calibration` `EvidenceRecord`.
  Commands must exactly bind the returned protocol checkpoint. No failed/incomplete record is
  publishable.

Matched-workload operations:

- `capture-matched-starting-conditions`: return `observer_present` and a serialized
  `CapturedMatchedWorkloadStartingConditions` as `observation`.
- `enter-matched-custom-control`: enter the already admitted path at maximum and confirm both
  Custom readbacks. Return `observer_present` and `confirmed`.
- `start-matched-workload`: start only the exact requested packaged `workload`; return
  `observer_present` and `started_at`.
- `capture-matched-observation`: request the exact NVIDIA UUID; return `observer_present` and a
  serialized `MatchedWorkloadObservation` as `observation`.
- `stop-matched-workload`: terminate and verify the workload is absent. Return `confirmed` (and an
  `observer_present` boolean, ignored during cleanup).
- `restore-matched-fan`: request `fan`; independently restore it to enable value `2` and return a
  serialized `MatchedWorkloadFanRestoration`. The runner calls it for both fans even if the first
  fails.

Loss of the observer, any invalid/missing/stale sample, deadline, wrong readback, instability,
thermal abort, workload failure, signal, or malformed response makes the stage no-go. The runner
terminates the harness cgroup, stops the workload where applicable, and attempts both Auto
restorations. It publishes only complete schema-valid records atomically and never overwrites an
existing path. Unconfirmed Auto requires immediate shutdown and independent recovery; otherwise
repair the prerequisite and begin a new protected evidence directory.
