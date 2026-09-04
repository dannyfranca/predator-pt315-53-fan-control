# Supervised endurance harness protocol

`fan-control-qualify supervised-endurance` is the privileged production entrypoint for the
60-minute authorization run. It requires UID 0, root-owned protected prerequisite evidence, and a
root-owned executable hardware harness. The core runner owns the fixed schedule, deadlines,
validation, cleanup order, evidence publication, and qualification authorization decision.

The plan manifest is a root-owned JSON object with absolute paths:

```json
{
  "qualification_harness_sha256": "lowercase SHA-256 of the reviewed harness executable",
  "preflight": "/var/lib/pt31553-fan-control/evidence/preflight.json",
  "baselines": ["seven evidence paths"],
  "matched_workload_runs": ["twelve evidence paths"],
  "cpu_calibration": "/var/lib/pt31553-fan-control/evidence/cpu-calibration.json",
  "gpu_calibration": "/var/lib/pt31553-fan-control/evidence/gpu-calibration.json",
  "live_lifecycle": "/var/lib/pt31553-fan-control/evidence/live-lifecycle.json"
}
```

Invocation:

```text
fan-control-qualify supervised-endurance \
  --manifest /etc/pt31553-fan-control/endurance-plan.json \
  --harness /usr/lib/pt31553-fan-control/endurance-harness \
  --observer-approval I-AM-PHYSICALLY-OBSERVING \
  --evidence-output /var/lib/pt31553-fan-control/evidence/endurance.json
```

For each operation the runner executes `HARNESS OPERATION ABSOLUTE_MONOTONIC_DEADLINE`, writes one
JSON request to stdin, and expects one JSON response on stdout. It kills the harness at the
deadline. Supported operations are:

- `capture-starting-conditions`
- `confirm-endurance-firmware-auto` (called once per fan before the run; returns a fresh
  `LiveLifecycleFanAutoObservation` for the currently discovered endpoint)
- `confirm-endurance-observer` (returns `{ "observer_present": true, "confirmed": true,
  "observed_at": <evidence timestamp> }`)
- `enter-custom-control`
- `begin-segment`
- `start-workload`
- `capture-observation`
- `stop-workload`
- `contain-workload` (hard-stop escalation after an unconfirmed normal stop)
- `force-contain-workload` (terminal process-group/cgroup kill and absence confirmation)
- `stop-service`
- `contain-service` (hard-stop escalation after an unconfirmed normal stop)
- `force-contain-service` (terminal unit/cgroup kill and absence confirmation)
- `restore-fan`
- `contain-fan-maximum` (direct maximum command; never selects Auto first). Its response must
  independently report `enable_readback: 1`, `pwm_write_succeeded: true`, `pwm_readback: 255`,
  the matching `enable_endpoint_identity` and `pwm_endpoint_identity`, and
  `outcome: "maximum-containment-confirmed"`. An asserted outcome alone is rejected.

Responses use the corresponding serialized public `fan-control-core` evidence types. The harness
must perform direct hardware/service operations; it must not reinterpret the schedule. Observer
presence is reconfirmed before entering Custom, each segment transition, workload start, every
two-second sample, and before and after workload/service shutdown. Control and shutdown calls are
capped to the five-second observer interval. Those timestamped confirmations are persisted in the
evidence; a passing run allows no gap greater than five seconds through confirmed service
shutdown. A sample exactly at a segment boundary belongs to the ending segment; the next segment
must be confirmed before the following two-second sample is due. After any failure or observer
withdrawal the core runner exhausts workload
termination first, including an explicit absence check when workload start was never attempted. If
workload absence cannot be proved, the runner still exhausts service containment to stop further
Custom writes. Once service absence is confirmed, it commands and confirms direct maximum fan
containment without selecting Auto. Normal fan restoration remains gated on both workload absence
and confirmed service containment. It then attempts CPU Auto and GPU Auto. Each `restore-fan`
operation reports only its Firmware Auto attempt. If either Auto confirmation fails, the coordinator
invokes `contain-fan-maximum` for both fans and accepts containment only from the independent strict
mode, PWM, and endpoint readbacks described above.
Before the first Custom write, the coordinator freshly confirms both lifecycle-bound physical
fan endpoints remain in Firmware Auto. The evidence binds every prerequisite source byte, including
the lifecycle record. Endurance evidence is staged first and is not authorization. A termination
signal and the final qualification-record commit race on one atomic state: a signal that wins
removes the staged evidence and publishes no authorization; a completed commit cannot be
retroactively withdrawn. Only a complete passing report can create the qualification commit marker
at `/var/lib/pt31553-fan-control/qualification.json`.
