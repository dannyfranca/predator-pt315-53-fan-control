# Supervised endurance harness protocol

`fan-control-qualify supervised-endurance` is the privileged production entrypoint for the
60-minute authorization run. It requires UID 0, root-owned protected prerequisite evidence, and a
root-owned executable hardware harness. The core runner owns the fixed schedule, deadlines,
validation, cleanup order, evidence publication, and qualification authorization decision.

The plan manifest is a root-owned JSON object with absolute paths:

```json
{
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
  --evidence-output /var/lib/pt31553-fan-control/evidence/endurance.json
```

For each operation the runner executes `HARNESS OPERATION ABSOLUTE_MONOTONIC_DEADLINE`, writes one
JSON request to stdin, and expects one JSON response on stdout. It kills the harness at the
deadline. Supported operations are:

- `capture-starting-conditions`
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

Responses use the corresponding serialized public `fan-control-core` evidence types. The harness
must perform direct hardware/service operations; it must not reinterpret the schedule. After any
failure the core runner exhausts workload termination first. Only after workload absence is
confirmed may it request service stop, CPU Auto, then GPU Auto. Only a complete passing report can
create `/var/lib/pt31553-fan-control/qualification.json`.
