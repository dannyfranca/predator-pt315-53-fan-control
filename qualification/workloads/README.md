# Fixed qualification workloads

These version `1.0.0` executables are the canonical commands recorded in qualification evidence.
Every executable accepts only `--fixed`. CPU load uses all online CPUs with `stress-ng`'s verified
`matrixprod` method. GPU load runs one fixed off-screen `glmark2` shading scene. `combined` runs both.

`mixed` begins with combined load and remains alive for the supervised 60-minute schedule. The
root-owned endurance harness sends `SIGUSR1` for a load segment and `SIGUSR2` for an idle segment;
termination stops and reaps both workload processes. The core qualifier owns segment timing and
validates observed utilization, power-profile transitions, thermal behavior, and cleanup.
