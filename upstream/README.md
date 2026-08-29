# Optional upstream path

This directory documents process only. It contains no compatibility claim and
no upstream-ready patch series.

Prepare an upstream submission only after exact-machine telemetry and PWM
qualification. At that point, add the narrow Linux patch series, cover letter,
sanitized test summary, `checkpatch` result, maintainer-routing result, and
submission notes. Keep downstream package and fan-policy details out of the
kernel patch.

Upstream acceptance never transfers local qualification or authorizes Custom
control. Treat any upstream or backported driver change as a new candidate and
repeat the documented build, recovery, and requalification process.
