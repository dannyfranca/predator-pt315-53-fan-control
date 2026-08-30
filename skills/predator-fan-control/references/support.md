# Support checks

Compatibility inspection is read-only. It can reject a target or identify a
preliminary match; it cannot qualify hardware or authorize Custom control.

## Select the declaration

From the exact target checkout, read `compatibility/*.toml`, the supported
scope in `README.md` and `CONTRIBUTING.md`, and current release support in
`SECURITY.md`. Do not carry identities from another revision. Treat impossible
hashes, placeholder signers, or an explicit unqualified declaration as an
authority blocker.

## Observe without writes

Collect only facts required by the selected declaration:

- DMI product, board, and BIOS values from `/sys/class/dmi/id/`;
- architecture, operating system, running kernel release, and package identity;
- Secure Boot state and boot entry/default state when readable;
- loaded `acer_wmi` module path, provenance, hash, signer, and vermagic;
- the unique Acer hwmon device, required endpoint names, file identity and
  permissions, and read-only mode/RPM values;
- CPU/GPU temperature sources, power source, competing controller services,
  and installed tool identities when required by the declaration.

Prefer direct reads and package/module metadata commands. Avoid broad system
dumps: serial numbers, usernames, hostnames, unrelated logs, and private
qualification evidence are not needed. Never write a PWM or enable endpoint,
start a service, load/unload a module, run a workload, or invoke restoration as
a compatibility check.

## Classify

Return exactly one result:

- `unsupported`: at least one observed fact definitively conflicts with the
  exact supported envelope or uses an excluded model, distribution, module, or
  backend.
- `preliminary match`: every safely observable fact required for preliminary
  triage matches, with no contradiction. List every unproven release,
  provenance, qualification, or authority fact. This result never means
  `supported`.
- `indeterminate`: a required observation is missing, unreadable, ambiguous,
  stale, or cannot be tied to the selected revision.

An unsupported result ends installation and all hardware/service mutation. A
preliminary match may proceed only to the selected revision's disabled
preparation steps. An indeterminate result stays read-only until its evidence
gap is resolved.

The check is complete only when every field in the target declaration is
listed as matching, conflicting, or unresolved and the report separately
states the authority state.
