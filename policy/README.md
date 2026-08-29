# Protected policy boundary

The controller's editable configuration is not safety authority. A Protected
policy is an immutable, root-owned snapshot of the exact compatibility,
calibration, and curve envelope exercised during qualification. The generated
Qualification record binds its SHA-256 digest.

`qualified-envelope.example.toml` documents the complete format only. Its
placeholder identities and calibration data are deliberately unqualified. Do
not install it as authority and do not infer Custom-control authorization from
its presence, a successful build, or source-complete verification.

A real Protected policy is produced and reviewed for one exact machine before
qualification. Keep it beneath root-owned, non-writable ancestors; never edit
it in place. Any changed identity or policy requires a new qualification.
