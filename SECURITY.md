# Security policy

This project controls cooling hardware. Treat unexpected fan behavior as a safety issue.

## Reporting privately

Do not open a public issue for a vulnerability, unsafe fan behavior, a bypass of fail-closed checks, or qualification evidence that may identify a machine or person. Contact the maintainer through the private contact method published on the [repository owner's GitHub profile](https://github.com/dannyfranca). Share only a minimal, non-sensitive summary until a secure channel is agreed.

Include, when safe and relevant:

- the exact `Predator PT315-53` DMI product/board identity and BIOS version;
- CachyOS, kernel, `acer_wmi`, Secure Boot, and signer identities;
- the observed fan modes, PWM/readback behavior, temperatures, and restoration result;
- the smallest reproducible sequence and the commit tested; and
- redacted logs or qualification evidence.

Never include passwords, tokens, private keys, serial numbers, usernames, hostnames, home-directory paths, or unrelated system data. Qualification records and logs can expose hardware, software, timing, and workload details; keep them private by default and redact them before sharing. Maintainers may request a narrower excerpt instead of a complete evidence record.

## Unsafe behavior

If a fan stops, becomes erratic, fails to return to Firmware Auto, or temperatures become unsafe:

1. Stop the controller or qualification run. Do not continue reproducing.
2. Use only the normal firmware or operating-system controls to return both fans to Firmware Auto.
3. Confirm both fans report Firmware Auto. If that cannot be confirmed immediately, shut down the machine.
4. Do not bypass safety checks, force capabilities, write the embedded controller directly, or load an unqualified replacement module.

This source tree is currently unqualified and not configured for active fan control. Only the current `main` branch is maintained; no released version is presently supported.
