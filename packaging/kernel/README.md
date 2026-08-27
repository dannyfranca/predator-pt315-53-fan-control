# Kernel source lock

`source-lock.toml` is the complete input allowlist for the stage-2 PWM
`linux-cachyos-gcc` candidate. It pins:

- the signed CachyOS tag, signed target commit/tree, release archive, detached archive signature, signer key, and authenticated signature-time policy;
- the signed CachyOS packaging commit/tree and the exact config contained by that snapshot;
- the machine-readable build environment, executable PKGBUILD-variable wrapper, and `makepkg.conf`;
- the raw, digest-addressed CachyOS v4 OCI manifest plus every referenced config/layer blob;
- the ordered GPL-2.0-only PT315-53 telemetry and PWM patches.

Copy the tracked metadata and patch inputs into a disposable bundle:

```sh
cp packaging/kernel/build-environment.toml /bundle/
cp packaging/kernel/build-candidate /bundle/
cp packaging/kernel/makepkg.conf /bundle/
cp packaging/kernel/toolchain-image-manifest.json /bundle/
cp packaging/kernel/cachyos-7.1.8-1.tag /bundle/
cp packaging/kernel/cachyos-7.1.8-1.commit /bundle/
cp packaging/kernel/linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f.commit /bundle/
cp packaging/kernel/trust/cachyos-release-key.gpg /bundle/
mkdir -p /bundle/patches
cp packaging/kernel/patches/0001-acer-wmi-add-pt31553-telemetry.patch /bundle/patches/
cp packaging/kernel/patches/0002-acer-wmi-enable-pt31553-pwm.patch /bundle/patches/
```

Fetch the four upstream source inputs at their exact `origin` paths: release archive, detached archive signature, packaging archive, and `config`. Populate `/bundle/oci/blobs/sha256/` with the OCI config and every compressed layer blob recorded by the manifest; each blob's immutable registry URL, digest, path, and size is recorded in the lock. Keep every recorded filename and do not leave registry metadata or other files in the bundle.

Also fetch the exact CachyOS v4 `bc` package at its locked `origin` into
`/bundle/build-tools/`. It is extracted without installation and used only to
generate the kernel time constants required before compiling `acer-wmi.c`.

Then make the staged bundle read-only and verify it offline:

```sh
chmod -R a+rX,a-w /bundle
mkdir -p "$PWD/build-output"
SOURCE_LOCK_OUTPUT="$PWD/build-output" scripts/verify-source-lock --inputs /bundle --exec-verified
```

For the stage-2 review gate, compile the patched translation unit in the same
verified, offline environment and retain the object plus its SHA-256 evidence:

```sh
SOURCE_LOCK_OUTPUT="$PWD/build-output" scripts/verify-source-lock \
  --inputs /bundle --exec-verified -- --compile-pwm
```

The verifier hashes every allowlisted regular file through retained directory-bound file descriptors, rejects symlinks, hard links, writable bundles, and extra files, then rehashes all pinned descriptors and repeats the live path scan before success. It verifies every signature in a fresh, offline GnuPG home at `signature_verification_epoch`, rejects expired/revoked status at that time, and requires that epoch to equal the latest creation time authenticated by the verified signatures. This preserves reproducibility after later key expiry without trusting an arbitrary historical clock. It also verifies the signed tag→commit relation, both signed commit→tree relations, and detached release signature with the pinned key, reconstructs both archives' Git tree IDs, compares `config` and the effective recipe source program with the packaging archive, validates the raw OCI manifest and every blob, and cross-checks the wrapper's actual exported PKGBUILD variables with the build metadata.

`--exec-verified` copies only bytes held by the verifier's pinned descriptors into a private read-only snapshot and runs the locked executor from that snapshot, so a pathname replacement after verification cannot cross the handoff into the build. `build-candidate` is a low-level deterministic executor, not an authentication boundary: invoking it directly is explicitly unverified. Only a successful `verify-source-lock --exec-verified` run constitutes the verified handoff.

The scope gate accepts exactly two ordered Linux changes. Stage 1 adds the exact
`Acer` / `Predator PT315-53` / `Civic_TLS` DMI entry and selects only
`.predator_v4 = 1`. Stage 2 adds only `.pwm = 1` to that model-specific quirk.
It rejects deletions, other files or models, forced capabilities, raw EC/WMI
access, and every unrelated kernel change. The gate applies the patch chain in
memory to the authenticated pinned `acer-wmi.c`; context drift fails before a
build starts.

Patch presence is not hardware qualification and does not authorize live fan
writes. The controller remains disabled until the exact candidate completes the
qualification and promotion gates.

The wrapper reconstructs a temporary OCI layout from the verified manifest and blobs, imports it into disposable Podman root/runroot storage, and executes that exact manifest digest using `--pull=never`, no network, and a read-only container root. It extracts only the pinned packaging snapshot into a disposable work directory; clears ambient CI controls; exposes the verified source/config/patch chain through a writable cache of read-only symlinks; adds only those patches to the authenticated recipe; writes packages only to the output mount; and explicitly selects CachyOS's default scheduler, GCC, `generic_v4`, and no NVIDIA/ZFS/R8125 module build. The verifier also accepts the exact `--compile-pwm` review gate, which extracts the locked `bc` executable into the disposable work directory and compiles only the patched `acer-wmi.o`; arbitrary `makepkg` flags are rejected. `makepkg`'s inconsistent snapshot checksum array is bypassed only after the source-lock verifier has authenticated and hashed every input. The wrapper never uses the caller's checkout or host `makepkg`.
