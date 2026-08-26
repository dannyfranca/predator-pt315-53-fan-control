# Kernel source lock

`source-lock.toml` is the complete input allowlist for the stage-0 `linux-cachyos-gcc` candidate. It pins:

- the signed CachyOS tag, signed target commit/tree, release archive, detached archive signature, signer key, and authenticated signature-time policy;
- the signed CachyOS packaging commit/tree and the exact config contained by that snapshot;
- the machine-readable build environment, executable PKGBUILD-variable wrapper, and `makepkg.conf`;
- the raw, digest-addressed CachyOS v4 OCI manifest plus every referenced config/layer blob;
- the complete patch set (empty for stage 0).

Copy the eight tracked inputs into a disposable bundle:

```sh
cp packaging/kernel/build-environment.toml /bundle/
cp packaging/kernel/build-candidate /bundle/
cp packaging/kernel/makepkg.conf /bundle/
cp packaging/kernel/toolchain-image-manifest.json /bundle/
cp packaging/kernel/cachyos-7.1.8-1.tag /bundle/
cp packaging/kernel/cachyos-7.1.8-1.commit /bundle/
cp packaging/kernel/linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f.commit /bundle/
cp packaging/kernel/trust/cachyos-release-key.gpg /bundle/
```

Fetch the four upstream source inputs at their exact `origin` paths: release archive, detached archive signature, packaging archive, and `config`. Populate `/bundle/oci/blobs/sha256/` with the OCI config and every compressed layer blob recorded by the manifest; each blob's immutable registry URL, digest, path, and size is recorded in the lock. Keep every recorded filename and do not leave registry metadata or other files in the bundle.

Then make the staged bundle read-only and verify it offline:

```sh
chmod -R a+rX,a-w /bundle
mkdir -p "$PWD/build-output"
SOURCE_LOCK_OUTPUT="$PWD/build-output" scripts/verify-source-lock --inputs /bundle --exec-verified
```

The verifier hashes every allowlisted regular file through retained directory-bound file descriptors, rejects symlinks, hard links, writable bundles, and extra files, then rehashes all pinned descriptors and repeats the live path scan before success. It verifies every signature in a fresh, offline GnuPG home at `signature_verification_epoch`, rejects expired/revoked status at that time, and requires that epoch to equal the latest creation time authenticated by the verified signatures. This preserves reproducibility after later key expiry without trusting an arbitrary historical clock. It also verifies the signed tag→commit relation, both signed commit→tree relations, and detached release signature with the pinned key, reconstructs both archives' Git tree IDs, compares `config` and the effective recipe source program with the packaging archive, validates the raw OCI manifest and every blob, and cross-checks the wrapper's actual exported PKGBUILD variables with the build metadata.

`--exec-verified` copies only bytes held by the verifier's pinned descriptors into a private read-only snapshot and runs the locked executor from that snapshot, so a pathname replacement after verification cannot cross the handoff into the build. `build-candidate` is a low-level deterministic executor, not an authentication boundary: invoking it directly is explicitly unverified. Only a successful `verify-source-lock --exec-verified` run constitutes the verified handoff.

The wrapper reconstructs a temporary OCI layout from the verified manifest and blobs, imports it into disposable Podman root/runroot storage, and executes that exact manifest digest using `--pull=never`, no network, and a read-only container root. It extracts only the pinned packaging snapshot into a disposable work directory; clears ambient CI controls; exposes the verified source/config through a writable cache of read-only symlinks; writes packages only to the output mount; and explicitly selects CachyOS's default scheduler, GCC, `generic_v4`, no NVIDIA/ZFS/R8125 module build, and no external patches. The verifier accepts only a full build or `--verifysource`; arbitrary `makepkg` flags are rejected. `makepkg`'s inconsistent snapshot checksum array is bypassed only after the source-lock verifier has authenticated and hashed every input. The wrapper never uses the caller's checkout or host `makepkg`. This stage requires an empty patch set; a later stage must add an explicit staging/application mapping before non-empty patch inputs can verify.
