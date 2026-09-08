# Kernel source lock

`source-lock.toml` is the complete input allowlist for the side-by-side
`linux-cachyos-pt31553` package set. It pins:

- the signed CachyOS tag, signed target commit/tree, release archive, detached archive signature, signer key, and authenticated signature-time policy;
- the signed CachyOS packaging commit/tree and the exact config contained by that snapshot;
- the machine-readable build environment, executable PKGBUILD-variable wrapper, and `makepkg.conf`;
- the raw, digest-addressed CachyOS v4 OCI manifest plus every referenced config/layer blob;
- the complete 191-package build-root update/dependency transaction and all
  detached signatures, including GCC, Rust, Rust source, bindgen, and pahole;
- NVIDIA open-kernel-module source 610.57.04 and both immutable CachyOS patch revisions;
- the ordered GPL-2.0-only PT315-53 telemetry and PWM patches.

Copy the tracked metadata and patch inputs into a disposable bundle:

```sh
cp packaging/kernel/build-environment.toml /bundle/
cp packaging/kernel/build-candidate /bundle/
cp scripts/check-sensitive-history /bundle/
cp packaging/kernel/makepkg.conf /bundle/
cp packaging/kernel/toolchain-image-manifest.json /bundle/
cp packaging/kernel/cachyos-7.1.8-1.tag /bundle/
cp packaging/kernel/cachyos-7.1.8-1.commit /bundle/
cp packaging/kernel/linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f.commit /bundle/
cp packaging/kernel/trust/cachyos-release-key.gpg /bundle/
mkdir -p /bundle/patches
mkdir -p /bundle/nvidia
cp packaging/kernel/patches/0001-acer-wmi-add-pt31553-telemetry.patch /bundle/patches/
cp packaging/kernel/patches/0002-acer-wmi-enable-pt31553-pwm.patch /bundle/patches/
```

Fetch the four kernel/packaging inputs at their exact `origin` paths: release
archive, detached archive signature, packaging archive, and `config`. Also
fetch the locked NVIDIA source archive into `/bundle/` and its two locked
CachyOS patches into `/bundle/nvidia/`. Populate
`/bundle/oci/blobs/sha256/` with the OCI config and every compressed layer
blob recorded by the manifest. Every immutable URL, digest, path, and size is
recorded in the lock. Keep every recorded filename and do not leave registry
metadata or other files in the bundle.

Also fetch the exact CachyOS v4 `bc` package at its locked `origin` into
`/bundle/build-tools/`. It is extracted without installation and used only to
generate the kernel time constants required before compiling `acer-wmi.c`.

For the full package build, populate `/bundle/build-dependencies/` with every
`build-dependency` input, preserving the exact locked filenames. These are
191 package archives plus their 191 detached signatures; the verifier pins
the entire closure independently and rejects omitted or changed entries.
Signatures can also be recovered from a repository database's `%PGPSIG%`
field when a mirror omits the separate `.sig` URL, but the recovered bytes
must match the locked signature hash. Repository databases are acquisition
metadata only and never enter the offline build. The Rust source archive
uses Arch's exact-version archive URL because the CachyOS mirror no longer
serves the selected source package. All selected archives were authenticated
with the distribution package-signing trust before the lock was recorded.

The pinned base image alone lacks the kernel recipe's build dependencies.
Before a full build, the wrapper updates only a disposable rootless
container using these authenticated local archives, with networking off,
trusted package signatures required, and normal dependency checks intact.
It refreshes public Arch keyring data only from the locked keyring archive.
No host package or trust store is modified. Source workspaces, output paths,
and signing keys are absent from this preparation container. The resulting
local image ID is then used read-only as UID 1000 for compilation, with the
provisioning flag explicitly cleared. The base OCI and all update inputs
remain in the retained source lock; package `.BUILDINFO` records the actual
installed build environment. The compile-only review gate still uses the
original immutable image and its separately locked `bc` executable.

Prepare a separate, non-symlink signing directory containing exactly the
operator-controlled signing inputs used during the handoff:

- `module-signing-key.pem`
- `module-signing-certificate.der`
- `kernel-signing-key.pem`
- `kernel-signing-certificate.pem`

The module certificate must be DER; the Secure-Boot certificate must be PEM.
The directory and all four files must be owned by the invoking user. Set the
directory to mode `0700`, private keys to `0600` or stricter, and certificates
to a mode without group/other write permission. The executor snapshots all
four no-follow-opened inputs into private storage, validates the snapshot, and
uses only those pinned bytes through build and final signing. Keep the source
directory outside the bundle, output, and source tree. Then make the staged
bundle read-only and build/sign it offline:

```sh
chmod -R a+rX,a-w /bundle
mkdir -p "$PWD/build-output"
SOURCE_LOCK_SIGNING_DIR=/secure/signing \
SOURCE_LOCK_OUTPUT="$PWD/build-output" \
  scripts/verify-source-lock --inputs /bundle --exec-verified
```

The default verified execution emits exactly three non-stock package names:
`linux-cachyos-pt31553`, `linux-cachyos-pt31553-headers`, and
`linux-cachyos-pt31553-nvidia-open`. The output directory must be empty. It
retains the complete build log, source lock, build environment, generated
`.SRCINFO`, package checksums, and each package's `.BUILDINFO`, `.MTREE`,
and `.PKGINFO`. The verified build injects the external module key only into
its disposable kernel tree, retains the matching public certificate in the
headers package, signs the packaged kernel image with the external
Secure-Boot identity, rebuilds its package metadata, and rewrites
`SHA256SUMS`. The Secure-Boot key stays on the host, and the completed output
replaces the empty destination only after every finalization step succeeds.
No private key enters a package or retained evidence.
The locked make configuration uses GNU make's silent mode to avoid retaining
tens of thousands of routine Kbuild progress records. Compiler warnings, errors,
and failure status remain intact; the complete emitted output is retained and
must pass the unchanged bounded sensitive-evidence scanner.
The disposable kernel build uses `CONFIG_MODULE_SIG_KEY="certs/pt31553-signing-key.pem"`,
not the kernel's auto-generated default key path. The wrapper assembles the
externally supplied module key and matching public certificate into that
owner-readable-only PEM bundle. It runs `syncconfig` before makepkg normalizes
source timestamps, so generated configuration cannot retain the default key.
The kernel generates `certs/signing_key.x509` from this bundle; do not preseed
that build target as read-only. Only the public certificate is copied into the
headers package. The provenance verifier requires the explicit external-key setting.
The verifier places the exact parsed source-lock bytes into its private
snapshot for retention; do not add `source-lock.toml` to the input bundle.

### Root-only Secure Boot signing with sbctl

Do not copy an existing root-only Secure Boot key into the build account.
For machines using sbctl's `/var/lib/sbctl/keys/db/{db.key,db.pem}`, the optional
`root-sbctl` mode retains that key's protection. After reviewing the helper,
and with explicit operator approval, install it as a root-owned executable:

```sh
sudo install -D -o root -g root -m 0755 scripts/pt31553-sign-kernel \
  /usr/local/libexec/pt31553-sign-kernel
```

This adds no Polkit rule, setuid bit, daemon, boot entry, or trust enrollment.
Each invocation uses ordinary `pkexec` authentication. The helper accepts
only `certificate CERT_SHA256` or `sign CERT_SHA256 IMAGE_SHA256`; it reads
image bytes from standard input and returns verified signed bytes on standard
output. It never accepts caller-selected file paths, executes build code as
root, or exports private-key bytes. Its fixed key path and every ancestor must
be root-controlled, with the key private. Image staging is root-only under
`/run` and removed on success or failure. Signing grants trust to bootable code;
authenticate only the reviewed candidate's signing operation.

Obtain the expected DER fingerprint from the independently approved/enrolled
identity, then export only the matching public certificate:

```sh
: "${PT31553_KERNEL_CERT_SHA256:?set the independently approved DER fingerprint}"
: "${PT31553_KERNEL_SIGNING_DIR:?set the absolute private signing directory}"
pkexec /usr/local/libexec/pt31553-sign-kernel certificate \
  "$PT31553_KERNEL_CERT_SHA256" \
  >"$PT31553_KERNEL_SIGNING_DIR/kernel-signing-certificate.pem"
```

For this mode the caller-owned signing directory must contain exactly **three**
files: the module key, module DER certificate, and kernel PEM certificate listed
above. A kernel private key in that directory is rejected. The executor verifies
the installed helper's root ownership and exact reviewed source digest before
building, snapshots these three files, and independently verifies the returned
image signature before package publication. Use:

```sh
SOURCE_LOCK_KERNEL_SIGNER=root-sbctl \
SOURCE_LOCK_KERNEL_CERT_SHA256="$PT31553_KERNEL_CERT_SHA256" \
SOURCE_LOCK_SIGNING_DIR="$PT31553_KERNEL_SIGNING_DIR" \
SOURCE_LOCK_OUTPUT="$PWD/build-output" \
  scripts/verify-source-lock --inputs /bundle --exec-verified
```

For the canonical `scripts/build-source-candidate` command, prefix the existing
README invocation with `SOURCE_LOCK_KERNEL_SIGNER=root-sbctl`; its mandatory
`--kernel-cert-sha256` supplies the approved identity. Keep the operator present
for the signing prompt after compilation. The default `file` mode remains for
separately provisioned caller-owned signing identities. To remove this optional
integration, remove only `/usr/local/libexec/pt31553-sign-kernel` with approval;
do not remove or alter the sbctl key, certificate, or firmware trust.

## Offline package provenance verification

Verify the resulting signed package set without network access or live
trust-store access. Supply three distinct public X.509 certificates:
the packaging signer, the certificate embedded by the kernel for module trust,
and the previously confirmed enrolled Secure-Boot image signer. Keep all
signing material outside the source tree and build-evidence directory.

Obtain the three expected SHA-256 certificate fingerprints from the independent,
reviewed trust-approval record. Do not derive expected values from the supplied
certificates; the verifier hashes those certificates and compares them with the
externally approved identities.

From the verified build handoff, sign the retained package manifest with its
dedicated packaging key. Keep the signature outside the build-evidence
directory so its exact top-level set remains closed:

```sh
openssl cms -sign -binary \
  -in "$PWD/build-output/SHA256SUMS" \
  -signer /secure/public/package-signing-certificate.pem \
  -inkey /secure/private/package-signing-key.pem \
  -outform DER -out /secure/public/package-set.p7s \
  -nocerts -noattr -md sha256
```

Then run:

```sh
scripts/verify-package-provenance \
  --artifacts "$PWD/build-output" \
  --module-cert /secure/signing/module-signing-certificate.der \
  --module-cert-sha256 MODULE_CERTIFICATE_SHA256 \
  --package-cert /secure/public/package-signing-certificate.pem \
  --package-cert-sha256 PACKAGE_CERTIFICATE_SHA256 \
  --kernel-cert /secure/public/enrolled-image-signing-certificate.pem \
  --kernel-cert-sha256 IMAGE_CERTIFICATE_SHA256 \
  --package-manifest-signature /secure/public/package-set.p7s \
  --output "$PWD/package-provenance-v1.json"
```

The verifier uses only its fixed `/usr/bin` paths for `bsdtar`, compression
tools, `modinfo`, `openssl`, and `sbverify`; ambient `PATH` entries cannot
replace a verification tool.
It reads no network resource, keyring, MOK database, firmware variable, or
machine certificate store. The expected fingerprints are mandatory so a
different public certificate cannot be substituted at verification time.

`provenance-policy.toml` pins the stable package set, versions, kernel release,
kernel and NVIDIA source identities, image path, `acer_wmi` path, and complete
bundled NVIDIA module path set. Signer identities are deliberately not
committed authority: the three mandatory expected DER fingerprints must match
the three supplied public certificates, must be distinct, are verified against
the actual package manifest/modules/image, and are recorded in the generated
unqualified provenance. Placeholder fingerprints are rejected.
The verifier then:

- rechecks the retained source lock and build environment against this source
  tree;
- authenticates the exact retained evidence set, including the effective
  `PKGBUILD`, build log, source metadata, and all package metadata; the signed
  `build-attestation.toml` binds the source lock and build environment to the
  exact recipe and `.SRCINFO`, while every `.BUILDINFO` binds back to that
  recipe;
- binds every package archive to its retained `.PKGINFO`, `.BUILDINFO`,
  `.MTREE`, checksum, package base, version, architecture, and complete shared
  build provenance, after authenticating `SHA256SUMS` with the expected
  packaging certificate;
- cryptographically verifies the detached PKCS#7 signature appended to
  `acer_wmi` and every bundled NVIDIA module using only the expected module
  certificate and SHA-512 CMS digests, matching the pinned kernel config;
- proves the signed kernel image contains the exact module trust certificate,
  and binds it to the packaged `.config` and `signing_key.x509`;
- requires the NVIDIA package to depend on the exact custom kernel,
  `nvidia-utils` release, and `libglvnd`, provide `NVIDIA-MODULE`, and conflict
  with the corresponding proprietary custom-kernel module package;
- requires exact module names, package ownership, paths, hashes, source
  identities, and kernel-bound vermagic;
- verifies the packaged kernel image signature with `sbverify` and the expected
  enrolled-signer certificate; and
- creates a new, read-only JSON record matching
`schemas/package-provenance-v1.json` and containing only portable identities
and hashes. Publication is atomic and no-clobber. It never serializes
certificate bytes, signature bytes, or input paths.

Private-key files, private-key content, and machine trust-store paths are
rejected in both retained evidence and package contents. Never pass a private
key, machine trust-store export, or unredacted machine evidence. A
successful package-provenance record is a qualification prerequisite; it does
not itself qualify hardware or authorize fan writes.

## Coherent source-candidate build

Top-level README step 3 is the sole canonical local wrapper invocation. It
derives the clean, non-shallow builder checkout's `source_revision` from
`HEAD` and publishes exactly to
`$(dirname "$source_root")/pt31553-source-candidate-$source_revision`. The
wrapper performs the authenticated kernel build,
package-manifest signing and provenance verification, generated compatibility
binding, controller build/signature verification, and final identity
declaration as one fail-closed operation. The three expected certificate
fingerprints must come from independent review outside the repository and
evidence; they must not be derived from the presented certificates. Do not
copy or translate that command here; follow the top-level runbook so build and
install resolve the same deterministic tree.

It requires a clean reviewed checkout and a new secure output directory. The
output contains `package-provenance-v1.json`, the compatibility declaration,
and `candidate-identity-v1.json` alongside packages and detached signatures.
The final manifest conforms to `schemas/candidate-identity-v1.json`, is always
`unqualified` and `disabled-only`, preserves `linux-cachyos-lts` as recovery,
and cannot designate the candidate as default. Private keys and machine trust
remain external. The controller source is a local archive of the controller
recipe's committed source-lock revision, and Cargo runs offline against
preseeded locked dependencies. Missing dependencies fail rather than being
installed. The wrapper never installs host packages, edits boot state, enables
services, or invokes GitHub Actions. Seed `--cargo-home` from the exact
controller `_commit` lock as shown in the top-level runbook. Unsafe inherited
environment overrides are rejected before signing.

CI also runs `scripts/check-sensitive-history` against every reachable Git
blob and historical path. Run it locally before publishing; deleting a secret
in a later commit does not make the history gate pass.

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

The recovery package remains stock `linux-cachyos-lts` 6.18. It is always
Firmware Auto recovery and is explicitly not PWM-capable.

The wrapper reconstructs a temporary OCI layout from the verified manifest and blobs, imports it into disposable Podman root/runroot storage, and uses that exact manifest digest as the base for the locked offline dependency transaction described above. Compilation then uses the derived local image ID with `--pull=never`, no network, an explicit unprivileged UID, and a read-only container root. It extracts only the pinned packaging snapshot into a disposable work directory; clears ambient CI controls; exposes the verified source/config/patch chain through a writable cache of read-only symlinks; assigns the unique package base and kernel release suffix; adds only the locked PT315-53 patches to the authenticated recipe; builds the matching locked NVIDIA open module; writes packages and retained evidence only to the output mount; and explicitly selects CachyOS's default scheduler, GCC, `generic_v4`, and no ZFS/R8125 module build. The verifier also accepts the exact `--compile-pwm` review gate, which extracts the locked `bc` executable into the disposable work directory and compiles only the patched `acer-wmi.o`; arbitrary `makepkg` flags are rejected. `makepkg`'s inconsistent snapshot checksum array is bypassed only after the source-lock verifier has authenticated and hashed every input. The wrapper never uses the caller's checkout or host `makepkg`.
