# Predator PT315-53 fan control

Source status: **unqualified and not configured**. This repository supports
only the documented build and disabled package installation; it does not yet
authorize Custom fan control or service enablement.

## Workspace

- `fan-control-core`: shared library
- `fan-control-daemon`: future automatic controller
- `fan-control-restore`: independent Firmware Auto restoration tool
- `fan-control-qualify`: privileged supervised qualification runner

Build and test every workspace member:

```console
cargo build --workspace
cargo test --workspace
```

Run the complete offline simulated-fault qualification gate without host hardware or services:

```console
cargo test -p fan-control-core --test simulated_fault_orderings
```

The guided live-lifecycle stage is exposed through
`run_live_lifecycle_qualification`. It orders invalid-configuration, duplicate-process,
normal stop/restart, `SIGKILL`, watchdog, AC-to-battery, suspend/resume, and reboot checks.
Every case must finish with independent CPU and GPU Firmware Auto (`2`) readbacks before
the next case. Its environment supplies fresh typed observations; a persisted outer
qualification coordinator must resume after reboot with distinct boot IDs and confirm both
fans in Auto before arming. The reboot boundary is deliberately split: `resume_after_reboot`
cannot arm the controller, and `arm_after_reboot` is called only after the core runner's fresh
CPU/GPU Auto gate succeeds. Suspend/resume evidence records ordered resume and process-start
times plus distinct pre-sleep and post-resume process identities. Invalid-configuration and
duplicate-process results carry fresh case-window timestamps; duplicate, normal restart, crash,
watchdog, and resume checks bind distinct before/after process identities. Raw WMI/EC access,
module unload, fan disconnection, kernel crash,
power cut, and real hardware-write failure injection are explicitly refused; those cases
belong only in the simulated gate. Before each crash case, the coordinator must safely run
`systemctl reset-failed pt31553-fand.service` while the healthy owner remains active; the recorded
reset preserves a fresh two-start budget. Crash cases pin the installed two-second restart delay
and two-start lifetime limit; Firmware Auto restoration itself remains unbounded and blocks
restart until safe.

Status invocations do no hardware or service work and exit after reporting the
current source role:

```console
cargo run -p fan-control-daemon
cargo run -p fan-control-restore -- --status
cargo run -p fan-control-qualify
```

`fan-control-restore --restore` is the explicit root service recovery mode. It
discovers the exact Acer hwmon device, owns the controller lock, requests and
confirms Firmware Auto for both fans, contains any confirmed-Custom fan at
maximum if restoration fails, and retries until Auto is confirmed.

## Canonical runbook: status, build, and disabled install

> **QUALIFICATION STATUS: UNQUALIFIED.** Source, a successful build, a package
> signature, CI, a tag, a release, or a bootable candidate does not authorize
> Custom control. Keep both fans in Firmware Auto (`2`) unless every later
> qualification and authority gate has passed for this exact machine.

This is the first operator runbook section. Stop on every failed command. It
prepares a disabled candidate only; it does not perform qualification,
enablement, or promotion.

### 1. Confirm scope and the safe starting state

The only supported hardware identity is Acer `Predator PT315-53`, board
`Civic_TLS`, on the pinned CachyOS package set. The only control backend is the
standard in-tree `acer_wmi` hwmon ABI. There is **no escape hatch**: no raw EC
or WMI writes, forced capabilities, replacement module, manual fan mode,
module unload, or other model/distribution path.

Start from a stock-kernel boot after a full power-off/power-on. No fan
controller, recovery helper, or Custom-control attempt may have run during the
boot. The independent `pt31553-fan-restore --restore` Auto-restoration helper
is permitted and required only after booting the candidate below; it is not
Custom control. Keep the stock standard kernel
and the stock `linux-cachyos-lts` recovery kernel installed. Confirm source-only
status without touching hardware:

```sh
set -eu
cargo run -p fan-control-daemon
cargo run -p fan-control-restore -- --status
cargo run -p fan-control-qualify
```

Every command must report an unqualified or recovery-only role. A successful
result does not authorize Custom control.

### 2. Keep editable inputs separate from safety authority

| Artifact | Role | Boundary |
| --- | --- | --- |
| `/etc/pt31553-fan-control/config.toml` | Operator configuration installed from `config/example.toml` | **Editable, never authority.** Validation or a package upgrade cannot authorize it. |
| `/usr/lib/pt31553-fan-control/compatibility.toml` | Exact-model declaration and supported envelope | Static declaration only; it is not observed qualification. |
| Operator-selected root-owned protected policy snapshot | Immutable copy of the configuration actually qualified | **Safety authority** only when its hash agrees with the qualification record. |
| `/var/lib/pt31553-fan-control/qualification.json` | Atomic go/no-go record from supervised endurance | **Safety authority**; missing, stale, incomplete, or no-go means disabled. |
| `/var/lib/pt31553-fan-control/evidence/supervised-endurance.json` | Raw evidence bound to the qualification record | **Safety authority input; private by default.** It has the same protected-file requirements; do not publish it, use the redaction command. |
| `package-provenance-v1.json` plus detached signatures | Authenticated kernel/package/module/image identities | **Prerequisite, not authority.** Provenance alone cannot enable control. |
| `promotion.json` plus sanitized evidence | Exact public artifact identity claim | **Public claim, not runtime authority.** It never authorizes another machine. |

Protected artifacts must be root-owned regular files, have one link, and be
non-writable by group/other beneath protected root-owned ancestors. Never edit
an authority artifact in place; produce a new qualification after any invalidating
change.

### 3. Build and verify from a clean source state

Install the repository's documented toolchain and policy tools first. Use a
new directory and an explicit reviewed revision; the placeholder check prevents
an accidental build from an unspecified branch:

```sh
set -eu
source_revision='REPLACE_WITH_REVIEWED_40_HEX_COMMIT'
source_parent=/absolute/path/to/new-empty-source-parent
case "$source_revision" in REPLACE_*|*[!0-9a-f]*) exit 1 ;; esac
test "${#source_revision}" -eq 40
case "$source_parent" in /absolute/path/*|'') exit 1 ;; esac
test ! -e "$source_parent"
/usr/bin/install -d -m 0755 "$source_parent"
git clone --no-checkout \
  https://github.com/dannyfranca/predator-pt315-53-fan-control.git \
  "$source_parent/source"
cd "$source_parent/source"
git checkout --detach "$source_revision"
test "$(git rev-parse HEAD)" = "$source_revision"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
cargo fetch --locked
cargo deny fetch
CARGO_NET_OFFLINE=true scripts/check-repository-policy
```

That policy command runs formatting, linting, all simulated unit/integration
tests, dependency policy, reachable-history secret scanning, and offline local
link validation. It makes no hardware qualification claim.

Build the signed controller package from its pinned recipe in a separate clean
directory. The runbook checkout and packaged controller are distinct reviewed
identities: the recipe pins the controller source archive, while the runbook
may be newer. Record and explicitly confirm both; never imply that the package
contains the runbook checkout. The signing key must already be
operator-controlled and trusted by the local pacman keyring; keep private keys
outside the source and output trees. Invoke Bash explicitly because `makepkg`
and `mapfile` are Bash interfaces:

```sh
/usr/bin/bash -eu <<'RUNBOOK_CONTROLLER'
controller_source_revision='REPLACE_WITH_REVIEWED_CONTROLLER_SOURCE_COMMIT'
controller_recipe="$PWD/packaging/controller"
controller_build=/absolute/path/to/new-controller-build
controller_signer='REPLACE_WITH_CONTROLLER_SIGNING_KEY_FINGERPRINT'
case "$controller_source_revision" in REPLACE_*|*[!0-9a-f]*) exit 1 ;; esac
test "${#controller_source_revision}" -eq 40
case "$controller_signer" in REPLACE_*|'') exit 1 ;; esac
case "$controller_build" in /absolute/path/*|'') exit 1 ;; esac
recipe_revision=$(/usr/bin/sed -n \
  "s/^_commit='\([0-9a-f]\{40\}\)'$/\1/p" \
  "$controller_recipe/PKGBUILD")
test "${#recipe_revision}" -eq 40
test "$recipe_revision" = "$controller_source_revision"
test ! -e "$controller_build"
/usr/bin/install -d -m 0700 "$controller_build"
/usr/bin/cp -a "$controller_recipe/." "$controller_build/"
cd "$controller_build"
mapfile -t controller_packages < <(makepkg --packagelist)
test "${#controller_packages[@]}" -eq 1
controller_package=${controller_packages[0]}
makepkg --cleanbuild --noconfirm --syncdeps --sign --key "$controller_signer"
test -f "$controller_package"
test -f "$controller_package.sig"
/usr/bin/pacman-key --verify "$controller_package.sig" "$controller_package"
controller_package_sha256=$(/usr/bin/sha256sum "$controller_package" | \
  /usr/bin/awk '{print $1}')
controller_package_identity=$(/usr/bin/pacman -Qp "$controller_package")
/usr/bin/printf 'controller_package=%s\ncontroller_package_sha256=%s\ncontroller_package_identity=%s\n' \
  "$controller_package" "$controller_package_sha256" "$controller_package_identity"
RUNBOOK_CONTROLLER
```

Retain the three printed values together. Use that exact absolute package path,
SHA-256, and pacman identity in step 4; a valid signature on any other package
is insufficient.

For the kernel, first use a reviewed, committed signer-enrollment revision in
which `packaging/kernel/provenance-policy.toml`,
`schemas/package-provenance-v1.json`, and `compatibility/pt315-53.toml` all
replace their policy-bound all-zero/all-`f` package, module, image, and signer
placeholders with the same reviewed public identities supplied below. This is
one coordinated change; do not edit a checkout in place. Review and commit the
enrollment, then begin again from its clean revision at step 3. Until that
prerequisite exists, the provenance verifier is expected to fail and no
candidate may be installed.

From that clean revision, assemble `/bundle` exactly as specified in
[`packaging/kernel/README.md`](packaging/kernel/README.md), keep signing inputs
outside it, and run only the authenticated wrapper into a new empty output:

```sh
set -eu
source_root=$PWD
test -x "$source_root/scripts/verify-source-lock"
test -x "$source_root/scripts/verify-package-provenance"
cd "$source_root"
test -d /bundle
test ! -e "$PWD/build-output"
/usr/bin/install -d -m 0700 "$PWD/build-output"
SOURCE_LOCK_SIGNING_DIR=/secure/signing \
SOURCE_LOCK_OUTPUT="$PWD/build-output" \
  scripts/verify-source-lock --inputs /bundle --exec-verified

package_manifest_signature=/secure/public/package-set.p7s
test ! -e "$package_manifest_signature"
/usr/bin/openssl cms -sign -binary \
  -in "$PWD/build-output/SHA256SUMS" \
  -signer /secure/public/package-signing-certificate.pem \
  -inkey /secure/private/package-signing-key.pem \
  -outform DER -out "$package_manifest_signature" \
  -nocerts -noattr -md sha256
test -s "$package_manifest_signature"

scripts/verify-package-provenance \
  --artifacts "$PWD/build-output" \
  --module-cert /secure/signing/module-signing-certificate.der \
  --module-cert-sha256 REPLACE_WITH_MODULE_CERT_SHA256 \
  --package-cert /secure/public/package-signing-certificate.pem \
  --package-cert-sha256 REPLACE_WITH_PACKAGE_CERT_SHA256 \
  --kernel-cert /secure/public/enrolled-image-signing-certificate.pem \
  --kernel-cert-sha256 REPLACE_WITH_IMAGE_CERT_SHA256 \
  --package-manifest-signature "$package_manifest_signature" \
  --output "$PWD/package-provenance-v1.json"
```

The source-lock wrapper builds exactly the uniquely named kernel, headers, and
NVIDIA-open packages. The provenance verifier must run offline after the
package-set manifest has been signed as described in the kernel README.

### 4. Install the controller disabled

Do this on the clean stock boot, before installing or booting the candidate
kernel. Reverify the exact package, require that neither controller unit is
already enabled or active, then install. Arch package installation does not
start either unit; the shipped preset also says `disable` for both.

```sh
set -eu
controller_package=/absolute/path/to/pt31553-fan-control.pkg.tar.zst
controller_signature="$controller_package.sig"
controller_package_sha256='REPLACE_WITH_RECORDED_CONTROLLER_PACKAGE_SHA256'
controller_package_identity='REPLACE_WITH_RECORDED_PACMAN_PACKAGE_IDENTITY'
case "$controller_package_sha256" in REPLACE_*|*[!0-9a-f]*) exit 1 ;; esac
test "${#controller_package_sha256}" -eq 64
case "$controller_package_identity" in REPLACE_*|'') exit 1 ;; esac
test "$(/usr/bin/sha256sum "$controller_package" | /usr/bin/awk '{print $1}')" = \
  "$controller_package_sha256"
test "$(/usr/bin/pacman -Qp "$controller_package")" = \
  "$controller_package_identity"
/usr/bin/pacman-key --verify "$controller_signature" "$controller_package"
! /usr/bin/pgrep -x pt31553-fand >/dev/null
for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
  enabled_state=$(/usr/bin/systemctl is-enabled "$unit" 2>/dev/null || true)
  case "$enabled_state" in
    not-found) ;;
    disabled)
      test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
      ;;
    *) exit 1 ;;
  esac
done
sudo /usr/bin/pacman -U "$controller_package"
for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
  /usr/bin/systemctl cat "$unit" >/dev/null
  test "$(/usr/bin/systemctl is-enabled "$unit")" = disabled
  test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
done
! /usr/bin/pgrep -x pt31553-fand >/dev/null
test -f /etc/pt31553-fan-control/config.toml
test -f /usr/lib/pt31553-fan-control/compatibility.toml
test -x /usr/bin/pt31553-fan-restore
```

Do not enable or start the daemon here. The editable configuration is still
not authority, and no qualification record exists. Do not run the recovery
helper on the stock kernel; it is deliberately not recovery-capable.

### 5. Perform the first disabled candidate boot

Continue with the detailed side-by-side procedure below, in this order:

1. **Record the stock recovery entries** and prove both stock images exist.
2. **Install without changing the default**; reverify the three exact kernel
   artifacts and retain both stock packages and entries.
3. **Boot the candidate once** using only the documented one-shot entry. Never
   make the candidate the default.
4. On the candidate boot, prove the stock entry remains the default, both
   controller units remain disabled/inactive, no daemon process or boot journal
   exists, and independent restoration confirms both fans in Firmware Auto.

Stop there. Only the separate qualification procedure may proceed beyond the
first disabled candidate boot.

## Side-by-side candidate install and recovery

This is the checked path for the exact `7.1.8-cachyos-pt31553` candidate. It
does not qualify the candidate or authorize fan control. Start only with a
successful package-provenance record from the preceding kernel procedure.
Stop at the first failed check. Keep AC power connected. Never unload
`acer_wmi`, remove a controller or kernel package, or reboot after any
custom-control attempt until both fans have confirmed Firmware Auto.

For a first candidate boot, begin from a full power-off/power-on firmware
initialization into the stock entry—not a warm reboot—and only if no fan
controller, recovery helper, or Custom-control attempt has run during this
boot. The independent Auto-restoration helper becomes a permitted exception
only after booting the candidate; it is required there and does not violate
that boundary. If either starting fact
is uncertain, first use the candidate-side Auto recovery and one-shot stock
return below, then restart this procedure. Preserve the current boot ID; the
candidate reboot gate proves that all install checks stayed within this same
clean stock boot.

### Record the stock recovery entries

Confirm the stock standard and 6.18 LTS packages and images exist before
installing anything:

```sh
set -eu
/usr/bin/pacman -Q linux-cachyos linux-cachyos-lts
lts_package=$(/usr/bin/pacman -Q linux-cachyos-lts)
case "$lts_package" in "linux-cachyos-lts 6.18"*) ;; *) exit 1 ;; esac
bootctl_status=$(/usr/bin/env LC_ALL=C /usr/bin/bootctl status --no-pager)
case "$bootctl_status" in *'Product: systemd-boot'*) ;; *) exit 1 ;; esac
/usr/bin/bootctl list --no-pager
```

From that listing, copy the exact standard and LTS entry IDs. Replace every
`REPLACE_...` value below; the checks deliberately fail for placeholders.

```sh
set -eu
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
default_entry='REPLACE_WITH_CURRENT_DEFAULT_STOCK_ENTRY_ID'

selected_entry=$(/usr/bin/python3 -I - \
  "$stock_entry" "$lts_entry" "$default_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, lts_id, expected_default_id = sys.argv[1:]
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in (stock_id, lts_id))
by_id = {entry["id"]: entry for entry in entries}
assert stock_id != lts_id
assert stock_id in by_id and lts_id in by_id

def paths(entry, field):
    value = entry.get(field, [])
    return [value] if isinstance(value, str) else value

def require_loader_files(entry):
    assert entry.get("type") == "type1"
    assert entry.get("source") in {"esp", "xbootldr"}
    boot_root = pathlib.Path(entry["root"])
    config = pathlib.Path(entry["path"])
    assert boot_root.is_absolute()
    assert config == boot_root / "loader" / "entries" / entry["id"]
    assert config.is_file()
    for field in ("linux", "initrd"):
        for value in paths(entry, field):
            path = pathlib.PurePosixPath(value)
            assert path.is_absolute() and ".." not in path.parts
            host_path = boot_root.joinpath(*path.parts[1:])
            assert host_path.is_file() and host_path.stat().st_size > 0

assert paths(by_id[stock_id], "linux") == ["/vmlinuz-linux-cachyos"]
assert "/initramfs-linux-cachyos.img" in paths(by_id[stock_id], "initrd")
assert paths(by_id[lts_id], "linux") == ["/vmlinuz-linux-cachyos-lts"]
assert paths(by_id[lts_id], "initrd") == [
    "/intel-ucode.img",
    "/initramfs-linux-cachyos-lts.img",
]
require_loader_files(by_id[stock_id])
require_loader_files(by_id[lts_id])
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert defaults == [expected_default_id]
assert expected_default_id in {stock_id, lts_id}
selected = [entry["id"] for entry in entries if entry.get("isSelected")]
assert len(selected) == 1
assert selected[0] in {stock_id, lts_id}
print(selected[0])
PY
)
running_module=$(/usr/bin/modinfo -n acer_wmi)
running_module_owner=$(/usr/bin/pacman -Qqo "$running_module")
case "$selected_entry" in
  "$stock_entry") test "$running_module_owner" = linux-cachyos ;;
  "$lts_entry") test "$running_module_owner" = linux-cachyos-lts ;;
  *) exit 1 ;;
esac
/usr/bin/printf '%s\n' "$default_entry" |
  sudo /usr/bin/tee /run/pt31553-stock-default-entry >/dev/null
sudo /usr/bin/chown root:root /run/pt31553-stock-default-entry
sudo /usr/bin/chmod 0400 /run/pt31553-stock-default-entry
```

The recovery binary and both unit files must already be installed, but the
units must be disabled and inactive. This guarantees the Auto recovery command
will be available after booting the candidate while preventing fan control
from starting on this stock boot:

```sh
set -eu
test -x /usr/bin/pt31553-fan-restore
for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
  /usr/bin/systemctl cat "$unit" >/dev/null
  test "$(/usr/bin/systemctl is-enabled "$unit")" = disabled
  test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
  test "$(/usr/bin/systemctl show "$unit" \
    --property=ActiveEnterTimestampMonotonic --value)" = 0
  test "$(/usr/bin/systemctl show "$unit" \
    --property=InactiveEnterTimestampMonotonic --value)" = 0
done
test -z "$(/usr/bin/journalctl -b --no-pager -o cat \
  _EXE=/usr/bin/pt31553-fand)"
! /usr/bin/pgrep -x pt31553-fand >/dev/null
start_boot_id=$(/usr/bin/cat /proc/sys/kernel/random/boot_id)
/usr/bin/printf '%s\n' "$start_boot_id" |
  sudo /usr/bin/tee /run/pt31553-clean-stock-boot-id >/dev/null
sudo /usr/bin/chown root:root /run/pt31553-clean-stock-boot-id
sudo /usr/bin/chmod 0400 /run/pt31553-clean-stock-boot-id
```

### Install without changing the default

Use only the three artifacts authenticated by
`scripts/verify-package-provenance`; do not use globs. Reverify the exact
archives immediately before installation and require the new record to equal
the accepted record. Installing this unique package set together does not
replace either stock package:

```sh
set -eu
artifact_dir=/absolute/path/to/build-output
provenance_record=/absolute/path/to/accepted-package-provenance-v1.json
package_manifest_signature=/absolute/path/to/package-set-manifest.p7s
module_cert=/absolute/path/to/module-signing-certificate.der
package_cert=/absolute/path/to/package-signing-certificate.pem
kernel_cert=/absolute/path/to/enrolled-image-signing-certificate.pem
module_cert_sha256='REPLACE_WITH_MODULE_CERT_SHA256'
package_cert_sha256='REPLACE_WITH_PACKAGE_CERT_SHA256'
kernel_cert_sha256='REPLACE_WITH_KERNEL_CERT_SHA256'
install_recheck_dir=/absolute/path/to/new-empty-install-recheck
test "$(sudo /usr/bin/stat -c '%u:%a' /run/pt31553-stock-default-entry)" = 0:400
default_entry=$(sudo /usr/bin/cat /run/pt31553-stock-default-entry)
default_efi_variable=/sys/firmware/efi/efivars/LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
test ! -e "$install_recheck_dir"
umask 077
/usr/bin/install -d -m 0700 "$install_recheck_dir"
scripts/verify-package-provenance \
  --artifacts "$artifact_dir" \
  --module-cert "$module_cert" \
  --module-cert-sha256 "$module_cert_sha256" \
  --package-cert "$package_cert" \
  --package-cert-sha256 "$package_cert_sha256" \
  --kernel-cert "$kernel_cert" \
  --kernel-cert-sha256 "$kernel_cert_sha256" \
  --package-manifest-signature "$package_manifest_signature" \
  --output "$install_recheck_dir/package-provenance-v1.json"
/usr/bin/cmp "$provenance_record" \
  "$install_recheck_dir/package-provenance-v1.json"

# Pin the already-verified stock default against package-hook writes. If power
# is lost, the immutable flag and stock value survive; rerunning this block
# safely clears and recreates the same guard before installation resumes.
if test -e "$default_efi_variable"; then
  test -f "$default_efi_variable"
  test ! -L "$default_efi_variable"
  sudo /usr/bin/chattr -i "$default_efi_variable"
fi
sudo /usr/bin/bootctl set-default "$default_entry"
test -f "$default_efi_variable"
test ! -L "$default_efi_variable"
sudo /usr/bin/chattr +i "$default_efi_variable"
/usr/bin/lsattr -d "$default_efi_variable" | /usr/bin/awk '{print $1}' | \
  /usr/bin/grep -q 'i'
restore_writable_stock_default() {
  restore_status=0
  sudo /usr/bin/chattr -i "$default_efi_variable" || restore_status=$?
  sudo /usr/bin/bootctl set-default "$default_entry" || restore_status=$?
  return "$restore_status"
}
trap restore_writable_stock_default EXIT HUP INT TERM
sudo /usr/bin/pacman -U \
  "$artifact_dir/linux-cachyos-pt31553-7.1.8-1-x86_64.pkg.tar.zst" \
  "$artifact_dir/linux-cachyos-pt31553-headers-7.1.8-1-x86_64.pkg.tar.zst" \
  "$artifact_dir/linux-cachyos-pt31553-nvidia-open-7.1.8-1-x86_64.pkg.tar.zst"
restore_writable_stock_default
trap - EXIT HUP INT TERM

/usr/bin/pacman -Q \
  linux-cachyos linux-cachyos-lts \
  linux-cachyos-pt31553 linux-cachyos-pt31553-headers \
  linux-cachyos-pt31553-nvidia-open

stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
/usr/bin/python3 -I - "$stock_entry" "$lts_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in sys.argv[1:])
by_id = {entry["id"]: entry for entry in entries}

def paths(entry, field):
    value = entry.get(field, [])
    return [value] if isinstance(value, str) else value

for entry_id in sys.argv[1:]:
    entry = by_id[entry_id]
    assert entry.get("type") == "type1"
    assert entry.get("source") in {"esp", "xbootldr"}
    boot_root = pathlib.Path(entry["root"])
    config = pathlib.Path(entry["path"])
    assert boot_root.is_absolute()
    assert config == boot_root / "loader" / "entries" / entry["id"]
    assert config.is_file()
    for field in ("linux", "initrd"):
        for value in paths(entry, field):
            path = pathlib.PurePosixPath(value)
            assert path.is_absolute() and ".." not in path.parts
            host_path = boot_root.joinpath(*path.parts[1:])
            assert host_path.is_file() and host_path.stat().st_size > 0
PY
```

Install the already-verified package image in the loader root used by the
stock entry. Then generate its matching initramfs before publishing the
candidate BLS entry. Temporary files stay on that loader filesystem, and
neither final path may be a symlink:

```sh
set -eu
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
candidate_release=7.1.8-cachyos-pt31553
packaged_candidate_image=/usr/lib/modules/$candidate_release/vmlinuz
test "$(sudo /usr/bin/stat -c '%u:%a' /run/pt31553-stock-default-entry)" = 0:400
default_entry=$(sudo /usr/bin/cat /run/pt31553-stock-default-entry)
candidate_boot_root=$(/usr/bin/python3 -I - "$stock_entry" "$default_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, default_id = sys.argv[1:]
matching = [entry for entry in entries if entry.get("id") == stock_id]
assert len(matching) == 1
stock = matching[0]
assert stock.get("type") == "type1"
assert stock.get("source") in {"esp", "xbootldr"}
boot_root = pathlib.Path(stock["root"])
config = pathlib.Path(stock["path"])
assert boot_root.is_absolute()
assert config == boot_root / "loader" / "entries" / stock["id"]
assert config.is_file()
candidate_config = config.parent / "linux-cachyos-pt31553.conf"
assert not candidate_config.exists() and not candidate_config.is_symlink()
assert not any(entry.get("linux") == "/vmlinuz-linux-cachyos-pt31553"
               for entry in entries)
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert defaults == [default_id]
print(boot_root)
PY
)
candidate_image="$candidate_boot_root/vmlinuz-linux-cachyos-pt31553"
candidate_initramfs="$candidate_boot_root/initramfs-linux-cachyos-pt31553.img"
test -f "$packaged_candidate_image"
test ! -L "$packaged_candidate_image"
# A power loss between the two final renames can leave an unpublished partial
# pair. The checks above prove no BLS entry references it and the stock default
# is still pinned, so this exact pair is safe to discard before retrying.
if test -e "$candidate_image" || test -e "$candidate_initramfs"; then
  test "$(/usr/bin/cat /proc/sys/kernel/random/boot_id)" = \
    "$(sudo /usr/bin/cat /run/pt31553-clean-stock-boot-id)"
  sudo /usr/bin/rm -f -- "$candidate_image" "$candidate_initramfs"
  sudo /usr/bin/sync -f "$candidate_boot_root"
fi
test ! -e "$candidate_image"
test ! -L "$candidate_image"
test ! -e "$candidate_initramfs"
test ! -L "$candidate_initramfs"
candidate_image_tmp=$(sudo /usr/bin/mktemp \
  "$candidate_boot_root/.pt31553-vmlinuz.XXXXXX")
candidate_initramfs_tmp=$(sudo /usr/bin/mktemp \
  "$candidate_boot_root/.pt31553-initramfs.XXXXXX")
cleanup_candidate_boot_temps() {
  sudo /usr/bin/rm -f -- "$candidate_image_tmp" "$candidate_initramfs_tmp"
}
trap cleanup_candidate_boot_temps EXIT HUP INT TERM
sudo /usr/bin/install -o root -g root -m 0644 \
  "$packaged_candidate_image" "$candidate_image_tmp"
sudo /usr/bin/mkinitcpio -k "$candidate_release" -g "$candidate_initramfs_tmp"
sudo /usr/bin/chown root:root "$candidate_initramfs_tmp"
sudo /usr/bin/chmod 0644 "$candidate_initramfs_tmp"
/usr/bin/cmp "$packaged_candidate_image" "$candidate_image_tmp"
/usr/bin/lsinitcpio "$candidate_initramfs_tmp" >/dev/null
sudo /usr/bin/mv -T "$candidate_image_tmp" "$candidate_image"
sudo /usr/bin/mv -T "$candidate_initramfs_tmp" "$candidate_initramfs"
trap - EXIT HUP INT TERM
/usr/bin/cmp "$packaged_candidate_image" "$candidate_image"
/usr/bin/lsinitcpio "$candidate_initramfs" >/dev/null
/usr/bin/sha256sum "$candidate_initramfs" | /usr/bin/awk '{print $1}' | \
  sudo /usr/bin/tee /run/pt31553-verified-candidate-initramfs-sha256 >/dev/null
sudo /usr/bin/chown root:root /run/pt31553-verified-candidate-initramfs-sha256
sudo /usr/bin/chmod 0400 /run/pt31553-verified-candidate-initramfs-sha256
```

Create the candidate's BLS Type #1 entry beside the recorded stock entry. Its
kernel options and any CPU-microcode initrds come from the stock entry; only the
stock kernel and main initramfs paths are replaced. The target directory is
derived from the loader-reported stock entry source, so a different ESP or
XBOOTLDR mount cannot silently redirect this step:

```sh
set -eu
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
test "$(sudo /usr/bin/stat -c '%u:%a' /run/pt31553-stock-default-entry)" = 0:400
default_entry=$(sudo /usr/bin/cat /run/pt31553-stock-default-entry)
candidate_config_dir=$(/usr/bin/python3 -I - "$stock_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
matching = [entry for entry in entries if entry.get("id") == sys.argv[1]]
assert len(matching) == 1
stock = matching[0]
assert stock.get("type") == "type1"
assert stock.get("source") in {"esp", "xbootldr"}
boot_root = pathlib.Path(stock["root"])
config = pathlib.Path(stock["path"])
assert boot_root.is_absolute()
assert config == boot_root / "loader" / "entries" / stock["id"]
assert config.is_file()
print(config.parent)
PY
)
candidate_config="$candidate_config_dir/linux-cachyos-pt31553.conf"
test ! -e "$candidate_config"
test ! -L "$candidate_config"
candidate_config_source_tmp=$(/usr/bin/mktemp)
candidate_config_publish_tmp=
cleanup_candidate_entry_temps() {
  temp_cleanup_status=0
  /usr/bin/rm -f -- "$candidate_config_source_tmp" || temp_cleanup_status=$?
  if test -n "$candidate_config_publish_tmp"; then
    sudo /usr/bin/rm -f -- "$candidate_config_publish_tmp" || temp_cleanup_status=$?
  fi
  return "$temp_cleanup_status"
}
trap cleanup_candidate_entry_temps EXIT HUP INT TERM
candidate_config_publish_tmp=$(sudo /usr/bin/mktemp \
  "$candidate_config_dir/.pt31553-entry.XXXXXX")

/usr/bin/python3 -I - "$stock_entry" >"$candidate_config_source_tmp" <<'PY'
import json
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
matching = [entry for entry in entries if entry.get("id") == sys.argv[1]]
assert len(matching) == 1
stock = matching[0]
assert stock.get("linux") == "/vmlinuz-linux-cachyos"
initrds = stock.get("initrd", [])
initrds = [initrds] if isinstance(initrds, str) else initrds
assert initrds.count("/initramfs-linux-cachyos.img") == 1
initrds = [
    "/initramfs-linux-cachyos-pt31553.img"
    if path == "/initramfs-linux-cachyos.img" else path
    for path in initrds
]
options = stock.get("options")
options = " ".join(options) if isinstance(options, list) else options
assert isinstance(options, str) and options and "\n" not in options

print("title Acer PT315-53 candidate 7.1.8")
print("version 7.1.8-cachyos-pt31553")
print("linux /vmlinuz-linux-cachyos-pt31553")
for initrd in initrds:
    print(f"initrd {initrd}")
print(f"options {options}")
PY
verify_pinned_stock_default() {
  candidate_visibility=$1
  /usr/bin/python3 -I - "$default_entry" "$candidate_visibility" <<'PY'
import json
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
default_id, candidate_visibility = sys.argv[1:]
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert defaults == [default_id]
candidate_entries = [
    entry for entry in entries
    if entry.get("linux") == "/vmlinuz-linux-cachyos-pt31553"
]
if candidate_visibility == "absent":
    assert candidate_entries == []
else:
    assert candidate_visibility == "present"
    assert len(candidate_entries) == 1
    assert candidate_entries[0]["id"] not in defaults
PY
}
sudo /usr/bin/bootctl set-default "$default_entry"
verify_pinned_stock_default absent
entry_status=0
sudo /usr/bin/install -o root -g root -m 0644 \
  "$candidate_config_source_tmp" "$candidate_config_publish_tmp" || entry_status=$?
if test "$entry_status" = 0; then
  sudo /usr/bin/sync -f "$candidate_config_publish_tmp" || entry_status=$?
fi
if test "$entry_status" = 0; then
  sudo /usr/bin/mv -T "$candidate_config_publish_tmp" "$candidate_config" || entry_status=$?
fi
cleanup_status=0
cleanup_candidate_entry_temps || cleanup_status=$?
trap - EXIT HUP INT TERM
test "$entry_status" = 0
test "$cleanup_status" = 0
test -f "$candidate_config"
test ! -L "$candidate_config"
verify_pinned_stock_default present
/usr/bin/bootctl list --no-pager
```

Register the loader-visible candidate image, then bind its signature to the exact image
certificate fingerprint from the verified provenance inputs. The certificate
must also be present in the firmware `db`; enrolled keys, Setup Mode, or Secure
Boot state that differ from these checks are a hard stop:

```sh
set -eu
image_cert=/absolute/path/to/enrolled-image-signing-certificate.pem
provenance_record=/absolute/path/to/accepted-package-provenance-v1.json
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
candidate_config=$(/usr/bin/python3 -I - "$stock_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
matching = [entry for entry in entries if entry.get("id") == sys.argv[1]]
assert len(matching) == 1
stock = matching[0]
assert stock.get("type") == "type1"
assert stock.get("source") in {"esp", "xbootldr"}
boot_root = pathlib.Path(stock["root"])
config = pathlib.Path(stock["path"])
assert config == boot_root / "loader" / "entries" / stock["id"]
assert config.is_file()
print(config.parent / "linux-cachyos-pt31553.conf")
PY
)
candidate_boot_root=$(/usr/bin/dirname \
  "$(/usr/bin/dirname "$(/usr/bin/dirname "$candidate_config")")")
candidate_image="$candidate_boot_root/vmlinuz-linux-cachyos-pt31553"
candidate_initramfs="$candidate_boot_root/initramfs-linux-cachyos-pt31553.img"
expected_image_cert_sha256=$(/usr/bin/python3 -I - "$provenance_record" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(record["kernel"]["image_signer_fingerprint"])
PY
)
actual_image_cert_sha256=$(
  /usr/bin/openssl x509 -in "$image_cert" -outform DER |
    /usr/bin/sha256sum | /usr/bin/awk '{print $1}'
)
test "$actual_image_cert_sha256" = "$expected_image_cert_sha256"

/usr/bin/python3 -I - "$provenance_record" "$candidate_image" <<'PY'
import hashlib
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = record["kernel"]["image_sha256"]
for image in (
    "/usr/lib/modules/7.1.8-cachyos-pt31553/vmlinuz",
    sys.argv[2],
):
    actual = hashlib.sha256(pathlib.Path(image).read_bytes()).hexdigest()
    assert actual == expected
PY

/usr/bin/sbverify --cert "$image_cert" "$candidate_image"
enrolled_db_dir=$(/usr/bin/mktemp -d)
trap '/usr/bin/rm -rf -- "$enrolled_db_dir"' EXIT
sudo /usr/bin/efi-readvar -v db -o "$enrolled_db_dir/db.esl"
sudo /usr/bin/chown "$(/usr/bin/id -u):$(/usr/bin/id -g)" \
  "$enrolled_db_dir/db.esl"
/usr/bin/sig-list-to-certs "$enrolled_db_dir/db.esl" "$enrolled_db_dir/db"
/usr/bin/python3 -I - "$expected_image_cert_sha256" "$enrolled_db_dir" <<'PY'
import hashlib
import pathlib
import sys

efivars = pathlib.Path("/sys/firmware/efi/efivars")

def value(path):
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    assert len(data) == 5
    return data[4]

assert value(efivars / "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c") == 0
assert value(efivars / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c") == 1
certificates = list(pathlib.Path(sys.argv[2]).glob("db-*.der"))
assert certificates
db_fingerprints = {hashlib.sha256(path.read_bytes()).hexdigest() for path in certificates}
assert sys.argv[1].lower() in db_fingerprints
PY
/usr/bin/sha256sum "$candidate_image" | /usr/bin/awk '{print $1}' |
  sudo /usr/bin/tee /run/pt31553-verified-candidate-image-sha256 >/dev/null
sudo /usr/bin/chown root:root /run/pt31553-verified-candidate-image-sha256
sudo /usr/bin/chmod 0400 /run/pt31553-verified-candidate-image-sha256
/usr/bin/lsinitcpio "$candidate_initramfs" >/dev/null
/usr/bin/bootctl list --no-pager
```

Installation hooks must not move the persistent default. Restore the recorded
stock default only if a hook changed it:

```sh
set -eu
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
test "$(sudo /usr/bin/stat -c '%u:%a' /run/pt31553-stock-default-entry)" = 0:400
default_entry=$(sudo /usr/bin/cat /run/pt31553-stock-default-entry)
current_default=$(/usr/bin/python3 -I - \
  "$stock_entry" "$lts_entry" "$default_entry" <<'PY'
import json
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, lts_id, expected_default_id = sys.argv[1:]
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in (stock_id, lts_id))
by_id = {entry["id"]: entry for entry in entries}
assert stock_id in by_id and lts_id in by_id
assert expected_default_id in {stock_id, lts_id}
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert len(defaults) == 1
print(defaults[0])
PY
)
if test "$current_default" != "$default_entry"; then
  sudo /usr/bin/bootctl set-default "$default_entry"
fi
```

Copy the new candidate entry ID from the listing. This check proves all three
entries are distinct and present, and that a stock entry—not the candidate—is
still the persistent default:

```sh
set -eu
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
candidate_entry='REPLACE_WITH_PT31553_CANDIDATE_ENTRY_ID'

/usr/bin/python3 -I - "$stock_entry" "$lts_entry" "$candidate_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, lts_id, candidate_id = sys.argv[1:]
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in (stock_id, lts_id, candidate_id))
by_id = {entry["id"]: entry for entry in entries}
assert len({stock_id, lts_id, candidate_id}) == 3
assert all(entry_id in by_id for entry_id in (stock_id, lts_id, candidate_id))

def paths(entry, field):
    value = entry.get(field, [])
    return [value] if isinstance(value, str) else value

def require_loader_files(entry):
    assert entry.get("type") == "type1"
    assert entry.get("source") in {"esp", "xbootldr"}
    boot_root = pathlib.Path(entry["root"])
    config = pathlib.Path(entry["path"])
    assert boot_root.is_absolute()
    assert config == boot_root / "loader" / "entries" / entry["id"]
    assert config.is_file()
    for field in ("linux", "initrd"):
        for value in paths(entry, field):
            path = pathlib.PurePosixPath(value)
            assert path.is_absolute() and ".." not in path.parts
            host_path = boot_root.joinpath(*path.parts[1:])
            assert host_path.is_file() and host_path.stat().st_size > 0

assert paths(by_id[stock_id], "linux") == ["/vmlinuz-linux-cachyos"]
assert "/initramfs-linux-cachyos.img" in paths(by_id[stock_id], "initrd")
assert paths(by_id[lts_id], "linux") == ["/vmlinuz-linux-cachyos-lts"]
assert paths(by_id[lts_id], "initrd") == [
    "/intel-ucode.img",
    "/initramfs-linux-cachyos-lts.img",
]
assert paths(by_id[candidate_id], "linux") == ["/vmlinuz-linux-cachyos-pt31553"]
expected_candidate_initrds = [
    "/initramfs-linux-cachyos-pt31553.img"
    if path == "/initramfs-linux-cachyos.img" else path
    for path in paths(by_id[stock_id], "initrd")
]
assert paths(by_id[candidate_id], "initrd") == expected_candidate_initrds
assert by_id[candidate_id].get("options") == by_id[stock_id].get("options")
stock_path = pathlib.Path(by_id[stock_id]["path"])
candidate_path = pathlib.Path(by_id[candidate_id]["path"])
assert by_id[candidate_id].get("source") == by_id[stock_id].get("source")
assert by_id[candidate_id].get("root") == by_id[stock_id].get("root")
assert candidate_path == stock_path.parent / "linux-cachyos-pt31553.conf"
for entry_id in (stock_id, lts_id, candidate_id):
    require_loader_files(by_id[entry_id])
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert len(defaults) == 1
default_id = defaults[0]
assert default_id in {stock_id, lts_id}
assert candidate_id != default_id
PY
```

Do not persistently change the default. Select the candidate for one reboot:

```sh
set -eu
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
candidate_entry='REPLACE_WITH_PT31553_CANDIDATE_ENTRY_ID'
expected_default_entry='REPLACE_WITH_CURRENT_DEFAULT_STOCK_ENTRY_ID'
image_cert=/absolute/path/to/enrolled-image-signing-certificate.pem
test "$(/usr/bin/cat /proc/sys/kernel/random/boot_id)" = \
  "$(sudo /usr/bin/cat /run/pt31553-clean-stock-boot-id)"
candidate_image=$(/usr/bin/python3 -I - "$stock_entry" "$lts_entry" \
  "$candidate_entry" "$expected_default_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, lts_id, candidate_id, expected_default_id = sys.argv[1:]
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in (stock_id, lts_id, candidate_id))
matching = [entry for entry in entries if entry.get("id") == candidate_id]
assert len(matching) == 1
candidate = matching[0]
stock_matching = [entry for entry in entries if entry.get("id") == stock_id]
assert len(stock_matching) == 1
stock = stock_matching[0]
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert expected_default_id in {stock_id, lts_id}
assert defaults == [expected_default_id]
assert candidate_id != expected_default_id
assert candidate.get("type") == "type1"
assert candidate.get("source") == stock.get("source")
assert candidate.get("root") == stock.get("root")

def paths(entry, field):
    value = entry.get(field, [])
    return [value] if isinstance(value, str) else value

assert paths(candidate, "linux") == ["/vmlinuz-linux-cachyos-pt31553"]
expected_initrds = [
    "/initramfs-linux-cachyos-pt31553.img"
    if path == "/initramfs-linux-cachyos.img" else path
    for path in paths(stock, "initrd")
]
assert paths(candidate, "initrd") == expected_initrds
stock_options = stock.get("options")
candidate_options = candidate.get("options")
if isinstance(stock_options, list):
    stock_options = " ".join(stock_options)
if isinstance(candidate_options, list):
    candidate_options = " ".join(candidate_options)
assert candidate_options == stock_options
config = pathlib.Path(candidate["path"])
assert config == pathlib.Path(stock["path"]).parent / "linux-cachyos-pt31553.conf"
boot_root = pathlib.Path(candidate["root"])
assert config == boot_root / "loader" / "entries" / candidate["id"]
assert config.is_file()
image = boot_root / "vmlinuz-linux-cachyos-pt31553"
initramfs = boot_root / "initramfs-linux-cachyos-pt31553.img"
assert image.is_file() and image.stat().st_size > 0
assert initramfs.is_file() and initramfs.stat().st_size > 0
print(image)
PY
)
candidate_initramfs="$(/usr/bin/dirname "$candidate_image")/initramfs-linux-cachyos-pt31553.img"
test "$(/usr/bin/sha256sum "$candidate_image" | /usr/bin/awk '{print $1}')" = \
  "$(sudo /usr/bin/cat /run/pt31553-verified-candidate-image-sha256)"
test "$(sudo /usr/bin/stat -c '%u:%a' \
  /run/pt31553-verified-candidate-initramfs-sha256)" = 0:400
test "$(/usr/bin/sha256sum "$candidate_initramfs" | /usr/bin/awk '{print $1}')" = \
  "$(sudo /usr/bin/cat /run/pt31553-verified-candidate-initramfs-sha256)"
/usr/bin/lsinitcpio "$candidate_initramfs" >/dev/null
/usr/bin/sbverify --cert "$image_cert" "$candidate_image"
for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
  /usr/bin/systemctl cat "$unit" >/dev/null
  test "$(/usr/bin/systemctl is-enabled "$unit")" = disabled
  test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
  test "$(/usr/bin/systemctl show "$unit" \
    --property=ActiveEnterTimestampMonotonic --value)" = 0
  test "$(/usr/bin/systemctl show "$unit" \
    --property=InactiveEnterTimestampMonotonic --value)" = 0
done
test -z "$(/usr/bin/journalctl -b --no-pager -o cat \
  _EXE=/usr/bin/pt31553-fand)"
! /usr/bin/pgrep -x pt31553-fand >/dev/null
/usr/bin/python3 -I - "$stock_entry" "$lts_entry" "$candidate_entry" \
  "$expected_default_entry" <<'PY'
import json
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, lts_id, candidate_id, expected_default_id = sys.argv[1:]
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in (stock_id, lts_id, candidate_id))
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert expected_default_id in {stock_id, lts_id}
assert defaults == [expected_default_id]
assert candidate_id != expected_default_id
PY
sudo /usr/bin/systemctl reboot --boot-loader-entry="$candidate_entry"
```

After boot, verify the exact candidate and recheck that fan control did not
become enabled. Do not start either unit here:

```sh
set -eu
test "$(/usr/bin/uname -r)" = 7.1.8-cachyos-pt31553
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
candidate_entry='REPLACE_WITH_PT31553_CANDIDATE_ENTRY_ID'
expected_default_entry='REPLACE_WITH_CURRENT_DEFAULT_STOCK_ENTRY_ID'
/usr/bin/python3 -I - "$stock_entry" "$lts_entry" "$candidate_entry" \
  "$expected_default_entry" <<'PY'
import json
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, lts_id, candidate_id, expected_default_id = sys.argv[1:]
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in (stock_id, lts_id, candidate_id))
assert sum(entry.get("id") == candidate_id for entry in entries) == 1
by_id = {entry["id"]: entry for entry in entries}
selected = [entry["id"] for entry in entries if entry.get("isSelected")]
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert selected == [candidate_id]
assert expected_default_id in {stock_id, lts_id}
assert defaults == [expected_default_id]
assert by_id[candidate_id].get("linux") == "/vmlinuz-linux-cachyos-pt31553"
initrds = by_id[candidate_id].get("initrd", [])
initrds = [initrds] if isinstance(initrds, str) else initrds
assert "/initramfs-linux-cachyos-pt31553.img" in initrds
PY
for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
  /usr/bin/systemctl cat "$unit" >/dev/null
  test "$(/usr/bin/systemctl is-enabled "$unit")" = disabled
  test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
  test "$(/usr/bin/systemctl show "$unit" \
    --property=ActiveEnterTimestampMonotonic --value)" = 0
  test "$(/usr/bin/systemctl show "$unit" \
    --property=InactiveEnterTimestampMonotonic --value)" = 0
done
test -z "$(/usr/bin/journalctl -b --no-pager -o cat \
  _EXE=/usr/bin/pt31553-fand)"
! /usr/bin/pgrep -x pt31553-fand >/dev/null
sudo /usr/bin/pt31553-fan-restore --restore
/usr/bin/bootctl list --no-pager
```

The candidate entry must show `selected`; a stock entry must still show
`default`. Only the separate qualification procedure may proceed from here.

### Sanitize qualification evidence and check promotion

Promotion is a manual, local operation after supervised endurance succeeds. Complete the
package-set verification and controller `pacman-key --verify` steps above first. Promotion binds
the hashes and signer identities of those already authenticated artifacts; it does not replace
their cryptographic verification.

Every input must be one root-owned, non-group/world-writable regular file with no hard links.
Every output parent and ancestor must likewise be protected and root-owned. First create a
whitelisted summary. It retains only the exact public hardware, kernel, module, policy, and
qualification identities plus the final outcome; raw samples, commands, readbacks, timestamps,
faults, workload details, paths, and process identities are never copied:

```sh
sudo /usr/bin/pt31553-fan-qualify redact-evidence \
  --qualification-record /var/lib/pt31553-fan-control/qualification.json \
  --evidence /var/lib/pt31553-fan-control/evidence/supervised-endurance.json \
  --authorized-evidence-path \
    /var/lib/pt31553-fan-control/evidence/supervised-endurance.json \
  --output /absolute/new/path/sanitized-qualification-evidence.json
```

Create a candidate manifest matching
[`schemas/promotion-manifest.json`](schemas/promotion-manifest.json), then check every bound
artifact and publish the immutable claim to a new path:

```sh
sudo /usr/bin/pt31553-fan-qualify check-promotion \
  --manifest /absolute/path/to/candidate-promotion.json \
  --qualification-record /var/lib/pt31553-fan-control/qualification.json \
  --evidence /var/lib/pt31553-fan-control/evidence/supervised-endurance.json \
  --authorized-evidence-path \
    /var/lib/pt31553-fan-control/evidence/supervised-endurance.json \
  --sanitized-evidence /absolute/path/to/sanitized-qualification-evidence.json \
  --protected-policy /absolute/path/to/qualified-root-owned-protected-policy.toml \
  --package-provenance /absolute/path/to/package-provenance-v1.json \
  --controller-package /absolute/path/to/pt31553-fan-control.pkg.tar.zst \
  --controller-signature /absolute/path/to/pt31553-fan-control.pkg.tar.zst.sig \
  --package-manifest-signature /absolute/path/to/package-set-manifest.p7s \
  --output /absolute/new/path/to/promotion.json
```

The check reruns strict qualification/evidence validation and requires exact controller,
policy, kernel image/module, package-set, signature-hash, signer, and sanitized-evidence
identities. It rejects symlinks, hard links, special files, mismatches, incomplete/no-go evidence,
unknown manifest claims, and existing output paths. CI success, a tag, a release, or public source
never substitutes for these files. On rejection it creates no promotion output.

### Retain the last qualified candidate

Complete this archive immediately after qualification and before entering the
removal procedure. The last-qualified candidate remains the rollback build
until a successor has passed every required qualification gate. Archive the
exact verified inputs outside the source tree in a new directory published
under a root-owned, non-writable archive parent. Also bundle the exact verifier
Git revision, including its bound
policy, schema, compatibility declaration, and history checks. Copy public
certificates only—never signing private keys—and verify through the archived
revision before making the archive read-only. Give every qualified build a
new versioned `last_qualified` path. For a successor, set `previous_qualified`
to the current rollback archive; it must remain present and immutable until
the successor is published atomically at its new path. The archive also keeps
the exact signed controller package and a standalone copy of its qualification
validator, so every install/recovery prerequisite remains restorable after
optional controller removal:

```sh
set -eu
artifact_dir=/absolute/path/to/build-output
provenance_record=/absolute/path/to/package-provenance-v1.json
package_manifest_signature=/absolute/path/to/package-set-manifest.p7s
module_cert=/absolute/path/to/module-signing-certificate.der
package_cert=/absolute/path/to/package-signing-certificate.pem
kernel_cert=/absolute/path/to/enrolled-image-signing-certificate.pem
module_cert_sha256='REPLACE_WITH_MODULE_CERT_SHA256'
package_cert_sha256='REPLACE_WITH_PACKAGE_CERT_SHA256'
kernel_cert_sha256='REPLACE_WITH_KERNEL_CERT_SHA256'
archive_parent=/var/lib/pt31553-fan-control/rollback
last_qualified=$archive_parent/pt31553-last-qualified-7.1.8-1
previous_qualified=
controller_package=/absolute/path/to/pt31553-fan-control-0.1.0-6-x86_64.pkg.tar.zst
controller_package_signature=/absolute/path/to/pt31553-fan-control-0.1.0-6-x86_64.pkg.tar.zst.sig
controller_package_sha256='REPLACE_WITH_CONTROLLER_PACKAGE_SHA256'
qualification_record=/var/lib/pt31553-fan-control/qualification.json
endurance_evidence=/var/lib/pt31553-fan-control/evidence/supervised-endurance.json
protected_policy=/absolute/path/to/qualified-root-owned-protected-policy.toml
expected_verifier_commit=$(/usr/bin/git rev-parse HEAD)

umask 077
sudo /usr/bin/install -d -o root -g root -m 0755 "$archive_parent"
test ! -L "$archive_parent"
test "$(sudo /usr/bin/stat -c '%U:%G:%a' "$archive_parent")" = root:root:755
sudo /usr/bin/python3 -I - "$archive_parent" <<'PY'
import os
import pathlib
import stat
import sys

current = pathlib.Path("/")
for component in pathlib.Path(sys.argv[1]).parts[1:]:
    current /= component
    metadata = os.lstat(current)
    assert metadata.st_uid == 0
    assert metadata.st_gid == 0
    assert metadata.st_mode & 0o022 == 0
    assert not stat.S_ISLNK(metadata.st_mode)
PY
test "$(/usr/bin/pacman -Qqo /usr/bin/pt31553-fan-qualify)" = pt31553-fan-control
test "$(sudo /usr/bin/stat -c '%U:%G:%a' /usr/bin/pt31553-fan-qualify)" = root:root:755
test -f "$controller_package"
test ! -L "$controller_package"
test -f "$controller_package_signature"
test ! -L "$controller_package_signature"
test "$(/usr/bin/sha256sum "$controller_package" | /usr/bin/awk '{print $1}')" = \
  "$controller_package_sha256"
/usr/bin/pacman-key --verify "$controller_package_signature" "$controller_package"
test "$(/usr/bin/pacman -Qp "$controller_package")" = \
  "$(/usr/bin/pacman -Q pt31553-fan-control)"
sudo /usr/bin/python3 -I - "$protected_policy" "$qualification_record" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

policy = pathlib.Path(sys.argv[1])
qualification = pathlib.Path(sys.argv[2])
assert policy.is_absolute()
current = pathlib.Path("/")
for component in policy.parts[1:]:
    current /= component
    metadata = os.lstat(current)
    assert metadata.st_uid == 0
    assert metadata.st_mode & 0o022 == 0
    assert not stat.S_ISLNK(metadata.st_mode)
assert stat.S_ISREG(os.lstat(policy).st_mode)
record = json.loads(qualification.read_text())
policy_sha256 = hashlib.sha256(policy.read_bytes()).hexdigest()
assert policy_sha256 == record["protected_policy_sha256"]
PY
if test -n "$previous_qualified"; then
  test "$previous_qualified" != "$last_qualified"
  test "$(/usr/bin/dirname "$previous_qualified")" = "$archive_parent"
  test -d "$previous_qualified"
  test ! -L "$previous_qualified"
  test "$(/usr/bin/stat -c '%U:%G' "$previous_qualified")" = root:root
  test -z "$(/usr/bin/find "$previous_qualified" \
    \( ! -user root -o ! -group root \) -print -quit)"
  test -z "$(/usr/bin/find "$previous_qualified" -perm /222 -print -quit)"
fi
if test -e "$last_qualified"; then
  test "$(/usr/bin/dirname "$last_qualified")" = "$archive_parent"
  test -d "$last_qualified"
  test ! -L "$last_qualified"
  test "$(/usr/bin/stat -c '%U:%G' "$last_qualified")" = root:root
  test -z "$(/usr/bin/find "$last_qualified" \
    \( ! -user root -o ! -group root \) -print -quit)"
  test -z "$(/usr/bin/find "$last_qualified" -perm /222 -print -quit)"
  archive_recheck=$(/usr/bin/mktemp -d \
    "/tmp/pt31553-pre-removal-recheck.XXXXXX")
  /usr/bin/git bundle verify "$last_qualified/verifier-source.bundle"
  /usr/bin/git clone --no-checkout "$last_qualified/verifier-source.bundle" \
    "$archive_recheck/verifier"
  /usr/bin/git -C "$archive_recheck/verifier" checkout --detach \
    "$(/usr/bin/cat "$last_qualified/verifier-commit")"
  "$archive_recheck/verifier/scripts/verify-package-provenance" \
    --artifacts "$last_qualified/build-output" \
    --module-cert "$last_qualified/module-signing-certificate.der" \
    --module-cert-sha256 "$module_cert_sha256" \
    --package-cert "$last_qualified/package-signing-certificate.pem" \
    --package-cert-sha256 "$package_cert_sha256" \
    --kernel-cert "$last_qualified/enrolled-image-signing-certificate.pem" \
    --kernel-cert-sha256 "$kernel_cert_sha256" \
    --package-manifest-signature "$last_qualified/package-set-manifest.p7s" \
    --output "$archive_recheck/package-provenance-v1.json"
  /usr/bin/cmp "$last_qualified/package-provenance-v1.json" \
    "$archive_recheck/package-provenance-v1.json"
  test "$(/usr/bin/sha256sum "$last_qualified/pt31553-fan-control.pkg.tar.zst" | \
    /usr/bin/awk '{print $1}')" = \
    "$(/usr/bin/cat "$last_qualified/controller-package.sha256")"
  test "$(/usr/bin/cat "$last_qualified/controller-package.sha256")" = \
    "$controller_package_sha256"
  test "$(/usr/bin/pacman -Qp \
    "$last_qualified/pt31553-fan-control.pkg.tar.zst")" = \
    "$(/usr/bin/pacman -Qp "$controller_package")"
  /usr/bin/pacman-key --verify \
    "$last_qualified/pt31553-fan-control.pkg.tar.zst.sig" \
    "$last_qualified/pt31553-fan-control.pkg.tar.zst"
  validator_recheck=$(/usr/bin/mktemp)
  /usr/bin/bsdtar -xOf \
    "$last_qualified/pt31553-fan-control.pkg.tar.zst" \
    usr/bin/pt31553-fan-qualify >"$validator_recheck"
  /usr/bin/cmp "$validator_recheck" "$last_qualified/pt31553-fan-qualify"
  /usr/bin/rm -f -- "$validator_recheck"
  test -x "$last_qualified/pt31553-fan-qualify"
  "$last_qualified/pt31553-fan-qualify" validate-records \
    --qualification-record "$last_qualified/qualification.json" \
    --evidence "$last_qualified/supervised-endurance.json" \
    --authorized-evidence-path \
      /var/lib/pt31553-fan-control/evidence/supervised-endurance.json
  /usr/bin/python3 -I - "$last_qualified" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
provenance = json.loads((root / "package-provenance-v1.json").read_text())
qualification = json.loads((root / "qualification.json").read_text())
policy_sha256 = hashlib.sha256((root / "protected-policy.toml").read_bytes()).hexdigest()
assert policy_sha256 == qualification["protected_policy_sha256"]
qualified_kernel = qualification["compatibility"]["kernel"]
for field in ("release", "package", "image_sha256", "image_signer_fingerprint"):
    assert qualified_kernel[field] == provenance["kernel"][field]
PY
  /usr/bin/cmp "$provenance_record" \
    "$last_qualified/package-provenance-v1.json"
  sudo /usr/bin/cmp "$qualification_record" \
    "$last_qualified/qualification.json"
  sudo /usr/bin/cmp "$endurance_evidence" \
    "$last_qualified/supervised-endurance.json"
  sudo /usr/bin/cmp "$protected_policy" \
    "$last_qualified/protected-policy.toml"
else
  test "$(/usr/bin/dirname "$last_qualified")" = "$archive_parent"
  archive_target=$(sudo /usr/bin/mktemp -d \
    "$archive_parent/.pt31553-last-qualified-staging.XXXXXX")
  operator_uid=$(/usr/bin/id -u)
  operator_gid=$(/usr/bin/id -g)
  sudo /usr/bin/chown "$operator_uid:$operator_gid" "$archive_target"
  test "$(sudo /usr/bin/stat -c '%u:%a' "$qualification_record")" = 0:600
  test "$(sudo /usr/bin/stat -c '%u:%a' "$endurance_evidence")" = 0:600
  /usr/bin/cp -a -- "$artifact_dir" "$archive_target/build-output"
  /usr/bin/cp -- "$provenance_record" "$archive_target/package-provenance-v1.json"
  /usr/bin/cp -- "$package_manifest_signature" \
    "$archive_target/package-set-manifest.p7s"
  /usr/bin/cp -- "$module_cert" "$archive_target/module-signing-certificate.der"
  /usr/bin/cp -- "$package_cert" "$archive_target/package-signing-certificate.pem"
  /usr/bin/cp -- "$kernel_cert" \
    "$archive_target/enrolled-image-signing-certificate.pem"
  /usr/bin/cp -- "$controller_package" \
    "$archive_target/pt31553-fan-control.pkg.tar.zst"
  /usr/bin/cp -- "$controller_package_signature" \
    "$archive_target/pt31553-fan-control.pkg.tar.zst.sig"
  /usr/bin/printf '%s\n' "$controller_package_sha256" > \
    "$archive_target/controller-package.sha256"
  sudo /usr/bin/install -o "$operator_uid" -g "$operator_gid" -m 0400 \
    "$qualification_record" "$archive_target/qualification.json"
  sudo /usr/bin/install -o "$operator_uid" -g "$operator_gid" -m 0400 \
    "$endurance_evidence" "$archive_target/supervised-endurance.json"
  sudo /usr/bin/install -o "$operator_uid" -g "$operator_gid" -m 0400 \
    "$protected_policy" "$archive_target/protected-policy.toml"
  /usr/bin/bsdtar -xOf \
    "$archive_target/pt31553-fan-control.pkg.tar.zst" \
    usr/bin/pt31553-fan-qualify >"$archive_target/pt31553-fan-qualify"
  /usr/bin/chmod 0500 "$archive_target/pt31553-fan-qualify"
  /usr/bin/cmp /usr/bin/pt31553-fan-qualify \
    "$archive_target/pt31553-fan-qualify"
  /usr/bin/printf '%s\n' "$expected_verifier_commit" > \
    "$archive_target/verifier-commit"
  /usr/bin/git bundle create "$archive_target/verifier-source.bundle" HEAD
  /usr/bin/git clone --no-checkout "$archive_target/verifier-source.bundle" \
    "$archive_target/verifier-checkout"
  /usr/bin/git -C "$archive_target/verifier-checkout" checkout --detach \
    "$(/usr/bin/cat "$archive_target/verifier-commit")"
  "$archive_target/verifier-checkout/scripts/verify-package-provenance" \
    --artifacts "$archive_target/build-output" \
    --module-cert "$archive_target/module-signing-certificate.der" \
    --module-cert-sha256 "$module_cert_sha256" \
    --package-cert "$archive_target/package-signing-certificate.pem" \
    --package-cert-sha256 "$package_cert_sha256" \
    --kernel-cert "$archive_target/enrolled-image-signing-certificate.pem" \
    --kernel-cert-sha256 "$kernel_cert_sha256" \
    --package-manifest-signature "$archive_target/package-set-manifest.p7s" \
    --output "$archive_target/reverified-package-provenance-v1.json"
  /usr/bin/cmp "$archive_target/package-provenance-v1.json" \
    "$archive_target/reverified-package-provenance-v1.json"
  /usr/bin/chmod -R a-w "$archive_target"
  test "$(/usr/bin/sha256sum "$archive_target/pt31553-fan-control.pkg.tar.zst" | \
    /usr/bin/awk '{print $1}')" = \
    "$(/usr/bin/cat "$archive_target/controller-package.sha256")"
  /usr/bin/pacman-key --verify \
    "$archive_target/pt31553-fan-control.pkg.tar.zst.sig" \
    "$archive_target/pt31553-fan-control.pkg.tar.zst"
  /usr/bin/python3 -I - "$archive_target" <<'PY'
import json
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
provenance = json.loads((root / "package-provenance-v1.json").read_text())
qualification = json.loads((root / "qualification.json").read_text())
policy_sha256 = hashlib.sha256((root / "protected-policy.toml").read_bytes()).hexdigest()
assert policy_sha256 == qualification["protected_policy_sha256"]
qualified_kernel = qualification["compatibility"]["kernel"]
for field in ("release", "package", "image_sha256", "image_signer_fingerprint"):
    assert qualified_kernel[field] == provenance["kernel"][field]
PY
  sudo /usr/bin/chown -R root:root "$archive_target"
  sudo /usr/bin/find "$archive_target" -type d -exec /usr/bin/chmod 0555 {} +
  sudo /usr/bin/find "$archive_target" -type f -perm /111 \
    -exec /usr/bin/chmod 0555 {} +
  sudo /usr/bin/find "$archive_target" -type f ! -perm /111 \
    -exec /usr/bin/chmod 0444 {} +
  test -z "$(sudo /usr/bin/find "$archive_target" \
    \( ! -user root -o ! -group root \) -print -quit)"
  test -z "$(sudo /usr/bin/find "$archive_target" -perm /222 -print -quit)"
  locked_recheck=$(/usr/bin/mktemp -d \
    "/tmp/pt31553-locked-archive-recheck.XXXXXX")
  test "$(/usr/bin/cat "$archive_target/verifier-commit")" = \
    "$expected_verifier_commit"
  /usr/bin/git bundle verify "$archive_target/verifier-source.bundle"
  /usr/bin/git clone --no-checkout "$archive_target/verifier-source.bundle" \
    "$locked_recheck/verifier"
  /usr/bin/git -C "$locked_recheck/verifier" checkout --detach \
    "$expected_verifier_commit"
  "$locked_recheck/verifier/scripts/verify-package-provenance" \
    --artifacts "$archive_target/build-output" \
    --module-cert "$archive_target/module-signing-certificate.der" \
    --module-cert-sha256 "$module_cert_sha256" \
    --package-cert "$archive_target/package-signing-certificate.pem" \
    --package-cert-sha256 "$package_cert_sha256" \
    --kernel-cert "$archive_target/enrolled-image-signing-certificate.pem" \
    --kernel-cert-sha256 "$kernel_cert_sha256" \
    --package-manifest-signature "$archive_target/package-set-manifest.p7s" \
    --output "$locked_recheck/package-provenance-v1.json"
  /usr/bin/cmp "$archive_target/package-provenance-v1.json" \
    "$locked_recheck/package-provenance-v1.json"
  /usr/bin/pacman-key --verify \
    "$archive_target/pt31553-fan-control.pkg.tar.zst.sig" \
    "$archive_target/pt31553-fan-control.pkg.tar.zst"
  validator_recheck=$(/usr/bin/mktemp)
  /usr/bin/bsdtar -xOf \
    "$archive_target/pt31553-fan-control.pkg.tar.zst" \
    usr/bin/pt31553-fan-qualify >"$validator_recheck"
  /usr/bin/cmp "$validator_recheck" "$archive_target/pt31553-fan-qualify"
  /usr/bin/rm -f -- "$validator_recheck"
  "$archive_target/pt31553-fan-qualify" validate-records \
    --qualification-record "$archive_target/qualification.json" \
    --evidence "$archive_target/supervised-endurance.json" \
    --authorized-evidence-path "$endurance_evidence"
  /usr/bin/python3 -I - "$archive_target" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
provenance = json.loads((root / "package-provenance-v1.json").read_text())
qualification = json.loads((root / "qualification.json").read_text())
policy_sha256 = hashlib.sha256((root / "protected-policy.toml").read_bytes()).hexdigest()
assert policy_sha256 == qualification["protected_policy_sha256"]
qualified_kernel = qualification["compatibility"]["kernel"]
for field in ("release", "package", "image_sha256", "image_signer_fingerprint"):
    assert qualified_kernel[field] == provenance["kernel"][field]
PY
  /usr/bin/rm -rf -- "$locked_recheck"
  sudo /usr/bin/sync -f "$archive_target"
  test ! -e "$last_qualified"
  sudo /usr/bin/mv -T "$archive_target" "$last_qualified"
  sudo /usr/bin/sync -f "$archive_parent"
fi
test -d "$last_qualified"
test ! -L "$last_qualified"
test "$(/usr/bin/stat -c '%U:%G' "$last_qualified")" = root:root
test -z "$(/usr/bin/find "$last_qualified" \
  \( ! -user root -o ! -group root \) -print -quit)"
test -z "$(/usr/bin/find "$last_qualified" -perm /222 -print -quit)"
/usr/bin/cmp "$provenance_record" \
  "$last_qualified/package-provenance-v1.json"
if test -n "$previous_qualified"; then
  test -d "$previous_qualified"
fi
```

Do not issue either removal command below unless this archive and its
reverification succeeded. For a qualified successor, the final checks above
prove the new versioned archive is published while the previous archive still
exists. Only then may the operator retire `previous_qualified`. Before
installing the next candidate, point the recheck below at this newly published
`last_qualified`; never install over a qualified candidate whose own archive
has not completed these checks.

### Return to stock before removal

On any anomaly, keep userspace alive and stop the controller normally. Its
stop hook restores Auto; then the independent recovery tool requests and
confirms CPU and GPU Firmware Auto again. The second command does not return
success until both readbacks equal `2`. If it keeps retrying or fails, do not
continue or reboot; use the emergency guidance in `SECURITY.md`.

Stop the sleep guard first: its stop hook can resume the daemon from a prepared
sleep, so the daemon stop must come after it. A failed initial daemon stop is
deliberately tolerated only so the independent recovery command still runs and
waits for ownership. After disabling both units, stop the daemon successfully,
clear any failed/restart state, perform a second independent Auto restore, and
require both units to remain inactive. Every command after the initial daemon
stop is fail-closed.

```sh
set -eu
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
candidate_entry='REPLACE_WITH_PT31553_CANDIDATE_ENTRY_ID'
recovery_attestation=/var/lib/pt31553-fan-control/recovery-to-stock.json
test "$(/usr/bin/uname -r)" = 7.1.8-cachyos-pt31553
sudo /usr/bin/systemctl stop pt31553-fan-sleep-guard.service
sudo /usr/bin/systemctl stop pt31553-fand.service || true
test "$(/usr/bin/systemctl is-active pt31553-fan-sleep-guard.service || true)" = inactive
sudo /usr/bin/pt31553-fan-restore --restore
sudo /usr/bin/systemctl disable \
  pt31553-fand.service pt31553-fan-sleep-guard.service
sudo /usr/bin/systemctl stop pt31553-fand.service
sudo /usr/bin/systemctl reset-failed pt31553-fand.service
sudo /usr/bin/pt31553-fan-restore --restore
for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
  test "$(/usr/bin/systemctl is-enabled "$unit")" = disabled
  test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
done
attestation_parent=$(/usr/bin/dirname "$recovery_attestation")
test "$(sudo /usr/bin/stat -c '%U:%G' "$attestation_parent")" = root:root
case "$(sudo /usr/bin/stat -c '%a' "$attestation_parent")" in
  700|750|755) ;;
  *) exit 1 ;;
esac
test ! -L "$attestation_parent"
attestation_source=$(/usr/bin/mktemp)
attestation_target=$(sudo /usr/bin/mktemp \
  "$attestation_parent/.recovery-to-stock.XXXXXX")
cleanup_recovery_attestation_temps() {
  /usr/bin/rm -f -- "$attestation_source"
  sudo /usr/bin/rm -f -- "$attestation_target"
}
trap cleanup_recovery_attestation_temps EXIT HUP INT TERM
/usr/bin/python3 -I - "$candidate_entry" "$lts_entry" >"$attestation_source" <<'PY'
import json
import pathlib
import subprocess
import sys

candidate_id, lts_id = sys.argv[1:]
entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
selected = [entry["id"] for entry in entries if entry.get("isSelected")]
assert selected == [candidate_id]
print(json.dumps({
    "schema_version": 1,
    "firmware_auto_confirmed": True,
    "source_boot_id": pathlib.Path(
        "/proc/sys/kernel/random/boot_id"
    ).read_text().strip(),
    "source_kernel_release": "7.1.8-cachyos-pt31553",
    "source_entry": candidate_id,
    "target_entry": lts_id,
}, separators=(",", ":")))
PY
sudo /usr/bin/install -o root -g root -m 0400 \
  "$attestation_source" "$attestation_target"
sudo /usr/bin/sync -f "$attestation_target"
sudo /usr/bin/mv -T "$attestation_target" "$recovery_attestation"
sudo /usr/bin/sync -f "$attestation_parent"
trap - EXIT HUP INT TERM
/usr/bin/rm -f -- "$attestation_source"
/usr/bin/pacman -Q linux-cachyos-lts
lts_package=$(/usr/bin/pacman -Q linux-cachyos-lts)
case "$lts_package" in "linux-cachyos-lts 6.18"*) ;; *) exit 1 ;; esac
lts_boot_root=$(/usr/bin/python3 -I - "$lts_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
matching = [entry for entry in entries if entry.get("id") == sys.argv[1]]
assert len(matching) == 1
lts = matching[0]
assert lts.get("type") == "type1"
assert lts.get("source") in {"esp", "xbootldr"}
boot_root = pathlib.Path(lts["root"])
config = pathlib.Path(lts["path"])
assert boot_root.is_absolute()
assert config == boot_root / "loader" / "entries" / lts["id"]
assert config.is_file()
assert lts.get("linux") == "/vmlinuz-linux-cachyos-lts"
initrds = lts.get("initrd", [])
initrds = [initrds] if isinstance(initrds, str) else initrds
assert initrds == ["/intel-ucode.img", "/initramfs-linux-cachyos-lts.img"]
for value in [lts["linux"], *initrds]:
    path = pathlib.PurePosixPath(value)
    assert path.is_absolute() and ".." not in path.parts
    host_path = boot_root.joinpath(*path.parts[1:])
    assert host_path.is_file() and host_path.stat().st_size > 0
print(boot_root)
PY
)
lts_image="$lts_boot_root/vmlinuz-linux-cachyos-lts"
lts_initramfs="$lts_boot_root/initramfs-linux-cachyos-lts.img"
lts_packaged_image=$(/usr/bin/pacman -Qlq linux-cachyos-lts | \
  /usr/bin/awk '
    /\/usr\/lib\/modules\/[^/]+\/vmlinuz$/ {
      if (image != "") exit 2
      image=$0
    }
    END {
      if (image == "") exit 1
      print image
    }
  ')
test -f "$lts_packaged_image"
test ! -L "$lts_packaged_image"
test "$(/usr/bin/pacman -Qqo "$lts_packaged_image")" = linux-cachyos-lts
/usr/bin/cmp "$lts_packaged_image" "$lts_image"
/usr/bin/lsinitcpio "$lts_initramfs" >/dev/null
sudo /usr/bin/systemctl reboot --boot-loader-entry="$lts_entry"
```

After the LTS recovery boot, prove the custom kernel is no longer running and
that the packaged 6.18 LTS module is selected. Confirm no userspace controller
is active and that this pre-PWM stock driver exposes no Custom-mode endpoints;
firmware is then the only remaining fan controller:

```sh
set -eu
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
/usr/bin/python3 -I - "$lts_entry" <<'PY'
import json
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
recovery_id = sys.argv[1]
assert sum(entry.get("id") == recovery_id for entry in entries) == 1
by_id = {entry["id"]: entry for entry in entries}
selected = [entry["id"] for entry in entries if entry.get("isSelected")]
assert selected == [recovery_id]
assert by_id[recovery_id].get("linux") == "/vmlinuz-linux-cachyos-lts"
initrds = by_id[recovery_id].get("initrd", [])
initrds = [initrds] if isinstance(initrds, str) else initrds
assert initrds == ["/intel-ucode.img", "/initramfs-linux-cachyos-lts.img"]
PY
recovery_module=$(/usr/bin/modinfo -n acer_wmi)
case "$recovery_module" in
  "/usr/lib/modules/$(/usr/bin/uname -r)/kernel/drivers/platform/x86/acer-wmi.ko"*) ;;
  *) exit 1 ;;
esac
recovery_module_owner=$(/usr/bin/pacman -Qqo "$recovery_module")
test "$recovery_module_owner" = linux-cachyos-lts
/usr/bin/modinfo -F vermagic acer_wmi
stock_acer_hwmon=$(/usr/bin/python3 -I - <<'PY'
import pathlib

matches = []
for hwmon in pathlib.Path("/sys/class/hwmon").glob("hwmon[0-9]*"):
    if (hwmon / "name").read_text().strip() == "acer":
        matches.append(hwmon)
assert len(matches) <= 1
if matches:
    print(matches[0])
PY
)
if test -n "$stock_acer_hwmon"; then
  for endpoint in pwm1 pwm1_enable pwm2 pwm2_enable; do
    test ! -e "$stock_acer_hwmon/$endpoint"
  done
fi
for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
  test "$(/usr/bin/systemctl is-enabled "$unit")" = disabled
  test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
done
! /usr/bin/pgrep -x pt31553-fand >/dev/null
/usr/bin/bootctl list --no-pager
```

Do not run `pt31553-fan-restore` from the stock kernel: stock is deliberately
not marked `recovery_pwm_capable` and does not expose the qualified two-fan PWM
ABI. The successful candidate-side Auto readbacks immediately before this
one-shot stock boot, followed by the stock-side absence checks above, are
therefore the removal prerequisite. Stock cannot issue Custom-mode writes and
no controller process is active.

Only after every preceding Auto and stock check passes may the candidate and,
if desired, the controller be removed. Remove exact packages without recursive
dependency removal, then confirm both stock entries and images remain:

```sh
set -eu
stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'
lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'
candidate_entry='REPLACE_WITH_PT31553_CANDIDATE_ENTRY_ID'
recovery_attestation=/var/lib/pt31553-fan-control/recovery-to-stock.json
remove_controller=0 # set to 1 only when controller removal is desired
case "$remove_controller" in 0|1) ;; *) exit 1 ;; esac
test ! -L "$recovery_attestation"
test "$(sudo /usr/bin/stat -c '%U:%G:%a' "$recovery_attestation")" = root:root:400
previous_boot_id=$(sudo /usr/bin/journalctl --list-boots --no-pager --quiet | \
  /usr/bin/awk '$1 == "-1" {print $2}')
case "$previous_boot_id" in
  *[!0-9a-f]*|'') exit 1 ;;
esac
test "${#previous_boot_id}" = 32
sudo /usr/bin/python3 -I - "$recovery_attestation" \
  "$candidate_entry" "$lts_entry" "$previous_boot_id" <<'PY'
import json
import pathlib
import sys

attestation = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert set(attestation) == {
    "schema_version", "firmware_auto_confirmed", "source_boot_id",
    "source_kernel_release", "source_entry", "target_entry",
}
assert attestation["schema_version"] == 1
assert attestation["firmware_auto_confirmed"] is True
assert attestation["source_kernel_release"] == "7.1.8-cachyos-pt31553"
assert attestation["source_entry"] == sys.argv[2]
assert attestation["target_entry"] == sys.argv[3]
current_boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
assert attestation["source_boot_id"] != current_boot_id
assert attestation["source_boot_id"].replace("-", "") == sys.argv[4]
PY
candidate_packages_installed=0
candidate_kernel_installed=0
for package in linux-cachyos-pt31553 linux-cachyos-pt31553-headers \
  linux-cachyos-pt31553-nvidia-open; do
  if /usr/bin/pacman -Q "$package" >/dev/null 2>&1; then
    candidate_packages_installed=$((candidate_packages_installed + 1))
    if test "$package" = linux-cachyos-pt31553; then
      candidate_kernel_installed=1
    fi
  fi
done
case "$candidate_packages_installed" in 0|1|2|3) ;; *) exit 1 ;; esac

candidate_boot_root=$(/usr/bin/python3 -I - \
  "$stock_entry" "$lts_entry" "$candidate_entry" \
  "$candidate_packages_installed" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, lts_id, candidate_id, installed_count = sys.argv[1:]
assert installed_count in {"0", "1", "2", "3"}
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in (stock_id, lts_id))
by_id = {entry["id"]: entry for entry in entries}
selected = [entry["id"] for entry in entries if entry.get("isSelected")]
assert selected == [lts_id]
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert len(defaults) == 1
assert defaults[0] in {stock_id, lts_id}

def paths(entry, field):
    value = entry.get(field, [])
    return [value] if isinstance(value, str) else value

def require_loader_files(entry):
    assert entry.get("type") == "type1"
    assert entry.get("source") in {"esp", "xbootldr"}
    boot_root = pathlib.Path(entry["root"])
    config = pathlib.Path(entry["path"])
    assert boot_root.is_absolute()
    assert config == boot_root / "loader" / "entries" / entry["id"]
    assert config.is_file()
    for field in ("linux", "initrd"):
        for value in paths(entry, field):
            path = pathlib.PurePosixPath(value)
            assert path.is_absolute() and ".." not in path.parts
            host_path = boot_root.joinpath(*path.parts[1:])
            assert host_path.is_file() and host_path.stat().st_size > 0

assert paths(by_id[stock_id], "linux") == ["/vmlinuz-linux-cachyos"]
assert "/initramfs-linux-cachyos.img" in paths(by_id[stock_id], "initrd")
assert paths(by_id[lts_id], "linux") == ["/vmlinuz-linux-cachyos-lts"]
assert paths(by_id[lts_id], "initrd") == [
    "/intel-ucode.img",
    "/initramfs-linux-cachyos-lts.img",
]
require_loader_files(by_id[stock_id])
require_loader_files(by_id[lts_id])
stock_path = pathlib.Path(by_id[stock_id]["path"])
expected_path = stock_path.parent / "linux-cachyos-pt31553.conf"
candidate_image_entries = [
    entry for entry in entries
    if entry.get("linux") == "/vmlinuz-linux-cachyos-pt31553"
]
candidate_id_entries = [entry for entry in entries if entry.get("id") == candidate_id]
assert len(candidate_image_entries) <= 1
assert len(candidate_id_entries) <= 1
if candidate_image_entries or candidate_id_entries:
    assert candidate_image_entries == candidate_id_entries
    candidate = candidate_image_entries[0]
    candidate_path = pathlib.Path(candidate["path"])
    assert candidate.get("type") == "type1"
    assert candidate.get("source") == by_id[stock_id].get("source")
    assert candidate.get("root") == by_id[stock_id].get("root")
    assert candidate_path == expected_path
    assert paths(candidate, "linux") == ["/vmlinuz-linux-cachyos-pt31553"]
    expected_initrds = [
        "/initramfs-linux-cachyos-pt31553.img"
        if path == "/initramfs-linux-cachyos.img" else path
        for path in paths(by_id[stock_id], "initrd")
    ]
    assert paths(candidate, "initrd") == expected_initrds
    stock_options = by_id[stock_id].get("options")
    candidate_options = candidate.get("options")
    if isinstance(stock_options, list):
        stock_options = " ".join(stock_options)
    if isinstance(candidate_options, list):
        candidate_options = " ".join(candidate_options)
    assert candidate_options == stock_options
    require_loader_files(candidate)
print(by_id[stock_id]["root"])
PY
)
candidate_config="$candidate_boot_root/loader/entries/linux-cachyos-pt31553.conf"
candidate_image="$candidate_boot_root/vmlinuz-linux-cachyos-pt31553"
candidate_initramfs="$candidate_boot_root/initramfs-linux-cachyos-pt31553.img"
for path in "$candidate_image" "$candidate_initramfs"; do
  if test -e "$path"; then
    test -f "$path"
    test ! -L "$path"
  fi
done
if test "$candidate_kernel_installed" = 1 && test -e "$candidate_image"; then
  /usr/bin/cmp /usr/lib/modules/7.1.8-cachyos-pt31553/vmlinuz \
    "$candidate_image"
fi
if test -e "$candidate_initramfs"; then
  /usr/bin/lsinitcpio "$candidate_initramfs" >/dev/null
fi
if test "$remove_controller" = 1; then
  if /usr/bin/pacman -Q pt31553-fan-control >/dev/null 2>&1; then
    sudo /usr/bin/pacman -R pt31553-fan-control
  else
    test ! -e /usr/bin/pt31553-fand
    test ! -e /usr/bin/pt31553-fan-restore
    test ! -e /usr/bin/pt31553-fan-qualify
    test ! -e /usr/lib/systemd/system/pt31553-fand.service
    test ! -e /usr/lib/systemd/system/pt31553-fan-sleep-guard.service
  fi
fi
sudo /usr/bin/rm -f -- "$candidate_config"
/usr/bin/python3 -I - "$candidate_entry" <<'PY'
import json
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
assert sys.argv[1] not in {entry["id"] for entry in entries}
assert not any(entry.get("linux") == "/vmlinuz-linux-cachyos-pt31553"
               for entry in entries)
PY
sudo /usr/bin/rm -f -- "$candidate_image" "$candidate_initramfs"
test ! -e "$candidate_image"
test ! -e "$candidate_initramfs"
for package in linux-cachyos-pt31553-nvidia-open \
  linux-cachyos-pt31553-headers linux-cachyos-pt31553; do
  if /usr/bin/pacman -Q "$package" >/dev/null 2>&1; then
    sudo /usr/bin/pacman -R "$package"
  fi
done
/usr/bin/pacman -Q linux-cachyos linux-cachyos-lts
lts_package=$(/usr/bin/pacman -Q linux-cachyos-lts)
case "$lts_package" in "linux-cachyos-lts 6.18"*) ;; *) exit 1 ;; esac

/usr/bin/python3 -I - "$stock_entry" "$lts_entry" "$candidate_entry" <<'PY'
import json
import pathlib
import subprocess
import sys

entries = json.loads(subprocess.run(
    ["/usr/bin/bootctl", "list", "--json=short"],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout)
stock_id, lts_id, removed_candidate_id = sys.argv[1:]
assert all(sum(entry.get("id") == entry_id for entry in entries) == 1
           for entry_id in (stock_id, lts_id))
by_id = {entry["id"]: entry for entry in entries}
assert removed_candidate_id not in by_id
assert not any(entry.get("linux") == "/vmlinuz-linux-cachyos-pt31553"
               for entry in entries)

def paths(entry, field):
    value = entry.get(field, [])
    return [value] if isinstance(value, str) else value

def require_loader_files(entry):
    assert entry.get("type") == "type1"
    assert entry.get("source") in {"esp", "xbootldr"}
    boot_root = pathlib.Path(entry["root"])
    config = pathlib.Path(entry["path"])
    assert boot_root.is_absolute()
    assert config == boot_root / "loader" / "entries" / entry["id"]
    assert config.is_file()
    for field in ("linux", "initrd"):
        for value in paths(entry, field):
            path = pathlib.PurePosixPath(value)
            assert path.is_absolute() and ".." not in path.parts
            host_path = boot_root.joinpath(*path.parts[1:])
            assert host_path.is_file() and host_path.stat().st_size > 0

assert paths(by_id[stock_id], "linux") == ["/vmlinuz-linux-cachyos"]
assert "/initramfs-linux-cachyos.img" in paths(by_id[stock_id], "initrd")
assert paths(by_id[lts_id], "linux") == ["/vmlinuz-linux-cachyos-lts"]
assert paths(by_id[lts_id], "initrd") == [
    "/intel-ucode.img",
    "/initramfs-linux-cachyos-lts.img",
]
require_loader_files(by_id[stock_id])
require_loader_files(by_id[lts_id])
defaults = [entry["id"] for entry in entries if entry.get("isDefault")]
assert len(defaults) == 1
assert defaults[0] in {stock_id, lts_id}
PY
sudo /usr/bin/rm -f -- "$recovery_attestation"
sudo /usr/bin/sync -f "$(/usr/bin/dirname "$recovery_attestation")"
```

### Reverify the retained candidate before a successor

Before installing a successor, verify the retained archive once more into a
new empty evidence directory. Check out and invoke the bundled verifier
revision and archived qualification validator, not the successor checkout or
an optionally removed controller package. This preserves the read-only archive
and keeps the retained candidate verifiable after successor policy changes:

```sh
set -eu
archive_parent=/var/lib/pt31553-fan-control/rollback
last_qualified=$archive_parent/pt31553-last-qualified-7.1.8-1
recheck_dir=/tmp/pt31553-last-qualified-recheck
protected_policy=/absolute/path/to/root-owned-protected-policy.toml
module_cert_sha256='REPLACE_WITH_MODULE_CERT_SHA256'
package_cert_sha256='REPLACE_WITH_PACKAGE_CERT_SHA256'
kernel_cert_sha256='REPLACE_WITH_KERNEL_CERT_SHA256'

test "$(/usr/bin/dirname "$last_qualified")" = "$archive_parent"
test ! -L "$archive_parent"
test "$(/usr/bin/stat -c '%U:%G:%a' "$archive_parent")" = root:root:755
test -d "$last_qualified"
test ! -L "$last_qualified"
test "$(/usr/bin/stat -c '%U:%G' "$last_qualified")" = root:root
test -z "$(/usr/bin/find "$last_qualified" \
  \( ! -user root -o ! -group root \) -print -quit)"
test -z "$(/usr/bin/find "$last_qualified" -perm /222 -print -quit)"
test ! -e "$recheck_dir"
umask 077
/usr/bin/install -d -m 0700 "$recheck_dir"
/usr/bin/git bundle verify "$last_qualified/verifier-source.bundle"
/usr/bin/git clone --no-checkout "$last_qualified/verifier-source.bundle" \
  "$recheck_dir/verifier"
/usr/bin/git -C "$recheck_dir/verifier" checkout --detach \
  "$(/usr/bin/cat "$last_qualified/verifier-commit")"
"$recheck_dir/verifier/scripts/verify-package-provenance" \
  --artifacts "$last_qualified/build-output" \
  --module-cert "$last_qualified/module-signing-certificate.der" \
  --module-cert-sha256 "$module_cert_sha256" \
  --package-cert "$last_qualified/package-signing-certificate.pem" \
  --package-cert-sha256 "$package_cert_sha256" \
  --kernel-cert "$last_qualified/enrolled-image-signing-certificate.pem" \
  --kernel-cert-sha256 "$kernel_cert_sha256" \
  --package-manifest-signature "$last_qualified/package-set-manifest.p7s" \
  --output "$recheck_dir/package-provenance-v1.json"
/usr/bin/cmp "$last_qualified/package-provenance-v1.json" \
  "$recheck_dir/package-provenance-v1.json"
/usr/bin/python3 -I - "$last_qualified" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
provenance = json.loads((root / "package-provenance-v1.json").read_text())
qualification = json.loads((root / "qualification.json").read_text())
policy_sha256 = hashlib.sha256((root / "protected-policy.toml").read_bytes()).hexdigest()
assert policy_sha256 == qualification["protected_policy_sha256"]
qualified_kernel = qualification["compatibility"]["kernel"]
for field in ("release", "package", "image_sha256", "image_signer_fingerprint"):
    assert qualified_kernel[field] == provenance["kernel"][field]
PY
archived_controller="$last_qualified/pt31553-fan-control.pkg.tar.zst"
archived_controller_signature="$last_qualified/pt31553-fan-control.pkg.tar.zst.sig"
test "$(/usr/bin/sha256sum "$archived_controller" | /usr/bin/awk '{print $1}')" = \
  "$(/usr/bin/cat "$last_qualified/controller-package.sha256")"
/usr/bin/pacman-key --verify "$archived_controller_signature" "$archived_controller"
validator_recheck=$(/usr/bin/mktemp)
/usr/bin/bsdtar -xOf "$archived_controller" \
  usr/bin/pt31553-fan-qualify >"$validator_recheck"
/usr/bin/cmp "$validator_recheck" "$last_qualified/pt31553-fan-qualify"
/usr/bin/rm -f -- "$validator_recheck"
test -x "$last_qualified/pt31553-fan-qualify"
"$last_qualified/pt31553-fan-qualify" validate-records \
  --qualification-record "$last_qualified/qualification.json" \
  --evidence "$last_qualified/supervised-endurance.json" \
  --authorized-evidence-path \
    /var/lib/pt31553-fan-control/evidence/supervised-endurance.json
archived_controller_version=$(/usr/bin/pacman -Qp "$archived_controller")
installed_controller_version=$(/usr/bin/pacman -Q pt31553-fan-control 2>/dev/null || true)
if test -n "$installed_controller_version"; then
  test -x /usr/bin/pt31553-fan-restore
  for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
    /usr/bin/systemctl cat "$unit" >/dev/null
    test "$(/usr/bin/systemctl is-enabled "$unit")" = disabled
    test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
  done
  sudo /usr/bin/pt31553-fan-restore --restore
fi
if test "$installed_controller_version" != "$archived_controller_version"; then
  sudo /usr/bin/pacman -U "$archived_controller"
fi
test "$(/usr/bin/pacman -Q pt31553-fan-control)" = "$archived_controller_version"
sudo /usr/bin/cmp "$protected_policy" "$last_qualified/protected-policy.toml" || {
  /usr/bin/printf '%s\n' \
    "protected policy drifted; restore $last_qualified/protected-policy.toml" >&2
  exit 1
}
test -x /usr/bin/pt31553-fan-restore
test -x /usr/bin/pt31553-fan-qualify
for unit in pt31553-fand.service pt31553-fan-sleep-guard.service; do
  /usr/bin/systemctl cat "$unit" >/dev/null
  test "$(/usr/bin/systemctl is-enabled "$unit")" = disabled
  test "$(/usr/bin/systemctl is-active "$unit" || true)" = inactive
done
```

An upgrade with the same package names may replace the installed candidate,
but it must not delete the last-qualified artifacts; they remain available for
reinstallation from a stock boot. Retire them only after the successor is
formally qualified.

## Project boundary

This project is limited to safe fan-control qualification for the exact Acer Predator PT315-53 on CachyOS through the standard in-tree `acer_wmi`/Acer hwmon interface. GUI work, other laptop models, other distributions, bypass backends, and unrelated system tuning are out of scope. See [CONTRIBUTING.md](CONTRIBUTING.md) for the required exact-model evidence.

Original repository work is [MIT-licensed](LICENSE). Linux-derived material remains `GPL-2.0-only`; see [LICENSING.md](LICENSING.md) for the boundary and provenance rules. Report vulnerabilities, unsafe fan behavior, and sensitive qualification evidence privately according to [SECURITY.md](SECURITY.md).
