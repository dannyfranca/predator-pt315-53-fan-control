use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
const SOURCE_COMMIT: &str = "aa7fe554205b70a4ec82ba8bacf9f8f0acf5f8c7";
const PACKAGING_COMMIT: &str = "ea72ae346038d296c9d7a7d72182bb4ff8454185";
const FINGERPRINT: &str = "1AF3BEC935AE677B74C784E317EC5F5A8D86CD19";

struct Input {
    name: &'static str,
    kind: &'static str,
    path: String,
    origin: String,
    revision: String,
    sha256: String,
    size: usize,
}

struct Fixture {
    root: PathBuf,
    lock: PathBuf,
    inputs: PathBuf,
    gpg: PathBuf,
    image_digest: String,
    config_hash: String,
}

impl Fixture {
    fn new() -> Self {
        Self::new_with_architecture("amd64")
    }

    fn new_with_architecture(image_architecture: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fan-control-source-lock-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let inputs = root.join("inputs");
        let bin = root.join("bin");
        fs::create_dir_all(&inputs).expect("create fixture inputs");
        fs::create_dir_all(&bin).expect("create fixture bin");

        let source_content = b"source\n";
        let source = include_bytes!("fixtures/source-lock-gpg/source.tar.gz");
        let signature = include_bytes!("fixtures/source-lock-gpg/source.tar.gz.sig");
        let key = include_bytes!("fixtures/source-lock-gpg/release-key.gpg");
        let config = b"CONFIG_TEST=y\n";
        fs::write(inputs.join("source.tar.gz"), source).expect("write source archive");
        fs::write(inputs.join("source.tar.gz.asc"), signature).expect("write signature");
        fs::write(inputs.join("release-key.gpg"), key).expect("write key");
        fs::write(inputs.join("config"), config).expect("write config");

        let source_commit = include_bytes!("fixtures/source-lock-gpg/source.commit");
        let packaging_commit = include_bytes!("fixtures/source-lock-gpg/packaging.commit");
        assert_eq!(git_object_id("commit", source_commit), SOURCE_COMMIT);
        assert_eq!(git_object_id("commit", packaging_commit), PACKAGING_COMMIT);
        fs::write(inputs.join("source.commit"), source_commit).expect("write source commit");
        fs::write(inputs.join("packaging.commit"), packaging_commit)
            .expect("write packaging commit");

        let tag = include_bytes!("fixtures/source-lock-gpg/release.tag");
        let tag_object = git_object_id("tag", tag);
        fs::write(inputs.join("release.tag"), tag).expect("write release tag");

        let archive_root = root
            .join("archive")
            .join(format!("linux-cachyos-{PACKAGING_COMMIT}"))
            .join("linux-cachyos");
        fs::create_dir_all(&archive_root).expect("create archive tree");
        fs::write(archive_root.join("config"), config).expect("write archive config");
        let recipe = format!(
            r#"_major=7.1
_minor=8
_tagrel=1
_srcname=cachyos-${{_major}}.${{_minor}}-${{_tagrel}}
arch=('x86_64')
source=(
    "https://github.com/CachyOS/linux/releases/download/${{_srcname}}/${{_srcname}}.tar.gz"{{,.asc}}
    "config"
)
validpgpkeys=(
  {FINGERPRINT}
)
"#
        );
        fs::write(archive_root.join("PKGBUILD"), &recipe).expect("write fixture recipe");
        let packaging = inputs.join("packaging.tar.gz");
        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&packaging)
            .arg("-C")
            .arg(root.join("archive"))
            .arg(format!("linux-cachyos-{PACKAGING_COMMIT}"))
            .status()
            .expect("create packaging archive");
        assert!(status.success());

        let config_blob =
            format!(r#"{{"architecture":"{image_architecture}","os":"linux"}}"#).into_bytes();
        let layer_blob = b"oci-layer";
        let config_digest = sha(&config_blob);
        let layer_digest = sha(layer_blob);
        let toolchain = format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {{
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "size": {},
    "digest": "sha256:{config_digest}"
  }},
  "layers": [{{
    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "size": {},
    "digest": "sha256:{layer_digest}"
  }}]
}}"#,
            config_blob.len(),
            layer_blob.len()
        );
        let image_digest = sha(toolchain.as_bytes());
        fs::write(inputs.join("toolchain.json"), &toolchain).expect("write toolchain manifest");
        let blob_root = inputs.join("oci/blobs/sha256");
        fs::create_dir_all(&blob_root).expect("create OCI blob directory");
        fs::write(blob_root.join(&config_digest), &config_blob).expect("write OCI config blob");
        fs::write(blob_root.join(&layer_digest), layer_blob).expect("write OCI layer blob");

        let environment = format!(
            r#"format = 1
candidate = "test-candidate"
architecture = "x86_64"
cpu_target = "x86-64-v4"
source_date_epoch = 1787723651
clean_chroot = true
pkgbase = "linux-cachyos-gcc"
cachy_config = true
cpu_scheduler = "cachyos"
makenconfig = false
makexconfig = false
localmodcfg = false
use_current = false
cc_harder = true
performance_governor = false
tcp_bbr3 = false
hz_ticks = 1000
tickrate = "full"
preempt = "full"
hugepage = "always"
build_nvidia_open = false
build_zfs = false
build_r8125 = false
build_debug = false
autofdo = false
propeller = false
use_llvm_lto = "none"
processor_opt = "generic_v4"
sync_database = false
toolchain_image_digest = "{image_digest}"
makepkg_config = "makepkg.conf"
build_wrapper = "build-candidate"
build_inputs = ["build-wrapper", "kernel-config", "kernel-source", "makepkg-config", "packaging-snapshot", "toolchain-blob-00", "toolchain-blob-01", "toolchain-image"]
patches = []
"#
        );
        fs::write(inputs.join("build-environment.toml"), &environment)
            .expect("write build environment");
        let makepkg = b"CARCH=\"x86_64\"\n";
        fs::write(inputs.join("makepkg.conf"), makepkg).expect("write makepkg config");
        let wrapper = build_wrapper(&image_digest);
        fs::write(inputs.join("build-candidate"), &wrapper).expect("write build wrapper");

        let packaging_bytes = fs::read(&packaging).expect("read packaging archive");
        let config_hash = sha(config);
        let source_tree = tree_id(&[("100644", "README", &git_object_id("blob", source_content))]);
        let packaging_inner = tree_id(&[
            (
                "100644",
                "PKGBUILD",
                &git_object_id("blob", recipe.as_bytes()),
            ),
            ("100644", "config", &git_object_id("blob", config)),
        ]);
        let packaging_tree = tree_id(&[("40000", "linux-cachyos", &packaging_inner)]);
        let definitions = [
            input(
                "kernel-source",
                "kernel-source",
                "source.tar.gz",
                "https://example.invalid/cachyos-7.1.8-1/source.tar.gz",
                SOURCE_COMMIT,
                source,
            ),
            input(
                "kernel-signature",
                "kernel-signature",
                "source.tar.gz.asc",
                "https://example.invalid/cachyos-7.1.8-1/source.tar.gz.asc",
                SOURCE_COMMIT,
                signature,
            ),
            input(
                "source-commit",
                "source-commit",
                "source.commit",
                &format!("https://example.invalid/commits/{SOURCE_COMMIT}"),
                SOURCE_COMMIT,
                source_commit,
            ),
            input(
                "release-tag",
                "release-tag",
                "release.tag",
                &format!("https://example.invalid/tags/{tag_object}"),
                &tag_object,
                tag,
            ),
            input(
                "signer-key",
                "signer-key",
                "release-key.gpg",
                "https://example.invalid/keys/release-key.gpg",
                &sha(key),
                key,
            ),
            input(
                "packaging-snapshot",
                "packaging",
                "packaging.tar.gz",
                &format!("https://example.invalid/{PACKAGING_COMMIT}/packaging.tar.gz"),
                PACKAGING_COMMIT,
                &packaging_bytes,
            ),
            input(
                "packaging-commit",
                "packaging-commit",
                "packaging.commit",
                &format!("https://example.invalid/commits/{PACKAGING_COMMIT}"),
                PACKAGING_COMMIT,
                packaging_commit,
            ),
            input(
                "kernel-config",
                "kernel-config",
                "config",
                &format!("https://example.invalid/{PACKAGING_COMMIT}/config"),
                PACKAGING_COMMIT,
                config,
            ),
            input(
                "build-environment",
                "build-environment",
                "build-environment.toml",
                "repository:packaging/kernel/build-environment.toml",
                &sha(environment.as_bytes()),
                environment.as_bytes(),
            ),
            input(
                "build-wrapper",
                "build-wrapper",
                "build-candidate",
                "repository:packaging/kernel/build-candidate",
                &sha(wrapper.as_bytes()),
                wrapper.as_bytes(),
            ),
            input(
                "makepkg-config",
                "makepkg-config",
                "makepkg.conf",
                "repository:packaging/kernel/makepkg.conf",
                &sha(makepkg),
                makepkg,
            ),
            input(
                "toolchain-image",
                "toolchain-image",
                "toolchain.json",
                &format!("oci://example.invalid/toolchain@sha256:{image_digest}"),
                &image_digest,
                toolchain.as_bytes(),
            ),
            input(
                "toolchain-blob-00",
                "toolchain-blob",
                &format!("oci/blobs/sha256/{config_digest}"),
                &format!("https://example.invalid/blobs/{config_digest}"),
                &config_digest,
                &config_blob,
            ),
            input(
                "toolchain-blob-01",
                "toolchain-blob",
                &format!("oci/blobs/sha256/{layer_digest}"),
                &format!("https://example.invalid/blobs/{layer_digest}"),
                &layer_digest,
                layer_blob,
            ),
        ];
        let tables = definitions.iter().map(input_table).collect::<String>();
        let lock = root.join("source-lock.toml");
        fs::write(
            &lock,
            format!(
                r#"format = 1
candidate = "test-candidate"
release_tag = "cachyos-7.1.8-1"
source_commit = "{SOURCE_COMMIT}"
source_tree = "{source_tree}"
tag_object = "{tag_object}"
tag_signer_fingerprint = "{FINGERPRINT}"
packaging_commit = "{PACKAGING_COMMIT}"
packaging_tree = "{packaging_tree}"
source_date_epoch = 1787723651
signature_verification_epoch = 1787728099
cpu_target = "x86-64-v4"
toolchain_image_digest = "{image_digest}"
patches = []
{tables}"#
            ),
        )
        .expect("write fixture lock");

        let gpg = bin.join("gpg");
        fs::write(
            &gpg,
            format!("#!/bin/sh\necho \"[GNUPG:] VALIDSIG {FINGERPRINT} verified\"\n"),
        )
        .expect("write mock gpg");
        #[cfg(unix)]
        fs::set_permissions(&gpg, fs::Permissions::from_mode(0o755)).expect("make mock executable");

        Self {
            root,
            lock,
            inputs,
            gpg,
            image_digest,
            config_hash,
        }
    }

    fn verify(&self) -> Output {
        self.command().output().expect("run source-lock verifier")
    }

    fn command(&self) -> Command {
        let path = format!(
            "{}:{}",
            self.gpg.parent().expect("mock bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("python3");
        command
            .arg(verifier())
            .arg("--lock")
            .arg(&self.lock)
            .arg("--inputs")
            .arg(&self.inputs)
            .env("PATH", path);
        command
    }

    fn execute_verified(&self, capture: &Path) -> Output {
        let mut command = self.command();
        command
            .arg("--exec-verified")
            .env("SOURCE_LOCK_OUTPUT", capture);
        command.output().expect("run verified build handoff")
    }

    fn replace_lock(&self, from: &str, to: &str) {
        let content = fs::read_to_string(&self.lock)
            .expect("read lock")
            .replace(from, to);
        fs::write(&self.lock, content).expect("rewrite lock");
    }

    fn input_snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut files = Vec::new();
        snapshot_tree(&self.inputs, &self.inputs, &mut files);
        files.sort_by(|left, right| left.0.cmp(&right.0));
        files
    }

    #[cfg(unix)]
    fn make_read_only(&self) {
        set_tree_modes(&self.inputs, 0o555, 0o444);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            restore_tree_modes(&self.inputs);
            let _ =
                fs::set_permissions(self.root.join("outside"), fs::Permissions::from_mode(0o755));
        }
        fs::remove_dir_all(&self.root).expect("remove fixture directory");
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn snapshot_tree(base: &Path, current: &Path, output: &mut Vec<(String, Vec<u8>)>) {
    for entry in fs::read_dir(current).expect("read input tree") {
        let entry = entry.expect("read input entry");
        if entry.file_type().expect("input type").is_dir() {
            snapshot_tree(base, &entry.path(), output);
        } else {
            output.push((
                entry
                    .path()
                    .strip_prefix(base)
                    .expect("relative input")
                    .to_string_lossy()
                    .into_owned(),
                fs::read(entry.path()).expect("read input"),
            ));
        }
    }
}

#[cfg(unix)]
fn set_tree_modes(path: &Path, directory_mode: u32, file_mode: u32) {
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("read tree") {
            set_tree_modes(
                &entry.expect("read tree entry").path(),
                directory_mode,
                file_mode,
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("set directory mode");
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode)).expect("set file mode");
    }
}

#[cfg(unix)]
fn restore_tree_modes(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    if metadata.is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                restore_tree_modes(&entry.path());
            }
        }
    } else {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
    }
}

fn git_object_id(kind: &str, bytes: &[u8]) -> String {
    let mut child = Command::new("python3")
        .args([
            "-c",
            "import hashlib,sys; b=sys.stdin.buffer.read(); print(hashlib.sha1(sys.argv[1].encode()+b' '+str(len(b)).encode()+b'\\0'+b).hexdigest())",
            kind,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start Git object hash helper");
    child
        .stdin
        .take()
        .expect("hash helper stdin")
        .write_all(bytes)
        .expect("write Git object");
    let output = child
        .wait_with_output()
        .expect("finish Git object hash helper");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("hash output")
        .trim()
        .to_owned()
}

fn tree_id(entries: &[(&str, &str, &str)]) -> String {
    let mut content = Vec::new();
    for (mode, name, object_id) in entries {
        content.extend_from_slice(mode.as_bytes());
        content.push(b' ');
        content.extend_from_slice(name.as_bytes());
        content.push(0);
        for pair in object_id.as_bytes().chunks_exact(2) {
            let pair = std::str::from_utf8(pair).expect("hex object ID");
            content.push(u8::from_str_radix(pair, 16).expect("hex object ID"));
        }
    }
    git_object_id("tree", &content)
}

fn build_wrapper(image_digest: &str) -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

: "${SOURCE_LOCK_BUNDLE:?set SOURCE_LOCK_BUNDLE to the verified bundle directory}"
if (( $# > 1 )); then
    exit 2
elif (( $# == 1 )) && [[ "$1" != --verifysource ]]; then
    exit 2
fi

if [[ ! -d "${SOURCE_LOCK_OUTPUT:-}" ]]; then
    [[ -z "${SOURCE_LOCK_ORIGINAL_BUNDLE:-}" ]] || exit 91
    cp "$SOURCE_LOCK_BUNDLE/makepkg.conf" "$SOURCE_LOCK_OUTPUT"
    exit 0
fi

toolchain_origin="docker.io/cachyos/docker-makepkg-v4@sha256:{IMAGE_DIGEST}"
toolchain="docker.io/library/source-lock@sha256:{IMAGE_DIGEST}"
packaging="packaging.tar.gz"
unset CI GITHUB_RUN_ID
export SOURCE_DATE_EPOCH=1787723651
export SRCDEST=/work/source-cache
export PKGDEST=$SOURCE_LOCK_OUTPUT
export _cachy_config=yes
export _cpusched=cachyos
export _makenconfig=no
export _makexconfig=no
export _localmodcfg=no
export _use_current=no
export _cc_harder=yes
export _per_gov=no
export _tcp_bbr3=no
export _HZ_ticks=1000
export _tickrate=full
export _preempt=full
export _hugepage=always
export _processor_opt=generic_v4
export _use_llvm_lto=none
export _use_lto_suffix=no
export _use_gcc_suffix=yes
export _use_kcfi=no
export _build_zfs=no
export _build_nvidia_open=no
export _build_r8125=no
export _build_debug=no
export _autofdo=no
export _propeller=no

ln -s /bundle/cachyos-7.1.8-1.tar.gz "$package_root/source-cache/cachyos-7.1.8-1.tar.gz"
ln -s /bundle/config "$package_root/source-cache/config"
podman_storage=(--root "$work_root/podman-root" --runroot "$work_root/podman-runroot" --storage-driver=overlay)
podman "${podman_storage[@]}" pull --quiet "oci:$image_layout:source-lock"
podman "${podman_storage[@]}" run --rm --pull=never --network=none --read-only --userns=keep-id:uid=1000,gid=1000 --entrypoint /bundle/build-candidate "$toolchain"
exec makepkg --config "$SOURCE_LOCK_BUNDLE/makepkg.conf" --skippgpcheck --skipchecksums --noconfirm --cleanbuild "$@"
"#
    .replace("{IMAGE_DIGEST}", image_digest)
}

fn input(
    name: &'static str,
    kind: &'static str,
    path: &str,
    origin: &str,
    revision: &str,
    content: &[u8],
) -> Input {
    Input {
        name,
        kind,
        path: path.to_owned(),
        origin: origin.to_owned(),
        revision: revision.to_owned(),
        sha256: sha(content),
        size: content.len(),
    }
}

fn input_table(input: &Input) -> String {
    format!(
        r#"
[[inputs]]
name = "{}"
kind = "{}"
path = "{}"
origin = "{}"
revision = "{}"
sha256 = "{}"
size = {}
"#,
        input.name, input.kind, input.path, input.origin, input.revision, input.sha256, input.size
    )
}

fn verifier() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/verify-source-lock")
}

fn failure_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[cfg(unix)]
#[test]
fn accepts_a_complete_read_only_bundle_without_modifying_it() {
    let fixture = Fixture::new();
    let before = fixture.input_snapshot();
    fixture.make_read_only();

    let output = fixture.verify();

    assert!(output.status.success(), "{}", failure_text(&output));
    assert_eq!(before, fixture.input_snapshot());
    assert!(String::from_utf8_lossy(&output.stdout).contains("14 immutable inputs"));
}

#[cfg(unix)]
#[test]
fn checked_in_executor_builds_through_the_offline_fake_podman_boundary() {
    let root = std::env::temp_dir().join(format!(
        "fan-control-checked-in-executor-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let bundle = root.join("bundle");
    let output = root.join("output");
    let bin = root.join("bin");
    let archive_root = root
        .join("archive")
        .join("linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f")
        .join("linux-cachyos");
    fs::create_dir_all(bundle.join("oci/blobs/sha256")).expect("create bundle OCI tree");
    fs::create_dir_all(&output).expect("create output directory");
    fs::create_dir_all(&bin).expect("create fake command directory");
    fs::create_dir_all(&archive_root).expect("create packaging tree");
    fs::write(archive_root.join("PKGBUILD"), "pkgname=test\n").expect("write PKGBUILD");
    let packaging = bundle.join("linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f.tar.gz");
    let archive_status = Command::new("tar")
        .args(["-czf"])
        .arg(&packaging)
        .arg("-C")
        .arg(root.join("archive"))
        .arg("linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f")
        .status()
        .expect("create executor packaging archive");
    assert!(archive_status.success());
    for (path, content) in [
        ("cachyos-7.1.8-1.tar.gz", "source"),
        ("cachyos-7.1.8-1.tar.gz.asc", "signature"),
        ("config", "CONFIG_TEST=y\n"),
        ("makepkg.conf", "CARCH=x86_64\n"),
        ("toolchain-image-manifest.json", "{}"),
        ("oci/blobs/sha256/test-blob", "blob"),
    ] {
        fs::write(bundle.join(path), content).expect("write executor bundle input");
    }

    let podman_log = root.join("podman.log");
    let makepkg_log = root.join("makepkg.log");
    let wrapper =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/kernel/build-candidate");
    let fake_podman = bin.join("podman");
    fs::write(
        &fake_podman,
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$TEST_PODMAN_LOG"
args=" $* "
if [[ "$args" == *" unshare chmod "* ]]; then
    exit 0
fi
if [[ "$args" == *" unshare rm -rf -- "* ]]; then
    /usr/bin/rm -rf -- "${@: -1}"
    exit 0
fi
if [[ "$args" == *" pull --quiet oci:"* ]]; then
    exit 0
fi
if [[ "$args" == *" run --rm --pull=never --network=none --read-only "* ]]; then
    env -i PATH="$TEST_BIN:/usr/bin:/bin" \
        SOURCE_LOCK_INSIDE=1 \
        SOURCE_LOCK_BUNDLE="$TEST_BUNDLE" \
        SOURCE_LOCK_OUTPUT="$TEST_OUTPUT" \
        TEST_MAKEPKG_LOG="$TEST_MAKEPKG_LOG" \
        /bin/bash "$TEST_WRAPPER" --verifysource
    exit $?
fi
exit 97
"#,
    )
    .expect("write fake podman");
    let fake_makepkg = bin.join("makepkg");
    fs::write(
        &fake_makepkg,
        r#"#!/usr/bin/env bash
set -euo pipefail
printf 'args=%s\n' "$*" >"$TEST_MAKEPKG_LOG"
env | /usr/bin/sort >>"$TEST_MAKEPKG_LOG"
"#,
    )
    .expect("write fake makepkg");
    fs::set_permissions(&fake_podman, fs::Permissions::from_mode(0o755))
        .expect("make fake podman executable");
    fs::set_permissions(&fake_makepkg, fs::Permissions::from_mode(0o755))
        .expect("make fake makepkg executable");

    let path = format!("{}:/usr/bin:/bin", bin.display());
    let run = Command::new("/bin/bash")
        .arg(&wrapper)
        .arg("--verifysource")
        .env("PATH", &path)
        .env("SOURCE_LOCK_BUNDLE", &bundle)
        .env("SOURCE_LOCK_OUTPUT", &output)
        .env("TEST_BIN", &bin)
        .env("TEST_BUNDLE", &bundle)
        .env("TEST_OUTPUT", &output)
        .env("TEST_WRAPPER", &wrapper)
        .env("TEST_PODMAN_LOG", &podman_log)
        .env("TEST_MAKEPKG_LOG", &makepkg_log)
        .output()
        .expect("run checked-in executor");
    assert!(run.status.success(), "{}", failure_text(&run));

    let podman = fs::read_to_string(&podman_log).expect("read fake podman log");
    assert!(podman.contains("--storage-driver=overlay pull --quiet oci:"));
    assert!(podman.contains("run --rm --pull=never --network=none --read-only"));
    assert!(podman.contains("--mount type=bind"));
    assert!(podman.contains("dst=/bundle,ro=true"));
    assert!(podman.contains("--entrypoint /bundle/build-candidate"));
    let makepkg = fs::read_to_string(&makepkg_log).expect("read fake makepkg log");
    assert!(
        makepkg.contains("--skippgpcheck --skipchecksums --noconfirm --cleanbuild --verifysource")
    );
    assert!(makepkg.contains("SOURCE_DATE_EPOCH=1786378335"));
    assert!(makepkg.contains("_processor_opt=generic_v4"));
    assert!(makepkg.contains("_cpusched=cachyos"));

    let missing_output = root.join("missing-output");
    let rejected = Command::new("/bin/bash")
        .arg(&wrapper)
        .env("PATH", &path)
        .env("SOURCE_LOCK_BUNDLE", &bundle)
        .env("SOURCE_LOCK_OUTPUT", &missing_output)
        .output()
        .expect("run executor without output directory");
    assert!(!rejected.status.success());
    assert!(failure_text(&rejected).contains("must be a non-symlink directory"));

    fs::remove_dir_all(&root).expect("remove actual executor fixture");
}

#[test]
fn rejects_missing_changed_and_unrecorded_inputs() {
    let missing = Fixture::new();
    fs::remove_file(missing.inputs.join("source.tar.gz")).expect("remove input");
    assert!(failure_text(&missing.verify()).contains("missing input"));

    let changed = Fixture::new();
    let path = changed.inputs.join("source.tar.gz");
    let mut bytes = fs::read(&path).expect("read input");
    bytes[0] ^= 1;
    fs::write(path, bytes).expect("change input");
    assert!(failure_text(&changed.verify()).contains("SHA-256 changed"));

    let extra = Fixture::new();
    fs::write(extra.inputs.join("surprise"), b"extra").expect("add extra input");
    assert!(failure_text(&extra.verify()).contains("unrecorded input"));

    let extra_directory = Fixture::new();
    let path = extra_directory.inputs.join("unrecorded-empty-directory");
    fs::create_dir(&path).expect("add extra directory");
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o555))
        .expect("make extra directory read-only");
    assert!(failure_text(&extra_directory.verify()).contains("unrecorded directory"));
}

#[test]
fn rejects_floating_origins_unrecorded_fields_and_wrong_kind_bindings() {
    let floating = Fixture::new();
    floating.replace_lock(
        "https://example.invalid/cachyos-7.1.8-1/source.tar.gz",
        "https://example.invalid/latest/source.tar.gz",
    );
    assert!(failure_text(&floating.verify()).contains("floating origin"));

    let unrecorded = Fixture::new();
    unrecorded.replace_lock("format = 1", "format = 1\nunknown = true");
    assert!(failure_text(&unrecorded.verify()).contains("unrecorded field"));

    let wrong_kind = Fixture::new();
    wrong_kind.replace_lock("kind = \"makepkg-config\"", "kind = \"kernel-source\"");
    assert!(failure_text(&wrong_kind.verify()).contains("identity required for kind"));
}

#[test]
fn rejects_duplicate_malformed_and_incomplete_manifests() {
    let duplicate = Fixture::new();
    duplicate.replace_lock("name = \"makepkg-config\"", "name = \"kernel-source\"");
    assert!(failure_text(&duplicate.verify()).contains("unique stable identifier"));

    let malformed = Fixture::new();
    malformed.replace_lock("patches = []", "patches = []\n[");
    assert!(failure_text(&malformed.verify()).contains("invalid TOML"));

    let incomplete = Fixture::new();
    incomplete.replace_lock("cpu_target = \"x86-64-v4\"\n", "");
    assert!(failure_text(&incomplete.verify()).contains("missing field"));
}

#[test]
fn rejects_patch_inputs_not_exactly_listed_by_the_patch_set() {
    let fixture = Fixture::new();
    let patch = b"diff --git a/a b/a\n";
    fs::write(fixture.inputs.join("fixture.patch"), patch).expect("write patch input");
    let record = input(
        "fixture-patch",
        "patch",
        "fixture.patch",
        "repository:patches/fixture.patch",
        &sha(patch),
        patch,
    );
    let lock = fs::read_to_string(&fixture.lock).expect("read lock");
    fs::write(&fixture.lock, format!("{lock}{}", input_table(&record)))
        .expect("append patch record");

    assert!(failure_text(&fixture.verify()).contains("must exactly list sorted patch input names"));
}

#[cfg(unix)]
#[test]
fn rejects_a_non_empty_patch_set_until_staging_is_defined() {
    let fixture = Fixture::new();
    let patch = b"diff --git a/a b/a\n";
    fs::write(fixture.inputs.join("fixture.patch"), patch).expect("write patch input");
    let record = input(
        "fixture-patch",
        "patch",
        "fixture.patch",
        "repository:patches/fixture.patch",
        &sha(patch),
        patch,
    );
    let environment_path = fixture.inputs.join("build-environment.toml");
    let before = fs::read_to_string(&environment_path).expect("read build environment");
    let after = before
        .replace(
            "build_inputs = [\"build-wrapper\"",
            "build_inputs = [\"build-wrapper\", \"fixture-patch\"",
        )
        .replace("patches = []", "patches = [\"fixture-patch\"]");
    fs::write(&environment_path, &after).expect("write patched build environment");
    fixture.replace_lock(
        &format!(
            "revision = \"{}\"\nsha256 = \"{}\"\nsize = {}",
            sha(before.as_bytes()),
            sha(before.as_bytes()),
            before.len()
        ),
        &format!(
            "revision = \"{}\"\nsha256 = \"{}\"\nsize = {}",
            sha(after.as_bytes()),
            sha(after.as_bytes()),
            after.len()
        ),
    );
    fixture.replace_lock("patches = []", "patches = [\"fixture-patch\"]");
    let lock = fs::read_to_string(&fixture.lock).expect("read lock");
    fs::write(&fixture.lock, format!("{lock}{}", input_table(&record)))
        .expect("append patch record");
    let output = fixture.verify();

    assert!(!output.status.success());
    assert!(failure_text(&output).contains("stage 0 requires an empty patch set"));
}

#[test]
fn rejects_invalid_signatures_and_configs_not_bound_to_packaging() {
    let signature = Fixture::new();
    let signature_path = signature.inputs.join("source.tar.gz.asc");
    let before = fs::read(&signature_path).expect("read source signature");
    let mut after = before.clone();
    after[32] ^= 1;
    fs::write(&signature_path, &after).expect("corrupt source signature");
    signature.replace_lock(&sha(&before), &sha(&after));
    assert!(failure_text(&signature.verify()).contains("source signature: gpg exited"));

    let config = Fixture::new();
    let replacement = b"CONFIG_EVIL=y\n";
    assert_eq!(replacement.len(), b"CONFIG_TEST=y\n".len());
    fs::write(config.inputs.join("config"), replacement).expect("change config");
    config.replace_lock(&config.config_hash, &sha(replacement));
    assert!(failure_text(&config.verify()).contains("does not match the pinned packaging"));

    let tree = Fixture::new();
    let lock = fs::read_to_string(&tree.lock).expect("read lock");
    let parsed: toml::Value = toml::from_str(&lock).expect("parse lock");
    let source_tree = parsed["source_tree"].as_str().expect("source tree");
    tree.replace_lock(source_tree, "0000000000000000000000000000000000000000");
    assert!(failure_text(&tree.verify()).contains("tree does not match source lock"));
}

#[cfg(unix)]
#[test]
fn uses_fixed_gpg_for_real_openpgp_material_and_rejects_wrong_tag_target() {
    let real = Fixture::new();
    let marker = real.root.join("path-gpg-ran");
    fs::write(
        &real.gpg,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
    )
    .expect("write PATH-shadowed gpg");
    fs::set_permissions(&real.gpg, fs::Permissions::from_mode(0o755))
        .expect("make shadow executable");
    real.make_read_only();
    let output = real.verify();
    assert!(output.status.success(), "{}", failure_text(&output));
    assert!(!marker.exists(), "verifier executed PATH-shadowed gpg");

    let wrong_target = Fixture::new();
    let tag_path = wrong_target.inputs.join("release.tag");
    let before = fs::read(&tag_path).expect("read tag");
    let after = String::from_utf8(before.clone())
        .expect("UTF-8 tag")
        .replace(SOURCE_COMMIT, "0000000000000000000000000000000000000000")
        .into_bytes();
    fs::write(&tag_path, &after).expect("write wrong-target tag");
    wrong_target.replace_lock(
        &git_object_id("tag", &before),
        &git_object_id("tag", &after),
    );
    wrong_target.replace_lock(&sha(&before), &sha(&after));
    assert!(failure_text(&wrong_target.verify()).contains("target commit does not match"));
}

#[test]
fn rejects_toolchain_manifest_bytes_changed_under_the_pinned_digest() {
    let fixture = Fixture::new();
    let path = fixture.inputs.join("toolchain.json");
    let content = fs::read_to_string(&path)
        .expect("read manifest")
        .replace("\"schemaVersion\": 2", "\"schemaVersion\": 3");
    let changed_digest = sha(content.as_bytes());
    fs::write(path, content).expect("change manifest");
    fixture.replace_lock(
        &format!("sha256 = \"{}\"", fixture.image_digest),
        &format!("sha256 = \"{changed_digest}\""),
    );

    let output = fixture.verify();

    assert!(!output.status.success());
    let failure = failure_text(&output);
    assert!(
        failure.contains("bytes do not match the pinned OCI manifest digest"),
        "{failure}"
    );
}

#[test]
fn rejects_a_coherent_non_amd64_toolchain_image() {
    let fixture = Fixture::new_with_architecture("arm64");
    assert!(failure_text(&fixture.verify()).contains("stage 0 requires linux/amd64"));
}

#[test]
fn rejects_build_metadata_or_wrapper_options_that_drift() {
    let signature_time = Fixture::new();
    signature_time.replace_lock(
        "signature_verification_epoch = 1787728099",
        "signature_verification_epoch = 1787728100",
    );
    assert!(failure_text(&signature_time.verify()).contains("latest authenticated signature time"));

    let timestamp = Fixture::new();
    timestamp.replace_lock(
        "source_date_epoch = 1787723651",
        "source_date_epoch = 1787723652",
    );
    assert!(
        failure_text(&timestamp.verify()).contains("does not match signed packaging commit time")
    );

    let cpu_target = Fixture::new();
    let path = cpu_target.inputs.join("build-environment.toml");
    let before = fs::read(&path).expect("read environment");
    let after = String::from_utf8(before.clone())
        .expect("UTF-8 environment")
        .replace("cpu_target = \"x86-64-v4\"", "cpu_target = \"x86-64\"");
    fs::write(&path, &after).expect("change CPU target");
    cpu_target.replace_lock(&sha(&before), &sha(after.as_bytes()));
    cpu_target.replace_lock("cpu_target = \"x86-64-v4\"", "cpu_target = \"x86-64\"");
    assert!(failure_text(&cpu_target.verify()).contains("stage 0 requires x86-64-v4"));

    let environment = Fixture::new();
    let path = environment.inputs.join("build-environment.toml");
    let before = fs::read(&path).expect("read environment");
    let after = String::from_utf8(before.clone())
        .expect("UTF-8 environment")
        .replace("build_zfs = false", "build_zfs = true ");
    fs::write(&path, &after).expect("change environment");
    environment.replace_lock(&sha(&before), &sha(after.as_bytes()));
    assert!(failure_text(&environment.verify()).contains("build environment.build_zfs"));

    let wrapper = Fixture::new();
    let path = wrapper.inputs.join("build-candidate");
    let before = fs::read(&path).expect("read wrapper");
    let after = String::from_utf8(before.clone())
        .expect("UTF-8 wrapper")
        .replace("export _build_zfs=no", "export _build_zfs=on");
    fs::write(&path, &after).expect("change wrapper");
    wrapper.replace_lock(&sha(&before), &sha(after.as_bytes()));
    assert!(failure_text(&wrapper.verify()).contains("exported PKGBUILD variables"));
}

#[test]
fn rejects_an_otherwise_valid_mutable_bundle() {
    let fixture = Fixture::new();

    assert!(failure_text(&fixture.verify()).contains("verified bundle must be read-only"));
}

#[cfg(unix)]
#[test]
fn verified_build_handoff_does_not_expose_the_original_bundle() {
    let fixture = Fixture::new();
    let expected = fs::read(fixture.inputs.join("makepkg.conf")).expect("read original input");
    let capture = fixture.root.join("captured-makepkg.conf");
    fixture.make_read_only();

    let output = fixture.execute_verified(&capture);

    assert!(output.status.success(), "{}", failure_text(&output));
    assert_eq!(fs::read(&capture).expect("read captured input"), expected);
    assert_eq!(
        fs::read(fixture.inputs.join("makepkg.conf")).expect("read original path"),
        expected
    );
}

#[cfg(unix)]
#[test]
fn verified_build_handoff_ignores_ambient_bash_hooks() {
    let fixture = Fixture::new();
    let hook = fixture.root.join("bash-env");
    let marker = fixture.root.join("hook-ran");
    fs::write(&hook, format!("touch '{}'\n", marker.display())).expect("write shell hook");
    let capture = fixture.root.join("captured-makepkg.conf");
    fixture.make_read_only();
    let mut command = fixture.command();
    let output = command
        .arg("--exec-verified")
        .env("SOURCE_LOCK_OUTPUT", &capture)
        .env("BASH_ENV", &hook)
        .output()
        .expect("run sanitized verified handoff");

    assert!(output.status.success(), "{}", failure_text(&output));
    assert!(!marker.exists(), "ambient BASH_ENV was sourced");
}

#[cfg(unix)]
#[test]
fn verified_build_handoff_rejects_unlocked_makepkg_options() {
    let fixture = Fixture::new();
    fixture.make_read_only();
    let output = fixture
        .command()
        .arg("--exec-verified")
        .arg("--")
        .arg("--sign")
        .output()
        .expect("run verified handoff with forbidden option");

    assert!(!output.status.success());
    assert!(failure_text(&output).contains("only --verifysource is allowed"));
}

#[cfg(unix)]
#[test]
fn verified_build_handoff_rejects_bytes_changed_through_a_retained_writer() {
    let fixture = Fixture::new();
    let input = fixture.inputs.join("makepkg.conf");
    let before = fs::read(&input).expect("read makepkg config");
    let mut large = before.clone();
    large.resize(128 * 1024 * 1024, b'X');
    fs::write(&input, &large).expect("write large handoff input");
    fixture.replace_lock(
        &format!(
            "revision = \"{}\"\nsha256 = \"{}\"\nsize = {}",
            sha(&before),
            sha(&before),
            before.len()
        ),
        &format!(
            "revision = \"{}\"\nsha256 = \"{}\"\nsize = {}",
            sha(&large),
            sha(&large),
            large.len()
        ),
    );
    let mut writer = OpenOptions::new()
        .write(true)
        .open(&input)
        .expect("retain writable descriptor");
    let temporary_root = fixture.root.join("handoff-temporary");
    fs::create_dir(&temporary_root).expect("create handoff temporary root");
    let capture = fixture.root.join("unexpected-capture");
    fixture.make_read_only();

    let mut command = fixture.command();
    command
        .arg("--exec-verified")
        .env("SOURCE_LOCK_OUTPUT", &capture)
        .env("TMPDIR", &temporary_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("start verified handoff");
    let mut snapshot_input = None;
    for _ in 0..2_000_000 {
        if let Ok(entries) = fs::read_dir(&temporary_root) {
            for entry in entries.flatten() {
                let candidate = entry.path().join("bundle/makepkg.conf");
                if candidate.exists() {
                    snapshot_input = Some(candidate);
                    break;
                }
            }
        }
        if snapshot_input.is_some() {
            break;
        }
        std::hint::spin_loop();
    }
    assert!(
        snapshot_input.is_some(),
        "verifier did not start the snapshot copy"
    );
    writer
        .seek(SeekFrom::Start((120 * 1024 * 1024) as u64))
        .expect("seek retained writer");
    writer
        .write_all(b"Y")
        .expect("mutate through retained writer");
    writer.flush().expect("flush retained writer");

    let output = child.wait_with_output().expect("finish verified handoff");
    assert!(!output.status.success());
    assert!(
        failure_text(&output).contains("changed during handoff"),
        "{}",
        failure_text(&output)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("source lock verified"));
}

#[cfg(unix)]
#[test]
fn rejects_direct_and_intermediate_symlinks() {
    let direct = Fixture::new();
    let source = direct.inputs.join("source.tar.gz");
    fs::remove_file(&source).expect("remove source");
    symlink(direct.inputs.join("source.tar.gz.asc"), source).expect("link source");
    assert!(failure_text(&direct.verify()).contains("symlinked input"));

    let intermediate = Fixture::new();
    let outside = intermediate.root.join("outside");
    fs::create_dir(&outside).expect("create outside directory");
    fs::rename(
        intermediate.inputs.join("source.tar.gz"),
        outside.join("source.tar.gz"),
    )
    .expect("move source");
    symlink(&outside, intermediate.inputs.join("nested")).expect("link directory");
    intermediate.replace_lock(
        "path = \"source.tar.gz\"",
        "path = \"nested/source.tar.gz\"",
    );
    assert!(failure_text(&intermediate.verify()).contains("symlinked input"));

    let hard_link = Fixture::new();
    fs::remove_file(hard_link.inputs.join("makepkg.conf")).expect("remove makepkg input");
    fs::hard_link(
        hard_link.inputs.join("source.tar.gz"),
        hard_link.inputs.join("makepkg.conf"),
    )
    .expect("hard-link inputs");
    assert!(failure_text(&hard_link.verify()).contains("hard-linked input"));

    let external_hard_link = Fixture::new();
    let outside = external_hard_link.root.join("outside-link");
    fs::hard_link(external_hard_link.inputs.join("makepkg.conf"), outside)
        .expect("create external hard link");
    assert!(failure_text(&external_hard_link.verify()).contains("hard-linked input"));
}

#[test]
fn checked_in_lock_records_every_input_class_and_raw_oci_identity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/kernel");
    let lock = fs::read_to_string(root.join("source-lock.toml")).expect("read checked-in lock");
    assert!(!lock.contains("REPLACE_"));
    for kind in [
        "kernel-source",
        "kernel-signature",
        "source-commit",
        "release-tag",
        "signer-key",
        "packaging",
        "packaging-commit",
        "kernel-config",
        "build-environment",
        "build-wrapper",
        "makepkg-config",
        "toolchain-image",
        "toolchain-blob",
    ] {
        assert!(lock.contains(&format!("kind = \"{kind}\"")));
    }

    let manifest = fs::read(root.join("toolchain-image-manifest.json")).expect("read OCI manifest");
    assert_ne!(
        manifest.last(),
        Some(&b'\n'),
        "raw OCI bytes must not be normalized"
    );
    let digest = sha(&manifest);
    assert!(lock.contains(&format!("toolchain_image_digest = \"{digest}\"")));
    assert!(lock.contains("patches = []"));

    let parsed: toml::Value = toml::from_str(&lock).expect("parse checked-in lock");
    let inputs = parsed["inputs"].as_array().expect("lock inputs");
    for (name, path) in [
        ("source-commit", root.join("cachyos-7.1.8-1.commit")),
        ("release-tag", root.join("cachyos-7.1.8-1.tag")),
        (
            "packaging-commit",
            root.join("linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f.commit"),
        ),
        ("signer-key", root.join("trust/cachyos-release-key.gpg")),
        ("build-environment", root.join("build-environment.toml")),
        ("build-wrapper", root.join("build-candidate")),
        ("makepkg-config", root.join("makepkg.conf")),
        (
            "toolchain-image",
            root.join("toolchain-image-manifest.json"),
        ),
    ] {
        let record = inputs
            .iter()
            .find(|input| input["name"].as_str() == Some(name))
            .expect("local artifact input record");
        let bytes = fs::read(path).expect("read local locked artifact");
        let digest = sha(&bytes);
        assert_eq!(record["sha256"].as_str(), Some(digest.as_str()));
        assert_eq!(record["size"].as_integer(), Some(bytes.len() as i64));
    }

    for (path, commit_field, tree_field) in [
        (
            root.join("cachyos-7.1.8-1.commit"),
            "source_commit",
            "source_tree",
        ),
        (
            root.join("linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f.commit"),
            "packaging_commit",
            "packaging_tree",
        ),
    ] {
        let commit = fs::read(path).expect("read checked-in commit object");
        assert_eq!(
            git_object_id("commit", &commit),
            parsed[commit_field].as_str().expect("locked commit ID")
        );
        assert_eq!(
            commit.split(|byte| *byte == b'\n').next(),
            Some(
                format!(
                    "tree {}",
                    parsed[tree_field].as_str().expect("locked tree ID")
                )
                .as_bytes()
            )
        );
    }

    let tag = fs::read(root.join("cachyos-7.1.8-1.tag")).expect("read checked-in tag");
    assert_eq!(
        git_object_id("tag", &tag),
        parsed["tag_object"].as_str().expect("locked tag ID")
    );
    let expected_tag_headers = format!(
        "object {}\ntype commit\ntag {}\n",
        parsed["source_commit"]
            .as_str()
            .expect("locked source commit"),
        parsed["release_tag"].as_str().expect("locked release tag")
    );
    assert!(tag.starts_with(expected_tag_headers.as_bytes()));
}
