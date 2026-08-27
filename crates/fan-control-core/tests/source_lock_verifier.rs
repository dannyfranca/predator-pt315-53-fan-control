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
candidate = "linux-cachyos-gcc-7.1.8-stage-0"
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
candidate = "linux-cachyos-gcc-7.1.8-stage-0"
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

fn pinned_acer_wmi_contexts() -> Vec<u8> {
    let mut lines = (1..=680)
        .map(|line| format!("/* pinned fixture line {line} */\n"))
        .collect::<Vec<_>>();
    for (line, content) in [
        (482, "\t.pwm = 1,\n"),
        (483, "};\n"),
        (484, "\n"),
        (
            485,
            "static struct quirk_entry quirk_acer_predator_v4 = {\n",
        ),
        (486, "\t.predator_v4 = 1,\n"),
        (487, "};\n"),
        (671, "\t\t},\n"),
        (672, "\t\t.driver_data = &quirk_acer_predator_ph315_53,\n"),
        (673, "\t},\n"),
        (674, "\t{\n"),
        (675, "\t\t.callback = dmi_matched,\n"),
        (676, "\t\t.ident = \"Acer Predator PHN16-71\",\n"),
    ] {
        lines[line - 1] = content.to_owned();
    }
    lines.concat().into_bytes()
}

fn validate_telemetry_patch(patch: &[u8], source: &[u8]) -> Output {
    let root = std::env::temp_dir().join(format!(
        "fan-control-telemetry-patch-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("create telemetry patch fixture");
    let patch_path = root.join("telemetry.patch");
    let source_path = root.join("acer-wmi.c");
    fs::write(&patch_path, patch).expect("write telemetry patch fixture");
    fs::write(&source_path, source).expect("write acer-wmi fixture");
    let output = Command::new("python3")
        .args([
            "-c",
            "import pathlib,runpy,sys; m=runpy.run_path(sys.argv[1], run_name='telemetry_patch_test'); m['validate_telemetry_patch'](pathlib.Path(sys.argv[2]).read_bytes(), pathlib.Path(sys.argv[3]).read_bytes())",
        ])
        .arg(verifier())
        .arg(&patch_path)
        .arg(&source_path)
        .output()
        .expect("run telemetry patch validator");
    fs::remove_dir_all(root).expect("remove telemetry patch fixture");
    output
}

fn validate_pwm_patch(telemetry_patch: &[u8], pwm_patch: &[u8], source: &[u8]) -> Output {
    let root = std::env::temp_dir().join(format!(
        "fan-control-pwm-patch-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("create PWM patch fixture");
    let telemetry_path = root.join("telemetry.patch");
    let pwm_path = root.join("pwm.patch");
    let source_path = root.join("acer-wmi.c");
    fs::write(&telemetry_path, telemetry_patch).expect("write telemetry patch fixture");
    fs::write(&pwm_path, pwm_patch).expect("write PWM patch fixture");
    fs::write(&source_path, source).expect("write acer-wmi fixture");
    let output = Command::new("python3")
        .args([
            "-c",
            "import pathlib,runpy,sys; m=runpy.run_path(sys.argv[1], run_name='pwm_patch_test'); source=pathlib.Path(sys.argv[4]).read_bytes(); telemetry=m['validate_telemetry_patch'](pathlib.Path(sys.argv[2]).read_bytes(), source); m['validate_pwm_patch'](pathlib.Path(sys.argv[3]).read_bytes(), telemetry)",
        ])
        .arg(verifier())
        .arg(&telemetry_path)
        .arg(&pwm_path)
        .arg(&source_path)
        .output()
        .expect("run PWM patch validator");
    fs::remove_dir_all(root).expect("remove PWM patch fixture");
    output
}

fn verify_stage_two_patch_scope(source: &[u8]) -> Output {
    let root = std::env::temp_dir().join(format!(
        "fan-control-stage-two-scope-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let bundle = root.join("bundle");
    let archive_root = root
        .join("source")
        .join("cachyos-7.1.8-1")
        .join("drivers/platform/x86");
    fs::create_dir_all(bundle.join("patches")).expect("create patch-scope bundle");
    fs::create_dir_all(&archive_root).expect("create patch-scope source tree");
    fs::write(archive_root.join("acer-wmi.c"), source).expect("write patch-scope source");
    for patch in [
        "0001-acer-wmi-add-pt31553-telemetry.patch",
        "0002-acer-wmi-enable-pt31553-pwm.patch",
    ] {
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../packaging/kernel/patches")
                .join(patch),
            bundle.join("patches").join(patch),
        )
        .expect("stage locked patch");
    }
    let archive = bundle.join("cachyos-7.1.8-1.tar.gz");
    let archive_status = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .arg("-C")
        .arg(root.join("source"))
        .arg("cachyos-7.1.8-1")
        .status()
        .expect("create patch-scope source archive");
    assert!(archive_status.success());

    let output = Command::new("python3")
        .args([
            "-c",
            r#"import pathlib,runpy,sys
m=runpy.run_path(sys.argv[1], run_name='stage_two_scope_test')
inputs=[
 {'name':'kernel-source','kind':'kernel-source','path':'cachyos-7.1.8-1.tar.gz'},
 {'name':'pt31553-telemetry','kind':'patch','path':'patches/0001-acer-wmi-add-pt31553-telemetry.patch'},
 {'name':'pt31553-pwm','kind':'patch','path':'patches/0002-acer-wmi-enable-pt31553-pwm.patch'},
]
lock={'candidate':m['STAGE2_CANDIDATE'],'patches':['pt31553-telemetry','pt31553-pwm'],'release_tag':'cachyos-7.1.8-1'}
bundle=m['Bundle'](pathlib.Path(sys.argv[2]))
try:
 bundle.discover()
 m['verify_patch_scope'](bundle, lock, inputs)
except m['VerificationError'] as error:
 print(error, file=sys.stderr); raise SystemExit(1)
finally:
 bundle.close()
"#,
        ])
        .arg(verifier())
        .arg(&bundle)
        .output()
        .expect("run production Stage-2 patch-scope verifier");
    fs::remove_dir_all(root).expect("remove patch-scope fixture");
    output
}

fn run_verified_cli_gate(candidate: &str, option: &str) -> Output {
    Command::new("python3")
        .args([
            "-c",
            r#"import runpy,sys
m=runpy.run_path(sys.argv[1], run_name='verified_cli_gate_test')
g=m['main'].__globals__
candidate=sys.argv[2]
option=sys.argv[3]
lock={
 'candidate':candidate,
 'source_date_epoch':100,
 'signature_verification_epoch':100,
 'source_commit':'source',
 'source_tree':'source-tree',
 'packaging_commit':'packaging',
 'packaging_tree':'packaging-tree',
 'tag_signer_fingerprint':'fingerprint',
 'release_tag':'release',
}
inputs=[{'kind':kind} for kind in ['signer-key','source-commit','packaging-commit','kernel-source','packaging']]
class FakeBundle:
 def __init__(self, _path): pass
 def close(self): pass
g['load_manifest']=lambda _path: lock
g['validate_manifest']=lambda _lock: inputs
g['Bundle']=FakeBundle
g['verify_hashes']=lambda *_args: None
g['verify_signatures']=lambda *_args: [100]
g['verify_commit_object']=lambda *_args: (100,100)
g['verify_archive_tree']=lambda *_args: None
g['verify_packaging_config']=lambda *_args: None
g['verify_recipe_sources']=lambda *_args: None
g['verify_patch_scope']=lambda *_args: None
g['verify_build_metadata']=lambda *_args: None
g['verify_pinned_inputs']=lambda *_args: None
g['build_from_verified_snapshot']=lambda _bundle,_inputs,args: print('handoff:'+','.join(args)) or 0
sys.argv=['verify-source-lock','--inputs','unused','--exec-verified','--',option]
raise SystemExit(m['main']())
"#,
        ])
        .arg(verifier())
        .arg(candidate)
        .arg(option)
        .output()
        .expect("run verified CLI compile gate")
}

fn validate_patch_wrapper(wrapper: &[u8], candidate: &str) -> Output {
    let root = std::env::temp_dir().join(format!(
        "fan-control-patch-wrapper-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("create patch wrapper fixture");
    let wrapper_path = root.join("build-candidate");
    fs::write(&wrapper_path, wrapper).expect("write patch wrapper fixture");
    let output = Command::new("python3")
        .args([
            "-c",
            "import pathlib,runpy,sys; m=runpy.run_path(sys.argv[1], run_name='patch_wrapper_test'); m['verify_patch_wrapper'](pathlib.Path(sys.argv[2]).read_text(), sys.argv[3])",
        ])
        .arg(verifier())
        .arg(&wrapper_path)
        .arg(candidate)
        .output()
        .expect("run patch wrapper validator");
    fs::remove_dir_all(root).expect("remove patch wrapper fixture");
    output
}

fn validate_checked_in_stage_two_manifest(mutation: &str) -> Output {
    let lock =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/kernel/source-lock.toml");
    Command::new("python3")
        .args([
            "-c",
            r#"import copy,pathlib,runpy,sys,tomllib
m=runpy.run_path(sys.argv[1], run_name='stage_two_manifest_test')
with pathlib.Path(sys.argv[2]).open('rb') as stream:
    lock=tomllib.load(stream)
mutation=sys.argv[3]
tools=[item for item in lock['inputs'] if item['kind']=='build-tool']
if mutation=='missing':
    lock['inputs']=[item for item in lock['inputs'] if item['kind']!='build-tool']
elif mutation=='duplicate':
    duplicate=copy.deepcopy(tools[0]); duplicate['name']='build-tool-bc-duplicate'; duplicate['path']='build-tools/duplicate.pkg.tar.zst'; lock['inputs'].append(duplicate)
elif mutation=='altered':
    tools[0]['sha256']='0'*64
elif mutation=='stage-one':
    lock['candidate']='linux-cachyos-gcc-7.1.8-stage-1-telemetry'; lock['patches']=['pt31553-telemetry']; lock['inputs']=[item for item in lock['inputs'] if item['name']!='pt31553-pwm']
elif mutation=='reverse-patches':
    lock['patches']=list(reversed(lock['patches']))
elif mutation=='stage-zero':
    lock['candidate']='linux-cachyos-gcc-7.1.8-stage-0'; lock['patches']=[]; lock['inputs']=[item for item in lock['inputs'] if item['kind']!='patch']
m['validate_manifest'](lock)
"#,
        ])
        .arg(verifier())
        .arg(lock)
        .arg(mutation)
        .output()
        .expect("validate checked-in stage-two manifest")
}

#[cfg(unix)]
fn run_verified_build_tool_snapshot_fixture(mutation: &str) -> (Output, bool) {
    let root = std::env::temp_dir().join(format!(
        "fan-control-build-tool-snapshot-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let bundle = root.join("bundle");
    let tool_dir = bundle.join("build-tools");
    let tool = tool_dir.join("bc.pkg.tar.zst");
    let wrapper = bundle.join("build-candidate");
    let output_dir = root.join("output");
    let marker = output_dir.join("snapshot-used");
    fs::create_dir_all(&tool_dir).expect("create snapshot fixture bundle");
    fs::create_dir(&output_dir).expect("create snapshot fixture output");
    let tool_bytes = b"pinned bc fixture\n";
    fs::write(&tool, tool_bytes).expect("write snapshot build tool");
    let wrapper_bytes = format!(
        r#"#!/bin/bash
set -euo pipefail
[[ "${{1:-}}" == --compile-pwm ]]
[[ "$SOURCE_LOCK_BUNDLE" != "{}" ]]
grep -qx 'pinned bc fixture' "$SOURCE_LOCK_BUNDLE/build-tools/bc.pkg.tar.zst"
printf 'yes\n' >"$SOURCE_LOCK_OUTPUT/snapshot-used"
"#,
        bundle.display()
    )
    .into_bytes();
    fs::write(&wrapper, &wrapper_bytes).expect("write snapshot wrapper");
    set_tree_modes(&bundle, 0o555, 0o444);

    match mutation {
        "none" => {}
        "missing" => {
            fs::set_permissions(&tool_dir, fs::Permissions::from_mode(0o755))
                .expect("unlock tool directory");
            fs::remove_file(&tool).expect("remove build tool");
            fs::set_permissions(&tool_dir, fs::Permissions::from_mode(0o555))
                .expect("relock tool directory");
        }
        "changed" => {
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o644))
                .expect("unlock build tool");
            fs::write(&tool, b"changed bc fixture\n").expect("change build tool");
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o444))
                .expect("relock build tool");
        }
        "writable" => fs::set_permissions(&tool, fs::Permissions::from_mode(0o644))
            .expect("make build tool writable"),
        "linked" => {
            let outside = root.join("outside-bc");
            fs::write(&outside, tool_bytes).expect("write outside build tool");
            fs::set_permissions(&tool_dir, fs::Permissions::from_mode(0o755))
                .expect("unlock tool directory");
            fs::remove_file(&tool).expect("remove build tool before linking");
            symlink(&outside, &tool).expect("link build tool");
            fs::set_permissions(&tool_dir, fs::Permissions::from_mode(0o555))
                .expect("relock tool directory");
        }
        "additional" => {
            fs::set_permissions(&bundle, fs::Permissions::from_mode(0o755)).expect("unlock bundle");
            let extra = bundle.join("unexpected");
            fs::write(&extra, b"unexpected\n").expect("write extra input");
            fs::set_permissions(&extra, fs::Permissions::from_mode(0o444))
                .expect("lock extra input");
            fs::set_permissions(&bundle, fs::Permissions::from_mode(0o555)).expect("relock bundle");
        }
        _ => panic!("unknown snapshot mutation"),
    }

    let run = Command::new("python3")
        .args([
            "-c",
            r#"import pathlib,runpy,sys
m=runpy.run_path(sys.argv[1], run_name='build_tool_snapshot_test')
inputs=[
 {'name':'build-wrapper','kind':'build-wrapper','path':'build-candidate','sha256':sys.argv[3],'size':int(sys.argv[4])},
 {'name':'build-tool-bc','kind':'build-tool','path':'build-tools/bc.pkg.tar.zst','sha256':sys.argv[5],'size':int(sys.argv[6])},
]
bundle=m['Bundle'](pathlib.Path(sys.argv[2]))
try:
 m['verify_hashes'](bundle, inputs)
 m['verify_pinned_inputs'](bundle, inputs)
 raise SystemExit(m['build_from_verified_snapshot'](bundle, inputs, ['--compile-pwm']))
except m['VerificationError'] as error:
 print(error, file=sys.stderr); raise SystemExit(1)
finally:
 bundle.close()
"#,
        ])
        .arg(verifier())
        .arg(&bundle)
        .arg(sha(&wrapper_bytes))
        .arg(wrapper_bytes.len().to_string())
        .arg(sha(tool_bytes))
        .arg(tool_bytes.len().to_string())
        .env("SOURCE_LOCK_OUTPUT", &output_dir)
        .output()
        .expect("run verified build-tool snapshot fixture");
    let used_snapshot = marker.exists();
    restore_tree_modes(&bundle);
    fs::remove_dir_all(&root).expect("remove build-tool snapshot fixture");
    (run, used_snapshot)
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
    let kernel_root = root.join("kernel");
    let archive_root = root
        .join("archive")
        .join("linux-cachyos-3c399d306eed6497838b246b9dbe73ec2cd1bb2f")
        .join("linux-cachyos");
    fs::create_dir_all(bundle.join("oci/blobs/sha256")).expect("create bundle OCI tree");
    fs::create_dir_all(bundle.join("patches")).expect("create bundle patch directory");
    fs::create_dir_all(&output).expect("create output directory");
    fs::create_dir_all(&bin).expect("create fake command directory");
    fs::create_dir_all(&archive_root).expect("create packaging tree");
    fs::create_dir_all(kernel_root.join("drivers/platform/x86"))
        .expect("create kernel source tree");
    fs::write(
        kernel_root.join("drivers/platform/x86/acer-wmi.c"),
        pinned_acer_wmi_contexts(),
    )
    .expect("write pinned acer-wmi fixture");
    fs::write(
        archive_root.join("PKGBUILD"),
        r#"pkgname=test
source=()
b2sums=()
prepare() {
    cd "$TEST_KERNEL_ROOT"
    local patch src
    for patch in "${source[@]}"; do
        src="${patch##*/}"
        [[ $src = *.patch ]] || continue
        patch -Np1 < "$TEST_BUNDLE/patches/$src"
    done
}
"#,
    )
    .expect("write PKGBUILD");
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
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/kernel/patches/0001-acer-wmi-add-pt31553-telemetry.patch"),
        bundle.join("patches/0001-acer-wmi-add-pt31553-telemetry.patch"),
    )
    .expect("stage locked telemetry patch");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/kernel/patches/0002-acer-wmi-enable-pt31553-pwm.patch"),
        bundle.join("patches/0002-acer-wmi-enable-pt31553-pwm.patch"),
    )
    .expect("stage locked PWM patch");

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
    package_root=""
    for arg in "$@"; do
        if [[ "$arg" == type=bind,src=*,dst=/work,rw=true ]]; then
            package_root="${arg#type=bind,src=}"
            package_root="${package_root%,dst=/work,rw=true}"
        fi
    done
    [[ -n "$package_root" ]]
    env -i PATH="$TEST_BIN:/usr/bin:/bin" \
        SOURCE_LOCK_INSIDE=1 \
        SOURCE_LOCK_BUNDLE="$TEST_BUNDLE" \
        SOURCE_LOCK_OUTPUT="$TEST_OUTPUT" \
        TEST_BUNDLE="$TEST_BUNDLE" \
        TEST_KERNEL_ROOT="$TEST_KERNEL_ROOT" \
        TEST_MAKEPKG_LOG="$TEST_MAKEPKG_LOG" \
        TEST_PACKAGE_ROOT="$package_root" \
        /bin/bash "$TEST_WRAPPER"
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
[[ "$(readlink "$TEST_PACKAGE_ROOT/source-cache/0001-acer-wmi-add-pt31553-telemetry.patch")" == "/bundle/patches/0001-acer-wmi-add-pt31553-telemetry.patch" ]]
[[ "$(readlink "$TEST_PACKAGE_ROOT/source-cache/0002-acer-wmi-enable-pt31553-pwm.patch")" == "/bundle/patches/0002-acer-wmi-enable-pt31553-pwm.patch" ]]
source "$TEST_PACKAGE_ROOT/PKGBUILD"
[[ "${source[*]}" == "0001-acer-wmi-add-pt31553-telemetry.patch 0002-acer-wmi-enable-pt31553-pwm.patch" ]]
[[ "${b2sums[*]}" == "SKIP SKIP" ]]
prepare
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
        .env("PATH", &path)
        .env("SOURCE_LOCK_BUNDLE", &bundle)
        .env("SOURCE_LOCK_OUTPUT", &output)
        .env("TEST_BIN", &bin)
        .env("TEST_BUNDLE", &bundle)
        .env("TEST_OUTPUT", &output)
        .env("TEST_KERNEL_ROOT", &kernel_root)
        .env("TEST_WRAPPER", &wrapper)
        .env("TEST_PODMAN_LOG", &podman_log)
        .env("TEST_MAKEPKG_LOG", &makepkg_log)
        .output()
        .expect("run checked-in executor");
    assert!(
        run.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        failure_text(&run)
    );

    let podman = fs::read_to_string(&podman_log).expect("read fake podman log");
    assert!(podman.contains("--storage-driver=overlay pull --quiet oci:"));
    assert!(podman.contains("run --rm --pull=never --network=none --read-only"));
    assert!(podman.contains("--mount type=bind"));
    assert!(podman.contains("dst=/bundle,ro=true"));
    assert!(podman.contains("--entrypoint /bundle/build-candidate"));
    let makepkg = fs::read_to_string(&makepkg_log).expect("read fake makepkg log");
    assert!(makepkg.contains("--skippgpcheck --skipchecksums --noconfirm --cleanbuild"));
    assert!(!makepkg.contains("--verifysource"));
    assert!(makepkg.contains("SOURCE_DATE_EPOCH=1786378335"));
    assert!(makepkg.contains("_processor_opt=generic_v4"));
    assert!(makepkg.contains("_cpusched=cachyos"));
    let patched_source = fs::read_to_string(kernel_root.join("drivers/platform/x86/acer-wmi.c"))
        .expect("read patched acer-wmi fixture");
    assert!(patched_source.contains("Predator PT315-53"));
    assert!(patched_source.contains("DMI_EXACT_MATCH(DMI_BOARD_NAME, \"Civic_TLS\")"));
    assert!(patched_source.contains("\t.pwm = 1,"));

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

#[cfg(unix)]
#[test]
fn checked_in_executor_compiles_pwm_candidate_and_emits_a_portable_checksum() {
    let root = std::env::temp_dir().join(format!(
        "fan-control-pwm-compile-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let bundle = root.join("bundle");
    let output = root.join("output");
    let bin = root.join("bin");
    let source_tree = root
        .join("source")
        .join("cachyos-7.1.8-1")
        .join("drivers/platform/x86");
    let tool_tree = root.join("tool").join("usr/bin");
    fs::create_dir_all(bundle.join("build-tools")).expect("create build-tool directory");
    fs::create_dir_all(bundle.join("patches")).expect("create patch directory");
    fs::create_dir_all(&output).expect("create output directory");
    fs::create_dir_all(&bin).expect("create fake command directory");
    fs::create_dir_all(&source_tree).expect("create source tree");
    fs::create_dir_all(&tool_tree).expect("create build-tool tree");
    fs::write(source_tree.join("acer-wmi.c"), pinned_acer_wmi_contexts())
        .expect("write pinned acer-wmi source");
    fs::write(tool_tree.join("bc"), b"#!/bin/sh\nexit 0\n").expect("write fake bc");
    fs::write(bundle.join("config"), b"CONFIG_TEST=y\n").expect("write kernel config");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/kernel/patches/0001-acer-wmi-add-pt31553-telemetry.patch"),
        bundle.join("patches/0001-acer-wmi-add-pt31553-telemetry.patch"),
    )
    .expect("stage telemetry patch");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/kernel/patches/0002-acer-wmi-enable-pt31553-pwm.patch"),
        bundle.join("patches/0002-acer-wmi-enable-pt31553-pwm.patch"),
    )
    .expect("stage PWM patch");
    let source_status = Command::new("tar")
        .args(["-czf"])
        .arg(bundle.join("cachyos-7.1.8-1.tar.gz"))
        .arg("-C")
        .arg(root.join("source"))
        .arg("cachyos-7.1.8-1")
        .status()
        .expect("create kernel source archive");
    assert!(source_status.success());
    let tool_status = Command::new("tar")
        .args(["-cf"])
        .arg(
            bundle
                .join("build-tools")
                .join("bc-1.08.2-1.1-x86_64_v4.pkg.tar.zst"),
        )
        .arg("-C")
        .arg(root.join("tool"))
        .arg("usr/bin/bc")
        .status()
        .expect("create build-tool archive");
    assert!(tool_status.success());

    let make_log = root.join("make.log");
    let fake_make = bin.join("make");
    fs::write(
        &fake_make,
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$TEST_MAKE_LOG"
source_root=""
while (( $# )); do
    if [[ "$1" == -C ]]; then source_root="$2"; shift 2; continue; fi
    shift
done
[[ -n "$source_root" ]]
if [[ " $(tail -n 1 "$TEST_MAKE_LOG") " == *" drivers/platform/x86/acer-wmi.o "* ]]; then
    grep -q 'Predator PT315-53' "$source_root/drivers/platform/x86/acer-wmi.c"
    grep -q 'DMI_EXACT_MATCH(DMI_BOARD_NAME, "Civic_TLS")' "$source_root/drivers/platform/x86/acer-wmi.c"
    grep -q $'\t.pwm = 1,' "$source_root/drivers/platform/x86/acer-wmi.c"
    printf 'pinned PWM object\n' >"$source_root/drivers/platform/x86/acer-wmi.o"
fi
"#,
    )
    .expect("write fake make");
    fs::set_permissions(&fake_make, fs::Permissions::from_mode(0o755))
        .expect("make fake make executable");

    let wrapper =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/kernel/build-candidate");
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let run = Command::new("/bin/bash")
        .arg(&wrapper)
        .arg("--compile-pwm")
        .env("PATH", path)
        .env("SOURCE_LOCK_INSIDE", "1")
        .env("SOURCE_LOCK_BUNDLE", &bundle)
        .env("SOURCE_LOCK_OUTPUT", &output)
        .env("TEST_MAKE_LOG", &make_log)
        .current_dir(&root)
        .output()
        .expect("run PWM compile gate");
    assert!(
        run.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        failure_text(&run)
    );

    let object = output.join("acer-wmi.o");
    let checksum = output.join("acer-wmi.o.sha256");
    let object_bytes = fs::read(&object).expect("read retained object");
    assert_eq!(object_bytes, b"pinned PWM object\n");
    assert_eq!(
        fs::read_to_string(&checksum).expect("read checksum manifest"),
        format!("{}  acer-wmi.o\n", sha(&object_bytes))
    );
    assert_eq!(
        fs::metadata(&object)
            .expect("object metadata")
            .permissions()
            .mode()
            & 0o777,
        0o444
    );
    let checksum_check = Command::new("sha256sum")
        .args(["-c", "acer-wmi.o.sha256"])
        .current_dir(&output)
        .output()
        .expect("verify retained checksum on host");
    assert!(
        checksum_check.status.success(),
        "{}",
        failure_text(&checksum_check)
    );
    let calls = fs::read_to_string(&make_log).expect("read make log");
    assert!(calls.lines().any(|line| line.ends_with(" olddefconfig")));
    assert!(
        calls
            .lines()
            .any(|line| line.ends_with(" -j2 drivers/platform/x86/acer-wmi.o"))
    );

    fs::remove_dir_all(root.join("pwm-compile")).expect("reset PWM compile tree");
    fs::write(
        &fake_make,
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" drivers/platform/x86/acer-wmi.o "* ]]; then
    exit 23
fi
"#,
    )
    .expect("write failing fake make");
    let failed = Command::new("/bin/bash")
        .arg(&wrapper)
        .arg("--compile-pwm")
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("SOURCE_LOCK_INSIDE", "1")
        .env("SOURCE_LOCK_BUNDLE", &bundle)
        .env("SOURCE_LOCK_OUTPUT", &output)
        .current_dir(&root)
        .output()
        .expect("run failing PWM compile gate");
    assert_eq!(failed.status.code(), Some(23), "{}", failure_text(&failed));
    assert!(
        !object.exists(),
        "failed compile must not publish an object"
    );
    assert!(
        !checksum.exists(),
        "failed compile must not publish a checksum"
    );

    fs::remove_dir_all(&root).expect("remove PWM compile fixture");
}

#[test]
fn stage_two_manifest_requires_the_one_exact_build_tool() {
    let accepted = validate_checked_in_stage_two_manifest("none");
    assert!(accepted.status.success(), "{}", failure_text(&accepted));
    let stage_one = validate_checked_in_stage_two_manifest("stage-one");
    assert!(stage_one.status.success(), "{}", failure_text(&stage_one));

    for (mutation, expected) in [
        ("missing", "require exactly the pinned bc package"),
        ("duplicate", "require exactly the pinned bc package"),
        ("altered", "bc package identity is not exact"),
        (
            "reverse-patches",
            "does not match the selected qualification stage",
        ),
        ("stage-zero", "stage 0 must not select build tools"),
    ] {
        let rejected = validate_checked_in_stage_two_manifest(mutation);
        assert!(!rejected.status.success(), "{mutation} unexpectedly passed");
        assert!(failure_text(&rejected).contains(expected), "{mutation}");
    }
}

#[cfg(unix)]
#[test]
fn verified_stage_one_handoff_snapshots_and_protects_the_build_tool() {
    let (accepted, used_snapshot) = run_verified_build_tool_snapshot_fixture("none");
    assert!(accepted.status.success(), "{}", failure_text(&accepted));
    assert!(
        used_snapshot,
        "build did not consume the verifier-owned snapshot"
    );

    for (mutation, expected) in [
        ("missing", "missing input"),
        ("changed", "size changed"),
        ("writable", "verified bundle must be read-only"),
        ("linked", "symlinked input is forbidden"),
        ("additional", "unrecorded input"),
    ] {
        let (rejected, used_snapshot) = run_verified_build_tool_snapshot_fixture(mutation);
        assert!(!rejected.status.success(), "{mutation} unexpectedly passed");
        assert!(!used_snapshot, "{mutation} reached the build wrapper");
        assert!(failure_text(&rejected).contains(expected), "{mutation}");
    }
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
fn rejects_downgrading_the_stage_one_candidate_to_an_empty_patch_set() {
    let fixture = Fixture::new();
    fixture.replace_lock(
        "candidate = \"linux-cachyos-gcc-7.1.8-stage-0\"",
        "candidate = \"linux-cachyos-gcc-7.1.8-stage-1-telemetry\"",
    );

    let output = fixture.verify();

    assert!(!output.status.success());
    assert!(failure_text(&output).contains("does not match the selected qualification stage"));
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

    assert!(failure_text(&fixture.verify()).contains("must exactly list unique patch input names"));
}

#[cfg(unix)]
#[test]
fn rejects_any_patch_outside_the_selected_qualification_stage() {
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
    assert!(failure_text(&output).contains("does not match the selected qualification stage"));
}

#[test]
fn validates_the_locked_telemetry_patch_against_pinned_source_contexts() {
    let patch = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/kernel/patches/0001-acer-wmi-add-pt31553-telemetry.patch"),
    )
    .expect("read locked telemetry patch");
    let source = pinned_acer_wmi_contexts();

    let accepted = validate_telemetry_patch(&patch, &source);
    assert!(accepted.status.success(), "{}", failure_text(&accepted));

    let mut shifted_source = b"/* unexpected leading line */\n".to_vec();
    shifted_source.extend_from_slice(&source);
    let shifted = validate_telemetry_patch(&patch, &shifted_source);
    assert!(!shifted.status.success());
    assert!(failure_text(&shifted).contains("does not apply exactly"));

    let patch_text = String::from_utf8(patch).expect("UTF-8 telemetry patch");
    let pwm_patch = patch_text.replacen("+\t.predator_v4 = 1,", "+\t.pwm = 1,", 1);
    let pwm = validate_telemetry_patch(pwm_patch.as_bytes(), &source);
    assert!(!pwm.status.success());
    assert!(failure_text(&pwm).contains("locked stage-1 source change"));

    let moved_patch = patch_text.replacen("@@ -482,6 +482,10", "@@ -485,6 +485,10", 1);
    let moved = validate_telemetry_patch(moved_patch.as_bytes(), &source);
    assert!(!moved.status.success());
    assert!(failure_text(&moved).contains("locked stage-1 source change"));
}

#[test]
fn validates_the_locked_pwm_patch_only_after_exact_telemetry() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/kernel/patches");
    let telemetry = fs::read(root.join("0001-acer-wmi-add-pt31553-telemetry.patch"))
        .expect("read locked telemetry patch");
    let pwm = fs::read(root.join("0002-acer-wmi-enable-pt31553-pwm.patch"))
        .expect("read locked PWM patch");
    let source = pinned_acer_wmi_contexts();

    let accepted = validate_pwm_patch(&telemetry, &pwm, &source);
    assert!(accepted.status.success(), "{}", failure_text(&accepted));

    let pwm_text = String::from_utf8(pwm.clone()).expect("UTF-8 PWM patch");
    let extra_capability = pwm_text.replace("+\t.pwm = 1,", "+\t.pwm = 1,\n+\t.force_caps = 1,");
    let rejected = validate_pwm_patch(&telemetry, extra_capability.as_bytes(), &source);
    assert!(!rejected.status.success());
    assert!(failure_text(&rejected).contains("locked stage-2 source change"));

    let wrong_context = pwm_text.replace("quirk_acer_predator_pt315_53", "quirk_acer_predator_v4");
    let rejected = validate_pwm_patch(&telemetry, wrong_context.as_bytes(), &source);
    assert!(!rejected.status.success());
    assert!(failure_text(&rejected).contains("locked stage-2 source change"));
}

#[test]
fn production_stage_two_scope_rejects_pinned_source_context_drift() {
    let source = pinned_acer_wmi_contexts();
    let accepted = verify_stage_two_patch_scope(&source);
    assert!(accepted.status.success(), "{}", failure_text(&accepted));

    let mut shifted = b"/* unexpected leading line */\n".to_vec();
    shifted.extend_from_slice(&source);
    let rejected = verify_stage_two_patch_scope(&shifted);
    assert!(!rejected.status.success());
    assert!(failure_text(&rejected).contains("does not apply exactly"));
}

#[test]
fn patch_wrapper_allows_only_the_exact_recipe_mutation() {
    let wrapper = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/kernel/build-candidate"),
    )
    .expect("read locked build wrapper");
    let accepted = validate_patch_wrapper(&wrapper, "linux-cachyos-gcc-7.1.8-stage-2-pwm");
    assert!(accepted.status.success(), "{}", failure_text(&accepted));

    let mut extra_mutation = wrapper;
    extra_mutation.extend_from_slice(
        b"recipe=\"$package_root/PKG\"\"BUILD\"\nprintf 'source+=(evil.patch)\\n' >>\"$recipe\"\n",
    );
    let rejected = validate_patch_wrapper(&extra_mutation, "linux-cachyos-gcc-7.1.8-stage-2-pwm");
    assert!(!rejected.status.success());
    assert!(failure_text(&rejected).contains("locked stage-2 mutation program"));
}

#[test]
fn preserves_the_exact_stage_one_wrapper_contract() {
    let wrapper = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/kernel/build-candidate"),
    )
    .expect("read Stage-2 wrapper");
    let stage_one = wrapper
        .replace("--compile-pwm", "--compile-telemetry")
        .replace("pwm-compile", "telemetry-compile")
        .replace(
            "pwm_patch=\"0002-acer-wmi-enable-pt31553-pwm.patch\"\n",
            "",
        )
        .replace(
            concat!(
                "        rm -f -- \"$SOURCE_LOCK_OUTPUT/acer-wmi.o\" \\\n",
                "            \"$SOURCE_LOCK_OUTPUT/acer-wmi.o.sha256\"\n"
            ),
            "",
        )
        .replace(
            "        patch --directory \"$source_root\" -Np1 \\\n            <\"$SOURCE_LOCK_BUNDLE/patches/$pwm_patch\"\n",
            "",
        )
        .replace(
            "ln -s \"/bundle/patches/$pwm_patch\" \"$package_root/source-cache/$pwm_patch\"\n",
            "",
        )
        .replace(
            "printf '\\nsource+=(\"%s\" \"%s\")\\nb2sums+=(\"SKIP\" \"SKIP\")\\n' \\\n    \"$telemetry_patch\" \"$pwm_patch\" >>\"$package_root/PKGBUILD\"",
            "printf '\\nsource+=(\"%s\")\\nb2sums+=(\"SKIP\")\\n' \"$telemetry_patch\" >>\"$package_root/PKGBUILD\"",
        );
    let accepted = validate_patch_wrapper(
        stage_one.as_bytes(),
        "linux-cachyos-gcc-7.1.8-stage-1-telemetry",
    );
    assert!(accepted.status.success(), "{}", failure_text(&accepted));
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
    assert!(failure_text(&fixture.verify()).contains("candidate requires linux/amd64"));
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
    assert!(failure_text(&cpu_target.verify()).contains("candidate requires x86-64-v4"));

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
    for option in ["--sign", "--compile-telemetry", "--compile-pwm"] {
        let fixture = Fixture::new();
        fixture.make_read_only();
        let output = fixture
            .command()
            .arg("--exec-verified")
            .arg("--")
            .arg(option)
            .output()
            .expect("run verified handoff with forbidden option");

        assert!(!output.status.success());
        assert!(
            failure_text(&output)
                .contains("only the selected compile gate or --verifysource is allowed")
        );
    }
}

#[test]
fn stage_two_cli_selects_only_the_pwm_compile_gate() {
    let candidate = "linux-cachyos-gcc-7.1.8-stage-2-pwm";
    let accepted = run_verified_cli_gate(candidate, "--compile-pwm");
    assert!(accepted.status.success(), "{}", failure_text(&accepted));
    assert!(String::from_utf8_lossy(&accepted.stdout).contains("handoff:--compile-pwm"));

    let rejected = run_verified_cli_gate(candidate, "--compile-telemetry");
    assert!(!rejected.status.success());
    assert!(
        failure_text(&rejected)
            .contains("only the selected compile gate or --verifysource is allowed")
    );
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains("handoff:"));
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
        "build-tool",
        "build-wrapper",
        "makepkg-config",
        "patch",
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
    assert!(lock.contains("candidate = \"linux-cachyos-gcc-7.1.8-stage-2-pwm\""));
    assert!(lock.contains("patches = [\"pt31553-telemetry\", \"pt31553-pwm\"]"));

    let parsed: toml::Value = toml::from_str(&lock).expect("parse checked-in lock");
    let inputs = parsed["inputs"].as_array().expect("lock inputs");
    let bc = inputs
        .iter()
        .find(|input| input["name"].as_str() == Some("build-tool-bc"))
        .expect("locked bc build tool");
    assert_eq!(bc["kind"].as_str(), Some("build-tool"));
    assert_eq!(
        bc["path"].as_str(),
        Some("build-tools/bc-1.08.2-1.1-x86_64_v4.pkg.tar.zst")
    );
    assert_eq!(bc["revision"].as_str(), Some("1.08.2-1.1"));
    assert_eq!(
        bc["sha256"].as_str(),
        Some("b3740d2c34090685b6ffe1b6a6b4631c45edd4801dc7a2bde1049de92165b0d3")
    );
    assert_eq!(bc["size"].as_integer(), Some(110253));
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
            "pt31553-telemetry",
            root.join("patches/0001-acer-wmi-add-pt31553-telemetry.patch"),
        ),
        (
            "pt31553-pwm",
            root.join("patches/0002-acer-wmi-enable-pt31553-pwm.patch"),
        ),
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

    let patch = fs::read_to_string(root.join("patches/0001-acer-wmi-add-pt31553-telemetry.patch"))
        .expect("read telemetry patch");
    let additions = patch
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .collect::<Vec<_>>();
    assert!(additions.contains(&"+\t\t\tDMI_EXACT_MATCH(DMI_SYS_VENDOR, \"Acer\"),"));
    assert!(
        additions.contains(&"+\t\t\tDMI_EXACT_MATCH(DMI_PRODUCT_NAME, \"Predator PT315-53\"),")
    );
    assert!(additions.contains(&"+\t\t\tDMI_EXACT_MATCH(DMI_BOARD_NAME, \"Civic_TLS\"),"));
    assert!(additions.contains(&"+\t.predator_v4 = 1,"));
    for forbidden in [".pwm", "force_caps", "ec_raw_mode", "wmi_evaluate_method"] {
        assert!(
            additions.iter().all(|line| !line.contains(forbidden)),
            "telemetry additions contain forbidden capability {forbidden}"
        );
    }

    let pwm_patch = fs::read_to_string(root.join("patches/0002-acer-wmi-enable-pt31553-pwm.patch"))
        .expect("read PWM patch");
    let pwm_additions = pwm_patch
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .collect::<Vec<_>>();
    assert_eq!(pwm_additions, ["+\t.pwm = 1,"]);

    let environment = fs::read_to_string(root.join("build-environment.toml"))
        .expect("read checked-in build environment");
    assert!(environment.contains("patches = [\"pt31553-telemetry\", \"pt31553-pwm\"]"));
    assert!(environment.contains("\"pt31553-telemetry\""));
    assert!(environment.contains("\"pt31553-pwm\""));
    let environment_value: toml::Value =
        toml::from_str(&environment).expect("parse checked-in build environment");
    let selected_inputs = environment_value["build_inputs"]
        .as_array()
        .expect("build inputs")
        .iter()
        .map(|name| name.as_str().expect("build input name"))
        .collect::<Vec<_>>();
    let excluded = [
        "kernel-signature",
        "source-commit",
        "release-tag",
        "signer-key",
        "packaging-commit",
        "build-environment",
    ];
    let mut expected_inputs = inputs
        .iter()
        .filter(|input| !excluded.contains(&input["kind"].as_str().expect("locked input kind")))
        .map(|input| input["name"].as_str().expect("locked input name"))
        .collect::<Vec<_>>();
    expected_inputs.sort_unstable();
    assert_eq!(selected_inputs, expected_inputs);
    let wrapper =
        fs::read_to_string(root.join("build-candidate")).expect("read checked-in build wrapper");
    assert!(wrapper.contains("/bundle/patches/$telemetry_patch"));
    assert!(wrapper.contains("/bundle/patches/$pwm_patch"));
    assert!(wrapper.contains("source+=(\"%s\" \"%s\")"));
}
