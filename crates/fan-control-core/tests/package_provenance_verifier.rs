use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::size_of;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
const RELEASE: &str = "7.1.8-cachyos-pt31553";
const KERNEL: &str = "linux-cachyos-pt31553";
const HEADERS: &str = "linux-cachyos-pt31553-headers";
const NVIDIA: &str = "linux-cachyos-pt31553-nvidia-open";
const NVIDIA_MODULES: [&str; 5] = [
    "nvidia",
    "nvidia-drm",
    "nvidia-modeset",
    "nvidia-peermem",
    "nvidia-uvm",
];

struct Fixture {
    root: PathBuf,
    artifacts: PathBuf,
    bin: PathBuf,
    module_cert: PathBuf,
    module_cert_der: PathBuf,
    module_cert_hash: String,
    package_cert: PathBuf,
    package_cert_der: PathBuf,
    package_cert_hash: String,
    kernel_cert: PathBuf,
    kernel_cert_der: PathBuf,
    kernel_cert_hash: String,
    manifest_signature: PathBuf,
    cms_log: PathBuf,
    real_modinfo: bool,
    real_openssl: bool,
    real_sbverify: bool,
}

impl Fixture {
    fn new() -> Self {
        Self::with_options(None, None, None, None, None, None)
    }

    fn without_buildinfo_field(omitted_buildinfo_field: Option<&str>) -> Self {
        Self::with_options(omitted_buildinfo_field, None, None, None, None, None)
    }

    fn with_bad_module_signature(module_name: &str) -> Self {
        Self::with_options(None, Some(module_name), None, None, None, None)
    }

    fn with_sensitive_package_file(path: &str, content: &[u8]) -> Self {
        Self::with_options(None, None, Some((path, content)), None, None, None)
    }

    fn with_extra_module() -> Self {
        let module = signed_module("unexpected", false);
        Self::with_options(
            None,
            None,
            Some((
                "usr/lib/modules/7.1.8-cachyos-pt31553/kernel/drivers/misc/unexpected.ko.zst",
                &module,
            )),
            None,
            None,
            None,
        )
    }

    fn with_mismatched_builddate() -> Self {
        Self::with_options(None, None, None, Some("1786378336"), None, None)
    }

    fn with_mismatched_buildinfo_format() -> Self {
        Self::with_options(None, None, None, None, Some("3"), None)
    }

    fn with_unknown_buildinfo_field() -> Self {
        Self::with_options(None, None, None, None, None, Some("builder_host = laptop"))
    }

    fn with_options(
        omitted_buildinfo_field: Option<&str>,
        bad_module_signature: Option<&str>,
        sensitive_package_file: Option<(&str, &[u8])>,
        nvidia_builddate: Option<&str>,
        nvidia_buildinfo_format: Option<&str>,
        nvidia_buildinfo_extra: Option<&str>,
    ) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fan-control-package-provenance-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let artifacts = root.join("artifacts");
        let bin = root.join("bin");
        fs::create_dir_all(&artifacts).expect("create artifact root");
        fs::create_dir_all(&bin).expect("create tool root");

        let module_cert = root.join("module-certificate.pem");
        let module_cert_der = root.join("module-certificate.der");
        let package_cert = root.join("package-certificate.pem");
        let package_cert_der = root.join("package-certificate.der");
        let kernel_cert = root.join("kernel-certificate.pem");
        let kernel_cert_der = root.join("kernel-certificate.der");
        fs::write(&module_cert, b"stable module certificate DER")
            .expect("write module certificate");
        fs::write(&module_cert_der, b"stable module certificate DER").expect("write module DER");
        fs::write(&package_cert, b"stable package certificate DER")
            .expect("write package certificate");
        fs::write(&package_cert_der, b"stable package certificate DER").expect("write package DER");
        fs::write(&kernel_cert, b"stable kernel certificate DER")
            .expect("write kernel certificate");
        fs::write(&kernel_cert_der, b"stable kernel certificate DER").expect("write kernel DER");
        let module_cert_hash = sha(b"stable module certificate DER");
        let package_cert_hash = sha(b"stable package certificate DER");
        let kernel_cert_hash = sha(b"stable kernel certificate DER");
        write_tool(
            &bin.join("openssl"),
            r#"#!/bin/sh
set -eu
case "$1" in
  x509)
    output=
    input=
    previous=
    for value in "$@"; do
      if [ "$previous" = -out ]; then output=$value; fi
      if [ "$previous" = -in ]; then input=$value; fi
      previous=$value
    done
    if [ -z "$output" ]; then exec /usr/bin/openssl "$@"; fi
    if cmp -s "$input" "$FAKE_MODULE_CERT"; then
      cp "$FAKE_MODULE_CERT_DER" "$output"
    elif cmp -s "$input" "$FAKE_PACKAGE_CERT"; then
      cp "$FAKE_PACKAGE_CERT_DER" "$output"
    elif cmp -s "$input" "$FAKE_KERNEL_CERT"; then
      cp "$FAKE_KERNEL_CERT_DER" "$output"
    else
      cp "$input" "$output"
    fi
    ;;
  pkey|pkcs12) exec /usr/bin/openssl "$@" ;;
  cms)
    [ "${FAIL_CMS:-0}" != 1 ]
    case " $* " in
      *" -cmsout "*)
        if [ "${WEAK_CMS:-0}" = 1 ]; then
          digest=sha1
        else
          case "$*" in *module-*.p7s*) digest=sha512 ;; *) digest=sha256 ;; esac
        fi
        printf '    digestAlgorithms:\n        algorithm: %s (oid)\n    encapContentInfo:\n      eContent: <ABSENT>\n    signerInfos:\n        digestAlgorithm:\n          algorithm: %s (oid)\n' "$digest" "$digest"
        exit 0
        ;;
    esac
    signature=
    content=
    certfile=
    previous=
    for value in "$@"; do
      if [ "$previous" = -in ]; then signature=$value; fi
      if [ "$previous" = -content ]; then content=$value; fi
      if [ "$previous" = -certfile ]; then certfile=$value; fi
      previous=$value
    done
    if [ "$(basename "$content")" = SHA256SUMS ]; then
      cmp -s "$certfile" "$FAKE_PACKAGE_CERT_DER"
    else
      cmp -s "$certfile" "$FAKE_MODULE_CERT_DER"
    fi
    [ "$(cat "$signature")" = "$(sha256sum "$content" | cut -d ' ' -f 1)" ]
    case "$(basename "$content")" in
      module-*.signed) basename "$content" >>"$FAKE_CMS_LOG" ;;
    esac
    ;;
  *) exit 2 ;;
esac
"#,
        );
        write_tool(
            &bin.join("sbverify"),
            r#"#!/bin/sh
set -eu
[ "$1" = --cert ]
[ -f "$2" ]
[ -f "$3" ]
expected=$(mktemp)
trap 'rm -f "$expected"' EXIT
if /usr/bin/openssl x509 -in "$FAKE_KERNEL_CERT" -out "$expected" 2>/dev/null; then
  cmp -s "$2" "$expected"
else
  cmp -s "$2" "$FAKE_KERNEL_CERT_DER"
fi
[ "$(dd if="$3" bs=2 count=1 2>/dev/null)" = MZ ]
[ "${FAIL_SBVERIFY:-0}" != 1 ]
"#,
        );
        write_tool(
            &bin.join("modinfo"),
            r#"#!/bin/sh
set -eu
[ "$1" = -F ]
case "$2" in
  name)
    if [ "${BAD_MODULE_NAME:-0}" = 1 ] && [ "$(basename "$3")" = module-1.ko ]; then
      echo nvidia_drm
    else
      sed -n 's/^NAME=//p' "$3" | head -n 1
    fi
    ;;
  vermagic)
    if [ "${BAD_ACER_VERMAGIC:-0}" = 1 ] && [ "$(basename "$3")" = module-0.ko ]; then
      echo '7.1.8-cachyos-pt31553 SMP mod_unload'
    elif [ "${BAD_VERMAGIC:-0}" = 1 ]; then
      echo wrong-release
    else
      sed -n 's/^VERMAGIC=//p' "$3" | head -n 1
    fi
    ;;
  version)
    if [ "${BAD_MODULE_VERSION:-0}" = 1 ] && [ "$(basename "$3")" != module-0.ko ]; then
      echo 999.0
    else
      sed -n 's/^VERSION=//p' "$3" | head -n 1
    fi
    ;;
  *) exit 2 ;;
esac
"#,
        );

        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .to_path_buf();
        fs::copy(
            workspace.join("packaging/kernel/source-lock.toml"),
            artifacts.join("source-lock.toml"),
        )
        .expect("copy source lock");
        fs::copy(
            workspace.join("packaging/kernel/build-environment.toml"),
            artifacts.join("build-environment.toml"),
        )
        .expect("copy build environment");
        fs::write(artifacts.join("build.log"), b"offline build\n").expect("write build log");
        fs::write(artifacts.join("package-set.SRCINFO"), valid_srcinfo()).expect("write SRCINFO");
        let recipe = b"effective locked recipe\n";
        fs::write(artifacts.join("PKGBUILD"), recipe).expect("write effective PKGBUILD");
        let pkgbuild_hash = sha(recipe);
        let attestation = format!(
            "format = 1\nsource_lock_sha256 = \"{}\"\nbuild_environment_sha256 = \"{}\"\npkgbuild_sha256 = \"{}\"\npackage_set_srcinfo_sha256 = \"{}\"\n",
            sha_file(&artifacts.join("source-lock.toml")),
            sha_file(&artifacts.join("build-environment.toml")),
            pkgbuild_hash,
            sha_file(&artifacts.join("package-set.SRCINFO")),
        );
        fs::write(artifacts.join("build-attestation.toml"), attestation)
            .expect("write build attestation");
        fs::create_dir(artifacts.join("packages")).expect("create retained metadata root");
        let cms_log = root.join("cms.log");

        let kernel_module =
            format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst");
        let image = format!("usr/lib/modules/{RELEASE}/vmlinuz");
        let mut kernel_files = vec![
            (
                image,
                fake_kernel_image(&fake_builtin_trust_payload(
                    b"stable module certificate DER",
                )),
            ),
            (
                kernel_module,
                signed_module("acer_wmi", bad_module_signature == Some("acer_wmi")),
            ),
        ];
        if let Some((path, content)) = sensitive_package_file {
            kernel_files.push((path.to_string(), content.to_vec()));
        }
        let kernel_archive = create_package(
            &root,
            &artifacts,
            KERNEL,
            "7.1.8-1",
            &kernel_files,
            omitted_buildinfo_field,
            &pkgbuild_hash,
            "1786378335",
            "2",
            None,
        );
        let headers_archive = create_package(
            &root,
            &artifacts,
            HEADERS,
            "7.1.8-1",
            &headers_files(b"stable module certificate DER"),
            omitted_buildinfo_field,
            &pkgbuild_hash,
            "1786378335",
            "2",
            None,
        );
        let nvidia_files = NVIDIA_MODULES
            .iter()
            .map(|name| {
                (
                    format!("usr/lib/modules/{RELEASE}/extramodules/{name}.ko.zst"),
                    signed_module(&name.replace('-', "_"), bad_module_signature == Some(*name)),
                )
            })
            .collect::<Vec<_>>();
        let nvidia_archive = create_package(
            &root,
            &artifacts,
            NVIDIA,
            "7.1.8-1",
            &nvidia_files,
            omitted_buildinfo_field,
            &pkgbuild_hash,
            nvidia_builddate.unwrap_or("1786378335"),
            nvidia_buildinfo_format.unwrap_or("2"),
            nvidia_buildinfo_extra,
        );
        let _ = (kernel_archive, headers_archive, nvidia_archive);
        rewrite_sums(&artifacts);
        let manifest_signature = root.join("package-set.p7s");
        fs::write(&manifest_signature, sha_file(&artifacts.join("SHA256SUMS")))
            .expect("write manifest signature");

        Self {
            root,
            artifacts,
            bin,
            module_cert,
            module_cert_der,
            module_cert_hash,
            package_cert,
            package_cert_der,
            package_cert_hash,
            kernel_cert,
            kernel_cert_der,
            kernel_cert_hash,
            manifest_signature,
            cms_log,
            real_modinfo: false,
            real_openssl: false,
            real_sbverify: false,
        }
    }

    fn with_real_crypto() -> Self {
        let mut fixture = Self::new();
        let root = fixture.root.clone();
        let module_key = root.join("real-module.key");
        let package_key = root.join("real-package.key");
        let kernel_key = root.join("real-kernel.key");
        generate_certificate(
            &module_key,
            &fixture.module_cert,
            &fixture.module_cert_der,
            "/CN=real-package-module-signer",
        );
        generate_certificate(
            &package_key,
            &fixture.package_cert,
            &fixture.package_cert_der,
            "/CN=real-package-manifest-signer",
        );
        generate_certificate(
            &kernel_key,
            &fixture.kernel_cert,
            &fixture.kernel_cert_der,
            "/CN=real-package-kernel-signer",
        );
        fixture.module_cert_hash = sha_file(&fixture.module_cert_der);
        fixture.package_cert_hash = sha_file(&fixture.package_cert_der);
        fixture.kernel_cert_hash = sha_file(&fixture.kernel_cert_der);

        for package in [KERNEL, HEADERS, NVIDIA] {
            fs::remove_dir_all(root.join(format!("stage-{package}"))).unwrap();
            fs::remove_dir_all(fixture.artifacts.join("packages").join(package)).unwrap();
            fs::remove_file(
                fixture
                    .artifacts
                    .join(format!("{package}-7.1.8-1-x86_64.pkg.tar.zst")),
            )
            .unwrap();
        }
        let pkgbuild_hash = sha_file(&fixture.artifacts.join("PKGBUILD"));
        let kernel_files = vec![
            (
                format!("usr/lib/modules/{RELEASE}/vmlinuz"),
                fake_kernel_image(&fake_builtin_trust_payload(
                    &fs::read(&fixture.module_cert_der).unwrap(),
                )),
            ),
            (
                format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
                real_signed_module(&root, &module_key, &fixture.module_cert, "acer_wmi", 0),
            ),
        ];
        create_package(
            &root,
            &fixture.artifacts,
            KERNEL,
            "7.1.8-1",
            &kernel_files,
            None,
            &pkgbuild_hash,
            "1786378335",
            "2",
            None,
        );
        create_package(
            &root,
            &fixture.artifacts,
            HEADERS,
            "7.1.8-1",
            &headers_files(&fs::read(&fixture.module_cert_der).unwrap()),
            None,
            &pkgbuild_hash,
            "1786378335",
            "2",
            None,
        );
        let nvidia_files = NVIDIA_MODULES
            .iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    format!("usr/lib/modules/{RELEASE}/extramodules/{name}.ko.zst"),
                    real_signed_module(
                        &root,
                        &module_key,
                        &fixture.module_cert,
                        &name.replace('-', "_"),
                        index + 1,
                    ),
                )
            })
            .collect::<Vec<_>>();
        create_package(
            &root,
            &fixture.artifacts,
            NVIDIA,
            "7.1.8-1",
            &nvidia_files,
            None,
            &pkgbuild_hash,
            "1786378335",
            "2",
            None,
        );
        rewrite_sums(&fixture.artifacts);
        assert!(
            Command::new("openssl")
                .args(["cms", "-sign", "-binary", "-in"])
                .arg(fixture.artifacts.join("SHA256SUMS"))
                .arg("-signer")
                .arg(&fixture.package_cert)
                .arg("-inkey")
                .arg(&package_key)
                .args(["-outform", "DER", "-out"])
                .arg(&fixture.manifest_signature)
                .args(["-nocerts", "-noattr", "-md", "sha256"])
                .status()
                .unwrap()
                .success()
        );
        fixture.real_modinfo = true;
        fixture.real_openssl = true;
        fixture
    }

    fn with_real_module_metadata(
        target: &str,
        embedded_name: &str,
        vermagic: &str,
        version: &str,
    ) -> Self {
        let fixture = Self::with_real_crypto();
        fs::remove_dir_all(fixture.root.join(format!("stage-{NVIDIA}"))).unwrap();
        fs::remove_dir_all(fixture.artifacts.join("packages").join(NVIDIA)).unwrap();
        fs::remove_file(
            fixture
                .artifacts
                .join(format!("{NVIDIA}-7.1.8-1-x86_64.pkg.tar.zst")),
        )
        .unwrap();
        let pkgbuild_hash = sha_file(&fixture.artifacts.join("PKGBUILD"));
        let nvidia_files = NVIDIA_MODULES
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let module_name = if *name == target {
                    embedded_name.to_owned()
                } else {
                    name.replace('-', "_")
                };
                let module_vermagic = if *name == target { vermagic } else { RELEASE };
                (
                    format!("usr/lib/modules/{RELEASE}/extramodules/{name}.ko.zst"),
                    real_signed_module_with_metadata(
                        &fixture.root,
                        &fixture.root.join("real-module.key"),
                        &fixture.module_cert,
                        &module_name,
                        module_vermagic,
                        version,
                        index + 30,
                    ),
                )
            })
            .collect::<Vec<_>>();
        create_package(
            &fixture.root,
            &fixture.artifacts,
            NVIDIA,
            "7.1.8-1",
            &nvidia_files,
            None,
            &pkgbuild_hash,
            "1786378335",
            "2",
            None,
        );
        rewrite_sums(&fixture.artifacts);
        sign_real_manifest(&fixture);
        fixture
    }

    fn with_extra_nvidia_module() -> Self {
        let fixture = Self::new();
        fs::remove_dir_all(fixture.root.join(format!("stage-{NVIDIA}"))).unwrap();
        fs::remove_dir_all(fixture.artifacts.join("packages").join(NVIDIA)).unwrap();
        fs::remove_file(
            fixture
                .artifacts
                .join(format!("{NVIDIA}-7.1.8-1-x86_64.pkg.tar.zst")),
        )
        .unwrap();
        let pkgbuild_hash = sha_file(&fixture.artifacts.join("PKGBUILD"));
        let mut nvidia_files = NVIDIA_MODULES
            .iter()
            .map(|name| {
                (
                    format!("usr/lib/modules/{RELEASE}/extramodules/{name}.ko.zst"),
                    signed_module(&name.replace('-', "_"), false),
                )
            })
            .collect::<Vec<_>>();
        nvidia_files.push((
            format!("usr/lib/modules/{RELEASE}/extramodules/nvidia-extra.ko.zst"),
            signed_module("nvidia_extra", false),
        ));
        create_package(
            &fixture.root,
            &fixture.artifacts,
            NVIDIA,
            "7.1.8-1",
            &nvidia_files,
            None,
            &pkgbuild_hash,
            "1786378335",
            "2",
            None,
        );
        rewrite_sums(&fixture.artifacts);
        resign_manifest(&fixture);
        fixture
    }

    fn with_real_crypto_and_secure_boot(tamper_image: bool, overlay_only: bool) -> Option<Self> {
        let sbsign = Path::new("/usr/bin/sbsign");
        let sbverify = Path::new("/usr/bin/sbverify");
        let objcopy = Path::new("/usr/bin/objcopy");
        let stub = Path::new("/usr/lib/systemd/boot/efi/linuxx64.efi.stub");
        if !sbsign.is_file() || !sbverify.is_file() || !objcopy.is_file() || !stub.is_file() {
            return None;
        }
        let mut fixture = Self::with_real_crypto();
        let unsigned_image = fixture.root.join("real-unsigned-kernel.efi");
        fs::copy(stub, &unsigned_image).unwrap();
        if overlay_only {
            OpenOptions::new()
                .append(true)
                .open(&unsigned_image)
                .unwrap()
                .write_all(&fs::read(&fixture.module_cert_der).unwrap())
                .unwrap();
        } else {
            let payload = fixture.root.join("real-kernel-payload.bin");
            fs::write(
                &payload,
                fake_bzimage(&fake_builtin_trust_payload(
                    &fs::read(&fixture.module_cert_der).unwrap(),
                )),
            )
            .unwrap();
            let section_image = fixture.root.join("real-section-kernel.efi");
            assert!(
                Command::new(objcopy)
                    .arg("--add-section")
                    .arg(format!(".linux={}", payload.display()))
                    .arg(&unsigned_image)
                    .arg(&section_image)
                    .status()
                    .unwrap()
                    .success()
            );
            fs::rename(section_image, &unsigned_image).unwrap();
        }
        let signed_image = fixture.root.join("real-signed-kernel.efi");
        assert!(
            Command::new(sbsign)
                .arg("--key")
                .arg(fixture.root.join("real-kernel.key"))
                .arg("--cert")
                .arg(&fixture.kernel_cert)
                .arg("--output")
                .arg(&signed_image)
                .arg(&unsigned_image)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        let mut image = fs::read(signed_image).unwrap();
        if tamper_image {
            assert!(image.len() > 4096);
            image[4096] ^= 1;
        }
        fs::remove_dir_all(fixture.root.join(format!("stage-{KERNEL}"))).unwrap();
        fs::remove_dir_all(fixture.artifacts.join("packages").join(KERNEL)).unwrap();
        fs::remove_file(
            fixture
                .artifacts
                .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst")),
        )
        .unwrap();
        let pkgbuild_hash = sha_file(&fixture.artifacts.join("PKGBUILD"));
        create_package(
            &fixture.root,
            &fixture.artifacts,
            KERNEL,
            "7.1.8-1",
            &[
                (format!("usr/lib/modules/{RELEASE}/vmlinuz"), image),
                (
                    format!(
                        "usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"
                    ),
                    real_signed_module(
                        &fixture.root,
                        &fixture.root.join("real-module.key"),
                        &fixture.module_cert,
                        "acer_wmi",
                        20,
                    ),
                ),
            ],
            None,
            &pkgbuild_hash,
            "1786378335",
            "2",
            None,
        );
        rewrite_sums(&fixture.artifacts);
        sign_real_manifest(&fixture);
        fixture.real_sbverify = true;
        Some(fixture)
    }

    fn replace_headers(&self, files: &[(String, Vec<u8>)]) {
        fs::remove_dir_all(self.root.join(format!("stage-{HEADERS}"))).unwrap();
        fs::remove_dir_all(self.artifacts.join("packages").join(HEADERS)).unwrap();
        fs::remove_file(
            self.artifacts
                .join(format!("{HEADERS}-7.1.8-1-x86_64.pkg.tar.zst")),
        )
        .unwrap();
        create_package(
            &self.root,
            &self.artifacts,
            HEADERS,
            "7.1.8-1",
            files,
            None,
            &sha_file(&self.artifacts.join("PKGBUILD")),
            "1786378335",
            "2",
            None,
        );
        rewrite_sums(&self.artifacts);
        if self.real_openssl {
            sign_real_manifest(self);
        } else {
            resign_manifest(self);
        }
    }

    fn run(&self) -> Output {
        self.command().output().expect("run provenance verifier")
    }

    fn command(&self) -> Command {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .to_path_buf();
        let source = r#"
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import sys
script = pathlib.Path(sys.argv[1])
tools = pathlib.Path(sys.argv[2])
loader = importlib.machinery.SourceFileLoader("package_provenance_fixture", str(script))
spec = importlib.util.spec_from_loader("package_provenance_fixture", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
loaded.REQUIRE_ROOT_OWNED_TOOLS = False
loaded.SUBPROCESS_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "OPENSSL_CONF": "/dev/null",
    "PATH": "/usr/bin",
}
for name in (
    "BAD_ACER_VERMAGIC", "BAD_MODULE_NAME", "BAD_MODULE_VERSION", "BAD_VERMAGIC", "FAIL_CMS", "FAIL_SBVERIFY", "FAKE_CMS_LOG",
    "FAKE_KERNEL_CERT", "FAKE_KERNEL_CERT_DER", "FAKE_MODULE_CERT",
    "FAKE_MODULE_CERT_DER", "FAKE_PACKAGE_CERT", "FAKE_PACKAGE_CERT_DER", "WEAK_CMS",
):
    if name in os.environ:
        loaded.SUBPROCESS_ENV[name] = os.environ[name]
if os.environ.get("REAL_MODINFO") != "1":
    loaded.TOOLS["modinfo"] = tools / "modinfo"
if sys.argv[3] == "fake-openssl":
    loaded.TOOLS["openssl"] = tools / "openssl"
    loaded.canonical_sensitive_artifact_inspection = lambda *args: None
if sys.argv[4] == "fake-sbverify":
    loaded.TOOLS["sbverify"] = tools / "sbverify"
if (tools / "bsdtar").is_file():
    loaded.TOOLS["bsdtar"] = tools / "bsdtar"
original_parse_policy = loaded.parse_policy
def fixture_policy(path):
    policy = original_parse_policy(path)
    if "TEST_MODULE_POLICY_SHA256" in os.environ:
        policy["package_signer_sha256"] = os.environ["TEST_PACKAGE_POLICY_SHA256"]
        policy["module_signer_sha256"] = os.environ["TEST_MODULE_POLICY_SHA256"]
        policy["kernel_image_signer_sha256"] = os.environ["TEST_KERNEL_POLICY_SHA256"]
    return policy
loaded.parse_policy = fixture_policy
original_validate_schema_policy = loaded.validate_schema_policy
def fixture_schema_policy(path, policy):
    schema = json.loads(path.read_text())
    schema["properties"]["build"]["properties"]["package_manifest_signer_fingerprint"]["const"] = policy["package_signer_sha256"]
    schema["$defs"]["module"]["properties"]["signer_fingerprint"]["const"] = policy["module_signer_sha256"]
    schema["properties"]["kernel"]["properties"]["module_trust_certificate_fingerprint"]["const"] = policy["module_signer_sha256"]
    schema["properties"]["kernel"]["properties"]["image_signer_fingerprint"]["const"] = policy["kernel_image_signer_sha256"]
    fixture_schema = tools / "fixture-package-provenance-schema.json"
    fixture_schema.write_text(json.dumps(schema))
    original_validate_schema_policy(fixture_schema, policy)
loaded.validate_schema_policy = fixture_schema_policy
original_validate_compatibility_policy = loaded.validate_compatibility_policy
def fixture_compatibility_policy(compatibility, policy):
    compatibility["module"]["signer_fingerprint"] = policy["module_signer_sha256"]
    compatibility["kernel"]["image_signer_fingerprint"] = policy["kernel_image_signer_sha256"]
    compatibility["module"]["vermagic"] = policy["kernel_release"] + " SMP preempt mod_unload"
    original_validate_compatibility_policy(compatibility, policy)
loaded.validate_compatibility_policy = fixture_compatibility_policy
sys.argv = [str(script), *sys.argv[5:]]
try:
    raise SystemExit(loaded.main())
except loaded.VerificationError as error:
    print(f"verify-package-provenance: {error}", file=sys.stderr)
    raise SystemExit(1)
"#;
        let mut command = Command::new("python3");
        command
            .args(["-c", source])
            .arg(workspace.join("scripts/verify-package-provenance"))
            .arg(&self.bin)
            .arg(if self.real_openssl {
                "real-openssl"
            } else {
                "fake-openssl"
            })
            .arg(if self.real_sbverify {
                "real-sbverify"
            } else {
                "fake-sbverify"
            })
            .args(["--artifacts"])
            .arg(&self.artifacts)
            .args(["--module-cert"])
            .arg(&self.module_cert)
            .args(["--module-cert-sha256", &self.module_cert_hash])
            .args(["--package-cert"])
            .arg(&self.package_cert)
            .args(["--package-cert-sha256", &self.package_cert_hash])
            .args(["--kernel-cert"])
            .arg(&self.kernel_cert)
            .args(["--kernel-cert-sha256", &self.kernel_cert_hash])
            .args(["--package-manifest-signature"])
            .arg(&self.manifest_signature)
            .args(["--output"])
            .arg(self.root.join("provenance.json"))
            .env("FAKE_MODULE_CERT", &self.module_cert)
            .env("FAKE_MODULE_CERT_DER", &self.module_cert_der)
            .env("FAKE_PACKAGE_CERT", &self.package_cert)
            .env("FAKE_PACKAGE_CERT_DER", &self.package_cert_der)
            .env("FAKE_KERNEL_CERT", &self.kernel_cert)
            .env("FAKE_KERNEL_CERT_DER", &self.kernel_cert_der)
            .env("FAKE_CMS_LOG", &self.cms_log);
        command
            .env("TEST_PACKAGE_POLICY_SHA256", &self.package_cert_hash)
            .env("TEST_MODULE_POLICY_SHA256", &self.module_cert_hash)
            .env("TEST_KERNEL_POLICY_SHA256", &self.kernel_cert_hash);
        if self.real_modinfo {
            command.env("REAL_MODINFO", "1");
        }
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).ok();
    }
}

#[test]
fn verifies_exact_packages_signers_modules_and_build_provenance_offline() {
    let fixture = Fixture::new();
    let output = fixture.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.root.join("provenance.json")).expect("read evidence"),
    )
    .expect("parse evidence");
    let schema = schema_for_fixture(&fixture);
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&evidence)
    );
    assert_eq!(evidence["kernel"]["release"], RELEASE);
    assert_eq!(
        evidence["kernel"]["image_sha256"],
        sha(&fake_kernel_image(&fake_builtin_trust_payload(
            b"stable module certificate DER"
        )))
    );
    assert_eq!(
        evidence["build"]["package_manifest_signer_fingerprint"],
        fixture.package_cert_hash
    );
    assert_eq!(
        evidence["kernel"]["module_trust_certificate_fingerprint"],
        fixture.module_cert_hash
    );
    assert_eq!(
        evidence["kernel"]["config_path"],
        format!("/usr/lib/modules/{RELEASE}/build/.config")
    );
    assert_eq!(
        evidence["kernel"]["image_signer_fingerprint"],
        fixture.kernel_cert_hash
    );
    assert_eq!(evidence["packages"].as_array().unwrap().len(), 3);
    assert_eq!(evidence["modules"].as_array().unwrap().len(), 6);
    assert_eq!(evidence["modules"][0]["name"], "acer_wmi");
    assert_eq!(
        evidence["modules"][0]["path"],
        format!("/usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst")
    );
    assert_eq!(evidence["modules"][0]["package"], KERNEL);
    assert_eq!(evidence["modules"][0]["provenance"], "in-tree");
    assert_eq!(evidence["modules"][0]["source"]["kind"], "kernel-tree");
    assert_eq!(evidence["modules"][1]["source"]["revision"], "610.57.04");
    assert_eq!(
        fs::read_to_string(&fixture.cms_log)
            .expect("read CMS invocation log")
            .lines()
            .collect::<Vec<_>>(),
        [
            "module-0.signed",
            "module-1.signed",
            "module-2.signed",
            "module-3.signed",
            "module-4.signed",
            "module-5.signed",
        ]
    );
    assert!(
        evidence["modules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|module| module["sha256"].as_str().unwrap().len() == 64
                && module["signer_fingerprint"] == fixture.module_cert_hash
                && module["vermagic"].as_str().unwrap().starts_with(RELEASE))
    );
    assert_eq!(
        evidence["build"]["source_lock_sha256"],
        sha_file(&fixture.artifacts.join("source-lock.toml"))
    );
    assert_eq!(
        evidence["build"]["build_environment_sha256"],
        sha_file(&fixture.artifacts.join("build-environment.toml"))
    );
    assert_eq!(
        evidence["build"]["pkgbuild_sha256"],
        sha_file(&fixture.artifacts.join("PKGBUILD"))
    );
    assert_eq!(
        evidence["build"]["build_attestation_sha256"],
        sha_file(&fixture.artifacts.join("build-attestation.toml"))
    );
    assert_eq!(
        evidence["build"]["package_set_srcinfo_sha256"],
        sha_file(&fixture.artifacts.join("package-set.SRCINFO"))
    );
    for package in evidence["packages"].as_array().unwrap() {
        let archive = fixture.artifacts.join(format!(
            "{}-{}-x86_64.pkg.tar.zst",
            package["name"].as_str().unwrap(),
            package["version"].as_str().unwrap()
        ));
        assert_eq!(package["sha256"], sha_file(&archive));
    }
    for module in evidence["modules"].as_array().unwrap() {
        let package = module["package"].as_str().unwrap();
        let archive = fixture
            .artifacts
            .join(format!("{package}-7.1.8-1-x86_64.pkg.tar.zst"));
        let member = module["path"].as_str().unwrap().trim_start_matches('/');
        let extracted = Command::new("tar")
            .args(["--zstd", "-xOf"])
            .arg(archive)
            .arg(member)
            .output()
            .expect("extract module for expected digest");
        assert!(extracted.status.success());
        assert_eq!(module["sha256"], sha(&extracted.stdout));
    }
    let package_identities = evidence["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| {
            (
                package["name"].as_str().unwrap(),
                package["version"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        package_identities,
        vec![
            (KERNEL, "7.1.8-1"),
            (HEADERS, "7.1.8-1"),
            (NVIDIA, "7.1.8-1")
        ]
    );
    let serialized = serde_json::to_string(&evidence).expect("serialize evidence");
    assert!(!serialized.contains(&fixture.root.to_string_lossy().to_string()));
    assert!(!serialized.contains("PUBLIC MODULE CERTIFICATE"));
}

#[test]
fn full_path_normalizes_real_x509_and_verifies_real_detached_cms() {
    let fixture = Fixture::with_real_crypto();
    let output = fixture.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(
        evidence["kernel"]["image_signer_fingerprint"],
        fixture.kernel_cert_hash
    );
    assert!(
        evidence["modules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|module| module["signer_fingerprint"] == fixture.module_cert_hash)
    );
}

#[test]
fn command_line_fingerprints_cannot_override_reviewed_signer_policy() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env_remove("TEST_PACKAGE_POLICY_SHA256")
        .env_remove("TEST_MODULE_POLICY_SHA256")
        .env_remove("TEST_KERNEL_POLICY_SHA256")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "accepted CLI-selected trust roots over the reviewed policy"
    );
}

#[test]
fn verifier_subprocesses_ignore_loader_and_openssl_environment_injection() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env("LD_PRELOAD", "/attacker-controlled/not-present.so")
        .env("OPENSSL_CONF", "/attacker-controlled/openssl.cnf")
        .env("OPENSSL_MODULES", "/attacker-controlled/providers")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn schema_rejects_duplicate_and_misbound_package_or_module_identities() {
    let fixture = Fixture::new();
    assert!(fixture.run().status.success());
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("provenance.json")).unwrap()).unwrap();
    let schema = schema_for_fixture(&fixture);
    let validator = jsonschema::validator_for(&schema).unwrap();

    evidence["modules"][0] = evidence["modules"][1].clone();
    assert!(!validator.is_valid(&evidence));

    let mut evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("provenance.json")).unwrap()).unwrap();
    evidence["modules"][1]["source"] = serde_json::json!({
        "kind": "kernel-tree",
        "revision": "7a84732fd5e4350c1312fd0ed0c72ffa139fb766"
    });
    assert!(!validator.is_valid(&evidence));

    let mut evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("provenance.json")).unwrap()).unwrap();
    evidence["packages"][1] = evidence["packages"][0].clone();
    assert!(!validator.is_valid(&evidence));
}

#[test]
fn schema_policy_binding_fails_closed_on_identity_drift() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let original: serde_json::Value = serde_json::from_slice(
        &fs::read(workspace.join("schemas/package-provenance-v1.json")).unwrap(),
    )
    .unwrap();
    let root = std::env::temp_dir().join(format!(
        "fan-control-schema-policy-drift-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    assert!(
        call_schema_policy_validator(
            &workspace,
            &workspace.join("schemas/package-provenance-v1.json")
        )
        .status
        .success()
    );
    for (case, pointer, replacement) in [
        (
            "candidate",
            "/properties/candidate/const",
            "wrong-candidate",
        ),
        (
            "architecture",
            "/$defs/package/properties/architecture/const",
            "aarch64",
        ),
        (
            "kernel-package",
            "/$defs/kernel_package/allOf/1/properties/name/const",
            "linux-wrong",
        ),
        (
            "headers-package",
            "/$defs/headers_package/allOf/1/properties/name/const",
            "linux-wrong-headers",
        ),
        (
            "nvidia-package",
            "/$defs/nvidia_package/allOf/1/properties/name/const",
            "linux-wrong-nvidia",
        ),
        (
            "kernel-image-path",
            "/properties/kernel/properties/image_path/const",
            "/usr/lib/modules/wrong/vmlinuz",
        ),
        (
            "nvidia-source",
            "/$defs/nvidia_module_template/allOf/1/properties/source/const/revision",
            "999.0",
        ),
        (
            "nvidia-module-path",
            "/$defs/nvidia_module/properties/path/const",
            "/usr/lib/modules/wrong/nvidia.ko.zst",
        ),
        (
            "package-version",
            "/$defs/package/properties/version/const",
            "7.1.9-1",
        ),
        (
            "module-path",
            "/$defs/acer_module/allOf/1/properties/path/const",
            "/usr/lib/modules/wrong/acer-wmi.ko.zst",
        ),
        (
            "kernel-release",
            "/properties/kernel/properties/release/const",
            "7.1.9-cachyos-pt31553",
        ),
        (
            "module-vermagic",
            "/$defs/module/properties/vermagic/const",
            "7.1.8-cachyos-pt31553 mod_unload",
        ),
        (
            "source-identity",
            "/properties/build/properties/source_commit/const",
            "0000000000000000000000000000000000000000",
        ),
        (
            "module-signer",
            "/$defs/module/properties/signer_fingerprint/const",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "package-signer",
            "/properties/build/properties/package_manifest_signer_fingerprint/const",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "module-trust-signer",
            "/properties/kernel/properties/module_trust_certificate_fingerprint/const",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "kernel-config-path",
            "/properties/kernel/properties/config_path/const",
            "/usr/lib/modules/wrong/.config",
        ),
        (
            "module-trust-certificate-path",
            "/properties/kernel/properties/module_trust_certificate_path/const",
            "/usr/lib/modules/wrong/signing_key.x509",
        ),
        (
            "kernel-image-signer",
            "/properties/kernel/properties/image_signer_fingerprint/const",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = serde_json::Value::String(replacement.into());
        let path = root.join(format!("{case}.json"));
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let output = call_schema_policy_validator(&workspace, &path);
        assert!(
            !output.status.success(),
            "accepted {case} schema-policy drift"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn compatibility_policy_binding_fails_closed_on_identity_drift() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let compatibility = workspace.join("compatibility/pt315-53.toml");
    let original: toml::Value =
        toml::from_str(&fs::read_to_string(&compatibility).unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "fan-control-compatibility-policy-drift-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    assert!(
        call_compatibility_policy_validator(&workspace, &compatibility)
            .status
            .success()
    );
    for (case, section, field, replacement) in [
        ("kernel-release", "kernel", "release", "wrong-release"),
        ("kernel-package", "kernel", "package", "linux-wrong"),
        (
            "source-commit",
            "kernel",
            "source_commit",
            "0000000000000000000000000000000000000000",
        ),
        (
            "image-signer",
            "kernel",
            "image_signer_fingerprint",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("module-name", "module", "name", "wrong_module"),
        (
            "module-path",
            "module",
            "path",
            "/usr/lib/modules/wrong/acer-wmi.ko.zst",
        ),
        (
            "module-signer",
            "module",
            "signer_fingerprint",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        (
            "module-vermagic",
            "module",
            "vermagic",
            "wrong-release SMP preempt mod_unload",
        ),
    ] {
        let mut changed = original.clone();
        changed[section][field] = toml::Value::String(replacement.into());
        let path = root.join(format!("{case}.toml"));
        fs::write(&path, toml::to_string(&changed).unwrap()).unwrap();
        let output = call_compatibility_policy_validator(&workspace, &path);
        assert!(
            !output.status.success(),
            "accepted {case} compatibility-policy drift"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_canonical_archive_path_aliases() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    for member in [
        "usr/lib/modules/release/kernel/./drivers/acer-wmi.ko.zst",
        "usr/lib/modules/release/kernel//drivers/acer-wmi.ko.zst",
        "usr/lib/modules/release/kernel/../acer-wmi.ko.zst",
    ] {
        assert!(
            !call_safe_member_validator(&workspace, member)
                .status
                .success(),
            "accepted canonical path alias {member}"
        );
    }
    assert!(
        call_safe_member_validator(&workspace, "usr/lib/modules/")
            .status
            .success()
    );
}

#[test]
fn system_modinfo_rejects_real_module_identity_mismatches() {
    for (case, embedded_name, vermagic, version) in [
        ("name", "nvidia_drm", RELEASE, "610.57.04"),
        ("vermagic", "nvidia", "wrong-release", "610.57.04"),
        (
            "vermagic-flags",
            "nvidia",
            &format!("{RELEASE} SMP"),
            "610.57.04",
        ),
        ("source-version", "nvidia", RELEASE, "999.0"),
    ] {
        let fixture =
            Fixture::with_real_module_metadata("nvidia", embedded_name, vermagic, version);
        let output = fixture.run();
        assert!(
            !output.status.success(),
            "system modinfo accepted real module {case} mismatch"
        );
        assert!(!fixture.root.join("provenance.json").exists());
    }

    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env("BAD_ACER_VERMAGIC", "1")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "accepted acer_wmi vermagic that drifted from the compatibility declaration"
    );
}

#[test]
fn rejects_an_extra_nvidia_module() {
    let fixture = Fixture::with_extra_nvidia_module();
    let output = fixture.run();
    assert!(!output.status.success(), "accepted an extra NVIDIA module");
    assert!(!fixture.root.join("provenance.json").exists());
}

#[test]
fn rejects_signature_trust_and_identity_mismatches() {
    for variable in [
        "FAIL_CMS",
        "WEAK_CMS",
        "FAIL_SBVERIFY",
        "BAD_VERMAGIC",
        "BAD_MODULE_VERSION",
    ] {
        let fixture = Fixture::new();
        let output = fixture
            .command()
            .env(variable, "1")
            .output()
            .expect("run verifier");
        assert!(
            !output.status.success(),
            "accepted mismatch controlled by {variable}"
        );
        assert!(!fixture.root.join("provenance.json").exists());
    }

    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env("BAD_MODULE_NAME", "1")
        .output()
        .expect("run verifier with mismatched module name");
    assert!(
        !output.status.success(),
        "accepted mismatched module identity"
    );
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args(["--module-cert-sha256", &"0".repeat(64)])
        .output()
        .expect("run verifier");
    assert!(
        !output.status.success(),
        "accepted wrong certificate fingerprint"
    );

    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args(["--kernel-cert"])
        .arg(&fixture.module_cert)
        .args(["--kernel-cert-sha256", &fixture.module_cert_hash])
        .output()
        .expect("run verifier with swapped image signer");
    assert!(
        !output.status.success(),
        "accepted the module signer for the image"
    );

    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args(["--module-cert"])
        .arg(&fixture.kernel_cert)
        .args(["--module-cert-sha256", &fixture.kernel_cert_hash])
        .output()
        .expect("run verifier with swapped module signer");
    assert!(
        !output.status.success(),
        "accepted the image signer for modules"
    );

    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args(["--package-cert"])
        .arg(&fixture.module_cert)
        .args(["--package-cert-sha256", &fixture.module_cert_hash])
        .env("TEST_PACKAGE_POLICY_SHA256", &fixture.module_cert_hash)
        .output()
        .expect("run verifier with a reused package signer");
    assert!(
        !output.status.success(),
        "accepted one certificate for package and module signing"
    );
}

#[test]
fn rejects_missing_or_drifted_packaged_kernel_module_trust() {
    let fixture = Fixture::new();
    let mut files = headers_files(b"stable module certificate DER");
    files.retain(|(path, _)| !path.ends_with("/.config"));
    fixture.replace_headers(&files);
    assert!(
        !fixture.run().status.success(),
        "accepted headers without the kernel configuration"
    );

    let fixture = Fixture::new();
    let mut files = headers_files(b"stable module certificate DER");
    files
        .iter_mut()
        .find(|(path, _)| path.ends_with("/.config"))
        .unwrap()
        .1 = b"CONFIG_MODULE_SIG=n\nCONFIG_MODULE_SIG_ALL=n\nCONFIG_MODULE_SIG_SHA512=n\nCONFIG_MODULE_SIG_KEY=\"\"\nCONFIG_SYSTEM_TRUSTED_KEYS=\"\"\n".to_vec();
    fixture.replace_headers(&files);
    assert!(
        !fixture.run().status.success(),
        "accepted a kernel configuration that disables module signing"
    );

    let fixture = Fixture::new();
    let files = headers_files(b"different public certificate DER");
    fixture.replace_headers(&files);
    assert!(
        !fixture.run().status.success(),
        "accepted a packaged module trust certificate with the wrong identity"
    );
}

#[test]
fn rejects_private_keys_and_ambiguous_artifacts_without_emitting_evidence() {
    let fixture = Fixture::new();
    fs::write(&fixture.module_cert, private_key_pem(""))
        .expect("replace certificate with private key");
    let output = fixture.run();
    assert!(!output.status.success(), "accepted private key input");
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::with_real_crypto();
    let (der_key, _) = binary_key_and_certificate();
    OpenOptions::new()
        .append(true)
        .open(&fixture.module_cert)
        .unwrap()
        .write_all(&der_key)
        .unwrap();
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted a valid pinned certificate with appended DER private-key material"
    );
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::new();
    let (der_key, _) = binary_key_and_certificate();
    let mut wrapped_key = b"retained log prefix\n".to_vec();
    wrapped_key.extend(der_key);
    fs::write(fixture.artifacts.join("build.log"), wrapped_key).unwrap();
    rewrite_sums(&fixture.artifacts);
    fs::write(
        &fixture.manifest_signature,
        sha_file(&fixture.artifacts.join("SHA256SUMS")),
    )
    .unwrap();
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted wrapped DER key in retained evidence"
    );
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::new();
    fs::write(fixture.artifacts.join("build.log"), private_key_pem("DSA "))
        .expect("inject private key into retained build log");
    rewrite_sums(&fixture.artifacts);
    fs::write(
        &fixture.manifest_signature,
        sha_file(&fixture.artifacts.join("SHA256SUMS")),
    )
    .expect("resign sensitive manifest fixture");
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted correctly signed sensitive retained evidence"
    );
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::new();
    fs::write(fixture.artifacts.join("unexpected.log"), b"ambiguous\n")
        .expect("write unexpected artifact");
    let output = fixture.run();
    assert!(!output.status.success(), "accepted ambiguous artifact set");
    assert!(!fixture.root.join("provenance.json").exists());
}

#[test]
fn accepts_benign_deep_base64_alphabet_path_content() {
    let structured = (0..17)
        .map(|index| format!("field{index:04}: value{index:04}"))
        .collect::<Vec<_>>()
        .join(" ");
    let deep_path = std::iter::once("src".to_string())
        .chain(std::iter::once("a".to_string()))
        .chain((0..20).map(|index| format!("Module{index:02}")))
        .collect::<Vec<_>>()
        .join("/");
    let long_deep_path = (0..20)
        .map(|index| format!("DirectoryName{index:02}"))
        .collect::<Vec<_>>()
        .join("/");
    let boundary_path = (0..18)
        .map(|index| format!("DirectoryName{index:03}"))
        .collect::<Vec<_>>()
        .join("/");
    let content =
        format!("{deep_path}\n{structured}\n{long_deep_path}\n{structured}\n{boundary_path}\n");
    let fixture = Fixture::with_sensitive_package_file(
        "usr/share/doc/benign-deep-path.txt",
        content.as_bytes(),
    );
    let output = fixture.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_private_jwks_in_packages_and_retained_evidence() {
    let jwk = private_jwk();
    let fixture = Fixture::with_sensitive_package_file("usr/share/doc/release.json", &jwk);
    let output = fixture.run();
    assert!(!output.status.success(), "accepted packaged private JWK");
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::new();
    fs::write(fixture.artifacts.join("build.log"), &jwk).unwrap();
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    let output = fixture.run();
    assert!(!output.status.success(), "accepted retained private JWK");
    assert!(!fixture.root.join("provenance.json").exists());
}

#[test]
fn rejects_age_secret_identities_in_packages_and_retained_evidence() {
    let age_secret = age_secret_fixture();
    assert_sensitive_package_rejected("usr/share/doc/release-key.txt", &age_secret);
    assert_sensitive_package_rejected(
        "usr/share/doc/encoded-release-key.txt",
        &base64_bytes(&age_secret),
    );

    let fixture = Fixture::new();
    fs::write(fixture.artifacts.join("build.log"), &age_secret).unwrap();
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    assert!(
        !fixture.run().status.success(),
        "accepted a retained age secret identity"
    );
    assert!(!fixture.root.join("provenance.json").exists());
}

#[test]
fn private_jwk_detection_fails_closed_on_binary_prefixes_and_scan_exhaustion() {
    let mut binary_prefixed = vec![0xff];
    binary_prefixed.extend(private_jwk());
    let fixture = Fixture::with_sensitive_package_file(
        "usr/share/doc/binary-prefixed-release.json",
        &binary_prefixed,
    );
    assert!(
        !fixture.run().status.success(),
        "accepted binary-prefixed private JWK"
    );

    let mut exhausted = b"[".repeat(4096);
    exhausted.extend(private_jwk());
    let fixture =
        Fixture::with_sensitive_package_file("usr/share/doc/exhausted-release.json", &exhausted);
    assert!(
        !fixture.run().status.success(),
        "accepted exhausted JWK scan budget"
    );
}

#[test]
fn rejects_putty_private_keys_in_packages_and_retained_evidence() {
    let mut putty = vec![0xff];
    putty.extend(putty_private_key());
    for (path, content) in [
        (
            "usr/share/doc/release.ppk",
            b"public-looking data".as_slice(),
        ),
        ("usr/share/doc/release-key.txt", putty.as_slice()),
    ] {
        let fixture = Fixture::with_sensitive_package_file(path, content);
        assert!(
            !fixture.run().status.success(),
            "accepted packaged PuTTY key {path}"
        );
    }

    let compressed_putty = gzip_bytes(&putty_private_key());
    let fixture = Fixture::with_sensitive_package_file(
        "usr/share/doc/compressed-release-key.txt.gz",
        &compressed_putty,
    );
    assert!(
        !fixture.run().status.success(),
        "accepted compressed packaged PuTTY private key"
    );

    let fixture = Fixture::new();
    fs::write(fixture.artifacts.join("build.log"), putty).unwrap();
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    assert!(
        !fixture.run().status.success(),
        "accepted retained PuTTY private key"
    );
}

#[test]
fn rejects_a_packaged_module_with_an_invalid_detached_signature() {
    let fixture = Fixture::with_bad_module_signature("nvidia-drm");
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted a packaged module whose detached signature does not match"
    );
    assert!(!fixture.root.join("provenance.json").exists());
}

#[test]
fn permits_unrelated_in_tree_kernel_modules() {
    let fixture = Fixture::with_extra_module();
    let output = fixture.run();
    assert!(
        output.status.success(),
        "rejected a normal in-tree kernel module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("provenance.json")).unwrap()).unwrap();
    assert!(
        evidence["modules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|module| module["name"] != "unexpected")
    );
}

#[test]
fn rejects_protected_module_names_outside_exact_policy_paths() {
    let duplicate = signed_module("acer_wmi", false);
    let fixture = Fixture::with_sensitive_package_file(
        &format!("usr/lib/modules/{RELEASE}/kernel/drivers/misc/acer-wmi.ko.zst"),
        &duplicate,
    );
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted duplicate protected acer_wmi module"
    );
    assert!(!fixture.root.join("provenance.json").exists());

    for module_name in [
        "nvidia",
        "nvidia_drm",
        "nvidia_modeset",
        "nvidia_peermem",
        "nvidia_uvm",
    ] {
        let disguised = signed_module(module_name, false);
        let fixture = Fixture::with_sensitive_package_file(
            &format!("usr/lib/modules/{RELEASE}/kernel/drivers/misc/innocent.ko.zst"),
            &disguised,
        );
        let output = fixture.run();
        assert!(
            !output.status.success(),
            "accepted protected embedded module identity {module_name} under an unrelated filename"
        );
        assert!(!fixture.root.join("provenance.json").exists());
    }
}

#[test]
fn rejects_unlisted_private_key_algorithms_in_retained_evidence() {
    let fixture = Fixture::with_real_crypto();
    let mut embedded_key = b"ordinary build-log prefix\n".to_vec();
    embedded_key.extend(binary_dh_private_key());
    fs::write(fixture.artifacts.join("build.log"), embedded_key).unwrap();
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted a raw DH PKCS#8 private key"
    );
    assert!(!fixture.root.join("provenance.json").exists());
}

#[test]
fn compatibility_changes_trigger_both_package_provenance_workflows() {
    let workflow = include_str!("../../../.github/workflows/package-provenance.yml");
    let (_, after_pull_request) = workflow.split_once("  pull_request:\n").unwrap();
    let (pull_request, after_push) = after_pull_request.split_once("  push:\n").unwrap();
    let (push, _) = after_push.split_once("\npermissions:\n").unwrap();
    for (event, paths) in [("pull_request", pull_request), ("push", push)] {
        assert!(
            paths.contains("- \"compatibility/pt315-53.toml\""),
            "{event} does not trigger package provenance verification for compatibility drift"
        );
    }
}

#[test]
fn rejects_swapped_archive_names_and_sensitive_package_content() {
    let fixture = Fixture::new();
    let kernel = fixture
        .artifacts
        .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst"));
    let nvidia = fixture
        .artifacts
        .join(format!("{NVIDIA}-7.1.8-1-x86_64.pkg.tar.zst"));
    let temporary = fixture.artifacts.join("swapped.tmp");
    fs::rename(&kernel, &temporary).unwrap();
    fs::rename(&nvidia, &kernel).unwrap();
    fs::rename(&temporary, &nvidia).unwrap();
    rewrite_sums(&fixture.artifacts);
    fs::write(
        &fixture.manifest_signature,
        sha_file(&fixture.artifacts.join("SHA256SUMS")),
    )
    .unwrap();
    let output = fixture.run();
    assert!(!output.status.success(), "accepted swapped archive names");
    assert!(!fixture.root.join("provenance.json").exists());

    let private_key = private_key_pem("");
    let encrypted_private_key = private_key_pem("ENCRYPTED ");
    let certificate = certificate_fixture(b"machine trust");
    for (path, content) in [
        (
            "usr/share/doc/build-notes.txt",
            encrypted_private_key.as_slice(),
        ),
        (
            "usr/share/ca-certificates/machine.crt",
            certificate.as_slice(),
        ),
        (
            "usr/share/doc/compressed-secret.zst",
            private_key.as_slice(),
        ),
    ] {
        let fixture = Fixture::with_sensitive_package_file(path, content);
        let output = fixture.run();
        assert!(
            !output.status.success(),
            "accepted sensitive package member {path}"
        );
        assert!(!fixture.root.join("provenance.json").exists());
    }

    let (der_key, der_cert) = binary_key_and_certificate();
    let mut wrapped_key = b"prefix".to_vec();
    wrapped_key.extend(der_key);
    let mut wrapped_cert = b"prefix".to_vec();
    wrapped_cert.extend(der_cert);
    for (path, content) in [
        ("usr/share/doc/key-material.bin", wrapped_key),
        ("usr/share/doc/trust-material.bin", wrapped_cert),
        (
            "usr/share/doc/native-key.bin",
            [b"openssh-key-".as_slice(), b"v1\0binary private key"].concat(),
        ),
    ] {
        let fixture = Fixture::with_sensitive_package_file(path, &content);
        let output = fixture.run();
        assert!(
            !output.status.success(),
            "accepted binary sensitive package member {path}"
        );
        assert!(!fixture.root.join("provenance.json").exists());
    }

    let x25519_key = binary_x25519_key();
    let mut wrapped_x25519_key = b"ordinary build note\n".to_vec();
    wrapped_x25519_key.extend(x25519_key);
    let fixture = Fixture::with_sensitive_package_file(
        "usr/share/doc/wrapped-modern-key.bin",
        &wrapped_x25519_key,
    );
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted a wrapped X25519 package key"
    );

    let compressed_x25519_key = bzip2_bytes(&binary_x25519_key());
    let fixture = Fixture::with_sensitive_package_file(
        "usr/share/doc/compressed-modern-key.bin",
        &compressed_x25519_key,
    );
    assert!(
        !fixture.run().status.success(),
        "accepted a BZip2-compressed packaged private key"
    );

    let zipped_key = zip_with_private_key();
    let fixture =
        Fixture::with_sensitive_package_file("usr/share/doc/nested-private-key.zip", &zipped_key);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted an opaque nested ZIP containing private-key material"
    );

    let tarred_key = tar_gz_with_private_key();
    let fixture = Fixture::with_sensitive_package_file(
        "usr/share/doc/nested-private-key.tar.gz",
        &tarred_key,
    );
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted an opaque nested tar archive containing private-key material"
    );
}

#[test]
fn rejects_legacy_key_encodings_and_prefixed_sensitive_containers() {
    let encrypted = encrypted_pkcs8_der();
    let base64_encrypted = base64_bytes(&encrypted);
    let prefixed_base64_encrypted = [b"AAA".as_slice(), base64_encrypted.as_slice()].concat();
    let suffixed_base64_encrypted = [base64_encrypted.as_slice(), b"AAA".as_slice()].concat();
    let long_suffixed_base64_encrypted =
        [base64_encrypted.as_slice(), b"AAAAAAAA".as_slice()].concat();
    let internal_padding_base64_encrypted =
        [b"AAAA=".as_slice(), base64_encrypted.as_slice()].concat();
    let mut fragmented_padding_base64_encrypted = Vec::new();
    for (index, chunk) in base64_encrypted.chunks(32).enumerate() {
        if index > 0 {
            fragmented_padding_base64_encrypted.push(b'=');
        }
        fragmented_padding_base64_encrypted.extend_from_slice(chunk);
    }
    let independently_padded_chunks = encrypted.chunks(23).map(base64_bytes).collect::<Vec<_>>();
    let independently_padded_base64_encrypted = independently_padded_chunks.join(&b'\n');
    let prefixed_independently_padded_base64_encrypted = independently_padded_chunks
        .iter()
        .map(|chunk| [b"A".as_slice(), chunk.as_slice()].concat())
        .collect::<Vec<_>>()
        .join(&b'\n');
    let suffixed_independently_padded_base64_encrypted = independently_padded_chunks
        .iter()
        .map(|chunk| [chunk.as_slice(), b"A".as_slice()].concat())
        .collect::<Vec<_>>()
        .join(&b'\n');
    let junk_fragmented_base64_encrypted = encrypted
        .chunks(23)
        .map(base64_bytes)
        .collect::<Vec<_>>()
        .join(b"AA==".as_slice());
    let variably_prefixed_independently_padded_base64_private = binary_x25519_key()
        .chunks(23)
        .enumerate()
        .map(|(index, chunk)| {
            let prefix = if index % 2 == 0 {
                b"A".as_slice()
            } else {
                b"AA"
            };
            [prefix, base64_bytes(chunk).as_slice()].concat()
        })
        .collect::<Vec<_>>()
        .join(&b'\n');
    let variably_prefixed_unpadded_base64_private = binary_x25519_key()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            let prefix = if index % 2 == 0 {
                b"A".as_slice()
            } else {
                b"AA"
            };
            [prefix, base64_bytes(chunk).as_slice()].concat()
        })
        .collect::<Vec<_>>()
        .join(&b'\n');
    let checksum_separated_base64_private = binary_x25519_key()
        .chunks(24)
        .map(base64_bytes)
        .collect::<Vec<_>>()
        .join(b"\n=AAAA\n".as_slice());
    let assignment_wrapped_base64_private = binary_x25519_key()
        .chunks(23)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "Key{index}={}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let punctuation_wrapped_base64_private = binary_x25519_key()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "chunk-{}:{}",
                index * 24,
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let differently_labeled_base64_private = binary_x25519_key()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            let label = if index % 2 == 0 { "x:" } else { "yy|" };
            format!("{label}{}", String::from_utf8_lossy(&base64_bytes(chunk)))
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let long_labeled_base64_private = binary_x25519_key()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "longlabel{index}:{}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let whitespace_labeled_base64_private = binary_x25519_key()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "longlabel{index} {}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let hash_labeled_base64_private = binary_x25519_key()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "longlabel{index}#{}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let hash_suffix_labeled_base64_private = binary_x25519_key()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "{}#longlabel{index}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let middle_labeled_base64_private = binary_x25519_key()
        .chunks(24)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "prefix{index:03}:{}:suffix{index:03}",
                String::from_utf8_lossy(&base64_bytes(chunk))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let path_shaped_base64_private = {
        let mut encoded = base64_bytes(&binary_x25519_key());
        while encoded.last() == Some(&b'=') {
            encoded.pop();
        }
        let path = encoded
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk))
            .collect::<Vec<_>>()
            .join("/");
        format!("{path}\n").into_bytes()
    };
    let irregular_path_base64_private = irregular_path_base64(&encrypted);
    let arbitrary_short_path_base64_private = {
        let mut content = binary_x25519_key();
        content.extend([0xff; 12]);
        arbitrary_short_path_base64(&content)
    };
    let long_prefixed_path_base64_private = {
        let mut content = vec![b'X'; 1_600];
        content.extend(&encrypted);
        content.extend([0xff; 12]);
        long_irregular_path_base64(&content)
    };
    let medium_prefixed_path_base64_private = {
        let mut content = vec![b'X'; 600];
        content.extend(&encrypted);
        content.extend([0xff; 12]);
        medium_irregular_path_base64(&content)
    };
    let ordered_multifield_base64_private = ordered_multifield_base64(&encrypted);
    let variable_field_count_base64_private = variable_field_count_base64(&encrypted);
    let over_limit_structured_base64_private = over_limit_structured_base64(&encrypted);
    let ordered_over_limit_structured_base64_private =
        ordered_over_limit_structured_base64(&encrypted);
    let openpgp_path_base64_private = {
        let mut content = vec![0xff; 48];
        content.extend(binary_openpgp_secret_key(5));
        arbitrary_short_path_base64(&content)
    };
    let mixed_path_base64_private = {
        let mut encoded = base64_bytes(&binary_x25519_key());
        while encoded.last() == Some(&b'=') {
            encoded.pop();
        }
        let mut cursor = 0;
        let mut chunks = Vec::new();
        for width in [3, 5, 4].into_iter().cycle() {
            if cursor >= encoded.len() {
                break;
            }
            let end = (cursor + width).min(encoded.len());
            chunks.push(String::from_utf8_lossy(&encoded[cursor..end]));
            cursor = end;
        }
        format!("{}\n", chunks.join("/")).into_bytes()
    };
    let long_fragment_path_base64_private = {
        let mut encoded = base64_bytes(&binary_x25519_key());
        while encoded.last() == Some(&b'=') {
            encoded.pop();
        }
        let mut chunks = encoded.chunks(4).map(Vec::from).collect::<Vec<_>>();
        let combined = [
            chunks[4].as_slice(),
            chunks[5].as_slice(),
            chunks[6].as_slice(),
        ]
        .concat();
        chunks.splice(4..7, [combined]);
        format!(
            "{}\n",
            chunks
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk))
                .collect::<Vec<_>>()
                .join("/")
        )
        .into_bytes()
    };
    let import_wrapped_base64_private = binary_x25519_key()
        .chunks(6)
        .map(|chunk| format!("import A{}", String::from_utf8_lossy(&base64_bytes(chunk))))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let interleaved_assignment_base64_private = binary_x25519_key()
        .chunks(6)
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|pair| {
            let name = base64_bytes(pair[0]);
            let value = pair
                .get(1)
                .map_or_else(Vec::new, |chunk| base64_bytes(chunk));
            format!(
                "A{}={}",
                String::from_utf8_lossy(&name),
                String::from_utf8_lossy(&value)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let irregular_base64_encrypted = base64_wrapped_at(&encrypted, 65);
    let ber_encrypted = ber_encrypted_pkcs8(&encrypted);
    let ber_nonminimal = ber_nonminimal_encrypted_pkcs8(&encrypted);
    let ber_indefinite_algorithm = ber_indefinite_algorithm_pkcs8(&encrypted);
    let ber_unencrypted = ber_unencrypted_pkcs8(&binary_x25519_key());
    let ber_fragmented = ber_fragmented_encrypted_pkcs8(&encrypted);
    let mut embedded = b"ordinary package record\n".to_vec();
    embedded.extend(&encrypted);
    let mut prefixed_gzip = b"ordinary prefix\n".to_vec();
    prefixed_gzip.extend(gzip_bytes(&private_key_pem("")));
    let mut nested_gzip = b"ordinary prefix\n".to_vec();
    nested_gzip.extend(gzip_bytes(&gzip_bytes(&private_key_pem(""))));
    let mut nested_zip = b"ordinary prefix\n".to_vec();
    nested_zip.extend(gzip_bytes(&zip_with_private_key()));
    let rsa_pss_certificate = rsa_pss_certificate_der();
    let mut base64_certificate = b"QQ==\n".to_vec();
    base64_certificate.extend(base64_wrapped_bytes(&rsa_pss_certificate));
    let irregular_base64_certificate = base64_wrapped_at(&rsa_pss_certificate, 65);
    let prefixed_base64_certificate = [
        b"AAA".as_slice(),
        base64_wrapped_bytes(&rsa_pss_certificate).as_slice(),
    ]
    .concat();
    let mut cumulative_zstd_blocks = b"ordinary prefix\n".to_vec();
    cumulative_zstd_blocks.extend(zstd_many_empty_blocks(32_769));
    cumulative_zstd_blocks.extend(zstd_many_empty_blocks(32_769));
    for prefix in [b"A".as_slice(), b"AA".as_slice(), b"AAA".as_slice()] {
        let mut content = prefix.to_vec();
        content.extend(&base64_encrypted);
        assert_sensitive_package_rejected(
            &format!(
                "usr/share/doc/base64-private-key-prefix-{}.txt",
                prefix.len()
            ),
            &content,
        );
    }
    for suffix in [b"A".as_slice(), b"AA".as_slice(), b"AAA".as_slice()] {
        let mut content = base64_encrypted.clone();
        content.extend(suffix);
        assert_sensitive_package_rejected(
            &format!(
                "usr/share/doc/base64-private-key-suffix-{}.txt",
                suffix.len()
            ),
            &content,
        );
    }
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-long-suffix.txt",
        &long_suffixed_base64_encrypted,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-internal-padding.txt",
        &internal_padding_base64_encrypted,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-fragmented-padding.txt",
        &fragmented_padding_base64_encrypted,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-independent-padding.txt",
        &independently_padded_base64_encrypted,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-prefixed-independent-padding.txt",
        &prefixed_independently_padded_base64_encrypted,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-suffixed-independent-padding.txt",
        &suffixed_independently_padded_base64_encrypted,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-junk-fragment.txt",
        &junk_fragmented_base64_encrypted,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-variable-independent-padding.txt",
        &variably_prefixed_independently_padded_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-variable-unpadded.txt",
        &variably_prefixed_unpadded_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-checksum-separators.txt",
        &checksum_separated_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-assignments.txt",
        &assignment_wrapped_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-punctuation-fields.txt",
        &punctuation_wrapped_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-different-labels.txt",
        &differently_labeled_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-long-labels.txt",
        &long_labeled_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-whitespace-labels.txt",
        &whitespace_labeled_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-hash-labels.txt",
        &hash_labeled_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-hash-suffix-labels.txt",
        &hash_suffix_labeled_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-middle-labels.txt",
        &middle_labeled_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-path-shaped.txt",
        &path_shaped_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-irregular-path.txt",
        &irregular_path_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-arbitrary-short-path.txt",
        &arbitrary_short_path_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-long-prefixed-path.txt",
        &long_prefixed_path_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-medium-prefixed-path.txt",
        &medium_prefixed_path_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-ordered-multifield.txt",
        &ordered_multifield_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-variable-field-count.txt",
        &variable_field_count_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-over-limit-structured-fields.txt",
        &over_limit_structured_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-ordered-over-limit-fields.txt",
        &ordered_over_limit_structured_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-openpgp-irregular-path.txt",
        &openpgp_path_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-mixed-path.txt",
        &mixed_path_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-long-fragment-path.txt",
        &long_fragment_path_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-import-fields.txt",
        &import_wrapped_base64_private,
    );
    assert_sensitive_package_rejected(
        "usr/share/doc/base64-private-key-interleaved-assignments.txt",
        &interleaved_assignment_base64_private,
    );
    for (path, content) in [
        ("usr/share/doc/encrypted-key.bin", encrypted.clone()),
        ("usr/share/doc/ber-encrypted-key.bin", ber_encrypted.clone()),
        ("usr/share/doc/ber-nonminimal-key.bin", ber_nonminimal),
        (
            "usr/share/doc/ber-indefinite-algorithm-key.bin",
            ber_indefinite_algorithm,
        ),
        (
            "usr/share/doc/ber-unencrypted-key.bin",
            ber_unencrypted.clone(),
        ),
        (
            "usr/share/doc/ber-fragmented-key.bin",
            ber_fragmented.clone(),
        ),
        (
            "usr/share/doc/compressed-ber-key.bin",
            gzip_bytes(&ber_encrypted),
        ),
        ("usr/share/doc/embedded-key.bin", embedded.clone()),
        ("usr/share/doc/compressed-key.bin", gzip_bytes(&embedded)),
        (
            "usr/share/doc/openpgp-key-export.bin",
            binary_openpgp_secret_key(5),
        ),
        (
            "usr/share/doc/openpgp-subkey-export.bin",
            binary_openpgp_secret_key(7),
        ),
        (
            "usr/share/doc/legacy-certificate.txt",
            legacy_x509_certificate_pem(),
        ),
        ("usr/share/doc/rsa-pss-certificate.der", rsa_pss_certificate),
        (
            "usr/share/doc/base64-private-key.txt",
            base64_encrypted.clone(),
        ),
        (
            "usr/share/doc/prefixed-base64-private-key.txt",
            prefixed_base64_encrypted.clone(),
        ),
        (
            "usr/share/doc/base64-certificate.txt",
            base64_certificate.clone(),
        ),
        (
            "usr/share/doc/prefixed-base64-certificate.txt",
            prefixed_base64_certificate.clone(),
        ),
        (
            "usr/share/doc/irregular-base64-private-key.txt",
            irregular_base64_encrypted.clone(),
        ),
        (
            "usr/share/doc/irregular-base64-certificate.txt",
            irregular_base64_certificate.clone(),
        ),
        (
            "usr/share/doc/certificate-bundle.bin",
            pkcs7_certificate_pem(),
        ),
        (
            "usr/share/doc/neutral-container.bin",
            v7_tar_with_compressed_private_key(),
        ),
        ("usr/share/doc/prefixed-gzip.bin", prefixed_gzip.clone()),
        ("usr/share/doc/nested-gzip.bin", nested_gzip),
        ("usr/share/doc/nested-zip.bin", nested_zip),
        ("usr/share/doc/zstd-block-bomb.bin", zstd_block_bomb()),
        (
            "usr/share/doc/cumulative-zstd-blocks.bin",
            cumulative_zstd_blocks,
        ),
    ] {
        assert_sensitive_package_rejected(path, &content);
    }

    for (name, content) in [
        ("BER encrypted PKCS#8", ber_encrypted.clone()),
        (
            "compressed BER encrypted PKCS#8",
            gzip_bytes(&ber_encrypted),
        ),
        ("PKCS#7 certificate store", pkcs7_certificate_pem()),
        ("RSA-PSS DER certificate", rsa_pss_certificate_der()),
        ("Base64 DER private key", base64_encrypted),
        ("prefixed Base64 DER private key", prefixed_base64_encrypted),
        ("suffixed Base64 DER private key", suffixed_base64_encrypted),
        (
            "long-suffixed Base64 DER private key",
            long_suffixed_base64_encrypted,
        ),
        (
            "internal-padding Base64 DER private key",
            internal_padding_base64_encrypted,
        ),
        (
            "fragmented-padding Base64 DER private key",
            fragmented_padding_base64_encrypted,
        ),
        (
            "independently-padded Base64 DER private key",
            independently_padded_base64_encrypted,
        ),
        (
            "prefixed independently-padded Base64 DER private key",
            prefixed_independently_padded_base64_encrypted,
        ),
        (
            "suffixed independently-padded Base64 DER private key",
            suffixed_independently_padded_base64_encrypted,
        ),
        (
            "junk-fragmented Base64 DER private key",
            junk_fragmented_base64_encrypted,
        ),
        (
            "variably-prefixed independently-padded Base64 DER private key",
            variably_prefixed_independently_padded_base64_private,
        ),
        (
            "variably-prefixed unpadded Base64 DER private key",
            variably_prefixed_unpadded_base64_private,
        ),
        (
            "checksum-separated Base64 DER private key",
            checksum_separated_base64_private,
        ),
        (
            "assignment-wrapped Base64 DER private key",
            assignment_wrapped_base64_private,
        ),
        (
            "punctuation-wrapped Base64 DER private key",
            punctuation_wrapped_base64_private,
        ),
        (
            "import-wrapped Base64 DER private key",
            import_wrapped_base64_private,
        ),
        (
            "interleaved-assignment Base64 DER private key",
            interleaved_assignment_base64_private,
        ),
        ("Base64 DER certificate", base64_certificate),
        (
            "prefixed Base64 DER certificate",
            prefixed_base64_certificate,
        ),
        (
            "irregular Base64 DER private key",
            irregular_base64_encrypted,
        ),
        (
            "irregular Base64 DER certificate",
            irregular_base64_certificate,
        ),
        ("prefixed Gzip private key", prefixed_gzip),
        ("archived private key", zip_with_private_key()),
        ("BER unencrypted private key", ber_unencrypted),
        ("fragmented BER private key", ber_fragmented),
    ] {
        let fixture = Fixture::new();
        fs::write(fixture.artifacts.join("build.log"), content).unwrap();
        rewrite_sums(&fixture.artifacts);
        resign_manifest(&fixture);
        assert!(
            !fixture.run().status.success(),
            "accepted {name} in retained evidence"
        );
        assert!(!fixture.root.join("provenance.json").exists());
    }

    let compressed = zstd_bytes(&encrypted);
    let mut skippable_zstd = [
        b"\x50\x2a\x4d\x18".as_slice(),
        (15_u32.to_le_bytes()).as_slice(),
        b"ordinary-prefix".as_slice(),
    ]
    .concat();
    skippable_zstd.extend(compressed);
    assert_sensitive_package_rejected("usr/share/doc/prefixed-zstd.bin", &skippable_zstd);

    let mut truncated_gzip = b"ordinary executable prefix\n".to_vec();
    let mut compressed_key = gzip_bytes(&private_key_pem(""));
    compressed_key.truncate(compressed_key.len() - 4);
    truncated_gzip.extend(compressed_key);
    assert_sensitive_package_rejected("usr/share/doc/truncated-embedded-gzip.bin", &truncated_gzip);

    let mut hidden_zstd = zstd_bytes(b"safe\n");
    hidden_zstd.extend(zstd_skippable_frame(&gzip_bytes(&private_key_pem(""))));
    assert_sensitive_package_rejected("usr/share/doc/hidden-zstd-frame.bin", &hidden_zstd);

    let mut self_extracting_zip = b"ordinary executable stub\n".to_vec();
    self_extracting_zip.extend(zip_with_private_key());
    assert_sensitive_package_rejected("usr/share/doc/self-extracting.bin", &self_extracting_zip);

    let mut trailing_bzip2 = bzip2_bytes(b"safe\n");
    trailing_bzip2.extend(gzip_bytes(&private_key_pem("")));
    assert_sensitive_package_rejected("usr/share/doc/trailing-bzip2.bin", &trailing_bzip2);
}

#[test]
fn rejects_cumulative_path_shaped_base64_candidate_budgets() {
    let ambiguous = (0..56)
        .map(|index| format!("{index:04}{}AAAA\n", "AAAA/".repeat(14)))
        .collect::<String>();
    let fixture = Fixture::with_sensitive_package_file(
        "usr/share/doc/ambiguous-path-record.txt",
        ambiguous.as_bytes(),
    );
    assert!(!fixture.run().status.success());
}

#[test]
fn rejects_disagreement_in_shared_buildinfo_provenance() {
    let fixture = Fixture::with_mismatched_builddate();
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted a package with a different BUILDINFO builddate"
    );
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::with_mismatched_buildinfo_format();
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted packages with different BUILDINFO formats"
    );

    let fixture = Fixture::with_unknown_buildinfo_field();
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted an unknown BUILDINFO provenance field"
    );
}

#[test]
fn rejects_changed_source_package_and_retained_metadata_evidence() {
    let fixture = Fixture::new();
    let package = fs::read_dir(&fixture.artifacts)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "zst"))
        .unwrap();
    OpenOptions::new()
        .append(true)
        .open(package)
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    let output = fixture.run();
    assert!(!output.status.success(), "accepted changed package bytes");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package checksum mismatch before archive inspection"),
        "did not reject a bad package checksum before archive inspection: {}",
        stderr
    );

    let fixture = Fixture::new();
    fs::write(
        fixture
            .artifacts
            .join("packages")
            .join(KERNEL)
            .join(".PKGINFO"),
        b"pkgname = replacement\n",
    )
    .unwrap();
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted mismatched retained metadata"
    );

    let fixture = Fixture::new();
    OpenOptions::new()
        .append(true)
        .open(fixture.artifacts.join("source-lock.toml"))
        .unwrap()
        .write_all(b"\n# changed\n")
        .unwrap();
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted changed source provenance"
    );

    for retained in ["PKGBUILD", "package-set.SRCINFO"] {
        let fixture = Fixture::new();
        OpenOptions::new()
            .append(true)
            .open(fixture.artifacts.join(retained))
            .unwrap()
            .write_all(b"\n# authenticated drift\n")
            .unwrap();
        rewrite_sums(&fixture.artifacts);
        resign_manifest(&fixture);
        let output = fixture.run();
        assert!(
            !output.status.success(),
            "accepted {retained} bytes not bound by the build attestation"
        );
    }

    let fixture = Fixture::new();
    fs::write(
        fixture.artifacts.join("package-set.SRCINFO"),
        valid_srcinfo().replace(
            "pkgbase = linux-cachyos-pt31553",
            "pkgbase = contradictory-package-base",
        ),
    )
    .unwrap();
    rewrite_build_attestation(&fixture.artifacts);
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted authenticated .SRCINFO that contradicts package policy"
    );

    let fixture = Fixture::new();
    fs::write(
        fixture.artifacts.join("package-set.SRCINFO"),
        valid_srcinfo().replace(
            "source = https://github.com/CachyOS/linux/releases/download/cachyos-7.1.8-1/cachyos-7.1.8-1.tar.gz",
            "source = cachyos-7.1.8-1.tar.gz::cachyos-7.1.8-1.tar.gz",
        ),
    )
    .unwrap();
    rewrite_build_attestation(&fixture.artifacts);
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted a local .SRCINFO source alias that does not match the source lock"
    );

    let fixture = Fixture::new();
    fs::write(
        fixture.artifacts.join("package-set.SRCINFO"),
        valid_srcinfo().replace(
            "source = 0001-acer-wmi-add-pt31553-telemetry.patch",
            "source = copied/0001-acer-wmi-add-pt31553-telemetry.patch",
        ),
    )
    .unwrap();
    rewrite_build_attestation(&fixture.artifacts);
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted a relocated lock-backed local .SRCINFO source"
    );

    let fixture = Fixture::new();
    let package = fs::read_dir(&fixture.artifacts)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "zst"))
        .unwrap();
    OpenOptions::new()
        .append(true)
        .open(&package)
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    rewrite_sums(&fixture.artifacts);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted attacker-recomputed checksums without a valid manifest signature"
    );
}

#[test]
fn rejects_missing_or_wrong_nvidia_dependency_identity() {
    for (needle, replacement) in [
        ("depend = nvidia-utils=610.57.04\n", ""),
        ("depend = libglvnd\n", ""),
        (
            "depend = linux-cachyos-pt31553=7.1.8-1\n",
            "depend = linux-cachyos-pt31553=7.1.9-1\n",
        ),
        ("provides = NVIDIA-MODULE\n", "provides = wrong-module\n"),
        (
            "conflict = linux-cachyos-pt31553-nvidia\n",
            "conflict = wrong-module\n",
        ),
        (
            "conflict = linux-cachyos-pt31553-nvidia\n",
            "conflict = linux-cachyos-pt31553-nvidia\nreplaces = linux-cachyos-pt31553-nvidia\n",
        ),
    ] {
        let fixture = Fixture::new();
        let pkginfo = fixture.root.join(format!("stage-{NVIDIA}/.PKGINFO"));
        let changed = fs::read_to_string(&pkginfo)
            .unwrap()
            .replace(needle, replacement);
        fs::write(&pkginfo, &changed).unwrap();
        fs::write(
            fixture
                .artifacts
                .join("packages")
                .join(NVIDIA)
                .join(".PKGINFO"),
            &changed,
        )
        .unwrap();
        rebuild_nvidia_archive(&fixture);
        let output = fixture.run();
        assert!(
            !output.status.success(),
            "accepted altered NVIDIA package relationship: {needle}"
        );
    }
}

#[test]
fn rejects_drifted_nvidia_srcinfo_relationships() {
    for (needle, replacement) in [
        ("\tdepends = libglvnd\n", ""),
        (
            "\tdepends = linux-cachyos-pt31553=7.1.8-1\n",
            "\tdepends = linux-cachyos-pt31553=7.1.9-1\n",
        ),
        (
            "\tprovides = NVIDIA-MODULE\n",
            "\tprovides = wrong-module\n",
        ),
        (
            "\tconflicts = linux-cachyos-pt31553-nvidia\n",
            "\tconflicts = wrong-module\n",
        ),
        (
            "\tconflicts = linux-cachyos-pt31553-nvidia\n",
            "\tconflicts = linux-cachyos-pt31553-nvidia\n\treplaces = linux-cachyos-pt31553-nvidia\n",
        ),
    ] {
        let fixture = Fixture::new();
        let path = fixture.artifacts.join("package-set.SRCINFO");
        fs::write(
            &path,
            fs::read_to_string(&path)
                .unwrap()
                .replace(needle, replacement),
        )
        .unwrap();
        rewrite_build_attestation(&fixture.artifacts);
        rewrite_sums(&fixture.artifacts);
        resign_manifest(&fixture);
        let output = fixture.run();
        assert!(
            !output.status.success(),
            "accepted altered NVIDIA SRCINFO relationship: {needle}"
        );
    }

    for relationship in [
        "depends",
        "depends_x86_64",
        "optdepends",
        "optdepends_x86_64",
        "makedepends",
        "makedepends_x86_64",
        "checkdepends",
        "checkdepends_x86_64",
    ] {
        let fixture = Fixture::new();
        let path = fixture.artifacts.join("package-set.SRCINFO");
        fs::write(
            &path,
            fs::read_to_string(&path).unwrap().replace(
                "\tarch = x86_64\n",
                &format!("\tarch = x86_64\n\t{relationship} = injected-global\n"),
            ),
        )
        .unwrap();
        rewrite_build_attestation(&fixture.artifacts);
        rewrite_sums(&fixture.artifacts);
        resign_manifest(&fixture);
        assert!(
            !fixture.run().status.success(),
            "accepted a global {relationship} relationship"
        );
    }
}

#[test]
fn rejects_module_trust_certificate_not_embedded_in_signed_kernel_image() {
    let fixture = Fixture::new();
    fs::write(
        fixture
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        fake_kernel_image(&fake_builtin_trust_payload(b"unrelated certificate")),
    )
    .unwrap();
    rebuild_kernel_archive(&fixture, &[], true);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted headers-only module trust evidence"
    );
}

#[test]
fn rejects_an_unapproved_certificate_inside_a_correctly_signed_module_payload() {
    let fixture = Fixture::with_real_crypto();
    let (_, unapproved_certificate) = binary_key_and_certificate();
    let payload = fixture.root.join("real-module-0.payload");
    OpenOptions::new()
        .append(true)
        .open(&payload)
        .unwrap()
        .write_all(&unapproved_certificate)
        .unwrap();
    let signature = fixture.root.join("real-module-extra-certificate.p7s");
    assert!(
        Command::new("openssl")
            .args(["cms", "-sign", "-binary", "-in"])
            .arg(&payload)
            .arg("-signer")
            .arg(&fixture.module_cert)
            .arg("-inkey")
            .arg(fixture.root.join("real-module.key"))
            .args(["-outform", "DER", "-out"])
            .arg(&signature)
            .args(["-nocerts", "-noattr", "-md", "sha512"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    fs::write(
        fixture.root.join(format!(
            "stage-{KERNEL}/usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"
        )),
        module_with_signature(&fs::read(payload).unwrap(), &fs::read(signature).unwrap()),
    )
    .unwrap();
    rebuild_kernel_archive(&fixture, &[], true);
    sign_real_manifest(&fixture);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted an unapproved certificate in a correctly signed module"
    );
    assert!(!fixture.root.join("provenance.json").exists());
}

#[test]
fn rejects_module_certificate_layout_outside_the_builtin_trust_section() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut payload = fake_builtin_trust_payload(b"unrelated certificate");
    payload.resize(payload.len().next_multiple_of(8), 0);
    payload.extend_from_slice(&certificate);
    payload.resize(payload.len().next_multiple_of(8), 0);
    payload.extend_from_slice(&(certificate.len() as u64).to_le_bytes());
    payload.extend_from_slice(&(certificate.len() as u64).to_le_bytes());
    fs::write(
        fixture
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        fake_kernel_image(&payload),
    )
    .unwrap();
    rebuild_kernel_archive(&fixture, &[], true);
    assert!(
        !fixture.run().status.success(),
        "accepted a trust-list byte pattern outside .init.rodata"
    );
}

#[test]
fn rejects_system_map_symbol_with_skewed_load_segment_mapping() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut payload = fake_builtin_trust_payload(&certificate);
    let trust_size = u64::from_le_bytes(payload[96..104].try_into().unwrap());
    payload[72..80].copy_from_slice(&(112_u64).to_le_bytes());
    payload[80..88].copy_from_slice(&(FAKE_TRUST_ADDRESS - 16).to_le_bytes());
    payload[88..96].copy_from_slice(&(FAKE_TRUST_ADDRESS - 16).to_le_bytes());
    payload[96..104].copy_from_slice(&(trust_size + 8).to_le_bytes());
    payload[104..112].copy_from_slice(&(trust_size + 8).to_le_bytes());
    replace_fake_kernel_image(&fixture, fake_kernel_image(&payload));
    assert!(
        !fixture.run().status.success(),
        "accepted a System.map symbol with inconsistent PT_LOAD offset mapping"
    );
}

#[test]
fn rejects_system_map_copy_not_bound_to_authenticated_elf_symbols() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut payload = fake_builtin_trust_payload(&certificate);
    let section_offset = u64::from_le_bytes(payload[40..48].try_into().unwrap()) as usize;
    let symbol_table_header = section_offset + 3 * 64;
    let symbol_table_offset = u64::from_le_bytes(
        payload[symbol_table_header + 24..symbol_table_header + 32]
            .try_into()
            .unwrap(),
    ) as usize;
    for index in 1..=3 {
        let value_offset = symbol_table_offset + index * 24 + 8;
        payload[value_offset..value_offset + 8]
            .copy_from_slice(&(FAKE_TRUST_ADDRESS + 0x1000 + index as u64 * 8).to_le_bytes());
    }
    replace_fake_kernel_image(&fixture, fake_kernel_image(&payload));
    assert!(
        !fixture.run().status.success(),
        "accepted a forged System.map target instead of authenticated ELF symbols"
    );
}

#[test]
fn rejects_stripped_kernel_payload_with_an_unbound_system_map() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut payload = fake_builtin_trust_payload(&certificate);
    let section_offset = u64::from_le_bytes(payload[40..48].try_into().unwrap()) as usize;
    let symbol_table_header = section_offset + 3 * 64;
    payload[symbol_table_header + 4..symbol_table_header + 8]
        .copy_from_slice(&(0_u32).to_le_bytes());
    replace_fake_kernel_image(&fixture, fake_kernel_image(&payload));
    assert!(
        !fixture.run().status.success(),
        "accepted a stripped payload whose System.map addresses are not authenticated"
    );
}

#[test]
fn accepts_stripped_kernel_payload_with_authenticated_btf_symbols() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut payload = fake_builtin_trust_payload_with_btf(&certificate);
    let section_offset = u64::from_le_bytes(payload[40..48].try_into().unwrap()) as usize;
    let symbol_table_header = section_offset + 3 * 64;
    payload[symbol_table_header + 4..symbol_table_header + 8]
        .copy_from_slice(&(0_u32).to_le_bytes());
    replace_fake_kernel_image(&fixture, fake_kernel_image(&payload));
    let output = fixture.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_excessive_elf_program_header_counts() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut payload = fake_builtin_trust_payload(&certificate);
    payload[56..58].copy_from_slice(&(129_u16).to_le_bytes());
    replace_fake_kernel_image(&fixture, fake_kernel_image(&payload));
    assert!(
        !fixture.run().status.success(),
        "accepted an excessive ELF program-header count"
    );
}

#[test]
fn rejects_oversized_elf_section_names() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut payload = fake_builtin_trust_payload(&certificate);
    let section_offset = u64::from_le_bytes(payload[40..48].try_into().unwrap()) as usize;
    let names_header = section_offset + 4 * 64;
    let names_offset = payload.len();
    payload.extend(std::iter::repeat_n(b'A', 256));
    payload.push(0);
    payload[names_header + 24..names_header + 32]
        .copy_from_slice(&(names_offset as u64).to_le_bytes());
    payload[names_header + 32..names_header + 40].copy_from_slice(&(257_u64).to_le_bytes());
    replace_fake_kernel_image(&fixture, fake_kernel_image(&payload));
    assert!(
        !fixture.run().status.success(),
        "accepted an oversized ELF section name"
    );
}

#[test]
fn exact_kernel_decompression_respects_the_shared_residency_budget() {
    let root = temporary_fixture("kernel-residency-budget");
    let payload = root.join("payload.gz");
    let mut streams = gzip_bytes(&[0_u8; 150]);
    streams.extend_from_slice(b"ordinary-separator");
    streams.extend(gzip_bytes(&[0_u8; 150]));
    fs::write(&payload, streams).unwrap();
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
script = pathlib.Path(sys.argv[1])
loader = importlib.machinery.SourceFileLoader("verify_package_provenance", str(script))
spec = importlib.util.spec_from_loader(loader.name, loader)
loaded = importlib.util.module_from_spec(spec)
loader.exec_module(loaded)
payload = pathlib.Path(sys.argv[2]).read_bytes()
try:
    loaded.exact_compressed_kernel_payload(
        payload,
        "residency fixture",
        pathlib.Path(sys.argv[3]),
        loaded.inspection_budget(),
        [512],
    )
except loaded.VerificationError:
    raise SystemExit(0)
raise SystemExit(1)
"#;
    let status = Command::new("python3")
        .args(["-I", "-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(&payload)
        .arg(&root)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "accepted expansion beyond shared residency"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn embedded_kernel_decompression_respects_the_shared_residency_budget() {
    let root = temporary_fixture("embedded-kernel-residency-budget");
    let payload = root.join("payload.gz");
    fs::write(&payload, gzip_bytes(&vec![0_u8; 257])).unwrap();
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
script = pathlib.Path(sys.argv[1])
loader = importlib.machinery.SourceFileLoader("verify_package_provenance", str(script))
spec = importlib.util.spec_from_loader(loader.name, loader)
loaded = importlib.util.module_from_spec(spec)
loader.exec_module(loaded)
payload = b"ordinary-prefix" + pathlib.Path(sys.argv[2]).read_bytes()
residency_budget = [512]
try:
    loaded.embedded_compressed_children(
        payload,
        "residency fixture",
        pathlib.Path(sys.argv[3]),
        loaded.inspection_budget(),
        max_expanded_size=512,
        residency_budget=residency_budget,
    )
except loaded.VerificationError:
    raise SystemExit(0)
raise SystemExit(1)
"#;
    let status = Command::new("python3")
        .args(["-I", "-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(&payload)
        .arg(&root)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "accepted embedded expansion beyond shared residency"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_duplicate_kernel_payload_certificate_occurrences() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut payload = fake_builtin_trust_payload(&certificate);
    payload.extend_from_slice(&certificate);
    let image = fake_kernel_image(&payload);
    fs::write(
        fixture
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        image,
    )
    .unwrap();
    rebuild_kernel_archive(&fixture, &[], true);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted duplicate module trust certificate occurrences"
    );
}

#[test]
fn compressed_kernel_payload_must_be_exact_and_bind_the_certificate() {
    let accepted = Fixture::new();
    let certificate = fs::read(&accepted.module_cert_der).unwrap();
    fs::write(
        accepted
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        fake_kernel_image(&gzip_bytes(&fake_builtin_trust_payload(&certificate))),
    )
    .unwrap();
    rebuild_kernel_archive(&accepted, &[], true);
    let output = accepted.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bzimage = Fixture::new();
    let certificate = fs::read(&bzimage.module_cert_der).unwrap();
    fs::write(
        bzimage
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        fake_bzimage(&gzip_bytes(&fake_builtin_trust_payload(&certificate))),
    )
    .unwrap();
    rebuild_kernel_archive(&bzimage, &[], true);
    let output = bzimage.run();
    assert!(
        output.status.success(),
        "normal x86 bzImage .text payload rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let zstd_trailer = Fixture::new();
    let certificate = fs::read(&zstd_trailer.module_cert_der).unwrap();
    let trusted_payload = fake_builtin_trust_payload(&certificate);
    let mut compressed = zstd_bytes(&trusted_payload);
    compressed.extend_from_slice(&(trusted_payload.len() as u32).to_le_bytes());
    replace_fake_kernel_image(&zstd_trailer, fake_kernel_image(&compressed));
    let output = zstd_trailer.run();
    assert!(
        output.status.success(),
        "normal Linux Zstandard size trailer rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let wrong_zstd_trailer = Fixture::new();
    let certificate = fs::read(&wrong_zstd_trailer.module_cert_der).unwrap();
    let trusted_payload = fake_builtin_trust_payload(&certificate);
    let mut compressed = zstd_bytes(&trusted_payload);
    compressed.extend_from_slice(&((trusted_payload.len() + 1) as u32).to_le_bytes());
    replace_fake_kernel_image(&wrong_zstd_trailer, fake_kernel_image(&compressed));
    assert!(
        !wrong_zstd_trailer.run().status.success(),
        "accepted a wrong Linux Zstandard size trailer"
    );

    let rejected = Fixture::new();
    let certificate = fs::read(&rejected.module_cert_der).unwrap();
    let mut compressed = gzip_bytes(b"kernel payload without the certificate");
    compressed.extend_from_slice(&certificate);
    fs::write(
        rejected
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        fake_kernel_image(&compressed),
    )
    .unwrap();
    rebuild_kernel_archive(&rejected, &[], true);
    let output = rejected.run();
    assert!(
        !output.status.success(),
        "accepted inert certificate bytes trailing a compressed kernel payload"
    );

    let prefixed = Fixture::new();
    let certificate = fs::read(&prefixed.module_cert_der).unwrap();
    let mut payload = b"non-kernel prefix".to_vec();
    payload.extend_from_slice(&gzip_bytes(b"kernel payload without the certificate"));
    payload.extend_from_slice(&certificate);
    fs::write(
        prefixed
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        fake_kernel_image(&payload),
    )
    .unwrap();
    rebuild_kernel_archive(&prefixed, &[], true);
    let output = prefixed.run();
    assert!(
        !output.status.success(),
        "accepted certificate bytes outside a prefixed compressed kernel payload"
    );

    let nested = Fixture::new();
    let certificate = fs::read(&nested.module_cert_der).unwrap();
    let mut inner = b"non-kernel prefix".to_vec();
    inner.extend_from_slice(&gzip_bytes(b"kernel payload without the certificate"));
    inner.extend_from_slice(&certificate);
    replace_fake_kernel_image(&nested, fake_kernel_image(&gzip_bytes(&inner)));
    let output = nested.run();
    assert!(
        !output.status.success(),
        "accepted certificate outside compressed data after outer decompression"
    );
}

#[test]
fn rejects_kernel_payload_overlapping_pe_certificate_table() {
    let fixture = Fixture::new();
    let certificate = fs::read(&fixture.module_cert_der).unwrap();
    let mut image = fake_kernel_image(&certificate);
    let security_entry = 0x98 + 112 + 8 * 4;
    image[security_entry..security_entry + 4].copy_from_slice(&(0x200_u32).to_le_bytes());
    image[security_entry + 4..security_entry + 8]
        .copy_from_slice(&(certificate.len() as u32).to_le_bytes());
    fs::write(
        fixture
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        image,
    )
    .unwrap();
    rebuild_kernel_archive(&fixture, &[], true);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted a kernel payload mapped over the Authenticode certificate table"
    );
}

#[test]
fn rejects_non_payload_padding_and_malformed_pe_section_ranges() {
    let text_only = Fixture::new();
    let certificate = fs::read(&text_only.module_cert_der).unwrap();
    replace_fake_kernel_image(
        &text_only,
        fake_kernel_image_sections(&[(".text", &certificate)]),
    );
    assert!(
        !text_only.run().status.success(),
        "accepted certificate in .text"
    );

    let padded = Fixture::new();
    let certificate = fs::read(&padded.module_cert_der).unwrap();
    let prefix = b"mapped kernel payload";
    let raw = [prefix.as_slice(), certificate.as_slice()].concat();
    let mut image = fake_kernel_image(&raw);
    let section_header = 0x98 + 152;
    image[section_header + 8..section_header + 12]
        .copy_from_slice(&(prefix.len() as u32).to_le_bytes());
    replace_fake_kernel_image(&padded, image);
    assert!(
        !padded.run().status.success(),
        "accepted certificate in raw section padding"
    );

    let out_of_bounds = Fixture::new();
    let certificate = fs::read(&out_of_bounds.module_cert_der).unwrap();
    let mut image = fake_kernel_image(&certificate);
    let invalid_offset = (image.len() - 1) as u32;
    image[section_header + 20..section_header + 24].copy_from_slice(&invalid_offset.to_le_bytes());
    replace_fake_kernel_image(&out_of_bounds, image);
    assert!(
        !out_of_bounds.run().status.success(),
        "accepted out-of-bounds kernel payload section"
    );

    let overlapping = Fixture::new();
    let certificate = fs::read(&overlapping.module_cert_der).unwrap();
    let mut image = fake_kernel_image_sections(&[
        (".linux", certificate.as_slice()),
        (".linux", b"second payload"),
    ]);
    let second_header = section_header + 40;
    image[second_header + 20..second_header + 24].copy_from_slice(&(0x200_u32).to_le_bytes());
    replace_fake_kernel_image(&overlapping, image);
    assert!(
        !overlapping.run().status.success(),
        "accepted overlapping kernel payload sections"
    );
}

fn replace_fake_kernel_image(fixture: &Fixture, image: Vec<u8>) {
    fs::write(
        fixture
            .root
            .join(format!("stage-{KERNEL}/usr/lib/modules/{RELEASE}/vmlinuz")),
        image,
    )
    .unwrap();
    rebuild_kernel_archive(fixture, &[], true);
}

#[test]
fn requires_every_shared_buildinfo_provenance_field() {
    for field in [
        "format",
        "builddate",
        "builddir",
        "packager",
        "buildenv",
        "options",
        "installed",
    ] {
        let fixture = Fixture::without_buildinfo_field(Some(field));
        let output = fixture.run();
        assert!(
            !output.status.success(),
            "accepted package set with {field} missing from every .BUILDINFO"
        );
    }
}

#[test]
fn bounds_archive_output_and_atomically_publishes_without_clobbering() {
    let fixture = Fixture::new();
    let package = fs::read_dir(&fixture.artifacts)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(".pkg.tar.zst")
        })
        .unwrap();
    OpenOptions::new()
        .write(true)
        .open(package)
        .unwrap()
        .set_len(4 * 1024 * 1024 * 1024 + 1)
        .unwrap();
    let output = fixture.run();
    assert!(!output.status.success(), "accepted an oversized archive");
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::new();
    write_tool(
        &fixture.bin.join("bsdtar"),
        "#!/bin/sh\n/usr/bin/bsdtar \"$@\"\n[ \"$1\" != -tf ] || echo usr/share/doc/phantom\n",
    );
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted disagreement between archive listing and TAR inspection"
    );
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::new();
    write_tool(
        &fixture.bin.join("bsdtar"),
        "#!/bin/sh\nyes x | head -c 17825792\n",
    );
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted an oversized archive listing"
    );
    assert!(!fixture.root.join("provenance.json").exists());

    let fixture = Fixture::new();
    assert!(fixture.run().status.success());
    let original = fs::read(fixture.root.join("provenance.json")).unwrap();
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "replaced an existing evidence record"
    );
    assert_eq!(
        fs::read(fixture.root.join("provenance.json")).unwrap(),
        original
    );

    let output = call_failing_evidence_publication(&fixture.root);
    assert!(
        !output.status.success(),
        "publication unexpectedly succeeded"
    );
    assert!(!fixture.root.join("link-failure.json").exists());
    assert!(
        fs::read_dir(&fixture.root).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")),
        "atomic publication left a visible temporary file"
    );
}

#[test]
fn one_pass_archive_inspection_rejects_links_special_files_and_bad_members() {
    let fixture = Fixture::new();
    let link = fixture
        .root
        .join(format!("stage-{KERNEL}/usr/share/doc/safe-link"));
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("release-notes.txt", &link).unwrap();
    rebuild_kernel_archive(&fixture, &["usr/share/doc/safe-link"], true);
    assert!(
        !fixture.run().status.success(),
        "accepted a package symlink"
    );

    let fixture = Fixture::new();
    let fifo = fixture
        .root
        .join(format!("stage-{KERNEL}/usr/share/doc/build-stream"));
    fs::create_dir_all(fifo.parent().unwrap()).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    rebuild_kernel_archive(&fixture, &["usr/share/doc/build-stream"], true);
    assert!(!fixture.run().status.success(), "accepted a package FIFO");

    let fixture = Fixture::new();
    let broken = fixture
        .root
        .join(format!("stage-{KERNEL}/usr/share/doc/broken.zst"));
    fs::create_dir_all(broken.parent().unwrap()).unwrap();
    fs::write(&broken, b"not zstd").unwrap();
    rebuild_kernel_archive(&fixture, &["usr/share/doc/broken.zst"], true);
    assert!(
        !fixture.run().status.success(),
        "accepted invalid member compression"
    );

    let fixture = Fixture::new();
    rebuild_kernel_archive(&fixture, &[], false);
    assert!(
        !fixture.run().status.success(),
        "accepted missing retained .MTREE"
    );

    let fixture = Fixture::new();
    rebuild_kernel_archive_with_duplicate_pkginfo(&fixture);
    assert!(
        !fixture.run().status.success(),
        "accepted duplicate package member paths"
    );

    let fixture = Fixture::new();
    rebuild_kernel_archive_with_oversized_sparse_member(&fixture);
    assert!(
        !fixture.run().status.success(),
        "accepted a package member beyond the per-member size bound"
    );

    let fixture = Fixture::new();
    rebuild_kernel_archive_with_trailing_private_key(&fixture);
    assert!(
        !fixture.run().status.success(),
        "accepted private-key bytes after the TAR terminator"
    );

    let fixture = Fixture::new();
    rebuild_kernel_archive_with_sensitive_pax_metadata(&fixture);
    assert!(
        !fixture.run().status.success(),
        "accepted private-key material in PAX metadata"
    );

    let fixture = Fixture::new();
    rebuild_kernel_archive_with_sensitive_gnu_longname(&fixture);
    assert!(
        !fixture.run().status.success(),
        "accepted private-key material hidden in a GNU LongName record"
    );

    let fixture = Fixture::new();
    let archive = fixture
        .artifacts
        .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst"));
    OpenOptions::new()
        .append(true)
        .open(&archive)
        .unwrap()
        .write_all(&zstd_skippable_frame(&gzip_bytes(&private_key_pem(""))))
        .unwrap();
    rewrite_sums(&fixture.artifacts);
    resign_manifest(&fixture);
    assert!(
        !fixture.run().status.success(),
        "accepted a package archive with an ignored Zstandard frame"
    );
}

#[test]
fn mtree_must_bind_package_member_inventory_and_content() {
    let directories = Fixture::new();
    let kernel_stage = directories.root.join(format!("stage-{KERNEL}"));
    assert!(
        read_mtree(&kernel_stage)
            .lines()
            .any(|line| line.starts_with("./usr ") && line.contains("type=dir"))
    );
    assert!(directories.run().status.success());

    let content = Fixture::new();
    rebuild_kernel_archive(&content, &[], true);
    let pkginfo = content.root.join(format!("stage-{KERNEL}/.PKGINFO"));
    let mut changed = fs::read(&pkginfo).unwrap();
    let changed_byte = changed.iter_mut().find(|byte| **byte == b'x').unwrap();
    *changed_byte = b'y';
    fs::write(&pkginfo, &changed).unwrap();
    fs::write(
        content
            .artifacts
            .join("packages")
            .join(KERNEL)
            .join(".PKGINFO"),
        changed,
    )
    .unwrap();
    write_kernel_archive(&content, &kernel_archive_members(&[]), true);
    let output = content.run();
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains(".MTREE SHA-256"),
        "accepted package content not bound by MTREE: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let inventory = Fixture::new();
    rebuild_kernel_archive(&inventory, &[], true);
    let extra = "usr/share/doc/unbound";
    let extra_path = inventory.root.join(format!("stage-{KERNEL}/{extra}"));
    fs::create_dir_all(extra_path.parent().unwrap()).unwrap();
    fs::write(extra_path, b"not inventoried\n").unwrap();
    write_kernel_archive(&inventory, &kernel_archive_members(&[extra]), true);
    let output = inventory.run();
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains(".MTREE inventory"),
        "accepted package member missing from MTREE: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stale = Fixture::new();
    rebuild_kernel_archive(&stale, &[], true);
    let mut members = kernel_archive_members(&[]);
    members.pop();
    write_kernel_archive(&stale, &members, true);
    let output = stale.run();
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains(".MTREE inventory"),
        "accepted stale MTREE member missing from package: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let timestamp = Fixture::new();
    rebuild_kernel_archive(&timestamp, &[], true);
    let stage = timestamp.root.join(format!("stage-{KERNEL}"));
    let mut mtree = read_mtree(&stage);
    let time = mtree.find("time=").unwrap();
    let fraction = mtree[time..].find(".0").unwrap() + time + 1;
    mtree.replace_range(fraction..fraction + 1, "1");
    replace_kernel_mtree(&timestamp, mtree.as_bytes());
    write_kernel_archive(&timestamp, &kernel_archive_members(&[]), true);
    let output = timestamp.run();
    assert!(
        !output.status.success() && String::from_utf8_lossy(&output.stderr).contains(".MTREE time"),
        "accepted fractional MTREE time absent from TAR: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let directory = Fixture::new();
    rebuild_kernel_archive(&directory, &[], true);
    let stage = directory.root.join(format!("stage-{KERNEL}"));
    let mtree = read_mtree(&stage).replace("mode=755 type=dir", "mode=700 type=dir");
    replace_kernel_mtree(&directory, mtree.as_bytes());
    write_kernel_archive(&directory, &kernel_archive_members(&[]), true);
    let output = directory.run();
    assert!(
        !output.status.success() && String::from_utf8_lossy(&output.stderr).contains(".MTREE mode"),
        "accepted wrong MTREE directory mode: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let framing = Fixture::new();
    rebuild_kernel_archive(&framing, &[], true);
    let mtree = framing.root.join(format!("stage-{KERNEL}/.MTREE"));
    OpenOptions::new()
        .append(true)
        .open(&mtree)
        .unwrap()
        .write_all(&gzip_bytes(b"# trailing stream\n"))
        .unwrap();
    retain_kernel_mtree(&framing);
    write_kernel_archive(&framing, &kernel_archive_members(&[]), true);
    let output = framing.run();
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("exact bounded gzip"),
        "accepted concatenated MTREE gzip streams: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn mtree_grammar_and_state_handling_fail_closed() {
    let escaped = Fixture::new();
    rebuild_kernel_archive(&escaped, &[], true);
    let stage = escaped.root.join(format!("stage-{KERNEL}"));
    let mtree = read_mtree(&stage)
        .replace("#mtree\n", "#mtree\n/unset all\n")
        .replace("./usr ", "./\\165sr ");
    let output = run_with_kernel_mtree(&escaped, mtree.as_bytes());
    assert!(
        output.status.success(),
        "rejected valid escaped path or /unset state: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let invalid_escape = Fixture::new();
    rebuild_kernel_archive(&invalid_escape, &[], true);
    let stage = invalid_escape.root.join(format!("stage-{KERNEL}"));
    let mtree = read_mtree(&stage).replace("./usr ", "./\\qsr ");
    let output = run_with_kernel_mtree(&invalid_escape, mtree.as_bytes());
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("invalid path escape"),
        "accepted invalid MTREE path escape: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let duplicate_attribute = Fixture::new();
    rebuild_kernel_archive(&duplicate_attribute, &[], true);
    let stage = duplicate_attribute.root.join(format!("stage-{KERNEL}"));
    let mtree = read_mtree(&stage).replace("./.BUILDINFO time=", "./.BUILDINFO uid=1 uid=1 time=");
    let output = run_with_kernel_mtree(&duplicate_attribute, mtree.as_bytes());
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("duplicate attribute"),
        "accepted duplicate MTREE attribute: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let duplicate_path = Fixture::new();
    rebuild_kernel_archive(&duplicate_path, &[], true);
    let stage = duplicate_path.root.join(format!("stage-{KERNEL}"));
    let mut mtree = read_mtree(&stage);
    let repeated = mtree
        .lines()
        .find(|line| line.starts_with("./usr "))
        .unwrap()
        .to_string();
    mtree.push_str(&repeated);
    mtree.push('\n');
    let output = run_with_kernel_mtree(&duplicate_path, mtree.as_bytes());
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("duplicate package paths"),
        "accepted duplicate MTREE path: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let unsupported_command = Fixture::new();
    rebuild_kernel_archive(&unsupported_command, &[], true);
    let stage = unsupported_command.root.join(format!("stage-{KERNEL}"));
    let mtree = read_mtree(&stage).replace("#mtree\n", "#mtree\n/unsupported\n");
    let output = run_with_kernel_mtree(&unsupported_command, mtree.as_bytes());
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("unsupported command"),
        "accepted unsupported MTREE command: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let oversized_number = Fixture::new();
    rebuild_kernel_archive(&oversized_number, &[], true);
    let stage = oversized_number.root.join(format!("stage-{KERNEL}"));
    let mut mtree = read_mtree(&stage);
    let start = mtree.find("time=").unwrap() + "time=".len();
    let end = mtree[start..]
        .find(char::is_whitespace)
        .map(|offset| start + offset)
        .unwrap();
    mtree.replace_range(start..end, "123456789012345678901");
    let output = run_with_kernel_mtree(&oversized_number, mtree.as_bytes());
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("invalid time"),
        "accepted oversized MTREE number: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn archive_member_count_is_bounded_before_tar_materialization() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
loaded.stream_limited = lambda *args: b"".join(
    f"member-{index}\n".encode() for index in range(loaded.MAX_ARCHIVE_MEMBERS + 1)
)
loaded.list_archive(pathlib.Path("untrusted.pkg.tar.zst"))
"#;
    let output = Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "accepted an archive member list beyond the bounded count"
    );
}

#[test]
fn mtree_expansion_budget_accepts_a_production_sized_inventory() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source = r##"
import gzip
import importlib.machinery
import importlib.util
import sys

loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)

count = 51_625
empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
empty_md5 = "d41d8cd98f00b204e9800998ecf8427e"
facts = {}
lines = ["#mtree"]
for index in range(count):
    path = f"usr/lib/modules/7.1.8/kernel/member-{index:05}.ko"
    facts[path] = {
        "type": "file",
        "uid": 0,
        "gid": 0,
        "mode": 0o644,
        "mtime": 1786378335,
        "size": 0,
        "sha256digest": empty_sha256,
        "md5digest": empty_md5,
    }
    lines.append(
        f"./{path} type=file uid=0 gid=0 mode=644 time=1786378335.0 "
        f"size=0 md5digest={empty_md5} sha256digest={empty_sha256}"
    )
mtree = ("\n".join(lines) + "\n").encode()
assert len(mtree) > 4 * 1024 * 1024
assert len(mtree) <= loaded.MAX_MTREE_EXPANDED_BYTES
loaded.validate_mtree(gzip.compress(mtree), facts)
"##;
    let output = Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rejected a production-sized MTREE inventory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn expected_top_level_package_compression_does_not_consume_the_embedded_budget() {
    let fixture = Fixture::new();
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    let members = (0..65)
        .map(|index| {
            let member = format!("usr/share/doc/compressed-{index}.zst");
            let path = stage.join(&member);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, zstd_bytes(b"ordinary package documentation\n")).unwrap();
            member
        })
        .collect::<Vec<_>>();
    let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
    rebuild_kernel_archive(&fixture, &member_refs, true);
    let output = fixture.run();
    assert!(
        output.status.success(),
        "valid top-level package compression exhausted the embedded-stream budget: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn package_member_decompression_process_count_is_bounded() {
    let fixture = Fixture::new();
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    let members = (0..129)
        .map(|index| {
            let member = format!("usr/share/doc/process-bounded-{index}.zst");
            let path = stage.join(&member);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, zstd_bytes(b"ordinary package documentation\n")).unwrap();
            member
        })
        .collect::<Vec<_>>();
    let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
    rebuild_kernel_archive(&fixture, &member_refs, true);
    assert!(
        !fixture.run().status.success(),
        "accepted more top-level compressed members than the process budget"
    );
}

#[test]
fn aggregate_package_member_expansion_budget_is_enforced_across_decompressions() {
    let root = std::env::temp_dir().join(format!(
        "fan-control-decompression-budget-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::write(root.join("one.gz"), gzip_bytes(b"sixteen bytes...\n")).unwrap();
    fs::write(root.join("two.gz"), gzip_bytes(b"sixteen bytes...\n")).unwrap();
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let source = r#"
import importlib.machinery, importlib.util, pathlib, sys
loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
root = pathlib.Path(sys.argv[2])
budget = loaded.inspection_budget(24)
try:
    loaded.decompress_member(root / "one.gz", "one.gz", root / "one", budget)
    loaded.decompress_member(root / "two.gz", "two.gz", root / "two", budget)
except loaded.VerificationError:
    raise SystemExit(0)
raise SystemExit(1)
"#;
    let output = Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(&root)
        .output()
        .unwrap();
    fs::remove_dir_all(root).ok();
    assert!(
        output.status.success(),
        "aggregate member expansion budget was not enforced: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn verifies_real_detached_pkcs7_module_signatures_and_rejects_tampering() {
    let root = std::env::temp_dir().join(format!(
        "fan-control-real-module-signature-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("create real-signature fixture");
    let key = root.join("ephemeral-test-key.pem");
    let cert = root.join("ephemeral-test-certificate.pem");
    let payload = root.join("module.payload");
    let signature = root.join("module.p7s");
    let module = root.join("module.ko");
    fs::write(&payload, b"real signed module payload\n").expect("write signed payload");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=ephemeral-test-module-signer",
            "-days",
            "1",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("generate ephemeral certificate");
    assert!(status.success());
    let status = Command::new("openssl")
        .args(["cms", "-sign", "-binary", "-in"])
        .arg(&payload)
        .arg("-signer")
        .arg(&cert)
        .arg("-inkey")
        .arg(&key)
        .args(["-outform", "DER", "-out"])
        .arg(&signature)
        .args(["-nocerts", "-noattr", "-md", "sha512"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("sign module payload");
    assert!(status.success());
    let payload_bytes = fs::read(&payload).expect("read payload");
    let signature_bytes = fs::read(&signature).expect("read signature");
    fs::write(
        &module,
        module_with_signature(&payload_bytes, &signature_bytes),
    )
    .expect("write signed module");

    let output = call_module_signature_verifier(&module, &cert, &root);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let weak_signature = root.join("module-sha256.p7s");
    assert!(
        Command::new("openssl")
            .args(["cms", "-sign", "-binary", "-in"])
            .arg(&payload)
            .arg("-signer")
            .arg(&cert)
            .arg("-inkey")
            .arg(&key)
            .args(["-outform", "DER", "-out"])
            .arg(&weak_signature)
            .args(["-nocerts", "-noattr", "-md", "sha256"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    fs::write(
        &module,
        module_with_signature(&payload_bytes, &fs::read(&weak_signature).unwrap()),
    )
    .unwrap();
    assert!(
        !call_module_signature_verifier(&module, &cert, &root)
            .status
            .success(),
        "accepted a SHA-256 module signature under the SHA-512 kernel policy"
    );

    let opaque_signature = root.join("opaque.p7s");
    assert!(
        Command::new("openssl")
            .args(["cms", "-sign", "-binary", "-nodetach", "-in"])
            .arg(&payload)
            .arg("-signer")
            .arg(&cert)
            .arg("-inkey")
            .arg(&key)
            .args(["-outform", "DER", "-out"])
            .arg(&opaque_signature)
            .args(["-nocerts", "-noattr", "-md", "sha256"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let unrelated = root.join("unrelated-manifest");
    fs::write(&unrelated, b"attacker-controlled external manifest\n").unwrap();
    let output = call_detached_signature_verifier(&opaque_signature, &unrelated, &cert);
    assert!(
        !output.status.success(),
        "accepted an opaque CMS object for an unrelated external manifest"
    );

    let attacker_key = root.join("attacker-key.pem");
    let attacker_cert = root.join("attacker-certificate.pem");
    let attacker_signature = root.join("attacker.p7s");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=embedded-attacker-signer",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&attacker_key)
            .arg("-out")
            .arg(&attacker_cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["cms", "-sign", "-binary", "-in"])
            .arg(&payload)
            .arg("-signer")
            .arg(&attacker_cert)
            .arg("-inkey")
            .arg(&attacker_key)
            .args(["-outform", "DER", "-out"])
            .arg(&attacker_signature)
            .args(["-noattr", "-md", "sha512"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    fs::write(
        &module,
        module_with_signature(
            &payload_bytes,
            &fs::read(&attacker_signature).expect("read attacker signature"),
        ),
    )
    .unwrap();
    let output = call_module_signature_verifier(&module, &cert, &root);
    assert!(
        !output.status.success(),
        "accepted an embedded signer instead of the pinned certificate"
    );

    fs::write(
        &module,
        module_with_signature(&payload_bytes, &signature_bytes),
    )
    .unwrap();

    let mut tampered = fs::read(&module).expect("read signed module");
    tampered[0] ^= 1;
    fs::write(&module, tampered).expect("tamper signed module");
    let output = call_module_signature_verifier(&module, &cert, &root);
    assert!(
        !output.status.success(),
        "accepted a tampered signed module"
    );
    fs::remove_dir_all(root).expect("remove real-signature fixture");
}

#[test]
fn full_verifier_uses_real_sbverify_and_rejects_wrong_signer_and_tampered_image() {
    let Some(fixture) = Fixture::with_real_crypto_and_secure_boot(false, false) else {
        return;
    };
    let output = fixture.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut wrong_signer = Fixture::with_real_crypto_and_secure_boot(false, false).unwrap();
    let wrong_key = wrong_signer.root.join("wrong-kernel.key");
    let wrong_cert = wrong_signer.root.join("wrong-kernel.pem");
    let wrong_der = wrong_signer.root.join("wrong-kernel.der");
    generate_certificate(
        &wrong_key,
        &wrong_cert,
        &wrong_der,
        "/CN=wrong-secure-boot-signer",
    );
    wrong_signer.kernel_cert = wrong_cert;
    wrong_signer.kernel_cert_der = wrong_der;
    wrong_signer.kernel_cert_hash = sha_file(&wrong_signer.kernel_cert_der);
    let output = wrong_signer.run();
    assert!(
        !output.status.success(),
        "full verifier accepted a wrong image signer"
    );

    let tampered = Fixture::with_real_crypto_and_secure_boot(true, false).unwrap();
    let output = tampered.run();
    assert!(
        !output.status.success(),
        "full verifier accepted a tampered EFI image"
    );
}

#[test]
fn rejects_module_certificate_in_signed_pe_overlay() {
    let Some(fixture) = Fixture::with_real_crypto_and_secure_boot(false, true) else {
        return;
    };
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted inert certificate bytes outside the signed PE kernel payload"
    );
}

#[allow(clippy::too_many_arguments)]
fn create_package(
    root: &Path,
    artifacts: &Path,
    name: &str,
    version: &str,
    files: &[(String, Vec<u8>)],
    omitted_buildinfo_field: Option<&str>,
    pkgbuild_hash: &str,
    builddate: &str,
    buildinfo_format: &str,
    buildinfo_extra: Option<&str>,
) -> PathBuf {
    let stage = root.join(format!("stage-{name}"));
    fs::create_dir(&stage).expect("create package stage");
    let mut pkginfo =
        format!("pkgname = {name}\npkgbase = {KERNEL}\npkgver = {version}\narch = x86_64\n");
    if name == NVIDIA {
        pkginfo.push_str(&format!(
            "depend = {KERNEL}=7.1.8-1\ndepend = nvidia-utils=610.57.04\ndepend = libglvnd\nprovides = NVIDIA-MODULE\nconflict = {KERNEL}-nvidia\n"
        ));
    }
    let mut buildinfo = format!(
        "format = {buildinfo_format}\npkgname = {name}\npkgbase = {KERNEL}\npkgver = {version}\npkgarch = x86_64\npkgbuild_sha256sum = {}\nbuilddate = {builddate}\nbuilddir = /build/linux-cachyos\npackager = Offline Builder\nbuildenv = !distcc\noptions = strip\ninstalled = glibc-2.42-1\n",
        pkgbuild_hash,
    );
    if let Some(extra) = buildinfo_extra {
        buildinfo.push_str(extra);
        buildinfo.push('\n');
    }
    if let Some(field) = omitted_buildinfo_field {
        buildinfo = buildinfo
            .lines()
            .filter(|line| !line.starts_with(&format!("{field} = ")))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
    }
    fs::write(stage.join(".PKGINFO"), &pkginfo).expect("write PKGINFO");
    fs::write(stage.join(".BUILDINFO"), &buildinfo).expect("write BUILDINFO");
    for (path, content) in files {
        let target = stage.join(path);
        fs::create_dir_all(target.parent().unwrap()).expect("create member parent");
        if path.ends_with(".zst") {
            let mut child = Command::new("zstd")
                .args(["-q", "-c"])
                .stdin(std::process::Stdio::piped())
                .stdout(fs::File::create(&target).expect("create compressed module"))
                .spawn()
                .expect("start zstd");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(content)
                .expect("write module to zstd");
            assert!(child.wait().expect("wait for zstd").success());
        } else {
            fs::write(target, content).expect("write package member");
        }
    }
    let file_members = files
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let mtree_members = package_archive_members(&file_members);
    normalize_mtimes(&stage, &mtree_members);
    write_finalizer_mtree(&stage);
    let retained = artifacts.join("packages").join(name);
    fs::create_dir(&retained).expect("create retained package metadata");
    fs::write(retained.join(".PKGINFO"), pkginfo).expect("retain PKGINFO");
    fs::write(retained.join(".BUILDINFO"), buildinfo).expect("retain BUILDINFO");
    fs::copy(stage.join(".MTREE"), retained.join(".MTREE")).expect("retain MTREE");

    let archive = artifacts.join(format!("{name}-{version}-x86_64.pkg.tar.zst"));
    let mut command = Command::new("bsdtar");
    command
        .args([
            "--zstd",
            "--no-recursion",
            "--uid",
            "0",
            "--gid",
            "0",
            "--mtime",
            "@1786378335",
            "-cf",
        ])
        .arg(&archive)
        .arg("-C")
        .arg(&stage);
    command.arg(&mtree_members[0]).arg(".MTREE");
    command.args(&mtree_members[1..]);
    let status = command.status().expect("create package archive");
    assert!(status.success());
    archive
}

fn write_mtree(stage: &Path, members: &[String]) {
    normalize_mtimes(stage, members);
    let output = Command::new("bsdtar")
        .current_dir(stage)
        .args([
            "--format=mtree",
            "--options=!all,use-set,type,uid,gid,mode,time,size,sha256,link",
            "--no-recursion",
            "-cf",
            "-",
        ])
        .args(members)
        .output()
        .expect("generate MTREE");
    finish_mtree(stage, output);
}

fn write_finalizer_mtree(stage: &Path) {
    let output = Command::new("bsdtar")
        .current_dir(stage)
        .args([
            "--format=mtree",
            "--options=!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link",
            "--uid",
            "0",
            "--gid",
            "0",
            "--exclude",
            ".MTREE",
            "-cf",
            "-",
            ".",
        ])
        .output()
        .expect("generate finalizer MTREE");
    finish_mtree(stage, output);
}

fn finish_mtree(stage: &Path, output: Output) {
    assert!(
        output.status.success(),
        "MTREE generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::write(stage.join(".MTREE"), gzip_bytes(&output.stdout)).expect("write MTREE");
}

fn normalize_mtimes(stage: &Path, members: &[String]) {
    assert!(
        Command::new("touch")
            .current_dir(stage)
            .args(["-h", "-d", "@1786378335", "--"])
            .args(members)
            .status()
            .expect("normalize fixture mtimes")
            .success()
    );
}

fn read_mtree(stage: &Path) -> String {
    let output = Command::new("gzip")
        .args(["-d", "-c"])
        .arg(stage.join(".MTREE"))
        .output()
        .expect("read MTREE");
    assert!(output.status.success());
    String::from_utf8(output.stdout).expect("MTREE is UTF-8")
}

fn retain_kernel_mtree(fixture: &Fixture) {
    fs::copy(
        fixture.root.join(format!("stage-{KERNEL}/.MTREE")),
        fixture
            .artifacts
            .join("packages")
            .join(KERNEL)
            .join(".MTREE"),
    )
    .unwrap();
}

fn replace_kernel_mtree(fixture: &Fixture, content: &[u8]) {
    fs::write(
        fixture.root.join(format!("stage-{KERNEL}/.MTREE")),
        gzip_bytes(content),
    )
    .unwrap();
    retain_kernel_mtree(fixture);
}

fn run_with_kernel_mtree(fixture: &Fixture, content: &[u8]) -> Output {
    replace_kernel_mtree(fixture, content);
    write_kernel_archive(fixture, &kernel_archive_members(&[]), true);
    fixture.run()
}

fn package_archive_members(files: &[String]) -> Vec<String> {
    let mut directories = BTreeSet::new();
    for file in files {
        let mut parent = Path::new(file).parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            directories.insert(path.to_string_lossy().into_owned());
            parent = path.parent();
        }
    }
    let mut members = vec![".BUILDINFO".to_string(), ".PKGINFO".to_string()];
    members.extend(directories);
    members.extend(files.iter().cloned());
    members
}

fn headers_files(module_certificate_der: &[u8]) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            format!("usr/lib/modules/{RELEASE}/build/include/test.h"),
            b"header\n".to_vec(),
        ),
        (
            format!("usr/lib/modules/{RELEASE}/build/.config"),
            b"CONFIG_64BIT=y\nCONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_ALL=y\nCONFIG_MODULE_SIG_SHA512=y\nCONFIG_MODULE_SIG_KEY=\"certs/signing_key.pem\"\nCONFIG_SYSTEM_EXTRA_CERTIFICATE=n\nCONFIG_SYSTEM_TRUSTED_KEYRING=y\nCONFIG_SYSTEM_TRUSTED_KEYS=\"\"\n"
                .to_vec(),
        ),
        (
            format!("usr/lib/modules/{RELEASE}/build/certs/signing_key.x509"),
            module_certificate_der.to_vec(),
        ),
        (
            format!("usr/lib/modules/{RELEASE}/build/System.map"),
            fake_system_map(module_certificate_der),
        ),
    ]
}

fn rebuild_kernel_archive(fixture: &Fixture, extra_members: &[&str], include_mtree: bool) {
    let members = kernel_archive_members(extra_members);
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    write_mtree(&stage, &members);
    retain_kernel_mtree(fixture);
    write_kernel_archive(fixture, &members, include_mtree);
}

fn kernel_archive_members(extra_members: &[&str]) -> Vec<String> {
    let mut files = vec![
        format!("usr/lib/modules/{RELEASE}/vmlinuz"),
        format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
    ];
    files.extend(extra_members.iter().map(|member| (*member).to_string()));
    package_archive_members(&files)
}

fn write_kernel_archive(fixture: &Fixture, members: &[String], include_mtree: bool) {
    let archive = fixture
        .artifacts
        .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst"));
    fs::remove_file(&archive).unwrap();
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    let mut command = Command::new("tar");
    command
        .args(["--zstd", "--no-recursion", "--mtime=@1786378335", "-cf"])
        .arg(&archive)
        .arg("-C")
        .arg(&stage);
    command.arg(&members[0]);
    if include_mtree {
        command.arg(".MTREE");
    }
    command.args(&members[1..]);
    assert!(command.status().unwrap().success());
    rewrite_sums(&fixture.artifacts);
    resign_manifest(fixture);
}

fn rebuild_nvidia_archive(fixture: &Fixture) {
    let archive = fixture
        .artifacts
        .join(format!("{NVIDIA}-7.1.8-1-x86_64.pkg.tar.zst"));
    fs::remove_file(&archive).unwrap();
    let stage = fixture.root.join(format!("stage-{NVIDIA}"));
    let files =
        NVIDIA_MODULES.map(|name| format!("usr/lib/modules/{RELEASE}/extramodules/{name}.ko.zst"));
    let members = package_archive_members(&files);
    write_mtree(&stage, &members);
    fs::copy(
        stage.join(".MTREE"),
        fixture
            .artifacts
            .join("packages")
            .join(NVIDIA)
            .join(".MTREE"),
    )
    .unwrap();
    let mut command = Command::new("tar");
    command
        .args(["--zstd", "--no-recursion", "--mtime=@1786378335", "-cf"])
        .arg(&archive)
        .arg("-C")
        .arg(&stage)
        .args([".BUILDINFO", ".MTREE"])
        .args(&members[1..]);
    assert!(command.status().unwrap().success());
    rewrite_sums(&fixture.artifacts);
    resign_manifest(fixture);
}

fn rebuild_kernel_archive_with_duplicate_pkginfo(fixture: &Fixture) {
    let archive = fixture
        .artifacts
        .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst"));
    fs::remove_file(&archive).unwrap();
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    let status = Command::new("tar")
        .args(["--zstd", "-cf"])
        .arg(&archive)
        .arg("-C")
        .arg(&stage)
        .args([
            ".BUILDINFO",
            ".MTREE",
            ".PKGINFO",
            ".PKGINFO",
            &format!("usr/lib/modules/{RELEASE}/vmlinuz"),
            &format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    rewrite_sums(&fixture.artifacts);
    resign_manifest(fixture);
}

fn rebuild_kernel_archive_with_oversized_sparse_member(fixture: &Fixture) {
    let archive = fixture
        .artifacts
        .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst"));
    fs::remove_file(&archive).unwrap();
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    let oversized = stage.join("usr/share/doc/oversized-build-record.bin");
    fs::create_dir_all(oversized.parent().unwrap()).unwrap();
    fs::File::create(&oversized)
        .unwrap()
        .set_len(512 * 1024 * 1024 + 1)
        .unwrap();
    let status = Command::new("tar")
        .args(["--sparse", "--zstd", "-cf"])
        .arg(&archive)
        .arg("-C")
        .arg(&stage)
        .args([
            ".BUILDINFO",
            ".MTREE",
            ".PKGINFO",
            &format!("usr/lib/modules/{RELEASE}/vmlinuz"),
            &format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
            "usr/share/doc/oversized-build-record.bin",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    rewrite_sums(&fixture.artifacts);
    resign_manifest(fixture);
}

fn rebuild_kernel_archive_with_trailing_private_key(fixture: &Fixture) {
    let archive = fixture
        .artifacts
        .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst"));
    fs::remove_file(&archive).unwrap();
    let unpacked = fixture.root.join("trailing-private-key.tar");
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    let status = Command::new("tar")
        .args(["-cf"])
        .arg(&unpacked)
        .arg("-C")
        .arg(&stage)
        .args([
            ".BUILDINFO",
            ".MTREE",
            ".PKGINFO",
            &format!("usr/lib/modules/{RELEASE}/vmlinuz"),
            &format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    OpenOptions::new()
        .append(true)
        .open(&unpacked)
        .unwrap()
        .write_all(&private_key_pem(""))
        .unwrap();
    assert!(
        Command::new("zstd")
            .args(["-q", "-c"])
            .arg(&unpacked)
            .stdout(fs::File::create(&archive).unwrap())
            .status()
            .unwrap()
            .success()
    );
    rewrite_sums(&fixture.artifacts);
    resign_manifest(fixture);
}

fn rebuild_kernel_archive_with_sensitive_pax_metadata(fixture: &Fixture) {
    let archive = fixture
        .artifacts
        .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst"));
    fs::remove_file(&archive).unwrap();
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    let status = Command::new("tar")
        .args([
            "--format=pax",
            "--pax-option=comment=BEGIN PRIVATE KEY",
            "--zstd",
            "-cf",
        ])
        .arg(&archive)
        .arg("-C")
        .arg(&stage)
        .args([
            ".BUILDINFO",
            ".MTREE",
            ".PKGINFO",
            &format!("usr/lib/modules/{RELEASE}/vmlinuz"),
            &format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    rewrite_sums(&fixture.artifacts);
    resign_manifest(fixture);
}

fn rebuild_kernel_archive_with_sensitive_gnu_longname(fixture: &Fixture) {
    let archive = fixture
        .artifacts
        .join(format!("{KERNEL}-7.1.8-1-x86_64.pkg.tar.zst"));
    fs::remove_file(&archive).unwrap();
    let unpacked = fixture.root.join("gnu-longname-private-key.tar");
    let stage = fixture.root.join(format!("stage-{KERNEL}"));
    let status = Command::new("tar")
        .args(["-cf"])
        .arg(&unpacked)
        .arg("-C")
        .arg(&stage)
        .args([
            ".BUILDINFO",
            ".MTREE",
            ".PKGINFO",
            &format!("usr/lib/modules/{RELEASE}/vmlinuz"),
            &format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let python = [
        "import pathlib,sys,tarfile; p=pathlib.Path(sys.argv[1]); data=p.read_bytes(); payload=b'.BUILDINFO\\0-----BEGIN PRI",
        "VATE KEY-----\\nsecret\\n'; info=tarfile.TarInfo('././@LongLink'); info.type=tarfile.GNUTYPE_LONGNAME; info.size=len(payload); header=info.tobuf(format=tarfile.GNU_FORMAT); p.write_bytes(header+payload+b'\\0'*((-len(payload))%512)+data)",
    ]
    .concat();
    assert!(
        Command::new("python3")
            .arg("-c")
            .arg(python)
            .arg(&unpacked)
            .status()
            .unwrap()
            .success()
    );
    let listing = Command::new("bsdtar")
        .args(["-tf"])
        .arg(&unpacked)
        .output()
        .unwrap();
    assert!(listing.status.success());
    assert_eq!(
        String::from_utf8(listing.stdout)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        [
            ".BUILDINFO",
            ".MTREE",
            ".PKGINFO",
            &format!("usr/lib/modules/{RELEASE}/vmlinuz"),
            &format!("usr/lib/modules/{RELEASE}/kernel/drivers/platform/x86/acer-wmi.ko.zst"),
        ],
        "logical archive listing exposed the hidden GNU LongName payload"
    );
    assert!(
        Command::new("zstd")
            .args(["-q", "-c"])
            .arg(&unpacked)
            .stdout(fs::File::create(&archive).unwrap())
            .status()
            .unwrap()
            .success()
    );
    rewrite_sums(&fixture.artifacts);
    resign_manifest(fixture);
}

fn signed_module(name: &str, invalid: bool) -> Vec<u8> {
    let payload =
        format!("NAME={name}\nVERMAGIC={RELEASE} SMP preempt mod_unload\nVERSION=610.57.04\n");
    let signature = if invalid {
        "0".repeat(64)
    } else {
        sha(payload.as_bytes())
    };
    module_with_signature(payload.as_bytes(), signature.as_bytes())
}

fn fake_kernel_image(payload: &[u8]) -> Vec<u8> {
    let bzimage = fake_bzimage(payload);
    fake_kernel_image_sections(&[(".linux", &bzimage)])
}

fn fake_builtin_trust_payload(certificate: &[u8]) -> Vec<u8> {
    let mut payload = vec![0_u8; 64];
    payload[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    payload[16..18].copy_from_slice(&(2_u16).to_le_bytes());
    payload[18..20].copy_from_slice(&(62_u16).to_le_bytes());
    payload[20..24].copy_from_slice(&(1_u32).to_le_bytes());
    payload[52..54].copy_from_slice(&(64_u16).to_le_bytes());
    payload[32..40].copy_from_slice(&(64_u64).to_le_bytes());
    payload[54..56].copy_from_slice(&(56_u16).to_le_bytes());
    payload[56..58].copy_from_slice(&(1_u16).to_le_bytes());
    payload.resize(120, 0);
    let trust_offset = payload.len();
    payload.extend_from_slice(certificate);
    payload.resize(payload.len().next_multiple_of(8), 0);
    payload.extend_from_slice(&(certificate.len() as u64).to_le_bytes());
    payload.extend_from_slice(&(certificate.len() as u64).to_le_bytes());
    let trust_size = payload.len() - trust_offset;
    let symbol_names =
        b"\0system_certificate_list\0system_certificate_list_size\0module_cert_size\0";
    let symbol_names_offset = payload.len();
    payload.extend_from_slice(symbol_names);
    payload.resize(payload.len().next_multiple_of(8), 0);
    let symbol_table_offset = payload.len();
    payload.resize(symbol_table_offset + 4 * 24, 0);
    let symbol_values = [
        (1_u32, FAKE_TRUST_ADDRESS, certificate.len() as u64),
        (
            1 + "system_certificate_list".len() as u32 + 1,
            FAKE_TRUST_ADDRESS + certificate.len().next_multiple_of(8) as u64,
            8,
        ),
        (
            1 + "system_certificate_list".len() as u32
                + 1
                + "system_certificate_list_size".len() as u32
                + 1,
            FAKE_TRUST_ADDRESS + certificate.len().next_multiple_of(8) as u64 + 8,
            8,
        ),
    ];
    for (index, (name_offset, value, size)) in symbol_values.into_iter().enumerate() {
        let offset = symbol_table_offset + (index + 1) * 24;
        payload[offset..offset + 4].copy_from_slice(&name_offset.to_le_bytes());
        payload[offset + 4] = 0x11;
        payload[offset + 6..offset + 8].copy_from_slice(&(1_u16).to_le_bytes());
        payload[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
        payload[offset + 16..offset + 24].copy_from_slice(&size.to_le_bytes());
    }
    let section_names = b"\0.init.data\0.strtab\0.symtab\0.shstrtab\0";
    let names_offset = payload.len();
    payload.extend_from_slice(section_names);
    payload.resize(payload.len().next_multiple_of(8), 0);
    let section_offset = payload.len();
    payload.resize(section_offset + 5 * 64, 0);
    payload[40..48].copy_from_slice(&(section_offset as u64).to_le_bytes());
    payload[58..60].copy_from_slice(&(64_u16).to_le_bytes());
    payload[60..62].copy_from_slice(&(5_u16).to_le_bytes());
    payload[62..64].copy_from_slice(&(4_u16).to_le_bytes());
    payload[64..68].copy_from_slice(&(1_u32).to_le_bytes());
    payload[68..72].copy_from_slice(&(4_u32).to_le_bytes());
    payload[72..80].copy_from_slice(&(trust_offset as u64).to_le_bytes());
    payload[80..88].copy_from_slice(&(FAKE_TRUST_ADDRESS).to_le_bytes());
    payload[88..96].copy_from_slice(&(FAKE_TRUST_ADDRESS).to_le_bytes());
    payload[96..104].copy_from_slice(&(trust_size as u64).to_le_bytes());
    payload[104..112].copy_from_slice(&(trust_size as u64).to_le_bytes());
    payload[112..120].copy_from_slice(&(8_u64).to_le_bytes());
    let trust_header = section_offset + 64;
    payload[trust_header..trust_header + 4].copy_from_slice(&(1_u32).to_le_bytes());
    payload[trust_header + 4..trust_header + 8].copy_from_slice(&(1_u32).to_le_bytes());
    payload[trust_header + 8..trust_header + 16].copy_from_slice(&(2_u64).to_le_bytes());
    payload[trust_header + 16..trust_header + 24]
        .copy_from_slice(&(FAKE_TRUST_ADDRESS).to_le_bytes());
    payload[trust_header + 24..trust_header + 32]
        .copy_from_slice(&(trust_offset as u64).to_le_bytes());
    payload[trust_header + 32..trust_header + 40]
        .copy_from_slice(&(trust_size as u64).to_le_bytes());
    payload[trust_header + 48..trust_header + 56].copy_from_slice(&(8_u64).to_le_bytes());
    let strings_header = section_offset + 128;
    let strings_name_offset = 1 + ".init.data".len() + 1;
    payload[strings_header..strings_header + 4]
        .copy_from_slice(&(strings_name_offset as u32).to_le_bytes());
    payload[strings_header + 4..strings_header + 8].copy_from_slice(&(3_u32).to_le_bytes());
    payload[strings_header + 24..strings_header + 32]
        .copy_from_slice(&(symbol_names_offset as u64).to_le_bytes());
    payload[strings_header + 32..strings_header + 40]
        .copy_from_slice(&(symbol_names.len() as u64).to_le_bytes());
    payload[strings_header + 48..strings_header + 56].copy_from_slice(&(1_u64).to_le_bytes());
    let symbols_header = section_offset + 192;
    let symbols_name_offset = strings_name_offset + ".strtab".len() + 1;
    payload[symbols_header..symbols_header + 4]
        .copy_from_slice(&(symbols_name_offset as u32).to_le_bytes());
    payload[symbols_header + 4..symbols_header + 8].copy_from_slice(&(2_u32).to_le_bytes());
    payload[symbols_header + 24..symbols_header + 32]
        .copy_from_slice(&(symbol_table_offset as u64).to_le_bytes());
    payload[symbols_header + 32..symbols_header + 40]
        .copy_from_slice(&((4 * 24_u64).to_le_bytes()));
    payload[symbols_header + 40..symbols_header + 44].copy_from_slice(&(2_u32).to_le_bytes());
    payload[symbols_header + 44..symbols_header + 48].copy_from_slice(&(1_u32).to_le_bytes());
    payload[symbols_header + 48..symbols_header + 56].copy_from_slice(&(8_u64).to_le_bytes());
    payload[symbols_header + 56..symbols_header + 64].copy_from_slice(&(24_u64).to_le_bytes());
    let names_header = section_offset + 256;
    let names_name_offset = symbols_name_offset + ".symtab".len() + 1;
    payload[names_header..names_header + 4]
        .copy_from_slice(&(names_name_offset as u32).to_le_bytes());
    payload[names_header + 4..names_header + 8].copy_from_slice(&(3_u32).to_le_bytes());
    payload[names_header + 24..names_header + 32]
        .copy_from_slice(&(names_offset as u64).to_le_bytes());
    payload[names_header + 32..names_header + 40]
        .copy_from_slice(&(section_names.len() as u64).to_le_bytes());
    payload[names_header + 48..names_header + 56].copy_from_slice(&(1_u64).to_le_bytes());
    payload
}

fn fake_builtin_trust_payload_with_btf(certificate: &[u8]) -> Vec<u8> {
    let mut payload = fake_builtin_trust_payload(certificate);
    let old_section_offset = u64::from_le_bytes(payload[40..48].try_into().unwrap()) as usize;
    let old_headers = payload[old_section_offset..old_section_offset + 5 * 64].to_vec();
    let trust_size = u64::from_le_bytes(old_headers[64 + 32..64 + 40].try_into().unwrap());

    let btf_strings =
        b"\0system_certificate_list\0system_certificate_list_size\0module_cert_size\0.init.data\0";
    let system_certificate_list = 1_u32;
    let system_certificate_list_size =
        system_certificate_list + "system_certificate_list".len() as u32 + 1;
    let module_cert_size =
        system_certificate_list_size + "system_certificate_list_size".len() as u32 + 1;
    let init_data = module_cert_size + "module_cert_size".len() as u32 + 1;
    let mut btf_types = Vec::new();
    btf_types.extend_from_slice(&0_u32.to_le_bytes());
    btf_types.extend_from_slice(&(1_u32 << 24).to_le_bytes());
    btf_types.extend_from_slice(&1_u32.to_le_bytes());
    btf_types.extend_from_slice(&8_u32.to_le_bytes());
    for name in [
        system_certificate_list,
        system_certificate_list_size,
        module_cert_size,
    ] {
        btf_types.extend_from_slice(&name.to_le_bytes());
        btf_types.extend_from_slice(&(14_u32 << 24).to_le_bytes());
        btf_types.extend_from_slice(&1_u32.to_le_bytes());
        btf_types.extend_from_slice(&1_u32.to_le_bytes());
    }
    btf_types.extend_from_slice(&init_data.to_le_bytes());
    btf_types.extend_from_slice(&((15_u32 << 24) | 3).to_le_bytes());
    btf_types.extend_from_slice(&(trust_size as u32).to_le_bytes());
    let certificate_padding_offset = certificate.len().next_multiple_of(8) as u32;
    for (variable_type, offset, size) in [
        (2_u32, 0_u32, certificate.len() as u32),
        (3_u32, certificate_padding_offset, 8_u32),
        (4_u32, certificate_padding_offset + 8, 8_u32),
    ] {
        btf_types.extend_from_slice(&variable_type.to_le_bytes());
        btf_types.extend_from_slice(&offset.to_le_bytes());
        btf_types.extend_from_slice(&size.to_le_bytes());
    }
    let mut btf = Vec::new();
    btf.extend_from_slice(&0xeb9f_u16.to_le_bytes());
    btf.push(1);
    btf.push(0);
    btf.extend_from_slice(&24_u32.to_le_bytes());
    btf.extend_from_slice(&0_u32.to_le_bytes());
    btf.extend_from_slice(&(btf_types.len() as u32).to_le_bytes());
    btf.extend_from_slice(&(btf_types.len() as u32).to_le_bytes());
    btf.extend_from_slice(&(btf_strings.len() as u32).to_le_bytes());
    btf.extend_from_slice(&btf_types);
    btf.extend_from_slice(btf_strings);

    payload.resize(payload.len().next_multiple_of(8), 0);
    let btf_offset = payload.len();
    payload.extend_from_slice(&btf);
    let section_names = b"\0.init.data\0.strtab\0.symtab\0.shstrtab\0.BTF\0";
    let btf_name_offset = section_names.len() - ".BTF\0".len();
    payload.resize(payload.len().next_multiple_of(8), 0);
    let names_offset = payload.len();
    payload.extend_from_slice(section_names);
    payload.resize(payload.len().next_multiple_of(8), 0);
    let section_offset = payload.len();
    payload.extend_from_slice(&old_headers);
    payload.resize(section_offset + 6 * 64, 0);
    payload[40..48].copy_from_slice(&(section_offset as u64).to_le_bytes());
    payload[60..62].copy_from_slice(&(6_u16).to_le_bytes());
    let names_header = section_offset + 4 * 64;
    payload[names_header + 24..names_header + 32]
        .copy_from_slice(&(names_offset as u64).to_le_bytes());
    payload[names_header + 32..names_header + 40]
        .copy_from_slice(&(section_names.len() as u64).to_le_bytes());
    let btf_header = section_offset + 5 * 64;
    payload[btf_header..btf_header + 4].copy_from_slice(&(btf_name_offset as u32).to_le_bytes());
    payload[btf_header + 4..btf_header + 8].copy_from_slice(&(1_u32).to_le_bytes());
    payload[btf_header + 24..btf_header + 32].copy_from_slice(&(btf_offset as u64).to_le_bytes());
    payload[btf_header + 32..btf_header + 40].copy_from_slice(&(btf.len() as u64).to_le_bytes());
    payload[btf_header + 48..btf_header + 56].copy_from_slice(&(4_u64).to_le_bytes());
    payload
}

const FAKE_TRUST_ADDRESS: u64 = 0xffff_ffff_8100_0000;

fn fake_system_map(certificate: &[u8]) -> Vec<u8> {
    let size_address = FAKE_TRUST_ADDRESS + certificate.len().next_multiple_of(8) as u64;
    format!(
        "{FAKE_TRUST_ADDRESS:016x} R system_certificate_list\n{size_address:016x} R system_certificate_list_size\n{:016x} R module_cert_size\n",
        size_address + 8
    )
    .into_bytes()
}

fn fake_bzimage(payload: &[u8]) -> Vec<u8> {
    let payload_offset = 0x80_u32;
    let mut text = vec![0_u8; payload_offset as usize];
    text.extend_from_slice(payload);
    let mut image = fake_kernel_image_sections(&[(".text", &text)]);
    image[0x1f1] = 7;
    image[0x1fe..0x200].copy_from_slice(b"\x55\xaa");
    image[0x202..0x206].copy_from_slice(b"HdrS");
    image[0x206..0x208].copy_from_slice(&(0x020f_u16).to_le_bytes());
    image[0x211] = 1;
    image[0x248..0x24c].copy_from_slice(&payload_offset.to_le_bytes());
    image[0x24c..0x250].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    image
}

fn fake_kernel_image_sections(sections: &[(&str, &[u8])]) -> Vec<u8> {
    let mut image = vec![0_u8; 0x200];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    image[0x84..0x86].copy_from_slice(&(0x8664_u16).to_le_bytes());
    image[0x86..0x88].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    image[0x94..0x96].copy_from_slice(&(152_u16).to_le_bytes());
    image[0x98..0x9a].copy_from_slice(&(0x20b_u16).to_le_bytes());
    image[0x98 + 108..0x98 + 112].copy_from_slice(&(5_u32).to_le_bytes());
    let mut raw_offset = 0x200_u32;
    for (index, (name, payload)) in sections.iter().enumerate() {
        assert!(name.len() <= 8);
        let header = 0x98 + 152 + 40 * index;
        image[header..header + name.len()].copy_from_slice(name.as_bytes());
        image[header + 8..header + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        image[header + 16..header + 20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        image[header + 20..header + 24].copy_from_slice(&raw_offset.to_le_bytes());
        image.extend_from_slice(payload);
        raw_offset += payload.len() as u32;
    }
    image
}

fn generate_certificate(key: &Path, cert: &Path, der: &Path, subject: &str) {
    assert!(
        Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", subject, "-days", "1",
                "-keyout",
            ])
            .arg(key)
            .arg("-out")
            .arg(cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["x509", "-in"])
            .arg(cert)
            .args(["-outform", "DER", "-out"])
            .arg(der)
            .status()
            .unwrap()
            .success()
    );
}

fn real_signed_module(root: &Path, key: &Path, cert: &Path, name: &str, index: usize) -> Vec<u8> {
    real_signed_module_with_metadata(root, key, cert, name, RELEASE, "610.57.04", index)
}

fn real_signed_module_with_metadata(
    root: &Path,
    key: &Path,
    cert: &Path,
    name: &str,
    vermagic: &str,
    version: &str,
    index: usize,
) -> Vec<u8> {
    let source = root.join(format!("real-module-{index}.c"));
    let payload = root.join(format!("real-module-{index}.payload"));
    let signature = root.join(format!("real-module-{index}.p7s"));
    fs::write(
        &source,
        format!(
            "__attribute__((section(\".modinfo\"), used)) static const char module_name[] = \"name={name}\";\n\
             __attribute__((section(\".modinfo\"), used)) static const char module_vermagic[] = \"vermagic={vermagic} SMP preempt mod_unload\";\n\
             __attribute__((section(\".modinfo\"), used)) static const char module_version[] = \"version={version}\";\n"
        ),
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-c", "-o"])
            .arg(&payload)
            .arg(&source)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["cms", "-sign", "-binary", "-in"])
            .arg(&payload)
            .arg("-signer")
            .arg(cert)
            .arg("-inkey")
            .arg(key)
            .args(["-outform", "DER", "-out"])
            .arg(&signature)
            .args(["-nocerts", "-noattr", "-md", "sha512"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let payload_bytes = fs::read(&payload).unwrap();
    module_with_signature(&payload_bytes, &fs::read(signature).unwrap())
}

fn module_with_signature(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let signer = b"fixture-signer";
    let key_id = b"key-id";
    let mut module = payload.to_vec();
    module.extend_from_slice(signer);
    module.extend_from_slice(key_id);
    module.extend_from_slice(signature);
    module.extend_from_slice(&[0, 6, 2, signer.len() as u8, key_id.len() as u8, 0, 0, 0]);
    module.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    module.extend_from_slice(b"~Module signature appended~\n");
    module
}

fn call_module_signature_verifier(module: &Path, cert: &Path, work: &Path) -> Output {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
loaded.verify_module_signature(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]), 99)
"#;
    Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(module)
        .arg(cert)
        .arg(work)
        .output()
        .expect("call module signature verifier")
}

fn call_detached_signature_verifier(signature: &Path, content: &Path, cert: &Path) -> Output {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
loaded.verify_detached_signature(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]), "manifest")
"#;
    Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(signature)
        .arg(content)
        .arg(cert)
        .output()
        .expect("call detached signature verifier")
}

fn call_schema_policy_validator(workspace: &Path, schema: &Path) -> Output {
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
policy = loaded.parse_policy(pathlib.Path(sys.argv[2]))
loaded.validate_schema_policy(pathlib.Path(sys.argv[3]), policy)
"#;
    Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(workspace.join("packaging/kernel/provenance-policy.toml"))
        .arg(schema)
        .output()
        .expect("call schema-policy validator")
}

fn call_compatibility_policy_validator(workspace: &Path, compatibility: &Path) -> Output {
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
policy = loaded.parse_policy(pathlib.Path(sys.argv[2]))
compatibility = loaded.parse_toml(pathlib.Path(sys.argv[3]), "compatibility declaration")
loaded.validate_compatibility_policy(compatibility, policy)
"#;
    Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(workspace.join("packaging/kernel/provenance-policy.toml"))
        .arg(compatibility)
        .output()
        .expect("call compatibility-policy validator")
}

fn call_safe_member_validator(workspace: &Path, member: &str) -> Output {
    let source = r#"
import importlib.machinery
import importlib.util
import sys
loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
raise SystemExit(0 if loaded.safe_member(sys.argv[2]) else 1)
"#;
    Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(member)
        .output()
        .expect("call safe-member validator")
}

fn schema_for_fixture(fixture: &Fixture) -> serde_json::Value {
    let mut schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/package-provenance-v1.json"
    )))
    .unwrap();
    schema["properties"]["build"]["properties"]["package_manifest_signer_fingerprint"]["const"] =
        fixture.package_cert_hash.clone().into();
    schema["$defs"]["module"]["properties"]["signer_fingerprint"]["const"] =
        fixture.module_cert_hash.clone().into();
    schema["properties"]["kernel"]["properties"]["module_trust_certificate_fingerprint"]["const"] =
        fixture.module_cert_hash.clone().into();
    schema["properties"]["kernel"]["properties"]["image_signer_fingerprint"]["const"] =
        fixture.kernel_cert_hash.clone().into();
    schema
}

fn call_failing_evidence_publication(root: &Path) -> Output {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let source = r#"
import importlib.machinery
import importlib.util
import pathlib
import sys
loader = importlib.machinery.SourceFileLoader("package_provenance", sys.argv[1])
spec = importlib.util.spec_from_loader("package_provenance", loader)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
def fail_link(*args, **kwargs):
    raise OSError("injected link failure")
loaded.os.link = fail_link
try:
    loaded.write_evidence(pathlib.Path(sys.argv[2]), {"schema_version": 1})
except loaded.VerificationError:
    raise SystemExit(1)
raise SystemExit(0)
"#;
    Command::new("python3")
        .args(["-c", source])
        .arg(workspace.join("scripts/verify-package-provenance"))
        .arg(root.join("link-failure.json"))
        .output()
        .expect("call evidence publisher")
}

fn rewrite_build_attestation(artifacts: &Path) {
    let attestation = format!(
        "format = 1\nsource_lock_sha256 = \"{}\"\nbuild_environment_sha256 = \"{}\"\npkgbuild_sha256 = \"{}\"\npackage_set_srcinfo_sha256 = \"{}\"\n",
        sha_file(&artifacts.join("source-lock.toml")),
        sha_file(&artifacts.join("build-environment.toml")),
        sha_file(&artifacts.join("PKGBUILD")),
        sha_file(&artifacts.join("package-set.SRCINFO")),
    );
    fs::write(artifacts.join("build-attestation.toml"), attestation)
        .expect("rewrite build attestation");
}

fn valid_srcinfo() -> String {
    format!(
        "pkgbase = {KERNEL}\n\tpkgver = 7.1.8\n\tpkgrel = 1\n\tarch = x86_64\n\tmakedepends = bc\n\tmakedepends = binutils\n\tmakedepends = cpio\n\tmakedepends = gettext\n\tmakedepends = glibc\n\tmakedepends = libelf\n\tmakedepends = libgcc\n\tmakedepends = openssl\n\tmakedepends = pahole\n\tmakedepends = perl\n\tmakedepends = python\n\tmakedepends = rust\n\tmakedepends = rust-bindgen\n\tmakedepends = rust-src\n\tmakedepends = tar\n\tmakedepends = xxhash\n\tmakedepends = xz\n\tmakedepends = zlib\n\tmakedepends = zstd\n\tsource = https://github.com/CachyOS/linux/releases/download/cachyos-7.1.8-1/cachyos-7.1.8-1.tar.gz\n\tsource = https://github.com/CachyOS/linux/releases/download/cachyos-7.1.8-1/cachyos-7.1.8-1.tar.gz.asc\n\tsource = https://raw.githubusercontent.com/CachyOS/linux-cachyos/3c399d306eed6497838b246b9dbe73ec2cd1bb2f/linux-cachyos/config\n\tsource = https://download.nvidia.com/XFree86/NVIDIA-kernel-module-source/NVIDIA-kernel-module-source-610.57.04.tar.xz\n\tsource = https://raw.githubusercontent.com/CachyOS/kernel-patches/fcdc4806b62f86b62a61b92c4b7213a1759537e5/7.1/misc/nvidia/0002-fix-dsc-correct-RC-parameter-tables-to-match-VESA-DS.patch\n\tsource = https://raw.githubusercontent.com/CachyOS/kernel-patches/fcdc4806b62f86b62a61b92c4b7213a1759537e5/7.1/misc/nvidia/0004-fix-dp-add-Bigscreen-Beyond-VR-headset-to-WAR-databa.patch\n\tsource = 0001-acer-wmi-add-pt31553-telemetry.patch\n\tsource = 0002-acer-wmi-enable-pt31553-pwm.patch\npkgname = {KERNEL}\npkgname = {HEADERS}\npkgname = {NVIDIA}\n\tdepends = {KERNEL}=7.1.8-1\n\tdepends = nvidia-utils=610.57.04\n\tdepends = libglvnd\n\tprovides = NVIDIA-MODULE\n\tconflicts = {KERNEL}-nvidia\n"
    )
}

fn rewrite_sums(artifacts: &Path) {
    let mut retained = [
        "build-attestation.toml",
        "build-environment.toml",
        "build.log",
        "PKGBUILD",
        "package-set.SRCINFO",
        "source-lock.toml",
    ]
    .iter()
    .map(|path| artifacts.join(path))
    .collect::<Vec<_>>();
    for package in [KERNEL, HEADERS, NVIDIA] {
        for metadata in [".BUILDINFO", ".MTREE", ".PKGINFO"] {
            retained.push(artifacts.join("packages").join(package).join(metadata));
        }
    }
    retained.extend(
        fs::read_dir(artifacts)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(".pkg.tar.zst")
            }),
    );
    retained.sort_by_key(|path| path.strip_prefix(artifacts).unwrap().to_path_buf());
    let sums = retained
        .iter()
        .map(|path| {
            format!(
                "{}  {}",
                sha_file(path),
                path.strip_prefix(artifacts).unwrap().to_string_lossy()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(artifacts.join("SHA256SUMS"), sums).expect("rewrite checksums");
}

fn resign_manifest(fixture: &Fixture) {
    fs::write(
        &fixture.manifest_signature,
        sha_file(&fixture.artifacts.join("SHA256SUMS")),
    )
    .expect("rewrite fixture manifest signature");
}

fn sign_real_manifest(fixture: &Fixture) {
    assert!(
        Command::new("openssl")
            .args(["cms", "-sign", "-binary", "-in"])
            .arg(fixture.artifacts.join("SHA256SUMS"))
            .arg("-signer")
            .arg(&fixture.package_cert)
            .arg("-inkey")
            .arg(fixture.root.join("real-package.key"))
            .args(["-outform", "DER", "-out"])
            .arg(&fixture.manifest_signature)
            .args(["-nocerts", "-noattr", "-md", "sha256"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}

fn private_key_pem(prefix: &str) -> Vec<u8> {
    format!("-----BEGIN {prefix}PRIVATE KEY-----\nsecret\n-----END {prefix}PRIVATE KEY-----\n")
        .into_bytes()
}

fn certificate_fixture(payload: &[u8]) -> Vec<u8> {
    [
        b"-----BEGIN CERT".as_slice(),
        b"IFICATE-----\n",
        payload,
        b"\n-----END CERTIFICATE-----\n",
    ]
    .concat()
}

fn age_secret_fixture() -> Vec<u8> {
    [
        b"AGE-SECRET-".as_slice(),
        b"KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ".as_slice(),
    ]
    .concat()
}

fn temporary_fixture(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "fan-control-{label}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    root
}

fn assert_sensitive_package_rejected(path: &str, content: &[u8]) {
    let fixture = Fixture::with_sensitive_package_file(path, content);
    let output = fixture.run();
    assert!(
        !output.status.success(),
        "accepted sensitive package member {path}"
    );
    assert!(!fixture.root.join("provenance.json").exists());
}

fn encrypted_pkcs8_der() -> Vec<u8> {
    let root = temporary_fixture("encrypted-pkcs8");
    let key = root.join("key.pem");
    let encrypted = root.join("encrypted.der");
    assert!(
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["pkcs8", "-topk8", "-in"])
            .arg(&key)
            .args([
                "-outform",
                "DER",
                "-v1",
                "PBE-SHA1-3DES",
                "-passout",
                "pass:review-fixture",
                "-out",
            ])
            .arg(&encrypted)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(encrypted).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn ber_encrypted_pkcs8(der: &[u8]) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    let header = if der[1] < 0x80 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    };
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[header..]);
    ber.extend_from_slice(&[0, 0]);

    let root = temporary_fixture("ber-encrypted-pkcs8");
    let path = root.join("encrypted.ber");
    fs::write(&path, &ber).unwrap();
    assert!(
        Command::new("openssl")
            .args(["pkcs8", "-inform", "DER", "-in"])
            .arg(&path)
            .args(["-passin", "pass:review-fixture", "-out", "/dev/null"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "OpenSSL did not accept the BER encrypted PKCS#8 fixture"
    );
    fs::remove_dir_all(root).unwrap();
    ber
}

fn ber_nonminimal_encrypted_pkcs8(der: &[u8]) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    let length_octets = usize::from(der[1] & 0x7f);
    assert!(der[1] > 0x80 && length_octets < 126);
    let mut ber = vec![0x30, 0x80 | ((length_octets + 1) as u8), 0];
    ber.extend_from_slice(&der[2..]);
    ber
}

fn ber_indefinite_algorithm_pkcs8(der: &[u8]) -> Vec<u8> {
    let outer_header = der_header_len(der);
    let algorithm = &der[outer_header..];
    assert_eq!(algorithm[0], 0x30);
    let algorithm_header = der_header_len(algorithm);
    let algorithm_length = der_value_len(algorithm);
    let algorithm_end = algorithm_header + algorithm_length;
    let mut value = vec![0x30, 0x80];
    value.extend_from_slice(&algorithm[algorithm_header..algorithm_end]);
    value.extend_from_slice(&[0, 0]);
    value.extend_from_slice(&algorithm[algorithm_end..]);
    let mut ber = vec![0x30];
    ber.extend(der_length(value.len()));
    ber.extend(value);
    ber
}

fn ber_unencrypted_pkcs8(der: &[u8]) -> Vec<u8> {
    let outer_header = der_header_len(der);
    let value = &der[outer_header..];
    let version_end = der_header_len(value) + der_value_len(value);
    let algorithm = &value[version_end..];
    let algorithm_header = der_header_len(algorithm);
    let algorithm_end = algorithm_header + der_value_len(algorithm);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&value[..version_end]);
    ber.extend_from_slice(&[0x30, 0x80]);
    ber.extend_from_slice(&algorithm[algorithm_header..algorithm_end]);
    ber.extend_from_slice(&[0, 0]);
    ber.extend_from_slice(&algorithm[algorithm_end..]);
    ber.extend_from_slice(&[0, 0]);
    assert_openssl_accepts_pkey(&ber);
    ber
}

fn ber_fragmented_encrypted_pkcs8(der: &[u8]) -> Vec<u8> {
    let outer_header = der_header_len(der);
    let value = &der[outer_header..];
    let algorithm_end = der_header_len(value) + der_value_len(value);
    let encrypted = &value[algorithm_end..];
    let encrypted_header = der_header_len(encrypted);
    let encrypted_end = encrypted_header + der_value_len(encrypted);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&value[..algorithm_end]);
    ber.extend_from_slice(&[0x24, 0x80]);
    for _ in 0..4097 {
        ber.extend_from_slice(&[0x04, 0x00]);
    }
    ber.push(0x04);
    ber.extend(der_length(encrypted_end - encrypted_header));
    ber.extend_from_slice(&encrypted[encrypted_header..encrypted_end]);
    ber.extend_from_slice(&[0, 0, 0, 0]);
    ber
}

fn assert_openssl_accepts_pkey(content: &[u8]) {
    let root = temporary_fixture("ber-private-key");
    let path = root.join("private.ber");
    fs::write(&path, content).unwrap();
    assert!(
        Command::new("openssl")
            .args(["pkey", "-inform", "DER", "-in"])
            .arg(&path)
            .arg("-noout")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "OpenSSL did not accept the BER private-key fixture"
    );
    fs::remove_dir_all(root).unwrap();
}

fn der_header_len(content: &[u8]) -> usize {
    if content[1] < 0x80 {
        2
    } else {
        2 + usize::from(content[1] & 0x7f)
    }
}

fn der_value_len(content: &[u8]) -> usize {
    if content[1] < 0x80 {
        usize::from(content[1])
    } else {
        let octets = usize::from(content[1] & 0x7f);
        usize::from_be_bytes({
            let mut encoded = [0; size_of::<usize>()];
            encoded[size_of::<usize>() - octets..].copy_from_slice(&content[2..2 + octets]);
            encoded
        })
    }
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let encoded = length.to_be_bytes();
    let first = encoded.iter().position(|byte| *byte != 0).unwrap();
    let octets = &encoded[first..];
    let mut result = vec![0x80 | (octets.len() as u8)];
    result.extend_from_slice(octets);
    result
}

fn binary_openpgp_secret_key(tag: u8) -> Vec<u8> {
    let body = [4, 0, 0, 0, 0, 1, 0, 8, 0x81, 0, 2, 3, 0, 0, 1, 1, 0, 0];
    let mut packet = vec![0xC0 | tag, body.len() as u8];
    packet.extend(body);
    packet
}

fn legacy_x509_certificate_pem() -> Vec<u8> {
    let root = temporary_fixture("legacy-x509-certificate");
    let key = root.join("key.pem");
    let certificate = root.join("certificate.pem");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=legacy-certificate-fixture",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read_to_string(certificate)
        .unwrap()
        .replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE")
        .replace("END CERTIFICATE", "END X509 CERTIFICATE")
        .into_bytes();
    fs::remove_dir_all(root).unwrap();
    content
}

fn pkcs7_certificate_pem() -> Vec<u8> {
    let root = temporary_fixture("pkcs7-certificate");
    let key = root.join("key.pem");
    let certificate = root.join("certificate.pem");
    let bundle = root.join("bundle.pem");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=pkcs7-certificate-fixture",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["crl2pkcs7", "-nocrl", "-certfile"])
            .arg(&certificate)
            .arg("-out")
            .arg(&bundle)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(bundle).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn rsa_pss_certificate_der() -> Vec<u8> {
    let root = temporary_fixture("rsa-pss-certificate");
    let key = root.join("key.pem");
    let certificate = root.join("certificate.der");
    assert!(
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA-PSS",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&key)
            .args(["-subj", "/CN=rsa-pss-certificate-fixture", "-days", "1"])
            .args(["-outform", "DER", "-out"])
            .arg(&certificate)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(certificate).unwrap();
    assert!(
        !content
            .windows(11)
            .any(|window| { window == b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" })
    );
    fs::remove_dir_all(root).unwrap();
    content
}

fn private_jwk() -> Vec<u8> {
    [
        b"{\"k".as_slice(),
        b"ty\":\"RSA\",\"n\":\"public-modulus\",\"e\":\"AQAB\",".as_slice(),
        b"\"d".as_slice(),
        b"\":\"private-exponent\"}\n".as_slice(),
    ]
    .concat()
}

fn binary_dh_private_key() -> Vec<u8> {
    let root = std::env::temp_dir().join(format!(
        "fan-control-dh-sensitive-material-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let key = root.join("private.der");
    assert!(
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "DH",
                "-pkeyopt",
                "group:ffdhe2048",
                "-outform",
                "DER",
                "-out",
            ])
            .arg(&key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(&key).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn putty_private_key() -> Vec<u8> {
    [
        b"PuTTY-User-Key-".as_slice(),
        b"File-3: ssh-rsa\nEncryption: none\nPrivate-Lines: 1\nsecret\nPrivate-MAC: deadbeef\n",
    ]
    .concat()
}

fn zip_with_private_key() -> Vec<u8> {
    let root = std::env::temp_dir().join(format!(
        "fan-control-nested-zip-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let secret = root.join("private-key.pem");
    let archive = root.join("private-key.zip");
    fs::write(&secret, private_key_pem("")).unwrap();
    assert!(
        Command::new("python3")
            .arg("-c")
            .arg("import pathlib,sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED); z.write(sys.argv[2], 'private-key.pem'); z.close()")
            .arg(&archive)
            .arg(&secret)
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(archive).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn tar_gz_with_private_key() -> Vec<u8> {
    let root = std::env::temp_dir().join(format!(
        "fan-control-nested-tar-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let secret = root.join("private-key.pem");
    let archive = root.join("private-key.tar.gz");
    fs::write(&secret, private_key_pem("")).unwrap();
    assert!(
        Command::new("python3")
            .arg("-c")
            .arg("import sys,tarfile; t=tarfile.open(sys.argv[1],'w:gz'); t.add(sys.argv[2], arcname='private-key.pem'); t.close()")
            .arg(&archive)
            .arg(&secret)
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(archive).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn v7_tar_with_compressed_private_key() -> Vec<u8> {
    let root = temporary_fixture("v7-tar-container");
    let member = root.join("private-key.pem.gz");
    let archive = root.join("neutral-container.bin");
    fs::write(&member, gzip_bytes(&private_key_pem(""))).unwrap();
    assert!(
        Command::new("tar")
            .args(["--format=v7", "-cf"])
            .arg(&archive)
            .arg("-C")
            .arg(&root)
            .arg("private-key.pem.gz")
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(archive).unwrap();
    assert_ne!(&content[257..262], b"ustar");
    fs::remove_dir_all(root).unwrap();
    content
}

fn binary_key_and_certificate() -> (Vec<u8>, Vec<u8>) {
    let root = std::env::temp_dir().join(format!(
        "fan-control-binary-sensitive-material-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let pem_key = root.join("key.pem");
    let pem_cert = root.join("cert.pem");
    let der_key = root.join("key.der");
    let der_cert = root.join("cert.der");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=binary-sensitive-fixture",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&pem_key)
            .arg("-out")
            .arg(&pem_cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(&pem_key)
            .args(["-outform", "DER", "-out"])
            .arg(&der_key)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["x509", "-in"])
            .arg(&pem_cert)
            .args(["-outform", "DER", "-out"])
            .arg(&der_cert)
            .status()
            .unwrap()
            .success()
    );
    let result = (fs::read(der_key).unwrap(), fs::read(der_cert).unwrap());
    fs::remove_dir_all(root).unwrap();
    result
}

fn binary_x25519_key() -> Vec<u8> {
    let root = std::env::temp_dir().join(format!(
        "fan-control-x25519-sensitive-material-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let key = root.join("key.der");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "X25519", "-outform", "DER", "-out"])
            .arg(&key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let content = fs::read(key).unwrap();
    fs::remove_dir_all(root).unwrap();
    content
}

fn gzip_bytes(content: &[u8]) -> Vec<u8> {
    let mut child = Command::new("gzip")
        .arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start gzip");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(content)
        .expect("write gzip input");
    let output = child.wait_with_output().expect("finish gzip");
    assert!(output.status.success());
    output.stdout
}

fn base64_bytes(content: &[u8]) -> Vec<u8> {
    openssl_base64_bytes(content, true)
}

fn irregular_path_base64(content: &[u8]) -> Vec<u8> {
    let mut encoded = base64_bytes(content);
    while encoded.last() == Some(&b'=') {
        encoded.pop();
    }
    let widths = [9, 11, 13, 10, 12];
    let mut output = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let end = (offset + widths[index % widths.len()]).min(encoded.len());
        if !output.is_empty() {
            output.push(b'/');
        }
        output.extend_from_slice(&encoded[offset..end]);
        offset = end;
        index += 1;
    }
    output.push(b'\n');
    output
}

fn long_irregular_path_base64(content: &[u8]) -> Vec<u8> {
    let encoded = base64_bytes(content);
    assert!(
        encoded.contains(&b'/'),
        "fixture needs a native Base64 slash"
    );
    let widths = [105, 109, 113, 107, 111];
    let mut output = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let end = (offset + widths[index % widths.len()]).min(encoded.len());
        if !output.is_empty() {
            output.push(b'/');
        }
        output.extend_from_slice(&encoded[offset..end]);
        offset = end;
        index += 1;
    }
    output.push(b'\n');
    output
}

fn medium_irregular_path_base64(content: &[u8]) -> Vec<u8> {
    let encoded = base64_bytes(content);
    assert!(
        encoded.contains(&b'/'),
        "fixture needs a native Base64 slash"
    );
    let widths = [14, 19, 23, 17, 29];
    let mut output = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let end = (offset + widths[index % widths.len()]).min(encoded.len());
        if !output.is_empty() {
            output.push(b'/');
        }
        output.extend_from_slice(&encoded[offset..end]);
        offset = end;
        index += 1;
    }
    output.push(b'\n');
    output
}

fn arbitrary_short_path_base64(content: &[u8]) -> Vec<u8> {
    let encoded = base64_bytes(content);
    assert!(
        encoded.contains(&b'/'),
        "fixture needs a native Base64 slash"
    );
    let widths = [5, 3, 2, 2, 2, 4];
    let mut output = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < encoded.len() {
        let end = (offset + widths[index % widths.len()]).min(encoded.len());
        if !output.is_empty() {
            output.push(b'/');
        }
        output.extend_from_slice(&encoded[offset..end]);
        offset = end;
        index += 1;
    }
    output.push(b'\n');
    output
}

fn ordered_multifield_base64(content: &[u8]) -> Vec<u8> {
    let mut padded = content.to_vec();
    padded.resize(content.len().next_multiple_of(12), 0);
    if padded.len().div_ceil(12) % 2 != 0 {
        padded.resize(padded.len() + 12, 0);
    }
    padded
        .chunks(12)
        .collect::<Vec<_>>()
        .chunks(2)
        .enumerate()
        .map(|(index, pair)| {
            let left = base64_bytes(pair[0]);
            let right = pair
                .get(1)
                .map_or_else(Vec::new, |chunk| base64_bytes(chunk));
            format!(
                "left-{index:03}:{};right-{index:03}:{}",
                String::from_utf8_lossy(&left),
                String::from_utf8_lossy(&right)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn over_limit_structured_base64(content: &[u8]) -> Vec<u8> {
    content
        .chunks(12)
        .map(|chunk| {
            let mut fields = vec!["QUFBQUFB".to_string(); 65];
            fields[32] = String::from_utf8(base64_bytes(chunk)).unwrap();
            fields.join(":")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn ordered_over_limit_structured_base64(content: &[u8]) -> Vec<u8> {
    let mut padded = vec![b'X'; 32 * 1024];
    padded.extend_from_slice(content);
    base64_bytes(&padded)
        .chunks(8)
        .map(|chunk| String::from_utf8_lossy(chunk))
        .collect::<Vec<_>>()
        .join(":")
        .into_bytes()
}

fn variable_field_count_base64(content: &[u8]) -> Vec<u8> {
    base64_bytes(content)
        .chunks(32)
        .enumerate()
        .map(|(index, chunk)| {
            let labels = if index % 2 == 0 {
                "HarmlessLabelA"
            } else {
                "HarmlessLabelA HarmlessLabelB"
            };
            format!("{labels} {}", String::from_utf8_lossy(chunk))
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn base64_wrapped_bytes(content: &[u8]) -> Vec<u8> {
    openssl_base64_bytes(content, false)
}

fn base64_wrapped_at(content: &[u8], width: usize) -> Vec<u8> {
    let encoded = base64_bytes(content);
    encoded
        .chunks(width)
        .flat_map(|chunk| chunk.iter().copied().chain(std::iter::once(b'\n')))
        .collect()
}

fn openssl_base64_bytes(content: &[u8], single_line: bool) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .arg("base64")
        .args(single_line.then_some("-A"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start OpenSSL Base64 encoder");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(content)
        .expect("write Base64 input");
    let output = child.wait_with_output().expect("finish Base64 encoding");
    assert!(output.status.success());
    output.stdout
}

fn zstd_bytes(content: &[u8]) -> Vec<u8> {
    let mut child = Command::new("zstd")
        .args(["-q", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start zstd");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(content)
        .expect("write zstd input");
    let output = child.wait_with_output().expect("finish zstd");
    assert!(output.status.success());
    output.stdout
}

fn zstd_skippable_frame(content: &[u8]) -> Vec<u8> {
    let mut frame = b"\x50\x2a\x4d\x18".to_vec();
    frame.extend(u32::try_from(content.len()).unwrap().to_le_bytes());
    frame.extend(content);
    frame
}

fn zstd_block_bomb() -> Vec<u8> {
    let mut frame = b"\x28\xb5\x2f\xfd\x20\x00".to_vec();
    frame.extend([0, 0, 0].repeat(65_537));
    frame.extend([1, 0, 0]);
    frame
}

fn zstd_many_empty_blocks(blocks: usize) -> Vec<u8> {
    assert!(blocks > 0);
    let mut frame = b"\x28\xb5\x2f\xfd\x20\x00".to_vec();
    frame.extend([0, 0, 0].repeat(blocks - 1));
    frame.extend([1, 0, 0]);
    frame
}

fn bzip2_bytes(content: &[u8]) -> Vec<u8> {
    let mut child = Command::new("bzip2")
        .arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start bzip2");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(content)
        .expect("write bzip2 input");
    let output = child.wait_with_output().expect("finish bzip2");
    assert!(output.status.success());
    output.stdout
}

fn write_tool(path: &Path, content: &str) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create fake tool");
    file.write_all(content.as_bytes()).expect("write fake tool");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("make tool executable");
}

fn sha(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

fn sha_file(path: &Path) -> String {
    sha(&fs::read(path).expect("read file for hash"))
}
