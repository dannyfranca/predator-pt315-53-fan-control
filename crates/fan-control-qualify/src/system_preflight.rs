use std::{
    ffi::CString,
    fs,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};

use fan_control_core::{
    PlatformError, PlatformErrorKind, PreflightArtifact, PreflightEnvironment,
    ProtectedFileRequirement, path_has_extended_acl, validate_root_owned_protected_file,
};
use serde_json::Value;

use crate::system_timestamp;

const DAEMON_PATH: &str = "/usr/bin/pt31553-fand";
const STOCK_KERNEL_IMAGE: &str = "/vmlinuz-linux-cachyos";
const STOCK_INITRAMFS: &str = "/initramfs-linux-cachyos.img";
const STOCK_LTS_KERNEL_IMAGE: &str = "/vmlinuz-linux-cachyos-lts";
const STOCK_LTS_INITRAMFS: [&str; 2] = ["/intel-ucode.img", "/initramfs-linux-cachyos-lts.img"];
const QUALIFICATION_WORKLOAD_ROOT: &str = "/usr/lib/pt31553-fan-control/workloads/";

/// One root-collected readiness snapshot consumed by the read-only preflight core.
///
/// Candidate trust is admitted before construction. Host state that requires root access is
/// collected here, while sensor reads remain isolated in the UID-65534 harness.
pub(crate) struct SystemPreflightEnvironment {
    recovery_ready: Result<bool, String>,
    stock_boot_fallback_ready: Result<bool, String>,
    qualification_workload_absent: Result<bool, String>,
}

impl SystemPreflightEnvironment {
    pub(crate) fn for_verified_candidate(stock_entry: &str, stock_lts_entry: &str) -> Self {
        Self {
            recovery_ready: inspect_recovery_readiness(),
            stock_boot_fallback_ready: inspect_stock_boot_fallback(stock_entry, stock_lts_entry),
            qualification_workload_absent: inspect_qualification_workload_absence(),
        }
    }
}

pub(crate) fn validate_stock_entry_ids(
    stock_entry: &str,
    stock_lts_entry: &str,
) -> Result<(), String> {
    if !safe_entry_id(stock_entry) || !safe_entry_id(stock_lts_entry) {
        return Err("stock boot entry IDs must be nonempty, bounded, slash-free text".into());
    }
    if stock_entry == stock_lts_entry {
        return Err("stock and stock-LTS boot entry IDs must differ".into());
    }
    Ok(())
}

impl PreflightEnvironment for SystemPreflightEnvironment {
    fn timestamp_now(&mut self) -> fan_control_core::EvidenceTimestamp {
        system_timestamp()
    }

    fn signing_trust_is_ready(&mut self) -> Result<bool, PlatformError> {
        // Construction is downstream of discover_system_candidate, which verifies the signed
        // package set, running image/modules, Secure Boot, and exact live candidate identity.
        Ok(true)
    }

    fn recovery_is_ready(&mut self) -> Result<bool, PlatformError> {
        readiness_result(&self.recovery_ready)
    }

    fn stock_boot_fallback_is_ready(&mut self) -> Result<bool, PlatformError> {
        readiness_result(&self.stock_boot_fallback_ready)
    }

    fn qualification_workload_is_absent(&mut self) -> Result<bool, PlatformError> {
        readiness_result(&self.qualification_workload_absent)
    }

    fn artifact_is_ready(&mut self, artifact: PreflightArtifact) -> Result<bool, PlatformError> {
        let path = Path::new(artifact.path());
        match artifact {
            PreflightArtifact::QualificationTool
            | PreflightArtifact::RestorationTool
            | PreflightArtifact::Daemon => {
                validate_root_owned_protected_file(path, ProtectedFileRequirement::Executable)
            }
            PreflightArtifact::DaemonServiceUnit | PreflightArtifact::SleepGuardServiceUnit => {
                validate_root_owned_protected_file(path, ProtectedFileRequirement::Regular)
            }
            PreflightArtifact::Journald => validate_root_owned_socket(path),
        }
        .map(|()| true)
        .or_else(|error| match error.kind() {
            PlatformErrorKind::Unavailable | PlatformErrorKind::PermissionDenied => Ok(false),
            _ => Err(error),
        })
    }

    fn available_bytes(&mut self, path: &Path) -> Result<u64, PlatformError> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            PlatformError::new(
                PlatformErrorKind::Unavailable,
                "disk path contains a NUL byte",
            )
        })?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `path` is NUL-terminated and `stats` points to writable storage.
        if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("statvfs failed: {}", std::io::Error::last_os_error()),
            ));
        }
        // SAFETY: successful statvfs initialized the structure.
        let stats = unsafe { stats.assume_init() };
        Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
    }
}

fn readiness_result(result: &Result<bool, String>) -> Result<bool, PlatformError> {
    result
        .as_ref()
        .copied()
        .map_err(|error| PlatformError::new(PlatformErrorKind::Unavailable, error.clone()))
}

fn inspect_recovery_readiness() -> Result<bool, String> {
    for unit in ["pt31553-fand.service", "pt31553-fan-sleep-guard.service"] {
        if command_text("/usr/bin/systemctl", &["is-enabled", unit])?.trim() != "disabled"
            || command_text("/usr/bin/systemctl", &["is-active", unit])?.trim() != "inactive"
            || command_text(
                "/usr/bin/systemctl",
                &[
                    "show",
                    unit,
                    "--property=ActiveEnterTimestampMonotonic",
                    "--value",
                ],
            )?
            .trim()
                != "0"
            || command_text(
                "/usr/bin/systemctl",
                &[
                    "show",
                    unit,
                    "--property=InactiveEnterTimestampMonotonic",
                    "--value",
                ],
            )?
            .trim()
                != "0"
        {
            return Ok(false);
        }
    }
    let journal = command_output(
        "/usr/bin/journalctl",
        &[
            "-b",
            "--no-pager",
            "-o",
            "cat",
            "_EXE=/usr/bin/pt31553-fand",
        ],
    )?;
    if !journal.status.success() || !journal.stdout.is_empty() || daemon_process_present()? {
        return Ok(false);
    }
    Ok(true)
}

fn inspect_stock_boot_fallback(stock_entry: &str, stock_lts_entry: &str) -> Result<bool, String> {
    if validate_stock_entry_ids(stock_entry, stock_lts_entry).is_err() {
        return Ok(false);
    }
    let output = command_output("/usr/bin/bootctl", &["list", "--json=short"])?;
    if !output.status.success() {
        return Err(format!("bootctl list failed with {}", output.status));
    }
    let entries: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("bootctl returned invalid JSON: {error}"))?;
    validate_stock_boot_entries(
        &entries,
        stock_entry,
        stock_lts_entry,
        protected_nonempty_file,
    )
}

fn validate_stock_boot_entries(
    entries: &Value,
    stock_entry: &str,
    stock_lts_entry: &str,
    file_ready: impl Fn(&Path) -> bool,
) -> Result<bool, String> {
    let entries = entries
        .as_array()
        .ok_or_else(|| "bootctl JSON is not an array".to_owned())?;
    let matching = |id: &str| {
        entries
            .iter()
            .filter(|entry| entry.get("id").and_then(Value::as_str) == Some(id))
            .collect::<Vec<_>>()
    };
    let stock = matching(stock_entry);
    let lts = matching(stock_lts_entry);
    if stock.len() != 1 || lts.len() != 1 {
        return Ok(false);
    }
    let defaults = entries
        .iter()
        .filter(|entry| entry.get("isDefault").and_then(Value::as_bool) == Some(true))
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if defaults.len() != 1 || ![stock_entry, stock_lts_entry].contains(&defaults[0]) {
        return Ok(false);
    }
    Ok(validate_boot_entry(
        stock[0],
        stock_entry,
        &[STOCK_KERNEL_IMAGE],
        &[STOCK_INITRAMFS],
        false,
        &file_ready,
    ) && validate_boot_entry(
        lts[0],
        stock_lts_entry,
        &[STOCK_LTS_KERNEL_IMAGE],
        &STOCK_LTS_INITRAMFS,
        true,
        &file_ready,
    ))
}

fn validate_boot_entry(
    entry: &Value,
    id: &str,
    expected_linux: &[&str],
    required_initrd: &[&str],
    exact_initrd: bool,
    file_ready: &impl Fn(&Path) -> bool,
) -> bool {
    let Some(linux) = boot_paths(entry.get("linux")) else {
        return false;
    };
    let Some(initrd) = boot_paths(entry.get("initrd")) else {
        return false;
    };
    if entry.get("type").and_then(Value::as_str) != Some("type1")
        || !matches!(
            entry.get("source").and_then(Value::as_str),
            Some("esp" | "xbootldr")
        )
        || linux != expected_linux
        || (exact_initrd && initrd != required_initrd)
        || required_initrd
            .iter()
            .any(|required| !initrd.contains(required))
    {
        return false;
    }
    let Some(root) = entry.get("root").and_then(Value::as_str).map(Path::new) else {
        return false;
    };
    let Some(config) = entry.get("path").and_then(Value::as_str).map(Path::new) else {
        return false;
    };
    if !root.is_absolute()
        || config != root.join("loader").join("entries").join(id)
        || !file_ready(config)
    {
        return false;
    }
    linux
        .iter()
        .chain(initrd.iter())
        .all(|path| boot_host_path(root, path).is_some_and(|path| file_ready(&path)))
}

fn boot_paths(value: Option<&Value>) -> Option<Vec<&str>> {
    match value? {
        Value::String(path) => Some(vec![path]),
        Value::Array(paths) => paths.iter().map(Value::as_str).collect(),
        _ => None,
    }
}

fn boot_host_path(root: &Path, boot_path: &str) -> Option<PathBuf> {
    let path = Path::new(boot_path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }
    Some(root.join(path.strip_prefix("/").ok()?))
}

fn protected_nonempty_file(path: &Path) -> bool {
    let Ok(leaf) = fs::symlink_metadata(path) else {
        return false;
    };
    if !leaf.is_file()
        || leaf.file_type().is_symlink()
        || leaf.uid() != 0
        || leaf.len() == 0
        || leaf.permissions().mode() & 0o022 != 0
    {
        return false;
    }
    path.parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .all(|ancestor| {
            fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == 0
                    && metadata.permissions().mode() & 0o022 == 0
            })
        })
}

fn safe_entry_id(id: &str) -> bool {
    let mut components = Path::new(id).components();
    !id.is_empty()
        && id.len() <= 255
        && !id.bytes().any(|byte| byte.is_ascii_control())
        && matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
}

fn inspect_qualification_workload_absence() -> Result<bool, String> {
    for entry in fs::read_dir("/proc").map_err(|error| format!("cannot inspect /proc: {error}"))? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot enumerate /proc: {error}")),
        };
        if !entry.file_name().as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let command = match fs::read(entry.path().join("cmdline")) {
            Ok(command) => command,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => return Err(format!("cannot inspect process command line: {error}")),
        };
        if command
            .split(|byte| *byte == 0)
            .any(|argument| argument.starts_with(QUALIFICATION_WORKLOAD_ROOT.as_bytes()))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn daemon_process_present() -> Result<bool, String> {
    for entry in fs::read_dir("/proc").map_err(|error| format!("cannot inspect /proc: {error}"))? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot enumerate /proc: {error}")),
        };
        if !entry.file_name().as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        match fs::read(entry.path().join("comm")) {
            Ok(name) if name.strip_suffix(b"\n") == Some(b"pt31553-fand") => return Ok(true),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => return Err(format!("cannot inspect process name: {error}")),
        }
        match fs::read_link(entry.path().join("exe")) {
            Ok(path) if path == Path::new(DAEMON_PATH) => return Ok(true),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => return Err(format!("cannot inspect process executable: {error}")),
        }
    }
    Ok(false)
}

fn command_text(program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = command_output(program, arguments)?;
    String::from_utf8(output.stdout)
        .map_err(|error| format!("{program} returned non-UTF-8 output: {error}"))
}

fn command_output(program: &str, arguments: &[&str]) -> Result<Output, String> {
    Command::new(program)
        .args(arguments)
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| format!("cannot execute {program}: {error}"))
}

fn validate_root_owned_socket(path: &Path) -> Result<(), PlatformError> {
    validate_owned_socket(path, 0)
}

pub(crate) fn validate_owned_socket(path: &Path, required_owner: u32) -> Result<(), PlatformError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|error| platform_io_error(&current, error))?;
        let has_extended_acl =
            path_has_extended_acl(&current).map_err(|error| platform_io_error(&current, error))?;
        let leaf = current == path;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != required_owner)
            || (!leaf && metadata.permissions().mode() & 0o022 != 0)
            || has_extended_acl
        {
            return Err(PlatformError::new(
                PlatformErrorKind::PermissionDenied,
                format!("unprotected artifact path: {}", current.display()),
            ));
        }
        if leaf && !metadata.file_type().is_socket() {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("artifact is not a socket: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn platform_io_error(path: &Path, error: std::io::Error) -> PlatformError {
    let kind = match error.kind() {
        std::io::ErrorKind::NotFound => PlatformErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => PlatformErrorKind::PermissionDenied,
        _ => PlatformErrorKind::Unavailable,
    };
    PlatformError::new(kind, format!("cannot inspect {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Value {
        serde_json::json!([
            {
                "id": "stock.conf",
                "type": "type1",
                "source": "esp",
                "root": "/boot",
                "path": "/boot/loader/entries/stock.conf",
                "linux": "/vmlinuz-linux-cachyos",
                "initrd": ["/intel-ucode.img", "/initramfs-linux-cachyos.img"],
                "isDefault": true
            },
            {
                "id": "stock-lts.conf",
                "type": "type1",
                "source": "xbootldr",
                "root": "/boot",
                "path": "/boot/loader/entries/stock-lts.conf",
                "linux": ["/vmlinuz-linux-cachyos-lts"],
                "initrd": ["/intel-ucode.img", "/initramfs-linux-cachyos-lts.img"]
            }
        ])
    }

    #[test]
    fn exact_stock_entries_and_stock_default_are_accepted() {
        assert!(
            validate_stock_boot_entries(&entries(), "stock.conf", "stock-lts.conf", |_| true)
                .unwrap()
        );
    }

    #[test]
    fn boot_fallback_rejects_substitution_duplicates_and_candidate_default() {
        let mut substituted = entries();
        substituted[0]["linux"] = "/vmlinuz-other".into();
        assert!(
            !validate_stock_boot_entries(&substituted, "stock.conf", "stock-lts.conf", |_| true)
                .unwrap()
        );

        let mut duplicate = entries();
        let repeated = duplicate[0].clone();
        duplicate.as_array_mut().unwrap().push(repeated);
        assert!(
            !validate_stock_boot_entries(&duplicate, "stock.conf", "stock-lts.conf", |_| true)
                .unwrap()
        );

        let mut candidate_default = entries();
        candidate_default[0]["isDefault"] = false.into();
        candidate_default
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": "candidate.conf",
                "isDefault": true
            }));
        assert!(
            !validate_stock_boot_entries(
                &candidate_default,
                "stock.conf",
                "stock-lts.conf",
                |_| true
            )
            .unwrap()
        );
    }

    #[test]
    fn boot_entry_ids_and_paths_are_constrained() {
        assert!(safe_entry_id("linux-cachyos.conf"));
        assert!(!safe_entry_id("../linux.conf"));
        assert!(!safe_entry_id("bad/id"));
        assert!(!safe_entry_id("."));
        assert!(!safe_entry_id(".."));
        assert!(boot_host_path(Path::new("/boot"), "/vmlinuz").is_some());
        assert!(boot_host_path(Path::new("/boot"), "/../etc/shadow").is_none());
        assert!(boot_host_path(Path::new("/boot"), "relative").is_none());
    }
}
