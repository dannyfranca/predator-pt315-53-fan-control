use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    BoundedIdentityBoundFileAccess, FileIdentity, FilePermissions, IdentityBoundReadAccess,
    PlatformError,
};

const ACER_HWMON_NAME_PAYLOAD: &str = "acer\n";
const EXPECTED_ENDPOINTS: [&str; 6] = [
    "pwm1",
    "pwm1_enable",
    "fan1_input",
    "pwm2",
    "pwm2_enable",
    "fan2_input",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanEndpoints {
    pwm: PathBuf,
    pwm_identity: Option<FileIdentity>,
    enable: PathBuf,
    enable_identity: Option<FileIdentity>,
    tachometer: PathBuf,
    tachometer_identity: Option<FileIdentity>,
}

impl FanEndpoints {
    pub fn pwm(&self) -> &Path {
        &self.pwm
    }

    pub fn enable(&self) -> &Path {
        &self.enable
    }

    pub fn tachometer(&self) -> &Path {
        &self.tachometer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcerHwmonDevice {
    hwmon_root: PathBuf,
    root: PathBuf,
    backing_identity: FileIdentity,
    cpu: FanEndpoints,
    gpu: FanEndpoints,
}

impl AcerHwmonDevice {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn cpu(&self) -> &FanEndpoints {
        &self.cpu
    }

    pub const fn gpu(&self) -> &FanEndpoints {
        &self.gpu
    }

    pub(crate) fn endpoint_identity(&self, path: &Path) -> Option<FileIdentity> {
        for endpoints in [&self.cpu, &self.gpu] {
            for (candidate, identity) in [
                (&endpoints.pwm, endpoints.pwm_identity),
                (&endpoints.enable, endpoints.enable_identity),
                (&endpoints.tachometer, endpoints.tachometer_identity),
            ] {
                if candidate == path {
                    return identity;
                }
            }
        }
        None
    }

    pub(crate) fn endpoint_bindings(&self) -> [(&Path, FileIdentity); 6] {
        [
            (
                &self.cpu.pwm,
                self.cpu.pwm_identity.expect("bound endpoint"),
            ),
            (
                &self.cpu.enable,
                self.cpu.enable_identity.expect("bound endpoint"),
            ),
            (
                &self.cpu.tachometer,
                self.cpu.tachometer_identity.expect("bound endpoint"),
            ),
            (
                &self.gpu.pwm,
                self.gpu.pwm_identity.expect("bound endpoint"),
            ),
            (
                &self.gpu.enable,
                self.gpu.enable_identity.expect("bound endpoint"),
            ),
            (
                &self.gpu.tachometer,
                self.gpu.tachometer_identity.expect("bound endpoint"),
            ),
        ]
    }

    pub(crate) fn abi_is_current_before(
        &self,
        files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
        deadline: Duration,
    ) -> Result<bool, AcerHwmonDiscoveryError> {
        let mut matches = find_acer_devices_before(files, &self.hwmon_root, deadline)?;
        let (root, backing_identity) = match matches.len() {
            0 => return Err(AcerHwmonDiscoveryError::NoDevice),
            1 => matches.pop().expect("one matched device"),
            count => return Err(AcerHwmonDiscoveryError::AmbiguousDevices { count }),
        };
        if root != self.root || backing_identity != self.backing_identity {
            return Ok(false);
        }
        validate_exact_two_fan_abi_before(files, self, deadline)?;
        for endpoints in [&self.cpu, &self.gpu] {
            for (path, expected) in [
                (&endpoints.pwm, endpoints.pwm_identity),
                (&endpoints.enable, endpoints.enable_identity),
                (&endpoints.tachometer, endpoints.tachometer_identity),
            ] {
                if files.identity_before(path, deadline)? != expected.expect("bound endpoint") {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub(crate) const fn backing_identity(&self) -> FileIdentity {
        self.backing_identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcerHwmonDiscoveryError {
    Platform(PlatformError),
    NoDevice,
    AmbiguousDevices {
        count: usize,
    },
    InvalidAbi {
        path: PathBuf,
        reason: String,
    },
    InvalidPermissions {
        path: PathBuf,
        expected: FilePermissions,
        actual: FilePermissions,
    },
}

impl fmt::Display for AcerHwmonDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(formatter, "hwmon discovery failed: {error}"),
            Self::NoDevice => formatter.write_str("no Acer hwmon device found"),
            Self::AmbiguousDevices { count } => {
                write!(formatter, "found {count} Acer hwmon devices")
            }
            Self::InvalidAbi { path, reason } => {
                write!(
                    formatter,
                    "invalid Acer hwmon ABI at {}: {reason}",
                    path.display()
                )
            }
            Self::InvalidPermissions {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "invalid permissions for {}: expected {expected:?}, got {actual:?}",
                path.display()
            ),
        }
    }
}

impl Error for AcerHwmonDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PlatformError> for AcerHwmonDiscoveryError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

pub fn discover_acer_hwmon(
    files: &mut dyn IdentityBoundReadAccess,
    hwmon_root: &Path,
) -> Result<AcerHwmonDevice, AcerHwmonDiscoveryError> {
    let mut matches = find_acer_devices(files, hwmon_root)?;

    let (root, backing_identity) = match matches.len() {
        0 => return Err(AcerHwmonDiscoveryError::NoDevice),
        1 => matches.pop().expect("one matched device"),
        count => return Err(AcerHwmonDiscoveryError::AmbiguousDevices { count }),
    };

    validate_exact_two_fan_abi(files, &root, backing_identity)?;

    let final_matches = find_acer_devices(files, hwmon_root)?;
    match final_matches.as_slice() {
        [(final_root, final_identity)]
            if final_root == &root && *final_identity == backing_identity => {}
        [] => return Err(AcerHwmonDiscoveryError::NoDevice),
        [_] => return Err(invalid_abi(&root, "Acer hwmon identity changed")),
        matches => {
            return Err(AcerHwmonDiscoveryError::AmbiguousDevices {
                count: matches.len(),
            });
        }
    }

    validate_exact_two_fan_abi(files, &root, backing_identity)?;

    let cpu = bind_endpoints(files, &root, 1)?;
    let gpu = bind_endpoints(files, &root, 2)?;
    if cpu != bind_endpoints(files, &root, 1)? || gpu != bind_endpoints(files, &root, 2)? {
        return Err(invalid_abi(
            &root,
            "endpoint identity changed during discovery",
        ));
    }

    Ok(AcerHwmonDevice {
        hwmon_root: hwmon_root.to_path_buf(),
        cpu,
        gpu,
        root,
        backing_identity,
    })
}

fn find_acer_devices(
    files: &mut dyn IdentityBoundReadAccess,
    hwmon_root: &Path,
) -> Result<Vec<(PathBuf, FileIdentity)>, AcerHwmonDiscoveryError> {
    let mut matches = Vec::new();
    for candidate in files.list(hwmon_root)? {
        validate_hwmon_entry(hwmon_root, &candidate)?;

        let identity = files.identity(&candidate)?;
        let name_path = candidate.join("name");
        let name = files.read_bound(&candidate, identity, "name")?;
        if name == ACER_HWMON_NAME_PAYLOAD {
            require_permissions(files, &name_path, FilePermissions::READ_ONLY)?;
            matches.push((candidate, identity));
        }
    }
    Ok(matches)
}

fn find_acer_devices_before(
    files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    hwmon_root: &Path,
    deadline: Duration,
) -> Result<Vec<(PathBuf, FileIdentity)>, AcerHwmonDiscoveryError> {
    let mut matches = Vec::new();
    for candidate in files.list_before(hwmon_root, deadline)? {
        validate_hwmon_entry(hwmon_root, &candidate)?;

        let identity = files.identity_before(&candidate, deadline)?;
        let name_path = candidate.join("name");
        let name_identity = files.identity_before(&name_path, deadline)?;
        let name =
            files.read_bound_before(&candidate, identity, "name", name_identity, deadline)?;
        if name == ACER_HWMON_NAME_PAYLOAD {
            matches.push((candidate, identity));
        }
    }
    Ok(matches)
}

fn validate_hwmon_entry(hwmon_root: &Path, path: &Path) -> Result<(), AcerHwmonDiscoveryError> {
    if path.parent() != Some(hwmon_root) {
        return Err(invalid_abi(path, "hwmon candidate is not a direct child"));
    }
    let valid = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("hwmon"))
        .is_some_and(|index| !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()));
    if !valid {
        return Err(invalid_abi(path, "malformed hwmon candidate name"));
    }
    Ok(())
}

fn validate_exact_two_fan_abi(
    files: &mut dyn IdentityBoundReadAccess,
    root: &Path,
    backing_identity: FileIdentity,
) -> Result<(), AcerHwmonDiscoveryError> {
    let entries = files.list_bound(root, backing_identity)?;
    validate_entry_names(root, &entries)?;

    for channel in 1..=2 {
        require_endpoint_permissions(files, root, channel)?;
    }

    let name_path = root.join("name");
    if files.read_bound(root, backing_identity, "name")? != ACER_HWMON_NAME_PAYLOAD {
        return Err(invalid_abi(root, "Acer identity changed during discovery"));
    }
    require_permissions(files, &name_path, FilePermissions::READ_ONLY)?;
    for channel in 1..=2 {
        require_endpoint_permissions(files, root, channel)?;
    }

    Ok(())
}

fn validate_exact_two_fan_abi_before(
    files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    deadline: Duration,
) -> Result<(), AcerHwmonDiscoveryError> {
    let root = device.root();
    let backing_identity = device.backing_identity();
    let entries = files.list_bound_before(root, backing_identity, deadline)?;
    validate_entry_names(root, &entries)?;

    let name_path = root.join("name");
    let name_identity = files.identity_before(&name_path, deadline)?;
    if files.read_bound_before(root, backing_identity, "name", name_identity, deadline)?
        != ACER_HWMON_NAME_PAYLOAD
    {
        return Err(invalid_abi(root, "Acer identity changed after discovery"));
    }
    require_permissions_bound_before(
        files,
        root,
        backing_identity,
        "name",
        name_identity,
        FilePermissions::READ_ONLY,
        deadline,
    )?;
    for (path, identity) in device.endpoint_bindings() {
        let expected = if path == device.cpu().tachometer() || path == device.gpu().tachometer() {
            FilePermissions::READ_ONLY
        } else {
            FilePermissions::READ_WRITE
        };
        require_permissions_bound_before(
            files,
            root,
            backing_identity,
            path.file_name()
                .and_then(|name| name.to_str())
                .expect("discovered endpoint has a UTF-8 child name"),
            identity,
            expected,
            deadline,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn require_permissions_bound_before(
    files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    root: &Path,
    backing_identity: FileIdentity,
    child: &str,
    child_identity: FileIdentity,
    expected: FilePermissions,
    deadline: Duration,
) -> Result<(), AcerHwmonDiscoveryError> {
    let actual =
        files.permissions_bound_before(root, backing_identity, child, child_identity, deadline)?;
    if actual != expected {
        return Err(AcerHwmonDiscoveryError::InvalidPermissions {
            path: root.join(child),
            expected,
            actual,
        });
    }
    Ok(())
}

fn validate_entry_names(root: &Path, entries: &[PathBuf]) -> Result<(), AcerHwmonDiscoveryError> {
    for entry in entries {
        if entry.parent() != Some(root) {
            return Err(invalid_abi(
                root,
                format!("endpoint is not a direct child: {}", entry.display()),
            ));
        }
        let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
            return Err(invalid_abi(root, "non-UTF-8 endpoint name"));
        };
        if (name.starts_with("pwm") || name.starts_with("fan"))
            && !EXPECTED_ENDPOINTS.contains(&name)
        {
            return Err(invalid_abi(root, format!("unexpected endpoint {name}")));
        }
    }

    let name_path = root.join("name");
    if entry_count(entries, &name_path) != 1 {
        return Err(invalid_abi(
            root,
            format!("identity must appear exactly once: {}", name_path.display()),
        ));
    }
    for channel in 1..=2 {
        let endpoints = endpoints(root, channel);
        for path in [&endpoints.pwm, &endpoints.enable, &endpoints.tachometer] {
            if entry_count(entries, path) != 1 {
                return Err(invalid_abi(
                    root,
                    format!("endpoint must appear exactly once: {}", path.display()),
                ));
            }
        }
    }
    Ok(())
}

fn entry_count(entries: &[PathBuf], expected: &Path) -> usize {
    entries
        .iter()
        .filter(|entry| entry.as_path() == expected)
        .count()
}

fn require_endpoint_permissions(
    files: &mut dyn IdentityBoundReadAccess,
    root: &Path,
    channel: usize,
) -> Result<(), AcerHwmonDiscoveryError> {
    let endpoints = endpoints(root, channel);
    for (path, expected) in [
        (&endpoints.pwm, FilePermissions::READ_WRITE),
        (&endpoints.enable, FilePermissions::READ_WRITE),
        (&endpoints.tachometer, FilePermissions::READ_ONLY),
    ] {
        require_permissions(files, path, expected)?;
    }
    Ok(())
}

fn endpoints(root: &Path, channel: usize) -> FanEndpoints {
    FanEndpoints {
        pwm: root.join(format!("pwm{channel}")),
        pwm_identity: None,
        enable: root.join(format!("pwm{channel}_enable")),
        enable_identity: None,
        tachometer: root.join(format!("fan{channel}_input")),
        tachometer_identity: None,
    }
}

fn bind_endpoints(
    files: &mut dyn IdentityBoundReadAccess,
    root: &Path,
    channel: usize,
) -> Result<FanEndpoints, AcerHwmonDiscoveryError> {
    let mut endpoints = endpoints(root, channel);
    endpoints.pwm_identity = Some(files.identity(&endpoints.pwm)?);
    endpoints.enable_identity = Some(files.identity(&endpoints.enable)?);
    endpoints.tachometer_identity = Some(files.identity(&endpoints.tachometer)?);
    Ok(endpoints)
}

fn require_permissions(
    files: &mut dyn IdentityBoundReadAccess,
    path: &Path,
    expected: FilePermissions,
) -> Result<(), AcerHwmonDiscoveryError> {
    let actual = files.permissions(path)?;
    if actual != expected {
        return Err(AcerHwmonDiscoveryError::InvalidPermissions {
            path: path.to_path_buf(),
            expected,
            actual,
        });
    }
    Ok(())
}

fn invalid_abi(path: &Path, reason: impl Into<String>) -> AcerHwmonDiscoveryError {
    AcerHwmonDiscoveryError::InvalidAbi {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}
