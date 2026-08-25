use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use crate::{FileAccess, FilePermissions, PlatformError};

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
    enable: PathBuf,
    tachometer: PathBuf,
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
    root: PathBuf,
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
    files: &mut dyn FileAccess,
    hwmon_root: &Path,
) -> Result<AcerHwmonDevice, AcerHwmonDiscoveryError> {
    let mut matches = find_acer_devices(files, hwmon_root)?;

    let root = match matches.len() {
        0 => return Err(AcerHwmonDiscoveryError::NoDevice),
        1 => matches.pop().expect("one matched device"),
        count => return Err(AcerHwmonDiscoveryError::AmbiguousDevices { count }),
    };

    validate_exact_two_fan_abi(files, &root)?;

    let final_matches = find_acer_devices(files, hwmon_root)?;
    match final_matches.as_slice() {
        [final_root] if final_root == &root => {}
        [] => return Err(AcerHwmonDiscoveryError::NoDevice),
        [_] => return Err(invalid_abi(&root, "Acer hwmon identity changed")),
        matches => {
            return Err(AcerHwmonDiscoveryError::AmbiguousDevices {
                count: matches.len(),
            });
        }
    }

    validate_exact_two_fan_abi(files, &root)?;

    Ok(AcerHwmonDevice {
        cpu: endpoints(&root, 1),
        gpu: endpoints(&root, 2),
        root,
    })
}

fn find_acer_devices(
    files: &mut dyn FileAccess,
    hwmon_root: &Path,
) -> Result<Vec<PathBuf>, AcerHwmonDiscoveryError> {
    let mut matches = Vec::new();
    for candidate in files.list(hwmon_root)? {
        validate_hwmon_entry(hwmon_root, &candidate)?;

        let name_path = candidate.join("name");
        let name = files.read(&name_path)?;
        if name == ACER_HWMON_NAME_PAYLOAD {
            require_permissions(files, &name_path, FilePermissions::READ_ONLY)?;
            matches.push(candidate);
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
    files: &mut dyn FileAccess,
    root: &Path,
) -> Result<(), AcerHwmonDiscoveryError> {
    let entries = files.list(root)?;
    validate_entry_names(root, &entries)?;

    for channel in 1..=2 {
        require_endpoint_permissions(files, root, channel)?;
    }

    let name_path = root.join("name");
    if files.read(&name_path)? != ACER_HWMON_NAME_PAYLOAD {
        return Err(invalid_abi(root, "Acer identity changed during discovery"));
    }
    require_permissions(files, &name_path, FilePermissions::READ_ONLY)?;
    for channel in 1..=2 {
        require_endpoint_permissions(files, root, channel)?;
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
    files: &mut dyn FileAccess,
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
        enable: root.join(format!("pwm{channel}_enable")),
        tachometer: root.join(format!("fan{channel}_input")),
    }
}

fn require_permissions(
    files: &mut dyn FileAccess,
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
