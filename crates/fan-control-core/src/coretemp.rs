use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use crate::{
    FileIdentity, IdentityBoundFileAccess, PlatformError, PlatformErrorKind, TemperatureCelsius,
};

const CORETEMP_NAME_PAYLOAD: &str = "coretemp\n";
const MIN_DOCUMENTED_TJMAX_MILLICELSIUS: i64 = 70_000;
const MAX_DOCUMENTED_TJMAX_MILLICELSIUS: i64 = 125_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoretempChannel {
    index: String,
    label: String,
    is_package: bool,
}

impl CoretempChannel {
    fn path(&self, root: &Path, suffix: &str) -> PathBuf {
        root.join(format!("temp{}_{suffix}", self.index))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoretempDevice {
    hwmon_root: PathBuf,
    root: PathBuf,
    backing_identity: FileIdentity,
    channels: Vec<CoretempChannel>,
}

impl CoretempDevice {
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Reads one fail-closed CPU sample after revalidating the discovered identity and labels.
    pub fn sample(
        &self,
        files: &mut dyn IdentityBoundFileAccess,
    ) -> Result<TemperatureCelsius, CoretempError> {
        let before = discover_coretemp(files, &self.hwmon_root)?;
        if before != *self {
            return Err(invalid_abi(
                &self.root,
                "coretemp identity or channel labels changed before sampling",
            ));
        }

        let mut hottest = None;
        for channel in &self.channels {
            let value = sample_channel(files, &self.root, self.backing_identity, channel)?;
            hottest = Some(hottest.map_or(value, |current: i64| current.max(value)));
        }

        let after = discover_coretemp(files, &self.hwmon_root)?;
        if after != before {
            return Err(invalid_abi(
                &self.root,
                "coretemp identity or channel labels changed during sampling",
            ));
        }

        let hottest = hottest.expect("discovery requires at least one package channel");
        Ok(TemperatureCelsius::try_from(hottest as f64 / 1_000.0)
            .expect("a bounded integer temperature is finite"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoretempError {
    Platform(PlatformError),
    NoDevice,
    AmbiguousDevices { count: usize },
    MissingPackageChannel,
    InvalidAbi { path: PathBuf, reason: String },
    InvalidSample { path: PathBuf, reason: String },
}

impl fmt::Display for CoretempError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(formatter, "coretemp access failed: {error}"),
            Self::NoDevice => formatter.write_str("no coretemp hwmon device found"),
            Self::AmbiguousDevices { count } => {
                write!(formatter, "found {count} coretemp hwmon devices")
            }
            Self::MissingPackageChannel => {
                formatter.write_str("coretemp has no package temperature channel")
            }
            Self::InvalidAbi { path, reason } => {
                write!(
                    formatter,
                    "invalid coretemp ABI at {}: {reason}",
                    path.display()
                )
            }
            Self::InvalidSample { path, reason } => write!(
                formatter,
                "invalid coretemp sample at {}: {reason}",
                path.display()
            ),
        }
    }
}

impl Error for CoretempError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PlatformError> for CoretempError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

pub fn discover_coretemp(
    files: &mut dyn IdentityBoundFileAccess,
    hwmon_root: &Path,
) -> Result<CoretempDevice, CoretempError> {
    let (root, backing_identity) = unique_coretemp(files, hwmon_root)?;
    let channels = discover_channels(files, &root, backing_identity)?;

    let (final_root, final_identity) = unique_coretemp(files, hwmon_root)?;
    if final_root != root || final_identity != backing_identity {
        return Err(invalid_abi(
            &root,
            "coretemp backing device changed during discovery",
        ));
    }
    let final_channels = discover_channels(files, &root, backing_identity)?;
    if final_channels != channels {
        return Err(invalid_abi(
            &root,
            "coretemp channel labels changed during discovery",
        ));
    }

    Ok(CoretempDevice {
        hwmon_root: hwmon_root.to_path_buf(),
        root,
        backing_identity,
        channels,
    })
}

fn unique_coretemp(
    files: &mut dyn IdentityBoundFileAccess,
    hwmon_root: &Path,
) -> Result<(PathBuf, FileIdentity), CoretempError> {
    let mut matches = Vec::new();
    for candidate in files.list(hwmon_root)? {
        validate_hwmon_entry(hwmon_root, &candidate)?;
        let identity = files.identity(&candidate)?;
        if files.read_bound(&candidate, identity, "name")? == CORETEMP_NAME_PAYLOAD {
            matches.push((candidate, identity));
        }
    }

    match matches.len() {
        0 => Err(CoretempError::NoDevice),
        1 => Ok(matches.pop().expect("one matched device")),
        count => Err(CoretempError::AmbiguousDevices { count }),
    }
}

fn validate_hwmon_entry(hwmon_root: &Path, path: &Path) -> Result<(), CoretempError> {
    if path.parent() != Some(hwmon_root) {
        return Err(invalid_abi(path, "hwmon candidate is not a direct child"));
    }
    let valid = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("hwmon"))
        .is_some_and(valid_positive_decimal_with_zero);
    if !valid {
        return Err(invalid_abi(path, "malformed hwmon candidate name"));
    }
    Ok(())
}

fn discover_channels(
    files: &mut dyn IdentityBoundFileAccess,
    root: &Path,
    backing_identity: FileIdentity,
) -> Result<Vec<CoretempChannel>, CoretempError> {
    let entries = files.list_bound(root, backing_identity)?;
    let mut seen_entries = BTreeSet::new();
    let mut channels = Vec::new();
    let mut labels = BTreeSet::new();

    for entry in entries {
        if entry.parent() != Some(root) {
            return Err(invalid_abi(
                root,
                format!("channel entry is not a direct child: {}", entry.display()),
            ));
        }
        if !seen_entries.insert(entry.clone()) {
            return Err(invalid_abi(
                root,
                format!("duplicate channel entry: {}", entry.display()),
            ));
        }

        let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
            return Err(invalid_abi(root, "non-UTF-8 channel entry"));
        };
        let Some(index) = temperature_label_index(name)? else {
            continue;
        };
        let payload = files.read_bound(root, backing_identity, name)?;
        let Some((label, is_package)) = selected_label(&payload, &entry)? else {
            continue;
        };
        if !labels.insert(label.clone()) {
            return Err(invalid_abi(
                &entry,
                format!("duplicate selected channel label {label}"),
            ));
        }
        channels.push(CoretempChannel {
            index: index.to_owned(),
            label,
            is_package,
        });
    }

    if !channels.iter().any(|channel| channel.is_package) {
        return Err(CoretempError::MissingPackageChannel);
    }
    channels.sort_by(|left, right| left.label.cmp(&right.label));
    Ok(channels)
}

fn temperature_label_index(name: &str) -> Result<Option<&str>, CoretempError> {
    if !name.starts_with("temp") || !name.ends_with("_label") {
        return Ok(None);
    }
    let index = &name[4..name.len() - "_label".len()];
    if !valid_positive_decimal(index) {
        return Err(invalid_abi(
            Path::new(name),
            "malformed temperature label filename",
        ));
    }
    Ok(Some(index))
}

fn selected_label(payload: &str, path: &Path) -> Result<Option<(String, bool)>, CoretempError> {
    let Some(label) = payload.strip_suffix('\n') else {
        return Err(invalid_abi(path, "channel label must end with one newline"));
    };
    if label.contains('\n') {
        return Err(invalid_abi(
            path,
            "channel label contains an embedded newline",
        ));
    }

    for (prefix, is_package) in [("Package id ", true), ("Core ", false)] {
        if let Some(identifier) = label.strip_prefix(prefix) {
            if !valid_positive_decimal_with_zero(identifier) {
                return Err(invalid_abi(path, "malformed package/core channel label"));
            }
            return Ok(Some((label.to_owned(), is_package)));
        }
    }
    Ok(None)
}

fn sample_channel(
    files: &mut dyn IdentityBoundFileAccess,
    root: &Path,
    backing_identity: FileIdentity,
    channel: &CoretempChannel,
) -> Result<i64, CoretempError> {
    reject_asserted_optional_flag(files, root, backing_identity, channel, "fault", "fault")?;
    reject_asserted_optional_flag(
        files,
        root,
        backing_identity,
        channel,
        "crit_alarm",
        "critical alarm",
    )?;

    let input_path = channel.path(root, "input");
    let input = parse_number(
        &files.read_bound(
            root,
            backing_identity,
            &format!("temp{}_input", channel.index),
        )?,
        &input_path,
    )?;
    let crit_path = channel.path(root, "crit");
    let tjmax = parse_number(
        &files.read_bound(
            root,
            backing_identity,
            &format!("temp{}_crit", channel.index),
        )?,
        &crit_path,
    )?;

    if !(MIN_DOCUMENTED_TJMAX_MILLICELSIUS..=MAX_DOCUMENTED_TJMAX_MILLICELSIUS).contains(&tjmax) {
        return Err(invalid_sample(
            &crit_path,
            format!("TjMax {tjmax} mC is outside the documented coretemp range"),
        ));
    }
    if tjmax % 1_000 != 0 {
        return Err(invalid_sample(
            &crit_path,
            format!("TjMax {tjmax} mC does not match coretemp's 1 C resolution"),
        ));
    }
    if !(0..=tjmax).contains(&input) {
        return Err(invalid_sample(
            &input_path,
            format!("temperature {input} mC is outside 0..={tjmax} mC"),
        ));
    }
    if input % 1_000 != 0 {
        return Err(invalid_sample(
            &input_path,
            format!("temperature {input} mC does not match coretemp's 1 C resolution"),
        ));
    }

    reject_asserted_optional_flag(files, root, backing_identity, channel, "fault", "fault")?;
    reject_asserted_optional_flag(
        files,
        root,
        backing_identity,
        channel,
        "crit_alarm",
        "critical alarm",
    )?;
    Ok(input)
}

fn reject_asserted_optional_flag(
    files: &mut dyn IdentityBoundFileAccess,
    root: &Path,
    backing_identity: FileIdentity,
    channel: &CoretempChannel,
    suffix: &str,
    description: &str,
) -> Result<(), CoretempError> {
    let path = channel.path(root, suffix);
    match files.read_bound(
        root,
        backing_identity,
        &format!("temp{}_{suffix}", channel.index),
    ) {
        Ok(payload) if payload == "0\n" => Ok(()),
        Ok(payload) if payload == "1\n" => {
            Err(invalid_sample(&path, format!("{description} is asserted")))
        }
        Ok(_) => Err(invalid_sample(
            &path,
            format!("{description} is not a sysfs boolean"),
        )),
        Err(error) if error.kind() == PlatformErrorKind::NotFound => Ok(()),
        Err(error) => Err(CoretempError::Platform(error)),
    }
}

fn parse_number(payload: &str, path: &Path) -> Result<i64, CoretempError> {
    let Some(number) = payload.strip_suffix('\n') else {
        return Err(invalid_sample(
            path,
            "numeric input must end with one newline",
        ));
    };
    if number.is_empty()
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || number.contains('\n')
    {
        return Err(invalid_sample(path, "numeric input is malformed"));
    }
    number
        .parse()
        .map_err(|_| invalid_sample(path, "numeric input is outside the supported integer range"))
}

fn valid_positive_decimal(index: &str) -> bool {
    index
        .bytes()
        .next()
        .is_some_and(|first| first.is_ascii_digit() && first != b'0')
        && index.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_positive_decimal_with_zero(index: &str) -> bool {
    index == "0" || valid_positive_decimal(index)
}

fn invalid_abi(path: &Path, reason: impl Into<String>) -> CoretempError {
    CoretempError::InvalidAbi {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn invalid_sample(path: &Path, reason: impl Into<String>) -> CoretempError {
    CoretempError::InvalidSample {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}
