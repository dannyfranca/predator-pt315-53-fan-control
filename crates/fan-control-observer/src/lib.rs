use std::{
    fmt,
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::UnixStream,
        },
    },
    path::Path,
    str::FromStr,
    time::Duration,
};

use serde::{Deserialize, Serialize};

pub const DEFAULT_SOCKET_PATH: &str = "/run/pt31553-fan-control/observer.sock";
pub const PRESENCE_WINDOW_MILLIS: u64 = 2_500;
const MAX_CONFIRMATION_BYTES: u64 = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmbientTemperature(i32);

impl AmbientTemperature {
    pub fn millicelsius(self) -> i32 {
        self.0
    }
}

impl FromStr for AmbientTemperature {
    type Err = AmbientTemperatureError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let (negative, unsigned) = value
            .strip_prefix('-')
            .map_or((false, value), |unsigned| (true, unsigned));
        let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.len() > 3
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(AmbientTemperatureError);
        }
        let whole = whole.parse::<i32>().map_err(|_| AmbientTemperatureError)?;
        let fraction = if fraction.is_empty() {
            0
        } else {
            fraction
                .parse::<i32>()
                .map_err(|_| AmbientTemperatureError)?
                * 10_i32.pow(3 - fraction.len() as u32)
        };
        let magnitude = whole
            .checked_mul(1_000)
            .and_then(|whole| whole.checked_add(fraction))
            .ok_or(AmbientTemperatureError)?;
        let millicelsius = if negative { -magnitude } else { magnitude };
        if !(-40_000..=80_000).contains(&millicelsius) {
            return Err(AmbientTemperatureError);
        }
        Ok(Self(millicelsius))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmbientTemperatureError;

impl fmt::Display for AmbientTemperatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ambient temperature must be -40.000 through 80.000 Celsius")
    }
}

impl std::error::Error for AmbientTemperatureError {}

#[derive(Debug, Default)]
pub struct PresenceTracker {
    last_activity_millis: Option<u64>,
}

impl PresenceTracker {
    pub fn record_activity(&mut self, now_millis: u64) {
        self.last_activity_millis = Some(now_millis);
    }

    pub fn is_present(&self, now_millis: u64) -> bool {
        self.last_activity_millis
            .is_some_and(|last| now_millis >= last && now_millis - last <= PRESENCE_WINDOW_MILLIS)
    }

    pub fn confirmation(
        &self,
        ambient: AmbientTemperature,
        monotonic_millis: u64,
        wall_unix_millis: i64,
    ) -> ObserverConfirmation {
        ObserverConfirmation {
            observer_present: self.is_present(monotonic_millis),
            confirmed: self.is_present(monotonic_millis),
            observed_at: ObserverTimestamp {
                monotonic_millis,
                wall_unix_millis,
            },
            ambient_millicelsius: ambient.millicelsius(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverConfirmation {
    pub observer_present: bool,
    pub confirmed: bool,
    pub observed_at: ObserverTimestamp,
    pub ambient_millicelsius: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverTimestamp {
    pub monotonic_millis: u64,
    pub wall_unix_millis: i64,
}

/// Reads one confirmation only from the protected root observer endpoint.
pub fn query_protected_observer(path: &Path) -> Result<ObserverConfirmation, ObserverClientError> {
    validate_protected_parent(path)?;
    let before = socket_identity(path)?;
    let stream = UnixStream::connect(path).map_err(ObserverClientError::Io)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(ObserverClientError::Io)?;
    require_root_peer(&stream)?;
    if socket_identity(path)? != before {
        return Err(ObserverClientError::Untrusted(
            "observer socket identity changed while connecting",
        ));
    }
    let mut response = Vec::new();
    stream
        .take(MAX_CONFIRMATION_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(ObserverClientError::Io)?;
    if response.is_empty() || response.len() as u64 > MAX_CONFIRMATION_BYTES {
        return Err(ObserverClientError::Untrusted(
            "observer response has an invalid size",
        ));
    }
    serde_json::from_slice(&response).map_err(ObserverClientError::Json)
}

#[derive(Debug)]
pub enum ObserverClientError {
    Io(io::Error),
    Json(serde_json::Error),
    Untrusted(&'static str),
}

impl fmt::Display for ObserverClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "observer I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "observer response is invalid: {error}"),
            Self::Untrusted(reason) => formatter.write_str(reason),
        }
    }
}

impl std::error::Error for ObserverClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Untrusted(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

fn validate_protected_parent(path: &Path) -> Result<(), ObserverClientError> {
    let parent = path.parent().ok_or(ObserverClientError::Untrusted(
        "observer socket has no parent",
    ))?;
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(ObserverClientError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(ObserverClientError::Untrusted(
                "observer socket parent is not protected by root",
            ));
        }
    }
    Ok(())
}

fn socket_identity(path: &Path) -> Result<SocketIdentity, ObserverClientError> {
    let metadata = std::fs::symlink_metadata(path).map_err(ObserverClientError::Io)?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.nlink() != 1 {
        return Err(ObserverClientError::Untrusted(
            "observer endpoint is not a unique root-owned socket",
        ));
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn require_root_peer(stream: &UnixStream) -> Result<(), ObserverClientError> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor is a connected Unix stream and the output buffer/length are valid.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(ObserverClientError::Io(io::Error::last_os_error()));
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(ObserverClientError::Untrusted(
            "observer peer credentials have an invalid size",
        ));
    }
    // SAFETY: successful getsockopt initialized a complete ucred value.
    let credentials = unsafe { credentials.assume_init() };
    if credentials.uid != 0 {
        return Err(ObserverClientError::Untrusted(
            "observer peer is not running as root",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambient_is_parsed_exactly_without_floating_point() {
        assert_eq!("24".parse::<AmbientTemperature>().unwrap().0, 24_000);
        assert_eq!("24.5".parse::<AmbientTemperature>().unwrap().0, 24_500);
        assert_eq!("-0.125".parse::<AmbientTemperature>().unwrap().0, -125);
        assert_eq!("80.000".parse::<AmbientTemperature>().unwrap().0, 80_000);
    }

    #[test]
    fn malformed_or_out_of_range_ambient_is_rejected() {
        for value in ["", ".5", "+24", "24.0001", "81", "-40.001", "nan"] {
            assert!(value.parse::<AmbientTemperature>().is_err(), "{value}");
        }
    }

    #[test]
    fn presence_requires_recent_non_future_activity() {
        let mut tracker = PresenceTracker::default();
        assert!(!tracker.is_present(10_000));
        tracker.record_activity(10_000);
        assert!(tracker.is_present(12_500));
        assert!(!tracker.is_present(12_501));
        assert!(!tracker.is_present(9_999));
    }

    #[test]
    fn confirmation_carries_current_clocks_and_measured_ambient() {
        let mut tracker = PresenceTracker::default();
        tracker.record_activity(100);
        assert_eq!(
            tracker.confirmation("23.75".parse().unwrap(), 101, 1_700_000_000_000),
            ObserverConfirmation {
                observer_present: true,
                confirmed: true,
                observed_at: ObserverTimestamp {
                    monotonic_millis: 101,
                    wall_unix_millis: 1_700_000_000_000,
                },
                ambient_millicelsius: 23_750,
            }
        );
    }

    #[test]
    fn client_rejects_a_socket_below_a_world_writable_parent() {
        let error = validate_protected_parent(Path::new("/tmp/observer.sock")).unwrap_err();
        assert!(matches!(error, ObserverClientError::Untrusted(_)));
    }

    #[test]
    fn client_rejects_a_regular_file_as_the_observer_endpoint() {
        let path = std::env::temp_dir().join(format!(
            "pt31553-observer-regular-file-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"not a socket").unwrap();
        let error = socket_identity(&path).unwrap_err();
        let _ = std::fs::remove_file(path);
        assert!(matches!(error, ObserverClientError::Untrusted(_)));
    }
}
