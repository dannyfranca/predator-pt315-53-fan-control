use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

pub const DEFAULT_SOCKET_PATH: &str = "/run/pt31553-fan-control/observer.sock";
pub const PRESENCE_WINDOW_MILLIS: u64 = 2_500;

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
}
