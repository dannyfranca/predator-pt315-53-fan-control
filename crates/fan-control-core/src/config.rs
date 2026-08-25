use std::{error::Error, fmt};

use serde::{Deserialize, Deserializer, de};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigV1 {
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema_version: u32,
    pub control: ControlConfig,
    pub fans: FansConfig,
    pub profiles: ProfilesConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    pub hysteresis_celsius: i64,
    pub lower_demand_hold_seconds: i64,
    pub max_down_ramp_percent_per_second: FiniteF64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FansConfig {
    pub cpu: FanConfig,
    pub gpu: FanConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FanConfig {
    pub minimum_duty_percent: i64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilesConfig {
    pub ac: ProfileConfig,
    pub battery: ProfileConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub cpu_curve: Vec<CurvePointConfig>,
    pub gpu_curve: Vec<CurvePointConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurvePointConfig {
    pub temperature_c: i64,
    pub demand_percent: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FiniteF64(f64);

impl FiniteF64 {
    pub const fn value(self) -> f64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for FiniteF64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FiniteFloatVisitor;

        impl<'de> de::Visitor<'de> for FiniteFloatVisitor {
            type Value = FiniteF64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a finite floating-point number")
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.is_finite() {
                    Ok(FiniteF64(value))
                } else {
                    Err(E::custom("floating-point number must be finite"))
                }
            }
        }

        deserializer.deserialize_any(FiniteFloatVisitor)
    }
}

#[derive(Debug)]
pub struct ConfigParseError(toml::de::Error);

impl fmt::Display for ConfigParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Error for ConfigParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

pub fn parse_config_v1(source: &str) -> Result<ConfigV1, ConfigParseError> {
    toml::from_str(source).map_err(ConfigParseError)
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = i64::deserialize(deserializer)?;
    if version == 1 {
        Ok(1)
    } else {
        Err(de::Error::custom("schema_version must be 1"))
    }
}
