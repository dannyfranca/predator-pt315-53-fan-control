use std::{error::Error, fmt, time::Duration};

use crate::{
    ConfigV1, CurvePoint, CurvePointConfig, DemandCurve, DemandPercent, DownshiftPolicy,
    HysteresisCelsius, TemperatureCelsius,
};

const MIN_TEMPERATURE_CELSIUS: i64 = 0;
const CPU_MAX_TEMPERATURE_CELSIUS: i64 = 90;
const GPU_MAX_TEMPERATURE_CELSIUS: i64 = 82;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Ac,
    Battery,
}

impl Profile {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ac => "ac",
            Self::Battery => "battery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    Cpu,
    Gpu,
}

impl Component {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
        }
    }

    pub const fn curve_name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu_curve",
            Self::Gpu => "gpu_curve",
        }
    }

    const fn maximum_temperature(self) -> i64 {
        match self {
            Self::Cpu => CPU_MAX_TEMPERATURE_CELSIUS,
            Self::Gpu => GPU_MAX_TEMPERATURE_CELSIUS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fan {
    Cpu,
    Gpu,
}

impl Fan {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedConfig {
    schema_version: u32,
    control: ValidatedControlConfig,
    fans: ValidatedFansConfig,
    profiles: ValidatedProfilesConfig,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ValidatedControlConfig {
    hysteresis: HysteresisCelsius,
    downshift_policy: DownshiftPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ValidatedFansConfig {
    cpu: ValidatedFanConfig,
    gpu: ValidatedFanConfig,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ValidatedFanConfig {
    minimum_duty: DemandPercent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedProfilesConfig {
    ac: ValidatedProfileConfig,
    battery: ValidatedProfileConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedProfileConfig {
    cpu_curve: DemandCurve,
    gpu_curve: DemandCurve,
}

impl ValidatedConfig {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn control(&self) -> &ValidatedControlConfig {
        &self.control
    }

    pub const fn fans(&self) -> &ValidatedFansConfig {
        &self.fans
    }

    pub const fn profiles(&self) -> &ValidatedProfilesConfig {
        &self.profiles
    }
}

impl ValidatedControlConfig {
    pub const fn hysteresis(&self) -> HysteresisCelsius {
        self.hysteresis
    }

    pub const fn downshift_policy(&self) -> DownshiftPolicy {
        self.downshift_policy
    }
}

impl ValidatedFansConfig {
    pub const fn cpu(&self) -> ValidatedFanConfig {
        self.cpu
    }

    pub const fn gpu(&self) -> ValidatedFanConfig {
        self.gpu
    }
}

impl ValidatedFanConfig {
    pub const fn minimum_duty(self) -> DemandPercent {
        self.minimum_duty
    }
}

impl ValidatedProfilesConfig {
    pub const fn ac(&self) -> &ValidatedProfileConfig {
        &self.ac
    }

    pub const fn battery(&self) -> &ValidatedProfileConfig {
        &self.battery
    }
}

impl ValidatedProfileConfig {
    pub const fn cpu_curve(&self) -> &DemandCurve {
        &self.cpu_curve
    }

    pub const fn gpu_curve(&self) -> &DemandCurve {
        &self.gpu_curve
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfigValidationError {
    HysteresisOutOfRange {
        value: i64,
    },
    LowerDemandHoldOutOfRange {
        value: i64,
    },
    MaxDownRampOutOfRange {
        value: f64,
    },
    FanMinimumOutOfRange {
        fan: Fan,
        value: i64,
    },
    CurveTooShort {
        profile: Profile,
        component: Component,
        point_count: usize,
    },
    TemperatureOutOfRange {
        profile: Profile,
        component: Component,
        point_index: usize,
        value: i64,
        minimum: i64,
        maximum: i64,
    },
    TemperaturesNotStrictlyIncreasing {
        profile: Profile,
        component: Component,
        point_index: usize,
    },
    DemandOutOfRange {
        profile: Profile,
        component: Component,
        point_index: usize,
        value: i64,
    },
    DemandDecreases {
        profile: Profile,
        component: Component,
        point_index: usize,
    },
    DoesNotReachFullDemand {
        profile: Profile,
        component: Component,
        threshold_celsius: i64,
    },
}

impl fmt::Display for ConfigValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HysteresisOutOfRange { value } => {
                write!(formatter, "hysteresis {value} must be in 3..=10 °C")
            }
            Self::LowerDemandHoldOutOfRange { value } => {
                write!(
                    formatter,
                    "lower-demand hold {value} must be in 10..=300 seconds"
                )
            }
            Self::MaxDownRampOutOfRange { value } => write!(
                formatter,
                "maximum down-ramp rate {value} must be in 0.1..=1.0 percentage-points per second"
            ),
            Self::FanMinimumOutOfRange { fan, value } => write!(
                formatter,
                "{} fan minimum duty {value} must be in 1..=99 percent",
                fan.name()
            ),
            Self::CurveTooShort {
                profile,
                component,
                point_count,
            } => write!(
                formatter,
                "{}.{} curve has {point_count} points; at least two are required",
                profile.name(),
                component.name()
            ),
            Self::TemperatureOutOfRange {
                profile,
                component,
                point_index,
                value,
                minimum,
                maximum,
            } => write!(
                formatter,
                "{}.{} curve point {point_index} temperature {value} must be in {minimum}..={maximum} °C",
                profile.name(),
                component.name()
            ),
            Self::TemperaturesNotStrictlyIncreasing {
                profile,
                component,
                point_index,
            } => write!(
                formatter,
                "{}.{} curve point {point_index} temperature must exceed the previous point",
                profile.name(),
                component.name()
            ),
            Self::DemandOutOfRange {
                profile,
                component,
                point_index,
                value,
            } => write!(
                formatter,
                "{}.{} curve point {point_index} demand {value} must be in 0..=100 percent",
                profile.name(),
                component.name()
            ),
            Self::DemandDecreases {
                profile,
                component,
                point_index,
            } => write!(
                formatter,
                "{}.{} curve point {point_index} demand must not be below the previous point",
                profile.name(),
                component.name()
            ),
            Self::DoesNotReachFullDemand {
                profile,
                component,
                threshold_celsius,
            } => write!(
                formatter,
                "{}.{} curve must reach 100 percent by {threshold_celsius} °C",
                profile.name(),
                component.name()
            ),
        }
    }
}

impl Error for ConfigValidationError {}

pub fn validate_config_v1(config: ConfigV1) -> Result<ValidatedConfig, ConfigValidationError> {
    let hysteresis_value = config.control.hysteresis_celsius;
    if !(3..=10).contains(&hysteresis_value) {
        return Err(ConfigValidationError::HysteresisOutOfRange {
            value: hysteresis_value,
        });
    }

    let hold_seconds = config.control.lower_demand_hold_seconds;
    if !(10..=300).contains(&hold_seconds) {
        return Err(ConfigValidationError::LowerDemandHoldOutOfRange {
            value: hold_seconds,
        });
    }

    let down_rate = config.control.max_down_ramp_percent_per_second.value();
    if !(0.1..=1.0).contains(&down_rate) {
        return Err(ConfigValidationError::MaxDownRampOutOfRange { value: down_rate });
    }

    let cpu_minimum = validate_fan_minimum(Fan::Cpu, config.fans.cpu.minimum_duty_percent)?;
    let gpu_minimum = validate_fan_minimum(Fan::Gpu, config.fans.gpu.minimum_duty_percent)?;

    let ac_cpu = validate_curve(Profile::Ac, Component::Cpu, config.profiles.ac.cpu_curve)?;
    let ac_gpu = validate_curve(Profile::Ac, Component::Gpu, config.profiles.ac.gpu_curve)?;
    let battery_cpu = validate_curve(
        Profile::Battery,
        Component::Cpu,
        config.profiles.battery.cpu_curve,
    )?;
    let battery_gpu = validate_curve(
        Profile::Battery,
        Component::Gpu,
        config.profiles.battery.gpu_curve,
    )?;

    let hysteresis = HysteresisCelsius::try_from(hysteresis_value as f64)
        .expect("range-checked hysteresis is valid");
    let downshift_policy =
        DownshiftPolicy::new(Duration::from_secs(hold_seconds as u64), down_rate)
            .expect("range-checked downshift policy is valid");

    Ok(ValidatedConfig {
        schema_version: config.schema_version,
        control: ValidatedControlConfig {
            hysteresis,
            downshift_policy,
        },
        fans: ValidatedFansConfig {
            cpu: ValidatedFanConfig {
                minimum_duty: cpu_minimum,
            },
            gpu: ValidatedFanConfig {
                minimum_duty: gpu_minimum,
            },
        },
        profiles: ValidatedProfilesConfig {
            ac: ValidatedProfileConfig {
                cpu_curve: ac_cpu,
                gpu_curve: ac_gpu,
            },
            battery: ValidatedProfileConfig {
                cpu_curve: battery_cpu,
                gpu_curve: battery_gpu,
            },
        },
    })
}

fn validate_fan_minimum(fan: Fan, value: i64) -> Result<DemandPercent, ConfigValidationError> {
    if !(1..=99).contains(&value) {
        return Err(ConfigValidationError::FanMinimumOutOfRange { fan, value });
    }

    Ok(DemandPercent::try_from(value as f64).expect("range-checked fan minimum is valid"))
}

fn validate_curve(
    profile: Profile,
    component: Component,
    points: Vec<CurvePointConfig>,
) -> Result<DemandCurve, ConfigValidationError> {
    if points.len() < 2 {
        return Err(ConfigValidationError::CurveTooShort {
            profile,
            component,
            point_count: points.len(),
        });
    }

    let maximum = component.maximum_temperature();
    for (index, point) in points.iter().enumerate() {
        if !(MIN_TEMPERATURE_CELSIUS..=maximum).contains(&point.temperature_c) {
            return Err(ConfigValidationError::TemperatureOutOfRange {
                profile,
                component,
                point_index: index,
                value: point.temperature_c,
                minimum: MIN_TEMPERATURE_CELSIUS,
                maximum,
            });
        }
        if !(0..=100).contains(&point.demand_percent) {
            return Err(ConfigValidationError::DemandOutOfRange {
                profile,
                component,
                point_index: index,
                value: point.demand_percent,
            });
        }
        if let Some(previous) = index.checked_sub(1).map(|previous| points[previous]) {
            if point.temperature_c <= previous.temperature_c {
                return Err(ConfigValidationError::TemperaturesNotStrictlyIncreasing {
                    profile,
                    component,
                    point_index: index,
                });
            }
            if point.demand_percent < previous.demand_percent {
                return Err(ConfigValidationError::DemandDecreases {
                    profile,
                    component,
                    point_index: index,
                });
            }
        }
    }

    if !points
        .iter()
        .any(|point| point.temperature_c <= maximum && point.demand_percent == 100)
    {
        return Err(ConfigValidationError::DoesNotReachFullDemand {
            profile,
            component,
            threshold_celsius: maximum,
        });
    }

    let runtime_points = points
        .into_iter()
        .map(|point| {
            CurvePoint::new(
                TemperatureCelsius::try_from(point.temperature_c as f64)
                    .expect("bounded integer temperature is finite"),
                DemandPercent::try_from(point.demand_percent as f64)
                    .expect("bounded integer demand is valid"),
            )
        })
        .collect();

    Ok(DemandCurve::from_ordered_points(runtime_points)
        .expect("validated curve has ordered points"))
}
