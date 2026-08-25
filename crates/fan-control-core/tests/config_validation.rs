use fan_control_core::{
    Component, ConfigValidationError, DemandPercent, Fan, Profile, TemperatureCelsius,
    parse_config_v1, validate_config_v1,
};

const VALID_CONFIG: &str = r#"
schema_version = 1

[control]
hysteresis_celsius = 3
lower_demand_hold_seconds = 10
max_down_ramp_percent_per_second = 1.0

[fans.cpu]
minimum_duty_percent = 30

[fans.gpu]
minimum_duty_percent = 25

[profiles.ac]
cpu_curve = [
  { temperature_c = 0, demand_percent = 30 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 0, demand_percent = 25 },
  { temperature_c = 82, demand_percent = 100 },
]

[profiles.battery]
cpu_curve = [
  { temperature_c = 40, demand_percent = 25 },
  { temperature_c = 85, demand_percent = 90 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 35, demand_percent = 25 },
  { temperature_c = 78, demand_percent = 90 },
  { temperature_c = 82, demand_percent = 100 },
]
"#;

#[test]
fn valid_configuration_becomes_runtime_ready_values() {
    let validated = validate_config_v1(parse_config_v1(VALID_CONFIG).unwrap()).unwrap();

    assert_eq!(validated.schema_version(), 1);
    assert_eq!(validated.control().hysteresis().value(), 3.0);
    assert_eq!(validated.control().downshift_policy().hold().as_secs(), 10);
    assert_eq!(
        validated
            .control()
            .downshift_policy()
            .max_down_rate_percent_per_second(),
        1.0
    );
    assert_eq!(validated.fans().cpu().minimum_duty().value(), 30.0);
    assert_eq!(validated.fans().gpu().minimum_duty().value(), 25.0);
    assert_eq!(
        validated
            .profiles()
            .ac()
            .cpu_curve()
            .evaluate(TemperatureCelsius::try_from(0.0).unwrap()),
        DemandPercent::try_from(30.0).unwrap()
    );
    assert_eq!(
        validated
            .profiles()
            .ac()
            .gpu_curve()
            .evaluate(TemperatureCelsius::try_from(0.0).unwrap()),
        DemandPercent::try_from(25.0).unwrap()
    );
    assert_eq!(
        validated
            .profiles()
            .battery()
            .cpu_curve()
            .evaluate(TemperatureCelsius::try_from(40.0).unwrap()),
        DemandPercent::try_from(25.0).unwrap()
    );
    assert_eq!(
        validated
            .profiles()
            .battery()
            .gpu_curve()
            .evaluate(TemperatureCelsius::try_from(35.0).unwrap()),
        DemandPercent::try_from(25.0).unwrap()
    );
}

#[test]
fn validation_rechecks_the_schema_version_invariant() {
    let mut config = parse_config_v1(VALID_CONFIG).unwrap();
    config.schema_version = 2;

    assert_eq!(
        validate_config_v1(config),
        Err(ConfigValidationError::UnsupportedSchemaVersion { value: 2 })
    );
}

#[test]
fn every_curve_requires_at_least_two_points() {
    for profile in [Profile::Ac, Profile::Battery] {
        for component in [Component::Cpu, Component::Gpu] {
            for replacement in ["[]", "[{ temperature_c = 40, demand_percent = 100 }]"] {
                let document = replace_curve(VALID_CONFIG, profile, component, replacement);
                assert_eq!(
                    validate(&document),
                    Err(ConfigValidationError::CurveTooShort {
                        profile,
                        component,
                        point_count: if replacement == "[]" { 0 } else { 1 },
                    })
                );
            }
        }
    }
}

#[test]
fn curve_temperatures_must_be_in_component_range_and_strictly_increase() {
    let cases = [
        (
            Profile::Ac,
            Component::Cpu,
            "[{ temperature_c = -1, demand_percent = 30 }, { temperature_c = 90, demand_percent = 100 }]",
            ConfigValidationError::TemperatureOutOfRange {
                profile: Profile::Ac,
                component: Component::Cpu,
                point_index: 0,
                value: -1,
                minimum: 0,
                maximum: 90,
            },
        ),
        (
            Profile::Ac,
            Component::Cpu,
            "[{ temperature_c = 0, demand_percent = 30 }, { temperature_c = 91, demand_percent = 100 }]",
            ConfigValidationError::TemperatureOutOfRange {
                profile: Profile::Ac,
                component: Component::Cpu,
                point_index: 1,
                value: 91,
                minimum: 0,
                maximum: 90,
            },
        ),
        (
            Profile::Battery,
            Component::Gpu,
            "[{ temperature_c = -1, demand_percent = 25 }, { temperature_c = 82, demand_percent = 100 }]",
            ConfigValidationError::TemperatureOutOfRange {
                profile: Profile::Battery,
                component: Component::Gpu,
                point_index: 0,
                value: -1,
                minimum: 0,
                maximum: 82,
            },
        ),
        (
            Profile::Battery,
            Component::Gpu,
            "[{ temperature_c = 0, demand_percent = 25 }, { temperature_c = 83, demand_percent = 100 }]",
            ConfigValidationError::TemperatureOutOfRange {
                profile: Profile::Battery,
                component: Component::Gpu,
                point_index: 1,
                value: 83,
                minimum: 0,
                maximum: 82,
            },
        ),
        (
            Profile::Ac,
            Component::Cpu,
            "[{ temperature_c = 40, demand_percent = 30 }, { temperature_c = 40, demand_percent = 100 }]",
            ConfigValidationError::TemperaturesNotStrictlyIncreasing {
                profile: Profile::Ac,
                component: Component::Cpu,
                point_index: 1,
            },
        ),
        (
            Profile::Ac,
            Component::Cpu,
            "[{ temperature_c = 50, demand_percent = 30 }, { temperature_c = 40, demand_percent = 100 }]",
            ConfigValidationError::TemperaturesNotStrictlyIncreasing {
                profile: Profile::Ac,
                component: Component::Cpu,
                point_index: 1,
            },
        ),
    ];

    for (profile, component, curve, expected) in cases {
        assert_eq!(
            validate(&replace_curve(VALID_CONFIG, profile, component, curve)),
            Err(expected)
        );
    }
}

#[test]
fn curve_demand_must_be_bounded_and_nondecreasing() {
    for (value, point_index) in [(-1, 0), (101, 1)] {
        let curve = format!(
            "[{{ temperature_c = 0, demand_percent = {} }}, {{ temperature_c = 90, demand_percent = {} }}]",
            if point_index == 0 { value } else { 30 },
            if point_index == 1 { value } else { 100 },
        );
        let document = replace_curve(VALID_CONFIG, Profile::Ac, Component::Cpu, &curve);
        assert_eq!(
            validate(&document),
            Err(ConfigValidationError::DemandOutOfRange {
                profile: Profile::Ac,
                component: Component::Cpu,
                point_index,
                value,
            })
        );
    }

    let document = replace_curve(
        VALID_CONFIG,
        Profile::Battery,
        Component::Gpu,
        "[{ temperature_c = 0, demand_percent = 80 }, { temperature_c = 82, demand_percent = 70 }]",
    );
    assert_eq!(
        validate(&document),
        Err(ConfigValidationError::DemandDecreases {
            profile: Profile::Battery,
            component: Component::Gpu,
            point_index: 1,
        })
    );

    let plateau = replace_curve(
        VALID_CONFIG,
        Profile::Ac,
        Component::Cpu,
        "[{ temperature_c = 0, demand_percent = 30 }, { temperature_c = 50, demand_percent = 30 }, { temperature_c = 90, demand_percent = 100 }]",
    );
    assert!(validate(&plateau).is_ok());

    let zero_demand = replace_curve(
        VALID_CONFIG,
        Profile::Ac,
        Component::Cpu,
        "[{ temperature_c = 0, demand_percent = 0 }, { temperature_c = 90, demand_percent = 100 }]",
    );
    assert!(validate(&zero_demand).is_ok());
}

#[test]
fn every_curve_must_reach_full_demand_by_its_approved_threshold() {
    for profile in [Profile::Ac, Profile::Battery] {
        for (component, threshold) in [(Component::Cpu, 90), (Component::Gpu, 82)] {
            let curve = format!(
                "[{{ temperature_c = 0, demand_percent = 30 }}, {{ temperature_c = {threshold}, demand_percent = 99 }}]"
            );
            let document = replace_curve(VALID_CONFIG, profile, component, &curve);
            assert_eq!(
                validate(&document),
                Err(ConfigValidationError::DoesNotReachFullDemand {
                    profile,
                    component,
                    threshold_celsius: threshold,
                })
            );
        }
    }

    for (component, early_temperature) in [(Component::Cpu, 80), (Component::Gpu, 70)] {
        let curve = format!(
            "[{{ temperature_c = 0, demand_percent = 30 }}, {{ temperature_c = {early_temperature}, demand_percent = 100 }}]"
        );
        let document = replace_curve(VALID_CONFIG, Profile::Ac, component, &curve);
        assert!(
            validate(&document).is_ok(),
            "rejected {component:?} curve reaching full demand early"
        );
    }
}

#[test]
fn fan_minimum_duty_must_be_an_integer_from_one_through_ninety_nine() {
    for fan in [Fan::Cpu, Fan::Gpu] {
        for value in [0, 1, 99, 100] {
            let valid = (1..=99).contains(&value);
            let document = replace_fan_minimum(VALID_CONFIG, fan, value);
            let result = validate(&document);
            if valid {
                assert!(result.is_ok(), "rejected {fan:?} minimum {value}");
            } else {
                assert_eq!(
                    result,
                    Err(ConfigValidationError::FanMinimumOutOfRange { fan, value })
                );
            }
        }
    }
}

#[test]
fn control_values_enforce_inclusive_approved_ranges() {
    for value in [2, 3, 10, 11] {
        let result = validate(&VALID_CONFIG.replace(
            "hysteresis_celsius = 3",
            &format!("hysteresis_celsius = {value}"),
        ));
        assert_range_result(
            result,
            (3..=10).contains(&value),
            ConfigValidationError::HysteresisOutOfRange { value },
        );
    }

    for value in [9, 10, 300, 301] {
        let result = validate(&VALID_CONFIG.replace(
            "lower_demand_hold_seconds = 10",
            &format!("lower_demand_hold_seconds = {value}"),
        ));
        assert_range_result(
            result,
            (10..=300).contains(&value),
            ConfigValidationError::LowerDemandHoldOutOfRange { value },
        );
    }

    for value in [0.09, 0.1, 1.0, 1.01] {
        let result = validate(&VALID_CONFIG.replace(
            "max_down_ramp_percent_per_second = 1.0",
            &format!("max_down_ramp_percent_per_second = {value:.2}"),
        ));
        assert_range_result(
            result,
            (0.1..=1.0).contains(&value),
            ConfigValidationError::MaxDownRampOutOfRange { value },
        );
    }
}

fn validate(document: &str) -> Result<fan_control_core::ValidatedConfig, ConfigValidationError> {
    validate_config_v1(parse_config_v1(document).unwrap())
}

fn assert_range_result(
    result: Result<fan_control_core::ValidatedConfig, ConfigValidationError>,
    valid: bool,
    expected_error: ConfigValidationError,
) {
    if valid {
        assert!(result.is_ok());
    } else {
        assert_eq!(result, Err(expected_error));
    }
}

fn replace_fan_minimum(document: &str, fan: Fan, value: i64) -> String {
    let current = match fan {
        Fan::Cpu => 30,
        Fan::Gpu => 25,
    };
    let table = format!("[fans.{}]", fan.name());
    document.replacen(
        &format!("{table}\nminimum_duty_percent = {current}"),
        &format!("{table}\nminimum_duty_percent = {value}"),
        1,
    )
}

fn replace_curve(
    document: &str,
    profile: Profile,
    component: Component,
    replacement: &str,
) -> String {
    let mut table = document.parse::<toml::Table>().unwrap();
    table["profiles"][profile.name()][component.curve_name()] =
        replacement.parse::<toml::Value>().unwrap();
    toml::to_string(&table).unwrap()
}
