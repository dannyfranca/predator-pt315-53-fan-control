use fan_control_core::{
    Component, EnvelopeValidationError, Fan, Profile, ValidatedConfig, parse_config_v1,
    validate_against_protected_envelope, validate_config_v1,
};

const PROTECTED_CONFIG: &str = r#"
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
  { temperature_c = 0, demand_percent = 20 },
  { temperature_c = 50, demand_percent = 70 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 0, demand_percent = 20 },
  { temperature_c = 45, demand_percent = 70 },
  { temperature_c = 82, demand_percent = 100 },
]

[profiles.battery]
cpu_curve = [
  { temperature_c = 0, demand_percent = 20 },
  { temperature_c = 50, demand_percent = 70 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 0, demand_percent = 20 },
  { temperature_c = 45, demand_percent = 70 },
  { temperature_c = 82, demand_percent = 100 },
]
"#;

#[test]
fn equal_and_more_aggressive_candidates_are_accepted() {
    let protected = validated(PROTECTED_CONFIG);
    assert!(validate_against_protected_envelope(&validated(PROTECTED_CONFIG), &protected).is_ok());

    let mut candidate = PROTECTED_CONFIG.parse::<toml::Table>().unwrap();
    candidate["fans"]["cpu"]["minimum_duty_percent"] = toml::Value::Integer(35);
    candidate["fans"]["gpu"]["minimum_duty_percent"] = toml::Value::Integer(30);
    for profile in [Profile::Ac, Profile::Battery] {
        candidate["profiles"][profile.name()]["cpu_curve"] = curve(&[(0, 30), (50, 80), (90, 100)]);
        candidate["profiles"][profile.name()]["gpu_curve"] = curve(&[(0, 30), (45, 80), (82, 100)]);
    }

    assert!(
        validate_against_protected_envelope(
            &validated(&toml::to_string(&candidate).unwrap()),
            &protected,
        )
        .is_ok()
    );
}

#[test]
fn mathematically_equal_curves_ignore_interpolation_round_off() {
    let protected = replace_curve(
        PROTECTED_CONFIG,
        Profile::Ac,
        Component::Cpu,
        &[(0, 0), (20, 100)],
    );
    let candidate = replace_curve(
        PROTECTED_CONFIG,
        Profile::Ac,
        Component::Cpu,
        &[(0, 0), (11, 55), (20, 100)],
    );

    assert!(
        validate_against_protected_envelope(&validated(&candidate), &validated(&protected)).is_ok()
    );
}

#[test]
fn protected_only_breakpoints_expose_weaker_candidate_segments() {
    for profile in [Profile::Ac, Profile::Battery] {
        for (component, maximum, protected_breakpoint) in
            [(Component::Cpu, 90, 50), (Component::Gpu, 82, 45)]
        {
            let candidate = replace_curve(
                PROTECTED_CONFIG,
                profile,
                component,
                &[(0, 20), (maximum, 100)],
            );

            assert_eq!(
                validate_against_protected_envelope(
                    &validated(&candidate),
                    &validated(PROTECTED_CONFIG)
                ),
                Err(EnvelopeValidationError::CurveBelowProtected {
                    profile,
                    component,
                    temperature_celsius: protected_breakpoint as f64,
                })
            );
        }
    }
}

#[test]
fn candidate_only_breakpoints_expose_weaker_candidate_segments() {
    let protected = replace_curve(
        PROTECTED_CONFIG,
        Profile::Ac,
        Component::Cpu,
        &[(0, 20), (90, 100)],
    );
    let candidate = replace_curve(
        PROTECTED_CONFIG,
        Profile::Ac,
        Component::Cpu,
        &[(0, 20), (50, 50), (90, 100)],
    );

    assert_eq!(
        validate_against_protected_envelope(&validated(&candidate), &validated(&protected)),
        Err(EnvelopeValidationError::CurveBelowProtected {
            profile: Profile::Ac,
            component: Component::Cpu,
            temperature_celsius: 50.0,
        })
    );
}

#[test]
fn each_candidate_fan_floor_must_meet_its_protected_floor() {
    for (fan, candidate_value, protected_value) in [(Fan::Cpu, 29, 30), (Fan::Gpu, 24, 25)] {
        let candidate = replace_fan_floor(PROTECTED_CONFIG, fan, candidate_value);
        assert_eq!(
            validate_against_protected_envelope(
                &validated(&candidate),
                &validated(PROTECTED_CONFIG)
            ),
            Err(EnvelopeValidationError::FanFloorBelowProtected {
                fan,
                candidate_percent: candidate_value as f64,
                protected_percent: protected_value as f64,
            })
        );
    }
}

fn validated(document: &str) -> ValidatedConfig {
    validate_config_v1(parse_config_v1(document).unwrap()).unwrap()
}

fn replace_curve(
    document: &str,
    profile: Profile,
    component: Component,
    points: &[(i64, i64)],
) -> String {
    let mut table = document.parse::<toml::Table>().unwrap();
    table["profiles"][profile.name()][component.curve_name()] = curve(points);
    toml::to_string(&table).unwrap()
}

fn replace_fan_floor(document: &str, fan: Fan, value: i64) -> String {
    let mut table = document.parse::<toml::Table>().unwrap();
    table["fans"][fan.name()]["minimum_duty_percent"] = toml::Value::Integer(value);
    toml::to_string(&table).unwrap()
}

fn curve(points: &[(i64, i64)]) -> toml::Value {
    toml::Value::Array(
        points
            .iter()
            .map(|&(temperature, demand)| {
                toml::Value::Table(toml::Table::from_iter([
                    ("temperature_c".into(), toml::Value::Integer(temperature)),
                    ("demand_percent".into(), toml::Value::Integer(demand)),
                ]))
            })
            .collect(),
    )
}
