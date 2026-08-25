use fan_control_core::{
    ExternalPower, TemperatureCelsius, calculate_fan_outputs, parse_config_v1, validate_config_v1,
};

const CONFIG: &str = r#"
schema_version = 1

[control]
hysteresis_celsius = 3
lower_demand_hold_seconds = 10
max_down_ramp_percent_per_second = 1.0

[fans.cpu]
minimum_duty_percent = 60

[fans.gpu]
minimum_duty_percent = 40

[profiles.ac]
cpu_curve = [
  { temperature_c = 0, demand_percent = 20 },
  { temperature_c = 72, demand_percent = 84 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 0, demand_percent = 30 },
  { temperature_c = 65, demand_percent = 86 },
  { temperature_c = 82, demand_percent = 100 },
]

[profiles.battery]
cpu_curve = [
  { temperature_c = 0, demand_percent = 10 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 0, demand_percent = 15 },
  { temperature_c = 82, demand_percent = 100 },
]
"#;

#[test]
fn higher_component_demand_drives_both_fans() {
    let config = validated_config();

    let cpu_hotter = calculate_fan_outputs(
        &config,
        temperature(72.0),
        temperature(0.0),
        ExternalPower::Connected,
    );
    let gpu_hotter = calculate_fan_outputs(
        &config,
        temperature(0.0),
        temperature(65.0),
        ExternalPower::Connected,
    );

    // Each hot component's demand is applied to both fans.
    assert_eq!(cpu_hotter.cpu_pwm().value(), 215);
    assert_eq!(cpu_hotter.gpu_pwm().value(), 215);
    assert_eq!(gpu_hotter.cpu_pwm().value(), 220);
    assert_eq!(gpu_hotter.gpu_pwm().value(), 220);
}

#[test]
fn each_fan_applies_its_own_configured_floor_before_pwm_conversion() {
    let config = validated_config();

    let outputs = calculate_fan_outputs(
        &config,
        temperature(0.0),
        temperature(0.0),
        ExternalPower::Connected,
    );

    assert_eq!(outputs.cpu_pwm().value(), 153);
    assert_eq!(outputs.gpu_pwm().value(), 102);
}

#[test]
fn disconnected_power_uses_battery_while_unknown_power_uses_ac() {
    let config = validated_config();
    let cpu = temperature(0.0);
    let gpu = temperature(41.0);

    let connected = calculate_fan_outputs(&config, cpu, gpu, ExternalPower::Connected);
    let disconnected = calculate_fan_outputs(&config, cpu, gpu, ExternalPower::Disconnected);
    let unknown = calculate_fan_outputs(&config, cpu, gpu, ExternalPower::Unknown);

    assert_ne!(disconnected, connected);
    assert_eq!(unknown, connected);
}

fn validated_config() -> fan_control_core::ValidatedConfig {
    validate_config_v1(parse_config_v1(CONFIG).unwrap()).unwrap()
}

fn temperature(value: f64) -> TemperatureCelsius {
    TemperatureCelsius::try_from(value).unwrap()
}
