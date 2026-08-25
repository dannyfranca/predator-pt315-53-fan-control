use fan_control_core::parse_config_v1;

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
  { temperature_c = 40, demand_percent = 30 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 35, demand_percent = 30 },
  { temperature_c = 82, demand_percent = 100 },
]

[profiles.battery]
cpu_curve = [
  { temperature_c = 40, demand_percent = 25 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 35, demand_percent = 25 },
  { temperature_c = 82, demand_percent = 100 },
]
"#;

#[test]
fn complete_schema_v1_configuration_parses_atomically() {
    let config = parse_config_v1(VALID_CONFIG).unwrap();

    assert_eq!(config.schema_version, 1);
    assert_eq!(config.control.hysteresis_celsius, 3);
    assert_eq!(config.control.lower_demand_hold_seconds, 10);
    assert_eq!(config.control.max_down_ramp_percent_per_second.value(), 1.0);
    assert_eq!(config.fans.cpu.minimum_duty_percent, 30);
    assert_eq!(config.fans.gpu.minimum_duty_percent, 25);
    assert_eq!(config.profiles.ac.cpu_curve.len(), 2);
    assert_eq!(config.profiles.ac.cpu_curve[0].temperature_c, 40);
    assert_eq!(config.profiles.ac.cpu_curve[0].demand_percent, 30);
    assert_eq!(config.profiles.battery.gpu_curve.len(), 2);
}

#[test]
fn missing_duplicate_unknown_and_malformed_fields_reject_the_whole_document() {
    let invalid_documents = [
        VALID_CONFIG.replace("schema_version = 1\n", ""),
        VALID_CONFIG.replace(
            "schema_version = 1\n",
            "schema_version = 1\nschema_version = 1\n",
        ),
        VALID_CONFIG.replace("[control]\n", "unexpected = 1\n\n[control]\n"),
        VALID_CONFIG.replace("[control]\n", "[control]\nunexpected = 1\n"),
        VALID_CONFIG.replace("[fans.cpu]\n", "[fans]\nunexpected = 1\n\n[fans.cpu]\n"),
        VALID_CONFIG.replace("[fans.cpu]\n", "[fans.cpu]\nunexpected = 1\n"),
        VALID_CONFIG.replace("[profiles.ac]\n", "[profiles.ac]\nunexpected = 1\n"),
        VALID_CONFIG.replacen(
            "{ temperature_c = 40, demand_percent = 30 }",
            "{ temperature_c = 40, demand_percent = 30, unexpected = 1 }",
            1,
        ),
        VALID_CONFIG.replace("hysteresis_celsius = 3", "hysteresis_celsius ="),
        VALID_CONFIG.replacen("minimum_duty_percent = 30\n", "", 1),
        VALID_CONFIG.replacen("gpu_curve = [", "renamed_curve = [", 1),
        VALID_CONFIG.replacen(
            "{ temperature_c = 40, demand_percent = 30 }",
            "{ temperature_c = 40 }",
            1,
        ),
        VALID_CONFIG.replace("[profiles.battery]", "[profiles.quiet]"),
        format!("{VALID_CONFIG}\n[profiles.quiet]\ncpu_curve = []\ngpu_curve = []\n"),
    ];

    for document in invalid_documents {
        assert!(parse_config_v1(&document).is_err(), "accepted:\n{document}");
    }
}

#[test]
fn every_required_schema_table_and_field_is_required() {
    let required_paths: &[&[&str]] = &[
        &["schema_version"],
        &["control"],
        &["control", "hysteresis_celsius"],
        &["control", "lower_demand_hold_seconds"],
        &["control", "max_down_ramp_percent_per_second"],
        &["fans"],
        &["fans", "cpu"],
        &["fans", "cpu", "minimum_duty_percent"],
        &["fans", "gpu"],
        &["fans", "gpu", "minimum_duty_percent"],
        &["profiles"],
        &["profiles", "ac"],
        &["profiles", "ac", "cpu_curve"],
        &["profiles", "ac", "gpu_curve"],
        &["profiles", "battery"],
        &["profiles", "battery", "cpu_curve"],
        &["profiles", "battery", "gpu_curve"],
    ];

    for path in required_paths {
        let document = document_without(path);
        assert!(
            parse_config_v1(&document).is_err(),
            "accepted document missing {path:?}:\n{document}"
        );
    }
}

#[test]
fn non_finite_and_incorrectly_typed_numbers_are_rejected() {
    let invalid_documents = [
        VALID_CONFIG.replace(
            "max_down_ramp_percent_per_second = 1.0",
            "max_down_ramp_percent_per_second = nan",
        ),
        VALID_CONFIG.replace(
            "max_down_ramp_percent_per_second = 1.0",
            "max_down_ramp_percent_per_second = inf",
        ),
        VALID_CONFIG.replace(
            "max_down_ramp_percent_per_second = 1.0",
            "max_down_ramp_percent_per_second = 1",
        ),
        VALID_CONFIG.replacen("hysteresis_celsius = 3", "hysteresis_celsius = 3.0", 1),
        VALID_CONFIG.replacen(
            "lower_demand_hold_seconds = 10",
            "lower_demand_hold_seconds = 10.0",
            1,
        ),
        VALID_CONFIG.replacen(
            "minimum_duty_percent = 30",
            "minimum_duty_percent = 30.0",
            1,
        ),
        VALID_CONFIG.replacen("temperature_c = 40", "temperature_c = 40.0", 1),
        VALID_CONFIG.replacen("demand_percent = 30", "demand_percent = 30.0", 1),
        VALID_CONFIG.replace("schema_version = 1", "schema_version = \"1\""),
        VALID_CONFIG.replace("schema_version = 1", "schema_version = 1.0"),
        VALID_CONFIG.replace("schema_version = 1", "schema_version = 0"),
        VALID_CONFIG.replace("schema_version = 1", "schema_version = -1"),
        VALID_CONFIG.replace("schema_version = 1", "schema_version = 2"),
    ];

    for document in invalid_documents {
        assert!(parse_config_v1(&document).is_err(), "accepted:\n{document}");
    }
}

fn document_without(path: &[&str]) -> String {
    let mut document = VALID_CONFIG.parse::<toml::Table>().unwrap();
    let (field, parents) = path.split_last().unwrap();
    let mut table = &mut document;

    for parent in parents {
        table = table
            .get_mut(*parent)
            .and_then(toml::Value::as_table_mut)
            .unwrap();
    }

    assert!(table.remove(*field).is_some());
    toml::to_string(&document).unwrap()
}
