use fan_control_core::{DemandPercent, DemandPercentError, Pwm};

#[test]
fn endpoints_map_to_the_full_pwm_range() {
    assert_eq!(to_pwm(0.0), 0);
    assert_eq!(to_pwm(100.0), 255);
}

#[test]
fn fractional_pwm_values_round_up() {
    assert_eq!(to_pwm(1.0), 3);
    assert_eq!(to_pwm(50.0), 128);
    assert_eq!(to_pwm(99.0), 253);
}

#[test]
fn demand_rejects_non_finite_and_out_of_range_percentages() {
    assert_eq!(
        DemandPercent::try_from(f64::NAN),
        Err(DemandPercentError::NonFinite)
    );
    assert_eq!(
        DemandPercent::try_from(f64::INFINITY),
        Err(DemandPercentError::NonFinite)
    );
    assert_eq!(
        DemandPercent::try_from(-0.1),
        Err(DemandPercentError::OutOfRange)
    );
    assert_eq!(
        DemandPercent::try_from(100.1),
        Err(DemandPercentError::OutOfRange)
    );
}

fn to_pwm(percent: f64) -> u8 {
    let demand = DemandPercent::try_from(percent).expect("test demand should be valid");
    Pwm::from(demand).value()
}
