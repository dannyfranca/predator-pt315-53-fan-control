use std::time::Duration;

use fan_control_core::{
    DemandPercent, DemandSmoother, DownshiftPolicy, DownshiftPolicyError, EffectiveTemperature,
    HysteresisCelsius, HysteresisError, MonotonicTime, MonotonicTimeError, TemperatureCelsius,
};

#[derive(Default)]
struct ManualClock {
    elapsed: Duration,
}

impl ManualClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from(self.elapsed)
    }

    fn advance(&mut self, duration: Duration) {
        self.elapsed += duration;
    }
}

#[test]
fn effective_temperature_uses_the_approved_asymmetric_hysteresis_rule() {
    let hysteresis = HysteresisCelsius::try_from(3.0).unwrap();
    let mut effective = EffectiveTemperature::new(temperature(70.0));

    assert_eq!(
        effective.update(temperature(69.0), hysteresis).value(),
        70.0
    );
    assert_eq!(
        effective.update(temperature(60.0), hysteresis).value(),
        63.0
    );
    assert_eq!(
        effective.update(temperature(65.0), hysteresis).value(),
        65.0
    );
}

#[test]
fn a_rise_cancels_the_pending_hold_and_applies_immediately() {
    let mut clock = ManualClock::default();
    let policy = DownshiftPolicy::new(Duration::from_secs(10), 1.0).unwrap();
    let mut smoother = DemandSmoother::new(demand(80.0), policy, clock.now());

    assert_eq!(
        smoother.update(demand(40.0), clock.now()).unwrap(),
        demand(80.0)
    );
    clock.advance(Duration::from_secs(5));
    assert_eq!(
        smoother.update(demand(90.0), clock.now()).unwrap(),
        demand(90.0)
    );

    assert_eq!(
        smoother.update(demand(40.0), clock.now()).unwrap(),
        demand(90.0)
    );
    clock.advance(Duration::from_secs(9));
    assert_eq!(
        smoother.update(demand(40.0), clock.now()).unwrap(),
        demand(90.0)
    );
}

#[test]
fn a_rise_below_the_command_restarts_the_hold() {
    let mut clock = ManualClock::default();
    let policy = DownshiftPolicy::new(Duration::from_secs(10), 1.0).unwrap();
    let mut smoother = DemandSmoother::new(demand(80.0), policy, clock.now());

    assert_eq!(smoother.update(demand(40.0), clock.now()), Ok(demand(80.0)));
    clock.advance(Duration::from_secs(5));
    assert_eq!(smoother.update(demand(60.0), clock.now()), Ok(demand(80.0)));
    clock.advance(Duration::from_secs(9));
    assert_eq!(smoother.update(demand(40.0), clock.now()), Ok(demand(80.0)));
    clock.advance(Duration::from_secs(2));
    assert_eq!(smoother.update(demand(40.0), clock.now()), Ok(demand(79.0)));
}

#[test]
fn a_sustained_decrease_holds_then_uses_elapsed_monotonic_time() {
    let mut clock = ManualClock::default();
    let policy = DownshiftPolicy::new(Duration::from_secs(10), 1.5).unwrap();
    let mut smoother = DemandSmoother::new(demand(80.0), policy, clock.now());

    assert_eq!(
        smoother.update(demand(40.0), clock.now()).unwrap(),
        demand(80.0)
    );
    clock.advance(Duration::from_secs(9));
    assert_eq!(
        smoother.update(demand(40.0), clock.now()).unwrap(),
        demand(80.0)
    );
    clock.advance(Duration::from_secs(3));
    assert_eq!(
        smoother.update(demand(40.0), clock.now()).unwrap(),
        demand(77.0)
    );
    clock.advance(Duration::from_secs(30));
    assert_eq!(
        smoother.update(demand(40.0), clock.now()).unwrap(),
        demand(40.0)
    );
}

#[test]
fn time_regression_is_rejected_without_changing_commanded_demand() {
    let policy = DownshiftPolicy::new(Duration::from_secs(10), 1.0).unwrap();
    let mut smoother = DemandSmoother::new(
        demand(80.0),
        policy,
        MonotonicTime::from(Duration::from_secs(5)),
    );

    assert_eq!(
        smoother.update(demand(40.0), MonotonicTime::from(Duration::from_secs(4))),
        Err(MonotonicTimeError::WentBackwards)
    );
    assert_eq!(smoother.commanded(), demand(80.0));

    assert_eq!(
        smoother.update(demand(40.0), MonotonicTime::from(Duration::from_secs(5))),
        Ok(demand(80.0))
    );
    assert_eq!(
        smoother.update(demand(40.0), MonotonicTime::from(Duration::from_secs(14))),
        Ok(demand(80.0))
    );
    assert_eq!(
        smoother.update(demand(40.0), MonotonicTime::from(Duration::from_secs(16))),
        Ok(demand(79.0))
    );
}

#[test]
fn policy_configuration_rejects_invalid_numeric_values() {
    assert_eq!(
        HysteresisCelsius::try_from(f64::NAN),
        Err(HysteresisError::NonFinite)
    );
    assert_eq!(
        HysteresisCelsius::try_from(f64::INFINITY),
        Err(HysteresisError::NonFinite)
    );
    assert_eq!(
        HysteresisCelsius::try_from(-1.0),
        Err(HysteresisError::Negative)
    );

    for rate in [f64::NAN, f64::INFINITY] {
        assert_eq!(
            DownshiftPolicy::new(Duration::ZERO, rate),
            Err(DownshiftPolicyError::NonFiniteRate)
        );
    }
    for rate in [0.0, -1.0] {
        assert_eq!(
            DownshiftPolicy::new(Duration::ZERO, rate),
            Err(DownshiftPolicyError::NonPositiveRate)
        );
    }
}

fn demand(value: f64) -> DemandPercent {
    DemandPercent::try_from(value).unwrap()
}

fn temperature(value: f64) -> TemperatureCelsius {
    TemperatureCelsius::try_from(value).unwrap()
}
