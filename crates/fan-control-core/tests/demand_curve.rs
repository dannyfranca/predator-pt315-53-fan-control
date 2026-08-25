use fan_control_core::{
    CurvePoint, DemandCurve, DemandCurveError, DemandPercent, TemperatureCelsius,
};

#[test]
fn temperatures_outside_the_curve_clamp_to_endpoint_demand() {
    let curve = curve(&[(40.0, 25.0), (60.0, 75.0)]);

    assert_eq!(evaluate(&curve, 20.0), 25.0);
    assert_eq!(evaluate(&curve, 80.0), 75.0);
}

#[test]
fn temperatures_at_breakpoints_return_their_demand() {
    let curve = curve(&[(40.0, 25.0), (60.0, 75.0), (80.0, 100.0)]);

    assert_eq!(evaluate(&curve, 40.0), 25.0);
    assert_eq!(evaluate(&curve, 60.0), 75.0);
    assert_eq!(evaluate(&curve, 80.0), 100.0);
}

#[test]
fn temperatures_between_breakpoints_interpolate_fractional_demand() {
    let curve = curve(&[(40.0, 25.0), (60.0, 75.0)]);

    assert_eq!(evaluate(&curve, 45.0), 37.5);
    assert_eq!(evaluate(&curve, 50.0), 50.0);
}

#[test]
fn interpolation_handles_extreme_finite_temperatures_without_overflow() {
    let curve = curve(&[(-f64::MAX, 0.0), (f64::MAX, 100.0)]);

    assert_eq!(evaluate(&curve, 0.0), 50.0);
}

#[test]
fn curve_construction_rejects_missing_or_unordered_points() {
    assert_eq!(
        DemandCurve::from_ordered_points(Vec::new()),
        Err(DemandCurveError::Empty)
    );

    for temperatures in [[40.0, 40.0], [60.0, 40.0]] {
        let points = temperatures
            .map(|temperature| {
                CurvePoint::new(
                    TemperatureCelsius::try_from(temperature).unwrap(),
                    DemandPercent::try_from(50.0).unwrap(),
                )
            })
            .to_vec();

        assert_eq!(
            DemandCurve::from_ordered_points(points),
            Err(DemandCurveError::NotStrictlyIncreasing)
        );
    }
}

fn curve(points: &[(f64, f64)]) -> DemandCurve {
    let points = points
        .iter()
        .map(|&(temperature, demand)| {
            CurvePoint::new(
                TemperatureCelsius::try_from(temperature).expect("temperature should be valid"),
                DemandPercent::try_from(demand).expect("demand should be valid"),
            )
        })
        .collect();

    DemandCurve::from_ordered_points(points).expect("curve should be ordered")
}

fn evaluate(curve: &DemandCurve, temperature: f64) -> f64 {
    curve
        .evaluate(TemperatureCelsius::try_from(temperature).expect("temperature should be valid"))
        .value()
}
