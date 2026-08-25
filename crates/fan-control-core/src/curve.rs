use crate::DemandPercent;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct TemperatureCelsius(f64);

impl TemperatureCelsius {
    pub const fn value(self) -> f64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemperatureError {
    NonFinite,
}

impl TryFrom<f64> for TemperatureCelsius {
    type Error = TemperatureError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if value.is_finite() {
            Ok(Self(value))
        } else {
            Err(TemperatureError::NonFinite)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CurvePoint {
    temperature: TemperatureCelsius,
    demand: DemandPercent,
}

impl CurvePoint {
    pub const fn new(temperature: TemperatureCelsius, demand: DemandPercent) -> Self {
        Self {
            temperature,
            demand,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DemandCurve {
    points: Vec<CurvePoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemandCurveError {
    Empty,
    NotStrictlyIncreasing,
}

impl DemandCurve {
    pub fn from_ordered_points(points: Vec<CurvePoint>) -> Result<Self, DemandCurveError> {
        if points.is_empty() {
            return Err(DemandCurveError::Empty);
        }

        if points
            .windows(2)
            .any(|pair| pair[0].temperature.value() >= pair[1].temperature.value())
        {
            return Err(DemandCurveError::NotStrictlyIncreasing);
        }

        Ok(Self { points })
    }

    pub fn evaluate(&self, temperature: TemperatureCelsius) -> DemandPercent {
        let first = self
            .points
            .first()
            .expect("a demand curve always contains at least one point");

        if temperature.value() <= first.temperature.value() {
            return first.demand;
        }

        for pair in self.points.windows(2) {
            let lower = pair[0];
            let upper = pair[1];

            if temperature.value() == upper.temperature.value() {
                return upper.demand;
            }

            if temperature.value() < upper.temperature.value() {
                let offset = temperature.value() - lower.temperature.value();
                let span = upper.temperature.value() - lower.temperature.value();
                let position = if offset.is_finite() && span.is_finite() {
                    offset / span
                } else {
                    let scale = temperature
                        .value()
                        .abs()
                        .max(lower.temperature.value().abs())
                        .max(upper.temperature.value().abs());
                    (temperature.value() / scale - lower.temperature.value() / scale)
                        / (upper.temperature.value() / scale - lower.temperature.value() / scale)
                };
                let interpolated =
                    lower.demand.value() + (upper.demand.value() - lower.demand.value()) * position;
                let bounded = interpolated.clamp(
                    lower.demand.value().min(upper.demand.value()),
                    lower.demand.value().max(upper.demand.value()),
                );

                return DemandPercent::try_from(bounded)
                    .expect("interpolation between validated demand endpoints is valid");
            }
        }

        self.points
            .last()
            .expect("a demand curve always contains at least one point")
            .demand
    }
}
