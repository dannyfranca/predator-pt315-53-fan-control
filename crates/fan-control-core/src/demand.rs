/// Validated normalized fan demand in percent.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct DemandPercent(f64);

impl DemandPercent {
    /// Returns the validated percentage in the inclusive range `0..=100`.
    pub const fn value(self) -> f64 {
        self.0
    }
}

/// Why a raw percentage could not become a [`DemandPercent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemandPercentError {
    /// The value was NaN or infinite.
    NonFinite,
    /// The value was outside the inclusive range `0..=100`.
    OutOfRange,
}

impl TryFrom<f64> for DemandPercent {
    type Error = DemandPercentError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if !value.is_finite() {
            return Err(DemandPercentError::NonFinite);
        }
        if !(0.0..=100.0).contains(&value) {
            return Err(DemandPercentError::OutOfRange);
        }

        Ok(Self(value))
    }
}

/// Standard 8-bit PWM output value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pwm(u8);

impl Pwm {
    pub const MAXIMUM: Self = Self(u8::MAX);

    /// Returns the PWM value in the inclusive range `0..=255`.
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl From<DemandPercent> for Pwm {
    fn from(demand: DemandPercent) -> Self {
        let scaled = demand.value() * f64::from(u8::MAX) / 100.0;
        Self(scaled.ceil() as u8)
    }
}
