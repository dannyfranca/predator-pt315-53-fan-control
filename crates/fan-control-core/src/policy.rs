use std::time::Duration;

use crate::{DemandPercent, TemperatureCelsius};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct HysteresisCelsius(f64);

impl HysteresisCelsius {
    pub const fn value(self) -> f64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HysteresisError {
    NonFinite,
    Negative,
}

impl TryFrom<f64> for HysteresisCelsius {
    type Error = HysteresisError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if !value.is_finite() {
            return Err(HysteresisError::NonFinite);
        }
        if value < 0.0 {
            return Err(HysteresisError::Negative);
        }

        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EffectiveTemperature {
    current: TemperatureCelsius,
}

impl EffectiveTemperature {
    pub const fn new(initial: TemperatureCelsius) -> Self {
        Self { current: initial }
    }

    pub fn update(
        &mut self,
        sample: TemperatureCelsius,
        hysteresis: HysteresisCelsius,
    ) -> TemperatureCelsius {
        if sample.value() >= self.current.value() {
            self.current = sample;
        } else {
            let effective = sample.value().max(
                self.current
                    .value()
                    .min(sample.value() + hysteresis.value()),
            );
            self.current = TemperatureCelsius::try_from(effective)
                .expect("effective temperature remains one of the finite bounds");
        }

        self.current
    }

    pub const fn current(self) -> TemperatureCelsius {
        self.current
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonotonicTime(Duration);

impl From<Duration> for MonotonicTime {
    fn from(elapsed: Duration) -> Self {
        Self(elapsed)
    }
}

impl MonotonicTime {
    fn elapsed_since(self, earlier: Self) -> Duration {
        self.0 - earlier.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DownshiftPolicy {
    hold: Duration,
    max_down_rate_percent_per_second: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownshiftPolicyError {
    NonFiniteRate,
    NonPositiveRate,
}

impl DownshiftPolicy {
    pub fn new(
        hold: Duration,
        max_down_rate_percent_per_second: f64,
    ) -> Result<Self, DownshiftPolicyError> {
        if !max_down_rate_percent_per_second.is_finite() {
            return Err(DownshiftPolicyError::NonFiniteRate);
        }
        if max_down_rate_percent_per_second <= 0.0 {
            return Err(DownshiftPolicyError::NonPositiveRate);
        }

        Ok(Self {
            hold,
            max_down_rate_percent_per_second,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonotonicTimeError {
    WentBackwards,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DemandSmoother {
    commanded: DemandPercent,
    last_target: DemandPercent,
    policy: DownshiftPolicy,
    pending_since: Option<MonotonicTime>,
    last_update: MonotonicTime,
}

impl DemandSmoother {
    pub const fn new(initial: DemandPercent, policy: DownshiftPolicy, now: MonotonicTime) -> Self {
        Self {
            commanded: initial,
            last_target: initial,
            policy,
            pending_since: None,
            last_update: now,
        }
    }

    pub fn update(
        &mut self,
        target: DemandPercent,
        now: MonotonicTime,
    ) -> Result<DemandPercent, MonotonicTimeError> {
        if now < self.last_update {
            return Err(MonotonicTimeError::WentBackwards);
        }

        let target_rose = target.value() > self.last_target.value();

        if target.value() >= self.commanded.value() {
            self.commanded = target;
            self.last_target = target;
            self.pending_since = None;
            self.last_update = now;
            return Ok(self.commanded);
        }

        if target_rose {
            self.last_target = target;
            self.pending_since = Some(now);
            self.last_update = now;
            return Ok(self.commanded);
        }

        let pending_since = *self.pending_since.get_or_insert(now);
        let held_before = self.last_update.elapsed_since(pending_since);
        let held_now = now.elapsed_since(pending_since);
        let ramp_elapsed = held_now
            .saturating_sub(self.policy.hold)
            .saturating_sub(held_before.saturating_sub(self.policy.hold));

        if !ramp_elapsed.is_zero() {
            let decrease =
                self.policy.max_down_rate_percent_per_second * ramp_elapsed.as_secs_f64();
            let next = (self.commanded.value() - decrease).max(target.value());
            self.commanded = DemandPercent::try_from(next)
                .expect("a downward step clamped to a validated target remains valid");
            if self.commanded == target {
                self.pending_since = None;
            }
        }

        self.last_target = target;
        self.last_update = now;
        Ok(self.commanded)
    }

    pub const fn commanded(self) -> DemandPercent {
        self.commanded
    }
}
