use std::{error::Error, fmt};

use crate::{Component, Fan, Profile, ValidatedConfig, ValidatedProfileConfig};

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectedConfig(ValidatedConfig);

impl ProtectedConfig {
    pub const fn config(&self) -> &ValidatedConfig {
        &self.0
    }

    pub fn into_config(self) -> ValidatedConfig {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EnvelopeValidationError {
    FanFloorBelowProtected {
        fan: Fan,
        candidate_percent: f64,
        protected_percent: f64,
    },
    CurveBelowProtected {
        profile: Profile,
        component: Component,
        temperature_celsius: f64,
    },
}

impl fmt::Display for EnvelopeValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FanFloorBelowProtected {
                fan,
                candidate_percent,
                protected_percent,
            } => write!(
                formatter,
                "{} fan floor {candidate_percent}% is below protected floor {protected_percent}%",
                fan.name()
            ),
            Self::CurveBelowProtected {
                profile,
                component,
                temperature_celsius,
            } => write!(
                formatter,
                "{}.{} curve is below its protected envelope at {temperature_celsius} °C",
                profile.name(),
                component.name()
            ),
        }
    }
}

impl Error for EnvelopeValidationError {}

pub fn validate_against_protected_envelope(
    candidate: ValidatedConfig,
    protected: &ValidatedConfig,
) -> Result<ProtectedConfig, EnvelopeValidationError> {
    validate_floor(
        Fan::Cpu,
        candidate.fans().cpu().minimum_duty().value(),
        protected.fans().cpu().minimum_duty().value(),
    )?;
    validate_floor(
        Fan::Gpu,
        candidate.fans().gpu().minimum_duty().value(),
        protected.fans().gpu().minimum_duty().value(),
    )?;

    validate_profile(
        Profile::Ac,
        candidate.profiles().ac(),
        protected.profiles().ac(),
    )?;
    validate_profile(
        Profile::Battery,
        candidate.profiles().battery(),
        protected.profiles().battery(),
    )?;

    Ok(ProtectedConfig(candidate))
}

fn validate_floor(
    fan: Fan,
    candidate_percent: f64,
    protected_percent: f64,
) -> Result<(), EnvelopeValidationError> {
    if candidate_percent < protected_percent {
        return Err(EnvelopeValidationError::FanFloorBelowProtected {
            fan,
            candidate_percent,
            protected_percent,
        });
    }

    Ok(())
}

fn validate_profile(
    profile: Profile,
    candidate: &ValidatedProfileConfig,
    protected: &ValidatedProfileConfig,
) -> Result<(), EnvelopeValidationError> {
    for (component, candidate_curve, protected_curve) in [
        (Component::Cpu, candidate.cpu_curve(), protected.cpu_curve()),
        (Component::Gpu, candidate.gpu_curve(), protected.gpu_curve()),
    ] {
        if let Some(temperature) = candidate_curve.first_below(protected_curve) {
            return Err(EnvelopeValidationError::CurveBelowProtected {
                profile,
                component,
                temperature_celsius: temperature.value(),
            });
        }
    }

    Ok(())
}
