use crate::{DemandPercent, Pwm, TemperatureCelsius, ValidatedConfig, ValidatedProfileConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalPower {
    Connected,
    Disconnected,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanOutputs {
    cpu_pwm: Pwm,
    gpu_pwm: Pwm,
}

impl FanOutputs {
    pub const fn maximum() -> Self {
        Self {
            cpu_pwm: Pwm::MAXIMUM,
            gpu_pwm: Pwm::MAXIMUM,
        }
    }

    pub const fn cpu_pwm(self) -> Pwm {
        self.cpu_pwm
    }

    pub const fn gpu_pwm(self) -> Pwm {
        self.gpu_pwm
    }
}

pub fn calculate_fan_outputs(
    config: &ValidatedConfig,
    cpu_temperature: TemperatureCelsius,
    gpu_temperature: TemperatureCelsius,
    external_power: ExternalPower,
) -> FanOutputs {
    let target = calculate_target_demand(config, cpu_temperature, gpu_temperature, external_power);

    fan_outputs_for_demand(config, target)
}

pub(crate) fn calculate_target_demand(
    config: &ValidatedConfig,
    cpu_temperature: TemperatureCelsius,
    gpu_temperature: TemperatureCelsius,
    external_power: ExternalPower,
) -> DemandPercent {
    let profile = selected_profile(config, external_power);
    maximum(
        profile.cpu_curve().evaluate(cpu_temperature),
        profile.gpu_curve().evaluate(gpu_temperature),
    )
}

pub(crate) fn fan_outputs_for_demand(
    config: &ValidatedConfig,
    demand: DemandPercent,
) -> FanOutputs {
    FanOutputs {
        cpu_pwm: Pwm::from(maximum(demand, config.fans().cpu().minimum_duty())),
        gpu_pwm: Pwm::from(maximum(demand, config.fans().gpu().minimum_duty())),
    }
}

fn selected_profile(
    config: &ValidatedConfig,
    external_power: ExternalPower,
) -> &ValidatedProfileConfig {
    match external_power {
        ExternalPower::Disconnected => config.profiles().battery(),
        ExternalPower::Connected | ExternalPower::Unknown => config.profiles().ac(),
    }
}

fn maximum(left: DemandPercent, right: DemandPercent) -> DemandPercent {
    if left.value() >= right.value() {
        left
    } else {
        right
    }
}
