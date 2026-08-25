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
    let profile = selected_profile(config, external_power);
    let cpu_demand = profile.cpu_curve().evaluate(cpu_temperature);
    let gpu_demand = profile.gpu_curve().evaluate(gpu_temperature);
    let target = maximum(cpu_demand, gpu_demand);

    FanOutputs {
        cpu_pwm: Pwm::from(maximum(target, config.fans().cpu().minimum_duty())),
        gpu_pwm: Pwm::from(maximum(target, config.fans().gpu().minimum_duty())),
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
