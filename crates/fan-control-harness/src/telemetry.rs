use std::{collections::BTreeMap, error::Error, fs, path::Path};

use fan_control_core::{
    CompleteSampleSet, EvidenceExternalPower, EvidenceProfile, EvidenceTimestamp, ExternalPower,
    NvidiaGpuSelector, SampleFreshness, TelemetrySampleEvidence, TemperatureCelsius,
    ValidatedConfig, parse_config_v1, validate_config_v1,
};
use fan_control_daemon::{
    EDITABLE_CONFIG_PATH, SystemNvidiaQualificationSample,
    capture_system_qualification_telemetry_sample,
};
use serde::{Deserialize, Serialize};

use crate::{evidence_timestamp, require_before_deadline};

const PROC_STAT: &str = "/proc/stat";
const CPU_ROOT: &str = "/sys/devices/system/cpu";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CpuTimeSnapshot {
    idle: u64,
    total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CpuThrottleSnapshot {
    counters: BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TelemetryRequest {
    pub(crate) nvidia_gpu_uuid: String,
    pub(crate) previous_cpu_time: CpuTimeSnapshot,
    pub(crate) starting_cpu_throttles: CpuThrottleSnapshot,
}

#[derive(Debug, Serialize)]
pub(crate) struct TelemetryCapture {
    pub(crate) nvidia_gpu_uuid: String,
    pub(crate) sample: TelemetrySampleEvidence,
    pub(crate) cpu_time_snapshot: CpuTimeSnapshot,
    pub(crate) cpu_throttle_snapshot: CpuThrottleSnapshot,
}

pub(crate) fn capture(
    request: TelemetryRequest,
    deadline: u64,
) -> Result<TelemetryCapture, Box<dyn Error>> {
    require_before_deadline(deadline)?;
    let selector = NvidiaGpuSelector::uuid(&request.nvidia_gpu_uuid)?;
    let capture = capture_system_qualification_telemetry_sample(&selector)?;
    let physical = capture.physical;
    let nvidia = capture.nvidia;
    if nvidia.gpu.uuid() != selector.value() {
        return Err("qualification telemetry belongs to a different NVIDIA GPU".into());
    }
    let cpu_time_snapshot = read_cpu_time(Path::new(PROC_STAT))?;
    let cpu_utilization_basis_points =
        utilization_between(request.previous_cpu_time, cpu_time_snapshot)?;
    let cpu_throttle_snapshot = read_cpu_throttles(Path::new(CPU_ROOT))?;
    let cpu_thermal_throttling =
        throttling_since(&request.starting_cpu_throttles, &cpu_throttle_snapshot)?;
    let config_source = fs::read_to_string(EDITABLE_CONFIG_PATH)?;
    let config = validate_config_v1(parse_config_v1(&config_source)?)?;
    let (external_power, selected_profile, profile) = match physical.external_power {
        ExternalPower::Connected => (
            EvidenceExternalPower::Ac,
            EvidenceProfile::Ac,
            config.profiles().ac(),
        ),
        ExternalPower::Disconnected => (
            EvidenceExternalPower::Battery,
            EvidenceProfile::Battery,
            config.profiles().battery(),
        ),
        ExternalPower::Unknown => return Err("external power state is unknown".into()),
    };
    let cpu_temperature =
        TemperatureCelsius::try_from(f64::from(physical.cpu_millicelsius) / 1_000.0)
            .map_err(|_| "CPU temperature is not finite")?;
    let gpu_temperature =
        TemperatureCelsius::try_from(f64::from(physical.gpu_millicelsius) / 1_000.0)
            .map_err(|_| "GPU temperature is not finite")?;
    let cpu_source_demand_basis_points =
        demand_basis_points(profile.cpu_curve().evaluate(cpu_temperature));
    let gpu_source_demand_basis_points =
        demand_basis_points(profile.gpu_curve().evaluate(gpu_temperature));
    let commanded_demand_basis_points =
        cpu_source_demand_basis_points.max(gpu_source_demand_basis_points);
    require_before_deadline(deadline)?;

    Ok(TelemetryCapture {
        nvidia_gpu_uuid: selector.value().to_owned(),
        sample: TelemetrySampleEvidence {
            timestamp: evidence_timestamp()?,
            cpu_millicelsius: Some(physical.cpu_millicelsius),
            gpu_millicelsius: Some(physical.gpu_millicelsius),
            freshness: SampleFreshness::Fresh,
            external_power: Some(external_power),
            selected_profile: Some(selected_profile),
            cpu_source_demand_basis_points: Some(cpu_source_demand_basis_points),
            gpu_source_demand_basis_points: Some(gpu_source_demand_basis_points),
            cpu_utilization_basis_points: Some(cpu_utilization_basis_points),
            gpu_utilization_basis_points: Some(nvidia.utilization_basis_points),
            commanded_demand_basis_points: Some(commanded_demand_basis_points),
            cpu_thermal_throttling: Some(cpu_thermal_throttling),
            gpu_thermal_throttling: Some(nvidia.thermal_throttling),
        },
        cpu_time_snapshot,
        cpu_throttle_snapshot,
    })
}

/// Builds telemetry around the exact sample consumed by a production control cycle instead of
/// performing a second temperature/power read that could describe a different decision.
pub(crate) fn capture_control_cycle(
    request: TelemetryRequest,
    physical: CompleteSampleSet,
    nvidia: SystemNvidiaQualificationSample,
    config: &ValidatedConfig,
    timestamp: EvidenceTimestamp,
    deadline: u64,
) -> Result<TelemetryCapture, Box<dyn Error>> {
    require_before_deadline(deadline)?;
    let selector = NvidiaGpuSelector::uuid(&request.nvidia_gpu_uuid)?;
    if nvidia.gpu.uuid() != selector.value() {
        return Err("qualification telemetry belongs to a different NVIDIA GPU".into());
    }
    let cpu_millicelsius = temperature_millicelsius(physical.cpu_temperature())?;
    let gpu_millicelsius = temperature_millicelsius(physical.gpu_temperature())?;
    let nvidia_gpu_millicelsius = (nvidia.gpu.temperature_celsius() * 1_000.0).round();
    if !nvidia_gpu_millicelsius.is_finite()
        || nvidia_gpu_millicelsius != f64::from(gpu_millicelsius)
    {
        return Err(
            "control and extended NVIDIA samples do not describe the same GPU reading".into(),
        );
    }
    let cpu_time_snapshot = read_cpu_time(Path::new(PROC_STAT))?;
    let cpu_utilization_basis_points =
        utilization_between(request.previous_cpu_time, cpu_time_snapshot)?;
    let cpu_throttle_snapshot = read_cpu_throttles(Path::new(CPU_ROOT))?;
    let cpu_thermal_throttling =
        throttling_since(&request.starting_cpu_throttles, &cpu_throttle_snapshot)?;
    let (external_power, selected_profile, profile) = match physical.external_power() {
        ExternalPower::Connected => (
            EvidenceExternalPower::Ac,
            EvidenceProfile::Ac,
            config.profiles().ac(),
        ),
        ExternalPower::Disconnected => (
            EvidenceExternalPower::Battery,
            EvidenceProfile::Battery,
            config.profiles().battery(),
        ),
        ExternalPower::Unknown => return Err("external power state is unknown".into()),
    };
    let cpu_source_demand_basis_points =
        demand_basis_points(profile.cpu_curve().evaluate(physical.cpu_temperature()));
    let gpu_source_demand_basis_points =
        demand_basis_points(profile.gpu_curve().evaluate(physical.gpu_temperature()));
    let commanded_demand_basis_points =
        cpu_source_demand_basis_points.max(gpu_source_demand_basis_points);
    require_before_deadline(deadline)?;
    Ok(TelemetryCapture {
        nvidia_gpu_uuid: selector.value().to_owned(),
        sample: TelemetrySampleEvidence {
            timestamp,
            cpu_millicelsius: Some(cpu_millicelsius),
            gpu_millicelsius: Some(gpu_millicelsius),
            freshness: SampleFreshness::Fresh,
            external_power: Some(external_power),
            selected_profile: Some(selected_profile),
            cpu_source_demand_basis_points: Some(cpu_source_demand_basis_points),
            gpu_source_demand_basis_points: Some(gpu_source_demand_basis_points),
            cpu_utilization_basis_points: Some(cpu_utilization_basis_points),
            gpu_utilization_basis_points: Some(nvidia.utilization_basis_points),
            commanded_demand_basis_points: Some(commanded_demand_basis_points),
            cpu_thermal_throttling: Some(cpu_thermal_throttling),
            gpu_thermal_throttling: Some(nvidia.thermal_throttling),
        },
        cpu_time_snapshot,
        cpu_throttle_snapshot,
    })
}

pub(crate) fn starting_snapshots() -> Result<(CpuTimeSnapshot, CpuThrottleSnapshot), Box<dyn Error>>
{
    Ok((
        read_cpu_time(Path::new(PROC_STAT))?,
        read_cpu_throttles(Path::new(CPU_ROOT))?,
    ))
}

fn demand_basis_points(demand: fan_control_core::DemandPercent) -> u16 {
    (demand.value() * 100.0).round() as u16
}

fn temperature_millicelsius(value: TemperatureCelsius) -> Result<i32, &'static str> {
    let value = (value.value() * 1_000.0).round();
    if !value.is_finite() || value < f64::from(i32::MIN) || value > f64::from(i32::MAX) {
        return Err("temperature cannot be represented as millicelsius");
    }
    Ok(value as i32)
}

fn read_cpu_time(path: &Path) -> Result<CpuTimeSnapshot, Box<dyn Error>> {
    parse_cpu_time(&fs::read_to_string(path)?)
}

fn parse_cpu_time(source: &str) -> Result<CpuTimeSnapshot, Box<dyn Error>> {
    let fields = source
        .lines()
        .next()
        .ok_or("/proc/stat has no aggregate CPU row")?
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.first() != Some(&"cpu") || fields.len() < 5 {
        return Err("/proc/stat aggregate CPU row is malformed".into());
    }
    let counters = fields[1..]
        .iter()
        .map(|field| field.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()?;
    let total = counters
        .iter()
        .take(8)
        .try_fold(0_u64, |total, counter| total.checked_add(*counter))
        .ok_or("/proc/stat aggregate CPU time overflowed")?;
    let idle = counters[3]
        .checked_add(counters.get(4).copied().unwrap_or(0))
        .ok_or("/proc/stat aggregate idle time overflowed")?;
    Ok(CpuTimeSnapshot { idle, total })
}

fn utilization_between(
    previous: CpuTimeSnapshot,
    current: CpuTimeSnapshot,
) -> Result<u16, Box<dyn Error>> {
    let total = current
        .total
        .checked_sub(previous.total)
        .filter(|total| *total > 0)
        .ok_or("aggregate CPU time did not advance monotonically")?;
    let idle = current
        .idle
        .checked_sub(previous.idle)
        .filter(|idle| *idle <= total)
        .ok_or("aggregate CPU idle time did not advance monotonically")?;
    let busy = total - idle;
    Ok(u16::try_from(
        (u128::from(busy) * 10_000 + u128::from(total) / 2) / u128::from(total),
    )?)
}

fn read_cpu_throttles(root: &Path) -> Result<CpuThrottleSnapshot, Box<dyn Error>> {
    let mut counters = BTreeMap::new();
    for cpu in fs::read_dir(root)? {
        let cpu = cpu?;
        let name = cpu.file_name();
        let name = name.to_string_lossy();
        if name.strip_prefix("cpu").is_none_or(|suffix| {
            suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            continue;
        }
        let throttle_root = cpu.path().join("thermal_throttle");
        for counter in fs::read_dir(&throttle_root)? {
            let counter = counter?;
            let counter_name = counter.file_name();
            let counter_name = counter_name.to_string_lossy();
            if !matches!(
                counter_name.as_ref(),
                "core_throttle_count" | "package_throttle_count"
            ) {
                continue;
            }
            let path = counter.path();
            let relative = path.strip_prefix(root)?.to_string_lossy().into_owned();
            let value = fs::read_to_string(path)?.trim().parse::<u64>()?;
            counters.insert(relative, value);
        }
    }
    if counters.is_empty() {
        return Err("CPU thermal throttle counters are unavailable".into());
    }
    Ok(CpuThrottleSnapshot { counters })
}

fn throttling_since(
    starting: &CpuThrottleSnapshot,
    current: &CpuThrottleSnapshot,
) -> Result<bool, Box<dyn Error>> {
    if starting.counters.keys().ne(current.counters.keys()) {
        return Err("CPU thermal throttle counter topology changed".into());
    }
    starting
        .counters
        .iter()
        .try_fold(false, |observed, (path, starting)| {
            let current = current
                .counters
                .get(path)
                .ok_or("CPU thermal throttle counter disappeared")?;
            if current < starting {
                return Err("CPU thermal throttle counter moved backwards");
            }
            Ok(observed || current > starting)
        })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_utilization_uses_monotonic_busy_time() {
        let previous = parse_cpu_time("cpu  100 5 50 800 20 10 5 10 0 0\n").unwrap();
        let current = parse_cpu_time("cpu  150 5 70 860 20 10 5 10 0 0\n").unwrap();

        assert_eq!(utilization_between(previous, current).unwrap(), 5_385);
    }

    #[test]
    fn cpu_utilization_rejects_stale_or_regressing_counters() {
        let sample = CpuTimeSnapshot {
            idle: 80,
            total: 100,
        };
        assert!(utilization_between(sample, sample).is_err());
        assert!(
            utilization_between(
                sample,
                CpuTimeSnapshot {
                    idle: 70,
                    total: 110
                }
            )
            .is_err()
        );
    }

    #[test]
    fn thermal_throttling_requires_the_same_monotonic_counter_set() {
        let starting = CpuThrottleSnapshot {
            counters: BTreeMap::from([("cpu0/core_throttle_count".into(), 10)]),
        };
        assert!(!throttling_since(&starting, &starting).unwrap());
        assert!(
            throttling_since(
                &starting,
                &CpuThrottleSnapshot {
                    counters: BTreeMap::from([("cpu0/core_throttle_count".into(), 11)]),
                },
            )
            .unwrap()
        );
        assert!(
            throttling_since(
                &starting,
                &CpuThrottleSnapshot {
                    counters: BTreeMap::from([("cpu1/core_throttle_count".into(), 10)]),
                },
            )
            .is_err()
        );
    }
}
