use std::{fmt, path::Path};

use crate::{
    CompatibilityDeclarationV1, CompatibilityObservation, IdentityBoundReadAccess,
    NvidiaGpuSampleError, NvidiaGpuSelector, NvmlAccess, NvmlErrorKind, PlatformError,
    PlatformErrorKind, ServiceAccess,
    authority::validate_policy_authority_sources,
    compatibility::{
        check_fan_abi_compatibility, check_platform_compatibility, check_trust_compatibility,
    },
    discover_acer_hwmon, discover_coretemp,
    ownership::COMPETING_FAN_CONTROL_SERVICES,
    parse_config_v1,
    restoration::FIRMWARE_AUTO,
    sample_nvidia_gpu, validate_config_v1,
};

/// The complete, stable ordering of prerequisites checked before qualification can start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PreflightCheck {
    Platform,
    Trust,
    FanAbi,
    Sensors,
    Configuration,
    Policy,
    Tooling,
    DiskSpace,
    CompetingServices,
    FirmwareAuto,
}

impl fmt::Display for PreflightCheck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Platform => "platform",
            Self::Trust => "trust",
            Self::FanAbi => "fan-abi",
            Self::Sensors => "sensors",
            Self::Configuration => "configuration",
            Self::Policy => "policy",
            Self::Tooling => "tooling",
            Self::DiskSpace => "disk-space",
            Self::CompetingServices => "competing-services",
            Self::FirmwareAuto => "firmware-auto",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightCheckResult {
    check: PreflightCheck,
    passed: bool,
    detail: String,
}

impl PreflightCheckResult {
    pub const fn check(&self) -> PreflightCheck {
        self.check
    }

    pub const fn passed(&self) -> bool {
        self.passed
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    checks: Vec<PreflightCheckResult>,
}

impl PreflightReport {
    pub fn checks(&self) -> &[PreflightCheckResult] {
        &self.checks
    }

    pub fn result(&self, check: PreflightCheck) -> Option<&PreflightCheckResult> {
        self.checks.iter().find(|result| result.check == check)
    }

    pub fn passed(&self) -> bool {
        self.checks.iter().all(|result| result.passed)
    }
}

impl fmt::Display for PreflightReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, result) in self.checks.iter().enumerate() {
            if index > 0 {
                formatter.write_str("\n")?;
            }
            write!(
                formatter,
                "{} {}: {}",
                if result.passed { "PASS" } else { "FAIL" },
                result.check,
                result.detail
            )?;
        }
        Ok(())
    }
}

/// Installed artifacts which must be usable before any qualification stage is run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PreflightArtifact {
    QualificationTool,
    RestorationTool,
    Daemon,
    DaemonServiceUnit,
    SleepGuardServiceUnit,
    Journald,
}

impl PreflightArtifact {
    pub const ALL: [Self; 6] = [
        Self::QualificationTool,
        Self::RestorationTool,
        Self::Daemon,
        Self::DaemonServiceUnit,
        Self::SleepGuardServiceUnit,
        Self::Journald,
    ];

    pub const fn path(self) -> &'static str {
        match self {
            Self::QualificationTool => "/usr/bin/pt31553-fan-qualify",
            Self::RestorationTool => "/usr/bin/pt31553-fan-restore",
            Self::Daemon => "/usr/bin/pt31553-fand",
            Self::DaemonServiceUnit => "/usr/lib/systemd/system/pt31553-fand.service",
            Self::SleepGuardServiceUnit => {
                "/usr/lib/systemd/system/pt31553-fan-sleep-guard.service"
            }
            Self::Journald => "/run/systemd/journal/socket",
        }
    }
}

/// Read-only host checks which are not represented by sysfs or service status.
pub trait PreflightEnvironment {
    fn artifact_is_ready(&mut self, artifact: PreflightArtifact) -> Result<bool, PlatformError>;

    fn available_bytes(&mut self, path: &Path) -> Result<u64, PlatformError>;
}

pub struct PreflightInputs<'a> {
    pub compatibility: &'a CompatibilityDeclarationV1,
    pub observations: &'a [CompatibilityObservation],
    pub config_source: &'a str,
    pub protected_policy_source: &'a str,
    pub qualification_record_source: &'a str,
    pub nvidia_selector: &'a NvidiaGpuSelector,
}

pub struct PreflightRequirements<'a> {
    pub hwmon_root: &'a Path,
    pub evidence_root: &'a Path,
    pub minimum_available_bytes: u64,
}

/// Runs every qualification prerequisite using a platform capability that has no write or lock
/// methods. A failure never suppresses later checks, so the report is a complete repair list.
pub fn run_read_only_preflight<P>(
    platform: &mut P,
    nvml: &mut dyn NvmlAccess,
    environment: &mut dyn PreflightEnvironment,
    inputs: &PreflightInputs<'_>,
    requirements: &PreflightRequirements<'_>,
) -> PreflightReport
where
    P: IdentityBoundReadAccess + ServiceAccess,
{
    let mut checks = Vec::with_capacity(10);
    checks.push(check_result(
        PreflightCheck::Platform,
        check_platform_compatibility(inputs.compatibility, inputs.observations)
            .map(|()| "exact hardware, BIOS, kernel, and module identities match".to_owned())
            .map_err(|error| error.to_string()),
    ));
    checks.push(check_result(
        PreflightCheck::Trust,
        check_trust_compatibility(inputs.compatibility, inputs.observations)
            .map(|()| "Secure Boot, kernel image, and module signature are trusted".to_owned())
            .map_err(|error| error.to_string()),
    ));

    let fan_abi = combine_checks([
        check_fan_abi_compatibility(inputs.compatibility, inputs.observations)
            .map_err(|error| error.to_string()),
        discover_acer_hwmon(platform, requirements.hwmon_root)
            .map(|_| ())
            .map_err(|error| error.to_string()),
    ]);
    checks.push(check_result(
        PreflightCheck::FanAbi,
        fan_abi.map(|()| "one exact two-fan Acer hwmon ABI is present".to_owned()),
    ));

    checks.push(check_result(
        PreflightCheck::Sensors,
        check_sensors(platform, nvml, inputs, requirements),
    ));
    checks.push(check_result(
        PreflightCheck::Configuration,
        parse_config_v1(inputs.config_source)
            .map_err(|error| error.to_string())
            .and_then(|config| validate_config_v1(config).map_err(|error| error.to_string()))
            .map(|_| "configuration is complete and valid".to_owned()),
    ));
    checks.push(check_result(
        PreflightCheck::Policy,
        validate_policy_authority_sources(
            inputs.protected_policy_source,
            inputs.qualification_record_source,
            inputs.observations,
        )
        .map(|()| "protected policy and qualification record agree".to_owned())
        .map_err(|error| error.to_string()),
    ));
    checks.push(check_result(
        PreflightCheck::Tooling,
        check_tooling(environment),
    ));
    checks.push(check_result(
        PreflightCheck::DiskSpace,
        check_disk_space(environment, requirements),
    ));
    checks.push(check_result(
        PreflightCheck::CompetingServices,
        check_competing_services(platform),
    ));
    checks.push(check_result(
        PreflightCheck::FirmwareAuto,
        check_firmware_auto(platform, requirements.hwmon_root),
    ));

    PreflightReport { checks }
}

fn check_sensors<P>(
    platform: &mut P,
    nvml: &mut dyn NvmlAccess,
    inputs: &PreflightInputs<'_>,
    requirements: &PreflightRequirements<'_>,
) -> Result<String, String>
where
    P: IdentityBoundReadAccess,
{
    let cpu = discover_coretemp(platform, requirements.hwmon_root)
        .and_then(|device| device.sample(platform))
        .map(|sample| sample.value())
        .map_err(|error| format!("CPU sensor: {error}"));
    let gpu = sample_nvidia_gpu(nvml, inputs.nvidia_selector)
        .map(|sample| sample.value())
        .map_err(nvidia_failure);

    match (cpu, gpu) {
        (Ok(cpu), Ok(gpu)) => Ok(format!(
            "fresh plausible CPU ({cpu} °C) and NVIDIA GPU ({gpu} °C) samples are healthy"
        )),
        (Err(cpu), Ok(_)) => Err(cpu),
        (Ok(_), Err(gpu)) => Err(gpu),
        (Err(cpu), Err(gpu)) => Err(format!("{cpu}; {gpu}")),
    }
}

fn nvidia_failure(error: NvidiaGpuSampleError) -> String {
    match &error {
        NvidiaGpuSampleError::Nvml(source) if source.kind() == NvmlErrorKind::ResetRequired => {
            format!("NVIDIA reset-required condition blocks qualification: {source}")
        }
        _ => format!("NVIDIA GPU sensor: {error}"),
    }
}

fn check_tooling(environment: &mut dyn PreflightEnvironment) -> Result<String, String> {
    let mut failures = Vec::new();
    for artifact in PreflightArtifact::ALL {
        match environment.artifact_is_ready(artifact) {
            Ok(true) => {}
            Ok(false) => failures.push(format!("missing {}", artifact.path())),
            Err(error) => failures.push(format!("cannot inspect {}: {error}", artifact.path())),
        }
    }
    if failures.is_empty() {
        Ok(
            "qualifier, restoration command, daemon, service units, and journald are ready"
                .to_owned(),
        )
    } else {
        Err(failures.join("; "))
    }
}

fn check_disk_space(
    environment: &mut dyn PreflightEnvironment,
    requirements: &PreflightRequirements<'_>,
) -> Result<String, String> {
    let available = environment
        .available_bytes(requirements.evidence_root)
        .map_err(|error| format!("cannot inspect available disk space: {error}"))?;
    if available < requirements.minimum_available_bytes {
        return Err(format!(
            "only {available} bytes available at {}; need at least {}",
            requirements.evidence_root.display(),
            requirements.minimum_available_bytes
        ));
    }
    Ok(format!(
        "{available} bytes available at {} (minimum {})",
        requirements.evidence_root.display(),
        requirements.minimum_available_bytes
    ))
}

fn check_firmware_auto<P>(platform: &mut P, hwmon_root: &Path) -> Result<String, String>
where
    P: IdentityBoundReadAccess,
{
    let before = discover_acer_hwmon(platform, hwmon_root).map_err(|error| error.to_string())?;
    let cpu = platform
        .read_bound(before.root(), before.backing_identity(), "pwm1_enable")
        .map_err(|error| format!("cannot read CPU fan mode: {error}"))?;
    let gpu = platform
        .read_bound(before.root(), before.backing_identity(), "pwm2_enable")
        .map_err(|error| format!("cannot read GPU fan mode: {error}"))?;
    let after = discover_acer_hwmon(platform, hwmon_root).map_err(|error| error.to_string())?;
    if after != before {
        return Err("Acer hwmon identity changed while reading fan modes".to_owned());
    }
    if cpu.trim() != FIRMWARE_AUTO || gpu.trim() != FIRMWARE_AUTO {
        return Err(format!(
            "both fans must already be Firmware Auto (2); observed CPU={} GPU={}",
            cpu.trim(),
            gpu.trim()
        ));
    }
    Ok("both fans are already in Firmware Auto".to_owned())
}

fn combine_checks<const N: usize>(checks: [Result<(), String>; N]) -> Result<(), String> {
    let failures = checks
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn check_competing_services(
    services: &mut (impl ServiceAccess + ?Sized),
) -> Result<String, String> {
    let mut failures = Vec::new();
    for service in COMPETING_FAN_CONTROL_SERVICES {
        match services.is_service_active(service) {
            Ok(false) => {}
            Ok(true) => failures.push(format!(
                "competing fan-control service is active: {service}"
            )),
            Err(error) if error.kind() == PlatformErrorKind::NotFound => {}
            Err(error) => failures.push(format!(
                "cannot inspect competing service {service}: {error}"
            )),
        }
    }
    if failures.is_empty() {
        Ok("no competing fan-control service is active".to_owned())
    } else {
        Err(failures.join("; "))
    }
}

fn check_result(check: PreflightCheck, result: Result<String, String>) -> PreflightCheckResult {
    match result {
        Ok(detail) => PreflightCheckResult {
            check,
            passed: true,
            detail,
        },
        Err(detail) => PreflightCheckResult {
            check,
            passed: false,
            detail,
        },
    }
}
