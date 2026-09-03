use std::{fmt, path::Path};

use crate::{
    AcerHwmonDevice, CPU_ABSOLUTE_ABORT_MILLICELSIUS, CompatibilityDeclarationV1,
    CompatibilityObservation, EvidenceFan, EvidenceRecord, EvidenceTimestamp,
    EvidenceValidationError, FanReadbackEvidence, FanReadbackField, FanReadbackPhase,
    FaultEvidence, GPU_ABSOLUTE_ABORT_MILLICELSIUS, IdentityBoundReadAccess, NvidiaGpuSampleError,
    NvidiaGpuSelector, NvmlAccess, NvmlErrorKind, ObservationOutcome, PlatformError,
    PlatformErrorKind, PreflightCheckEvidence, QualificationEnvelopeIdentityV1, RunOutcomeEvidence,
    RunOutcomeStatus, ServiceAccess,
    authority::validate_policy_authority_sources,
    compatibility::{
        check_fan_abi_compatibility, check_platform_compatibility, check_trust_compatibility,
    },
    discover_acer_hwmon, discover_coretemp,
    ownership::COMPETING_FAN_CONTROL_SERVICES,
    parse_config_v1, sample_nvidia_gpu, validate_config_v1,
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
    Recovery,
    StockBootFallback,
    Tooling,
    DiskSpace,
    CompetingServices,
    FirmwareAuto,
    EvidenceCollection,
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
            Self::Recovery => "recovery",
            Self::StockBootFallback => "stock-boot-fallback",
            Self::Tooling => "tooling",
            Self::DiskSpace => "disk-space",
            Self::CompetingServices => "competing-services",
            Self::FirmwareAuto => "firmware-auto",
            Self::EvidenceCollection => "evidence-collection",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightCheckResult {
    check: PreflightCheck,
    passed: bool,
    detail: String,
    timestamp: EvidenceTimestamp,
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

    pub const fn timestamp(&self) -> EvidenceTimestamp {
        self.timestamp
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    checks: Vec<PreflightCheckResult>,
    firmware_auto_readbacks: Vec<FanReadbackEvidence>,
}

impl PreflightReport {
    pub fn collection_failure(timestamp: EvidenceTimestamp, detail: impl Into<String>) -> Self {
        Self {
            checks: vec![PreflightCheckResult {
                check: PreflightCheck::EvidenceCollection,
                passed: false,
                detail: detail.into(),
                timestamp,
            }],
            firmware_auto_readbacks: Vec::new(),
        }
    }

    pub fn checks(&self) -> &[PreflightCheckResult] {
        &self.checks
    }

    pub fn result(&self, check: PreflightCheck) -> Option<&PreflightCheckResult> {
        self.checks.iter().find(|result| result.check == check)
    }

    pub fn passed(&self) -> bool {
        self.checks.iter().all(|result| result.passed)
    }

    /// Converts the complete report into immutable stage evidence without adding any write
    /// capability to the preflight itself.
    pub fn into_evidence(
        self,
        qualification_envelope: QualificationEnvelopeIdentityV1,
        started_at: EvidenceTimestamp,
        completed_at: EvidenceTimestamp,
    ) -> Result<EvidenceRecord, EvidenceValidationError> {
        let passed = self.passed();
        let final_firmware_auto_confirmed =
            [EvidenceFan::Cpu, EvidenceFan::Gpu].into_iter().all(|fan| {
                self.firmware_auto_readbacks.iter().any(|readback| {
                    readback.fan == fan
                        && readback.field == FanReadbackField::Enable
                        && readback.phase == Some(FanReadbackPhase::Final)
                        && readback.value == Some(2)
                        && readback.outcome == ObservationOutcome::Confirmed
                })
            });
        let faults = self
            .checks
            .iter()
            .filter(|result| !result.passed)
            .map(|result| FaultEvidence {
                timestamp: result.timestamp,
                boot_id: None,
                code: format!("preflight-{}", result.check),
                detail: result.detail.clone(),
            })
            .collect::<Vec<_>>();
        let reason = if passed {
            "read-only preflight passed".to_owned()
        } else {
            self.checks
                .iter()
                .find(|result| !result.passed)
                .map(|result| result.detail.clone())
                .unwrap_or_else(|| "read-only preflight failed".to_owned())
        };
        let mut record = EvidenceRecord::complete_v2(
            qualification_envelope,
            "preflight",
            started_at,
            completed_at,
            RunOutcomeEvidence {
                status: if passed {
                    RunOutcomeStatus::Passed
                } else {
                    RunOutcomeStatus::Failed
                },
                reason,
                another_passing_run_required: !passed,
                final_firmware_auto_confirmed,
            },
        );
        record.readbacks = self.firmware_auto_readbacks;
        record.faults = faults;
        record.preflight_checks = Some(
            self.checks
                .into_iter()
                .map(|result| PreflightCheckEvidence {
                    timestamp: result.timestamp,
                    check: result.check.to_string(),
                    passed: result.passed,
                    detail: result.detail,
                })
                .collect(),
        );
        record.validate()?;
        Ok(record)
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
    fn timestamp_now(&mut self) -> EvidenceTimestamp;

    fn signing_trust_is_ready(&mut self) -> Result<bool, PlatformError>;

    fn recovery_is_ready(&mut self) -> Result<bool, PlatformError>;

    fn stock_boot_fallback_is_ready(&mut self) -> Result<bool, PlatformError>;

    fn qualification_workload_is_absent(&mut self) -> Result<bool, PlatformError>;

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
    let mut checks = Vec::with_capacity(12);
    macro_rules! record_check {
        ($check:expr, $result:expr) => {{
            let result = $result;
            let timestamp = environment.timestamp_now();
            checks.push(check_result($check, result, timestamp));
        }};
    }
    record_check!(
        PreflightCheck::Platform,
        check_platform_compatibility(inputs.compatibility, inputs.observations)
            .map(|()| "exact hardware, BIOS, kernel, and module identities match".to_owned())
            .map_err(|error| error.to_string())
    );
    record_check!(PreflightCheck::Trust, check_trust(environment, inputs));

    let fan_abi = combine_checks([
        check_fan_abi_compatibility(inputs.compatibility, inputs.observations)
            .map_err(|error| error.to_string()),
        discover_acer_hwmon(platform, requirements.hwmon_root)
            .map_err(|error| error.to_string())
            .and_then(|device| check_fan_endpoint_sandbox_boundary(platform, &device)),
    ]);
    record_check!(
        PreflightCheck::FanAbi,
        fan_abi.map(|()| "one exact two-fan Acer hwmon ABI is present".to_owned())
    );

    record_check!(
        PreflightCheck::Sensors,
        check_sensors(platform, nvml, inputs, requirements)
    );
    record_check!(
        PreflightCheck::Configuration,
        parse_config_v1(inputs.config_source)
            .map_err(|error| error.to_string())
            .and_then(|config| validate_config_v1(config).map_err(|error| error.to_string()))
            .map(|_| "configuration is complete and valid".to_owned())
    );
    record_check!(
        PreflightCheck::Policy,
        validate_policy_authority_sources(
            inputs.protected_policy_source,
            inputs.qualification_record_source,
            inputs.observations,
        )
        .map(|()| "protected policy and qualification record agree".to_owned())
        .map_err(|error| error.to_string())
    );
    record_check!(
        PreflightCheck::Recovery,
        readiness_check(
            environment.recovery_is_ready(),
            "independent Firmware Auto recovery is ready",
            "independent Firmware Auto recovery is not ready",
        )
    );
    record_check!(
        PreflightCheck::StockBootFallback,
        readiness_check(
            environment.stock_boot_fallback_is_ready(),
            "stock and stock-LTS boot fallbacks are present, bootable, and remain default",
            "stock boot fallback is missing, unbootable, or no longer default",
        )
    );
    record_check!(PreflightCheck::Tooling, check_tooling(environment));
    record_check!(
        PreflightCheck::DiskSpace,
        check_disk_space(environment, requirements)
    );
    record_check!(
        PreflightCheck::CompetingServices,
        check_competing_services(platform, environment)
    );
    let firmware_auto = check_firmware_auto(platform, environment, requirements.hwmon_root);
    let firmware_auto_result = firmware_auto.result;
    record_check!(PreflightCheck::FirmwareAuto, firmware_auto_result);

    PreflightReport {
        checks,
        firmware_auto_readbacks: firmware_auto.readbacks,
    }
}

fn check_trust(
    environment: &mut dyn PreflightEnvironment,
    inputs: &PreflightInputs<'_>,
) -> Result<String, String> {
    check_trust_compatibility(inputs.compatibility, inputs.observations)
        .map_err(|error| error.to_string())?;
    readiness_check(
        environment.signing_trust_is_ready(),
        "Secure Boot, kernel image, module, package set, and signer identities are trusted",
        "candidate signing trust is incomplete",
    )
}

fn readiness_check(
    result: Result<bool, PlatformError>,
    ready: &str,
    not_ready: &str,
) -> Result<String, String> {
    match result {
        Ok(true) => Ok(ready.to_owned()),
        Ok(false) => Err(not_ready.to_owned()),
        Err(error) => Err(format!("cannot verify readiness: {error}")),
    }
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
        .map_err(|error| format!("CPU sensor: {error}"))
        .and_then(|temperature| {
            if temperature * 1_000.0 >= f64::from(CPU_ABSOLUTE_ABORT_MILLICELSIUS) {
                Err(format!(
                    "CPU sensor: {temperature} °C reaches the {} °C absolute abort limit",
                    CPU_ABSOLUTE_ABORT_MILLICELSIUS / 1_000
                ))
            } else {
                Ok(temperature)
            }
        });
    let gpu = sample_nvidia_gpu(nvml, inputs.nvidia_selector)
        .map(|sample| sample.value())
        .map_err(nvidia_failure)
        .and_then(|temperature| {
            if temperature * 1_000.0 >= f64::from(GPU_ABSOLUTE_ABORT_MILLICELSIUS) {
                Err(format!(
                    "NVIDIA GPU sensor: {temperature} °C reaches the {} °C absolute abort limit",
                    GPU_ABSOLUTE_ABORT_MILLICELSIUS / 1_000
                ))
            } else {
                Ok(temperature)
            }
        });

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

struct FirmwareAutoCheck {
    result: Result<String, String>,
    readbacks: Vec<FanReadbackEvidence>,
}

fn check_firmware_auto<P>(
    platform: &mut P,
    environment: &mut dyn PreflightEnvironment,
    hwmon_root: &Path,
) -> FirmwareAutoCheck
where
    P: IdentityBoundReadAccess,
{
    let before = match discover_acer_hwmon(platform, hwmon_root) {
        Ok(device) => device,
        Err(error) => {
            return FirmwareAutoCheck {
                result: Err(error.to_string()),
                readbacks: Vec::new(),
            };
        }
    };
    if let Err(error) = check_fan_endpoint_sandbox_boundary(platform, &before) {
        return FirmwareAutoCheck {
            result: Err(error),
            readbacks: Vec::new(),
        };
    }
    let mut readbacks = Vec::with_capacity(2);
    let mut values = Vec::with_capacity(2);
    let mut errors = Vec::new();
    for (fan, fan_name, child, endpoint) in [
        (
            EvidenceFan::Cpu,
            "CPU",
            "pwm1_enable",
            before.cpu().enable(),
        ),
        (
            EvidenceFan::Gpu,
            "GPU",
            "pwm2_enable",
            before.gpu().enable(),
        ),
    ] {
        let identity = before
            .endpoint_identity(endpoint)
            .expect("discovery binds every endpoint");
        let endpoint_identity = format!("device-{}-inode-{}", identity.device(), identity.inode());
        let result =
            platform.read_child_bound(before.root(), before.backing_identity(), child, identity);
        let timestamp = environment.timestamp_now();
        match result {
            Ok(payload) => match payload.trim().parse::<u32>() {
                Ok(value @ 0..=2) => {
                    values.push(Some(value));
                    readbacks.push(FanReadbackEvidence {
                        timestamp,
                        source_timestamp: None,
                        fresh: None,
                        boot_id: None,
                        fan,
                        field: FanReadbackField::Enable,
                        value: Some(value),
                        endpoint_identity,
                        outcome: if value == 2 {
                            ObservationOutcome::Confirmed
                        } else {
                            ObservationOutcome::Unexpected
                        },
                        phase: Some(FanReadbackPhase::Final),
                    });
                }
                _ => {
                    let payload = payload.trim();
                    let preview = payload.chars().take(64).collect::<String>();
                    errors.push(format!(
                        "{fan_name} {} contained invalid mode {preview:?}",
                        endpoint.display()
                    ));
                    values.push(None);
                    readbacks.push(FanReadbackEvidence {
                        timestamp,
                        source_timestamp: None,
                        fresh: None,
                        boot_id: None,
                        fan,
                        field: FanReadbackField::Enable,
                        value: None,
                        endpoint_identity,
                        outcome: ObservationOutcome::Unreadable,
                        phase: Some(FanReadbackPhase::Final),
                    });
                }
            },
            Err(error) => {
                errors.push(format!(
                    "{fan_name} {} could not be read: {error}",
                    endpoint.display()
                ));
                values.push(None);
                readbacks.push(FanReadbackEvidence {
                    timestamp,
                    source_timestamp: None,
                    fresh: None,
                    boot_id: None,
                    fan,
                    field: FanReadbackField::Enable,
                    value: None,
                    endpoint_identity,
                    outcome: ObservationOutcome::Unreadable,
                    phase: Some(FanReadbackPhase::Final),
                });
            }
        }
    }
    let after = match discover_acer_hwmon(platform, hwmon_root) {
        Ok(device) => device,
        Err(error) => {
            for readback in &mut readbacks {
                readback.value = None;
                readback.outcome = ObservationOutcome::Unreadable;
            }
            return FirmwareAutoCheck {
                result: Err(error.to_string()),
                readbacks,
            };
        }
    };
    if after != before {
        for readback in &mut readbacks {
            readback.value = None;
            readback.outcome = ObservationOutcome::Unreadable;
        }
        return FirmwareAutoCheck {
            result: Err("Acer hwmon identity changed while reading fan modes".to_owned()),
            readbacks,
        };
    }
    if let Err(error) = check_fan_endpoint_sandbox_boundary(platform, &after) {
        for readback in &mut readbacks {
            readback.value = None;
            readback.outcome = ObservationOutcome::Unreadable;
        }
        return FirmwareAutoCheck {
            result: Err(error),
            readbacks,
        };
    }
    if values.iter().any(|value| *value != Some(2)) {
        let error_detail = if errors.is_empty() {
            String::new()
        } else {
            format!("; errors: {}", errors.join("; "))
        };
        return FirmwareAutoCheck {
            result: Err(format!(
                "both fans must already be Firmware Auto (2); observed CPU={} GPU={}{}",
                values
                    .first()
                    .copied()
                    .flatten()
                    .map_or("unreadable".into(), |value| value.to_string()),
                values
                    .get(1)
                    .copied()
                    .flatten()
                    .map_or("unreadable".into(), |value| value.to_string()),
                error_detail
            )),
            readbacks,
        };
    }
    FirmwareAutoCheck {
        result: Ok("both fans are already in Firmware Auto".to_owned()),
        readbacks,
    }
}

fn check_fan_endpoint_sandbox_boundary(
    platform: &mut impl IdentityBoundReadAccess,
    device: &AcerHwmonDevice,
) -> Result<(), String> {
    for (child, endpoint) in [
        ("pwm1", device.cpu().pwm()),
        ("pwm1_enable", device.cpu().enable()),
        ("pwm2", device.gpu().pwm()),
        ("pwm2_enable", device.gpu().enable()),
    ] {
        let identity = device
            .endpoint_identity(endpoint)
            .expect("discovery binds every endpoint");
        let permissions = platform
            .permissions_child_bound(device.root(), device.backing_identity(), child, identity)
            .map_err(|error| error.to_string())?;
        if permissions.owner_uid() != 0
            || permissions.mode() & 0o022 != 0
            || permissions.has_extended_acl()
        {
            return Err(format!(
                "fan mode endpoint is not root-owned, has group/world write bits, or has an extended ACL: {}",
                endpoint.display()
            ));
        }
    }
    Ok(())
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
    environment: &mut dyn PreflightEnvironment,
) -> Result<String, String> {
    let mut failures = Vec::new();
    for service in COMPETING_FAN_CONTROL_SERVICES
        .into_iter()
        .chain(["pt31553-fand.service", "pt31553-fan-sleep-guard.service"])
    {
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
    match environment.qualification_workload_is_absent() {
        Ok(true) => {}
        Ok(false) => failures.push("a qualification workload is still active".to_owned()),
        Err(error) => failures.push(format!(
            "cannot verify that qualification workloads are absent: {error}"
        )),
    }
    if failures.is_empty() {
        Ok("no fan-control service or qualification workload is active".to_owned())
    } else {
        Err(failures.join("; "))
    }
}

fn check_result(
    check: PreflightCheck,
    result: Result<String, String>,
    timestamp: EvidenceTimestamp,
) -> PreflightCheckResult {
    match result {
        Ok(detail) => PreflightCheckResult {
            check,
            passed: true,
            detail,
            timestamp,
        },
        Err(detail) => PreflightCheckResult {
            check,
            passed: false,
            detail,
            timestamp,
        },
    }
}
