mod support;

use std::{collections::BTreeMap, path::Path};

use fan_control_core::{
    FakePlatform, FileIdentity, FilePermissions, IdentityBoundReadAccess, NvidiaGpuSelector,
    NvmlAccess, NvmlError, NvmlErrorKind, NvmlGpuSample, PlatformError, PlatformErrorKind,
    PlatformOperation, PreflightArtifact, PreflightCheck, PreflightEnvironment, PreflightInputs,
    PreflightReport, PreflightRequirements, ServiceAccess, run_read_only_preflight,
};
use support::{
    PROTECTED_POLICY, compatibility_declaration, matching_observation_for_policy, matching_record,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const EVIDENCE_ROOT: &str = "/var/lib/pt31553-fan-control/evidence";
const EXPECTED_UUID: &str = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const VALID_CONFIG: &str = r#"
schema_version = 1

[control]
hysteresis_celsius = 3
lower_demand_hold_seconds = 10
max_down_ramp_percent_per_second = 1.0

[fans.cpu]
minimum_duty_percent = 30

[fans.gpu]
minimum_duty_percent = 25

[profiles.ac]
cpu_curve = [{ temperature_c = 40, demand_percent = 30 }, { temperature_c = 90, demand_percent = 100 }]
gpu_curve = [{ temperature_c = 35, demand_percent = 25 }, { temperature_c = 82, demand_percent = 100 }]

[profiles.battery]
cpu_curve = [{ temperature_c = 40, demand_percent = 30 }, { temperature_c = 90, demand_percent = 100 }]
gpu_curve = [{ temperature_c = 35, demand_percent = 25 }, { temperature_c = 82, demand_percent = 100 }]
"#;

#[derive(Clone)]
struct StubNvml(Result<NvmlGpuSample, NvmlError>);

impl NvmlAccess for StubNvml {
    fn sample_by_identity(
        &mut self,
        _selector: &NvidiaGpuSelector,
    ) -> Result<NvmlGpuSample, NvmlError> {
        self.0.clone()
    }
}

struct StubEnvironment {
    artifacts: BTreeMap<PreflightArtifact, bool>,
    available_bytes: Result<u64, PlatformError>,
    requested_artifacts: Vec<PreflightArtifact>,
}

impl StubEnvironment {
    fn ready() -> Self {
        Self {
            artifacts: PreflightArtifact::ALL
                .into_iter()
                .map(|artifact| (artifact, true))
                .collect(),
            available_bytes: Ok(2_000_000),
            requested_artifacts: Vec::new(),
        }
    }
}

impl PreflightEnvironment for StubEnvironment {
    fn artifact_is_ready(&mut self, artifact: PreflightArtifact) -> Result<bool, PlatformError> {
        self.requested_artifacts.push(artifact);
        Ok(self.artifacts.get(&artifact).copied().unwrap_or(false))
    }

    fn available_bytes(&mut self, _path: &Path) -> Result<u64, PlatformError> {
        self.available_bytes.clone()
    }
}

#[test]
fn reports_every_required_check_and_passes_without_any_write_or_lock() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();

    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    );

    assert!(report.passed());
    assert_eq!(
        report
            .checks()
            .iter()
            .map(|result| result.check())
            .collect::<Vec<_>>(),
        vec![
            PreflightCheck::Platform,
            PreflightCheck::Trust,
            PreflightCheck::FanAbi,
            PreflightCheck::Sensors,
            PreflightCheck::Configuration,
            PreflightCheck::Policy,
            PreflightCheck::Tooling,
            PreflightCheck::DiskSpace,
            PreflightCheck::CompetingServices,
            PreflightCheck::FirmwareAuto,
        ]
    );
    assert!(report.checks().iter().all(|result| result.passed()));
    let plain = report.to_string();
    assert!(plain.lines().all(|line| line.starts_with("PASS ")));
    assert!(plain.contains("PASS firmware-auto: both fans are already in Firmware Auto"));
    assert_eq!(
        environment.requested_artifacts,
        vec![
            PreflightArtifact::QualificationTool,
            PreflightArtifact::RestorationTool,
            PreflightArtifact::Daemon,
            PreflightArtifact::DaemonServiceUnit,
            PreflightArtifact::SleepGuardServiceUnit,
            PreflightArtifact::Journald,
        ]
    );
    assert!(platform.operations().iter().all(|operation| !matches!(
        operation,
        PlatformOperation::Write { .. }
            | PlatformOperation::AcquireRuntimeLock(_)
            | PlatformOperation::ReleaseRuntimeLock(_)
    )));
}

#[test]
fn nvidia_reset_required_is_a_clear_blocking_sensor_failure() {
    let (mut platform, _, mut environment) = passing_fixture();
    let mut nvml = StubNvml(Err(NvmlError::new(
        NvmlErrorKind::ResetRequired,
        "GPU requires reset",
    )));
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let inputs = PreflightInputs {
        compatibility: &declaration,
        observations: &observations,
        config_source: VALID_CONFIG,
        protected_policy_source: PROTECTED_POLICY,
        qualification_record_source: &record,
        nvidia_selector: &selector,
    };
    let requirements = PreflightRequirements {
        hwmon_root: Path::new(HWMON_ROOT),
        evidence_root: Path::new(EVIDENCE_ROOT),
        minimum_available_bytes: 1_000_000,
    };

    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &inputs,
        &requirements,
    );

    assert!(!report.passed());
    let sensor = report.result(PreflightCheck::Sensors).unwrap();
    assert!(!sensor.passed());
    assert!(sensor.detail().contains("NVIDIA reset-required"));
    assert!(sensor.detail().contains("blocks qualification"));
}

#[test]
fn missing_cpu_sensor_is_a_blocking_sensor_failure() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    platform.remove_path(Path::new(HWMON_ROOT).join("hwmon1"));
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    );

    let sensor = report.result(PreflightCheck::Sensors).unwrap();
    assert!(!sensor.passed());
    assert!(sensor.detail().contains("CPU sensor"));
    assert!(sensor.detail().contains("no coretemp hwmon device found"));
}

#[test]
fn incompatible_platform_trust_abi_and_policy_each_fail_their_reported_check() {
    for check in [
        PreflightCheck::Platform,
        PreflightCheck::Trust,
        PreflightCheck::FanAbi,
        PreflightCheck::Policy,
    ] {
        let (mut platform, mut nvml, mut environment) = passing_fixture();
        let declaration = compatibility_declaration(PROTECTED_POLICY);
        let mut observation = matching_observation_for_policy(PROTECTED_POLICY);
        let mut record = matching_record(PROTECTED_POLICY);
        match check {
            PreflightCheck::Platform => observation.hardware.bios_version = "V1.18".to_owned(),
            PreflightCheck::Trust => observation.module_signature_trusted = false,
            PreflightCheck::FanAbi => {
                observation.fan_abi.endpoints.pop();
            }
            PreflightCheck::Policy => {
                record = record.replacen(
                    "\"policy_version\":\"1.0.0\"",
                    "\"policy_version\":\"2.0.0\"",
                    1,
                );
            }
            _ => unreachable!(),
        }
        let observations = [observation];

        let report = run_fixture_report(
            &mut platform,
            &mut nvml,
            &mut environment,
            &declaration,
            &observations,
            &record,
        );

        assert!(!report.result(check).unwrap().passed(), "{check:?}");
        assert_eq!(report.checks().len(), 10);
        assert!(report.result(PreflightCheck::FirmwareAuto).is_some());
    }
}

#[test]
fn failures_are_all_reported_instead_of_short_circuiting() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    platform.insert_file(Path::new(HWMON_ROOT).join("hwmon0/pwm2_enable"), "1\n");
    platform.insert_service("fancontrol.service", true);
    platform.insert_service("nbfc.service", true);
    environment
        .artifacts
        .insert(PreflightArtifact::RestorationTool, false);
    environment.available_bytes = Ok(999);
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();

    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: "schema_version = 1",
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000,
        },
    );

    for check in [
        PreflightCheck::Configuration,
        PreflightCheck::Tooling,
        PreflightCheck::DiskSpace,
        PreflightCheck::CompetingServices,
        PreflightCheck::FirmwareAuto,
    ] {
        assert!(!report.result(check).unwrap().passed(), "{check:?}");
    }
    assert_eq!(report.checks().len(), 10);
    assert_eq!(
        report.result(PreflightCheck::Tooling).unwrap().detail(),
        "missing /usr/bin/pt31553-fan-restore"
    );
    let competing = report
        .result(PreflightCheck::CompetingServices)
        .unwrap()
        .detail();
    assert!(competing.contains("fancontrol.service"));
    assert!(competing.contains("nbfc.service"));
}

#[test]
fn either_fan_outside_firmware_auto_blocks_preflight() {
    for channel in 1..=2 {
        let (mut platform, mut nvml, mut environment) = passing_fixture();
        platform.insert_file(
            Path::new(HWMON_ROOT).join(format!("hwmon0/pwm{channel}_enable")),
            "1\n",
        );
        let declaration = compatibility_declaration(PROTECTED_POLICY);
        let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
        let record = matching_record(PROTECTED_POLICY);
        let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
        let report = run_read_only_preflight(
            &mut platform,
            &mut nvml,
            &mut environment,
            &PreflightInputs {
                compatibility: &declaration,
                observations: &observations,
                config_source: VALID_CONFIG,
                protected_policy_source: PROTECTED_POLICY,
                qualification_record_source: &record,
                nvidia_selector: &selector,
            },
            &PreflightRequirements {
                hwmon_root: Path::new(HWMON_ROOT),
                evidence_root: Path::new(EVIDENCE_ROOT),
                minimum_available_bytes: 1_000_000,
            },
        );

        assert!(
            !report
                .result(PreflightCheck::FirmwareAuto)
                .unwrap()
                .passed(),
            "fan channel {channel}"
        );
    }
}

#[test]
fn fan_mode_reads_fail_closed_when_the_discovered_hwmon_identity_rebinds() {
    let (platform, mut nvml, mut environment) = passing_fixture();
    let mut platform = RebindOnCpuModeRead { inner: platform };
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    );

    assert!(
        !report
            .result(PreflightCheck::FirmwareAuto)
            .unwrap()
            .passed()
    );
}

fn passing_fixture() -> (FakePlatform, StubNvml, StubEnvironment) {
    let mut platform = FakePlatform::new();
    let acer = Path::new(HWMON_ROOT).join("hwmon0");
    platform.insert_file_with_permissions(acer.join("name"), "acer\n", FilePermissions::READ_ONLY);
    for channel in 1..=2 {
        platform.insert_file_with_permissions(
            acer.join(format!("pwm{channel}")),
            "128\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            acer.join(format!("pwm{channel}_enable")),
            "2\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            acer.join(format!("fan{channel}_input")),
            "2500\n",
            FilePermissions::READ_ONLY,
        );
    }
    let coretemp = Path::new(HWMON_ROOT).join("hwmon1");
    for (name, contents) in [
        ("name", "coretemp\n"),
        ("temp1_label", "Package id 0\n"),
        ("temp1_input", "65000\n"),
        ("temp1_crit", "100000\n"),
    ] {
        platform.insert_file_with_permissions(
            coretemp.join(name),
            contents,
            FilePermissions::READ_ONLY,
        );
    }
    for service in fan_control_core::COMPETING_FAN_CONTROL_SERVICES {
        platform.insert_service(service, false);
    }

    let nvml = StubNvml(Ok(NvmlGpuSample::new(
        EXPECTED_UUID,
        "00000000:01:00.0",
        67.0,
    )));
    (platform, nvml, StubEnvironment::ready())
}

fn run_fixture_report(
    platform: &mut (impl IdentityBoundReadAccess + ServiceAccess),
    nvml: &mut dyn NvmlAccess,
    environment: &mut dyn PreflightEnvironment,
    declaration: &fan_control_core::CompatibilityDeclarationV1,
    observations: &[fan_control_core::CompatibilityObservation],
    record: &str,
) -> PreflightReport {
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    run_read_only_preflight(
        platform,
        nvml,
        environment,
        &PreflightInputs {
            compatibility: declaration,
            observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    )
}

struct RebindOnCpuModeRead {
    inner: FakePlatform,
}

impl IdentityBoundReadAccess for RebindOnCpuModeRead {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        IdentityBoundReadAccess::read(&mut self.inner, path)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        IdentityBoundReadAccess::list(&mut self.inner, directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        IdentityBoundReadAccess::permissions(&mut self.inner, path)
    }

    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        IdentityBoundReadAccess::identity(&mut self.inner, path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        if child == "pwm1_enable" {
            self.inner.rebind_path_identity(directory);
        }
        IdentityBoundReadAccess::read_bound(&mut self.inner, directory, expected, child)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        IdentityBoundReadAccess::list_bound(&mut self.inner, directory, expected)
    }
}

impl ServiceAccess for RebindOnCpuModeRead {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        self.inner.is_service_active(service)
    }
}

#[test]
fn environment_errors_are_failures_not_panics() {
    let (mut platform, mut nvml, mut environment) = passing_fixture();
    environment.available_bytes = Err(PlatformError::new(
        PlatformErrorKind::Unavailable,
        "statvfs unavailable",
    ));
    let declaration = compatibility_declaration(PROTECTED_POLICY);
    let observations = [matching_observation_for_policy(PROTECTED_POLICY)];
    let record = matching_record(PROTECTED_POLICY);
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let report = run_read_only_preflight(
        &mut platform,
        &mut nvml,
        &mut environment,
        &PreflightInputs {
            compatibility: &declaration,
            observations: &observations,
            config_source: VALID_CONFIG,
            protected_policy_source: PROTECTED_POLICY,
            qualification_record_source: &record,
            nvidia_selector: &selector,
        },
        &PreflightRequirements {
            hwmon_root: Path::new(HWMON_ROOT),
            evidence_root: Path::new(EVIDENCE_ROOT),
            minimum_available_bytes: 1_000_000,
        },
    );
    assert_eq!(
        report.result(PreflightCheck::DiskSpace).unwrap().detail(),
        "cannot inspect available disk space: statvfs unavailable"
    );
}
