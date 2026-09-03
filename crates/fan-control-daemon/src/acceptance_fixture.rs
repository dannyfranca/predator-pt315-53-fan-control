use std::{cell::Cell, io, path::Path, process::Command, rc::Rc, time::Duration};

use fan_control_core::{
    CompatibilityDeclarationV1, CompatibilityObservation, EmergencyFanStatus, EvidenceCompleteness,
    ExternalPower, FakePlatform, FakeStep, FanWriteBackend, FilePermissions,
    GracefulShutdownFailure, ObservedFanAbi, ObservedSample, PackageProvenanceV1, PlatformError,
    PlatformErrorKind, PlatformOperation, QUALIFICATION_RECORD_PATH,
    SUPERVISED_ENDURANCE_EVIDENCE_PATH, SampleCapture, SampleSourceError, SampleSources,
    ServiceNotification, ServiceNotifier, ShutdownController, SystemdNotifier, TemperatureCelsius,
    discover_acer_hwmon, parse_compatibility_v1,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    ProductionControlLoopError, QualifiedStartupInputs, qualified_startup,
    run_production_control_loop,
    system::{
        QualifiedArchivePaths, StartupDiscoveryEnvironment, SystemSensorSourceDiscovery,
        discover_startup_with, qualified_archive_paths_for_version,
    },
};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";
const POLICY_TEMPLATE: &str = include_str!("../../../policy/qualified-envelope.example.toml");

/// Debug-build subprocess fixture for exercising the production daemon entrypoint safely.
///
/// It uses the same admission, signal, systemd notification, control, cleanup, and release code as
/// production, but all fan I/O is confined to `FakePlatform`.
pub fn run_acceptance_fixture(
    scenario: &str,
    notifier: SystemdNotifier,
    shutdown: &mut ShutdownController,
) -> Result<(), io::Error> {
    let scenario = Scenario::parse(scenario)?;
    let policy = policy_source();
    let mut platform = qualified_platform(&policy)?;
    let compatibility = compatibility_source(&policy);
    let mut environment = FixtureStartupDiscoveryEnvironment {
        platform: &mut platform,
        policy: &policy,
        compatibility: &compatibility,
    };
    let mut discovery = discover_startup_with(&mut environment).map_err(startup_io_error)?;
    let observations = [discovery.observation];
    let mut startup = qualified_startup(
        &mut platform,
        &discovery.device,
        &mut discovery.sources,
        QualifiedStartupInputs {
            editable_config: &discovery.editable_config,
            compatibility_declaration: &discovery.compatibility_declaration,
            protected_policy: &discovery.protected_policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &observations,
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &shutdown.request_handle(),
    )
    .map_err(startup_io_error)?;

    if scenario == Scenario::LostAuthority {
        startup
            .ownership
            .restore_firmware_auto(&discovery.device)
            .map_err(startup_io_error)?;
    }
    prepare_exit_fault(startup.ownership.acceptance_platform_mut(), scenario);
    if matches!(
        scenario,
        Scenario::CleanupContained
            | Scenario::CleanupCritical
            | Scenario::CleanupReadbackUnconfirmed
            | Scenario::ReleaseFailure
    ) {
        shutdown.request();
    }
    let request = shutdown.request_handle();
    let notifier = FixtureNotifier {
        inner: notifier,
        shutdown: request,
        stop_after_watchdog: matches!(scenario, Scenario::Normal | Scenario::Rediscovery),
        fail_watchdog: scenario == Scenario::WatchdogFailure,
        pause_after_ready: scenario == Scenario::NotificationTransportFailure,
    };
    let (sources, discovery) = runtime_inputs(scenario);
    let result = run_production_control_loop(startup, sources, discovery, shutdown, notifier);

    let cpu_auto = platform.file_contents(Path::new(ACER_ROOT).join("pwm1_enable")) == Some("2");
    let gpu_auto = platform.file_contents(Path::new(ACER_ROOT).join("pwm2_enable")) == Some("2");
    let release_attempted = platform
        .operations()
        .iter()
        .any(|operation| matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)));
    let release_ordered = release_follows_both_auto_writes(&platform);
    let (cpu_max, gpu_max) = cleanup_maximum_confirmation(&result);
    println!(
        "fixture-state cpu_auto={cpu_auto} gpu_auto={gpu_auto} cpu_max={cpu_max} gpu_max={gpu_max} release_attempted={release_attempted} release_ordered={release_ordered} result={}",
        if result.is_ok() { "ok" } else { "error" }
    );

    result.map_err(|error| io::Error::other(error.to_string()))
}

fn cleanup_maximum_confirmation(
    result: &Result<(), ProductionControlLoopError<io::Error>>,
) -> (bool, bool) {
    let Err(ProductionControlLoopError::Cleanup { cleanup, .. }) = result else {
        return (false, false);
    };
    let containment = match cleanup {
        GracefulShutdownFailure::Contained { containment, .. }
        | GracefulShutdownFailure::Critical { containment, .. } => containment,
    };
    (
        matches!(containment.cpu(), EmergencyFanStatus::MaximumConfirmed),
        matches!(containment.gpu(), EmergencyFanStatus::MaximumConfirmed),
    )
}

/// Safe host-adapter injection for the same ordered discovery composition used by production.
struct FixtureStartupDiscoveryEnvironment<'a> {
    platform: &'a mut FakePlatform,
    policy: &'a str,
    compatibility: &'a str,
}

impl StartupDiscoveryEnvironment for FixtureStartupDiscoveryEnvironment<'_> {
    type Sources = RuntimeSources;

    fn read_editable_config(&mut self) -> Result<String, crate::StartupError> {
        Ok(include_str!("../../../config/example.toml").to_owned())
    }

    fn load_compatibility_declaration(
        &mut self,
    ) -> Result<(String, CompatibilityDeclarationV1), crate::StartupError> {
        Ok((
            self.compatibility.to_owned(),
            parse_compatibility_v1(self.compatibility)
                .map_err(|error| crate::StartupError::Compatibility(error.to_string()))?,
        ))
    }

    fn load_qualified_archive(
        &mut self,
    ) -> Result<(QualifiedArchivePaths, String, PackageProvenanceV1), crate::StartupError> {
        let provenance = serde_json::from_value(json!({
            "schema_version": 1,
            "candidate": "acceptance-fixture",
            "build": {
                "source_commit": "fixture",
                "source_lock_sha256": "fixture",
                "build_environment_sha256": "fixture",
                "build_attestation_sha256": "fixture",
                "pkgbuild_sha256": "fixture",
                "package_set_srcinfo_sha256": "fixture",
                "package_manifest_signature_sha256": null,
                "package_manifest_signer_fingerprint": "fixture"
            },
            "kernel": {
                "release": "fixture",
                "package": "fixture",
                "image_path": "/fixture/vmlinuz",
                "image_sha256": "fixture",
                "image_signer_fingerprint": "fixture",
                "config_path": "/fixture/config",
                "config_sha256": "fixture",
                "module_trust_certificate_path": "/fixture/cert",
                "module_trust_certificate_fingerprint": "fixture"
            },
            "modules": [],
            "packages": []
        }))
        .map_err(|error| crate::StartupError::Compatibility(error.to_string()))?;
        Ok((
            qualified_archive_paths_for_version("acceptance-fixture"),
            self.policy.to_owned(),
            provenance,
        ))
    }

    fn discover_sources(&mut self) -> Result<Self::Sources, crate::StartupError> {
        Ok(RuntimeSources::healthy())
    }

    fn discover_acer_device(
        &mut self,
        _sources: &mut Self::Sources,
    ) -> Result<fan_control_core::AcerHwmonDevice, crate::StartupError> {
        discover_acer_hwmon(self.platform, Path::new(HWMON_ROOT))
            .map_err(|error| crate::StartupError::Device(error.to_string()))
    }

    fn observe_live_identity(
        &mut self,
        _declaration: &CompatibilityDeclarationV1,
        _provenance: &PackageProvenanceV1,
        _archive: &QualifiedArchivePaths,
        _device: &fan_control_core::AcerHwmonDevice,
    ) -> Result<CompatibilityObservation, crate::StartupError> {
        matching_observation(self.compatibility)
            .map_err(|error| crate::StartupError::Compatibility(error.to_string()))
    }
}

fn release_follows_both_auto_writes(platform: &FakePlatform) -> bool {
    let operations = platform.operations();
    let Some(release) = operations
        .iter()
        .rposition(|operation| matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)))
    else {
        return true;
    };
    ["pwm1_enable", "pwm2_enable"].iter().all(|endpoint| {
        operations[..release].iter().rposition(|operation| {
            matches!(
                operation,
                PlatformOperation::Write { path, contents }
                    if path.file_name().is_some_and(|name| name == *endpoint) && contents == "2"
            )
        }) > operations[..release].iter().rposition(|operation| {
            matches!(
                operation,
                PlatformOperation::Write { path, contents }
                    if path.file_name().is_some_and(|name| name == *endpoint) && contents == "1"
            )
        })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Normal,
    Signal,
    SleepStop,
    Rediscovery,
    ControlFault,
    WatchdogFailure,
    NotificationTransportFailure,
    Timeout,
    DeviceChange,
    LostAuthority,
    CleanupContained,
    CleanupCritical,
    CleanupReadbackUnconfirmed,
    ReleaseFailure,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, io::Error> {
        match value {
            "normal" => Ok(Self::Normal),
            "signal" => Ok(Self::Signal),
            "sleep-stop" => Ok(Self::SleepStop),
            "rediscovery" => Ok(Self::Rediscovery),
            "control-fault" => Ok(Self::ControlFault),
            "watchdog-failure" => Ok(Self::WatchdogFailure),
            "notification-transport-failure" => Ok(Self::NotificationTransportFailure),
            "timeout" => Ok(Self::Timeout),
            "device-change" => Ok(Self::DeviceChange),
            "lost-authority" => Ok(Self::LostAuthority),
            "cleanup-contained" => Ok(Self::CleanupContained),
            "cleanup-critical" => Ok(Self::CleanupCritical),
            "cleanup-readback-unconfirmed" => Ok(Self::CleanupReadbackUnconfirmed),
            "release-failure" => Ok(Self::ReleaseFailure),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown acceptance fixture scenario: {value}"),
            )),
        }
    }
}

fn prepare_exit_fault(platform: &mut FakePlatform, scenario: Scenario) {
    let injected = || {
        PlatformError::new(
            PlatformErrorKind::Unavailable,
            "injected acceptance fixture failure",
        )
    };
    match scenario {
        Scenario::Timeout => platform.queue_file_steps([FakeStep::Advance(Duration::from_secs(3))]),
        Scenario::DeviceChange => platform.rebind_path_identity(ACER_ROOT),
        Scenario::LostAuthority => {}
        Scenario::CleanupContained => {
            let mut steps = Vec::new();
            for _ in 0..3 {
                steps.extend([
                    FakeStep::Pass,
                    FakeStep::Pass,
                    FakeStep::Fail(injected()),
                    FakeStep::Fail(injected()),
                ]);
            }
            platform.queue_file_steps(steps);
        }
        Scenario::CleanupCritical => {
            let mut steps = Vec::new();
            for _ in 0..3 {
                steps.extend([
                    FakeStep::Fail(injected()),
                    FakeStep::Fail(injected()),
                    FakeStep::Pass,
                    FakeStep::Pass,
                ]);
            }
            platform.queue_file_steps(steps);
        }
        Scenario::CleanupReadbackUnconfirmed => {
            let cpu = Path::new(ACER_ROOT).join("pwm1_enable");
            let gpu = Path::new(ACER_ROOT).join("pwm2_enable");
            let mut steps = Vec::new();
            for _ in 0..3 {
                steps.extend([
                    FakeStep::Pass,
                    FakeStep::Pass,
                    FakeStep::ReplaceContents {
                        path: cpu.clone(),
                        contents: "1\n".into(),
                    },
                    FakeStep::ReplaceContents {
                        path: gpu.clone(),
                        contents: "1\n".into(),
                    },
                ]);
            }
            platform.queue_file_steps(steps);
        }
        Scenario::ReleaseFailure => {
            platform.queue_runtime_lock_steps([FakeStep::Fail(injected())]);
        }
        _ => {}
    }
}

fn runtime_inputs(
    scenario: Scenario,
) -> (RuntimeSources, SystemSensorSourceDiscovery<RuntimeSources>) {
    let rediscoveries = Rc::new(Cell::new(0));
    let mut failures_remaining = usize::from(scenario == Scenario::Rediscovery);
    let adapter = SystemSensorSourceDiscovery::injected(move |_files| {
        rediscoveries.set(rediscoveries.get() + 1);
        if failures_remaining > 0 {
            failures_remaining -= 1;
            Err(SampleSourceError::new("injected rediscovery failure"))
        } else {
            Ok(RuntimeSources::healthy())
        }
    });
    let sources = match scenario {
        Scenario::Rediscovery => RuntimeSources::cpu_failure(),
        Scenario::ControlFault => RuntimeSources::power_failure(),
        Scenario::CleanupContained
        | Scenario::CleanupCritical
        | Scenario::CleanupReadbackUnconfirmed
        | Scenario::ReleaseFailure => RuntimeSources::healthy(),
        _ => RuntimeSources::healthy(),
    };
    (sources, adapter)
}

#[derive(Debug)]
struct FixtureNotifier {
    inner: SystemdNotifier,
    shutdown: fan_control_core::ShutdownRequest,
    stop_after_watchdog: bool,
    fail_watchdog: bool,
    pause_after_ready: bool,
}

impl ServiceNotifier for FixtureNotifier {
    type Error = io::Error;

    fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error> {
        if self.fail_watchdog && notification == ServiceNotification::Watchdog {
            return Err(io::Error::other("injected watchdog notification failure"));
        }
        self.inner.notify(notification)?;
        if self.pause_after_ready && notification == ServiceNotification::Ready {
            std::thread::sleep(Duration::from_millis(200));
        }
        if !self.stop_after_watchdog && notification == ServiceNotification::Watchdog {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.stop_after_watchdog && notification == ServiceNotification::Watchdog {
            self.shutdown.request();
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RuntimeSources {
    fail_cpu: bool,
    fail_power: bool,
}

impl RuntimeSources {
    const fn healthy() -> Self {
        Self {
            fail_cpu: false,
            fail_power: false,
        }
    }

    const fn cpu_failure() -> Self {
        Self {
            fail_cpu: true,
            ..Self::healthy()
        }
    }

    const fn power_failure() -> Self {
        Self {
            fail_power: true,
            ..Self::healthy()
        }
    }
}

impl SampleSources for RuntimeSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        if self.fail_cpu {
            Err(SampleSourceError::new("injected CPU failure"))
        } else {
            Ok(capture.capture(TemperatureCelsius::try_from(60.0).expect("valid fixture value")))
        }
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(capture.capture(TemperatureCelsius::try_from(55.0).expect("valid fixture value")))
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        if self.fail_power {
            Err(SampleSourceError::new("injected power failure"))
        } else {
            Ok(capture.capture(ExternalPower::Connected))
        }
    }
}

fn qualified_platform(policy: &str) -> Result<FakePlatform, io::Error> {
    let mut platform = FakePlatform::new();
    let root = Path::new(ACER_ROOT);
    platform.insert_file_with_permissions(root.join("name"), "acer\n", FilePermissions::READ_ONLY);
    for channel in 1..=2 {
        platform.insert_file(root.join(format!("pwm{channel}")), "255\n");
        platform.insert_file(root.join(format!("pwm{channel}_enable")), "2\n");
        platform.insert_file_with_permissions(
            root.join(format!("fan{channel}_input")),
            "3500\n",
            FilePermissions::READ_ONLY,
        );
    }
    let evidence = matching_endurance_evidence(policy)?;
    platform.insert_file_with_permissions(
        SUPERVISED_ENDURANCE_EVIDENCE_PATH,
        &evidence,
        FilePermissions::READ_ONLY,
    );
    platform.insert_file_with_permissions(
        QUALIFICATION_RECORD_PATH,
        matching_record(policy, &evidence)?,
        FilePermissions::READ_ONLY,
    );
    Ok(platform)
}

fn policy_source() -> String {
    POLICY_TEMPLATE
        .replace("example-unqualified-pt31553", "pt31553-v1")
        .replace("0.0.0-example", "1.0.0")
        .replace("REPLACE_WITH_OBSERVED_BIOS", "V1.17")
        .replace(
            "REPLACE_WITH_QUALIFIED_KERNEL_RELEASE",
            "7.1.8-cachyos-pt31553",
        )
        .replace(
            "0000000000000000000000000000000000000000",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .replace(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .replace(
            "/usr/lib/modules/REPLACE/",
            "/usr/lib/modules/7.1.8-cachyos-pt31553/",
        )
        .replace(
            "REPLACE_WITH_QUALIFIED_VERMAGIC",
            "7.1.8-cachyos-pt31553 SMP preempt mod_unload",
        )
}

fn compatibility_source(policy: &str) -> String {
    policy
        .split_once("[compatibility]\n")
        .expect("fixture policy contains compatibility")
        .1
        .split_once("\n[calibration.cpu]\n")
        .expect("fixture policy contains calibration")
        .0
        .replace("[compatibility.", "[")
}

fn matching_observation(source: &str) -> Result<CompatibilityObservation, io::Error> {
    let declaration = parse_compatibility_v1(source).map_err(startup_io_error)?;
    Ok(CompatibilityObservation {
        hardware: declaration.hardware.clone(),
        kernel: declaration.kernel.clone(),
        module: declaration.module.clone(),
        secure_boot_enabled: true,
        kernel_image_trusted: true,
        module_signature_trusted: true,
        fan_abi: ObservedFanAbi {
            hwmon_name: declaration.fan_control.hwmon_name.clone(),
            endpoints: declaration.fan_control.endpoints.clone(),
        },
        backend_evidence_completeness: EvidenceCompleteness::Complete,
        backends: vec![FanWriteBackend::AcerHwmon],
        capability_evidence_completeness: EvidenceCompleteness::Complete,
        enabled_capabilities: Vec::new(),
    })
}

fn matching_endurance_evidence(policy: &str) -> Result<String, io::Error> {
    let archive = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../qualification/supervised-endurance-v2.json.gz");
    let output = Command::new("gzip").arg("-dc").arg(archive).output()?;
    if !output.status.success() {
        return Err(io::Error::other("cannot unpack acceptance evidence"));
    }
    let mut evidence: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| io::Error::other(error.to_string()))?;
    evidence["qualification_envelope"]["protected_policy_sha256"] = sha256(policy).into();
    evidence["qualification_envelope"]["compatibility"] = serde_json::to_value(
        parse_compatibility_v1(&compatibility_source(policy)).map_err(startup_io_error)?,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    serde_json::to_string(&evidence).map_err(|error| io::Error::other(error.to_string()))
}

fn matching_record(policy: &str, evidence: &str) -> Result<String, io::Error> {
    let completed_at = serde_json::from_str::<serde_json::Value>(evidence)
        .map_err(|error| io::Error::other(error.to_string()))?["completed_at"]
        .clone();
    let compatibility =
        parse_compatibility_v1(&compatibility_source(policy)).map_err(startup_io_error)?;
    serde_json::to_string(&json!({
        "schema_version": 2,
        "qualification_id": "pt31553-v1",
        "policy_version": "1.0.0",
        "protected_policy_sha256": sha256(policy),
        "compatibility": compatibility,
        "supervised_endurance": {
            "schema_version": 1,
            "evidence_sha256": sha256(evidence),
            "evidence_path": SUPERVISED_ENDURANCE_EVIDENCE_PATH,
            "evidence_schema_version": 2,
            "stage": "supervised-endurance",
            "record_status": "complete",
            "outcome": "passed",
            "final_firmware_auto_confirmed": true,
            "workload_stopped": true,
            "service_stopped": true,
            "completed_at": completed_at
        }
    }))
    .map_err(|error| io::Error::other(error.to_string()))
}

fn sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn startup_io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
