use std::{path::Path, time::Duration};

use fan_control_core::{
    ExternalPower, FakePlatform, FilePermissions, ObservedSample, PlatformOperation,
    QUALIFICATION_RECORD_PATH, SUPERVISED_ENDURANCE_EVIDENCE_PATH, SampleCapture,
    SampleSourceError, SampleSources, ShutdownRequest, TemperatureCelsius,
    acquire_controller_ownership, discover_acer_hwmon,
};
use fan_control_daemon::{QualifiedStartupInputs, StartupError, qualified_startup};

#[path = "../../fan-control-core/tests/support/mod.rs"]
mod support;

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

#[test]
fn exact_qualified_startup_returns_current_armed_control() {
    let mut platform = qualified_platform();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    let policy = support::PROTECTED_POLICY;
    let mut sources = FixedSources;

    let startup = qualified_startup(
        &mut platform,
        &device,
        &mut sources,
        QualifiedStartupInputs {
            editable_config: &editable_config(policy),
            compatibility_declaration: &compatibility_source(policy),
            protected_policy: policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &[support::matching_observation_for_policy(policy)],
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &ShutdownRequest::new(),
    )
    .unwrap();

    assert!(startup.armed().is_current_for(startup.ownership()));
    startup.restore_and_release().unwrap();
}

#[test]
fn post_lock_rediscovery_precedes_the_first_fan_write() {
    let mut platform = qualified_platform();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    let mut sources = FixedSources;
    let policy = support::PROTECTED_POLICY;

    let startup = qualified_startup(
        &mut platform,
        &device,
        &mut sources,
        QualifiedStartupInputs {
            editable_config: &editable_config(policy),
            compatibility_declaration: &compatibility_source(policy),
            protected_policy: policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &[support::matching_observation_for_policy(policy)],
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &ShutdownRequest::new(),
    )
    .unwrap();
    startup.restore_and_release().unwrap();

    let acquired = platform
        .operations()
        .iter()
        .position(|operation| matches!(operation, PlatformOperation::AcquireRuntimeLock(_)))
        .unwrap();
    let rediscovered = platform
        .operations()
        .iter()
        .enumerate()
        .skip(acquired + 1)
        .find_map(|(index, operation)| {
            matches!(operation, PlatformOperation::List(path) if path == Path::new(HWMON_ROOT))
                .then_some(index)
        })
        .unwrap();
    let first_write = platform
        .operations()
        .iter()
        .enumerate()
        .skip(acquired + 1)
        .find_map(|(index, operation)| {
            matches!(operation, PlatformOperation::Write { .. }).then_some(index)
        })
        .unwrap();
    assert!(acquired < rediscovered && rediscovered < first_write);
}

#[test]
fn changed_post_lock_device_is_safed_using_its_current_identity() {
    let mut platform = qualified_platform();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    platform.rebind_path_identity(ACER_ROOT);
    platform.insert_file(Path::new(ACER_ROOT).join("pwm1_enable"), "1\n");
    platform.insert_file(Path::new(ACER_ROOT).join("pwm2_enable"), "1\n");
    let mut sources = FixedSources;
    let policy = support::PROTECTED_POLICY;

    let error = qualified_startup(
        &mut platform,
        &device,
        &mut sources,
        QualifiedStartupInputs {
            editable_config: &editable_config(policy),
            compatibility_declaration: &compatibility_source(policy),
            protected_policy: policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &[support::matching_observation_for_policy(policy)],
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &ShutdownRequest::new(),
    )
    .unwrap_err();

    assert!(matches!(error, StartupError::Device(_)));
    assert_eq!(
        platform.file_contents(Path::new(ACER_ROOT).join("pwm1_enable")),
        Some("2")
    );
    assert_eq!(
        platform.file_contents(Path::new(ACER_ROOT).join("pwm2_enable")),
        Some("2")
    );
    assert!(
        platform
            .operations()
            .iter()
            .any(|operation| matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)))
    );
}

#[test]
fn malformed_config_is_rejected_before_ownership() {
    let mut platform = qualified_platform();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    let mut sources = FixedSources;
    let policy = support::PROTECTED_POLICY;

    let error = qualified_startup(
        &mut platform,
        &device,
        &mut sources,
        QualifiedStartupInputs {
            editable_config: "not = [valid",
            compatibility_declaration: &compatibility_source(policy),
            protected_policy: policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &[support::matching_observation_for_policy(policy)],
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &ShutdownRequest::new(),
    )
    .unwrap_err();

    assert!(matches!(error, StartupError::Configuration(_)));
    assert!(
        !platform
            .operations()
            .iter()
            .any(|operation| matches!(operation, PlatformOperation::AcquireRuntimeLock(_)))
    );
}

#[test]
fn mismatched_live_identity_is_rejected_before_ownership() {
    let mut platform = qualified_platform();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    let mut sources = FixedSources;
    let policy = support::PROTECTED_POLICY;
    let mut observation = support::matching_observation_for_policy(policy);
    observation.hardware.bios_version = "V1.18".into();

    let error = qualified_startup(
        &mut platform,
        &device,
        &mut sources,
        QualifiedStartupInputs {
            editable_config: &editable_config(policy),
            compatibility_declaration: &compatibility_source(policy),
            protected_policy: policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &[observation],
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &ShutdownRequest::new(),
    )
    .unwrap_err();

    assert!(matches!(error, StartupError::Compatibility(_)));
    assert!(
        !platform
            .operations()
            .iter()
            .any(|operation| matches!(operation, PlatformOperation::AcquireRuntimeLock(_)))
    );
}

#[test]
fn missing_qualification_restores_auto_and_releases_without_custom_mode() {
    let mut platform = qualified_platform();
    platform.remove_path(QUALIFICATION_RECORD_PATH);
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    let mut sources = FixedSources;
    let policy = support::PROTECTED_POLICY;

    let error = qualified_startup(
        &mut platform,
        &device,
        &mut sources,
        QualifiedStartupInputs {
            editable_config: &editable_config(policy),
            compatibility_declaration: &compatibility_source(policy),
            protected_policy: policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &[support::matching_observation_for_policy(policy)],
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &ShutdownRequest::new(),
    )
    .unwrap_err();

    assert!(matches!(error, StartupError::Authority(_)));
    assert!(
        platform
            .operations()
            .iter()
            .any(|operation| matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)))
    );
    assert!(!platform.operations().iter().any(|operation| {
        matches!(
            operation,
            PlatformOperation::Write { path, contents }
                if path.file_name().is_some_and(|name| name == "pwm1_enable" || name == "pwm2_enable")
                    && contents == "1"
        )
    }));
}

#[test]
fn shutdown_during_admission_restores_and_releases_without_custom_mode() {
    let mut platform = qualified_platform();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    let shutdown = ShutdownRequest::new();
    let mut sources = ShutdownDuringSample {
        shutdown: shutdown.clone(),
    };
    let policy = support::PROTECTED_POLICY;

    let error = qualified_startup(
        &mut platform,
        &device,
        &mut sources,
        QualifiedStartupInputs {
            editable_config: &editable_config(policy),
            compatibility_declaration: &compatibility_source(policy),
            protected_policy: policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &[support::matching_observation_for_policy(policy)],
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &shutdown,
    )
    .unwrap_err();

    assert_eq!(error, StartupError::ShutdownRequested);
    assert_eq!(
        platform.file_contents(Path::new(ACER_ROOT).join("pwm1_enable")),
        Some("2")
    );
    assert_eq!(
        platform.file_contents(Path::new(ACER_ROOT).join("pwm2_enable")),
        Some("2")
    );
    assert!(
        platform
            .operations()
            .iter()
            .any(|operation| matches!(operation, PlatformOperation::ReleaseRuntimeLock(_)))
    );
    assert!(!platform.operations().iter().any(|operation| {
        matches!(
            operation,
            PlatformOperation::Write { path, contents }
                if path.file_name().is_some_and(|name| name == "pwm1_enable" || name == "pwm2_enable")
                    && contents == "1"
        )
    }));
}

#[test]
fn startup_diagnostics_are_stable_by_rejection_stage() {
    let cases = [
        (
            StartupError::Configuration(String::new()),
            "configuration-rejected",
        ),
        (
            StartupError::Compatibility(String::new()),
            "configuration-rejected",
        ),
        (
            StartupError::Authority(String::new()),
            "configuration-rejected",
        ),
        (StartupError::Ownership(String::new()), "ownership-denied"),
        (StartupError::Device(String::new()), "sensor-unavailable"),
        (StartupError::Sampling(String::new()), "sensor-unavailable"),
        (
            StartupError::Safing(String::new()),
            "firmware-auto-unconfirmed",
        ),
        (StartupError::Arming(String::new()), "arming-rejected"),
        (
            StartupError::Release(String::new()),
            "platform-operation-failed",
        ),
        (StartupError::ShutdownRequested, "shutdown-requested"),
    ];

    for (error, expected) in cases {
        assert_eq!(error.diagnostic_id(), expected);
    }
}

fn qualified_platform() -> FakePlatform {
    let mut platform = FakePlatform::new();
    insert_acer_device(&mut platform);
    platform.insert_file_with_permissions(
        QUALIFICATION_RECORD_PATH,
        support::matching_record(support::PROTECTED_POLICY),
        FilePermissions::READ_ONLY,
    );
    platform.insert_file_with_permissions(
        SUPERVISED_ENDURANCE_EVIDENCE_PATH,
        support::matching_endurance_evidence(support::PROTECTED_POLICY),
        FilePermissions::READ_ONLY,
    );
    platform
}

fn insert_acer_device(platform: &mut FakePlatform) {
    let root = Path::new(ACER_ROOT);
    platform.insert_file_with_permissions(root.join("name"), "acer\n", FilePermissions::READ_ONLY);
    platform.insert_file(root.join("pwm1"), "255\n");
    platform.insert_file(root.join("pwm1_enable"), "2\n");
    platform.insert_file_with_permissions(
        root.join("fan1_input"),
        "3500\n",
        FilePermissions::READ_ONLY,
    );
    platform.insert_file(root.join("pwm2"), "255\n");
    platform.insert_file(root.join("pwm2_enable"), "2\n");
    platform.insert_file_with_permissions(
        root.join("fan2_input"),
        "3500\n",
        FilePermissions::READ_ONLY,
    );
}

fn editable_config(policy: &str) -> String {
    policy
        .split_once("[protected]\n")
        .unwrap()
        .1
        .replace("[protected.", "[")
}

fn compatibility_source(policy: &str) -> String {
    policy
        .split_once("[compatibility]\n")
        .unwrap()
        .1
        .split_once("\n[calibration.cpu]\n")
        .unwrap()
        .0
        .replace("[compatibility.", "[")
}

#[derive(Debug)]
struct FixedSources;

impl SampleSources for FixedSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(capture.capture(TemperatureCelsius::try_from(60.0).unwrap()))
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(capture.capture(TemperatureCelsius::try_from(55.0).unwrap()))
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        Ok(capture.capture(ExternalPower::Connected))
    }
}

#[derive(Debug)]
struct ShutdownDuringSample {
    shutdown: ShutdownRequest,
}

impl SampleSources for ShutdownDuringSample {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        self.shutdown.request();
        Ok(capture.capture(TemperatureCelsius::try_from(60.0).unwrap()))
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(capture.capture(TemperatureCelsius::try_from(55.0).unwrap()))
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        Ok(capture.capture(ExternalPower::Connected))
    }
}

#[test]
fn test_fixture_uses_the_production_ownership_contract() {
    let mut platform = qualified_platform();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let device = ownership
        .discover_acer_hwmon(Path::new(HWMON_ROOT))
        .unwrap();
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.delay(Duration::ZERO);
    ownership.release().unwrap();
}
