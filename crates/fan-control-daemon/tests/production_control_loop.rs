use std::{cell::Cell, convert::Infallible, io, path::Path, rc::Rc};

use fan_control_core::{
    BoundedIdentityBoundReadAccess, ExternalPower, FakePlatform, FilePermissions, ObservedSample,
    PlatformOperation, QUALIFICATION_RECORD_PATH, SUPERVISED_ENDURANCE_EVIDENCE_PATH,
    SampleCapture, SampleSourceError, SampleSources, SensorSourceDiscovery, ServiceNotification,
    ServiceNotifier, ShutdownController, ShutdownRequest, TemperatureCelsius, discover_acer_hwmon,
};
use fan_control_daemon::{
    ProductionControlLoopError, QualifiedStartupInputs, qualified_startup,
    run_production_control_loop,
};

#[path = "../../fan-control-core/tests/support/mod.rs"]
mod support;

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

#[test]
fn production_loop_notifies_only_after_a_real_cycle_then_restores_and_releases() {
    let mut platform = qualified_platform();
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    let mut startup_sources = HealthySources;
    let policy = support::PROTECTED_POLICY;
    let startup = qualified_startup(
        &mut platform,
        &device,
        &mut startup_sources,
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
    let mut shutdown = ShutdownController::new();
    let shutdown_request = shutdown.request_handle();
    let notifications = Rc::new(std::cell::RefCell::new(Vec::new()));

    run_production_control_loop(
        startup,
        RuntimeSources::healthy(),
        ScriptedDiscovery::healthy(),
        &mut shutdown,
        StopAfterWatchdog {
            shutdown: shutdown_request,
            notifications: notifications.clone(),
        },
    )
    .unwrap();

    assert_eq!(
        *notifications.borrow(),
        [ServiceNotification::Ready, ServiceNotification::Watchdog]
    );
    assert_safed_and_released(&platform);
}

#[test]
fn production_loop_recovers_sensor_sources_before_readiness() {
    let mut platform = qualified_platform();
    let startup = qualified_startup_fixture(&mut platform);
    let mut shutdown = ShutdownController::new();
    let shutdown_request = shutdown.request_handle();
    let notifications = Rc::new(std::cell::RefCell::new(Vec::new()));
    let rediscoveries = Rc::new(Cell::new(0));

    run_production_control_loop(
        startup,
        RuntimeSources::cpu_failure(),
        ScriptedDiscovery {
            failures_remaining: 1,
            rediscoveries: rediscoveries.clone(),
        },
        &mut shutdown,
        StopAfterWatchdog {
            shutdown: shutdown_request,
            notifications: notifications.clone(),
        },
    )
    .unwrap();

    assert_eq!(rediscoveries.get(), 2);
    assert_eq!(
        *notifications.borrow(),
        [ServiceNotification::Ready, ServiceNotification::Watchdog]
    );
    assert_safed_and_released(&platform);
}

#[test]
fn production_loop_restores_and_releases_after_latched_control_fault() {
    let mut platform = qualified_platform();
    let startup = qualified_startup_fixture(&mut platform);
    let mut shutdown = ShutdownController::new();
    let shutdown_request = shutdown.request_handle();
    let notifications = Rc::new(std::cell::RefCell::new(Vec::new()));

    let error = run_production_control_loop(
        startup,
        RuntimeSources::power_failure(),
        ScriptedDiscovery::healthy(),
        &mut shutdown,
        StopAfterWatchdog {
            shutdown: shutdown_request,
            notifications: notifications.clone(),
        },
    )
    .unwrap_err();

    assert!(matches!(error, ProductionControlLoopError::Iteration(_)));
    assert!(notifications.borrow().is_empty());
    assert_safed_and_released(&platform);
}

#[test]
fn production_loop_restores_and_releases_after_watchdog_failure() {
    let mut platform = qualified_platform();
    let startup = qualified_startup_fixture(&mut platform);
    let mut shutdown = ShutdownController::new();
    let notifications = Rc::new(std::cell::RefCell::new(Vec::new()));

    let error = run_production_control_loop(
        startup,
        RuntimeSources::healthy(),
        ScriptedDiscovery::healthy(),
        &mut shutdown,
        FailOnWatchdog {
            notifications: notifications.clone(),
        },
    )
    .unwrap_err();

    assert!(matches!(error, ProductionControlLoopError::Iteration(_)));
    assert_eq!(
        *notifications.borrow(),
        [ServiceNotification::Ready, ServiceNotification::Watchdog]
    );
    assert_safed_and_released(&platform);
}

#[test]
fn production_loop_honors_shutdown_before_another_control_cycle() {
    let mut platform = qualified_platform();
    let startup = qualified_startup_fixture(&mut platform);
    let mut shutdown = ShutdownController::new();
    shutdown.request();
    let shutdown_request = shutdown.request_handle();
    let notifications = Rc::new(std::cell::RefCell::new(Vec::new()));

    run_production_control_loop(
        startup,
        RuntimeSources::healthy(),
        ScriptedDiscovery::healthy(),
        &mut shutdown,
        StopAfterWatchdog {
            shutdown: shutdown_request,
            notifications: notifications.clone(),
        },
    )
    .unwrap();

    assert!(notifications.borrow().is_empty());
    assert_safed_and_released(&platform);
}

#[derive(Debug)]
struct StopAfterWatchdog {
    shutdown: fan_control_core::ShutdownRequest,
    notifications: Rc<std::cell::RefCell<Vec<ServiceNotification>>>,
}

impl ServiceNotifier for StopAfterWatchdog {
    type Error = Infallible;

    fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error> {
        self.notifications.borrow_mut().push(notification);
        if notification == ServiceNotification::Watchdog {
            self.shutdown.request();
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FailOnWatchdog {
    notifications: Rc<std::cell::RefCell<Vec<ServiceNotification>>>,
}

impl ServiceNotifier for FailOnWatchdog {
    type Error = io::Error;

    fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error> {
        self.notifications.borrow_mut().push(notification);
        if notification == ServiceNotification::Watchdog {
            Err(io::Error::other("injected watchdog failure"))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct ScriptedDiscovery {
    failures_remaining: usize,
    rediscoveries: Rc<Cell<usize>>,
}

impl ScriptedDiscovery {
    fn healthy() -> Self {
        Self {
            failures_remaining: 0,
            rediscoveries: Rc::new(Cell::new(0)),
        }
    }
}

impl SensorSourceDiscovery for ScriptedDiscovery {
    type Sources = RuntimeSources;

    fn rediscover(
        &mut self,
        _files: &mut dyn BoundedIdentityBoundReadAccess,
        _deadline: std::time::Duration,
    ) -> Result<Self::Sources, SampleSourceError> {
        self.rediscoveries.set(self.rediscoveries.get() + 1);
        if self.failures_remaining > 0 {
            self.failures_remaining -= 1;
            Err(SampleSourceError::new("injected rediscovery failure"))
        } else {
            Ok(RuntimeSources::healthy())
        }
    }
}

#[derive(Debug)]
struct HealthySources;

impl SampleSources for HealthySources {
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
            fail_power: false,
        }
    }

    const fn power_failure() -> Self {
        Self {
            fail_cpu: false,
            fail_power: true,
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
            Ok(capture.capture(TemperatureCelsius::try_from(60.0).unwrap()))
        }
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
        if self.fail_power {
            Err(SampleSourceError::new("injected power failure"))
        } else {
            Ok(capture.capture(ExternalPower::Connected))
        }
    }
}

fn qualified_startup_fixture(
    platform: &mut FakePlatform,
) -> fan_control_daemon::QualifiedStartup<'_, FakePlatform> {
    let device = discover_acer_hwmon(platform, Path::new(HWMON_ROOT)).unwrap();
    let mut sources = HealthySources;
    let policy = support::PROTECTED_POLICY;
    qualified_startup(
        platform,
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
    .unwrap()
}

fn assert_safed_and_released(platform: &FakePlatform) {
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

fn qualified_platform() -> FakePlatform {
    let mut platform = FakePlatform::new();
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
