use std::{
    cell::{Cell, RefCell},
    convert::Infallible,
    path::{Path, PathBuf},
    rc::Rc,
    sync::LazyLock,
    time::Duration,
};

use fan_control_core::{
    BoundedFileAccess, BoundedIdentityBoundFileAccess, Clock, ControlCycleOperation,
    ControlCycleReadback, ControlCycleSampleGate, ControllerOwnership, DemandPercent,
    ExternalPower, FakePlatform, FakeRuntimeLock, FakeStep, Fan, FileAccess, FileIdentity,
    FilePermissions, FreshSampleGate, HealthyControl, HealthyControlCycleError,
    IdentityBoundFileAccess, ObservedSample, OwnershipSampleReadiness, PlatformError,
    PlatformErrorKind, PlatformOperation, Pwm, RuntimeLockAccess, RuntimeLockError, SampleCapture,
    SampleSetError, SampleSourceError, SampleSources, SensorControlState, SensorControlStep,
    SensorSourceDiscovery, ServiceAccess, ServiceNotification, ServiceNotifier, ShutdownController,
    ShutdownRequest, TemperatureCelsius, TransientSensorControl, TransientSensorControlError,
    ValidatedConfig, acquire_controller_ownership, admit_policy_authority, arm_both_fans_safely,
    calculate_fan_outputs, discover_acer_hwmon, run_healthy_control_cycle,
    run_supervised_control_iteration,
};

mod support;
use support::{
    diagnostic_field, matching_observation_for_policy, matching_record, protected_config,
    record_diagnostics, runtime_protected_policy,
};

fn state_and_fault_diagnostic_sequence(
    events: &[std::collections::BTreeMap<String, String>],
) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match diagnostic_field(event, "event_id") {
            "pt31553.runtime-fault.v1" => Some(format!(
                "fault:{}:{}",
                diagnostic_field(event, "fault_id"),
                diagnostic_field(event, "endpoint")
            )),
            "pt31553.state-transition.v1" => Some(format!(
                "state:{}:{}:{}",
                diagnostic_field(event, "from_state"),
                diagnostic_field(event, "to_state"),
                diagnostic_field(event, "reason")
            )),
            _ => None,
        })
        .collect()
}

fn assert_state_and_fault_diagnostic_sequence(
    events: &[std::collections::BTreeMap<String, String>],
    expected: &[&str],
) {
    assert_eq!(
        state_and_fault_diagnostic_sequence(events),
        expected
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect::<Vec<_>>()
    );
}

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";
static PROTECTED_POLICY: LazyLock<String> = LazyLock::new(runtime_protected_policy);

#[derive(Debug, Clone, Copy)]
struct Frame {
    cpu: f64,
    gpu: f64,
    power: ExternalPower,
}

#[derive(Debug)]
struct CountingSources {
    frames: Vec<Frame>,
    frame: usize,
    cpu_reads: usize,
    gpu_reads: usize,
    power_reads: usize,
    fail_cpu: bool,
}

impl CountingSources {
    fn new(frames: Vec<Frame>) -> Self {
        Self {
            frames,
            frame: 0,
            cpu_reads: 0,
            gpu_reads: 0,
            power_reads: 0,
            fail_cpu: false,
        }
    }

    fn current(&self) -> Frame {
        self.frames[self.frame]
    }
}

impl SampleSources for CountingSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        self.cpu_reads += 1;
        if self.fail_cpu {
            return Err(SampleSourceError::new("CPU sample unavailable"));
        }
        Ok(capture.capture(TemperatureCelsius::try_from(self.current().cpu).unwrap()))
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        self.gpu_reads += 1;
        Ok(capture.capture(TemperatureCelsius::try_from(self.current().gpu).unwrap()))
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        self.power_reads += 1;
        let power = self.current().power;
        self.frame += 1;
        Ok(capture.capture(power))
    }
}

#[derive(Debug)]
struct CancellingSources {
    inner: CountingSources,
    shutdown: ShutdownRequest,
}

impl SampleSources for CancellingSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        self.inner.sample_cpu(capture)
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        let sample = self.inner.sample_gpu(capture)?;
        self.shutdown.request();
        Ok(sample)
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        self.inner.observe_external_power(capture)
    }
}

type SourceDropProbe = (Rc<Cell<bool>>, Rc<RefCell<Vec<bool>>>);

#[derive(Debug)]
struct RecoveryScript {
    frames: Vec<Frame>,
    frame: usize,
    cpu_reads: usize,
    gpu_reads: usize,
    fail_cpu: bool,
    fail_gpu: bool,
    fail_power: bool,
    rediscoveries: usize,
    fail_rediscovery_once: bool,
    next_binding: u64,
    last_sample_binding: Option<u64>,
    source_drop_probe: Option<SourceDropProbe>,
    shutdown_after_sample: Option<ShutdownRequest>,
}

impl RecoveryScript {
    fn new(frames: Vec<Frame>) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            frames,
            frame: 0,
            cpu_reads: 0,
            gpu_reads: 0,
            fail_cpu: false,
            fail_gpu: false,
            fail_power: false,
            rediscoveries: 0,
            fail_rediscovery_once: false,
            next_binding: 1,
            last_sample_binding: None,
            source_drop_probe: None,
            shutdown_after_sample: None,
        }))
    }
}

#[derive(Debug)]
struct RecoverySources {
    script: Rc<RefCell<RecoveryScript>>,
    binding: u64,
}

impl Drop for RecoverySources {
    fn drop(&mut self) {
        let probe = self.script.borrow().source_drop_probe.clone();
        if let Some((firmware_auto_confirmed, observations)) = probe {
            observations
                .borrow_mut()
                .push(firmware_auto_confirmed.get());
        }
    }
}

impl SampleSources for RecoverySources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        let mut script = self.script.borrow_mut();
        script.cpu_reads += 1;
        script.last_sample_binding = Some(self.binding);
        if script.fail_cpu {
            return Err(SampleSourceError::new("CPU sample unavailable"));
        }
        let cpu = script.frames[script.frame].cpu;
        drop(script);
        Ok(capture.capture(TemperatureCelsius::try_from(cpu).unwrap()))
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        let mut script = self.script.borrow_mut();
        script.gpu_reads += 1;
        if script.fail_gpu {
            return Err(SampleSourceError::new("GPU sample unavailable"));
        }
        let gpu = script.frames[script.frame].gpu;
        drop(script);
        Ok(capture.capture(TemperatureCelsius::try_from(gpu).unwrap()))
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        let mut script = self.script.borrow_mut();
        if script.fail_power {
            return Err(SampleSourceError::new("power sample unavailable"));
        }
        let power = script.frames[script.frame].power;
        script.frame += 1;
        if let Some(shutdown) = script.shutdown_after_sample.take() {
            shutdown.request();
        }
        drop(script);
        Ok(capture.capture(power))
    }
}

#[derive(Debug)]
struct RecoveryDiscovery {
    script: Rc<RefCell<RecoveryScript>>,
}

impl SensorSourceDiscovery for RecoveryDiscovery {
    type Sources = RecoverySources;

    fn rediscover(
        &mut self,
        files: &mut dyn fan_control_core::IdentityBoundReadAccess,
    ) -> Result<Self::Sources, SampleSourceError> {
        files
            .identity(Path::new(ACER_ROOT))
            .map_err(|error| SampleSourceError::new(error.to_string()))?;
        let mut script = self.script.borrow_mut();
        script.rediscoveries += 1;
        if script.fail_rediscovery_once {
            script.fail_rediscovery_once = false;
            return Err(SampleSourceError::new("sensor identities unavailable"));
        }
        let binding = script.next_binding;
        script.next_binding += 1;
        Ok(RecoverySources {
            script: Rc::clone(&self.script),
            binding,
        })
    }
}

fn recovery_control(
    armed: fan_control_core::ArmedFanControl,
    authority: fan_control_core::AdmittedPolicyAuthority,
    frames: Vec<Frame>,
) -> (
    TransientSensorControl<RecoveryDiscovery>,
    Rc<RefCell<RecoveryScript>>,
) {
    let (control, script, _) = recovery_control_with_shutdown(armed, authority, frames);
    (control, script)
}

fn recovery_control_with_shutdown(
    armed: fan_control_core::ArmedFanControl,
    authority: fan_control_core::AdmittedPolicyAuthority,
    frames: Vec<Frame>,
) -> (
    TransientSensorControl<RecoveryDiscovery>,
    Rc<RefCell<RecoveryScript>>,
    ShutdownRequest,
) {
    let script = RecoveryScript::new(frames);
    let discovery = RecoveryDiscovery {
        script: Rc::clone(&script),
    };
    let initial_sources = RecoverySources {
        script: Rc::clone(&script),
        binding: 0,
    };
    let shutdown = ShutdownRequest::new();
    (
        TransientSensorControl::from_armed(
            armed,
            authority,
            shutdown.clone(),
            discovery,
            initial_sources,
        ),
        script,
        shutdown,
    )
}

fn healthy_control(armed: fan_control_core::ArmedFanControl) -> HealthyControl {
    HealthyControl::from_armed(armed, ShutdownRequest::new())
}

struct RecordingNotifier(Rc<RefCell<Vec<ServiceNotification>>>);

impl ServiceNotifier for RecordingNotifier {
    type Error = Infallible;

    fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error> {
        self.0.borrow_mut().push(notification);
        Ok(())
    }
}

#[test]
fn supervised_heartbeat_follows_a_real_normal_control_cycle() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let (mut control, _) = recovery_control(
        armed,
        authority,
        vec![Frame {
            cpu: 70.0,
            gpu: 65.0,
            power: ExternalPower::Connected,
        }],
    );
    let notifications = Rc::new(RefCell::new(Vec::new()));
    let mut heartbeat =
        fan_control_core::ControlLoopHeartbeat::new(RecordingNotifier(Rc::clone(&notifications)));

    let step = run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat)
        .expect("a completed real control iteration should notify systemd");

    assert!(matches!(step, SensorControlStep::Completed(_)));
    assert_eq!(
        *notifications.borrow(),
        vec![ServiceNotification::Ready, ServiceNotification::Watchdog]
    );
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn supervised_heartbeat_tracks_every_successful_recovery_transition_after_readiness() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let low = Frame {
        cpu: 40.0,
        gpu: 35.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame, frame, frame, low]);
    let notifications = Rc::new(RefCell::new(Vec::new()));
    let mut heartbeat =
        fan_control_core::ControlLoopHeartbeat::new(RecordingNotifier(Rc::clone(&notifications)));

    assert!(matches!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::Completed(_)
    ));
    let mut expected = vec![ServiceNotification::Ready, ServiceNotification::Watchdog];

    ownership.delay(Duration::from_secs(2));
    script.borrow_mut().fail_cpu = true;
    assert!(matches!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::FirmwareAutoRestored { .. }
    ));
    expected.push(ServiceNotification::Watchdog);
    assert_eq!(*notifications.borrow(), expected);

    script.borrow_mut().fail_cpu = false;
    script.borrow_mut().fail_rediscovery_once = true;
    assert!(matches!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::AwaitingRediscovery(_)
    ));
    expected.push(ServiceNotification::Watchdog);
    assert_eq!(*notifications.borrow(), expected);

    assert_eq!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::AwaitingSecondSample
    );
    expected.push(ServiceNotification::Watchdog);
    assert_eq!(*notifications.borrow(), expected);

    ownership.delay(Duration::from_secs(2));
    assert_eq!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::Rearmed
    );
    expected.push(ServiceNotification::Watchdog);
    assert_eq!(*notifications.borrow(), expected);

    assert!(matches!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::Completed(_)
    ));
    assert_eq!(
        *notifications.borrow(),
        [
            ServiceNotification::Ready,
            ServiceNotification::Watchdog,
            ServiceNotification::Watchdog,
            ServiceNotification::Watchdog,
            ServiceNotification::Watchdog,
            ServiceNotification::Watchdog,
            ServiceNotification::Watchdog,
        ]
    );
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn one_cycle_uses_one_fresh_snapshot_and_verifies_each_changed_output() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (candidate, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    let mut sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);
    let marker = ownership.platform().operations().len();

    let (completed, diagnostic_events) = record_diagnostics(|| {
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap()
    });

    let expected = calculate_fan_outputs(
        &candidate,
        TemperatureCelsius::try_from(70.0).unwrap(),
        TemperatureCelsius::try_from(65.0).unwrap(),
        ExternalPower::Connected,
    );
    assert_eq!(diagnostic_events.len(), 1);
    let event = &diagnostic_events[0];
    assert_eq!(
        diagnostic_field(event, "event_id"),
        "pt31553.control-cycle.v1"
    );
    assert_eq!(diagnostic_field(event, "cpu_temperature_celsius"), "70.0");
    assert_eq!(diagnostic_field(event, "gpu_temperature_celsius"), "65.0");
    assert_eq!(diagnostic_field(event, "external_power"), "connected");
    assert_eq!(diagnostic_field(event, "profile"), "ac");
    let demand = DemandPercent::try_from(
        diagnostic_field(event, "demand_percent")
            .parse::<f64>()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(Pwm::from(demand), expected.cpu_pwm());
    assert_eq!(Pwm::from(demand), expected.gpu_pwm());
    assert_eq!(diagnostic_field(event, "cpu_pwm_endpoint"), "acer:cpu:pwm1");
    assert_eq!(
        diagnostic_field(event, "cpu_command_pwm"),
        expected.cpu_pwm().value().to_string()
    );
    assert_eq!(
        diagnostic_field(event, "cpu_readback_pwm"),
        expected.cpu_pwm().value().to_string()
    );
    assert_eq!(
        diagnostic_field(event, "cpu_tachometer_endpoint"),
        "acer:cpu:fan1_input"
    );
    assert_eq!(diagnostic_field(event, "cpu_rpm_command_pwm"), "255");
    assert_eq!(diagnostic_field(event, "cpu_rpm"), "3000");
    assert_eq!(diagnostic_field(event, "gpu_pwm_endpoint"), "acer:gpu:pwm2");
    assert_eq!(
        diagnostic_field(event, "gpu_command_pwm"),
        expected.gpu_pwm().value().to_string()
    );
    assert_eq!(
        diagnostic_field(event, "gpu_readback_pwm"),
        expected.gpu_pwm().value().to_string()
    );
    assert_eq!(
        diagnostic_field(event, "gpu_tachometer_endpoint"),
        "acer:gpu:fan2_input"
    );
    assert_eq!(diagnostic_field(event, "gpu_rpm_command_pwm"), "255");
    assert_eq!(diagnostic_field(event, "gpu_rpm"), "3000");
    assert_eq!(
        diagnostic_field(event, "message"),
        "completed fan control cycle"
    );

    assert_eq!(completed.outputs(), expected);
    assert_eq!(
        completed.sample().external_power(),
        ExternalPower::Connected
    );
    assert_eq!(
        (sources.cpu_reads, sources.gpu_reads, sources.power_reads),
        (1, 1, 1)
    );
    assert_eq!(control.last_outputs(), expected);
    assert_eq!(
        ownership.platform().file_contents(cpu_pwm()),
        Some(expected.cpu_pwm().value().to_string().as_str())
    );
    assert_eq!(
        ownership.platform().file_contents(gpu_pwm()),
        Some(expected.gpu_pwm().value().to_string().as_str())
    );

    let operations = &ownership.platform().operations()[marker..];
    assert_changed_write_is_immediately_read(operations, cpu_pwm(), expected.cpu_pwm().value());
    assert_changed_write_is_immediately_read(operations, gpu_pwm(), expected.gpu_pwm().value());
    let first_normal_write = operations.iter().position(is_pwm_write).unwrap();
    assert!(operations[..first_normal_write].iter().any(
        |operation| matches!(operation, PlatformOperation::Read(path) if path == cpu_enable())
    ));
    assert!(operations[..first_normal_write].iter().any(
        |operation| matches!(operation, PlatformOperation::Read(path) if path == gpu_enable())
    ));

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn shutdown_during_a_cycle_prevents_normal_writes_and_permanently_invalidates_it() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let shutdown = ShutdownController::new();
    let request = shutdown.request_handle();
    let mut control = HealthyControl::from_armed(armed, request.clone());
    let mut sources = CancellingSources {
        inner: CountingSources::new(vec![Frame {
            cpu: 70.0,
            gpu: 65.0,
            power: ExternalPower::Connected,
        }]),
        shutdown: request.clone(),
    };
    let marker = ownership.platform().operations().len();

    assert!(matches!(
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources),
        Err(HealthyControlCycleError::ShutdownRequested)
    ));
    assert!(
        !ownership.platform().operations()[marker..]
            .iter()
            .any(is_pwm_write)
    );

    let mut replacement_sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);
    assert!(matches!(
        run_healthy_control_cycle(&mut ownership, &mut control, &mut replacement_sources,),
        Err(HealthyControlCycleError::Invalidated)
    ));

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn shutdown_after_cpu_write_prevents_gpu_write() {
    let (platform, device) = fixture();
    let injection = Rc::new(Cell::new(RuntimeInterference::None));
    let shutdown = ShutdownRequest::new();
    let mut platform =
        InterferingPlatform::new(platform, Rc::clone(&injection)).with_shutdown(shutdown.clone());
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = HealthyControl::from_armed(armed, shutdown);
    injection.set(RuntimeInterference::ShutdownAfterCpuWrite);
    let mut sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);
    let marker = ownership.platform().operations().len();

    assert!(matches!(
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources),
        Err(HealthyControlCycleError::ShutdownRequested)
    ));
    let operations = &ownership.platform().operations()[marker..];
    assert!(operations.iter().any(
        |operation| matches!(operation, PlatformOperation::Write { path, .. } if path == cpu_pwm())
    ));
    assert!(operations.iter().all(
        |operation| !matches!(operation, PlatformOperation::Write { path, .. } if path == gpu_pwm())
    ));

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn repeated_cycles_wait_for_two_second_cadence_and_never_reuse_samples() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    let mut sources = CountingSources::new(vec![
        Frame {
            cpu: 60.0,
            gpu: 55.0,
            power: ExternalPower::Disconnected,
        },
        Frame {
            cpu: 80.0,
            gpu: 75.0,
            power: ExternalPower::Connected,
        },
    ]);
    let delay_marker = ownership.platform().delays().len();

    let first = run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
    let second = run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();

    assert_eq!(
        (sources.cpu_reads, sources.gpu_reads, sources.power_reads),
        (2, 2, 2)
    );
    assert_eq!(
        second.sample().cycle_started_at() - first.sample().cycle_started_at(),
        Duration::from_secs(2)
    );
    assert_eq!(
        &ownership.platform().delays()[delay_marker..],
        &[Duration::from_secs(2)]
    );
    assert!(second.outputs().cpu_pwm() > first.outputs().cpu_pwm());

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn each_fresh_power_snapshot_selects_that_cycles_profile() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    let mut sources = CountingSources::new(vec![
        Frame {
            cpu: 70.0,
            gpu: 65.0,
            power: ExternalPower::Disconnected,
        },
        Frame {
            cpu: 70.0,
            gpu: 65.0,
            power: ExternalPower::Connected,
        },
    ]);

    let battery = run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
    let ac = run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();

    assert_eq!(
        battery.sample().external_power(),
        ExternalPower::Disconnected
    );
    assert_eq!(ac.sample().external_power(), ExternalPower::Connected);
    assert!(ac.outputs().cpu_pwm() > battery.outputs().cpu_pwm());
    assert!(ac.outputs().gpu_pwm() > battery.outputs().gpu_pwm());
    assert_eq!(
        (sources.cpu_reads, sources.gpu_reads, sources.power_reads),
        (2, 2, 2)
    );

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn unchanged_outputs_are_verified_but_not_rewritten() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let mut sources = CountingSources::new(vec![frame, frame]);
    run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
    let marker = ownership.platform().operations().len();

    run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();

    let operations = &ownership.platform().operations()[marker..];
    assert!(!operations.iter().any(is_pwm_write));
    assert!(
        operations.iter().any(
            |operation| matches!(operation, PlatformOperation::Read(path) if path == cpu_pwm())
        )
    );
    assert!(
        operations.iter().any(
            |operation| matches!(operation, PlatformOperation::Read(path) if path == gpu_pwm())
        )
    );

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn lower_demand_holds_then_ramps_down_on_fresh_cycle_time() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    let high = Frame {
        cpu: 80.0,
        gpu: 75.0,
        power: ExternalPower::Connected,
    };
    let low = Frame {
        cpu: 40.0,
        gpu: 35.0,
        power: ExternalPower::Connected,
    };
    let mut sources = CountingSources::new(
        std::iter::once(high)
            .chain(std::iter::repeat_n(low, 7))
            .collect(),
    );
    let mut outputs = Vec::new();

    for _ in 0..8 {
        outputs.push(
            run_healthy_control_cycle(&mut ownership, &mut control, &mut sources)
                .unwrap()
                .outputs(),
        );
    }

    assert!(outputs[1..7].iter().all(|output| *output == outputs[0]));
    assert!(outputs[7].cpu_pwm() < outputs[0].cpu_pwm());
    assert_eq!(
        (sources.cpu_reads, sources.gpu_reads, sources.power_reads),
        (8, 8, 8)
    );

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn delayed_interpolated_tachometer_response_inside_the_qualified_band_is_accepted() {
    let (platform, device) = fixture();
    let injection = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    injection.set(RuntimeInterference::CpuTachometerZeroOnce);
    let frame = Frame {
        cpu: 60.0,
        gpu: 55.0,
        power: ExternalPower::Connected,
    };
    let mut sources = CountingSources::new(vec![frame, frame, frame]);

    for _ in 0..3 {
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
    }

    assert!(control.is_current_for(&ownership));
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn response_windows_use_confirmed_commands_and_each_fans_own_read_time() {
    let (platform, device) = fixture();
    let injection = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    injection.set(RuntimeInterference::DelayCpuConfirmationThenCpuZeroAndDelayedGpuTachometer);
    let frame = Frame {
        cpu: 60.0,
        gpu: 55.0,
        power: ExternalPower::Connected,
    };
    let mut sources = CountingSources::new(vec![frame, frame, frame]);

    for _ in 0..3 {
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
    }

    assert!(control.is_current_for(&ownership));
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn each_fan_faults_independently_after_its_qualified_response_deadline() {
    for (interference, expected_fan, expected_interpolated_rpm) in [
        (RuntimeInterference::CpuTachometerZero, Fan::Cpu, 2929),
        (RuntimeInterference::GpuTachometerOutOfBand, Fan::Gpu, 2967),
    ] {
        let (platform, device) = fixture();
        let injection = Rc::new(Cell::new(RuntimeInterference::None));
        let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let (_, armed) = arm(&mut ownership, &device);
        let mut control = healthy_control(armed);
        injection.set(interference);
        let frame = Frame {
            cpu: 60.0,
            gpu: 55.0,
            power: ExternalPower::Connected,
        };
        let mut sources = CountingSources::new(vec![frame, frame, frame, frame]);

        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
        let error =
            run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap_err();

        assert!(matches!(
            error,
            HealthyControlCycleError::TachometerOutOfBand {
                fan,
                expected_rpm,
                actual_rpm,
            } if fan == expected_fan
                && expected_rpm == expected_interpolated_rpm
                && actual_rpm == if expected_fan == Fan::Cpu { 0 } else { 1000 }
        ));
        assert!(!control.is_current_for(&ownership));
        ownership.restore_firmware_auto(&device).unwrap();
        ownership.release().unwrap();
    }
}

#[test]
fn overdue_response_faults_before_a_changed_command_can_replace_it() {
    let policy = PROTECTED_POLICY.replacen(
        "response_deadline_millis = 4000",
        "response_deadline_millis = 1000",
        1,
    );
    let (platform, device) = fixture();
    let injection = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm_with_policy_authority(&mut ownership, &device, &policy);
    let mut control = healthy_control(armed);
    injection.set(RuntimeInterference::CpuTachometerZero);
    let mut sources = CountingSources::new(vec![
        Frame {
            cpu: 60.0,
            gpu: 55.0,
            power: ExternalPower::Connected,
        },
        Frame {
            cpu: 70.0,
            gpu: 55.0,
            power: ExternalPower::Connected,
        },
    ]);

    run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();
    let marker = ownership.platform().operations().len();
    let error = run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap_err();

    assert!(matches!(
        error,
        HealthyControlCycleError::TachometerOutOfBand {
            fan: Fan::Cpu,
            actual_rpm: 0,
            ..
        }
    ));
    assert!(
        ownership.platform().operations()[marker..]
            .iter()
            .all(|operation| !is_pwm_write(operation))
    );
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn backing_device_rebind_is_rejected_before_normal_output() {
    let (platform, device) = fixture();
    let interference = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&interference));
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    interference.set(RuntimeInterference::RebindRootOnIdentity);
    let mut sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);
    let marker = ownership.platform().operations().len();

    assert!(matches!(
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources),
        Err(HealthyControlCycleError::DeviceChanged)
    ));
    assert!(
        ownership.platform().operations()[marker..]
            .iter()
            .all(|operation| !is_pwm_write(operation))
    );
    assert!(!control.is_current_for(&ownership));

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn tachometer_endpoint_rebind_is_rejected_during_preflight() {
    let (error, operations) = run_interfered_cycle(RuntimeInterference::RebindGpuTachOnIdentity);
    assert!(matches!(error, HealthyControlCycleError::DeviceChanged));
    assert!(operations.iter().all(|operation| !is_pwm_write(operation)));
}

#[test]
fn post_discovery_ambiguity_or_malformed_abi_blocks_normal_output() {
    for interference in [
        RuntimeInterference::AddAmbiguousAcerDevice,
        RuntimeInterference::AddMalformedFanEndpoint,
        RuntimeInterference::MakeEndpointWorldWritable,
    ] {
        let (error, operations) = run_interfered_cycle(interference);
        assert!(matches!(error, HealthyControlCycleError::Device(_)));
        assert!(operations.iter().all(|operation| !is_pwm_write(operation)));
    }
}

#[test]
fn deadline_expiry_is_reported_consistently_at_each_output_phase() {
    for interference in [
        RuntimeInterference::ExpireBeforePreflight,
        RuntimeInterference::ExpireBeforeCpuReadback,
        RuntimeInterference::ExpireBetweenFanWrites,
    ] {
        let (error, _) = run_interfered_cycle(interference);
        assert!(matches!(error, HealthyControlCycleError::DeadlineExceeded));
    }
}

#[test]
fn each_fan_mode_mismatch_blocks_all_normal_output() {
    for (interference, expected_fan) in [
        (RuntimeInterference::CpuModeBeforeRead, Fan::Cpu),
        (RuntimeInterference::GpuModeBeforeRead, Fan::Gpu),
    ] {
        let (error, operations) = run_interfered_cycle(interference);
        assert!(matches!(
            error,
            HealthyControlCycleError::UnexpectedReadback {
                fan,
                field: ControlCycleReadback::Mode,
                operation: ControlCycleOperation::ConfirmBeforeOutput,
                ..
            } if fan == expected_fan
        ));
        assert!(operations.iter().all(|operation| !is_pwm_write(operation)));
    }
}

#[test]
fn bound_write_rejects_identity_or_mode_interference_after_prechecks() {
    for interference in [
        RuntimeInterference::RebindRootBeforeWrite,
        RuntimeInterference::RebindTargetBeforeWrite,
        RuntimeInterference::CpuModeBeforeWrite,
        RuntimeInterference::GpuModeBeforeCpuWrite,
        RuntimeInterference::RebindGpuEndpointBeforeCpuWrite,
    ] {
        let (error, operations) = run_interfered_cycle(interference);
        assert!(matches!(
            error,
            HealthyControlCycleError::Platform {
                fan: Fan::Cpu,
                operation: ControlCycleOperation::WriteDuty,
                ..
            }
        ));
        assert!(operations.iter().all(|operation| !is_pwm_write(operation)));
    }

    for interference in [
        RuntimeInterference::GpuModeBeforeWrite,
        RuntimeInterference::CpuModeBeforeGpuWrite,
        RuntimeInterference::RebindCpuEndpointBeforeGpuWrite,
    ] {
        let (error, operations) = run_interfered_cycle(interference);
        assert!(matches!(
            error,
            HealthyControlCycleError::Platform {
                fan: Fan::Gpu,
                operation: ControlCycleOperation::WriteDuty,
                ..
            }
        ));
        assert!(operations.iter().all(|operation| {
            !matches!(operation, PlatformOperation::Write { path, .. } if path == gpu_pwm())
        }));
    }
}

#[test]
fn each_changed_pwm_readback_mismatch_invalidates_the_cycle() {
    for (interference, expected_fan) in [
        (RuntimeInterference::CpuDutyAfterWrite, Fan::Cpu),
        (RuntimeInterference::GpuDutyAfterWrite, Fan::Gpu),
    ] {
        let (error, operations) = run_interfered_cycle(interference);
        assert!(matches!(
            error,
            HealthyControlCycleError::UnexpectedReadback {
                fan,
                field: ControlCycleReadback::Duty,
                operation: ControlCycleOperation::ConfirmWrittenDuty,
                ..
            } if fan == expected_fan
        ));
        if expected_fan == Fan::Cpu {
            assert!(operations.iter().all(|operation| {
                !matches!(operation, PlatformOperation::Write { path, .. } if path == gpu_pwm())
            }));
        }
    }
}

#[test]
fn output_change_during_tachometer_io_invalidates_the_cycle() {
    let (error, _) = run_interfered_cycle(RuntimeInterference::CpuDutyDuringGpuTachometerRead);

    assert!(matches!(
        error,
        HealthyControlCycleError::UnexpectedReadback {
            fan: Fan::Cpu,
            field: ControlCycleReadback::Duty,
            operation: ControlCycleOperation::ConfirmResult,
            ..
        }
    ));
}

fn run_interfered_cycle(
    interference: RuntimeInterference,
) -> (HealthyControlCycleError, Vec<PlatformOperation>) {
    let (platform, device) = fixture();
    let injection = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    injection.set(interference);
    let mut sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);
    let marker = ownership.platform().operations().len();

    let error = run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap_err();
    let operations = ownership.platform().operations()[marker..].to_vec();
    assert!(!control.is_current_for(&ownership));
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
    (error, operations)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeInterference {
    None,
    ShutdownAfterCpuWrite,
    RebindRootOnIdentity,
    RebindGpuTachOnIdentity,
    AddAmbiguousAcerDevice,
    AddMalformedFanEndpoint,
    MakeEndpointWorldWritable,
    ExpireBeforePreflight,
    ExpireBeforeCpuReadback,
    ExpireBetweenFanWrites,
    RebindRootBeforeWrite,
    RebindTargetBeforeWrite,
    DisappearTargetBeforeWrite,
    CpuModeBeforeRead,
    CpuModeBeforeReadAndRestorationDeadlineAuto,
    GpuModeBeforeRead,
    CpuModeBeforeWrite,
    GpuModeBeforeWrite,
    CpuModeBeforeGpuWrite,
    GpuModeBeforeCpuWrite,
    RebindCpuEndpointBeforeGpuWrite,
    RebindGpuEndpointBeforeCpuWrite,
    CpuDutyAfterWrite,
    GpuDutyAfterWrite,
    CpuTachometerZero,
    CpuTachometerZeroOnce,
    GpuTachometerOutOfBand,
    CpuDutyDuringGpuTachometerRead,
    DelayCpuConfirmationThenCpuZeroAndDelayedGpuTachometer,
    CpuZeroAndDelayedGpuTachometer,
    FailCpuDutyReadback,
    GpuDutyReadbackFailureAndRestorationDeadlineCustom,
    RestorationUnavailable,
    RestorationDeadlineCustom,
    RestorationDeadlineAuto,
    CpuModeBeforeRecoveryAutoCheck,
    CpuModeBeforeRecoveryAutoCheckAndRestorationDeadlineCustom,
    ArmingFailureAndRestorationUnavailable,
}

struct InterferingPlatform {
    inner: FakePlatform,
    interference: Rc<Cell<RuntimeInterference>>,
    last_normal_write: Option<String>,
    gpu_tachometer_reads_during_interference: usize,
    firmware_auto_confirmed: Rc<Cell<bool>>,
    shutdown: Option<ShutdownRequest>,
}

impl InterferingPlatform {
    fn new(inner: FakePlatform, interference: Rc<Cell<RuntimeInterference>>) -> Self {
        Self {
            inner,
            interference,
            last_normal_write: None,
            gpu_tachometer_reads_during_interference: 0,
            firmware_auto_confirmed: Rc::new(Cell::new(false)),
            shutdown: None,
        }
    }

    fn with_shutdown(mut self, shutdown: ShutdownRequest) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    fn maybe_rebind(&mut self, path: &Path) {
        if path == Path::new(ACER_ROOT)
            && self.interference.get() == RuntimeInterference::RebindRootOnIdentity
        {
            self.interference.set(RuntimeInterference::None);
            self.inner.rebind_path_identity(path);
        }
        if path == Path::new(ACER_ROOT).join("fan2_input")
            && self.interference.get() == RuntimeInterference::RebindGpuTachOnIdentity
        {
            self.interference.set(RuntimeInterference::None);
            self.inner.rebind_path_identity(path);
        }
    }

    fn operations(&self) -> &[PlatformOperation] {
        self.inner.operations()
    }

    fn firmware_auto_confirmation(&self) -> Rc<Cell<bool>> {
        Rc::clone(&self.firmware_auto_confirmed)
    }
}

impl FileAccess for InterferingPlatform {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        self.inner.read(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.inner.write(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        self.inner.list(directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        self.inner.permissions(path)
    }
}

impl IdentityBoundFileAccess for InterferingPlatform {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        self.maybe_rebind(path);
        self.inner.identity(path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        self.inner.read_bound(directory, expected, child)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.inner.list_bound(directory, expected)
    }
}

impl BoundedFileAccess for InterferingPlatform {
    fn read_before(&mut self, path: &Path, deadline: Duration) -> Result<String, PlatformError> {
        if matches!(
            self.interference.get(),
            RuntimeInterference::CpuModeBeforeRecoveryAutoCheck
                | RuntimeInterference::CpuModeBeforeRecoveryAutoCheckAndRestorationDeadlineCustom
        ) && path == cpu_enable()
        {
            self.interference.set(
                if self.interference.get()
                    == RuntimeInterference::CpuModeBeforeRecoveryAutoCheckAndRestorationDeadlineCustom
                {
                    RuntimeInterference::RestorationDeadlineCustom
                } else {
                    RuntimeInterference::None
                },
            );
            self.inner.insert_file(path, "1\n");
        }
        if self.interference.get() == RuntimeInterference::RestorationUnavailable
            && (path == cpu_enable() || path == gpu_enable())
        {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                "restoration unavailable",
            ));
        }
        let result = self.inner.read_before(path, deadline);
        if result.is_ok()
            && (path == cpu_enable() || path == gpu_enable())
            && self
                .inner
                .file_contents(cpu_enable())
                .is_some_and(|value| value.trim() == "2")
            && self
                .inner
                .file_contents(gpu_enable())
                .is_some_and(|value| value.trim() == "2")
        {
            self.firmware_auto_confirmed.set(true);
        }
        result
    }

    fn list_before(
        &mut self,
        directory: &Path,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        match self.interference.get() {
            RuntimeInterference::AddAmbiguousAcerDevice if directory == Path::new(HWMON_ROOT) => {
                self.interference.set(RuntimeInterference::None);
                insert_acer_device(&mut self.inner, Path::new(HWMON_ROOT).join("hwmon8"));
            }
            RuntimeInterference::AddMalformedFanEndpoint if directory == Path::new(HWMON_ROOT) => {
                self.interference.set(RuntimeInterference::None);
                self.inner
                    .insert_file(Path::new(ACER_ROOT).join("pwm3"), "128\n");
            }
            RuntimeInterference::ExpireBeforePreflight if directory == Path::new(HWMON_ROOT) => {
                self.interference.set(RuntimeInterference::None);
                self.inner.delay(Duration::from_secs(2));
            }
            _ => {}
        }
        self.inner.list_before(directory, deadline)
    }

    fn write_before(
        &mut self,
        path: &Path,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        let interference = self.interference.get();
        if matches!(
            interference,
            RuntimeInterference::CpuModeBeforeReadAndRestorationDeadlineAuto
                | RuntimeInterference::GpuDutyReadbackFailureAndRestorationDeadlineCustom
                | RuntimeInterference::RestorationDeadlineCustom
                | RuntimeInterference::RestorationDeadlineAuto
        ) && (path == cpu_enable() || path == gpu_enable())
        {
            if interference == RuntimeInterference::RestorationDeadlineAuto {
                self.inner.insert_file(cpu_enable(), "2\n");
                self.inner.insert_file(gpu_enable(), "2\n");
            }
            self.interference.set(RuntimeInterference::None);
            self.inner.delay(Duration::from_secs(3));
        }
        if self.interference.get() == RuntimeInterference::RestorationUnavailable
            && (path == cpu_enable() || path == gpu_enable())
        {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                "restoration unavailable",
            ));
        }
        self.inner.write_before(path, contents, deadline)
    }
}

impl BoundedIdentityBoundFileAccess for InterferingPlatform {
    fn identity_before(
        &mut self,
        path: &Path,
        deadline: Duration,
    ) -> Result<FileIdentity, PlatformError> {
        self.maybe_rebind(path);
        self.inner.identity_before(path, deadline)
    }

    fn read_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError> {
        let interference = self.interference.get();
        if interference
            == RuntimeInterference::DelayCpuConfirmationThenCpuZeroAndDelayedGpuTachometer
            && self.last_normal_write.as_deref() == Some("pwm1")
            && child == "pwm1"
        {
            let result = self.inner.read_bound_before(
                directory,
                expected_directory,
                child,
                expected_child,
                deadline,
            );
            self.inner.delay(Duration::from_secs(1));
            self.interference
                .set(RuntimeInterference::CpuZeroAndDelayedGpuTachometer);
            return result;
        }
        if interference == RuntimeInterference::CpuTachometerZeroOnce && child == "fan1_input" {
            self.interference.set(RuntimeInterference::None);
            self.inner.insert_file_with_permissions(
                directory.join(child),
                "0\n",
                FilePermissions::READ_ONLY,
            );
            let result = self.inner.read_bound_before(
                directory,
                expected_directory,
                child,
                expected_child,
                deadline,
            );
            self.inner.insert_file_with_permissions(
                directory.join(child),
                "3000\n",
                FilePermissions::READ_ONLY,
            );
            return result;
        }
        if matches!(
            interference,
            RuntimeInterference::CpuTachometerZero
                | RuntimeInterference::CpuZeroAndDelayedGpuTachometer
        ) && child == "fan1_input"
        {
            self.inner.insert_file_with_permissions(
                directory.join(child),
                "0\n",
                FilePermissions::READ_ONLY,
            );
        }
        if interference == RuntimeInterference::CpuZeroAndDelayedGpuTachometer
            && child == "fan2_input"
        {
            self.gpu_tachometer_reads_during_interference += 1;
            if self.gpu_tachometer_reads_during_interference == 3 {
                self.inner.delay(Duration::from_millis(1_001));
            }
        }
        if interference == RuntimeInterference::GpuTachometerOutOfBand && child == "fan2_input" {
            self.inner.insert_file_with_permissions(
                directory.join(child),
                "1000\n",
                FilePermissions::READ_ONLY,
            );
        }
        if interference == RuntimeInterference::CpuDutyDuringGpuTachometerRead
            && child == "fan2_input"
        {
            self.interference.set(RuntimeInterference::None);
            let result = self.inner.read_bound_before(
                directory,
                expected_directory,
                child,
                expected_child,
                deadline,
            );
            self.inner
                .insert_file_with_permissions(cpu_pwm(), "0\n", FilePermissions::READ_WRITE);
            return result;
        }
        if (matches!(
            interference,
            RuntimeInterference::CpuModeBeforeRead
                | RuntimeInterference::CpuModeBeforeReadAndRestorationDeadlineAuto
        ) && child == "pwm1_enable")
            || (interference == RuntimeInterference::GpuModeBeforeRead && child == "pwm2_enable")
        {
            self.interference.set(
                if matches!(
                    interference,
                    RuntimeInterference::CpuModeBeforeReadAndRestorationDeadlineAuto
                ) {
                    interference
                } else {
                    RuntimeInterference::None
                },
            );
            self.inner.insert_file(directory.join(child), "2\n");
            if interference == RuntimeInterference::CpuModeBeforeReadAndRestorationDeadlineAuto {
                self.inner.insert_file(gpu_enable(), "2\n");
            }
        }
        if (interference == RuntimeInterference::CpuDutyAfterWrite
            && self.last_normal_write.as_deref() == Some("pwm1")
            && child == "pwm1")
            || (interference == RuntimeInterference::GpuDutyAfterWrite
                && self.last_normal_write.as_deref() == Some("pwm2")
                && child == "pwm2")
        {
            self.interference.set(RuntimeInterference::None);
            self.inner.insert_file(directory.join(child), "0\n");
        }
        if interference == RuntimeInterference::FailCpuDutyReadback
            && self.last_normal_write.as_deref() == Some("pwm1")
            && child == "pwm1"
        {
            self.interference.set(RuntimeInterference::None);
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                "CPU PWM readback unavailable",
            ));
        }
        if interference == RuntimeInterference::GpuDutyReadbackFailureAndRestorationDeadlineCustom
            && self.last_normal_write.as_deref() == Some("pwm2")
            && child == "pwm2"
        {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                "GPU PWM readback unavailable",
            ));
        }
        let result = self.inner.read_bound_before(
            directory,
            expected_directory,
            child,
            expected_child,
            deadline,
        );
        if result.is_ok()
            && interference == RuntimeInterference::ExpireBetweenFanWrites
            && self.last_normal_write.as_deref() == Some("pwm1")
            && child == "pwm1"
        {
            self.interference.set(RuntimeInterference::None);
            self.inner.delay(Duration::from_secs(2));
        }
        result
    }

    fn list_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.inner
            .list_bound_before(directory, expected_directory, deadline)
    }

    fn permissions_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<FilePermissions, PlatformError> {
        if self.interference.get() == RuntimeInterference::MakeEndpointWorldWritable {
            self.interference.set(RuntimeInterference::None);
            self.inner.set_file_permissions(
                Path::new(ACER_ROOT).join("pwm1_enable"),
                FilePermissions::from_mode(0o666),
            );
        }
        if self.interference.get() == RuntimeInterference::ArmingFailureAndRestorationUnavailable {
            self.interference
                .set(RuntimeInterference::RestorationUnavailable);
            self.inner.set_file_permissions(
                Path::new(ACER_ROOT).join("pwm1_enable"),
                FilePermissions::from_mode(0o666),
            );
        }
        self.inner.permissions_bound_before(
            directory,
            expected_directory,
            child,
            expected_child,
            deadline,
        )
    }

    fn write_bound_if_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        expected_children: &[(&str, FileIdentity)],
        guards: &[(&str, &str)],
        target_child: &str,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        match self.interference.get() {
            RuntimeInterference::RebindRootBeforeWrite => {
                self.interference.set(RuntimeInterference::None);
                self.inner.rebind_path_identity(directory);
            }
            RuntimeInterference::RebindTargetBeforeWrite => {
                self.interference.set(RuntimeInterference::None);
                self.inner
                    .rebind_path_identity(directory.join(target_child));
            }
            RuntimeInterference::DisappearTargetBeforeWrite => {
                self.interference.set(RuntimeInterference::None);
                self.inner
                    .queue_file_steps([FakeStep::Disappear(directory.join(target_child))]);
            }
            RuntimeInterference::CpuModeBeforeWrite if target_child == "pwm1" => {
                self.interference.set(RuntimeInterference::None);
                self.inner.insert_file(directory.join("pwm1_enable"), "2\n");
            }
            RuntimeInterference::GpuModeBeforeWrite if target_child == "pwm2" => {
                self.interference.set(RuntimeInterference::None);
                self.inner.insert_file(directory.join("pwm2_enable"), "2\n");
            }
            RuntimeInterference::CpuModeBeforeGpuWrite if target_child == "pwm2" => {
                self.interference.set(RuntimeInterference::None);
                self.inner.insert_file(directory.join("pwm1_enable"), "2\n");
            }
            RuntimeInterference::GpuModeBeforeCpuWrite if target_child == "pwm1" => {
                self.interference.set(RuntimeInterference::None);
                self.inner.insert_file(directory.join("pwm2_enable"), "2\n");
            }
            RuntimeInterference::RebindCpuEndpointBeforeGpuWrite if target_child == "pwm2" => {
                self.interference.set(RuntimeInterference::None);
                self.inner.rebind_path_identity(directory.join("pwm1"));
            }
            RuntimeInterference::RebindGpuEndpointBeforeCpuWrite if target_child == "pwm1" => {
                self.interference.set(RuntimeInterference::None);
                self.inner.rebind_path_identity(directory.join("pwm2"));
            }
            _ => {}
        }
        let result = self.inner.write_bound_if_before(
            directory,
            expected_directory,
            expected_children,
            guards,
            target_child,
            contents,
            deadline,
        );
        if result.is_ok() {
            self.last_normal_write = Some(target_child.to_owned());
            if self.interference.get() == RuntimeInterference::ShutdownAfterCpuWrite
                && target_child == "pwm1"
            {
                self.interference.set(RuntimeInterference::None);
                self.shutdown
                    .as_ref()
                    .expect("shutdown interference requires a request handle")
                    .request();
            }
            if self.interference.get() == RuntimeInterference::ExpireBeforeCpuReadback
                && target_child == "pwm1"
            {
                self.interference.set(RuntimeInterference::None);
                self.inner.delay(Duration::from_secs(2));
            }
        }
        result
    }
}

impl Clock for InterferingPlatform {
    fn monotonic_now(&mut self) -> Duration {
        self.inner.monotonic_now()
    }

    fn delay(&mut self, duration: Duration) {
        self.inner.delay(duration);
    }
}

impl ServiceAccess for InterferingPlatform {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        self.inner.is_service_active(service)
    }
}

impl RuntimeLockAccess for InterferingPlatform {
    type RuntimeLock = FakeRuntimeLock;

    fn try_acquire_root_runtime_lock(
        &mut self,
        path: &Path,
    ) -> Result<Self::RuntimeLock, RuntimeLockError> {
        self.inner.try_acquire_root_runtime_lock(path)
    }

    fn release_runtime_lock(
        &mut self,
        lock: Self::RuntimeLock,
    ) -> Result<(), (Self::RuntimeLock, PlatformError)> {
        self.inner.release_runtime_lock(lock)
    }
}

#[test]
fn a_failed_fresh_sample_permanently_invalidates_normal_control() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    let mut sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);
    sources.fail_cpu = true;
    let marker = ownership.platform().operations().len();

    assert!(matches!(
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources),
        Err(HealthyControlCycleError::Sample(
            SampleSetError::Input { .. }
        ))
    ));
    assert!(!control.is_current_for(&ownership));
    assert!(
        ownership.platform().operations()[marker..]
            .iter()
            .all(|operation| !is_pwm_write(operation))
    );
    assert!(matches!(
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources),
        Err(HealthyControlCycleError::Invalidated)
    ));

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn control_path_fault_classes_restore_auto_and_permanently_latch() {
    for interference in [
        RuntimeInterference::RebindRootOnIdentity,
        RuntimeInterference::AddMalformedFanEndpoint,
        RuntimeInterference::DisappearTargetBeforeWrite,
        RuntimeInterference::CpuModeBeforeRead,
        RuntimeInterference::GpuModeBeforeRead,
        RuntimeInterference::CpuDutyAfterWrite,
        RuntimeInterference::GpuDutyAfterWrite,
        RuntimeInterference::FailCpuDutyReadback,
    ] {
        let (platform, device) = fixture();
        let injection = Rc::new(Cell::new(RuntimeInterference::None));
        let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let (authority, armed) = arm_with_authority(&mut ownership, &device);
        let frame = Frame {
            cpu: 70.0,
            gpu: 65.0,
            power: ExternalPower::Connected,
        };
        let (mut control, script) = recovery_control(armed, authority, vec![frame]);
        injection.set(interference);
        let marker = ownership.platform().operations().len();

        let Err(TransientSensorControlError::ControlLatched { fault }) =
            control.step(&mut ownership)
        else {
            panic!("{interference:?} must report its latched control fault")
        };
        match interference {
            RuntimeInterference::RebindRootOnIdentity => {
                assert!(matches!(fault, HealthyControlCycleError::DeviceChanged));
            }
            RuntimeInterference::AddMalformedFanEndpoint => {
                assert!(matches!(fault, HealthyControlCycleError::Device(_)));
            }
            RuntimeInterference::DisappearTargetBeforeWrite => assert!(matches!(
                fault,
                HealthyControlCycleError::Platform {
                    operation: ControlCycleOperation::WriteDuty,
                    ..
                }
            )),
            RuntimeInterference::CpuModeBeforeRead | RuntimeInterference::GpuModeBeforeRead => {
                assert!(matches!(
                    fault,
                    HealthyControlCycleError::UnexpectedReadback {
                        field: ControlCycleReadback::Mode,
                        ..
                    }
                ))
            }
            RuntimeInterference::CpuDutyAfterWrite | RuntimeInterference::GpuDutyAfterWrite => {
                assert!(matches!(
                    fault,
                    HealthyControlCycleError::UnexpectedReadback {
                        field: ControlCycleReadback::Duty,
                        ..
                    }
                ))
            }
            RuntimeInterference::FailCpuDutyReadback => assert!(matches!(
                fault,
                HealthyControlCycleError::Platform {
                    fan: Fan::Cpu,
                    operation: ControlCycleOperation::ConfirmWrittenDuty,
                    ..
                }
            )),
            _ => unreachable!("the fault-class matrix contains only covered interference"),
        }
        assert_eq!(control.state(), SensorControlState::Faulted);
        assert_eq!(
            ownership.platform().inner.file_contents(cpu_enable()),
            Some("2")
        );
        assert_eq!(
            ownership.platform().inner.file_contents(gpu_enable()),
            Some("2")
        );
        assert_eq!(script.borrow().rediscoveries, 0);

        let operations = &ownership.platform().operations()[marker..];
        let restoration_started = operations
            .iter()
            .position(|operation| {
                matches!(
                    operation,
                    PlatformOperation::Write { path, contents }
                        if (path == cpu_enable() || path == gpu_enable()) && contents == "2"
                )
            })
            .expect("a latched fault must begin Firmware Auto restoration");
        assert!(
            operations[restoration_started..]
                .iter()
                .all(|operation| !is_pwm_write(operation))
        );
        assert!(matches!(
            control.step(&mut ownership),
            Err(TransientSensorControlError::Faulted)
        ));
        assert_eq!(script.borrow().rediscoveries, 0);

        ownership.release().unwrap();
    }
}

#[test]
fn post_write_fault_stops_normal_output_then_contains_at_maximum_and_stays_critical() {
    let (platform, device) = fixture();
    let injection = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
    let auto_confirmed = platform.firmware_auto_confirmation();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame]);
    let drop_observations = Rc::new(RefCell::new(Vec::new()));
    script.borrow_mut().source_drop_probe =
        Some((Rc::clone(&auto_confirmed), Rc::clone(&drop_observations)));
    auto_confirmed.set(false);
    let marker = ownership.platform().operations().len();
    injection.set(RuntimeInterference::GpuDutyReadbackFailureAndRestorationDeadlineCustom);

    let Err(TransientSensorControlError::ControlLatchCritical { containment, .. }) =
        control.step(&mut ownership)
    else {
        panic!("unconfirmed containment must remain a critical latch")
    };
    assert!(!containment.restoration_confirmed());
    assert!(matches!(
        containment.cpu(),
        fan_control_core::EmergencyFanStatus::MaximumConfirmed
    ));
    assert!(matches!(
        containment.gpu(),
        fan_control_core::EmergencyFanStatus::MaximumConfirmed
    ));
    assert_eq!(
        ownership.platform().inner.file_contents(cpu_pwm()),
        Some("255")
    );
    assert_eq!(
        ownership.platform().inner.file_contents(gpu_pwm()),
        Some("255")
    );
    let operations = &ownership.platform().operations()[marker..];
    let restoration_started = operations
        .iter()
        .position(|operation| {
            matches!(
                operation,
                PlatformOperation::Write { path, contents }
                    if (path == cpu_enable() || path == gpu_enable()) && contents == "2"
            )
        })
        .expect("post-write fault must begin Firmware Auto restoration");
    assert!(operations[..restoration_started].iter().any(|operation| {
        matches!(operation, PlatformOperation::Write { contents, .. } if is_pwm_write(operation) && contents != "255")
    }));
    assert!(operations[restoration_started..].iter().all(|operation| {
        !is_pwm_write(operation)
            || matches!(operation, PlatformOperation::Write { contents, .. } if contents == "255")
    }));
    assert_eq!(control.state(), SensorControlState::Faulted);
    assert!(drop_observations.borrow().is_empty());
    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::Faulted)
    ));

    injection.set(RuntimeInterference::None);
    ownership.restore_firmware_auto(&device).unwrap();
    drop(control);
    assert_eq!(*drop_observations.borrow(), vec![true]);
    ownership.release().unwrap();
}

#[test]
fn auto_confirmed_containment_reports_latch_and_drops_obsolete_bindings() {
    let (platform, device) = fixture();
    let injection = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
    let auto_confirmed = platform.firmware_auto_confirmation();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame]);
    let drop_observations = Rc::new(RefCell::new(Vec::new()));
    script.borrow_mut().source_drop_probe =
        Some((Rc::clone(&auto_confirmed), Rc::clone(&drop_observations)));
    auto_confirmed.set(false);
    injection.set(RuntimeInterference::CpuModeBeforeReadAndRestorationDeadlineAuto);

    let (result, diagnostic_events) = record_diagnostics(|| control.step(&mut ownership));
    let Err(TransientSensorControlError::ControlLatchContained { containment, .. }) = result else {
        panic!("Auto-confirmed containment must report a permanent latch")
    };
    assert_state_and_fault_diagnostic_sequence(
        &diagnostic_events,
        &[
            "fault:unexpected-readback:acer:cpu:pwm1_enable",
            "state:custom-control:restoring:control-fault",
            "fault:restoration-unconfirmed:none",
            "state:restoring:firmware-auto:restoration-confirmed",
            "state:firmware-auto:fault-latched:control-fault",
        ],
    );
    assert!(containment.restoration_confirmed());
    assert_eq!(*drop_observations.borrow(), vec![true]);
    assert_eq!(control.state(), SensorControlState::Faulted);
    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::Faulted)
    ));
    assert_eq!(script.borrow().rediscoveries, 0);

    ownership.release().unwrap();
}

#[test]
fn transient_cpu_failure_restores_auto_then_rediscovers_and_fully_rearms() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let low = Frame {
        cpu: 40.0,
        gpu: 35.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame, frame, frame, low]);
    assert!(matches!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::Completed(_)
    ));
    ownership.delay(Duration::from_secs(2));
    script.borrow_mut().fail_cpu = true;
    let marker = ownership.platform().operations().len();

    let (step, diagnostic_events) = record_diagnostics(|| control.step(&mut ownership).unwrap());
    assert!(matches!(
        step,
        SensorControlStep::FirmwareAutoRestored {
            fault: SampleSetError::Input {
                input: fan_control_core::RequiredInput::Cpu,
                ..
            }
        }
    ));
    let sample_faults = diagnostic_events
        .iter()
        .filter(|event| {
            event.get("fault_id").map(|value| value.trim_matches('"')) == Some("sensor-unavailable")
        })
        .collect::<Vec<_>>();
    assert_state_and_fault_diagnostic_sequence(
        &diagnostic_events,
        &[
            "fault:sensor-unavailable:sensor:cpu:temperature",
            "state:custom-control:restoring:sensor-fault",
            "state:restoring:firmware-auto:restoration-confirmed",
        ],
    );
    assert!(!sample_faults.is_empty());
    assert!(
        sample_faults
            .iter()
            .all(|event| { diagnostic_field(event, "endpoint") == "sensor:cpu:temperature" })
    );
    assert_eq!(control.state(), SensorControlState::FirmwareAutoRecovery);
    assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("2"));
    assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("2"));
    assert!(
        ownership.platform().operations()[marker..]
            .iter()
            .all(|operation| !is_pwm_write(operation))
    );

    script.borrow_mut().fail_cpu = false;
    script.borrow_mut().fail_rediscovery_once = true;
    assert!(matches!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::AwaitingRediscovery(_)
    ));
    assert_eq!(script.borrow().rediscoveries, 1);
    assert_eq!(
        (script.borrow().cpu_reads, script.borrow().gpu_reads),
        (2, 1)
    );

    assert_eq!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::AwaitingSecondSample
    );
    assert_eq!(script.borrow().rediscoveries, 2);
    assert_eq!(script.borrow().last_sample_binding, Some(1));
    assert_eq!(control.state(), SensorControlState::FirmwareAutoRecovery);
    assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("2"));
    assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("2"));

    ownership.delay(Duration::from_secs(2));
    assert_eq!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::Rearmed
    );
    assert_eq!(control.state(), SensorControlState::CustomControl);
    assert_eq!(script.borrow().rediscoveries, 2);
    assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("1"));
    assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("1"));
    assert_eq!(ownership.platform().file_contents(cpu_pwm()), Some("255"));
    assert_eq!(ownership.platform().file_contents(gpu_pwm()), Some("255"));

    let SensorControlStep::Completed(first_cycle) = control.step(&mut ownership).unwrap() else {
        panic!("rearmed control must resume normal cycles")
    };
    assert_eq!(
        first_cycle.outputs(),
        calculate_fan_outputs(
            &protected_config(&PROTECTED_POLICY),
            TemperatureCelsius::try_from(low.cpu).unwrap(),
            TemperatureCelsius::try_from(low.gpu).unwrap(),
            low.power,
        )
    );

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn shutdown_after_recovery_sample_readiness_is_observable_before_rearming() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script, shutdown) =
        recovery_control_with_shutdown(armed, authority, vec![frame, frame, frame]);

    assert!(matches!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::Completed(_)
    ));
    ownership.delay(Duration::from_secs(2));
    script.borrow_mut().fail_cpu = true;
    assert!(matches!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::FirmwareAutoRestored { .. }
    ));
    script.borrow_mut().fail_cpu = false;
    assert_eq!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::AwaitingSecondSample
    );
    ownership.delay(Duration::from_secs(2));
    script.borrow_mut().shutdown_after_sample = Some(shutdown);

    let (result, diagnostic_events) = record_diagnostics(|| control.step(&mut ownership));

    assert!(matches!(
        result,
        Err(TransientSensorControlError::ShutdownRequested)
    ));
    assert_eq!(diagnostic_events.len(), 2);
    assert_eq!(
        diagnostic_field(&diagnostic_events[0], "fault_id"),
        "shutdown-requested"
    );
    assert_eq!(
        diagnostic_field(&diagnostic_events[1], "from_state"),
        "firmware-auto"
    );
    assert_eq!(
        diagnostic_field(&diagnostic_events[1], "to_state"),
        "fault-latched"
    );

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn failed_sources_are_dropped_only_after_firmware_auto_is_confirmed() {
    let (platform, device) = fixture();
    let interference = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, interference);
    let auto_confirmed = platform.firmware_auto_confirmation();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame]);
    let drop_observations = Rc::new(RefCell::new(Vec::new()));
    script.borrow_mut().source_drop_probe =
        Some((Rc::clone(&auto_confirmed), Rc::clone(&drop_observations)));
    auto_confirmed.set(false);
    script.borrow_mut().fail_cpu = true;

    assert!(matches!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::FirmwareAutoRestored { .. }
    ));
    assert_eq!(*drop_observations.borrow(), vec![true]);

    drop(control);
    ownership.release().unwrap();
}

#[test]
fn unexpected_mode_during_rediscovery_restores_auto_and_permanently_latches() {
    let (platform, device) = fixture();
    let interference = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&interference));
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame]);
    script.borrow_mut().fail_cpu = true;
    control.step(&mut ownership).unwrap();
    {
        let mut script = script.borrow_mut();
        script.fail_cpu = false;
        script.fail_rediscovery_once = true;
    }
    assert!(matches!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::AwaitingRediscovery(_)
    ));

    interference.set(RuntimeInterference::CpuModeBeforeRecoveryAutoCheck);
    let (result, diagnostic_events) = record_diagnostics(|| control.step(&mut ownership));
    assert_state_and_fault_diagnostic_sequence(
        &diagnostic_events,
        &[
            "fault:firmware-auto-unconfirmed:none",
            "state:firmware-auto:restoring:control-fault",
            "state:restoring:firmware-auto:restoration-confirmed",
            "state:firmware-auto:fault-latched:control-fault",
        ],
    );
    assert!(matches!(
        result,
        Err(TransientSensorControlError::RecoveryLatched {
            fault: SampleSetError::FirmwareAutoUnconfirmed
        })
    ));
    assert_eq!(
        ownership.platform().inner.file_contents(cpu_enable()),
        Some("2")
    );
    assert_eq!(
        ownership.platform().inner.file_contents(gpu_enable()),
        Some("2")
    );
    assert_eq!(script.borrow().rediscoveries, 1);
    assert_eq!(control.state(), SensorControlState::Faulted);
    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::Faulted)
    ));

    ownership.release().unwrap();
}

#[test]
fn failed_restoration_after_mode_drift_contains_and_retains_sensor_bindings() {
    let (platform, device) = fixture();
    let interference = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&interference));
    let auto_confirmed = platform.firmware_auto_confirmation();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame, frame]);
    script.borrow_mut().fail_cpu = true;
    control.step(&mut ownership).unwrap();
    script.borrow_mut().fail_cpu = false;
    assert_eq!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::AwaitingSecondSample
    );
    let drop_observations = Rc::new(RefCell::new(Vec::new()));
    script.borrow_mut().source_drop_probe =
        Some((Rc::clone(&auto_confirmed), Rc::clone(&drop_observations)));
    ownership.delay(Duration::from_secs(2));
    auto_confirmed.set(false);
    interference
        .set(RuntimeInterference::CpuModeBeforeRecoveryAutoCheckAndRestorationDeadlineCustom);

    let (result, diagnostic_events) = record_diagnostics(|| control.step(&mut ownership));
    let Err(TransientSensorControlError::RecoveryLatchCritical {
        fault: SampleSetError::FirmwareAutoUnconfirmed,
        restoration,
        containment,
    }) = result
    else {
        panic!("failed restoration after mode drift must remain critical")
    };
    assert_state_and_fault_diagnostic_sequence(
        &diagnostic_events,
        &[
            "fault:firmware-auto-unconfirmed:none",
            "state:firmware-auto:restoring:control-fault",
            "fault:restoration-unconfirmed:none",
            "fault:containment-unconfirmed:none",
            "state:restoring:fault-latched:restoration-failed",
        ],
    );
    assert!(!containment.restoration_confirmed());
    let fan_control_core::FirmwareAutoRestorationError::DeadlineExceeded { attempts, cpu, gpu } =
        restoration
    else {
        panic!("the injected restoration deadline must be preserved")
    };
    assert_eq!(attempts, 1);
    assert!(!cpu.is_confirmed());
    assert!(!gpu.is_confirmed());
    assert!(matches!(
        containment.cpu(),
        fan_control_core::EmergencyFanStatus::MaximumConfirmed
    ));
    assert!(matches!(
        containment.gpu(),
        fan_control_core::EmergencyFanStatus::FirmwareAuto
    ));
    assert!(drop_observations.borrow().is_empty());

    interference.set(RuntimeInterference::None);
    ownership.restore_firmware_auto(&device).unwrap();
    drop(control);
    assert_eq!(*drop_observations.borrow(), vec![true]);
    ownership.release().unwrap();
}

#[test]
fn failed_rearming_restoration_retains_sensor_bindings() {
    let (platform, device) = fixture();
    let interference = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&interference));
    let auto_confirmed = platform.firmware_auto_confirmation();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame, frame]);
    script.borrow_mut().fail_cpu = true;
    control.step(&mut ownership).unwrap();
    script.borrow_mut().fail_cpu = false;
    assert_eq!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::AwaitingSecondSample
    );
    let drop_observations = Rc::new(RefCell::new(Vec::new()));
    script.borrow_mut().source_drop_probe =
        Some((Rc::clone(&auto_confirmed), Rc::clone(&drop_observations)));
    ownership.delay(Duration::from_secs(2));
    auto_confirmed.set(false);
    interference.set(RuntimeInterference::ArmingFailureAndRestorationUnavailable);

    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::Rearming(
            fan_control_core::FanArmingError::RestorationFailed { .. }
        ))
    ));
    assert_eq!(control.state(), SensorControlState::Faulted);
    assert!(drop_observations.borrow().is_empty());
    let marker = ownership.platform().operations().len();
    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::Faulted)
    ));
    assert!(
        ownership.platform().operations()[marker..]
            .iter()
            .all(|operation| !is_pwm_write(operation))
    );

    interference.set(RuntimeInterference::None);
    ownership.restore_firmware_auto(&device).unwrap();
    drop(control);
    assert_eq!(*drop_observations.borrow(), vec![true]);
    ownership.release().unwrap();
}

#[test]
fn a_recovery_sample_failure_discards_identity_and_sample_history() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame, frame, frame]);
    script.borrow_mut().fail_cpu = true;
    control.step(&mut ownership).unwrap();

    script.borrow_mut().fail_cpu = false;
    assert_eq!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::AwaitingSecondSample
    );
    ownership.delay(Duration::from_secs(2));
    script.borrow_mut().fail_gpu = true;
    assert!(matches!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::FirmwareAutoRestored {
            fault: SampleSetError::Input {
                input: fan_control_core::RequiredInput::Gpu,
                ..
            }
        }
    ));

    script.borrow_mut().fail_gpu = false;
    assert_eq!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::AwaitingSecondSample
    );
    assert_eq!(script.borrow().rediscoveries, 2);
    assert_eq!(script.borrow().last_sample_binding, Some(2));
    assert_eq!(control.state(), SensorControlState::FirmwareAutoRecovery);
    ownership.delay(Duration::from_secs(2));
    assert_eq!(
        control.step(&mut ownership).unwrap(),
        SensorControlStep::Rearmed
    );

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn a_non_sensor_failure_during_recovery_faults_without_automatic_reentry() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame]);
    script.borrow_mut().fail_cpu = true;
    control.step(&mut ownership).unwrap();

    let marker = ownership.platform().operations().len();
    {
        let mut script = script.borrow_mut();
        script.fail_cpu = false;
        script.fail_power = true;
    }
    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::RecoveryLatched {
            fault: SampleSetError::Input {
                input: fan_control_core::RequiredInput::Power,
                ..
            }
        })
    ));
    assert_eq!(control.state(), SensorControlState::Faulted);
    assert_eq!(script.borrow().rediscoveries, 1);
    assert!(
        ownership.platform().operations()[marker..]
            .iter()
            .all(|operation| !is_pwm_write(operation))
    );
    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::Faulted)
    ));

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn auto_confirmed_recovery_containment_latches_and_drops_sensor_bindings() {
    let (platform, device) = fixture();
    let interference = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&interference));
    let auto_confirmed = platform.firmware_auto_confirmation();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame]);
    let drop_observations = Rc::new(RefCell::new(Vec::new()));
    script.borrow_mut().source_drop_probe =
        Some((Rc::clone(&auto_confirmed), Rc::clone(&drop_observations)));
    script.borrow_mut().fail_cpu = true;
    auto_confirmed.set(false);
    interference.set(RuntimeInterference::RestorationDeadlineAuto);

    let Err(TransientSensorControlError::RecoveryLatchContained {
        fault:
            SampleSetError::Input {
                input: fan_control_core::RequiredInput::Cpu,
                ..
            },
        restoration,
        containment,
    }) = control.step(&mut ownership)
    else {
        panic!("Auto-confirmed recovery containment must report a permanent latch")
    };
    assert!(matches!(
        *restoration,
        fan_control_core::FirmwareAutoRestorationError::DeadlineExceeded { attempts: 1, .. }
    ));
    assert!(containment.restoration_confirmed());
    assert!(matches!(
        containment.cpu(),
        fan_control_core::EmergencyFanStatus::FirmwareAuto
    ));
    assert!(matches!(
        containment.gpu(),
        fan_control_core::EmergencyFanStatus::FirmwareAuto
    ));
    assert_eq!(*drop_observations.borrow(), vec![true]);
    assert_eq!(control.state(), SensorControlState::Faulted);
    assert_eq!(script.borrow().rediscoveries, 0);
    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::Faulted)
    ));

    ownership.release().unwrap();
}

#[test]
fn failed_sensor_restoration_contains_at_maximum_without_rediscovery() {
    let (platform, device) = fixture();
    let interference = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&interference));
    let auto_confirmed = platform.firmware_auto_confirmation();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, armed) = arm_with_authority(&mut ownership, &device);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let (mut control, script) = recovery_control(armed, authority, vec![frame]);
    let drop_observations = Rc::new(RefCell::new(Vec::new()));
    script.borrow_mut().source_drop_probe =
        Some((Rc::clone(&auto_confirmed), Rc::clone(&drop_observations)));
    script.borrow_mut().fail_cpu = true;
    auto_confirmed.set(false);
    interference.set(RuntimeInterference::RestorationDeadlineCustom);

    let (result, diagnostic_events) = record_diagnostics(|| control.step(&mut ownership));
    let Err(TransientSensorControlError::RecoveryLatchCritical {
        fault:
            SampleSetError::Input {
                input: fan_control_core::RequiredInput::Cpu,
                ..
            },
        restoration,
        containment,
    }) = result
    else {
        panic!("failed sensor restoration must invoke critical containment")
    };
    assert_state_and_fault_diagnostic_sequence(
        &diagnostic_events,
        &[
            "fault:sensor-unavailable:sensor:cpu:temperature",
            "state:custom-control:restoring:sensor-fault",
            "fault:restoration-unconfirmed:none",
            "fault:containment-unconfirmed:none",
            "state:restoring:fault-latched:restoration-failed",
        ],
    );
    assert!(!containment.restoration_confirmed());
    let fan_control_core::FirmwareAutoRestorationError::DeadlineExceeded { attempts, cpu, gpu } =
        restoration
    else {
        panic!("the injected restoration deadline must be preserved")
    };
    assert_eq!(attempts, 1);
    assert!(!cpu.is_confirmed());
    assert!(!gpu.is_confirmed());
    assert!(matches!(
        containment.cpu(),
        fan_control_core::EmergencyFanStatus::MaximumConfirmed
    ));
    assert!(matches!(
        containment.gpu(),
        fan_control_core::EmergencyFanStatus::MaximumConfirmed
    ));
    assert_eq!(control.state(), SensorControlState::Faulted);
    assert_eq!(script.borrow().rediscoveries, 0);
    assert!(drop_observations.borrow().is_empty());
    assert!(matches!(
        control.step(&mut ownership),
        Err(TransientSensorControlError::Faulted)
    ));

    ownership.restore_firmware_auto(&device).unwrap();
    drop(control);
    assert_eq!(*drop_observations.borrow(), vec![true]);
    ownership.release().unwrap();
}

#[test]
fn restoration_invalidates_the_arming_receipt_before_sampling_or_output() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = healthy_control(armed);
    ownership.restore_firmware_auto(&device).unwrap();
    let mut sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);

    let (result, diagnostic_events) = record_diagnostics(|| {
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources)
    });
    assert!(matches!(
        result,
        Err(HealthyControlCycleError::StaleArmingReceipt)
    ));
    let fault = diagnostic_events
        .iter()
        .find(|event| {
            event.get("fault_id").map(|value| value.trim_matches('"')) == Some("device-changed")
        })
        .unwrap();
    assert_eq!(diagnostic_field(fault, "endpoint"), "none");
    assert_eq!(
        (sources.cpu_reads, sources.gpu_reads, sources.power_reads),
        (0, 0, 0)
    );
    ownership.release().unwrap();
}

#[test]
fn runtime_sample_gate_rejects_a_missed_cadence_before_reading_sources() {
    let mut platform = FakePlatform::new();
    let mut gate = ControlCycleSampleGate::new();
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let mut sources = CountingSources::new(vec![frame, frame]);
    gate.sample(&mut sources, &mut platform).unwrap();
    platform.advance_monotonic_time_to(Duration::from_millis(2_101));

    assert!(matches!(
        gate.sample(&mut sources, &mut platform),
        Err(SampleSetError::CadenceMissed { .. })
    ));
    assert_eq!(
        (sources.cpu_reads, sources.gpu_reads, sources.power_reads),
        (1, 1, 1)
    );
}

#[test]
fn runtime_sample_gate_accepts_the_exact_upper_jitter_boundary_with_fresh_inputs() {
    let mut gate = ControlCycleSampleGate::new();
    let mut clock = MutableClock::new(Duration::ZERO);
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let mut sources = CountingSources::new(vec![frame, frame]);
    gate.sample(&mut sources, &mut clock).unwrap();
    clock.now = Duration::from_millis(2_100);

    gate.sample(&mut sources, &mut clock).unwrap();

    assert_eq!(
        (sources.cpu_reads, sources.gpu_reads, sources.power_reads),
        (2, 2, 2)
    );
}

#[test]
fn runtime_sample_gate_rejects_clock_regression_without_delaying_or_sampling() {
    let mut gate = ControlCycleSampleGate::new();
    let mut clock = MutableClock::new(Duration::from_secs(10));
    let frame = Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    };
    let mut sources = CountingSources::new(vec![frame, frame]);
    gate.sample(&mut sources, &mut clock).unwrap();
    clock.now = Duration::from_secs(5);

    assert!(matches!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::ClockWentBackwards)
    ));
    assert_eq!(clock.delay_count, 0);
    assert_eq!(
        (sources.cpu_reads, sources.gpu_reads, sources.power_reads),
        (1, 1, 1)
    );
}

struct MutableClock {
    now: Duration,
    delay_count: usize,
}

impl MutableClock {
    const fn new(now: Duration) -> Self {
        Self {
            now,
            delay_count: 0,
        }
    }
}

impl Clock for MutableClock {
    fn monotonic_now(&mut self) -> Duration {
        self.now
    }

    fn delay(&mut self, duration: Duration) {
        self.delay_count += 1;
        self.now = self.now.saturating_add(duration);
    }
}

fn arm<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &fan_control_core::AcerHwmonDevice,
) -> (ValidatedConfig, fan_control_core::ArmedFanControl)
where
    P: fan_control_core::BoundedIdentityBoundFileAccess
        + fan_control_core::Clock
        + fan_control_core::IdentityBoundFileAccess
        + fan_control_core::RuntimeLockAccess,
{
    let (authority, armed) = arm_with_authority(ownership, device);
    let candidate = protected_config(&PROTECTED_POLICY);
    drop(authority);
    (candidate, armed)
}

fn arm_with_authority<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &fan_control_core::AcerHwmonDevice,
) -> (
    fan_control_core::AdmittedPolicyAuthority,
    fan_control_core::ArmedFanControl,
)
where
    P: fan_control_core::BoundedIdentityBoundFileAccess
        + fan_control_core::Clock
        + fan_control_core::IdentityBoundFileAccess
        + fan_control_core::RuntimeLockAccess,
{
    arm_with_policy_authority(ownership, device, &PROTECTED_POLICY)
}

fn arm_with_policy_authority<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &fan_control_core::AcerHwmonDevice,
    policy: &str,
) -> (
    fan_control_core::AdmittedPolicyAuthority,
    fan_control_core::ArmedFanControl,
)
where
    P: fan_control_core::BoundedIdentityBoundFileAccess
        + fan_control_core::Clock
        + fan_control_core::IdentityBoundFileAccess
        + fan_control_core::RuntimeLockAccess,
{
    ownership.restore_firmware_auto(device).unwrap();
    let authority = admit_policy_authority(
        ownership,
        device,
        policy,
        &matching_record(policy),
        &[matching_observation_for_policy(policy)],
    )
    .unwrap();
    let candidate = protected_config(policy);
    let mut gate = FreshSampleGate::new();
    let mut sources = CountingSources::new(vec![
        Frame {
            cpu: 70.0,
            gpu: 65.0,
            power: ExternalPower::Connected,
        },
        Frame {
            cpu: 70.0,
            gpu: 65.0,
            power: ExternalPower::Connected,
        },
    ]);
    assert_eq!(
        ownership
            .collect_fresh_sample(device, &mut gate, &mut sources)
            .unwrap(),
        OwnershipSampleReadiness::AwaitingSecondSample
    );
    ownership.delay(Duration::from_secs(2));
    let OwnershipSampleReadiness::Ready(sample) = ownership
        .collect_fresh_sample(device, &mut gate, &mut sources)
        .unwrap()
    else {
        panic!("second complete sample must arm the freshness gate")
    };
    let armed = arm_both_fans_safely(ownership, device, &authority, &candidate, sample).unwrap();
    (authority, armed)
}

fn fixture() -> (FakePlatform, fan_control_core::AcerHwmonDevice) {
    let root = Path::new(ACER_ROOT);
    let mut platform = FakePlatform::new();
    insert_acer_device(&mut platform, root);
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    (platform, device)
}

fn insert_acer_device(platform: &mut FakePlatform, root: impl AsRef<Path>) {
    let root = root.as_ref();
    platform.insert_file_with_permissions(root.join("name"), "acer\n", FilePermissions::READ_ONLY);
    for channel in 1..=2 {
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}")),
            "128\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}_enable")),
            "2\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("fan{channel}_input")),
            "3000\n",
            FilePermissions::READ_ONLY,
        );
    }
}

fn assert_changed_write_is_immediately_read(
    operations: &[PlatformOperation],
    path: &Path,
    pwm: u8,
) {
    let index = operations
        .iter()
        .position(|operation| {
            matches!(operation, PlatformOperation::Write { path: actual, contents }
                if actual == path && contents == &pwm.to_string())
        })
        .unwrap();
    assert!(
        matches!(operations.get(index + 1), Some(PlatformOperation::Read(actual)) if actual == path)
    );
}

fn is_pwm_write(operation: &PlatformOperation) -> bool {
    matches!(operation, PlatformOperation::Write { path, .. }
        if path == cpu_pwm() || path == gpu_pwm())
}

fn cpu_enable() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm1_enable")
}

fn gpu_enable() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm2_enable")
}

fn cpu_pwm() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm1")
}

fn gpu_pwm() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/pwm2")
}
