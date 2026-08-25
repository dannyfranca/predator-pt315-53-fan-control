use std::{
    cell::Cell,
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use fan_control_core::{
    BoundedFileAccess, BoundedIdentityBoundFileAccess, Clock, CompatibilityDeclarationV1,
    CompatibilityObservation, ControlCycleOperation, ControlCycleReadback, ControlCycleSampleGate,
    ControllerOwnership, EvidenceCompleteness, ExternalPower, FakePlatform, FakeRuntimeLock, Fan,
    FanWriteBackend, FileAccess, FileIdentity, FilePermissions, FreshSampleGate, HealthyControl,
    HealthyControlCycleError, IdentityBoundFileAccess, ObservedFanAbi, ObservedSample,
    OwnershipSampleReadiness, PlatformError, PlatformOperation, RuntimeLockAccess,
    RuntimeLockError, SampleCapture, SampleSetError, SampleSourceError, SampleSources,
    ServiceAccess, TemperatureCelsius, ValidatedConfig, acquire_controller_ownership,
    admit_policy_authority, arm_both_fans_safely, calculate_fan_outputs, discover_acer_hwmon,
    parse_compatibility_v1, parse_config_v1, run_healthy_control_cycle, validate_config_v1,
};
use sha2::{Digest, Sha256};

const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

const PROTECTED_POLICY: &str = r#"schema_version = 1
qualification_id = "pt31553-v1"
policy_version = "1.0.0"

[compatibility]
schema_version = 1

[compatibility.hardware]
dmi_product_name = "Predator PT315-53"
dmi_board_name = "Civic_TLS"
bios_version = "V1.17"

[compatibility.kernel]
release = "7.1.8-1-cachyos-pt31553"
package = "linux-cachyos-pt31553"
source_commit = "0123456789abcdef0123456789abcdef01234567"
image_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
image_signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[compatibility.module]
name = "acer_wmi"
path = "/usr/lib/modules/7.1.8-1-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
vermagic = "7.1.8-1-cachyos-pt31553 SMP preempt mod_unload"
provenance = "in-tree"

[compatibility.secure_boot]
required = true

[compatibility.fan_control]
backend = "acer-hwmon"
hwmon_name = "acer"
endpoints = ["pwm1", "pwm1_enable", "fan1_input", "pwm2", "pwm2_enable", "fan2_input"]
forbidden_capabilities = [
  "force-caps",
  "ec-raw-mode",
  "predator-v4-override",
  "direct-wmi",
  "raw-ec",
  "replacement-wmi-module",
  "alternate-fan-write-backend",
]

[protected]
schema_version = 1

[protected.control]
hysteresis_celsius = 3
lower_demand_hold_seconds = 10
max_down_ramp_percent_per_second = 1.0

[protected.fans.cpu]
minimum_duty_percent = 30

[protected.fans.gpu]
minimum_duty_percent = 25

[protected.profiles.ac]
cpu_curve = [
  { temperature_c = 40, demand_percent = 30 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 35, demand_percent = 30 },
  { temperature_c = 82, demand_percent = 100 },
]

[protected.profiles.battery]
cpu_curve = [
  { temperature_c = 40, demand_percent = 30 },
  { temperature_c = 70, demand_percent = 50 },
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 35, demand_percent = 30 },
  { temperature_c = 65, demand_percent = 50 },
  { temperature_c = 82, demand_percent = 100 },
]
"#;

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

#[test]
fn one_cycle_uses_one_fresh_snapshot_and_verifies_each_changed_output() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (candidate, armed) = arm(&mut ownership, &device);
    let mut control = HealthyControl::from_armed(armed);
    let mut sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);
    let marker = ownership.platform().operations().len();

    let completed = run_healthy_control_cycle(&mut ownership, &mut control, &mut sources).unwrap();

    let expected = calculate_fan_outputs(
        &candidate,
        TemperatureCelsius::try_from(70.0).unwrap(),
        TemperatureCelsius::try_from(65.0).unwrap(),
        ExternalPower::Connected,
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
fn repeated_cycles_wait_for_two_second_cadence_and_never_reuse_samples() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = HealthyControl::from_armed(armed);
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
    let mut control = HealthyControl::from_armed(armed);
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
    let mut control = HealthyControl::from_armed(armed);
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
    let mut control = HealthyControl::from_armed(armed);
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
fn backing_device_rebind_is_rejected_before_normal_output() {
    let (platform, device) = fixture();
    let interference = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&interference));
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = HealthyControl::from_armed(armed);
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

fn run_interfered_cycle(
    interference: RuntimeInterference,
) -> (HealthyControlCycleError, Vec<PlatformOperation>) {
    let (platform, device) = fixture();
    let injection = Rc::new(Cell::new(RuntimeInterference::None));
    let mut platform = InterferingPlatform::new(platform, Rc::clone(&injection));
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = HealthyControl::from_armed(armed);
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuntimeInterference {
    None,
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
    CpuModeBeforeRead,
    GpuModeBeforeRead,
    CpuModeBeforeWrite,
    GpuModeBeforeWrite,
    CpuModeBeforeGpuWrite,
    GpuModeBeforeCpuWrite,
    RebindCpuEndpointBeforeGpuWrite,
    RebindGpuEndpointBeforeCpuWrite,
    CpuDutyAfterWrite,
    GpuDutyAfterWrite,
}

struct InterferingPlatform {
    inner: FakePlatform,
    interference: Rc<Cell<RuntimeInterference>>,
    last_normal_write: Option<String>,
}

impl InterferingPlatform {
    fn new(inner: FakePlatform, interference: Rc<Cell<RuntimeInterference>>) -> Self {
        Self {
            inner,
            interference,
            last_normal_write: None,
        }
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
        self.inner.read_before(path, deadline)
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
        if (interference == RuntimeInterference::CpuModeBeforeRead && child == "pwm1_enable")
            || (interference == RuntimeInterference::GpuModeBeforeRead && child == "pwm2_enable")
        {
            self.interference.set(RuntimeInterference::None);
            self.inner.insert_file(directory.join(child), "2\n");
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
    let mut control = HealthyControl::from_armed(armed);
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
fn restoration_invalidates_the_arming_receipt_before_sampling_or_output() {
    let (mut platform, device) = fixture();
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (_, armed) = arm(&mut ownership, &device);
    let mut control = HealthyControl::from_armed(armed);
    ownership.restore_firmware_auto(&device).unwrap();
    let mut sources = CountingSources::new(vec![Frame {
        cpu: 70.0,
        gpu: 65.0,
        power: ExternalPower::Connected,
    }]);

    assert!(matches!(
        run_healthy_control_cycle(&mut ownership, &mut control, &mut sources),
        Err(HealthyControlCycleError::StaleArmingReceipt)
    ));
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
    ownership.restore_firmware_auto(device).unwrap();
    let authority = admit_policy_authority(
        ownership,
        device,
        PROTECTED_POLICY,
        &matching_record(PROTECTED_POLICY),
        &[matching_observation_for_policy(PROTECTED_POLICY)],
    )
    .unwrap();
    let candidate = protected_config(PROTECTED_POLICY);
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
    (candidate, armed)
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
            if channel == 1 { "2400\n" } else { "2600\n" },
            FilePermissions::READ_ONLY,
        );
    }
}

fn matching_observation_for_policy(policy: &str) -> CompatibilityObservation {
    let declaration = compatibility_declaration(policy);
    CompatibilityObservation {
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
    }
}

fn compatibility_declaration(policy: &str) -> CompatibilityDeclarationV1 {
    let start = policy.find("[compatibility]\n").unwrap();
    let end = policy.find("\n[protected]\n").unwrap();
    let source = policy[start..end]
        .replacen("[compatibility]\n", "", 1)
        .replace("[compatibility.", "[");
    parse_compatibility_v1(&source).unwrap()
}

fn protected_config(policy: &str) -> ValidatedConfig {
    let start = policy.find("[protected]\n").unwrap();
    let source = policy[start..]
        .replacen("[protected]\n", "", 1)
        .replace("[protected.", "[");
    validate_config_v1(parse_config_v1(&source).unwrap()).unwrap()
}

fn matching_record(policy: &str) -> String {
    format!(
        r#"{{"schema_version":1,"qualification_id":"pt31553-v1","policy_version":"1.0.0","protected_policy_sha256":"{}","compatibility":{{"schema_version":1,"hardware":{{"dmi_product_name":"Predator PT315-53","dmi_board_name":"Civic_TLS","bios_version":"V1.17"}},"kernel":{{"release":"7.1.8-1-cachyos-pt31553","package":"linux-cachyos-pt31553","source_commit":"{}","image_sha256":"{}","image_signer_fingerprint":"{}"}},"module":{{"name":"acer_wmi","path":"/usr/lib/modules/7.1.8-1-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst","sha256":"{}","signer_fingerprint":"{}","vermagic":"7.1.8-1-cachyos-pt31553 SMP preempt mod_unload","provenance":"in-tree"}},"secure_boot":{{"required":true}},"fan_control":{{"backend":"acer-hwmon","hwmon_name":"acer","endpoints":["pwm1","pwm1_enable","fan1_input","pwm2","pwm2_enable","fan2_input"],"forbidden_capabilities":["force-caps","ec-raw-mode","predator-v4-override","direct-wmi","raw-ec","replacement-wmi-module","alternate-fan-write-backend"]}}}}}}"#,
        sha256(policy),
        SOURCE_COMMIT,
        HASH_A,
        HASH_B,
        HASH_A,
        HASH_B,
    )
}

fn sha256(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
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
