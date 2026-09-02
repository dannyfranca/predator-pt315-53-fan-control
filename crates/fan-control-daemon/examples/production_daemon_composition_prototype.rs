//! PROTOTYPE — fake-platform-only evidence for the production daemon composition seam.
//!
//! This deliberately lives as an example, not production code. It invokes the real core safety
//! APIs while replacing every host boundary with an in-memory fake.

use std::{
    cell::{Cell, RefCell},
    convert::Infallible,
    io::Read,
    path::Path,
    rc::Rc,
    sync::OnceLock,
    time::Duration,
};

use fan_control_core::{
    AcerHwmonDevice, AdmittedPolicyAuthority, CompatibilityDeclarationV1, CompatibilityObservation,
    ControlLoopHeartbeat, ControllerOwnership, EvidenceCompleteness, ExternalPower, FakePlatform,
    FanWriteBackend, FilePermissions, FreshSampleGate, IdentityBoundReadAccess, ObservedFanAbi,
    ObservedSample, OwnershipSampleReadiness, PolicyAuthorityAdmissionError,
    QUALIFICATION_RECORD_PATH, SUPERVISED_ENDURANCE_EVIDENCE_PATH, SampleCapture,
    SampleSourceError, SampleSources, SensorControlState, SensorControlStep, SensorSourceDiscovery,
    ServiceNotification, ServiceNotifier, ShutdownController, SupervisedControlIterationError,
    TemperatureCelsius, TransientSensorControl, TransientSensorControlError, ValidatedConfig,
    acquire_controller_ownership, admit_policy_authority, arm_both_fans_safely,
    parse_compatibility_v1, parse_config_v1, run_supervised_control_iteration, validate_config_v1,
};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

const PROTECTED_POLICY: &str = r#"schema_version = 2
qualification_id = "pt31553-v1"
policy_version = "1.0.0"

[compatibility]
schema_version = 1

[compatibility.hardware]
dmi_product_name = "Predator PT315-53"
dmi_board_name = "Civic_TLS"
bios_version = "V1.17"

[compatibility.kernel]
release = "7.1.8-cachyos-pt31553"
package = "linux-cachyos-pt31553"
source_commit = "0123456789abcdef0123456789abcdef01234567"
image_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
image_signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[compatibility.module]
name = "acer_wmi"
path = "/usr/lib/modules/7.1.8-cachyos-pt31553/kernel/drivers/platform/x86/acer-wmi.ko.zst"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
signer_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
vermagic = "7.1.8-cachyos-pt31553 SMP preempt mod_unload"
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

[calibration.cpu]
floor_basis_points = 3000
response_deadline_millis = 4000
anchors = [
  { duty_basis_points = 3000, median_rpm = 2500 },
  { duty_basis_points = 10000, median_rpm = 3500 },
]

[calibration.gpu]
floor_basis_points = 2500
response_deadline_millis = 4000
anchors = [
  { duty_basis_points = 2500, median_rpm = 2500 },
  { duty_basis_points = 10000, median_rpm = 3500 },
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
  { temperature_c = 90, demand_percent = 100 },
]
gpu_curve = [
  { temperature_c = 35, demand_percent = 30 },
  { temperature_c = 82, demand_percent = 100 },
]
"#;

fn main() {
    println!("PROTOTYPE: fake adapters only; no host fan, sysfs, NVML, or systemd access\n");
    healthy_startup_and_iteration();
    rejected_admission();
    mid_cycle_sensor_fault();
    graceful_termination();
    restoration_failure();
    println!("\nVERDICT CANDIDATE");
    println!("  one owner keeps platform + runtime lock for the daemon lifetime");
    println!("  opaque core receipts cross phases; the daemon never recreates safety decisions");
    println!("  adapters stay narrow: startup inputs, sensor discovery, notifier, termination");
}

fn healthy_startup_and_iteration() {
    let mut platform = fixture("2\n", "2\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let device = ownership
        .discover_acer_hwmon(Path::new(HWMON_ROOT))
        .unwrap();
    let mut shutdown = ShutdownController::new();
    let (authority, armed) = admit_and_arm(&mut ownership, &device);
    let fail_cpu = Rc::new(Cell::new(false));
    let (mut control, mut heartbeat, notifications) = runtime(
        armed,
        authority,
        shutdown.request_handle(),
        Rc::clone(&fail_cpu),
    );

    let step = run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat)
        .expect("healthy control must complete");
    assert!(matches!(step, SensorControlStep::Completed(_)));
    assert_eq!(
        *notifications.borrow(),
        [ServiceNotification::Ready, ServiceNotification::Watchdog]
    );

    shutdown.cleanup(&mut ownership, &device).unwrap();
    ownership.release().unwrap();
    assert_auto(&platform);
    println!("PASS healthy: admitted → armed → controlled → READY → WATCHDOG → Auto → released");
}

fn rejected_admission() {
    let mut platform = fixture("2\n", "2\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let device = ownership
        .discover_acer_hwmon(Path::new(HWMON_ROOT))
        .unwrap();
    ownership.restore_firmware_auto(&device).unwrap();
    let mut observation = matching_observation();
    observation.secure_boot_enabled = false;

    let result = admit_policy_authority(
        &mut ownership,
        &device,
        PROTECTED_POLICY,
        Path::new(QUALIFICATION_RECORD_PATH),
        &[observation],
    );
    assert!(matches!(
        result,
        Err(PolicyAuthorityAdmissionError::Rejected(_))
    ));
    ownership.release().unwrap();
    assert_auto(&platform);
    println!("PASS rejected admission: no authority receipt; Auto reconfirmed; lock releasable");
}

fn mid_cycle_sensor_fault() {
    let mut platform = fixture("2\n", "2\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let device = ownership
        .discover_acer_hwmon(Path::new(HWMON_ROOT))
        .unwrap();
    let mut shutdown = ShutdownController::new();
    let (authority, armed) = admit_and_arm(&mut ownership, &device);
    let fail_cpu = Rc::new(Cell::new(false));
    let (mut control, mut heartbeat, notifications) = runtime(
        armed,
        authority,
        shutdown.request_handle(),
        Rc::clone(&fail_cpu),
    );

    assert!(matches!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::Completed(_)
    ));
    ownership.delay(Duration::from_secs(2));
    fail_cpu.set(true);
    assert!(matches!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::FirmwareAutoRestored { .. }
    ));
    assert_eq!(control.state(), SensorControlState::FirmwareAutoRecovery);
    assert_eq!(
        *notifications.borrow(),
        [
            ServiceNotification::Ready,
            ServiceNotification::Watchdog,
            ServiceNotification::Watchdog,
        ]
    );
    assert_auto(ownership.platform());

    shutdown.cleanup(&mut ownership, &device).unwrap();
    ownership.release().unwrap();
    println!(
        "PASS mid-cycle fault: control stopped; Auto restored in-call; recovery owns next step"
    );
}

fn graceful_termination() {
    let mut platform = fixture("2\n", "2\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let device = ownership
        .discover_acer_hwmon(Path::new(HWMON_ROOT))
        .unwrap();
    let mut shutdown = ShutdownController::new();
    let (authority, armed) = admit_and_arm(&mut ownership, &device);
    let (mut control, mut heartbeat, _) = runtime(
        armed,
        authority,
        shutdown.request_handle(),
        Rc::new(Cell::new(false)),
    );

    assert!(matches!(
        run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat).unwrap(),
        SensorControlStep::Completed(_)
    ));
    shutdown.request();
    let stopped = run_supervised_control_iteration(&mut control, &mut ownership, &mut heartbeat);
    assert!(matches!(
        stopped,
        Err(SupervisedControlIterationError::Control(
            TransientSensorControlError::ShutdownRequested
        ))
    ));
    shutdown.cleanup(&mut ownership, &device).unwrap();
    ownership.release().unwrap();
    assert_auto(&platform);
    println!(
        "PASS termination: request is permanent; no next demand; cleanup confirms Auto before release"
    );
}

fn restoration_failure() {
    let mut platform = fixture("1\n", "1\n");
    let device =
        fan_control_core::discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    platform.set_file_permissions(cpu_enable(), FilePermissions::READ_ONLY);
    platform.set_file_permissions(gpu_enable(), FilePermissions::READ_ONLY);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();

    let result = admit_policy_authority(
        &mut ownership,
        &device,
        PROTECTED_POLICY,
        Path::new(QUALIFICATION_RECORD_PATH),
        &[matching_observation()],
    );
    assert!(matches!(
        result,
        Err(PolicyAuthorityAdmissionError::RestorationFailed { .. })
    ));
    let containment = ownership.contain_custom_fans_at_maximum(&device);
    assert!(!containment.restoration_confirmed());
    assert!(ownership.release().is_err());
    assert_eq!(platform.file_contents(cpu_pwm()), Some("255"));
    assert_eq!(platform.file_contents(gpu_pwm()), Some("255"));
    println!("PASS restoration failure: maximum containment attempted; ownership cannot release");
}

fn admit_and_arm(
    ownership: &mut ControllerOwnership<'_, FakePlatform>,
    device: &AcerHwmonDevice,
) -> (AdmittedPolicyAuthority, fan_control_core::ArmedFanControl) {
    ownership.restore_firmware_auto(device).unwrap();
    let authority = admit_policy_authority(
        ownership,
        device,
        PROTECTED_POLICY,
        Path::new(QUALIFICATION_RECORD_PATH),
        &[matching_observation()],
    )
    .unwrap();
    let candidate = protected_config();
    let mut gate = FreshSampleGate::new();
    let mut sources = FixedSources;
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
        panic!("second sample did not open the arming gate")
    };
    let armed = arm_both_fans_safely(ownership, device, &authority, &candidate, sample).unwrap();
    (authority, armed)
}

type PrototypeRuntime = (
    TransientSensorControl<PrototypeDiscovery>,
    ControlLoopHeartbeat<RecordingNotifier>,
    Rc<RefCell<Vec<ServiceNotification>>>,
);

fn runtime(
    armed: fan_control_core::ArmedFanControl,
    authority: AdmittedPolicyAuthority,
    shutdown: fan_control_core::ShutdownRequest,
    fail_cpu: Rc<Cell<bool>>,
) -> PrototypeRuntime {
    let notifications = Rc::new(RefCell::new(Vec::new()));
    let sources = RuntimeSources {
        fail_cpu: Rc::clone(&fail_cpu),
    };
    let discovery = PrototypeDiscovery { fail_cpu };
    (
        TransientSensorControl::from_armed(armed, authority, shutdown, discovery, sources),
        ControlLoopHeartbeat::new(RecordingNotifier(Rc::clone(&notifications))),
        notifications,
    )
}

#[derive(Debug)]
struct FixedSources;

impl SampleSources for FixedSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(capture.capture(TemperatureCelsius::try_from(70.0).unwrap()))
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(capture.capture(TemperatureCelsius::try_from(65.0).unwrap()))
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
    fail_cpu: Rc<Cell<bool>>,
}

impl SampleSources for RuntimeSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        if self.fail_cpu.get() {
            return Err(SampleSourceError::new("prototype CPU sensor fault"));
        }
        FixedSources.sample_cpu(capture)
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        FixedSources.sample_gpu(capture)
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        FixedSources.observe_external_power(capture)
    }
}

#[derive(Debug)]
struct PrototypeDiscovery {
    fail_cpu: Rc<Cell<bool>>,
}

impl SensorSourceDiscovery for PrototypeDiscovery {
    type Sources = RuntimeSources;

    fn rediscover(
        &mut self,
        _files: &mut dyn IdentityBoundReadAccess,
    ) -> Result<Self::Sources, SampleSourceError> {
        Ok(RuntimeSources {
            fail_cpu: Rc::clone(&self.fail_cpu),
        })
    }
}

struct RecordingNotifier(Rc<RefCell<Vec<ServiceNotification>>>);

impl ServiceNotifier for RecordingNotifier {
    type Error = Infallible;

    fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error> {
        self.0.borrow_mut().push(notification);
        Ok(())
    }
}

fn fixture(cpu_mode: &str, gpu_mode: &str) -> FakePlatform {
    let mut platform = FakePlatform::new();
    platform.insert_file_with_permissions(
        QUALIFICATION_RECORD_PATH,
        matching_record(),
        FilePermissions::READ_ONLY,
    );
    platform.insert_file_with_permissions(
        SUPERVISED_ENDURANCE_EVIDENCE_PATH,
        matching_endurance_evidence(),
        FilePermissions::READ_ONLY,
    );
    let root = Path::new(ACER_ROOT);
    platform.insert_file_with_permissions(root.join("name"), "acer\n", FilePermissions::READ_ONLY);
    for channel in 1..=2 {
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}")),
            "128\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}_enable")),
            if channel == 1 { cpu_mode } else { gpu_mode },
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("fan{channel}_input")),
            "3000\n",
            FilePermissions::READ_ONLY,
        );
    }
    platform
}

fn compatibility_declaration() -> CompatibilityDeclarationV1 {
    let source = PROTECTED_POLICY
        .split_once("[compatibility]\n")
        .unwrap()
        .1
        .split_once("\n[calibration.cpu]\n")
        .unwrap()
        .0
        .replace("[compatibility.", "[");
    parse_compatibility_v1(&source).unwrap()
}

fn matching_observation() -> CompatibilityObservation {
    let declaration = compatibility_declaration();
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

fn protected_config() -> ValidatedConfig {
    let source = PROTECTED_POLICY
        .split_once("[protected]\n")
        .unwrap()
        .1
        .replace("[protected.", "[");
    validate_config_v1(parse_config_v1(&source).unwrap()).unwrap()
}

fn matching_record() -> String {
    let evidence = matching_endurance_evidence();
    let completed_at =
        serde_json::from_str::<serde_json::Value>(evidence).unwrap()["completed_at"].clone();
    serde_json::to_string(&serde_json::json!({
        "schema_version": 2,
        "qualification_id": "pt31553-v1",
        "policy_version": "1.0.0",
        "protected_policy_sha256": sha256(PROTECTED_POLICY),
        "compatibility": compatibility_declaration(),
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
    .unwrap()
}

fn matching_endurance_evidence() -> &'static str {
    static EVIDENCE: OnceLock<String> = OnceLock::new();
    EVIDENCE.get_or_init(|| {
        let mut compressed = GzDecoder::new(
            &include_bytes!("../../../qualification/supervised-endurance-v2.json.gz")[..],
        );
        let mut source = String::new();
        compressed.read_to_string(&mut source).unwrap();
        let mut record: serde_json::Value = serde_json::from_str(&source).unwrap();
        record["qualification_envelope"]["protected_policy_sha256"] =
            sha256(PROTECTED_POLICY).into();
        record["qualification_envelope"]["compatibility"] =
            serde_json::to_value(compatibility_declaration()).unwrap();
        serde_json::to_string(&record).unwrap()
    })
}

fn sha256(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
}

fn assert_auto(platform: &FakePlatform) {
    assert_eq!(platform.file_contents(cpu_enable()), Some("2"));
    assert_eq!(platform.file_contents(gpu_enable()), Some("2"));
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
