//! Allowlisted structured runtime events for journald.
//!
//! Event payloads deliberately accept only domain enums and bounded numeric values. Raw errors,
//! configuration, evidence, paths, identifiers, and source payloads never enter the default log
//! contract.

use std::{collections::BTreeMap, fmt, io, os::unix::net::UnixDatagram, path::Path};

use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

use crate::{DemandPercent, ExternalPower, Pwm, RequiredInput, SampleSetError, TemperatureCelsius};

const JOURNALD_SOCKET: &str = "/run/systemd/journal/socket";
#[cfg(debug_assertions)]
const TEST_JOURNALD_SOCKET_ENV: &str = "PT31553_TEST_JOURNALD_SOCKET";
const DIAGNOSTIC_CONTRACT_MARKER: &str = "pt31553.typed-runtime-diagnostics.v1";

pub const STATE_TRANSITION_EVENT_ID: &str = "pt31553.state-transition.v1";
pub const RUNTIME_FAULT_EVENT_ID: &str = "pt31553.runtime-fault.v1";
pub const CONTROL_CYCLE_EVENT_ID: &str = "pt31553.control-cycle.v1";
pub const RESTORATION_ATTEMPT_EVENT_ID: &str = "pt31553.restoration-attempt.v1";

const RUNTIME_STATE_IDS: &[&str] = &[
    RuntimeState::Unqualified.id(),
    RuntimeState::FirmwareAuto.id(),
    RuntimeState::Arming.id(),
    RuntimeState::CustomControl.id(),
    RuntimeState::Restoring.id(),
    RuntimeState::EmergencyContainment.id(),
    RuntimeState::FaultLatched.id(),
];
const RUNTIME_TRANSITION_IDS: &[&str] = &[
    RuntimeTransition::TwoFreshSamples.id(),
    RuntimeTransition::ArmingConfirmed.id(),
    RuntimeTransition::SensorFault.id(),
    RuntimeTransition::ControlFault.id(),
    RuntimeTransition::RestorationConfirmed.id(),
    RuntimeTransition::RestorationFailed.id(),
    RuntimeTransition::ContainmentActivated.id(),
    RuntimeTransition::RearmRequested.id(),
    RuntimeTransition::Shutdown.id(),
];
const RUNTIME_FAULT_IDS: &[&str] = &[
    RuntimeFault::OwnershipDenied.id(),
    RuntimeFault::ConfigurationRejected.id(),
    RuntimeFault::FirmwareAutoUnconfirmed.id(),
    RuntimeFault::SensorUnavailable.id(),
    RuntimeFault::SensorStale.id(),
    RuntimeFault::SensorFromFuture.id(),
    RuntimeFault::SensorLate.id(),
    RuntimeFault::CadenceMissed.id(),
    RuntimeFault::DeviceChanged.id(),
    RuntimeFault::PlatformOperation.id(),
    RuntimeFault::UnexpectedReadback.id(),
    RuntimeFault::TachometerMalformed.id(),
    RuntimeFault::TachometerOutOfBand.id(),
    RuntimeFault::DeadlineExceeded.id(),
    RuntimeFault::ShutdownRequested.id(),
    RuntimeFault::ArmingRejected.id(),
    RuntimeFault::RestorationUnconfirmed.id(),
    RuntimeFault::ContainmentUnconfirmed.id(),
];
const RUNTIME_ENDPOINT_IDS: &[&str] = &[
    "none",
    RuntimeEndpoint::CpuTemperature.id(),
    RuntimeEndpoint::GpuTemperature.id(),
    RuntimeEndpoint::ExternalPower.id(),
    RuntimeEndpoint::CpuPwm.id(),
    RuntimeEndpoint::CpuEnable.id(),
    RuntimeEndpoint::CpuTachometer.id(),
    RuntimeEndpoint::GpuPwm.id(),
    RuntimeEndpoint::GpuEnable.id(),
    RuntimeEndpoint::GpuTachometer.id(),
];
const RESTORATION_READBACK_IDS: &[&str] = &[
    RestorationReadback::FirmwareAuto.id(),
    RestorationReadback::Custom.id(),
    RestorationReadback::Other.id(),
    RestorationReadback::Unreadable.id(),
];

/// Installs the allowlisted native-journald sink when the system journal is available.
///
/// Journald metadata such as source paths and line numbers is deliberately omitted. Failure to
/// reach journald leaves diagnostics disabled without affecting fan-control behavior.
pub fn init_journald_diagnostics() {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os(TEST_JOURNALD_SOCKET_ENV) {
        let _ = init_journald_diagnostics_at(Path::new(&path));
        return;
    }
    let _ = init_journald_diagnostics_at(Path::new(JOURNALD_SOCKET));
}

fn init_journald_diagnostics_at(path: &Path) -> io::Result<()> {
    let layer = JournaldDiagnosticsLayer::connect(path)?;
    tracing_subscriber::registry()
        .with(layer)
        .try_init()
        .map_err(io::Error::other)
}

#[derive(Debug)]
struct JournaldDiagnosticsLayer {
    socket: UnixDatagram,
}

impl JournaldDiagnosticsLayer {
    fn connect(path: &Path) -> io::Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        socket.connect(path)?;
        Ok(Self { socket })
    }
}

impl<S> Layer<S> for JournaldDiagnosticsLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        if event.metadata().target() != "pt31553.runtime" {
            return;
        }

        let mut visitor = JournaldFieldVisitor::default();
        event.record(&mut visitor);
        if visitor.is_typed_contract_event() {
            let mut payload = Vec::with_capacity(512);
            put_native_field(
                &mut payload,
                "PRIORITY",
                match *event.metadata().level() {
                    tracing::Level::ERROR => "3",
                    tracing::Level::WARN => "4",
                    tracing::Level::INFO => "5",
                    tracing::Level::DEBUG => "6",
                    tracing::Level::TRACE => "7",
                },
            );
            for (name, value) in visitor.fields {
                if let Some(native_name) = native_field_name(&name) {
                    put_native_field(&mut payload, native_name, &value);
                }
            }
            let _ = self.socket.send(&payload);
        }
    }
}

#[derive(Default)]
struct JournaldFieldVisitor {
    fields: BTreeMap<String, String>,
}

impl JournaldFieldVisitor {
    fn record_value(&mut self, field: &tracing::field::Field, value: impl fmt::Display) {
        if field.name() == "diagnostic_contract" || native_field_name(field.name()).is_some() {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }
    }

    fn is_typed_contract_event(&self) -> bool {
        if self.field("diagnostic_contract") != Some(DIAGNOSTIC_CONTRACT_MARKER)
            || self.fields.values().any(|value| value.len() > 64)
        {
            return false;
        }
        match self.field("event_id") {
            Some(STATE_TRANSITION_EVENT_ID) => self.valid_state_transition(),
            Some(RUNTIME_FAULT_EVENT_ID) => self.valid_fault(),
            Some(CONTROL_CYCLE_EVENT_ID) => self.valid_control_cycle(),
            Some(RESTORATION_ATTEMPT_EVENT_ID) => self.valid_restoration_attempt(),
            _ => false,
        }
    }

    fn valid_state_transition(&self) -> bool {
        self.has_exact_fields(&[
            "diagnostic_contract",
            "event_id",
            "from_state",
            "to_state",
            "reason",
            "message",
        ]) && self.message_is("fan controller state transition")
            && self.field_is_one_of("from_state", RUNTIME_STATE_IDS)
            && self.field_is_one_of("to_state", RUNTIME_STATE_IDS)
            && self.field_is_one_of("reason", RUNTIME_TRANSITION_IDS)
    }

    fn valid_fault(&self) -> bool {
        self.has_exact_fields(&[
            "diagnostic_contract",
            "event_id",
            "fault_id",
            "endpoint",
            "message",
        ]) && self.message_is("fan controller fault")
            && self.field_is_one_of("fault_id", RUNTIME_FAULT_IDS)
            && self.field_is_one_of("endpoint", RUNTIME_ENDPOINT_IDS)
    }

    fn valid_control_cycle(&self) -> bool {
        self.has_exact_fields(&[
            "diagnostic_contract",
            "event_id",
            "cpu_temperature_celsius",
            "gpu_temperature_celsius",
            "external_power",
            "profile",
            "demand_percent",
            "cpu_pwm_endpoint",
            "cpu_command_pwm",
            "cpu_readback_pwm",
            "cpu_tachometer_endpoint",
            "cpu_rpm_command_pwm",
            "cpu_rpm",
            "gpu_pwm_endpoint",
            "gpu_command_pwm",
            "gpu_readback_pwm",
            "gpu_tachometer_endpoint",
            "gpu_rpm_command_pwm",
            "gpu_rpm",
            "message",
        ]) && self.message_is("completed fan control cycle")
            && self.finite_number("cpu_temperature_celsius")
            && self.finite_number("gpu_temperature_celsius")
            && self.field_is_one_of("external_power", &["connected", "disconnected", "unknown"])
            && self.field_is_one_of("profile", &["ac", "battery"])
            && self.number_in_range("demand_percent", 0.0, 100.0)
            && self.field("cpu_pwm_endpoint") == Some(RuntimeEndpoint::CpuPwm.id())
            && self.u8_number("cpu_command_pwm")
            && self.u8_number("cpu_readback_pwm")
            && self.field("cpu_tachometer_endpoint") == Some(RuntimeEndpoint::CpuTachometer.id())
            && self.u8_number("cpu_rpm_command_pwm")
            && self.u32_number("cpu_rpm")
            && self.field("gpu_pwm_endpoint") == Some(RuntimeEndpoint::GpuPwm.id())
            && self.u8_number("gpu_command_pwm")
            && self.u8_number("gpu_readback_pwm")
            && self.field("gpu_tachometer_endpoint") == Some(RuntimeEndpoint::GpuTachometer.id())
            && self.u8_number("gpu_rpm_command_pwm")
            && self.u32_number("gpu_rpm")
    }

    fn valid_restoration_attempt(&self) -> bool {
        self.has_exact_fields(&[
            "diagnostic_contract",
            "event_id",
            "attempt",
            "cpu_enable_endpoint",
            "cpu_write_succeeded",
            "cpu_mode_readback",
            "gpu_enable_endpoint",
            "gpu_write_succeeded",
            "gpu_mode_readback",
            "message",
        ]) && self.message_is("Firmware Auto restoration attempt")
            && matches!(
                self.field("attempt")
                    .and_then(|value| value.parse::<u8>().ok()),
                Some(1..=3)
            )
            && self.field("cpu_enable_endpoint") == Some(RuntimeEndpoint::CpuEnable.id())
            && self.field_is_one_of("cpu_write_succeeded", &["true", "false"])
            && self.field_is_one_of("cpu_mode_readback", RESTORATION_READBACK_IDS)
            && self.field("gpu_enable_endpoint") == Some(RuntimeEndpoint::GpuEnable.id())
            && self.field_is_one_of("gpu_write_succeeded", &["true", "false"])
            && self.field_is_one_of("gpu_mode_readback", RESTORATION_READBACK_IDS)
    }

    fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(|value| value.trim_matches('"'))
    }

    fn message_is(&self, expected: &str) -> bool {
        self.field("message") == Some(expected)
    }

    fn has_exact_fields(&self, expected: &[&str]) -> bool {
        self.fields.len() == expected.len()
            && expected.iter().all(|name| self.fields.contains_key(*name))
    }

    fn field_is_one_of(&self, name: &str, allowed: &[&str]) -> bool {
        self.field(name)
            .is_some_and(|value| allowed.contains(&value))
    }

    fn finite_number(&self, name: &str) -> bool {
        self.field(name)
            .and_then(|value| value.parse::<f64>().ok())
            .is_some_and(f64::is_finite)
    }

    fn number_in_range(&self, name: &str, minimum: f64, maximum: f64) -> bool {
        self.field(name)
            .and_then(|value| value.parse::<f64>().ok())
            .is_some_and(|value| value.is_finite() && (minimum..=maximum).contains(&value))
    }

    fn u8_number(&self, name: &str) -> bool {
        self.field(name)
            .is_some_and(|value| value.parse::<u8>().is_ok())
    }

    fn u32_number(&self, name: &str) -> bool {
        self.field(name)
            .is_some_and(|value| value.parse::<u32>().is_ok())
    }
}

impl Visit for JournaldFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_value(field, value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_value(field, value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_value(field, value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_value(field, value);
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.record_value(field, value);
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.record_value(field, format_args!("{value:?}"));
    }
}

fn put_native_field(payload: &mut Vec<u8>, name: &str, value: &str) {
    payload.extend_from_slice(name.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(&(value.len() as u64).to_le_bytes());
    payload.extend_from_slice(value.as_bytes());
    payload.push(b'\n');
}

fn native_field_name(name: &str) -> Option<&'static str> {
    Some(match name {
        "message" => "MESSAGE",
        "event_id" => "PT31553_EVENT_ID",
        "from_state" => "PT31553_FROM_STATE",
        "to_state" => "PT31553_TO_STATE",
        "reason" => "PT31553_REASON",
        "fault_id" => "PT31553_FAULT_ID",
        "endpoint" => "PT31553_ENDPOINT",
        "cpu_temperature_celsius" => "PT31553_CPU_TEMPERATURE_CELSIUS",
        "gpu_temperature_celsius" => "PT31553_GPU_TEMPERATURE_CELSIUS",
        "external_power" => "PT31553_EXTERNAL_POWER",
        "profile" => "PT31553_PROFILE",
        "demand_percent" => "PT31553_DEMAND_PERCENT",
        "cpu_pwm_endpoint" => "PT31553_CPU_PWM_ENDPOINT",
        "cpu_command_pwm" => "PT31553_CPU_COMMAND_PWM",
        "cpu_readback_pwm" => "PT31553_CPU_READBACK_PWM",
        "cpu_tachometer_endpoint" => "PT31553_CPU_TACHOMETER_ENDPOINT",
        "cpu_rpm_command_pwm" => "PT31553_CPU_RPM_COMMAND_PWM",
        "cpu_rpm" => "PT31553_CPU_RPM",
        "gpu_pwm_endpoint" => "PT31553_GPU_PWM_ENDPOINT",
        "gpu_command_pwm" => "PT31553_GPU_COMMAND_PWM",
        "gpu_readback_pwm" => "PT31553_GPU_READBACK_PWM",
        "gpu_tachometer_endpoint" => "PT31553_GPU_TACHOMETER_ENDPOINT",
        "gpu_rpm_command_pwm" => "PT31553_GPU_RPM_COMMAND_PWM",
        "gpu_rpm" => "PT31553_GPU_RPM",
        "attempt" => "PT31553_ATTEMPT",
        "cpu_enable_endpoint" => "PT31553_CPU_ENABLE_ENDPOINT",
        "cpu_write_succeeded" => "PT31553_CPU_WRITE_SUCCEEDED",
        "cpu_mode_readback" => "PT31553_CPU_MODE_READBACK",
        "gpu_enable_endpoint" => "PT31553_GPU_ENABLE_ENDPOINT",
        "gpu_write_succeeded" => "PT31553_GPU_WRITE_SUCCEEDED",
        "gpu_mode_readback" => "PT31553_GPU_MODE_READBACK",
        _ => return None,
    })
}

pub(crate) fn sample_fault(error: &SampleSetError) -> (RuntimeFault, Option<RuntimeEndpoint>) {
    let endpoint = match error {
        SampleSetError::Input { input, .. }
        | SampleSetError::Stale { input }
        | SampleSetError::Future { input }
        | SampleSetError::Late { input } => Some(sample_endpoint(*input)),
        _ => None,
    };
    let fault = match error {
        SampleSetError::FirmwareAutoUnconfirmed => RuntimeFault::FirmwareAutoUnconfirmed,
        SampleSetError::Input { .. } => RuntimeFault::SensorUnavailable,
        SampleSetError::Stale { .. } => RuntimeFault::SensorStale,
        SampleSetError::Future { .. } => RuntimeFault::SensorFromFuture,
        SampleSetError::Late { .. } => RuntimeFault::SensorLate,
        SampleSetError::CadenceMissed { .. } => RuntimeFault::CadenceMissed,
        SampleSetError::ClockWentBackwards
        | SampleSetError::DeadlineOverflow
        | SampleSetError::CaptureCycleOverflow => RuntimeFault::DeadlineExceeded,
    };
    (fault, endpoint)
}

const fn sample_endpoint(input: RequiredInput) -> RuntimeEndpoint {
    match input {
        RequiredInput::Cpu => RuntimeEndpoint::CpuTemperature,
        RequiredInput::Gpu => RuntimeEndpoint::GpuTemperature,
        RequiredInput::Power => RuntimeEndpoint::ExternalPower,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    Unqualified,
    FirmwareAuto,
    Arming,
    CustomControl,
    Restoring,
    EmergencyContainment,
    FaultLatched,
}

impl RuntimeState {
    const fn id(self) -> &'static str {
        match self {
            Self::Unqualified => "unqualified",
            Self::FirmwareAuto => "firmware-auto",
            Self::Arming => "arming",
            Self::CustomControl => "custom-control",
            Self::Restoring => "restoring",
            Self::EmergencyContainment => "emergency-containment",
            Self::FaultLatched => "fault-latched",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTransition {
    TwoFreshSamples,
    ArmingConfirmed,
    SensorFault,
    ControlFault,
    RestorationConfirmed,
    RestorationFailed,
    ContainmentActivated,
    RearmRequested,
    Shutdown,
}

impl RuntimeTransition {
    const fn id(self) -> &'static str {
        match self {
            Self::TwoFreshSamples => "two-fresh-samples",
            Self::ArmingConfirmed => "arming-confirmed",
            Self::SensorFault => "sensor-fault",
            Self::ControlFault => "control-fault",
            Self::RestorationConfirmed => "restoration-confirmed",
            Self::RestorationFailed => "restoration-failed",
            Self::ContainmentActivated => "containment-activated",
            Self::RearmRequested => "rearm-requested",
            Self::Shutdown => "shutdown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEndpoint {
    CpuTemperature,
    GpuTemperature,
    ExternalPower,
    CpuPwm,
    CpuEnable,
    CpuTachometer,
    GpuPwm,
    GpuEnable,
    GpuTachometer,
}

impl RuntimeEndpoint {
    const fn id(self) -> &'static str {
        match self {
            Self::CpuTemperature => "sensor:cpu:temperature",
            Self::GpuTemperature => "sensor:gpu:temperature",
            Self::ExternalPower => "power:external",
            Self::CpuPwm => "acer:cpu:pwm1",
            Self::CpuEnable => "acer:cpu:pwm1_enable",
            Self::CpuTachometer => "acer:cpu:fan1_input",
            Self::GpuPwm => "acer:gpu:pwm2",
            Self::GpuEnable => "acer:gpu:pwm2_enable",
            Self::GpuTachometer => "acer:gpu:fan2_input",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFault {
    OwnershipDenied,
    ConfigurationRejected,
    FirmwareAutoUnconfirmed,
    SensorUnavailable,
    SensorStale,
    SensorFromFuture,
    SensorLate,
    CadenceMissed,
    DeviceChanged,
    PlatformOperation,
    UnexpectedReadback,
    TachometerMalformed,
    TachometerOutOfBand,
    DeadlineExceeded,
    ShutdownRequested,
    ArmingRejected,
    RestorationUnconfirmed,
    ContainmentUnconfirmed,
}

impl RuntimeFault {
    const fn id(self) -> &'static str {
        match self {
            Self::OwnershipDenied => "ownership-denied",
            Self::ConfigurationRejected => "configuration-rejected",
            Self::FirmwareAutoUnconfirmed => "firmware-auto-unconfirmed",
            Self::SensorUnavailable => "sensor-unavailable",
            Self::SensorStale => "sensor-stale",
            Self::SensorFromFuture => "sensor-from-future",
            Self::SensorLate => "sensor-late",
            Self::CadenceMissed => "sample-cadence-missed",
            Self::DeviceChanged => "device-changed",
            Self::PlatformOperation => "platform-operation-failed",
            Self::UnexpectedReadback => "unexpected-readback",
            Self::TachometerMalformed => "tachometer-malformed",
            Self::TachometerOutOfBand => "tachometer-out-of-band",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::ShutdownRequested => "shutdown-requested",
            Self::ArmingRejected => "arming-rejected",
            Self::RestorationUnconfirmed => "restoration-unconfirmed",
            Self::ContainmentUnconfirmed => "containment-unconfirmed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanDiagnostic {
    pub command: Pwm,
    pub readback: Pwm,
    pub rpm_command: Pwm,
    pub rpm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ControlCycleDiagnostic {
    pub cpu_temperature: TemperatureCelsius,
    pub gpu_temperature: TemperatureCelsius,
    pub external_power: ExternalPower,
    pub demand: DemandPercent,
    pub cpu: FanDiagnostic,
    pub gpu: FanDiagnostic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorationReadback {
    FirmwareAuto,
    Custom,
    Other,
    Unreadable,
}

impl RestorationReadback {
    const fn id(self) -> &'static str {
        match self {
            Self::FirmwareAuto => "firmware-auto",
            Self::Custom => "custom",
            Self::Other => "other",
            Self::Unreadable => "unreadable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestorationFanDiagnostic {
    pub write_succeeded: bool,
    pub readback: RestorationReadback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestorationAttemptDiagnostic {
    pub attempt: u8,
    pub cpu: RestorationFanDiagnostic,
    pub gpu: RestorationFanDiagnostic,
}

pub fn emit_state_transition(from: RuntimeState, to: RuntimeState, reason: RuntimeTransition) {
    tracing::info!(
        target: "pt31553.runtime",
        diagnostic_contract = DIAGNOSTIC_CONTRACT_MARKER,
        event_id = STATE_TRANSITION_EVENT_ID,
        from_state = from.id(),
        to_state = to.id(),
        reason = reason.id(),
        "fan controller state transition"
    );
}

pub fn emit_fault(fault: RuntimeFault, endpoint: Option<RuntimeEndpoint>) {
    tracing::error!(
        target: "pt31553.runtime",
        diagnostic_contract = DIAGNOSTIC_CONTRACT_MARKER,
        event_id = RUNTIME_FAULT_EVENT_ID,
        fault_id = fault.id(),
        endpoint = endpoint.map_or("none", RuntimeEndpoint::id),
        "fan controller fault"
    );
}

pub fn emit_control_cycle(event: ControlCycleDiagnostic) {
    let profile = match event.external_power {
        ExternalPower::Disconnected => "battery",
        ExternalPower::Connected | ExternalPower::Unknown => "ac",
    };
    let external_power = match event.external_power {
        ExternalPower::Connected => "connected",
        ExternalPower::Disconnected => "disconnected",
        ExternalPower::Unknown => "unknown",
    };
    tracing::info!(
        target: "pt31553.runtime",
        diagnostic_contract = DIAGNOSTIC_CONTRACT_MARKER,
        event_id = CONTROL_CYCLE_EVENT_ID,
        cpu_temperature_celsius = event.cpu_temperature.value(),
        gpu_temperature_celsius = event.gpu_temperature.value(),
        external_power,
        profile,
        demand_percent = event.demand.value(),
        cpu_pwm_endpoint = RuntimeEndpoint::CpuPwm.id(),
        cpu_command_pwm = event.cpu.command.value(),
        cpu_readback_pwm = event.cpu.readback.value(),
        cpu_tachometer_endpoint = RuntimeEndpoint::CpuTachometer.id(),
        cpu_rpm_command_pwm = event.cpu.rpm_command.value(),
        cpu_rpm = event.cpu.rpm,
        gpu_pwm_endpoint = RuntimeEndpoint::GpuPwm.id(),
        gpu_command_pwm = event.gpu.command.value(),
        gpu_readback_pwm = event.gpu.readback.value(),
        gpu_tachometer_endpoint = RuntimeEndpoint::GpuTachometer.id(),
        gpu_rpm_command_pwm = event.gpu.rpm_command.value(),
        gpu_rpm = event.gpu.rpm,
        "completed fan control cycle"
    );
}

pub fn emit_restoration_attempt(event: RestorationAttemptDiagnostic) {
    tracing::info!(
        target: "pt31553.runtime",
        diagnostic_contract = DIAGNOSTIC_CONTRACT_MARKER,
        event_id = RESTORATION_ATTEMPT_EVENT_ID,
        attempt = event.attempt,
        cpu_enable_endpoint = RuntimeEndpoint::CpuEnable.id(),
        cpu_write_succeeded = event.cpu.write_succeeded,
        cpu_mode_readback = event.cpu.readback.id(),
        gpu_enable_endpoint = RuntimeEndpoint::GpuEnable.id(),
        gpu_write_succeeded = event.gpu.write_succeeded,
        gpu_mode_readback = event.gpu.readback.id(),
        "Firmware Auto restoration attempt"
    );
}

#[cfg(test)]
#[derive(Clone, Default)]
struct TestDiagnosticLayer(
    std::sync::Arc<std::sync::Mutex<Vec<std::collections::BTreeMap<String, String>>>>,
);

#[cfg(test)]
#[derive(Default)]
struct TestDiagnosticFields(std::collections::BTreeMap<String, String>);

#[cfg(test)]
impl Visit for TestDiagnosticFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[cfg(test)]
impl<S> Layer<S> for TestDiagnosticLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = TestDiagnosticFields::default();
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

#[cfg(test)]
pub(crate) fn record_test_diagnostics<R>(
    action: impl FnOnce() -> R,
) -> (R, Vec<std::collections::BTreeMap<String, String>>) {
    static CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static GLOBAL_SUBSCRIBER: std::sync::Once = std::sync::Once::new();

    GLOBAL_SUBSCRIBER.call_once(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
    });
    let _capture_guard = CAPTURE_LOCK.lock().unwrap();
    let layer = TestDiagnosticLayer::default();
    let events = std::sync::Arc::clone(&layer.0);
    let result =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), action);
    let events = std::sync::Arc::try_unwrap(events)
        .unwrap()
        .into_inner()
        .unwrap();
    (result, events)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, process::Command, sync::Mutex, time::Duration};

    use super::*;

    static JOURNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn native_journald_sink_delivers_every_allowlisted_event_contract() {
        let _guard = JOURNAL_TEST_LOCK.lock().unwrap();
        let fault = capture_native_event(|| {
            emit_fault(
                RuntimeFault::UnexpectedReadback,
                Some(RuntimeEndpoint::GpuPwm),
            );
        });
        assert_native_fields(
            &fault,
            &[
                ("PRIORITY", "3"),
                ("PT31553_EVENT_ID", RUNTIME_FAULT_EVENT_ID),
                ("PT31553_FAULT_ID", "unexpected-readback"),
                ("PT31553_ENDPOINT", "acer:gpu:pwm2"),
            ],
        );

        let transition = capture_native_event(|| {
            emit_state_transition(
                RuntimeState::Arming,
                RuntimeState::CustomControl,
                RuntimeTransition::ArmingConfirmed,
            );
        });
        assert_native_fields(
            &transition,
            &[
                ("PRIORITY", "5"),
                ("PT31553_EVENT_ID", STATE_TRANSITION_EVENT_ID),
                ("PT31553_FROM_STATE", "arming"),
                ("PT31553_TO_STATE", "custom-control"),
                ("PT31553_REASON", "arming-confirmed"),
            ],
        );

        let cycle = capture_native_event(|| {
            emit_control_cycle(ControlCycleDiagnostic {
                cpu_temperature: TemperatureCelsius::try_from(71.5).unwrap(),
                gpu_temperature: TemperatureCelsius::try_from(64.0).unwrap(),
                external_power: ExternalPower::Disconnected,
                demand: DemandPercent::try_from(63.25).unwrap(),
                cpu: FanDiagnostic {
                    command: Pwm::from(DemandPercent::try_from(63.25).unwrap()),
                    readback: Pwm::from(DemandPercent::try_from(63.25).unwrap()),
                    rpm_command: Pwm::from(DemandPercent::try_from(58.0).unwrap()),
                    rpm: 3210,
                },
                gpu: FanDiagnostic {
                    command: Pwm::from(DemandPercent::try_from(63.25).unwrap()),
                    readback: Pwm::from(DemandPercent::try_from(63.25).unwrap()),
                    rpm_command: Pwm::from(DemandPercent::try_from(58.0).unwrap()),
                    rpm: 3090,
                },
            });
        });
        assert_native_fields(
            &cycle,
            &[
                ("PRIORITY", "5"),
                ("PT31553_EVENT_ID", CONTROL_CYCLE_EVENT_ID),
                ("PT31553_CPU_TEMPERATURE_CELSIUS", "71.5"),
                ("PT31553_GPU_TEMPERATURE_CELSIUS", "64"),
                ("PT31553_EXTERNAL_POWER", "disconnected"),
                ("PT31553_PROFILE", "battery"),
                ("PT31553_DEMAND_PERCENT", "63.25"),
                ("PT31553_CPU_PWM_ENDPOINT", "acer:cpu:pwm1"),
                ("PT31553_CPU_COMMAND_PWM", "162"),
                ("PT31553_CPU_READBACK_PWM", "162"),
                ("PT31553_CPU_TACHOMETER_ENDPOINT", "acer:cpu:fan1_input"),
                ("PT31553_CPU_RPM_COMMAND_PWM", "148"),
                ("PT31553_CPU_RPM", "3210"),
                ("PT31553_GPU_PWM_ENDPOINT", "acer:gpu:pwm2"),
                ("PT31553_GPU_COMMAND_PWM", "162"),
                ("PT31553_GPU_READBACK_PWM", "162"),
                ("PT31553_GPU_TACHOMETER_ENDPOINT", "acer:gpu:fan2_input"),
                ("PT31553_GPU_RPM_COMMAND_PWM", "148"),
                ("PT31553_GPU_RPM", "3090"),
            ],
        );

        let restoration = capture_native_event(|| {
            emit_restoration_attempt(RestorationAttemptDiagnostic {
                attempt: 2,
                cpu: RestorationFanDiagnostic {
                    write_succeeded: false,
                    readback: RestorationReadback::Unreadable,
                },
                gpu: RestorationFanDiagnostic {
                    write_succeeded: true,
                    readback: RestorationReadback::FirmwareAuto,
                },
            });
        });
        assert_native_fields(
            &restoration,
            &[
                ("PRIORITY", "5"),
                ("PT31553_EVENT_ID", RESTORATION_ATTEMPT_EVENT_ID),
                ("PT31553_ATTEMPT", "2"),
                ("PT31553_CPU_ENABLE_ENDPOINT", "acer:cpu:pwm1_enable"),
                ("PT31553_CPU_WRITE_SUCCEEDED", "false"),
                ("PT31553_CPU_MODE_READBACK", "unreadable"),
                ("PT31553_GPU_ENABLE_ENDPOINT", "acer:gpu:pwm2_enable"),
                ("PT31553_GPU_WRITE_SUCCEEDED", "true"),
                ("PT31553_GPU_MODE_READBACK", "firmware-auto"),
            ],
        );

        assert_native_event_dropped(|| {
            tracing::error!(
                target: "pt31553.runtime",
                event_id = RUNTIME_FAULT_EVENT_ID,
                endpoint = "/private/device/path",
                "raw private error"
            );
        });

        assert_native_event_dropped(|| {
            tracing::error!(
                target: "pt31553.runtime",
                diagnostic_contract = DIAGNOSTIC_CONTRACT_MARKER,
                event_id = RUNTIME_FAULT_EVENT_ID,
                fault_id = "unexpected-readback",
                endpoint = "/private/device/path",
                "fan controller fault"
            );
        });
    }

    #[test]
    fn injectable_initializer_wires_the_native_journald_sink() {
        let socket_path = std::env::temp_dir().join(format!(
            "pt31553-journald-test-{}-{:?}.socket",
            std::process::id(),
            std::thread::current().id()
        ));
        let receiver = UnixDatagram::bind(&socket_path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("diagnostics::tests::journald_initializer_child")
            .env("PT31553_TEST_JOURNALD_SOCKET", &socket_path)
            .status()
            .unwrap();
        assert!(status.success());

        let event = receive_native_event(&receiver);
        assert_eq!(
            event.get("PT31553_EVENT_ID").map(String::as_str),
            Some(RUNTIME_FAULT_EVENT_ID)
        );
        assert_eq!(
            event.get("PT31553_FAULT_ID").map(String::as_str),
            Some("shutdown-requested")
        );
        fs::remove_file(socket_path).unwrap();
    }

    #[test]
    fn journald_initializer_child() {
        if std::env::var_os(TEST_JOURNALD_SOCKET_ENV).is_none() {
            return;
        }
        init_journald_diagnostics();
        emit_fault(RuntimeFault::ShutdownRequested, None);
    }

    #[test]
    fn unavailable_journald_socket_is_a_nonfatal_initialization_error() {
        let error = JournaldDiagnosticsLayer::connect(Path::new(
            "/run/pt31553-fan-control/nonexistent-journald-socket",
        ))
        .unwrap_err();

        assert!(matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        ));
    }

    fn capture_native_event(action: impl FnOnce()) -> BTreeMap<String, String> {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let layer = JournaldDiagnosticsLayer { socket: sender };

        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), action);
        receive_native_event(&receiver)
    }

    fn assert_native_event_dropped(action: impl FnOnce()) {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(25)))
            .unwrap();
        let layer = JournaldDiagnosticsLayer { socket: sender };

        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), action);

        let mut payload = [0_u8; 64];
        let error = receiver.recv(&mut payload).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
    }

    fn receive_native_event(receiver: &UnixDatagram) -> BTreeMap<String, String> {
        let mut payload = [0_u8; 2048];
        let length = receiver.recv(&mut payload).unwrap();
        parse_native_fields(&payload[..length])
    }

    fn parse_native_fields(mut payload: &[u8]) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        while !payload.is_empty() {
            let name_end = payload.iter().position(|byte| *byte == b'\n').unwrap();
            let name = std::str::from_utf8(&payload[..name_end]).unwrap();
            payload = &payload[name_end + 1..];
            let length = u64::from_le_bytes(payload[..8].try_into().unwrap()) as usize;
            payload = &payload[8..];
            let value = std::str::from_utf8(&payload[..length]).unwrap();
            payload = &payload[length + 1..];
            fields.insert(name.to_owned(), value.to_owned());
        }
        fields
    }

    fn assert_native_fields(event: &BTreeMap<String, String>, expected: &[(&str, &str)]) {
        assert!(event.contains_key("MESSAGE"));
        assert_eq!(event.len(), expected.len() + 1);
        for (name, value) in expected {
            assert_eq!(event.get(*name).map(String::as_str), Some(*value), "{name}");
        }

        assert!(!event.contains_key("CODE_FILE"));
        assert!(!event.contains_key("CODE_LINE"));
        assert!(!event.contains_key("TARGET"));
    }
}
