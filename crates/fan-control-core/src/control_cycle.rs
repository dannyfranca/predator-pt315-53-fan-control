use std::{error::Error, fmt, path::Path, time::Duration};

use crate::{
    AcerHwmonDevice, AcerHwmonDiscoveryError, ArmedFanControl, BoundedIdentityBoundFileAccess,
    Clock, CompleteSampleSet, ControlCycleSampleGate, ControllerOwnership, DemandSmoother,
    EffectiveTemperature, Fan, FanEndpoints, FanOutputs, MonotonicTime, MonotonicTimeError,
    PlatformError, PlatformErrorKind, Pwm, RuntimeLockAccess, SampleSetError, SampleSources,
    ValidatedConfig,
    output::{calculate_target_demand, fan_outputs_for_demand},
    tachometer::{TachometerObservationError, TachometerValidator},
};

const CUSTOM_CONTROL: &str = "1";

/// Runtime state that can exist only after a successful two-fan handover.
#[derive(Debug)]
pub struct HealthyControl {
    ownership_id: u64,
    custom_epoch: u64,
    config: ValidatedConfig,
    device: AcerHwmonDevice,
    sample_gate: ControlCycleSampleGate,
    demand_history: Option<ControlDemandHistory>,
    last_outputs: FanOutputs,
    tachometers: TachometerValidator,
    invalidated: bool,
}

impl HealthyControl {
    pub fn from_armed(armed: ArmedFanControl) -> Self {
        let crate::arming::ArmedControlParts {
            ownership_id,
            custom_epoch,
            config,
            device,
            calibration,
            cpu_custom_confirmed_at,
            gpu_custom_confirmed_at,
        } = armed.into_control_parts();
        Self {
            ownership_id,
            custom_epoch,
            config,
            device,
            sample_gate: ControlCycleSampleGate::new(),
            demand_history: None,
            last_outputs: FanOutputs::maximum(),
            tachometers: TachometerValidator::new(
                calibration,
                Pwm::MAXIMUM,
                cpu_custom_confirmed_at,
                gpu_custom_confirmed_at,
            ),
            invalidated: false,
        }
    }

    pub fn is_current_for<P>(&self, ownership: &ControllerOwnership<'_, P>) -> bool
    where
        P: RuntimeLockAccess + ?Sized,
    {
        !self.invalidated && ownership.custom_epoch_is_current(self.ownership_id, self.custom_epoch)
    }

    pub const fn last_outputs(&self) -> FanOutputs {
        self.last_outputs
    }

    pub(crate) fn into_recovery_parts(self) -> (ValidatedConfig, AcerHwmonDevice) {
        (self.config, self.device)
    }
}

#[derive(Debug, Clone, Copy)]
struct ControlDemandHistory {
    cpu_temperature: EffectiveTemperature,
    gpu_temperature: EffectiveTemperature,
    smoother: DemandSmoother,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompletedControlCycle {
    sample: CompleteSampleSet,
    outputs: FanOutputs,
}

impl CompletedControlCycle {
    pub const fn sample(self) -> CompleteSampleSet {
        self.sample
    }

    pub const fn outputs(self) -> FanOutputs {
        self.outputs
    }
}

#[derive(Debug)]
pub enum HealthyControlCycleError {
    Invalidated,
    StaleArmingReceipt,
    Sample(SampleSetError),
    PolicyClock(MonotonicTimeError),
    DeadlineOverflow,
    DeadlineExceeded,
    Device(AcerHwmonDiscoveryError),
    DeviceChanged,
    Platform {
        fan: Fan,
        operation: ControlCycleOperation,
        source: PlatformError,
    },
    UnexpectedReadback {
        fan: Fan,
        field: ControlCycleReadback,
        operation: ControlCycleOperation,
        expected: String,
        actual: String,
    },
    MalformedTachometer {
        fan: Fan,
        actual: String,
    },
    TachometerOutOfBand {
        fan: Fan,
        expected_rpm: u32,
        actual_rpm: u32,
    },
}

impl fmt::Display for HealthyControlCycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalidated => formatter.write_str("healthy control state is invalidated"),
            Self::StaleArmingReceipt => {
                formatter.write_str("arming receipt no longer belongs to current ownership")
            }
            Self::Sample(error) => write!(formatter, "control-cycle sample failed: {error}"),
            Self::PolicyClock(error) => write!(formatter, "control policy clock failed: {error:?}"),
            Self::DeadlineOverflow => formatter.write_str("control-cycle deadline overflowed"),
            Self::DeadlineExceeded => formatter.write_str("control cycle exceeded its cadence"),
            Self::Device(error) => write!(formatter, "Acer hwmon verification failed: {error}"),
            Self::DeviceChanged => {
                formatter.write_str("Acer hwmon identity or endpoint mapping changed")
            }
            Self::Platform {
                fan,
                operation,
                source,
            } => write!(formatter, "{} fan {operation} failed: {source}", fan.name()),
            Self::UnexpectedReadback {
                fan,
                field,
                operation,
                expected,
                actual,
            } => write!(
                formatter,
                "{} fan {operation} {field} expected {expected:?}, got {actual:?}",
                fan.name()
            ),
            Self::MalformedTachometer { fan, actual } => write!(
                formatter,
                "{} fan tachometer readback is malformed: {actual:?}",
                fan.name()
            ),
            Self::TachometerOutOfBand {
                fan,
                expected_rpm,
                actual_rpm,
            } => write!(
                formatter,
                "{} fan tachometer settled outside its qualified ±30% band (expected {expected_rpm} RPM, got {actual_rpm} RPM)",
                fan.name()
            ),
        }
    }
}

impl Error for HealthyControlCycleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sample(error) => Some(error),
            Self::Device(error) => Some(error),
            Self::Platform { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<SampleSetError> for HealthyControlCycleError {
    fn from(error: SampleSetError) -> Self {
        Self::Sample(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCycleOperation {
    ConfirmBeforeOutput,
    ReadPriorDuty,
    WriteDuty,
    ConfirmWrittenDuty,
    ConfirmResult,
    ReadTachometer,
}

impl fmt::Display for ControlCycleOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConfirmBeforeOutput => "pre-output mode confirmation",
            Self::ReadPriorDuty => "prior-duty confirmation",
            Self::WriteDuty => "duty write",
            Self::ConfirmWrittenDuty => "written-duty confirmation",
            Self::ConfirmResult => "result confirmation",
            Self::ReadTachometer => "tachometer read",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCycleReadback {
    Mode,
    Duty,
}

impl fmt::Display for ControlCycleReadback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Mode => "mode",
            Self::Duty => "duty",
        })
    }
}

/// Runs one serialized normal-control cycle and invalidates the state on any failure.
pub fn run_healthy_control_cycle<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    control: &mut HealthyControl,
    sources: &mut dyn SampleSources,
) -> Result<CompletedControlCycle, HealthyControlCycleError>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    if control.invalidated {
        return Err(HealthyControlCycleError::Invalidated);
    }
    if !control.is_current_for(ownership) {
        control.invalidated = true;
        return Err(HealthyControlCycleError::StaleArmingReceipt);
    }

    let result = try_run_cycle(ownership, control, sources);
    if result.is_err() {
        control.invalidated = true;
    }
    result
}

fn try_run_cycle<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    control: &mut HealthyControl,
    sources: &mut dyn SampleSources,
) -> Result<CompletedControlCycle, HealthyControlCycleError>
where
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
{
    let device = control.device.clone();
    let sample = control
        .sample_gate
        .sample(sources, ownership.platform_mut())?;
    let deadline = sample
        .cycle_started_at()
        .checked_add(crate::NORMAL_SAMPLE_CADENCE)
        .ok_or(HealthyControlCycleError::DeadlineOverflow)?;
    let (next_history, outputs) = next_outputs(&control.config, control.demand_history, sample)?;

    verify_device_before(ownership.platform_mut(), &device, deadline)?;
    confirm_state(
        ownership.platform_mut(),
        &device,
        control.last_outputs,
        deadline,
        ControlCycleOperation::ConfirmBeforeOutput,
        ControlCycleOperation::ReadPriorDuty,
    )?;
    verify_device_before(ownership.platform_mut(), &device, deadline)?;

    write_changed_outputs(
        ownership.platform_mut(),
        &device,
        control.last_outputs,
        outputs,
        deadline,
        &mut control.tachometers,
    )?;

    confirm_state(
        ownership.platform_mut(),
        &device,
        outputs,
        deadline,
        ControlCycleOperation::ConfirmResult,
        ControlCycleOperation::ConfirmResult,
    )?;
    verify_device_before(ownership.platform_mut(), &device, deadline)?;
    validate_tachometer_response(
        ownership.platform_mut(),
        &device,
        &mut control.tachometers,
        deadline,
    )?;
    confirm_state(
        ownership.platform_mut(),
        &device,
        outputs,
        deadline,
        ControlCycleOperation::ConfirmResult,
        ControlCycleOperation::ConfirmResult,
    )?;
    verify_device_before(ownership.platform_mut(), &device, deadline)?;

    control.demand_history = Some(next_history);
    control.last_outputs = outputs;
    Ok(CompletedControlCycle { sample, outputs })
}

fn next_outputs(
    config: &ValidatedConfig,
    history: Option<ControlDemandHistory>,
    sample: CompleteSampleSet,
) -> Result<(ControlDemandHistory, FanOutputs), HealthyControlCycleError> {
    let now = MonotonicTime::from(sample.completed_at());
    let next = match history {
        Some(mut history) => {
            let cpu_temperature = history
                .cpu_temperature
                .update(sample.cpu_temperature(), config.control().hysteresis());
            let gpu_temperature = history
                .gpu_temperature
                .update(sample.gpu_temperature(), config.control().hysteresis());
            let target = calculate_target_demand(
                config,
                cpu_temperature,
                gpu_temperature,
                sample.external_power(),
            );
            history
                .smoother
                .update(target, now)
                .map_err(HealthyControlCycleError::PolicyClock)?;
            history
        }
        None => {
            let cpu_temperature = EffectiveTemperature::new(sample.cpu_temperature());
            let gpu_temperature = EffectiveTemperature::new(sample.gpu_temperature());
            let target = calculate_target_demand(
                config,
                cpu_temperature.current(),
                gpu_temperature.current(),
                sample.external_power(),
            );
            ControlDemandHistory {
                cpu_temperature,
                gpu_temperature,
                smoother: DemandSmoother::new(target, config.control().downshift_policy(), now),
            }
        }
    };
    let outputs = fan_outputs_for_demand(config, next.smoother.commanded());
    Ok((next, outputs))
}

fn verify_device_before(
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    expected: &AcerHwmonDevice,
    deadline: Duration,
) -> Result<(), HealthyControlCycleError> {
    match expected.abi_is_current_before(platform, deadline) {
        Ok(true) => Ok(()),
        Ok(false) => Err(HealthyControlCycleError::DeviceChanged),
        Err(AcerHwmonDiscoveryError::Platform(error))
            if error.kind() == PlatformErrorKind::TimedOut =>
        {
            Err(HealthyControlCycleError::DeadlineExceeded)
        }
        Err(error) => Err(HealthyControlCycleError::Device(error)),
    }
}

fn confirm_state(
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    outputs: FanOutputs,
    deadline: Duration,
    mode_operation: ControlCycleOperation,
    duty_operation: ControlCycleOperation,
) -> Result<(), HealthyControlCycleError> {
    for (fan, endpoints, pwm) in [
        (Fan::Cpu, device.cpu(), outputs.cpu_pwm()),
        (Fan::Gpu, device.gpu(), outputs.gpu_pwm()),
    ] {
        confirm(
            platform,
            device,
            endpoints.enable(),
            fan,
            ControlCycleReadback::Mode,
            CUSTOM_CONTROL,
            mode_operation,
            deadline,
        )?;
        confirm(
            platform,
            device,
            endpoints.pwm(),
            fan,
            ControlCycleReadback::Duty,
            &pwm.value().to_string(),
            duty_operation,
            deadline,
        )?;
    }
    Ok(())
}

fn write_changed_outputs(
    platform: &mut (impl BoundedIdentityBoundFileAccess + Clock + ?Sized),
    device: &AcerHwmonDevice,
    previous: FanOutputs,
    next: FanOutputs,
    deadline: Duration,
    tachometers: &mut TachometerValidator,
) -> Result<(), HealthyControlCycleError> {
    for (fan, endpoints, previous_pwm, next_pwm) in [
        (Fan::Cpu, device.cpu(), previous.cpu_pwm(), next.cpu_pwm()),
        (Fan::Gpu, device.gpu(), previous.gpu_pwm(), next.gpu_pwm()),
    ] {
        if previous_pwm == next_pwm {
            continue;
        }
        confirm(
            platform,
            device,
            endpoints.enable(),
            fan,
            ControlCycleReadback::Mode,
            CUSTOM_CONTROL,
            ControlCycleOperation::ConfirmBeforeOutput,
            deadline,
        )?;
        write(platform, device, endpoints, fan, next_pwm, deadline)?;
        confirm(
            platform,
            device,
            endpoints.pwm(),
            fan,
            ControlCycleReadback::Duty,
            &next_pwm.value().to_string(),
            ControlCycleOperation::ConfirmWrittenDuty,
            deadline,
        )?;
        tachometers.command_confirmed(fan, next_pwm, platform.monotonic_now());
    }
    Ok(())
}

fn validate_tachometer_response(
    platform: &mut (impl BoundedIdentityBoundFileAccess + Clock + ?Sized),
    device: &AcerHwmonDevice,
    tachometers: &mut TachometerValidator,
    deadline: Duration,
) -> Result<(), HealthyControlCycleError> {
    let cpu_raw = read_tachometer(platform, device, device.cpu(), Fan::Cpu, deadline)?;
    let cpu_observed_at = platform.monotonic_now();
    let cpu_rpm = parse_tachometer(Fan::Cpu, cpu_raw)?;
    observe_tachometer(tachometers, Fan::Cpu, cpu_rpm, cpu_observed_at)?;

    let gpu_raw = read_tachometer(platform, device, device.gpu(), Fan::Gpu, deadline)?;
    let gpu_observed_at = platform.monotonic_now();
    let gpu_rpm = parse_tachometer(Fan::Gpu, gpu_raw)?;
    observe_tachometer(tachometers, Fan::Gpu, gpu_rpm, gpu_observed_at)
}

fn read_tachometer(
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    endpoints: &FanEndpoints,
    fan: Fan,
    deadline: Duration,
) -> Result<String, HealthyControlCycleError> {
    platform
        .read_bound_before(
            device.root(),
            device.backing_identity(),
            child_name(endpoints.tachometer()),
            endpoint_identity(device, endpoints.tachometer()),
            deadline,
        )
        .map_err(|source| operation_error(fan, ControlCycleOperation::ReadTachometer, source))
}

fn parse_tachometer(fan: Fan, actual: String) -> Result<u32, HealthyControlCycleError> {
    actual
        .trim()
        .parse()
        .map_err(|_| HealthyControlCycleError::MalformedTachometer { fan, actual })
}

fn observe_tachometer(
    tachometers: &mut TachometerValidator,
    fan: Fan,
    rpm: u32,
    observed_at: Duration,
) -> Result<(), HealthyControlCycleError> {
    match tachometers.observe(fan, rpm, observed_at) {
        Ok(()) => Ok(()),
        Err(TachometerObservationError::DeadlineOverflow) => {
            Err(HealthyControlCycleError::DeadlineOverflow)
        }
        Err(TachometerObservationError::OutOfBand {
            expected_rpm,
            actual_rpm,
        }) => Err(HealthyControlCycleError::TachometerOutOfBand {
            fan,
            expected_rpm,
            actual_rpm,
        }),
    }
}

fn write(
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    endpoints: &FanEndpoints,
    fan: Fan,
    pwm: Pwm,
    deadline: Duration,
) -> Result<(), HealthyControlCycleError> {
    platform
        .write_bound_if_before(
            device.root(),
            device.backing_identity(),
            &device
                .endpoint_bindings()
                .map(|(path, identity)| (child_name(path), identity)),
            &[
                (child_name(device.cpu().enable()), CUSTOM_CONTROL),
                (child_name(device.gpu().enable()), CUSTOM_CONTROL),
            ],
            child_name(endpoints.pwm()),
            &pwm.value().to_string(),
            deadline,
        )
        .map_err(|source| operation_error(fan, ControlCycleOperation::WriteDuty, source))
}

#[allow(clippy::too_many_arguments)]
fn confirm(
    platform: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
    device: &AcerHwmonDevice,
    path: &Path,
    fan: Fan,
    field: ControlCycleReadback,
    expected: &str,
    operation: ControlCycleOperation,
    deadline: Duration,
) -> Result<(), HealthyControlCycleError> {
    let actual = platform
        .read_bound_before(
            device.root(),
            device.backing_identity(),
            child_name(path),
            endpoint_identity(device, path),
            deadline,
        )
        .map_err(|source| operation_error(fan, operation, source))?;
    if actual.trim() != expected {
        return Err(HealthyControlCycleError::UnexpectedReadback {
            fan,
            field,
            operation,
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

fn child_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("discovered endpoint must have a UTF-8 child name")
}

fn endpoint_identity(device: &AcerHwmonDevice, path: &Path) -> crate::FileIdentity {
    device
        .endpoint_identity(path)
        .expect("control I/O must use a discovered endpoint")
}

fn operation_error(
    fan: Fan,
    operation: ControlCycleOperation,
    source: PlatformError,
) -> HealthyControlCycleError {
    if source.kind() == PlatformErrorKind::TimedOut {
        HealthyControlCycleError::DeadlineExceeded
    } else {
        HealthyControlCycleError::Platform {
            fan,
            operation,
            source,
        }
    }
}
