use std::{
    error::Error,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::{Clock, ExternalPower, TemperatureCelsius};

pub const NORMAL_SAMPLE_CADENCE: Duration = Duration::from_secs(2);
pub const MAX_SAMPLE_CADENCE_JITTER: Duration = Duration::from_millis(100);

static NEXT_GATE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaptureCycle {
    gate_id: u64,
    cycle_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaptureToken {
    cycle: CaptureCycle,
    input: RequiredInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredInput {
    Cpu,
    Gpu,
    Power,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleSourceError {
    reason: String,
}

impl SampleSourceError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for SampleSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl Error for SampleSourceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedSample<T> {
    value: T,
    observed_at: Duration,
    capture_token: CaptureToken,
}

impl<T> ObservedSample<T> {
    pub const fn observed_at(&self) -> Duration {
        self.observed_at
    }

    pub const fn value(&self) -> &T {
        &self.value
    }

    fn into_value(self) -> T {
        self.value
    }
}

/// Gate-owned capability for timestamping one direct source read.
pub struct SampleCapture<'a> {
    clock: &'a mut dyn Clock,
    deadline: Duration,
    capture_token: CaptureToken,
}

impl SampleCapture<'_> {
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Stamps a value at the instant the source captured it.
    pub fn capture<T>(&mut self, value: T) -> ObservedSample<T> {
        ObservedSample {
            value,
            observed_at: self.clock.monotonic_now(),
            capture_token: self.capture_token,
        }
    }
}

/// Direct access to the three required inputs for one control cycle.
///
/// Implementations must perform a fresh read on every call and must not return cached values. The
/// only way to mint an observation is to timestamp the captured value through the supplied context,
/// which shares the gate's monotonic clock. Each source owns device-specific validity checks and
/// reports any partial, invalid, or unavailable read as an error.
pub trait SampleSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError>;

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError>;

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompleteSampleSet {
    cpu_temperature: TemperatureCelsius,
    gpu_temperature: TemperatureCelsius,
    external_power: ExternalPower,
    cycle_started_at: Duration,
    completed_at: Duration,
}

impl CompleteSampleSet {
    pub const fn cpu_temperature(self) -> TemperatureCelsius {
        self.cpu_temperature
    }

    pub const fn gpu_temperature(self) -> TemperatureCelsius {
        self.gpu_temperature
    }

    pub const fn external_power(self) -> ExternalPower {
        self.external_power
    }

    pub const fn cycle_started_at(self) -> Duration {
        self.cycle_started_at
    }

    pub const fn completed_at(self) -> Duration {
        self.completed_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SampleReadiness {
    AwaitingSecondSample,
    Ready(CompleteSampleSet),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SampleSetError {
    FirmwareAutoUnconfirmed,
    Input {
        input: RequiredInput,
        source: SampleSourceError,
    },
    Stale {
        input: RequiredInput,
    },
    Future {
        input: RequiredInput,
    },
    Late {
        input: RequiredInput,
    },
    ClockWentBackwards,
    DeadlineOverflow,
    CaptureCycleOverflow,
    CadenceMissed {
        expected_at: Duration,
        observed_at: Duration,
    },
}

impl fmt::Display for SampleSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirmwareAutoUnconfirmed => {
                formatter.write_str("Firmware Auto must be confirmed before sampling")
            }
            Self::Input { input, source } => write!(formatter, "{input:?} sample failed: {source}"),
            Self::Stale { input } => write!(formatter, "{input:?} sample is stale"),
            Self::Future { input } => {
                write!(formatter, "{input:?} sample timestamp is in the future")
            }
            Self::Late { input } => write!(formatter, "{input:?} sample missed its deadline"),
            Self::ClockWentBackwards => formatter.write_str("monotonic clock went backwards"),
            Self::DeadlineOverflow => formatter.write_str("sample deadline overflowed"),
            Self::CaptureCycleOverflow => formatter.write_str("sample capture cycle overflowed"),
            Self::CadenceMissed {
                expected_at,
                observed_at,
            } => write!(
                formatter,
                "control-cycle cadence missed: expected at {expected_at:?}, observed at {observed_at:?}"
            ),
        }
    }
}

impl Error for SampleSetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Input { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct FreshSampleGate {
    gate_id: u64,
    next_cycle_id: u64,
    last_successful_cycle_started_at: Option<Duration>,
    last_successful_cycle_completed_at: Option<Duration>,
}

impl FreshSampleGate {
    pub fn new() -> Self {
        Self {
            gate_id: next_gate_id(),
            next_cycle_id: 0,
            last_successful_cycle_started_at: None,
            last_successful_cycle_completed_at: None,
        }
    }

    pub fn reset(&mut self) {
        self.last_successful_cycle_started_at = None;
        self.last_successful_cycle_completed_at = None;
    }

    pub fn sample(
        &mut self,
        sources: &mut dyn SampleSources,
        clock: &mut dyn Clock,
    ) -> Result<SampleReadiness, SampleSetError> {
        let capture_cycle = CaptureCycle {
            gate_id: self.gate_id,
            cycle_id: self.next_cycle_id,
        };
        self.next_cycle_id = match self.next_cycle_id.checked_add(1) {
            Some(next) => next,
            None => {
                self.reset();
                return Err(SampleSetError::CaptureCycleOverflow);
            }
        };

        let sample = match collect_complete_set(
            sources,
            clock,
            capture_cycle,
            self.last_successful_cycle_completed_at,
        ) {
            Ok(sample) => sample,
            Err(error) => {
                self.reset();
                return Err(error);
            }
        };

        let current_started_at = sample.cycle_started_at;
        let consecutive = match self.last_successful_cycle_started_at {
            Some(previous) if current_started_at < previous => {
                self.reset();
                return Err(SampleSetError::ClockWentBackwards);
            }
            Some(previous) => current_started_at
                .checked_sub(previous)
                .is_some_and(is_normal_cadence),
            None => false,
        };
        self.last_successful_cycle_started_at = Some(current_started_at);
        self.last_successful_cycle_completed_at = Some(sample.completed_at);

        if consecutive {
            Ok(SampleReadiness::Ready(sample))
        } else {
            Ok(SampleReadiness::AwaitingSecondSample)
        }
    }
}

impl Default for FreshSampleGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Schedules exactly one fresh complete sample set for each normal control cycle.
#[derive(Debug)]
pub struct ControlCycleSampleGate {
    gate_id: u64,
    next_cycle_id: u64,
    last_successful_cycle_started_at: Option<Duration>,
    last_successful_cycle_completed_at: Option<Duration>,
}

impl ControlCycleSampleGate {
    pub fn new() -> Self {
        Self {
            gate_id: next_gate_id(),
            next_cycle_id: 0,
            last_successful_cycle_started_at: None,
            last_successful_cycle_completed_at: None,
        }
    }

    pub fn sample(
        &mut self,
        sources: &mut dyn SampleSources,
        clock: &mut dyn Clock,
    ) -> Result<CompleteSampleSet, SampleSetError> {
        if let Some(previous_started_at) = self.last_successful_cycle_started_at {
            let expected_at = previous_started_at
                .checked_add(NORMAL_SAMPLE_CADENCE)
                .ok_or(SampleSetError::DeadlineOverflow)?;
            let observed_at = clock.monotonic_now();
            if observed_at < previous_started_at {
                return Err(SampleSetError::ClockWentBackwards);
            }
            let latest = expected_at
                .checked_add(MAX_SAMPLE_CADENCE_JITTER)
                .ok_or(SampleSetError::DeadlineOverflow)?;
            if observed_at > latest {
                return Err(SampleSetError::CadenceMissed {
                    expected_at,
                    observed_at,
                });
            }
            if observed_at < expected_at {
                clock.delay(expected_at - observed_at);
            }
        }

        let capture_cycle = CaptureCycle {
            gate_id: self.gate_id,
            cycle_id: self.next_cycle_id,
        };
        self.next_cycle_id = self
            .next_cycle_id
            .checked_add(1)
            .ok_or(SampleSetError::CaptureCycleOverflow)?;
        let sample = collect_complete_set(
            sources,
            clock,
            capture_cycle,
            self.last_successful_cycle_completed_at,
        )?;

        if let Some(previous_started_at) = self.last_successful_cycle_started_at {
            let elapsed = sample
                .cycle_started_at
                .checked_sub(previous_started_at)
                .ok_or(SampleSetError::ClockWentBackwards)?;
            if !is_normal_cadence(elapsed) {
                let expected_at = previous_started_at
                    .checked_add(NORMAL_SAMPLE_CADENCE)
                    .ok_or(SampleSetError::DeadlineOverflow)?;
                return Err(SampleSetError::CadenceMissed {
                    expected_at,
                    observed_at: sample.cycle_started_at,
                });
            }
        }

        self.last_successful_cycle_started_at = Some(sample.cycle_started_at);
        self.last_successful_cycle_completed_at = Some(sample.completed_at);
        Ok(sample)
    }
}

impl Default for ControlCycleSampleGate {
    fn default() -> Self {
        Self::new()
    }
}

fn next_gate_id() -> u64 {
    NEXT_GATE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("sample gate ID space exhausted")
}

fn is_normal_cadence(elapsed: Duration) -> bool {
    let earliest = NORMAL_SAMPLE_CADENCE
        .checked_sub(MAX_SAMPLE_CADENCE_JITTER)
        .expect("cadence jitter is shorter than the cadence");
    let latest = NORMAL_SAMPLE_CADENCE
        .checked_add(MAX_SAMPLE_CADENCE_JITTER)
        .expect("cadence plus jitter fits Duration");
    (earliest..=latest).contains(&elapsed)
}

fn collect_complete_set(
    sources: &mut dyn SampleSources,
    clock: &mut dyn Clock,
    capture_cycle: CaptureCycle,
    previous_completed_at: Option<Duration>,
) -> Result<CompleteSampleSet, SampleSetError> {
    let cycle_started_at = clock.monotonic_now();
    if previous_completed_at.is_some_and(|completed_at| cycle_started_at < completed_at) {
        return Err(SampleSetError::ClockWentBackwards);
    }
    let deadline = cycle_started_at
        .checked_add(NORMAL_SAMPLE_CADENCE)
        .ok_or(SampleSetError::DeadlineOverflow)?;

    let cpu = {
        let mut capture = SampleCapture {
            clock,
            deadline,
            capture_token: CaptureToken {
                cycle: capture_cycle,
                input: RequiredInput::Cpu,
            },
        };
        sources
            .sample_cpu(&mut capture)
            .map_err(|source| SampleSetError::Input {
                input: RequiredInput::Cpu,
                source,
            })?
    };
    let cpu_checked_at = clock.monotonic_now();
    validate_observation(
        RequiredInput::Cpu,
        &cpu,
        CaptureToken {
            cycle: capture_cycle,
            input: RequiredInput::Cpu,
        },
        cycle_started_at,
        deadline,
        cpu_checked_at,
    )?;

    let gpu = {
        let mut capture = SampleCapture {
            clock,
            deadline,
            capture_token: CaptureToken {
                cycle: capture_cycle,
                input: RequiredInput::Gpu,
            },
        };
        sources
            .sample_gpu(&mut capture)
            .map_err(|source| SampleSetError::Input {
                input: RequiredInput::Gpu,
                source,
            })?
    };
    let gpu_checked_at = clock.monotonic_now();
    if gpu_checked_at < cpu_checked_at {
        return Err(SampleSetError::ClockWentBackwards);
    }
    validate_observation(
        RequiredInput::Gpu,
        &gpu,
        CaptureToken {
            cycle: capture_cycle,
            input: RequiredInput::Gpu,
        },
        cpu_checked_at,
        deadline,
        gpu_checked_at,
    )?;

    let power = {
        let mut capture = SampleCapture {
            clock,
            deadline,
            capture_token: CaptureToken {
                cycle: capture_cycle,
                input: RequiredInput::Power,
            },
        };
        sources
            .observe_external_power(&mut capture)
            .map_err(|source| SampleSetError::Input {
                input: RequiredInput::Power,
                source,
            })?
    };
    let completed_at = clock.monotonic_now();
    if completed_at < gpu_checked_at {
        return Err(SampleSetError::ClockWentBackwards);
    }
    validate_observation(
        RequiredInput::Power,
        &power,
        CaptureToken {
            cycle: capture_cycle,
            input: RequiredInput::Power,
        },
        gpu_checked_at,
        deadline,
        completed_at,
    )?;

    Ok(CompleteSampleSet {
        cpu_temperature: cpu.into_value(),
        gpu_temperature: gpu.into_value(),
        external_power: power.into_value(),
        cycle_started_at,
        completed_at,
    })
}

fn validate_observation<T>(
    input: RequiredInput,
    observation: &ObservedSample<T>,
    capture_token: CaptureToken,
    requested_at: Duration,
    deadline: Duration,
    checked_at: Duration,
) -> Result<(), SampleSetError> {
    if observation.capture_token != capture_token {
        return Err(SampleSetError::Stale { input });
    }
    if checked_at < requested_at {
        return Err(SampleSetError::ClockWentBackwards);
    }
    if observation.observed_at < requested_at {
        return Err(SampleSetError::Stale { input });
    }
    if observation.observed_at > checked_at {
        return Err(SampleSetError::Future { input });
    }
    if checked_at > deadline {
        return Err(SampleSetError::Late { input });
    }
    Ok(())
}
