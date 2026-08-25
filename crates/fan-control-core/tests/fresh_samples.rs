use std::{collections::VecDeque, time::Duration};

use fan_control_core::{
    Clock, ExternalPower, FreshSampleGate, ObservedSample, RequiredInput, SampleCapture,
    SampleReadiness, SampleSetError, SampleSourceError, SampleSources, TemperatureCelsius,
};

#[derive(Debug)]
struct ScriptedClock {
    times: VecDeque<Duration>,
}

impl ScriptedClock {
    fn new(times: impl IntoIterator<Item = Duration>) -> Self {
        Self {
            times: times.into_iter().collect(),
        }
    }
}

impl Clock for ScriptedClock {
    fn monotonic_now(&mut self) -> Duration {
        self.times.pop_front().expect("scripted monotonic time")
    }

    fn delay(&mut self, _duration: Duration) {
        panic!("sample collection must not delay the control loop")
    }
}

#[derive(Debug, Default)]
struct ScriptedSources {
    cpu: VecDeque<Result<TemperatureCelsius, SampleSourceError>>,
    gpu: VecDeque<Result<TemperatureCelsius, SampleSourceError>>,
    power: VecDeque<Result<ExternalPower, SampleSourceError>>,
    deadlines: Vec<Duration>,
}

#[derive(Debug, Default)]
struct CachingCpuSources {
    cached_cpu: Option<ObservedSample<TemperatureCelsius>>,
}

#[derive(Debug, Default)]
struct ReusingCpuAsGpuSources {
    cpu: Option<ObservedSample<TemperatureCelsius>>,
}

#[derive(Debug, Default)]
struct FutureCpuSources;

impl SampleSources for FutureCpuSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(capture.capture(temp(70.0)))
    }

    fn sample_gpu(
        &mut self,
        _capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        panic!("future CPU observation must reject before GPU sampling")
    }

    fn observe_external_power(
        &mut self,
        _capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        panic!("future CPU observation must reject before power sampling")
    }
}

impl SampleSources for CachingCpuSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(match self.cached_cpu {
            Some(sample) => sample,
            None => {
                let sample = capture.capture(temp(70.0));
                self.cached_cpu = Some(sample);
                sample
            }
        })
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(capture.capture(temp(65.0)))
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        Ok(capture.capture(ExternalPower::Connected))
    }
}

impl SampleSources for ReusingCpuAsGpuSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        let sample = capture.capture(temp(70.0));
        self.cpu = Some(sample);
        Ok(sample)
    }

    fn sample_gpu(
        &mut self,
        _capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Ok(self.cpu.expect("CPU sample must exist"))
    }

    fn observe_external_power(
        &mut self,
        _capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        panic!("cross-input reuse must reject before power sampling")
    }
}

impl SampleSources for ScriptedSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        self.deadlines.push(capture.deadline());
        self.cpu
            .pop_front()
            .expect("scripted CPU sample")
            .map(|value| capture.capture(value))
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        self.deadlines.push(capture.deadline());
        self.gpu
            .pop_front()
            .expect("scripted GPU sample")
            .map(|value| capture.capture(value))
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        self.deadlines.push(capture.deadline());
        self.power
            .pop_front()
            .expect("scripted power sample")
            .map(|value| capture.capture(value))
    }
}

#[test]
fn two_complete_sets_at_the_normal_cadence_unlock_the_current_set() {
    let mut sources = valid_sources(&[0, 2]);
    let mut clock = clock_for_cycles(&[0, 2]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(
        gate.sample(&mut sources, &mut clock).unwrap(),
        SampleReadiness::AwaitingSecondSample
    );
    let SampleReadiness::Ready(sample) = gate.sample(&mut sources, &mut clock).unwrap() else {
        panic!("second consecutive set must be ready");
    };

    assert_eq!(sample.cpu_temperature().value(), 70.0);
    assert_eq!(sample.gpu_temperature().value(), 65.0);
    assert_eq!(sample.external_power(), ExternalPower::Connected);
    assert_eq!(sample.cycle_started_at(), Duration::from_secs(2));
    assert_eq!(sample.completed_at(), Duration::from_millis(2_300));
    assert_eq!(
        sources.deadlines,
        vec![Duration::from_secs(2); 3]
            .into_iter()
            .chain(vec![Duration::from_secs(4); 3])
            .collect::<Vec<_>>()
    );
}

#[test]
fn cadence_jitter_bounds_are_inclusive_and_nearby_values_are_rejected() {
    for (second_start, expected) in [
        (millis(1_899), "waiting"),
        (millis(1_900), "ready"),
        (millis(2_100), "ready"),
        (millis(2_101), "waiting"),
    ] {
        let mut sources = valid_sources(&[0, 2]);
        let mut clock = clock_for_cycle_starts(&[Duration::ZERO, second_start]);
        let mut gate = FreshSampleGate::new();

        assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
        assert_eq!(sample(&mut gate, &mut sources, &mut clock), expected);
    }
}

#[test]
fn every_required_input_failure_rejects_the_entire_set() {
    for input in [RequiredInput::Cpu, RequiredInput::Gpu, RequiredInput::Power] {
        let mut sources = valid_sources(&[0]);
        match input {
            RequiredInput::Cpu => {
                sources.cpu[0] = Err(SampleSourceError::new("required input failed"));
            }
            RequiredInput::Gpu => {
                sources.gpu[0] = Err(SampleSourceError::new("required input failed"));
            }
            RequiredInput::Power => {
                sources.power[0] = Err(SampleSourceError::new("required input failed"));
            }
        }
        let mut clock = clock_for_cycles(&[0]);
        let mut gate = FreshSampleGate::new();

        assert!(matches!(
            gate.sample(&mut sources, &mut clock),
            Err(SampleSetError::Input { input: actual, .. }) if actual == input
        ));
    }
}

#[test]
fn a_cpu_read_finishing_after_the_deadline_fails_closed() {
    let mut sources = valid_sources(&[5]);
    let mut clock = ScriptedClock::new([seconds(5), millis(7_001), millis(7_001)]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::Late {
            input: RequiredInput::Cpu,
        })
    );
}

#[test]
fn a_cached_observation_cannot_complete_a_later_cycle() {
    let mut sources = CachingCpuSources::default();
    let mut clock = ScriptedClock::new([
        millis(0),
        millis(50),
        millis(100),
        millis(150),
        millis(200),
        millis(250),
        millis(300),
        seconds(2),
        millis(2_100),
    ]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::Stale {
            input: RequiredInput::Cpu,
        })
    );
}

#[test]
fn a_cached_observation_at_the_next_cycle_start_is_still_rejected() {
    let mut sources = CachingCpuSources::default();
    let mut clock = ScriptedClock::new([
        seconds(0),
        seconds(2),
        seconds(2),
        seconds(2),
        seconds(2),
        seconds(2),
        seconds(2),
        seconds(2),
        seconds(2),
    ]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::Stale {
            input: RequiredInput::Cpu,
        })
    );
}

#[test]
fn an_observation_from_another_required_input_is_rejected() {
    let mut sources = ReusingCpuAsGpuSources::default();
    let mut clock = ScriptedClock::new([millis(0), millis(50), millis(100), millis(150)]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::Stale {
            input: RequiredInput::Gpu,
        })
    );
}

#[test]
fn a_future_observation_rejects_the_cycle() {
    let mut sources = FutureCpuSources;
    let mut clock = ScriptedClock::new([millis(0), millis(500), millis(100)]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::Future {
            input: RequiredInput::Cpu,
        })
    );
}

#[test]
fn late_gpu_or_power_rejects_the_whole_cycle() {
    for input in [RequiredInput::Gpu, RequiredInput::Power] {
        let mut sources = valid_sources(&[0]);
        let times = match input {
            RequiredInput::Gpu => vec![
                millis(0),
                millis(50),
                millis(100),
                millis(2_001),
                millis(2_001),
            ],
            RequiredInput::Power => vec![
                millis(0),
                millis(50),
                millis(100),
                millis(150),
                millis(200),
                millis(2_001),
                millis(2_001),
            ],
            RequiredInput::Cpu => unreachable!(),
        };
        let mut clock = ScriptedClock::new(times);
        let mut gate = FreshSampleGate::new();

        assert_eq!(
            gate.sample(&mut sources, &mut clock),
            Err(SampleSetError::Late { input })
        );
    }
}

#[test]
fn a_failed_cycle_discards_the_prior_success_and_requires_two_new_sets() {
    let mut sources = valid_sources(&[0, 1, 2, 4]);
    sources.cpu[1] = Err(SampleSourceError::new("CPU read failed"));
    sources.gpu.remove(1);
    sources.power.remove(1);
    let mut clock = ScriptedClock::new([
        millis(0),
        millis(50),
        millis(100),
        millis(150),
        millis(200),
        millis(250),
        millis(300),
        seconds(1),
        seconds(2),
        millis(2_050),
        millis(2_100),
        millis(2_150),
        millis(2_200),
        millis(2_250),
        millis(2_300),
        seconds(4),
        millis(4_050),
        millis(4_100),
        millis(4_150),
        millis(4_200),
        millis(4_250),
        millis(4_300),
    ]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "error");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "ready");
}

#[test]
fn a_failure_after_ready_requires_two_new_successes() {
    let mut sources = valid_sources(&[0, 2, 3, 4, 6]);
    sources.cpu[2] = Err(SampleSourceError::new("CPU read failed"));
    sources.gpu.remove(2);
    sources.power.remove(2);
    let mut clock = ScriptedClock::new([
        millis(0),
        millis(50),
        millis(100),
        millis(150),
        millis(200),
        millis(250),
        millis(300),
        seconds(2),
        millis(2_050),
        millis(2_100),
        millis(2_150),
        millis(2_200),
        millis(2_250),
        millis(2_300),
        seconds(3),
        seconds(4),
        millis(4_050),
        millis(4_100),
        millis(4_150),
        millis(4_200),
        millis(4_250),
        millis(4_300),
        seconds(6),
        millis(6_050),
        millis(6_100),
        millis(6_150),
        millis(6_200),
        millis(6_250),
        millis(6_300),
    ]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "ready");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "error");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "ready");
}

#[test]
fn a_clock_regression_between_inputs_rejects_the_cycle() {
    let mut sources = valid_sources(&[8, 10]);
    let mut clock = ScriptedClock::new([
        seconds(8),
        millis(8_050),
        millis(8_100),
        millis(8_150),
        millis(8_200),
        millis(8_250),
        millis(8_300),
        seconds(10),
        millis(10_500),
        seconds(11),
        millis(10_500),
        millis(10_700),
    ]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::ClockWentBackwards)
    );
}

#[test]
fn a_clock_regression_between_completed_cycles_rejects_and_resets() {
    let mut sources = valid_sources(&[0, 4, 6]);
    let mut times = vec![
        millis(0),
        millis(500),
        millis(1_000),
        millis(1_500),
        millis(1_700),
        millis(1_900),
        millis(2_000),
    ];
    times.push(millis(1_900));
    times.extend(clock_times_for_cycle(seconds(4)));
    times.extend(clock_times_for_cycle(seconds(6)));
    let mut clock = ScriptedClock::new(times);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::ClockWentBackwards)
    );
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "ready");
}

#[test]
fn a_late_cadence_or_lifecycle_reset_discards_the_streak() {
    let mut sources = valid_sources(&[0, 3, 5, 7, 9]);
    let mut clock = clock_for_cycles(&[0, 3, 5, 7, 9]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "ready");

    gate.reset();
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "ready");
}

#[test]
fn unknown_power_is_a_complete_conservative_power_observation() {
    let mut sources = valid_sources(&[0, 2]);
    sources.power[0] = Ok(ExternalPower::Unknown);
    sources.power[1] = Ok(ExternalPower::Unknown);
    let mut clock = clock_for_cycles(&[0, 2]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    let SampleReadiness::Ready(set) = gate.sample(&mut sources, &mut clock).unwrap() else {
        panic!("second complete set must be ready");
    };
    assert_eq!(set.external_power(), ExternalPower::Unknown);
}

#[test]
fn unknown_power_never_masks_an_invalid_temperature() {
    for input in [RequiredInput::Cpu, RequiredInput::Gpu] {
        let mut sources = valid_sources(&[0, 2]);
        sources.power[0] = Ok(ExternalPower::Unknown);
        sources.power[1] = Ok(ExternalPower::Unknown);
        match input {
            RequiredInput::Cpu => {
                sources.cpu[1] = Err(SampleSourceError::new("temperature read failed"));
            }
            RequiredInput::Gpu => {
                sources.gpu[1] = Err(SampleSourceError::new("temperature read failed"));
            }
            RequiredInput::Power => unreachable!(),
        }
        let mut clock =
            ScriptedClock::new(clock_times_for_cycle(Duration::ZERO).into_iter().chain([
                seconds(2),
                millis(2_050),
                millis(2_100),
            ]));
        let mut gate = FreshSampleGate::new();

        assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
        assert!(matches!(
            gate.sample(&mut sources, &mut clock),
            Err(SampleSetError::Input { input: actual, .. }) if actual == input
        ));
    }
}

#[test]
fn completion_exactly_at_the_deadline_is_valid() {
    let mut sources = valid_sources(&[0, 2]);
    let mut clock = ScriptedClock::new([
        millis(0),
        millis(50),
        millis(100),
        millis(150),
        millis(200),
        seconds(2),
        seconds(2),
        seconds(2),
        millis(2_050),
        millis(2_100),
        millis(2_150),
        millis(2_200),
        seconds(4),
        seconds(4),
    ]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "ready");
}

#[test]
fn deadline_overflow_rejects_the_cycle_and_clears_the_streak() {
    let first_start = Duration::MAX - Duration::from_secs(3);
    let overflow_start = Duration::MAX - Duration::from_secs(1);
    let mut sources = ScriptedSources::default();
    for _ in 0..2 {
        sources.cpu.push_back(Ok(temp(70.0)));
        sources.gpu.push_back(Ok(temp(65.0)));
        sources.power.push_back(Ok(ExternalPower::Connected));
    }
    let mut clock = ScriptedClock::new([
        first_start,
        first_start,
        first_start,
        first_start,
        first_start,
        first_start,
        first_start,
        overflow_start,
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
    ]);
    let mut gate = FreshSampleGate::new();

    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
    assert_eq!(
        gate.sample(&mut sources, &mut clock),
        Err(SampleSetError::DeadlineOverflow)
    );
    assert_eq!(sample(&mut gate, &mut sources, &mut clock), "waiting");
}

fn valid_sources(cycle_starts_seconds: &[u64]) -> ScriptedSources {
    let mut sources = ScriptedSources::default();
    for _ in cycle_starts_seconds {
        sources.cpu.push_back(Ok(temp(70.0)));
        sources.gpu.push_back(Ok(temp(65.0)));
        sources.power.push_back(Ok(ExternalPower::Connected));
    }
    sources
}

fn clock_for_cycles(cycle_starts_seconds: &[u64]) -> ScriptedClock {
    let starts = cycle_starts_seconds
        .iter()
        .copied()
        .map(seconds)
        .collect::<Vec<_>>();
    clock_for_cycle_starts(&starts)
}

fn clock_for_cycle_starts(cycle_starts: &[Duration]) -> ScriptedClock {
    ScriptedClock::new(cycle_starts.iter().copied().flat_map(clock_times_for_cycle))
}

fn clock_times_for_cycle(start: Duration) -> [Duration; 7] {
    [
        start,
        start + millis(50),
        start + millis(100),
        start + millis(150),
        start + millis(200),
        start + millis(250),
        start + millis(300),
    ]
}

fn sample(
    gate: &mut FreshSampleGate,
    sources: &mut dyn SampleSources,
    clock: &mut ScriptedClock,
) -> &'static str {
    match gate.sample(sources, clock) {
        Ok(SampleReadiness::AwaitingSecondSample) => "waiting",
        Ok(SampleReadiness::Ready(_)) => "ready",
        Err(_) => "error",
    }
}

fn temp(value: f64) -> TemperatureCelsius {
    TemperatureCelsius::try_from(value).unwrap()
}

fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn millis(value: u64) -> Duration {
    Duration::from_millis(value)
}
