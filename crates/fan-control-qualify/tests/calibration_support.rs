use fan_control_core::{
    CalibrationLevelObservation, CalibrationReadbackSample, CalibrationStep,
    ConservativeFanCalibration, Fan, FanCalibrationEvidence, FanHoldObservation,
};

pub fn completed_calibration(fan: Fan) -> FanCalibrationEvidence {
    let mut session = ConservativeFanCalibration::start(fan);
    let mut clock = 1;
    for rpm in [5_000, 3_800, 3_300, 2_800] {
        record_stable_level(&mut session, rpm, 3_000, &mut clock);
    }
    let step = session.next_step();
    let mut unstable = level_observation(step, 900, 2_000, &mut clock);
    for (index, sample) in unstable.samples.iter_mut().enumerate() {
        sample.selected_rpm = Some(if index % 2 == 0 { 900 } else { 1_300 });
    }
    session.record_level(unstable).unwrap();
    for _ in 0..5 {
        record_stable_level(&mut session, 5_000, 4_000, &mut clock);
        record_stable_level(&mut session, 3_300, 5_000, &mut clock);
    }
    let hold_step = session.next_step();
    let hold_samples = (0..451)
        .map(|index| CalibrationReadbackSample {
            monotonic_millis: clock + index * 2_000,
            selected_enable_readback: 1,
            selected_pwm_readback: hold_step.pwm_value().unwrap(),
            other_enable_readback: 1,
            other_pwm_readback: u8::MAX,
            selected_rpm: Some(3_300),
        })
        .collect();
    clock += 451 * 2_000;
    session
        .record_hold(FanHoldObservation {
            samples: hold_samples,
            stall_observed: false,
            unexplained_rpm_collapse_observed: false,
        })
        .unwrap();
    for (rpm, response) in [
        (3_300, 3_000),
        (3_800, 4_000),
        (4_500, 5_000),
        (6_200, 6_000),
    ] {
        record_stable_level(&mut session, rpm, response, &mut clock);
    }
    session.evidence().unwrap().clone()
}

fn record_stable_level(
    session: &mut ConservativeFanCalibration,
    rpm: u32,
    response_millis: u64,
    clock: &mut u64,
) {
    let observation = level_observation(session.next_step(), rpm, response_millis, clock);
    session.record_level(observation).unwrap();
}

fn level_observation(
    step: CalibrationStep,
    rpm: u32,
    response_millis: u64,
    clock: &mut u64,
) -> CalibrationLevelObservation {
    let started_at = *clock;
    let intervals = response_millis.div_ceil(2_000).max(3);
    *clock += response_millis + 1;
    CalibrationLevelObservation {
        commanded_at_monotonic_millis: started_at,
        samples: (0..=intervals)
            .map(|index| CalibrationReadbackSample {
                monotonic_millis: started_at + response_millis * index / intervals,
                selected_enable_readback: 1,
                selected_pwm_readback: step.pwm_value().unwrap(),
                other_enable_readback: 1,
                other_pwm_readback: u8::MAX,
                selected_rpm: (index + 3 > intervals).then_some(rpm),
            })
            .collect(),
        stall_observed: false,
        unexplained_rpm_collapse_observed: false,
    }
}
