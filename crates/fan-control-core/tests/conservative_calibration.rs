use std::{cell::Cell, fs};

mod support;

use fan_control_core::{
    CalibrationLevelObservation, CalibrationObservationError, CalibrationReadbackSample,
    CalibrationStep, ConservativeFanCalibration, EvidenceFan, EvidenceRecord, Fan,
    FanHoldObservation, MAXIMUM_CALIBRATION_RESPONSE_MILLIS, REQUIRED_FLOOR_HOLD_MILLIS,
    REQUIRED_MAXIMUM_TO_FLOOR_TRANSITIONS, RunOutcomeStatus, parse_evidence_v1, parse_evidence_v2,
};

thread_local! {
    static NEXT_MONOTONIC_MILLIS: Cell<u64> = const { Cell::new(1) };
}

fn allocate_time(duration_millis: u64) -> u64 {
    NEXT_MONOTONIC_MILLIS.with(|next| {
        let started_at = next.get();
        next.set(started_at + duration_millis + 1);
        started_at
    })
}

fn stable(step: CalibrationStep, rpm: u32, response_millis: u64) -> CalibrationLevelObservation {
    let started_at = allocate_time(response_millis);
    let intervals = response_millis.div_ceil(2_000).max(3);
    let samples = (0..=intervals)
        .map(|index| CalibrationReadbackSample {
            monotonic_millis: started_at + response_millis * index / intervals,
            selected_enable_readback: 1,
            selected_pwm_readback: step.pwm_value().unwrap(),
            other_enable_readback: 1,
            other_pwm_readback: u8::MAX,
            selected_rpm: (index + 3 > intervals).then(|| match index + 2 - intervals {
                0 => rpm - 10,
                1 => rpm,
                _ => rpm + 10,
            }),
        })
        .collect();
    CalibrationLevelObservation {
        commanded_at_monotonic_millis: started_at,
        samples,
        stall_observed: false,
        unexplained_rpm_collapse_observed: false,
    }
}

fn unstable(step: CalibrationStep) -> CalibrationLevelObservation {
    let mut observation = stable(step, 900, 2_000);
    for (index, sample) in observation.samples.iter_mut().enumerate() {
        sample.selected_rpm = Some(if index % 2 == 0 { 900 } else { 1_300 });
    }
    observation
}

fn establish_floor(session: &mut ConservativeFanCalibration) {
    for rpm in [5_000, 3_800, 3_300, 2_800] {
        let step = session.next_step();
        session.record_level(stable(step, rpm, 3_000)).unwrap();
    }
    let step = session.next_step();
    assert_eq!(
        step,
        CalibrationStep::Sweep {
            duty_basis_points: 3_000,
            pwm_value: 77
        }
    );
    session.record_level(unstable(step)).unwrap();
    assert_eq!(session.floor_basis_points(), Some(5_000));
}

fn pass_transitions(session: &mut ConservativeFanCalibration) {
    for attempt in 1..=REQUIRED_MAXIMUM_TO_FLOOR_TRANSITIONS {
        let maximum = session.next_step();
        assert_eq!(
            maximum,
            CalibrationStep::TransitionToMaximum {
                attempt,
                pwm_value: 255
            }
        );
        session.record_level(stable(maximum, 5_000, 4_000)).unwrap();

        let floor = session.next_step();
        assert_eq!(
            floor,
            CalibrationStep::TransitionToFloor {
                attempt,
                duty_basis_points: 5_000,
                pwm_value: 128,
            }
        );
        session.record_level(stable(floor, 3_300, 5_000)).unwrap();
    }
}

fn pass_hold(session: &mut ConservativeFanCalibration) {
    let step = session.next_step();
    assert_eq!(
        step,
        CalibrationStep::HoldFloor {
            duty_basis_points: 5_000,
            pwm_value: 128,
            required_duration_millis: REQUIRED_FLOOR_HOLD_MILLIS,
        }
    );
    let samples = hold_samples(step, 451, 2_000);
    session
        .record_hold(FanHoldObservation {
            samples,
            stall_observed: false,
            unexplained_rpm_collapse_observed: false,
        })
        .unwrap();
}

fn hold_samples(
    step: CalibrationStep,
    count: usize,
    gap_millis: u64,
) -> Vec<CalibrationReadbackSample> {
    let duration_millis = count.saturating_sub(1) as u64 * gap_millis;
    let started_at = allocate_time(duration_millis);
    (0..count)
        .map(|index| CalibrationReadbackSample {
            monotonic_millis: started_at + index as u64 * gap_millis,
            selected_enable_readback: 1,
            selected_pwm_readback: step.pwm_value().unwrap(),
            other_enable_readback: 1,
            other_pwm_readback: u8::MAX,
            selected_rpm: Some(3_300),
        })
        .collect()
}

fn complete_calibration(fan: Fan) -> ConservativeFanCalibration {
    let mut session = ConservativeFanCalibration::start(fan);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    pass_hold(&mut session);
    for (rpm, response) in [
        (3_300, 3_000),
        (3_800, 4_000),
        (4_300, 5_000),
        (5_000, 6_000),
    ] {
        let step = session.next_step();
        session.record_level(stable(step, rpm, response)).unwrap();
    }
    session
}

fn passing_publication_record(session: &ConservativeFanCalibration) -> EvidenceRecord {
    let mut record = parse_evidence_v1(include_str!(
        "../../../qualification/evidence-example/evidence-v1.json"
    ))
    .unwrap();
    record.schema_version = 2;
    record.calibration.clear();
    record.faults.clear();
    record
        .thermal_summary
        .as_mut()
        .unwrap()
        .nvidia_faults
        .clear();
    let mut gpu_restoration = record.restoration_attempts[0].clone();
    gpu_restoration.fan = EvidenceFan::Gpu;
    record.restoration_attempts.push(gpu_restoration);
    record.outcome.status = RunOutcomeStatus::Passed;
    record.outcome.reason = "fan calibration passed".into();
    record.outcome.another_passing_run_required = false;
    support::bind_record_to_calibration_protocol(&mut record, session.evidence().unwrap());
    record
}

#[test]
fn descending_sweep_stops_at_first_unstable_level_and_sets_full_step_margin() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);

    establish_floor(&mut session);

    assert_eq!(
        session.next_step(),
        CalibrationStep::TransitionToMaximum {
            attempt: 1,
            pwm_value: 255,
        }
    );
    assert_eq!(session.lowest_stable_basis_points(), Some(4_000));
}

#[test]
fn an_all_stable_sweep_completes_with_a_forty_percent_floor() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    for rpm in [5_000, 3_800, 3_300, 2_800, 2_300] {
        let step = session.next_step();
        session.record_level(stable(step, rpm, 3_000)).unwrap();
    }
    assert_eq!(session.floor_basis_points(), Some(4_000));

    for _ in 0..REQUIRED_MAXIMUM_TO_FLOOR_TRANSITIONS {
        let maximum = session.next_step();
        session.record_level(stable(maximum, 5_000, 4_000)).unwrap();
        let floor = session.next_step();
        assert!(matches!(
            floor,
            CalibrationStep::TransitionToFloor {
                duty_basis_points: 4_000,
                ..
            }
        ));
        session.record_level(stable(floor, 2_800, 5_000)).unwrap();
    }
    let hold = session.next_step();
    assert!(matches!(
        hold,
        CalibrationStep::HoldFloor {
            duty_basis_points: 4_000,
            ..
        }
    ));
    session
        .record_hold(FanHoldObservation {
            samples: hold_samples(hold, 451, 2_000),
            stall_observed: false,
            unexplained_rpm_collapse_observed: false,
        })
        .unwrap();
    for (expected_duty, rpm) in [
        (4_000, 2_800),
        (5_750, 3_500),
        (7_500, 4_300),
        (10_000, 5_000),
    ] {
        let step = session.next_step();
        assert_eq!(step.duty_basis_points(), Some(expected_duty));
        session.record_level(stable(step, rpm, 4_000)).unwrap();
    }

    let evidence = session.evidence().unwrap();
    assert_eq!(evidence.floor_basis_points, 4_000);
    assert_eq!(
        evidence
            .anchors
            .iter()
            .map(|anchor| anchor.duty_basis_points)
            .collect::<Vec<_>>(),
        vec![4_000, 5_750, 7_500, 10_000]
    );
}

#[test]
fn an_unstable_sixty_percent_level_cannot_produce_a_conservative_floor() {
    let mut session = ConservativeFanCalibration::start(Fan::Gpu);
    let maximum = session.next_step();
    session.record_level(stable(maximum, 5_000, 2_000)).unwrap();
    let sixty = session.next_step();

    let error = session.record_level(unstable(sixty)).unwrap_err();

    assert_eq!(
        error,
        CalibrationObservationError::ConservativeMarginUnavailable
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn inconclusive_sweep_observations_terminally_fail_closed() {
    for case in ["sparse", "clustered", "overlong"] {
        let mut session = ConservativeFanCalibration::start(Fan::Cpu);
        for rpm in [5_000, 3_800] {
            let step = session.next_step();
            session.record_level(stable(step, rpm, 2_000)).unwrap();
        }
        let step = session.next_step();
        let mut observation = stable(step, 3_300, if case == "overlong" { 11_000 } else { 2_000 });
        match case {
            "sparse" => {
                let last = observation.samples.len() - 1;
                for sample in &mut observation.samples[..last] {
                    sample.selected_rpm = None;
                }
            }
            "clustered" => {
                let started_at = observation.commanded_at_monotonic_millis;
                for (index, sample) in observation.samples.iter_mut().enumerate() {
                    sample.monotonic_millis = started_at + index as u64;
                }
            }
            "overlong" => {}
            _ => unreachable!(),
        }

        assert_eq!(
            session.record_level(observation).unwrap_err(),
            CalibrationObservationError::InconclusiveObservation,
            "case: {case}"
        );
        assert_eq!(session.next_step(), CalibrationStep::Failed);
    }
}

#[test]
fn a_reported_stall_during_the_sweep_is_the_first_unstable_boundary() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    for rpm in [5_000, 3_800, 3_300, 2_800] {
        let step = session.next_step();
        session.record_level(stable(step, rpm, 2_000)).unwrap();
    }
    let thirty = session.next_step();
    let mut observation = stable(thirty, 2_000, 2_000);
    observation.stall_observed = true;
    for sample in &mut observation.samples {
        sample.selected_rpm = Some(2_000);
    }

    session.record_level(observation).unwrap();

    assert_eq!(session.floor_basis_points(), Some(5_000));
    assert!(matches!(
        session.next_step(),
        CalibrationStep::TransitionToMaximum { attempt: 1, .. }
    ));
}

#[test]
fn a_reported_sweep_stall_cannot_hide_an_invalid_rpm() {
    for invalid_rpm in [0, 20_001] {
        let mut session = ConservativeFanCalibration::start(Fan::Cpu);
        let step = session.next_step();
        let mut observation = stable(step, 5_000, 2_000);
        observation.stall_observed = true;
        observation.samples.last_mut().unwrap().selected_rpm = Some(invalid_rpm);

        assert_eq!(
            session.record_level(observation).unwrap_err(),
            CalibrationObservationError::InvalidRpm
        );
        assert_eq!(session.next_step(), CalibrationStep::Failed);
    }
}

#[test]
fn a_reported_sweep_stall_cannot_hide_a_tachometer_dropout() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    observation.stall_observed = true;

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::InvalidRpm
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn a_zero_tachometer_sample_during_the_sweep_is_invalid() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    observation.samples.last_mut().unwrap().selected_rpm = Some(0);

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::InvalidRpm
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn an_unreadable_tachometer_sweep_observation_is_invalid() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    for sample in &mut observation.samples {
        sample.selected_rpm = None;
    }

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::InvalidRpm
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn five_complete_maximum_to_floor_transitions_are_required_before_the_hold() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);

    for attempt in 1..=REQUIRED_MAXIMUM_TO_FLOOR_TRANSITIONS {
        let maximum = session.next_step();
        session.record_level(stable(maximum, 5_000, 4_000)).unwrap();
        assert_eq!(
            session.next_step(),
            CalibrationStep::TransitionToFloor {
                attempt,
                duty_basis_points: 5_000,
                pwm_value: 128,
            }
        );
        let floor = session.next_step();
        session.record_level(stable(floor, 3_300, 5_000)).unwrap();
    }

    assert!(matches!(
        session.next_step(),
        CalibrationStep::HoldFloor { .. }
    ));
}

#[test]
fn hold_requires_fifteen_minutes_with_no_sampling_gap() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    let step = session.next_step();
    let samples = hold_samples(step, 450, 2_001);

    let error = session
        .record_hold(FanHoldObservation {
            samples,
            stall_observed: false,
            unexplained_rpm_collapse_observed: false,
        })
        .unwrap_err();

    assert_eq!(error, CalibrationObservationError::IncompleteHold);
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn clustered_hold_samples_cannot_claim_fifteen_minutes() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    let step = session.next_step();

    let error = session
        .record_hold(FanHoldObservation {
            samples: hold_samples(step, 451, 1),
            stall_observed: false,
            unexplained_rpm_collapse_observed: false,
        })
        .unwrap_err();

    assert_eq!(error, CalibrationObservationError::IncompleteHold);
}

#[test]
fn hold_rejects_reported_stall_or_unexplained_rpm_collapse() {
    for (stall_observed, unexplained_rpm_collapse_observed) in [(true, false), (false, true)] {
        let mut session = ConservativeFanCalibration::start(Fan::Cpu);
        establish_floor(&mut session);
        pass_transitions(&mut session);
        let step = session.next_step();

        assert_eq!(
            session
                .record_hold(FanHoldObservation {
                    samples: hold_samples(step, 451, 2_000),
                    stall_observed,
                    unexplained_rpm_collapse_observed,
                })
                .unwrap_err(),
            CalibrationObservationError::IncompleteHold
        );
    }
}

#[test]
fn hold_must_start_after_the_fifth_floor_transition() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    let step = session.next_step();
    let mut samples = hold_samples(step, 451, 2_000);
    for (index, sample) in samples.iter_mut().enumerate() {
        sample.monotonic_millis = 1 + index as u64 * 2_000;
    }

    assert_eq!(
        session
            .record_hold(FanHoldObservation {
                samples,
                stall_observed: false,
                unexplained_rpm_collapse_observed: false,
            })
            .unwrap_err(),
        CalibrationObservationError::UnexpectedStep
    );
}

#[test]
fn other_fan_must_remain_in_custom_mode_at_verified_maximum() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    observation.samples[1].other_pwm_readback = 254;

    let error = session.record_level(observation).unwrap_err();

    assert_eq!(error, CalibrationObservationError::OtherFanNotAtMaximum);
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn exact_selected_mode_and_pwm_readback_are_required() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    observation.samples[1].selected_enable_readback = 2;

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::SelectedFanReadbackMismatch
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn selected_pwm_readback_must_exactly_match_the_command() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    observation.samples[1].selected_pwm_readback = 254;

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::SelectedFanReadbackMismatch
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn other_fan_enable_readback_must_remain_in_custom_mode() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    observation.samples[1].other_enable_readback = 2;

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::OtherFanNotAtMaximum
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn a_failed_transition_terminally_rejects_the_stage() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    let maximum = session.next_step();
    session.record_level(stable(maximum, 5_000, 4_000)).unwrap();
    let floor = session.next_step();

    let error = session.record_level(unstable(floor)).unwrap_err();

    assert_eq!(error, CalibrationObservationError::UnstableRequiredLevel);
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn completed_stage_writes_ordered_rpm_anchors_and_capped_response_deadline() {
    let mut session = ConservativeFanCalibration::start(Fan::Gpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    pass_hold(&mut session);

    for (duty, rpm, response) in [
        (5_000, 3_300, 5_000),
        (6_250, 3_800, 6_000),
        (7_500, 4_300, 9_500),
        (10_000, 5_000, 8_000),
    ] {
        let step = session.next_step();
        assert_eq!(step.duty_basis_points(), Some(duty));
        session.record_level(stable(step, rpm, response)).unwrap();
    }

    assert_eq!(session.next_step(), CalibrationStep::Complete);
    let evidence = session.evidence().unwrap();
    assert_eq!(evidence.fan, EvidenceFan::Gpu);
    assert_eq!(evidence.floor_basis_points, 5_000);
    assert_eq!(
        evidence.response_deadline_millis,
        MAXIMUM_CALIBRATION_RESPONSE_MILLIS
    );
    assert_eq!(
        evidence
            .anchors
            .iter()
            .map(|anchor| (anchor.duty_basis_points, anchor.median_rpm))
            .collect::<Vec<_>>(),
        vec![
            (5_000, 3_300),
            (6_250, 3_800),
            (7_500, 4_300),
            (10_000, 5_000)
        ]
    );
}

#[test]
fn completed_calibration_is_atomically_published_as_protected_v2_evidence() {
    let session = complete_calibration(Fan::Cpu);
    let record = passing_publication_record(&session);
    let directory = std::env::temp_dir().join(format!(
        "pt31553-calibration-publication-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).unwrap();
    let destination = directory.join("calibration.json");

    session.publish_evidence(&destination, record).unwrap();

    let published = parse_evidence_v2(&fs::read_to_string(&destination).unwrap()).unwrap();
    assert_eq!(published.stage, "fan-calibration");
    assert_eq!(
        published.calibration,
        vec![session.evidence().unwrap().clone()]
    );
    let mut stripped = published;
    stripped.calibration.clear();
    assert!(stripped.validate().is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn calibration_publication_rejects_failed_or_no_go_outcomes() {
    let session = complete_calibration(Fan::Cpu);
    for status in [RunOutcomeStatus::Failed, RunOutcomeStatus::NoGo] {
        let mut record = passing_publication_record(&session);
        record.outcome.status = status;
        let destination = std::env::temp_dir().join(format!(
            "pt31553-calibration-unsuccessful-{}-{status:?}.json",
            std::process::id()
        ));

        assert!(matches!(
            session.publish_evidence(&destination, record),
            Err(fan_control_core::CalibrationEvidenceWriteError::UnsuccessfulEvidenceOutcome)
        ));
        assert!(!destination.exists());
    }
}

#[test]
fn a_post_completion_failure_clears_publishable_evidence() {
    let mut session = complete_calibration(Fan::Cpu);
    assert!(session.evidence().is_some());
    let record = passing_publication_record(&session);

    assert_eq!(
        session
            .record_hold(FanHoldObservation {
                samples: Vec::new(),
                stall_observed: false,
                unexplained_rpm_collapse_observed: false,
            })
            .unwrap_err(),
        CalibrationObservationError::UnexpectedStep
    );
    assert!(session.evidence().is_none());
    let destination = std::env::temp_dir().join(format!(
        "pt31553-calibration-after-failure-{}.json",
        std::process::id()
    ));
    assert!(matches!(
        session.publish_evidence(&destination, record),
        Err(fan_control_core::CalibrationEvidenceWriteError::IncompleteCalibration)
    ));
    assert!(!destination.exists());
}

#[test]
fn calibration_publication_rejects_a_legacy_v1_record() {
    let session = complete_calibration(Fan::Cpu);
    let mut record = parse_evidence_v1(include_str!(
        "../../../qualification/evidence-example/evidence-v1.json"
    ))
    .unwrap();
    record.calibration.clear();
    let destination = std::env::temp_dir().join(format!(
        "pt31553-calibration-v1-rejected-{}.json",
        std::process::id()
    ));

    assert!(matches!(
        session.publish_evidence(&destination, record),
        Err(fan_control_core::CalibrationEvidenceWriteError::UnsupportedEvidenceVersion)
    ));
    assert!(!destination.exists());
}

#[test]
fn slowest_response_plus_two_seconds_is_used_when_below_the_cap() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    pass_hold(&mut session);

    for (rpm, response) in [
        (3_300, 3_000),
        (3_800, 4_000),
        (4_300, 5_000),
        (5_000, 6_000),
    ] {
        let step = session.next_step();
        session.record_level(stable(step, rpm, response)).unwrap();
    }

    assert_eq!(session.evidence().unwrap().response_deadline_millis, 8_000);
}

#[test]
fn a_checkpoint_clone_resumes_at_the_exact_pending_action() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let first = session.next_step();
    session.record_level(stable(first, 5_000, 2_000)).unwrap();

    let mut resumed = ConservativeFanCalibration::resume(Fan::Cpu, session.checkpoint()).unwrap();

    assert_eq!(
        resumed.next_step(),
        CalibrationStep::RevalidateBothAtMaximum { pwm_value: 255 }
    );
    let revalidation = resumed.next_step();
    let mut observation = stable(revalidation, 5_000, 2_000);
    observation.commanded_at_monotonic_millis += 60_000;
    for sample in &mut observation.samples {
        sample.monotonic_millis += 60_000;
    }
    resumed.record_level(observation).unwrap();
    assert_eq!(
        resumed.next_step(),
        CalibrationStep::Sweep {
            duty_basis_points: 6_000,
            pwm_value: 153,
        }
    );
}

#[test]
fn checkpoint_survives_a_json_round_trip_before_resuming() {
    let mut session = ConservativeFanCalibration::start(Fan::Gpu);
    let first = session.next_step();
    session.record_level(stable(first, 5_000, 2_000)).unwrap();
    let serialized = serde_json::to_string(&session.checkpoint()).unwrap();
    let checkpoint = serde_json::from_str(&serialized).unwrap();

    let resumed = ConservativeFanCalibration::resume(Fan::Gpu, checkpoint).unwrap();

    assert_eq!(
        resumed.next_step(),
        CalibrationStep::RevalidateBothAtMaximum { pwm_value: 255 }
    );
}

#[test]
fn a_resumed_floor_hold_requires_maximum_revalidation_first() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    let mut resumed = ConservativeFanCalibration::resume(Fan::Cpu, session.checkpoint()).unwrap();

    let revalidation = resumed.next_step();
    assert_eq!(
        revalidation,
        CalibrationStep::RevalidateBothAtMaximum { pwm_value: 255 }
    );
    resumed
        .record_level(stable(revalidation, 5_000, 2_000))
        .unwrap();
    assert!(matches!(
        resumed.next_step(),
        CalibrationStep::HoldFloor {
            duty_basis_points: 5_000,
            ..
        }
    ));
    pass_hold(&mut resumed);
    assert!(matches!(
        resumed.next_step(),
        CalibrationStep::CaptureAnchor { .. }
    ));
}

#[test]
fn a_maximum_duty_hold_cannot_replace_the_resumed_floor_hold() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    let mut resumed = ConservativeFanCalibration::resume(Fan::Cpu, session.checkpoint()).unwrap();
    let revalidation = resumed.next_step();

    assert_eq!(
        resumed
            .record_hold(FanHoldObservation {
                samples: hold_samples(revalidation, 451, 2_000),
                stall_observed: false,
                unexplained_rpm_collapse_observed: false,
            })
            .unwrap_err(),
        CalibrationObservationError::UnexpectedStep
    );
    assert_eq!(resumed.next_step(), CalibrationStep::Failed);
}

#[test]
fn checkpoint_replay_rejects_a_duplicated_transition_pair() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    let maximum = session.next_step();
    session.record_level(stable(maximum, 5_000, 4_000)).unwrap();
    let floor = session.next_step();
    session.record_level(stable(floor, 3_300, 5_000)).unwrap();

    let mut checkpoint = serde_json::to_value(session.checkpoint()).unwrap();
    let events = checkpoint["events"].as_array_mut().unwrap();
    let pair = events[events.len() - 2..].to_vec();
    events.extend(pair.clone());
    events.extend(pair.clone());
    events.extend(pair.clone());
    events.extend(pair);
    let checkpoint = serde_json::from_value(checkpoint).unwrap();

    assert_eq!(
        ConservativeFanCalibration::resume(Fan::Cpu, checkpoint).unwrap_err(),
        CalibrationObservationError::InvalidCheckpoint
    );
}

#[test]
fn checkpoint_replay_rejects_an_event_appended_after_completion() {
    let session = complete_calibration(Fan::Cpu);
    let mut checkpoint = serde_json::to_value(session.checkpoint()).unwrap();
    let events = checkpoint["events"].as_array_mut().unwrap();
    let mut appended = events[0].clone();
    appended["observation"]["step"] = serde_json::json!({
        "kind": "revalidate-both-at-maximum",
        "pwm_value": 255
    });
    events.push(appended);
    let checkpoint = serde_json::from_value(checkpoint).unwrap();

    assert_eq!(
        ConservativeFanCalibration::resume(Fan::Cpu, checkpoint).unwrap_err(),
        CalibrationObservationError::InvalidCheckpoint
    );
}

#[test]
fn checkpoint_replay_rejects_overlapping_event_times() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let first = session.next_step();
    session.record_level(stable(first, 5_000, 2_000)).unwrap();
    let second = session.next_step();
    session.record_level(stable(second, 3_800, 2_000)).unwrap();
    let mut checkpoint = serde_json::to_value(session.checkpoint()).unwrap();
    let events = checkpoint["events"].as_array_mut().unwrap();
    let first_start = events[0]["observation"]["observation"]["commanded_at_monotonic_millis"]
        .as_u64()
        .unwrap();
    let second_observation = &mut events[1]["observation"]["observation"];
    let old_start = second_observation["commanded_at_monotonic_millis"]
        .as_u64()
        .unwrap();
    second_observation["commanded_at_monotonic_millis"] = first_start.into();
    for sample in second_observation["samples"].as_array_mut().unwrap() {
        let timestamp = sample["monotonic_millis"].as_u64().unwrap();
        sample["monotonic_millis"] = (timestamp - old_start + first_start).into();
    }
    let checkpoint = serde_json::from_value(checkpoint).unwrap();

    assert_eq!(
        ConservativeFanCalibration::resume(Fan::Cpu, checkpoint).unwrap_err(),
        CalibrationObservationError::InvalidCheckpoint
    );
}

#[test]
fn tampered_checkpoint_cannot_resume() {
    let session = ConservativeFanCalibration::start(Fan::Cpu);
    let mut checkpoint = serde_json::to_value(session.checkpoint()).unwrap();
    checkpoint["events"] = serde_json::json!([{
        "kind": "level",
        "observation": {
            "step": {"kind": "sweep", "duty_basis_points": 10000, "pwm_value": 255},
            "observation": serde_json::to_value(stable(
                CalibrationStep::Sweep { duty_basis_points: 10_000, pwm_value: 255 },
                5_000,
                2_000
            )).unwrap()
        }
    }]);
    checkpoint["events"][0]["observation"]["observation"]["samples"][0]["selected_pwm_readback"] =
        serde_json::json!(254);
    let checkpoint = serde_json::from_value(checkpoint).unwrap();

    assert_eq!(
        ConservativeFanCalibration::resume(Fan::Cpu, checkpoint).unwrap_err(),
        CalibrationObservationError::InvalidCheckpoint
    );
}

#[test]
fn checkpoint_resume_requires_the_independently_expected_fan() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    session.record_level(stable(step, 5_000, 2_000)).unwrap();
    let checkpoint = session.checkpoint();

    assert_eq!(
        ConservativeFanCalibration::resume(Fan::Gpu, checkpoint).unwrap_err(),
        CalibrationObservationError::InvalidCheckpoint
    );
}

#[test]
fn hold_rejects_a_period_without_continuous_exact_readbacks() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    let step = session.next_step();
    let mut samples = hold_samples(step, 451, 2_000);
    samples[225].other_pwm_readback = 254;

    let error = session
        .record_hold(FanHoldObservation {
            samples,
            stall_observed: false,
            unexplained_rpm_collapse_observed: false,
        })
        .unwrap_err();

    assert_eq!(error, CalibrationObservationError::OtherFanNotAtMaximum);
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn implausibly_high_rpm_is_invalid_not_a_sweep_boundary() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    for sample in &mut observation.samples {
        if sample.selected_rpm.is_some() {
            sample.selected_rpm = Some(20_001);
        }
    }

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::InvalidRpm
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn a_required_level_rejects_a_missing_final_tachometer_readback() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    observation.samples.last_mut().unwrap().selected_rpm = None;

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::InvalidRpm
    );
}

#[test]
fn a_tachometer_dropout_cannot_hide_an_rpm_collapse() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 4_000);
    let first_rpm = observation
        .samples
        .iter()
        .position(|sample| sample.selected_rpm.is_some())
        .unwrap();
    observation.samples[first_rpm].selected_rpm = Some(100);
    observation.samples[first_rpm + 1].selected_rpm = None;

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::InvalidRpm
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn an_inter_step_verification_gap_terminally_rejects_calibration() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    let first = session.next_step();
    session.record_level(stable(first, 5_000, 2_000)).unwrap();
    let second = session.next_step();
    let mut observation = stable(second, 3_800, 2_000);
    observation.commanded_at_monotonic_millis += 2_000;
    for sample in &mut observation.samples {
        sample.monotonic_millis += 2_000;
    }

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::UnexpectedStep
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}

#[test]
fn millisecond_clustered_samples_do_not_prove_a_settled_response() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    let step = session.next_step();
    let mut observation = stable(step, 5_000, 2_000);
    let started_at = observation.commanded_at_monotonic_millis;
    for (index, sample) in observation.samples.iter_mut().enumerate() {
        sample.monotonic_millis = started_at + index as u64;
    }

    assert_eq!(
        session.record_level(observation).unwrap_err(),
        CalibrationObservationError::InconclusiveObservation
    );
}

#[test]
fn decreasing_anchor_medians_reject_protected_evidence() {
    let mut session = ConservativeFanCalibration::start(Fan::Cpu);
    establish_floor(&mut session);
    pass_transitions(&mut session);
    pass_hold(&mut session);
    let floor = session.next_step();
    session.record_level(stable(floor, 3_300, 5_000)).unwrap();
    let midpoint = session.next_step();

    assert_eq!(
        session
            .record_level(stable(midpoint, 3_000, 5_000))
            .unwrap_err(),
        CalibrationObservationError::DecreasingAnchorRpm
    );
    assert_eq!(session.next_step(), CalibrationStep::Failed);
}
