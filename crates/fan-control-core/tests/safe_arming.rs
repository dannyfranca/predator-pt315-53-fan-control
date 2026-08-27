use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use fan_control_core::{
    AcerHwmonDiscoveryError, AdmittedPolicyAuthority, ArmingReadySample, BoundedFileAccess,
    BoundedIdentityBoundFileAccess, Clock, ControllerOwnership, EmergencyFanStatus, ExternalPower,
    FakePlatform, FakeRuntimeLock, Fan, FanArmingError, FanArmingFailure, FanArmingOperation,
    FanArmingReadback, FileAccess, FileIdentity, FilePermissions, FreshSampleGate,
    IdentityBoundFileAccess, ObservedSample, OwnershipSampleReadiness, PlatformError,
    PlatformErrorKind, PlatformOperation, QUALIFICATION_RECORD_PATH,
    RootOwnedQualificationRecordAccess, RuntimeLockAccess, RuntimeLockError,
    SUPERVISED_ENDURANCE_EVIDENCE_PATH, SampleCapture, SampleSetError, SampleSourceError,
    SampleSources, ServiceAccess, TemperatureCelsius, ValidatedConfig,
    acquire_controller_ownership, admit_policy_authority, arm_both_fans_safely,
    discover_acer_hwmon,
};

mod support;
use support::{
    PROTECTED_POLICY, diagnostic_field, matching_endurance_evidence,
    matching_observation_for_policy, matching_record, protected_config, record_diagnostics,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const ACER_ROOT: &str = "/sys/class/hwmon/hwmon7";

#[derive(Debug, Default)]
struct HealthySources;

impl SampleSources for HealthySources {
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

#[derive(Debug, Default)]
struct FailingCpuSources;

impl SampleSources for FailingCpuSources {
    fn sample_cpu(
        &mut self,
        _capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        Err(SampleSourceError::new("CPU sample unavailable"))
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        HealthySources.sample_gpu(capture)
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        HealthySources.observe_external_power(capture)
    }
}

#[test]
fn ownership_cannot_mint_an_arming_sample_before_firmware_auto_confirmation() {
    let (mut platform, device) = fixture("2400\n", "2600\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let mut gate = FreshSampleGate::new();
    let mut sources = HealthySources;

    assert_eq!(
        ownership.collect_fresh_sample(&device, &mut gate, &mut sources),
        Err(SampleSetError::FirmwareAutoUnconfirmed)
    );

    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn policy_admission_rechecks_auto_after_restoration() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform =
        PathAwarePlatform::new(platform, InjectedFault::ChangeGpuModeBeforeAdmission);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    ownership.restore_firmware_auto(&device).unwrap();

    let error = admit_policy_authority(
        &mut ownership,
        &device,
        PROTECTED_POLICY,
        Path::new(QUALIFICATION_RECORD_PATH),
        &[matching_observation_for_policy(PROTECTED_POLICY)],
    )
    .unwrap_err();

    assert!(matches!(
        error.reason(),
        fan_control_core::PolicyAuthorityError::FirmwareAutoUnconfirmed
    ));
    assert_eq!(
        ownership.platform().inner.file_contents(cpu_enable()),
        Some("2")
    );
    assert_eq!(
        ownership.platform().inner.file_contents(gpu_enable()),
        Some("2")
    );
    ownership.release().unwrap();
}

#[test]
fn every_sample_rechecks_auto_and_sample_failure_invalidates_release() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform =
        PathAwarePlatform::new(platform, InjectedFault::ChangeGpuModeBeforeSecondSample);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    ownership.restore_firmware_auto(&device).unwrap();
    let mut gate = FreshSampleGate::new();
    let mut sources = HealthySources;
    assert_eq!(
        ownership
            .collect_fresh_sample(&device, &mut gate, &mut sources)
            .unwrap(),
        OwnershipSampleReadiness::AwaitingSecondSample
    );
    ownership.delay(Duration::from_secs(2));

    assert_eq!(
        ownership.collect_fresh_sample(&device, &mut gate, &mut sources),
        Err(SampleSetError::FirmwareAutoUnconfirmed)
    );
    let mut ownership = ownership.release().unwrap_err().into_ownership();
    ownership.restore_firmware_auto(&device).unwrap();

    let mut failing_sources = FailingCpuSources;
    assert!(
        ownership
            .collect_fresh_sample(&device, &mut gate, &mut failing_sources)
            .is_err()
    );
    let mut ownership = ownership.release().unwrap_err().into_ownership();
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn admitted_two_sample_handover_reaches_verified_maximum_without_normal_demand() {
    let (mut platform, device) = fixture("2400\n", "2600\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);
    let marker = ownership.platform().operations().len();

    let armed =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap();

    assert_eq!(armed.cpu_rpm(), 2400);
    assert_eq!(armed.gpu_rpm(), 2600);
    assert!(armed.is_current_for(&ownership));
    assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("1"));
    assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("1"));
    assert_eq!(ownership.platform().file_contents(cpu_pwm()), Some("255"));
    assert_eq!(ownership.platform().file_contents(gpu_pwm()), Some("255"));

    let operations = &ownership.platform().operations()[marker..];
    let cpu_custom = operations
        .iter()
        .position(|operation| is_write(operation, cpu_enable(), "1"))
        .unwrap();
    let gpu_custom = operations
        .iter()
        .position(|operation| is_write(operation, gpu_enable(), "1"))
        .unwrap();
    assert!(cpu_custom < gpu_custom);
    assert!(
        operations[cpu_custom + 1..gpu_custom]
            .iter()
            .all(|operation| !matches!(operation, PlatformOperation::Write { .. }))
    );
    let first_custom = cpu_custom.min(gpu_custom);
    for path in [cpu_pwm(), gpu_pwm()] {
        let write = operations
            .iter()
            .position(|operation| is_write(operation, path, "255"))
            .unwrap();
        let readback = operations
            .iter()
            .enumerate()
            .skip(write + 1)
            .find(|(_, operation)| matches!(operation, PlatformOperation::Read(actual) if actual == path))
            .map(|(index, _)| index)
            .unwrap();
        assert!(readback < first_custom);
    }
    assert!(operations.iter().all(|operation| {
        !matches!(operation, PlatformOperation::Write { path, contents }
            if (path == cpu_pwm() || path == gpu_pwm()) && contents != "255")
    }));

    ownership.restore_firmware_auto(&device).unwrap();
    assert!(!armed.is_current_for(&ownership));
    ownership.release().unwrap();
}

#[test]
fn gpu_handover_failure_restores_both_without_applying_normal_demand() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform = PathAwarePlatform::new(platform, InjectedFault::RejectGpuCustom);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::Platform {
            fan: Fan::Gpu,
            operation: FanArmingOperation::EnterCustom,
            ..
        })
    ));
    assert!(ownership.platform().cpu_custom_written);
    assert!(ownership.platform().gpu_custom_attempted);
    assert_eq!(
        ownership.platform().inner.file_contents(cpu_enable()),
        Some("2")
    );
    assert_eq!(
        ownership.platform().inner.file_contents(gpu_enable()),
        Some("2")
    );
    assert!(
        ownership
            .platform()
            .inner
            .operations()
            .iter()
            .all(|operation| {
                !matches!(operation, PlatformOperation::Write { path, contents }
            if (path == cpu_pwm() || path == gpu_pwm()) && contents != "255")
            })
    );

    ownership.release().unwrap();
}

#[test]
fn pre_handover_failures_attempt_full_restoration() {
    for (fault, fan, operation) in [
        (
            InjectedFault::RejectInitialCpuAutoRead,
            Fan::Cpu,
            FanArmingOperation::ConfirmFirmwareAuto,
        ),
        (
            InjectedFault::RejectGpuMaximumWrite,
            Fan::Gpu,
            FanArmingOperation::StageMaximum,
        ),
        (
            InjectedFault::CorruptCpuMaximumReadback,
            Fan::Cpu,
            FanArmingOperation::ReadDuty,
        ),
    ] {
        let (platform, device) = fixture("2400\n", "2600\n");
        let mut platform = PathAwarePlatform::new(platform, fault);
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);
        let marker = ownership.platform().inner.operations().len();

        let error = arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample)
            .unwrap_err();

        assert!(
            matches!(
                error.reason(),
                FanArmingFailure::Platform {
                    fan: actual_fan,
                    operation: actual_operation,
                    ..
                } if *actual_fan == fan && *actual_operation == operation
            ) || matches!(
                error.reason(),
                FanArmingFailure::UnexpectedReadback {
                    fan: actual_fan,
                    operation: actual_operation,
                    ..
                } if *actual_fan == fan && *actual_operation == operation
            ),
            "{error:?}"
        );
        assert_auto_restoration_attempted(&ownership.platform().inner, marker);
        assert_eq!(
            ownership.platform().inner.file_contents(cpu_enable()),
            Some("2")
        );
        assert_eq!(
            ownership.platform().inner.file_contents(gpu_enable()),
            Some("2")
        );
        ownership.release().unwrap();
    }
}

#[test]
fn state_change_after_tachometer_response_is_rejected_by_final_verification() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform = PathAwarePlatform::new(platform, InjectedFault::ChangeCpuModeAfterTach);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::UnexpectedReadback {
            fan: Fan::Cpu,
            operation: FanArmingOperation::FinalConfirmCustom,
            ..
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
    ownership.release().unwrap();
}

#[test]
fn pwm_changes_after_tachometer_response_are_rejected_by_final_verification() {
    for (fault, fan) in [
        (InjectedFault::ChangeCpuPwmAfterTach, Fan::Cpu),
        (InjectedFault::ChangeGpuPwmAfterTach, Fan::Gpu),
    ] {
        let (platform, device) = fixture("2400\n", "2600\n");
        let mut platform = PathAwarePlatform::new(platform, fault);
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

        let error = arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample)
            .unwrap_err();

        assert!(matches!(
            error,
            FanArmingError::Rejected(FanArmingFailure::UnexpectedReadback {
                fan: actual,
                operation: FanArmingOperation::FinalConfirmCustom,
                ..
            }) if actual == fan
        ));
        assert_eq!(
            ownership.platform().inner.file_contents(cpu_enable()),
            Some("2")
        );
        assert_eq!(
            ownership.platform().inner.file_contents(gpu_enable()),
            Some("2")
        );
        ownership.release().unwrap();
    }
}

#[test]
fn cpu_change_during_final_gpu_snapshot_is_caught_by_closing_recheck() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform =
        PathAwarePlatform::new(platform, InjectedFault::ChangeCpuPwmDuringFinalGpuSnapshot);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::UnexpectedReadback {
            fan: Fan::Cpu,
            operation: FanArmingOperation::FinalConfirmCustom,
            ..
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
    ownership.release().unwrap();
}

#[test]
fn gpu_change_during_closing_cpu_read_is_caught_before_success() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform =
        PathAwarePlatform::new(platform, InjectedFault::ChangeGpuPwmDuringClosingCpuRead);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::UnexpectedReadback {
            fan: Fan::Gpu,
            operation: FanArmingOperation::FinalConfirmCustom,
            ..
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
    ownership.release().unwrap();
}

#[test]
fn failed_restoration_is_reported_and_blocks_release_until_a_confirmed_retry() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform =
        PathAwarePlatform::new(platform, InjectedFault::RejectGpuCustomAndRestoration);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    let FanArmingError::RestorationFailed { containment, .. } = error else {
        panic!("failed restoration must report containment")
    };
    assert_eq!(containment.cpu(), &EmergencyFanStatus::MaximumConfirmed);
    assert_eq!(containment.gpu(), &EmergencyFanStatus::FirmwareAuto);
    let mut ownership = ownership.release().unwrap_err().into_ownership();
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn containment_that_confirms_auto_reports_recovered_restoration_failure() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform = PathAwarePlatform::new(
        platform,
        InjectedFault::RejectGpuCustomWithTransientAutoReadFailures,
    );
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Recovered {
            reason: FanArmingFailure::Platform {
                fan: Fan::Gpu,
                operation: FanArmingOperation::EnterCustom,
                ..
            },
            ..
        }
    ));
    assert_eq!(
        ownership.platform().inner.file_contents(cpu_enable()),
        Some("2")
    );
    assert_eq!(
        ownership.platform().inner.file_contents(gpu_enable()),
        Some("2")
    );
    ownership.release().unwrap();
}

#[test]
fn handover_deadline_failure_occurs_only_after_both_custom_writes_then_restores() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform = PathAwarePlatform::new(platform, InjectedFault::ExpireCustomConfirmation);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(
        matches!(
            error,
            FanArmingError::Rejected(FanArmingFailure::Platform {
                fan: Fan::Cpu,
                operation: FanArmingOperation::ConfirmCustom,
                ..
            })
        ),
        "{error:?}"
    );
    assert!(ownership.platform().cpu_custom_written);
    assert!(ownership.platform().gpu_custom_written);
    assert_eq!(
        ownership.platform().inner.file_contents(cpu_enable()),
        Some("2")
    );
    assert_eq!(
        ownership.platform().inner.file_contents(gpu_enable()),
        Some("2")
    );
    ownership.release().unwrap();
}

#[test]
fn custom_duty_read_failure_is_attributed_to_the_pwm_endpoint() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform = PathAwarePlatform::new(platform, InjectedFault::RejectCpuCustomDutyRead);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let (error, diagnostic_events) = record_diagnostics(|| {
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err()
    });

    assert!(matches!(
        error.reason(),
        FanArmingFailure::Platform {
            fan: Fan::Cpu,
            operation: FanArmingOperation::ConfirmCustom,
            readback: Some(FanArmingReadback::Duty),
            ..
        }
    ));
    let fault = diagnostic_events
        .iter()
        .find(|event| {
            event.get("fault_id").map(|value| value.trim_matches('"')) == Some("arming-rejected")
        })
        .unwrap();
    assert_eq!(diagnostic_field(fault, "endpoint"), "acer:cpu:pwm1");
    ownership.release().unwrap();
}

#[test]
fn implausible_nonzero_tachometer_values_restore_both() {
    for cpu_rpm in ["1\n", "20001\n", "4294967295\n"] {
        let (mut platform, device) = fixture(cpu_rpm, "2600\n");
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

        let error = arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample)
            .unwrap_err();

        assert!(matches!(
            error,
            FanArmingError::Rejected(FanArmingFailure::InvalidTachometer { fan: Fan::Cpu, .. })
        ));
        assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("2"));
        assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("2"));
        ownership.release().unwrap();
    }
}

#[test]
fn malformed_tachometer_values_restore_both() {
    for (cpu_rpm, gpu_rpm, fan) in [("NaN\n", "2600\n", Fan::Cpu), ("2400\n", "-1\n", Fan::Gpu)] {
        let (mut platform, device) = fixture(cpu_rpm, gpu_rpm);
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

        let error = arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample)
            .unwrap_err();

        assert!(matches!(
            error,
            FanArmingError::Rejected(FanArmingFailure::InvalidTachometer {
                fan: actual,
                ..
            }) if actual == fan
        ));
        assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("2"));
        assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("2"));
        ownership.release().unwrap();
    }
}

#[test]
fn tachometer_read_failures_restore_both() {
    for (fault, fan) in [
        (InjectedFault::RejectCpuTachRead, Fan::Cpu),
        (InjectedFault::RejectGpuTachRead, Fan::Gpu),
    ] {
        let (platform, device) = fixture("2400\n", "2600\n");
        let mut platform = PathAwarePlatform::new(platform, fault);
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

        let error = arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample)
            .unwrap_err();

        assert!(matches!(
            error,
            FanArmingError::Rejected(FanArmingFailure::Platform {
                fan: actual,
                operation: FanArmingOperation::ReadTachometer,
                ..
            }) if actual == fan
        ));
        assert_eq!(
            ownership.platform().inner.file_contents(cpu_enable()),
            Some("2")
        );
        assert_eq!(
            ownership.platform().inner.file_contents(gpu_enable()),
            Some("2")
        );
        ownership.release().unwrap();
    }
}

#[test]
fn failed_handover_starts_a_new_two_sample_epoch() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform = PathAwarePlatform::new(platform, InjectedFault::RejectGpuCustom);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    ownership.restore_firmware_auto(&device).unwrap();
    let authority = admit_policy_authority(
        &mut ownership,
        &device,
        PROTECTED_POLICY,
        Path::new(QUALIFICATION_RECORD_PATH),
        &[matching_observation_for_policy(PROTECTED_POLICY)],
    )
    .unwrap();
    let candidate = protected_config(PROTECTED_POLICY);
    let mut gate = FreshSampleGate::new();
    let mut sources = HealthySources;
    assert_eq!(
        ownership
            .collect_fresh_sample(&device, &mut gate, &mut sources)
            .unwrap(),
        OwnershipSampleReadiness::AwaitingSecondSample
    );
    ownership.delay(Duration::from_secs(2));
    let OwnershipSampleReadiness::Ready(sample) = ownership
        .collect_fresh_sample(&device, &mut gate, &mut sources)
        .unwrap()
    else {
        panic!("second complete sample must arm the freshness gate")
    };

    arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert_eq!(
        ownership
            .collect_fresh_sample(&device, &mut gate, &mut sources)
            .unwrap(),
        OwnershipSampleReadiness::AwaitingSecondSample
    );
    ownership.restore_firmware_auto(&device).unwrap();
    ownership.release().unwrap();
}

#[test]
fn ready_sample_is_invalidated_by_a_new_firmware_auto_epoch() {
    let (mut platform, device) = fixture("2400\n", "2600\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);
    ownership.restore_firmware_auto(&device).unwrap();
    let marker = ownership.platform().operations().len();

    let (error, diagnostic_events) = record_diagnostics(|| {
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err()
    });

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::ObsoleteSampleEpoch)
    ));
    let fault = diagnostic_events
        .iter()
        .find(|event| diagnostic_field(event, "event_id") == "pt31553.runtime-fault.v1")
        .unwrap();
    assert_eq!(diagnostic_field(fault, "fault_id"), "arming-rejected");
    assert!(
        diagnostic_events
            .iter()
            .all(|event| { diagnostic_field(event, "event_id") != "pt31553.state-transition.v1" })
    );
    assert!(ownership.platform().operations()[marker..].iter().all(
        |operation| !matches!(operation, PlatformOperation::Write { path, contents }
                if (path == cpu_enable() || path == gpu_enable()) && contents == "1")
    ));
    ownership.release().unwrap();
}

#[test]
fn envelope_violation_is_rejected_before_custom_or_normal_output() {
    let (mut platform, device) = fixture("2400\n", "2600\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, _, sample) = admit_and_sample(&mut ownership, &device);
    let weaker_policy =
        PROTECTED_POLICY.replacen("minimum_duty_percent = 30", "minimum_duty_percent = 20", 1);
    let candidate = protected_config(&weaker_policy);
    let marker = ownership.platform().operations().len();

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::Policy(_))
    ));
    assert!(ownership.platform().operations()[marker..].iter().all(
        |operation| !matches!(operation, PlatformOperation::Write { path, .. }
                if path == cpu_pwm() || path == gpu_pwm())
    ));
    assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("2"));
    assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("2"));
    ownership.release().unwrap();
}

#[test]
fn zero_tachometer_times_out_then_restores_both() {
    let (mut platform, device) = fixture("0\n", "2600\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::TachometerTimeout {
            cpu_rpm: None,
            gpu_rpm: Some(2600),
        })
    ));
    assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("2"));
    assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("2"));
    ownership.release().unwrap();
}

#[test]
fn one_fan_response_cannot_be_cached_while_the_other_starts() {
    let (platform, device) = fixture("2400\n", "0\n");
    let mut platform = PathAwarePlatform::new(platform, InjectedFault::CpuStopsBeforeGpuResponds);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::TachometerTimeout {
            cpu_rpm: None,
            gpu_rpm: Some(2600),
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
    ownership.release().unwrap();
}

#[test]
fn sample_expiring_before_handover_never_enters_custom() {
    let (mut platform, device) = fixture("2400\n", "2600\n");
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);
    ownership.delay(Duration::from_millis(2_001));
    let marker = ownership.platform().operations().len();

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error,
        FanArmingError::Rejected(FanArmingFailure::StaleSample)
    ));
    assert!(
        ownership.platform().operations()[marker..]
            .iter()
            .all(|operation| {
                !matches!(operation, PlatformOperation::Write { path, contents }
            if (path == cpu_enable() || path == gpu_enable()) && contents == "1")
            })
    );
    assert_eq!(ownership.platform().file_contents(cpu_enable()), Some("2"));
    assert_eq!(ownership.platform().file_contents(gpu_enable()), Some("2"));
    ownership.release().unwrap();
}

fn admit_and_sample<P>(
    ownership: &mut ControllerOwnership<'_, P>,
    device: &fan_control_core::AcerHwmonDevice,
) -> (AdmittedPolicyAuthority, ValidatedConfig, ArmingReadySample)
where
    P: BoundedFileAccess + Clock + RootOwnedQualificationRecordAccess + RuntimeLockAccess,
{
    ownership.restore_firmware_auto(device).unwrap();
    let authority = admit_policy_authority(
        ownership,
        device,
        PROTECTED_POLICY,
        Path::new(QUALIFICATION_RECORD_PATH),
        &[matching_observation_for_policy(PROTECTED_POLICY)],
    )
    .unwrap();
    let candidate = protected_config(PROTECTED_POLICY);
    let mut gate = FreshSampleGate::new();
    let mut sources = HealthySources;
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
    (authority, candidate, sample)
}

#[test]
fn arming_rejects_root_and_endpoint_rebinds_at_each_handover_phase() {
    for (fault, expected_fan, expected_operation) in [
        (
            InjectedFault::RebindRootBeforeMaximum,
            Fan::Cpu,
            FanArmingOperation::StageMaximum,
        ),
        (
            InjectedFault::RebindGpuPwmBeforeMaximum,
            Fan::Gpu,
            FanArmingOperation::StageMaximum,
        ),
        (
            InjectedFault::RebindCpuEnableBeforeCustom,
            Fan::Cpu,
            FanArmingOperation::EnterCustom,
        ),
        (
            InjectedFault::RebindGpuEnableBeforeCustom,
            Fan::Gpu,
            FanArmingOperation::EnterCustom,
        ),
        (
            InjectedFault::RebindCpuTachBeforeRead,
            Fan::Cpu,
            FanArmingOperation::ReadTachometer,
        ),
        (
            InjectedFault::RebindGpuTachBeforeRead,
            Fan::Gpu,
            FanArmingOperation::ReadTachometer,
        ),
    ] {
        let (platform, device) = fixture("2400\n", "2600\n");
        let mut platform = PathAwarePlatform::new(platform, fault);
        let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
        let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);
        let marker = ownership.platform().inner.operations().len();

        let error = arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample)
            .unwrap_err();

        assert!(matches!(
            error.reason(),
            FanArmingFailure::Platform { fan, operation, .. }
                if *fan == expected_fan && *operation == expected_operation
        ));
        assert_auto_restoration_attempted(&ownership.platform().inner, marker);
        assert_eq!(
            ownership.platform().inner.file_contents(cpu_enable()),
            Some("2")
        );
        assert_eq!(
            ownership.platform().inner.file_contents(gpu_enable()),
            Some("2")
        );
        ownership.release().unwrap();
    }
}

#[test]
fn arming_preserves_post_discovery_ambiguity_attribution() {
    let (platform, device) = fixture("2400\n", "2600\n");
    let mut platform = PathAwarePlatform::new(platform, InjectedFault::AddAmbiguousAcerDevice);
    let mut ownership = acquire_controller_ownership(&mut platform).unwrap();
    let (authority, candidate, sample) = admit_and_sample(&mut ownership, &device);

    let error =
        arm_both_fans_safely(&mut ownership, &device, &authority, &candidate, sample).unwrap_err();

    assert!(matches!(
        error.reason(),
        FanArmingFailure::DeviceAbi(AcerHwmonDiscoveryError::AmbiguousDevices { count: 2 })
    ));
    ownership.release().unwrap();
}

fn fixture(cpu_rpm: &str, gpu_rpm: &str) -> (FakePlatform, fan_control_core::AcerHwmonDevice) {
    let root = Path::new(ACER_ROOT);
    let mut platform = FakePlatform::new();
    platform.insert_file_with_permissions(
        QUALIFICATION_RECORD_PATH,
        matching_record(PROTECTED_POLICY),
        FilePermissions::READ_ONLY,
    );
    platform.insert_file_with_permissions(
        SUPERVISED_ENDURANCE_EVIDENCE_PATH,
        matching_endurance_evidence(PROTECTED_POLICY),
        FilePermissions::READ_ONLY,
    );
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
            if channel == 1 { cpu_rpm } else { gpu_rpm },
            FilePermissions::READ_ONLY,
        );
    }
    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    (platform, device)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedFault {
    ChangeGpuModeBeforeAdmission,
    ChangeGpuModeBeforeSecondSample,
    RejectInitialCpuAutoRead,
    RejectGpuMaximumWrite,
    CorruptCpuMaximumReadback,
    RejectGpuCustom,
    RejectGpuCustomAndRestoration,
    RejectGpuCustomWithTransientAutoReadFailures,
    ChangeCpuModeAfterTach,
    ChangeCpuPwmAfterTach,
    ChangeGpuPwmAfterTach,
    ChangeCpuPwmDuringFinalGpuSnapshot,
    ChangeGpuPwmDuringClosingCpuRead,
    CpuStopsBeforeGpuResponds,
    RejectCpuTachRead,
    RejectGpuTachRead,
    RejectCpuCustomDutyRead,
    ExpireCustomConfirmation,
    RebindRootBeforeMaximum,
    RebindGpuPwmBeforeMaximum,
    RebindCpuEnableBeforeCustom,
    RebindGpuEnableBeforeCustom,
    RebindCpuTachBeforeRead,
    RebindGpuTachBeforeRead,
    AddAmbiguousAcerDevice,
}

#[derive(Debug)]
struct PathAwarePlatform {
    inner: FakePlatform,
    fault: InjectedFault,
    cpu_custom_written: bool,
    gpu_custom_attempted: bool,
    gpu_custom_written: bool,
    tachometer_seen: bool,
    deadline_expired: bool,
    auto_write_failures_remaining: u8,
    auto_read_failures_remaining: u8,
    fault_consumed: bool,
    sampling_delay_seen: bool,
    cpu_final_duty_seen: bool,
    auto_mode_reads_after_sampling_delay: u8,
    completed_tachometer_snapshots: u8,
}

impl PathAwarePlatform {
    fn new(inner: FakePlatform, fault: InjectedFault) -> Self {
        Self {
            inner,
            fault,
            cpu_custom_written: false,
            gpu_custom_attempted: false,
            gpu_custom_written: false,
            tachometer_seen: false,
            deadline_expired: false,
            auto_write_failures_remaining: 0,
            auto_read_failures_remaining: 0,
            fault_consumed: false,
            sampling_delay_seen: false,
            cpu_final_duty_seen: false,
            auto_mode_reads_after_sampling_delay: 0,
            completed_tachometer_snapshots: 0,
        }
    }

    fn injected_error(message: &str) -> PlatformError {
        PlatformError::new(PlatformErrorKind::Unavailable, message)
    }
}

impl FileAccess for PathAwarePlatform {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        self.inner.read(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.inner.write(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        self.inner.list(directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        self.inner.permissions(path)
    }
}

impl RootOwnedQualificationRecordAccess for PathAwarePlatform {
    fn read_root_owned_qualification_record(
        &mut self,
        path: &Path,
    ) -> Result<String, PlatformError> {
        self.inner.read_root_owned_qualification_record(path)
    }

    fn verify_root_owned_supervised_endurance_evidence(
        &mut self,
        path: &Path,
        expected_sha256: &str,
        expected_envelope: &fan_control_core::QualificationEnvelopeIdentityV1,
    ) -> Result<(), PlatformError> {
        self.inner.verify_root_owned_supervised_endurance_evidence(
            path,
            expected_sha256,
            expected_envelope,
        )
    }
}

impl IdentityBoundFileAccess for PathAwarePlatform {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
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
    ) -> Result<Vec<std::path::PathBuf>, PlatformError> {
        self.inner.list_bound(directory, expected)
    }
}

impl BoundedFileAccess for PathAwarePlatform {
    fn read_before(&mut self, path: &Path, deadline: Duration) -> Result<String, PlatformError> {
        if self.auto_read_failures_remaining > 0 && (path == cpu_enable() || path == gpu_enable()) {
            self.auto_read_failures_remaining -= 1;
            return Err(Self::injected_error("transient Firmware Auto read failure"));
        }
        if !self.fault_consumed
            && self.sampling_delay_seen
            && self.auto_mode_reads_after_sampling_delay >= 2
            && self.fault == InjectedFault::RejectInitialCpuAutoRead
            && path == cpu_enable()
        {
            self.fault_consumed = true;
            return Err(Self::injected_error("CPU mode read rejected"));
        }
        if !self.fault_consumed
            && self.fault == InjectedFault::CorruptCpuMaximumReadback
            && path == cpu_pwm()
        {
            self.fault_consumed = true;
            return Ok("254\n".to_owned());
        }
        if !self.fault_consumed
            && ((self.fault == InjectedFault::RejectCpuTachRead && path == cpu_tachometer())
                || (self.fault == InjectedFault::RejectGpuTachRead && path == gpu_tachometer()))
        {
            self.fault_consumed = true;
            return Err(Self::injected_error("tachometer read rejected"));
        }
        if !self.fault_consumed
            && self.fault == InjectedFault::RejectCpuCustomDutyRead
            && path == cpu_pwm()
            && self.gpu_custom_written
        {
            self.fault_consumed = true;
            return Err(Self::injected_error("CPU Custom duty read rejected"));
        }
        if self.fault == InjectedFault::ExpireCustomConfirmation
            && !self.deadline_expired
            && path == cpu_enable()
            && self.gpu_custom_written
        {
            self.deadline_expired = true;
            self.inner.advance_monotonic_time_to(deadline);
        }

        if self.fault == InjectedFault::ChangeCpuPwmDuringFinalGpuSnapshot
            && self.cpu_final_duty_seen
            && path == gpu_enable()
        {
            self.cpu_final_duty_seen = false;
            self.inner.insert_file(cpu_pwm(), "200\n");
        }

        let result = self.inner.read_before(path, deadline);
        if self.fault == InjectedFault::ChangeGpuModeBeforeAdmission
            && !self.fault_consumed
            && path == gpu_enable()
            && matches!(result.as_deref(), Ok(value) if value.trim() == "2")
        {
            self.fault_consumed = true;
            self.inner.insert_file(gpu_enable(), "1\n");
        }
        if self.fault == InjectedFault::CpuStopsBeforeGpuResponds
            && !self.fault_consumed
            && path == gpu_tachometer()
            && result.is_ok()
        {
            self.fault_consumed = true;
            self.inner.insert_file(cpu_tachometer(), "0\n");
            self.inner.insert_file(gpu_tachometer(), "2600\n");
        }
        if !self.tachometer_seen
            && (path == cpu_tachometer() || path == gpu_tachometer())
            && result.is_ok()
        {
            self.tachometer_seen = true;
            match self.fault {
                InjectedFault::ChangeCpuModeAfterTach => {
                    self.inner.insert_file(cpu_enable(), "2\n");
                }
                InjectedFault::ChangeCpuPwmAfterTach => {
                    self.inner.insert_file(cpu_pwm(), "200\n");
                }
                InjectedFault::ChangeGpuPwmAfterTach => {
                    self.inner.insert_file(gpu_pwm(), "200\n");
                }
                _ => {}
            }
        }
        if self.fault == InjectedFault::ChangeCpuPwmDuringFinalGpuSnapshot
            && self.tachometer_seen
            && path == cpu_pwm()
            && result.is_ok()
        {
            self.cpu_final_duty_seen = true;
        }
        if path == gpu_tachometer() && result.is_ok() {
            self.completed_tachometer_snapshots += 1;
        }
        if self.fault == InjectedFault::ChangeGpuPwmDuringClosingCpuRead
            && !self.fault_consumed
            && self.completed_tachometer_snapshots >= 2
            && path == cpu_pwm()
            && result.is_ok()
        {
            self.fault_consumed = true;
            self.inner.insert_file(gpu_pwm(), "200\n");
        }
        if self.sampling_delay_seen
            && (path == cpu_enable() || path == gpu_enable())
            && matches!(result.as_deref(), Ok(value) if value.trim() == "2")
        {
            self.auto_mode_reads_after_sampling_delay += 1;
        }
        result
    }

    fn list_before(
        &mut self,
        directory: &Path,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        if !self.fault_consumed
            && self.sampling_delay_seen
            && self.fault == InjectedFault::AddAmbiguousAcerDevice
            && directory == Path::new(HWMON_ROOT)
        {
            self.fault_consumed = true;
            let root = Path::new(HWMON_ROOT).join("hwmon8");
            self.inner.insert_file_with_permissions(
                root.join("name"),
                "acer\n",
                FilePermissions::READ_ONLY,
            );
            for channel in 1..=2 {
                self.inner.insert_file_with_permissions(
                    root.join(format!("pwm{channel}")),
                    "128\n",
                    FilePermissions::READ_WRITE,
                );
                self.inner.insert_file_with_permissions(
                    root.join(format!("pwm{channel}_enable")),
                    "2\n",
                    FilePermissions::READ_WRITE,
                );
                self.inner.insert_file_with_permissions(
                    root.join(format!("fan{channel}_input")),
                    "2500\n",
                    FilePermissions::READ_ONLY,
                );
            }
        }
        self.inner.list_before(directory, deadline)
    }

    fn write_before(
        &mut self,
        path: &Path,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        if !self.fault_consumed
            && self.fault == InjectedFault::RejectGpuMaximumWrite
            && path == gpu_pwm()
            && contents == "255"
        {
            self.fault_consumed = true;
            return Err(Self::injected_error("GPU maximum write rejected"));
        }
        if contents == "2" && self.auto_write_failures_remaining > 0 {
            self.auto_write_failures_remaining -= 1;
            return Err(Self::injected_error("Firmware Auto write rejected"));
        }
        if path == cpu_enable() && contents == "1" {
            let result = self.inner.write_before(path, contents, deadline);
            if result.is_ok() {
                self.cpu_custom_written = true;
            }
            return result;
        }
        if path == gpu_enable() && contents == "1" {
            self.gpu_custom_attempted = true;
            if matches!(
                self.fault,
                InjectedFault::RejectGpuCustom
                    | InjectedFault::RejectGpuCustomAndRestoration
                    | InjectedFault::RejectGpuCustomWithTransientAutoReadFailures
            ) {
                if self.fault == InjectedFault::RejectGpuCustomAndRestoration {
                    self.auto_write_failures_remaining = 6;
                }
                if self.fault == InjectedFault::RejectGpuCustomWithTransientAutoReadFailures {
                    self.auto_read_failures_remaining = 6;
                }
                return Err(Self::injected_error("GPU Custom write rejected"));
            }
            let result = self.inner.write_before(path, contents, deadline);
            if result.is_ok() {
                self.gpu_custom_written = true;
            }
            return result;
        }
        self.inner.write_before(path, contents, deadline)
    }
}

impl BoundedIdentityBoundFileAccess for PathAwarePlatform {
    fn identity_before(
        &mut self,
        path: &Path,
        deadline: Duration,
    ) -> Result<FileIdentity, PlatformError> {
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
        let path = directory.join(child);
        if !self.fault_consumed
            && ((self.fault == InjectedFault::RebindCpuTachBeforeRead && child == "fan1_input")
                || (self.fault == InjectedFault::RebindGpuTachBeforeRead && child == "fan2_input"))
        {
            self.fault_consumed = true;
            self.inner.rebind_path_identity(&path);
        }
        self.require_identity(directory, expected_directory, deadline)?;
        self.require_identity(&path, expected_child, deadline)?;
        let result = self.read_before(&path, deadline)?;
        self.require_identity(directory, expected_directory, deadline)?;
        self.require_identity(&path, expected_child, deadline)?;
        Ok(result)
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
        if !self.fault_consumed {
            let rebind = match self.fault {
                InjectedFault::RebindRootBeforeMaximum
                    if target_child == "pwm1" && contents == "255" =>
                {
                    Some(directory.to_path_buf())
                }
                InjectedFault::RebindGpuPwmBeforeMaximum
                    if target_child == "pwm2" && contents == "255" =>
                {
                    Some(directory.join(target_child))
                }
                InjectedFault::RebindCpuEnableBeforeCustom
                    if target_child == "pwm1_enable" && contents == "1" =>
                {
                    Some(directory.join(target_child))
                }
                InjectedFault::RebindGpuEnableBeforeCustom
                    if target_child == "pwm2_enable" && contents == "1" =>
                {
                    Some(directory.join(target_child))
                }
                _ => None,
            };
            if let Some(path) = rebind {
                self.fault_consumed = true;
                self.inner.rebind_path_identity(path);
            }
        }
        self.require_identity(directory, expected_directory, deadline)?;
        for (child, expected) in expected_children {
            self.require_identity(&directory.join(child), *expected, deadline)?;
        }
        for (child, expected) in guards {
            let path = directory.join(child);
            let actual = self.read_before(&path, deadline)?;
            if actual.trim() != *expected {
                return Err(Self::injected_error("guarded arming state changed"));
            }
        }
        self.write_before(&directory.join(target_child), contents, deadline)
    }
}

impl PathAwarePlatform {
    fn require_identity(
        &mut self,
        path: &Path,
        expected: FileIdentity,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        if self.inner.identity_before(path, deadline)? == expected {
            Ok(())
        } else {
            Err(Self::injected_error("bound arming identity changed"))
        }
    }
}

fn assert_auto_restoration_attempted(platform: &FakePlatform, marker: usize) {
    let operations = &platform.operations()[marker..];
    for path in [cpu_enable(), gpu_enable()] {
        assert!(
            operations
                .iter()
                .any(|operation| is_write(operation, path, "2"))
        );
        assert!(operations.iter().any(
            |operation| matches!(operation, PlatformOperation::Read(actual) if actual == path)
        ));
    }
}

impl Clock for PathAwarePlatform {
    fn monotonic_now(&mut self) -> Duration {
        self.inner.monotonic_now()
    }

    fn delay(&mut self, duration: Duration) {
        self.sampling_delay_seen = true;
        if self.fault == InjectedFault::ChangeGpuModeBeforeSecondSample {
            self.inner.insert_file(gpu_enable(), "1\n");
        }
        self.inner.delay(duration);
    }
}

impl ServiceAccess for PathAwarePlatform {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        self.inner.is_service_active(service)
    }
}

impl RuntimeLockAccess for PathAwarePlatform {
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

fn is_write(operation: &PlatformOperation, path: &Path, contents: &str) -> bool {
    matches!(operation, PlatformOperation::Write { path: actual, contents: value }
        if actual == path && value == contents)
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

fn cpu_tachometer() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/fan1_input")
}

fn gpu_tachometer() -> &'static Path {
    Path::new("/sys/class/hwmon/hwmon7/fan2_input")
}
