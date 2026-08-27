use fan_control_core::{
    ABBREVIATED_RECHECKS, AbbreviatedRecheck, AbbreviatedRecheckOutcome, AbbreviatedRecheckResults,
    CompatibilityDeclarationV1, FullRequalificationReason, PhysicalHardwareContinuity,
    QualificationBaseline, QualificationCandidate, QualificationRecordV2, RequalificationDecision,
    decide_requalification, parse_config_v1, validate_config_v1,
};

mod support;
use support::{HASH_B, PROTECTED_POLICY, compatibility_declaration, matching_record};

fn decision(
    candidate_compatibility: &CompatibilityDeclarationV1,
    candidate_policy: &str,
    candidate_config: &str,
    physical_hardware: PhysicalHardwareContinuity,
    abbreviated_rechecks: Option<&AbbreviatedRecheckResults>,
) -> RequalificationDecision {
    decision_with_policy_identity(
        candidate_compatibility,
        candidate_policy,
        candidate_config,
        physical_hardware,
        abbreviated_rechecks,
    )
}

fn decision_with_policy_identity(
    candidate_compatibility: &CompatibilityDeclarationV1,
    candidate_policy_source: &str,
    candidate_config: &str,
    physical_hardware: PhysicalHardwareContinuity,
    abbreviated_rechecks: Option<&AbbreviatedRecheckResults>,
) -> RequalificationDecision {
    decision_with_policy_sources(
        candidate_compatibility,
        PROTECTED_POLICY,
        candidate_policy_source,
        candidate_config,
        physical_hardware,
        abbreviated_rechecks,
    )
}

fn decision_with_policy_sources(
    candidate_compatibility: &CompatibilityDeclarationV1,
    baseline_policy_source: &str,
    candidate_policy_source: &str,
    candidate_config: &str,
    physical_hardware: PhysicalHardwareContinuity,
    abbreviated_rechecks: Option<&AbbreviatedRecheckResults>,
) -> RequalificationDecision {
    let qualification: QualificationRecordV2 =
        serde_json::from_str(&matching_record(PROTECTED_POLICY)).unwrap();
    let candidate_configuration =
        validate_config_v1(parse_config_v1(candidate_config).unwrap()).unwrap();

    decide_requalification(
        QualificationBaseline {
            qualification: &qualification,
            protected_policy_source: baseline_policy_source,
        },
        QualificationCandidate {
            compatibility: candidate_compatibility,
            protected_policy_source: candidate_policy_source,
            editable_configuration: &candidate_configuration,
            physical_hardware,
            abbreviated_rechecks,
        },
    )
}

fn protected_configuration() -> String {
    PROTECTED_POLICY
        .split_once("[protected]\n")
        .unwrap()
        .1
        .replace("[protected.", "[")
}

fn same_code_rebuild() -> String {
    PROTECTED_POLICY
        .replace("7.1.8-1-cachyos-pt31553", "7.1.8-2-cachyos-pt31553")
        .replacen(
            "image_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "image_sha256 = \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"",
            1,
        )
        .replacen(
            "sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "sha256 = \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"",
            1,
        )
}

fn baseline_compatibility() -> CompatibilityDeclarationV1 {
    compatibility_declaration(PROTECTED_POLICY)
}

fn same_code_rebuild_compatibility() -> CompatibilityDeclarationV1 {
    compatibility_declaration(&same_code_rebuild())
}

fn abbreviated_results(
    candidate: &CompatibilityDeclarationV1,
    outcomes: [AbbreviatedRecheckOutcome; ABBREVIATED_RECHECKS.len()],
) -> AbbreviatedRecheckResults {
    AbbreviatedRecheckResults::new(
        serde_json::from_str(&matching_record(PROTECTED_POLICY)).unwrap(),
        candidate.clone(),
        PROTECTED_POLICY,
        outcomes,
    )
}

#[test]
fn unchanged_envelope_accepts_conservative_configuration_for_validation_and_rearming() {
    let configuration = protected_configuration().replacen(
        "minimum_duty_percent = 30",
        "minimum_duty_percent = 40",
        1,
    );

    assert_eq!(
        decision(
            &baseline_compatibility(),
            PROTECTED_POLICY,
            &configuration,
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            None,
        ),
        RequalificationDecision::ValidateConfigurationAndRearm
    );
}

#[test]
fn protected_policy_metadata_or_calibration_drift_requires_full_requalification() {
    let changed_policy = PROTECTED_POLICY.replacen(
        "policy_version = \"1.0.0\"",
        "policy_version = \"1.0.1\"",
        1,
    );
    assert_eq!(
        decision_with_policy_identity(
            &baseline_compatibility(),
            &changed_policy,
            &protected_configuration(),
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            None,
        ),
        RequalificationDecision::FullRequalificationRequired {
            reason: FullRequalificationReason::ProtectedPolicyChanged,
        }
    );
}

#[test]
fn caller_cannot_replace_both_policy_sources_after_qualification() {
    let changed_policy = PROTECTED_POLICY.replacen("median_rpm = 2500", "median_rpm = 2501", 1);

    assert_eq!(
        decision_with_policy_sources(
            &baseline_compatibility(),
            &changed_policy,
            &changed_policy,
            &protected_configuration(),
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            None,
        ),
        RequalificationDecision::FullRequalificationRequired {
            reason: FullRequalificationReason::InvalidProtectedPolicyIdentity,
        }
    );
}

#[test]
fn record_hash_cannot_bind_a_manifest_with_a_different_compatibility_identity() {
    let changed_policy = same_code_rebuild();
    let mut record: serde_json::Value =
        serde_json::from_str(&matching_record(&changed_policy)).unwrap();
    record["compatibility"] = serde_json::to_value(baseline_compatibility()).unwrap();
    let qualification: QualificationRecordV2 = serde_json::from_value(record).unwrap();
    let candidate_configuration =
        validate_config_v1(parse_config_v1(&protected_configuration()).unwrap()).unwrap();

    assert_eq!(
        decide_requalification(
            QualificationBaseline {
                qualification: &qualification,
                protected_policy_source: &changed_policy,
            },
            QualificationCandidate {
                compatibility: &baseline_compatibility(),
                protected_policy_source: &changed_policy,
                editable_configuration: &candidate_configuration,
                physical_hardware: PhysicalHardwareContinuity::ConfirmedUnchanged,
                abbreviated_rechecks: None,
            },
        ),
        RequalificationDecision::FullRequalificationRequired {
            reason: FullRequalificationReason::InvalidProtectedPolicyIdentity,
        }
    );
}

#[test]
fn quieter_editable_configuration_is_rejected_without_claiming_hardware_drift() {
    let configuration = protected_configuration().replacen(
        "minimum_duty_percent = 30",
        "minimum_duty_percent = 29",
        1,
    );

    assert!(matches!(
        decision(
            &baseline_compatibility(),
            PROTECTED_POLICY,
            &configuration,
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            None,
        ),
        RequalificationDecision::ConfigurationRejected { .. }
    ));
}

#[test]
fn physical_hardware_bios_mapping_driver_and_policy_drift_require_full_requalification() {
    let configuration = protected_configuration();
    let mut cases = Vec::new();
    cases.push((
        baseline_compatibility(),
        PROTECTED_POLICY.to_owned(),
        PhysicalHardwareContinuity::FanOrBoardReplaced,
        FullRequalificationReason::PhysicalHardwareChanged,
    ));

    let mut bios_changed = baseline_compatibility();
    bios_changed.hardware.bios_version = "V1.18".to_owned();
    cases.push((
        bios_changed,
        PROTECTED_POLICY.to_owned(),
        PhysicalHardwareContinuity::ConfirmedUnchanged,
        FullRequalificationReason::HardwareIdentityChanged,
    ));

    let mut mapping_changed = baseline_compatibility();
    mapping_changed.fan_control.endpoints[0] = "pwm3".to_owned();
    cases.push((
        mapping_changed,
        PROTECTED_POLICY.to_owned(),
        PhysicalHardwareContinuity::ConfirmedUnchanged,
        FullRequalificationReason::FanMappingOrControlPathChanged,
    ));

    let mut driver_changed = baseline_compatibility();
    driver_changed.kernel.source_commit = "fedcba9876543210fedcba9876543210fedcba98".to_owned();
    cases.push((
        driver_changed,
        PROTECTED_POLICY.to_owned(),
        PhysicalHardwareContinuity::ConfirmedUnchanged,
        FullRequalificationReason::DriverBehaviorChanged,
    ));

    cases.push((
        baseline_compatibility(),
        PROTECTED_POLICY.replacen("minimum_duty_percent = 30", "minimum_duty_percent = 29", 1),
        PhysicalHardwareContinuity::ConfirmedUnchanged,
        FullRequalificationReason::ProtectedPolicyWeakened,
    ));

    for (compatibility, policy, continuity, expected) in cases {
        assert_eq!(
            decision(&compatibility, &policy, &configuration, continuity, None),
            RequalificationDecision::FullRequalificationRequired { reason: expected }
        );
    }
}

#[test]
fn unverified_physical_hardware_fails_closed() {
    assert_eq!(
        decision(
            &baseline_compatibility(),
            PROTECTED_POLICY,
            &protected_configuration(),
            PhysicalHardwareContinuity::Unverified,
            None,
        ),
        RequalificationDecision::FullRequalificationRequired {
            reason: FullRequalificationReason::PhysicalHardwareUnverified,
        }
    );
}

#[test]
fn same_code_rebuild_selects_the_complete_abbreviated_path() {
    assert_eq!(
        decision(
            &same_code_rebuild_compatibility(),
            PROTECTED_POLICY,
            &protected_configuration(),
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            None,
        ),
        RequalificationDecision::AbbreviatedRequalificationRequired {
            checks: &ABBREVIATED_RECHECKS,
        }
    );
    assert_eq!(
        ABBREVIATED_RECHECKS,
        [
            AbbreviatedRecheck::OfflineIdentityAndAbi,
            AbbreviatedRecheck::FirmwareAutoRestoration,
            AbbreviatedRecheck::ArmingMaximumAndTachometer,
            AbbreviatedRecheck::CombinedAcWorkload,
            AbbreviatedRecheck::ServiceStopRestoration,
            AbbreviatedRecheck::RebootRestoration,
        ]
    );
}

#[test]
fn any_abbreviated_failure_or_difference_expands_to_full_requalification() {
    for (index, outcome, expected) in [
        (
            2,
            AbbreviatedRecheckOutcome::Failed,
            FullRequalificationReason::AbbreviatedCheckFailed {
                check: AbbreviatedRecheck::ArmingMaximumAndTachometer,
            },
        ),
        (
            3,
            AbbreviatedRecheckOutcome::Different,
            FullRequalificationReason::AbbreviatedCheckDifferent {
                check: AbbreviatedRecheck::CombinedAcWorkload,
            },
        ),
    ] {
        let mut outcomes = [AbbreviatedRecheckOutcome::Passed; ABBREVIATED_RECHECKS.len()];
        outcomes[index] = outcome;
        let results = abbreviated_results(&same_code_rebuild_compatibility(), outcomes);

        assert_eq!(
            decision(
                &same_code_rebuild_compatibility(),
                PROTECTED_POLICY,
                &protected_configuration(),
                PhysicalHardwareContinuity::ConfirmedUnchanged,
                Some(&results),
            ),
            RequalificationDecision::FullRequalificationRequired { reason: expected }
        );
    }
}

#[test]
fn known_abbreviated_failure_takes_precedence_over_pending_checks() {
    let results = abbreviated_results(
        &same_code_rebuild_compatibility(),
        [
            AbbreviatedRecheckOutcome::Pending,
            AbbreviatedRecheckOutcome::Passed,
            AbbreviatedRecheckOutcome::Passed,
            AbbreviatedRecheckOutcome::Failed,
            AbbreviatedRecheckOutcome::Passed,
            AbbreviatedRecheckOutcome::Pending,
        ],
    );

    assert_eq!(
        decision(
            &same_code_rebuild_compatibility(),
            PROTECTED_POLICY,
            &protected_configuration(),
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            Some(&results),
        ),
        RequalificationDecision::FullRequalificationRequired {
            reason: FullRequalificationReason::AbbreviatedCheckFailed {
                check: AbbreviatedRecheck::CombinedAcWorkload,
            },
        }
    );
}

#[test]
fn same_code_rebuild_is_eligible_only_after_every_abbreviated_check_passes() {
    let pending = abbreviated_results(
        &same_code_rebuild_compatibility(),
        [
            AbbreviatedRecheckOutcome::Passed,
            AbbreviatedRecheckOutcome::Passed,
            AbbreviatedRecheckOutcome::Passed,
            AbbreviatedRecheckOutcome::Passed,
            AbbreviatedRecheckOutcome::Passed,
            AbbreviatedRecheckOutcome::Pending,
        ],
    );
    assert!(matches!(
        decision(
            &same_code_rebuild_compatibility(),
            PROTECTED_POLICY,
            &protected_configuration(),
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            Some(&pending),
        ),
        RequalificationDecision::AbbreviatedRequalificationRequired { .. }
    ));

    let passed = abbreviated_results(
        &same_code_rebuild_compatibility(),
        [AbbreviatedRecheckOutcome::Passed; ABBREVIATED_RECHECKS.len()],
    );
    assert_eq!(
        decision(
            &same_code_rebuild_compatibility(),
            PROTECTED_POLICY,
            &protected_configuration(),
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            Some(&passed),
        ),
        RequalificationDecision::EligibleAfterAbbreviatedRequalification
    );
}

#[test]
fn abbreviated_results_cannot_be_reused_for_another_rebuild() {
    let first_rebuild = same_code_rebuild_compatibility();
    let passed = abbreviated_results(
        &first_rebuild,
        [AbbreviatedRecheckOutcome::Passed; ABBREVIATED_RECHECKS.len()],
    );
    let mut second_rebuild = first_rebuild;
    second_rebuild.kernel.image_sha256 = HASH_B.to_owned();

    assert_eq!(
        decision(
            &second_rebuild,
            PROTECTED_POLICY,
            &protected_configuration(),
            PhysicalHardwareContinuity::ConfirmedUnchanged,
            Some(&passed),
        ),
        RequalificationDecision::AbbreviatedRequalificationRequired {
            checks: &ABBREVIATED_RECHECKS,
        }
    );
}
