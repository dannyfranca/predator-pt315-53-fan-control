use crate::{
    CompatibilityDeclarationV1, EnvelopeValidationError, KernelIdentity, ModuleIdentity,
    QualificationRecordV2, ValidatedConfig,
    authority::{requalification_policy_snapshot, validate_record_identity},
    compatibility::validate_declaration,
    validate_against_protected_envelope,
};
use sha2::{Digest, Sha256};

/// Evidence that the physical fans and board have not been replaced since qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalHardwareContinuity {
    ConfirmedUnchanged,
    FanOrBoardReplaced,
    Unverified,
}

/// The fixed automated checks permitted for a same-code rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbbreviatedRecheck {
    OfflineIdentityAndAbi,
    FirmwareAutoRestoration,
    ArmingMaximumAndTachometer,
    CombinedAcWorkload,
    ServiceStopRestoration,
    RebootRestoration,
}

pub const ABBREVIATED_RECHECKS: [AbbreviatedRecheck; 6] = [
    AbbreviatedRecheck::OfflineIdentityAndAbi,
    AbbreviatedRecheck::FirmwareAutoRestoration,
    AbbreviatedRecheck::ArmingMaximumAndTachometer,
    AbbreviatedRecheck::CombinedAcWorkload,
    AbbreviatedRecheck::ServiceStopRestoration,
    AbbreviatedRecheck::RebootRestoration,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbbreviatedRecheckOutcome {
    Pending,
    Passed,
    Failed,
    Different,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbbreviatedRecheckResults {
    baseline_qualification: QualificationRecordV2,
    candidate_compatibility: CompatibilityDeclarationV1,
    protected_policy_sha256: String,
    outcomes: [AbbreviatedRecheckOutcome; ABBREVIATED_RECHECKS.len()],
}

impl AbbreviatedRecheckResults {
    pub fn new(
        baseline_qualification: QualificationRecordV2,
        candidate_compatibility: CompatibilityDeclarationV1,
        protected_policy_source: &str,
        outcomes: [AbbreviatedRecheckOutcome; ABBREVIATED_RECHECKS.len()],
    ) -> Self {
        Self {
            baseline_qualification,
            candidate_compatibility,
            protected_policy_sha256: policy_source_sha256(protected_policy_source),
            outcomes,
        }
    }

    pub const fn outcomes(&self) -> &[AbbreviatedRecheckOutcome; ABBREVIATED_RECHECKS.len()] {
        &self.outcomes
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QualificationBaseline<'a> {
    pub qualification: &'a QualificationRecordV2,
    pub protected_policy_source: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct QualificationCandidate<'a> {
    pub compatibility: &'a CompatibilityDeclarationV1,
    pub protected_policy_source: &'a str,
    pub editable_configuration: &'a ValidatedConfig,
    pub physical_hardware: PhysicalHardwareContinuity,
    pub abbreviated_rechecks: Option<&'a AbbreviatedRecheckResults>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullRequalificationReason {
    PhysicalHardwareChanged,
    PhysicalHardwareUnverified,
    InvalidQualifiedCompatibility,
    InvalidCandidateCompatibility,
    HardwareIdentityChanged,
    FanMappingOrControlPathChanged,
    DriverBehaviorChanged,
    TrustBoundaryChanged,
    ProtectedPolicyWeakened,
    ProtectedPolicyChanged,
    InvalidProtectedPolicyIdentity,
    AbbreviatedCheckFailed { check: AbbreviatedRecheck },
    AbbreviatedCheckDifferent { check: AbbreviatedRecheck },
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequalificationDecision {
    ValidateConfigurationAndRearm,
    AbbreviatedRequalificationRequired {
        checks: &'static [AbbreviatedRecheck],
    },
    EligibleAfterAbbreviatedRequalification,
    FullRequalificationRequired {
        reason: FullRequalificationReason,
    },
    ConfigurationRejected {
        error: EnvelopeValidationError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompatibilityDrift {
    Unchanged,
    SameCodeRebuild,
    Full(FullRequalificationReason),
}

/// Selects the only safe path after comparing current state with qualified authority.
///
/// Exact authority reuse is limited to an unchanged qualification envelope plus an editable
/// configuration that remains at least as conservative as the protected policy. Rebuild-only
/// identity drift is eligible for the fixed abbreviated checks. Every unclassified, material, or
/// insufficiently evidenced change fails closed into full requalification.
pub fn decide_requalification(
    baseline: QualificationBaseline<'_>,
    candidate: QualificationCandidate<'_>,
) -> RequalificationDecision {
    let full = |reason| RequalificationDecision::FullRequalificationRequired { reason };

    match candidate.physical_hardware {
        PhysicalHardwareContinuity::ConfirmedUnchanged => {}
        PhysicalHardwareContinuity::FanOrBoardReplaced => {
            return full(FullRequalificationReason::PhysicalHardwareChanged);
        }
        PhysicalHardwareContinuity::Unverified => {
            return full(FullRequalificationReason::PhysicalHardwareUnverified);
        }
    }

    if validate_record_identity(baseline.qualification).is_err() {
        return full(FullRequalificationReason::InvalidQualifiedCompatibility);
    }
    let baseline_compatibility = baseline.qualification.compatibility();
    let compatibility_drift =
        classify_compatibility_drift(baseline_compatibility, candidate.compatibility);
    if let CompatibilityDrift::Full(reason) = compatibility_drift {
        return full(reason);
    }

    let Ok(baseline_policy) = requalification_policy_snapshot(baseline.protected_policy_source)
    else {
        return full(FullRequalificationReason::InvalidProtectedPolicyIdentity);
    };
    let Ok(candidate_policy) = requalification_policy_snapshot(candidate.protected_policy_source)
    else {
        return full(FullRequalificationReason::InvalidProtectedPolicyIdentity);
    };
    if baseline_policy.protected_policy_sha256 != baseline.qualification.protected_policy_sha256()
        || baseline_policy.qualification_id != baseline.qualification.qualification_id()
        || baseline_policy.policy_version != baseline.qualification.policy_version()
        || baseline_policy.compatibility != *baseline.qualification.compatibility()
    {
        return full(FullRequalificationReason::InvalidProtectedPolicyIdentity);
    }

    if baseline_policy.protected != candidate_policy.protected {
        let reason = if validate_against_protected_envelope(
            &candidate_policy.protected,
            &baseline_policy.protected,
        )
        .is_err()
        {
            FullRequalificationReason::ProtectedPolicyWeakened
        } else {
            FullRequalificationReason::ProtectedPolicyChanged
        };
        return full(reason);
    }
    if baseline_policy.protected_policy_sha256 != candidate_policy.protected_policy_sha256 {
        return full(FullRequalificationReason::ProtectedPolicyChanged);
    }

    if let Err(error) = validate_against_protected_envelope(
        candidate.editable_configuration,
        &baseline_policy.protected,
    ) {
        return RequalificationDecision::ConfigurationRejected { error };
    }

    if compatibility_drift == CompatibilityDrift::Unchanged {
        return RequalificationDecision::ValidateConfigurationAndRearm;
    }

    let Some(results) = candidate.abbreviated_rechecks else {
        return RequalificationDecision::AbbreviatedRequalificationRequired {
            checks: &ABBREVIATED_RECHECKS,
        };
    };
    if results.baseline_qualification != *baseline.qualification
        || results.candidate_compatibility != *candidate.compatibility
        || results.protected_policy_sha256 != candidate_policy.protected_policy_sha256
    {
        return RequalificationDecision::AbbreviatedRequalificationRequired {
            checks: &ABBREVIATED_RECHECKS,
        };
    }
    let mut has_pending_rechecks = false;
    for (check, outcome) in ABBREVIATED_RECHECKS
        .iter()
        .copied()
        .zip(results.outcomes.iter().copied())
    {
        match outcome {
            AbbreviatedRecheckOutcome::Pending => {
                has_pending_rechecks = true;
            }
            AbbreviatedRecheckOutcome::Passed => {}
            AbbreviatedRecheckOutcome::Failed => {
                return full(FullRequalificationReason::AbbreviatedCheckFailed { check });
            }
            AbbreviatedRecheckOutcome::Different => {
                return full(FullRequalificationReason::AbbreviatedCheckDifferent { check });
            }
        }
    }

    if has_pending_rechecks {
        return RequalificationDecision::AbbreviatedRequalificationRequired {
            checks: &ABBREVIATED_RECHECKS,
        };
    }

    RequalificationDecision::EligibleAfterAbbreviatedRequalification
}

fn policy_source_sha256(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
}

/// Exhaustively partitions compatibility fields into material drift and the only fields a
/// same-code rebuild is permitted to change. Adding a declaration field therefore requires an
/// explicit classification here instead of silently broadening abbreviated eligibility.
fn classify_compatibility_drift(
    baseline: &CompatibilityDeclarationV1,
    candidate: &CompatibilityDeclarationV1,
) -> CompatibilityDrift {
    let CompatibilityDeclarationV1 {
        schema_version: baseline_schema,
        hardware: baseline_hardware,
        kernel: baseline_kernel,
        module: baseline_module,
        secure_boot: baseline_secure_boot,
        fan_control: baseline_fan_control,
    } = baseline;
    let CompatibilityDeclarationV1 {
        schema_version: candidate_schema,
        hardware: candidate_hardware,
        kernel: candidate_kernel,
        module: candidate_module,
        secure_boot: candidate_secure_boot,
        fan_control: candidate_fan_control,
    } = candidate;

    if baseline_hardware != candidate_hardware {
        return CompatibilityDrift::Full(FullRequalificationReason::HardwareIdentityChanged);
    }
    if baseline_fan_control != candidate_fan_control {
        return CompatibilityDrift::Full(FullRequalificationReason::FanMappingOrControlPathChanged);
    }

    let KernelIdentity {
        release: baseline_release,
        package: baseline_package,
        source_commit: baseline_source_commit,
        image_sha256: baseline_image_sha256,
        image_signer_fingerprint: baseline_image_signer,
    } = baseline_kernel;
    let KernelIdentity {
        release: candidate_release,
        package: candidate_package,
        source_commit: candidate_source_commit,
        image_sha256: candidate_image_sha256,
        image_signer_fingerprint: candidate_image_signer,
    } = candidate_kernel;
    let ModuleIdentity {
        name: baseline_module_name,
        path: baseline_module_path,
        sha256: baseline_module_sha256,
        signer_fingerprint: baseline_module_signer,
        vermagic: baseline_vermagic,
        provenance: baseline_provenance,
    } = baseline_module;
    let ModuleIdentity {
        name: candidate_module_name,
        path: candidate_module_path,
        sha256: candidate_module_sha256,
        signer_fingerprint: candidate_module_signer,
        vermagic: candidate_vermagic,
        provenance: candidate_provenance,
    } = candidate_module;

    if baseline_package != candidate_package
        || baseline_source_commit != candidate_source_commit
        || baseline_module_name != candidate_module_name
        || baseline_provenance != candidate_provenance
    {
        return CompatibilityDrift::Full(FullRequalificationReason::DriverBehaviorChanged);
    }
    if baseline_schema != candidate_schema
        || baseline_secure_boot != candidate_secure_boot
        || baseline_image_signer != candidate_image_signer
        || baseline_module_signer != candidate_module_signer
    {
        return CompatibilityDrift::Full(FullRequalificationReason::TrustBoundaryChanged);
    }
    if validate_declaration(candidate).is_err() {
        return CompatibilityDrift::Full(FullRequalificationReason::InvalidCandidateCompatibility);
    }

    if baseline_release != candidate_release
        || baseline_image_sha256 != candidate_image_sha256
        || baseline_module_path != candidate_module_path
        || baseline_module_sha256 != candidate_module_sha256
        || baseline_vermagic != candidate_vermagic
    {
        CompatibilityDrift::SameCodeRebuild
    } else {
        CompatibilityDrift::Unchanged
    }
}
