use std::{collections::BTreeSet, error::Error, fmt};

use serde::{Deserialize, Deserializer, de};

const EXPECTED_PRODUCT: &str = "Predator PT315-53";
const EXPECTED_BOARD: &str = "Civic_TLS";
const EXPECTED_BIOS: &str = "V1.17";
const EXPECTED_KERNEL_PACKAGE: &str = "linux-cachyos-pt31553";
const EXPECTED_MODULE_NAME: &str = "acer_wmi";
const EXPECTED_HWMON_NAME: &str = "acer";
const EXPECTED_ENDPOINTS: [&str; 6] = [
    "pwm1",
    "pwm1_enable",
    "fan1_input",
    "pwm2",
    "pwm2_enable",
    "fan2_input",
];
const FORBIDDEN_CAPABILITIES: [EscapeHatchCapability; 7] = [
    EscapeHatchCapability::ForceCaps,
    EscapeHatchCapability::EcRawMode,
    EscapeHatchCapability::PredatorV4Override,
    EscapeHatchCapability::DirectWmi,
    EscapeHatchCapability::RawEc,
    EscapeHatchCapability::ReplacementWmiModule,
    EscapeHatchCapability::AlternateFanWriteBackend,
];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityDeclarationV1 {
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema_version: u32,
    pub hardware: HardwareIdentity,
    pub kernel: KernelIdentity,
    pub module: ModuleIdentity,
    pub secure_boot: SecureBootRequirements,
    pub fan_control: FanControlDeclaration,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareIdentity {
    pub dmi_product_name: String,
    pub dmi_board_name: String,
    pub bios_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelIdentity {
    pub release: String,
    pub package: String,
    pub source_commit: String,
    pub image_sha256: String,
    pub image_signer_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentity {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub signer_fingerprint: String,
    pub vermagic: String,
    pub provenance: ModuleProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleProvenance {
    InTree,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureBootRequirements {
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FanControlDeclaration {
    pub backend: FanWriteBackend,
    pub hwmon_name: String,
    pub endpoints: Vec<String>,
    pub forbidden_capabilities: Vec<EscapeHatchCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanWriteBackend {
    AcerHwmon,
    DirectWmi,
    RawEc,
    ReplacementModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscapeHatchCapability {
    ForceCaps,
    EcRawMode,
    PredatorV4Override,
    DirectWmi,
    RawEc,
    ReplacementWmiModule,
    AlternateFanWriteBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceCompleteness {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFanAbi {
    pub hwmon_name: String,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityObservation {
    pub hardware: HardwareIdentity,
    pub kernel: KernelIdentity,
    pub module: ModuleIdentity,
    pub secure_boot_enabled: bool,
    pub kernel_image_trusted: bool,
    pub module_signature_trusted: bool,
    pub fan_abi: ObservedFanAbi,
    pub backend_evidence_completeness: EvidenceCompleteness,
    pub backends: Vec<FanWriteBackend>,
    pub capability_evidence_completeness: EvidenceCompleteness,
    pub enabled_capabilities: Vec<EscapeHatchCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedCompatibility(());

#[derive(Debug)]
pub enum CompatibilityDeclarationError {
    Parse(toml::de::Error),
    Unsafe {
        field: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for CompatibilityDeclarationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => error.fmt(formatter),
            Self::Unsafe { field, reason } => {
                write!(
                    formatter,
                    "unsafe compatibility declaration at {field}: {reason}"
                )
            }
        }
    }
}

impl Error for CompatibilityDeclarationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Unsafe { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityAdmissionError {
    UnsafeDeclaration { field: &'static str },
    MissingObservation,
    AmbiguousObservations { count: usize },
    Mismatch { field: &'static str },
    IncompleteEvidence { field: &'static str },
    Untrusted { field: &'static str },
    ForbiddenCapability { capability: EscapeHatchCapability },
    MissingBackend,
    AmbiguousBackends { count: usize },
    UnsupportedBackend { backend: FanWriteBackend },
}

impl fmt::Display for CompatibilityAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeDeclaration { field } => {
                write!(formatter, "unsafe compatibility declaration at {field}")
            }
            Self::MissingObservation => formatter.write_str("compatibility observation is missing"),
            Self::AmbiguousObservations { count } => {
                write!(
                    formatter,
                    "compatibility observation is ambiguous: found {count}"
                )
            }
            Self::Mismatch { field } => write!(formatter, "compatibility mismatch at {field}"),
            Self::IncompleteEvidence { field } => {
                write!(formatter, "compatibility evidence is incomplete at {field}")
            }
            Self::Untrusted { field } => write!(formatter, "compatibility trust failed at {field}"),
            Self::ForbiddenCapability { capability } => {
                write!(formatter, "forbidden capability is enabled: {capability:?}")
            }
            Self::MissingBackend => formatter.write_str("fan-write backend evidence is missing"),
            Self::AmbiguousBackends { count } => {
                write!(
                    formatter,
                    "fan-write backend evidence is ambiguous: found {count}"
                )
            }
            Self::UnsupportedBackend { backend } => {
                write!(formatter, "unsupported fan-write backend: {backend:?}")
            }
        }
    }
}

impl Error for CompatibilityAdmissionError {}

pub fn parse_compatibility_v1(
    source: &str,
) -> Result<CompatibilityDeclarationV1, CompatibilityDeclarationError> {
    let declaration = toml::from_str(source).map_err(CompatibilityDeclarationError::Parse)?;
    validate_declaration(&declaration)?;
    Ok(declaration)
}

pub fn admit_compatibility(
    declaration: &CompatibilityDeclarationV1,
    observations: &[CompatibilityObservation],
) -> Result<AdmittedCompatibility, CompatibilityAdmissionError> {
    if let Err(CompatibilityDeclarationError::Unsafe { field, .. }) =
        validate_declaration(declaration)
    {
        return Err(CompatibilityAdmissionError::UnsafeDeclaration { field });
    }

    let observation = match observations {
        [] => return Err(CompatibilityAdmissionError::MissingObservation),
        [observation] => observation,
        observations => {
            return Err(CompatibilityAdmissionError::AmbiguousObservations {
                count: observations.len(),
            });
        }
    };

    require_equal(
        "hardware.dmi_product_name",
        &declaration.hardware.dmi_product_name,
        &observation.hardware.dmi_product_name,
    )?;
    require_equal(
        "hardware.dmi_board_name",
        &declaration.hardware.dmi_board_name,
        &observation.hardware.dmi_board_name,
    )?;
    require_equal(
        "hardware.bios_version",
        &declaration.hardware.bios_version,
        &observation.hardware.bios_version,
    )?;
    require_equal(
        "kernel.release",
        &declaration.kernel.release,
        &observation.kernel.release,
    )?;
    require_equal(
        "kernel.package",
        &declaration.kernel.package,
        &observation.kernel.package,
    )?;
    require_equal(
        "kernel.source_commit",
        &declaration.kernel.source_commit,
        &observation.kernel.source_commit,
    )?;
    require_equal(
        "kernel.image_sha256",
        &declaration.kernel.image_sha256,
        &observation.kernel.image_sha256,
    )?;
    require_equal(
        "kernel.image_signer_fingerprint",
        &declaration.kernel.image_signer_fingerprint,
        &observation.kernel.image_signer_fingerprint,
    )?;
    require_equal(
        "module.name",
        &declaration.module.name,
        &observation.module.name,
    )?;
    require_equal(
        "module.path",
        &declaration.module.path,
        &observation.module.path,
    )?;
    require_equal(
        "module.sha256",
        &declaration.module.sha256,
        &observation.module.sha256,
    )?;
    require_equal(
        "module.signer_fingerprint",
        &declaration.module.signer_fingerprint,
        &observation.module.signer_fingerprint,
    )?;
    require_equal(
        "module.vermagic",
        &declaration.module.vermagic,
        &observation.module.vermagic,
    )?;
    require_equal(
        "module.provenance",
        &declaration.module.provenance,
        &observation.module.provenance,
    )?;

    if !observation.secure_boot_enabled {
        return Err(CompatibilityAdmissionError::Untrusted {
            field: "secure_boot.enabled",
        });
    }
    if !observation.kernel_image_trusted {
        return Err(CompatibilityAdmissionError::Untrusted {
            field: "secure_boot.kernel_image_trusted",
        });
    }
    if !observation.module_signature_trusted {
        return Err(CompatibilityAdmissionError::Untrusted {
            field: "secure_boot.module_signature_trusted",
        });
    }

    if observation.capability_evidence_completeness != EvidenceCompleteness::Complete {
        return Err(CompatibilityAdmissionError::IncompleteEvidence {
            field: "fan_control.capabilities",
        });
    }
    if let Some(capability) = observation.enabled_capabilities.first().copied() {
        return Err(CompatibilityAdmissionError::ForbiddenCapability { capability });
    }
    if observation.backend_evidence_completeness != EvidenceCompleteness::Complete {
        return Err(CompatibilityAdmissionError::IncompleteEvidence {
            field: "fan_control.backends",
        });
    }
    if let Some(backend) = observation
        .backends
        .iter()
        .copied()
        .find(|backend| *backend != FanWriteBackend::AcerHwmon)
    {
        return Err(CompatibilityAdmissionError::UnsupportedBackend { backend });
    }
    match observation.backends.as_slice() {
        [] => return Err(CompatibilityAdmissionError::MissingBackend),
        [FanWriteBackend::AcerHwmon] => {}
        backends => {
            return Err(CompatibilityAdmissionError::AmbiguousBackends {
                count: backends.len(),
            });
        }
    }
    require_equal(
        "fan_control.hwmon_name",
        &declaration.fan_control.hwmon_name,
        &observation.fan_abi.hwmon_name,
    )?;
    if !is_same_unique_set(
        &declaration.fan_control.endpoints,
        &observation.fan_abi.endpoints,
    ) {
        return Err(CompatibilityAdmissionError::Mismatch {
            field: "fan_control.endpoints",
        });
    }

    Ok(AdmittedCompatibility(()))
}

pub(crate) fn validate_declaration(
    declaration: &CompatibilityDeclarationV1,
) -> Result<(), CompatibilityDeclarationError> {
    require_safe(
        declaration.schema_version == 1,
        "schema_version",
        "only schema version 1 is supported",
    )?;
    require_safe(
        declaration.hardware.dmi_product_name == EXPECTED_PRODUCT,
        "hardware.dmi_product_name",
        "must name the qualified product",
    )?;
    require_safe(
        declaration.hardware.dmi_board_name == EXPECTED_BOARD,
        "hardware.dmi_board_name",
        "must name the qualified board",
    )?;
    require_safe(
        declaration.hardware.bios_version == EXPECTED_BIOS,
        "hardware.bios_version",
        "must name the qualified BIOS",
    )?;
    require_safe(
        declaration.kernel.package == EXPECTED_KERNEL_PACKAGE,
        "kernel.package",
        "must name the dedicated kernel package",
    )?;
    require_safe(
        supported_kernel_release(&declaration.kernel.release),
        "kernel.release",
        "must be kernel 6.19 or newer",
    )?;
    require_safe(
        is_lower_hex(&declaration.kernel.source_commit, 40),
        "kernel.source_commit",
        "must be an exact hexadecimal source commit",
    )?;
    require_safe(
        is_lower_hex(&declaration.kernel.image_sha256, 64),
        "kernel.image_sha256",
        "must be a SHA-256 digest",
    )?;
    require_safe(
        is_lower_hex(&declaration.kernel.image_signer_fingerprint, 64),
        "kernel.image_signer_fingerprint",
        "must be a full signing-key fingerprint",
    )?;
    require_safe(
        declaration.module.name == EXPECTED_MODULE_NAME,
        "module.name",
        "must use the in-tree acer_wmi module",
    )?;
    let expected_module_path = format!(
        "/usr/lib/modules/{}/kernel/drivers/platform/x86/acer-wmi.ko.zst",
        declaration.kernel.release
    );
    require_safe(
        declaration.module.path == expected_module_path,
        "module.path",
        "must use the packaged in-tree module path",
    )?;
    require_safe(
        is_lower_hex(&declaration.module.sha256, 64),
        "module.sha256",
        "must be a SHA-256 digest",
    )?;
    require_safe(
        is_lower_hex(&declaration.module.signer_fingerprint, 64),
        "module.signer_fingerprint",
        "must be a full signing-key fingerprint",
    )?;
    require_safe(
        declaration
            .module
            .vermagic
            .strip_prefix(&declaration.kernel.release)
            .is_some_and(|suffix| suffix.starts_with(' ')),
        "module.vermagic",
        "must bind the module to the declared kernel release",
    )?;
    require_safe(
        declaration.module.provenance == ModuleProvenance::InTree,
        "module.provenance",
        "external or replacement modules are forbidden",
    )?;
    require_safe(
        declaration.secure_boot.required,
        "secure_boot.required",
        "Secure Boot trust is mandatory",
    )?;
    require_safe(
        declaration.fan_control.backend == FanWriteBackend::AcerHwmon,
        "fan_control.backend",
        "only the standard Acer hwmon backend is allowed",
    )?;
    require_safe(
        declaration.fan_control.hwmon_name == EXPECTED_HWMON_NAME,
        "fan_control.hwmon_name",
        "must use the acer hwmon device",
    )?;
    require_safe(
        is_exact_string_set(&declaration.fan_control.endpoints, &EXPECTED_ENDPOINTS),
        "fan_control.endpoints",
        "must declare exactly the two-fan Acer hwmon ABI",
    )?;
    require_safe(
        is_exact_capability_set(
            &declaration.fan_control.forbidden_capabilities,
            &FORBIDDEN_CAPABILITIES,
        ),
        "fan_control.forbidden_capabilities",
        "must forbid every known escape hatch",
    )?;
    Ok(())
}

fn require_equal<T: PartialEq>(
    field: &'static str,
    expected: &T,
    actual: &T,
) -> Result<(), CompatibilityAdmissionError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CompatibilityAdmissionError::Mismatch { field })
    }
}

fn require_safe(
    condition: bool,
    field: &'static str,
    reason: &'static str,
) -> Result<(), CompatibilityDeclarationError> {
    if condition {
        Ok(())
    } else {
        Err(CompatibilityDeclarationError::Unsafe { field, reason })
    }
}

fn supported_kernel_release(release: &str) -> bool {
    if !release.ends_with("-cachyos-pt31553")
        || !release
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
        || !release
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
        || !release
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || release
            .as_bytes()
            .windows(2)
            .any(|pair| !pair[0].is_ascii_alphanumeric() && !pair[1].is_ascii_alphanumeric())
    {
        return false;
    }

    let mut components = release.split(['.', '-']);
    let Some(major) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    let Some(minor) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    (major, minor) >= (6, 19)
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_exact_string_set(values: &[String], expected: &[&str]) -> bool {
    let values_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let expected_set: BTreeSet<&str> = expected.iter().copied().collect();
    values.len() == values_set.len() && values_set == expected_set
}

fn is_same_unique_set(left: &[String], right: &[String]) -> bool {
    let left_set: BTreeSet<&str> = left.iter().map(String::as_str).collect();
    let right_set: BTreeSet<&str> = right.iter().map(String::as_str).collect();
    left.len() == left_set.len() && right.len() == right_set.len() && left_set == right_set
}

fn is_exact_capability_set(
    values: &[EscapeHatchCapability],
    expected: &[EscapeHatchCapability],
) -> bool {
    let values_set: BTreeSet<_> = values.iter().copied().collect();
    let expected_set: BTreeSet<_> = expected.iter().copied().collect();
    values.len() == values_set.len() && values_set == expected_set
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = i64::deserialize(deserializer)?;
    if version == 1 {
        Ok(1)
    } else {
        Err(de::Error::custom("schema_version must be 1"))
    }
}
