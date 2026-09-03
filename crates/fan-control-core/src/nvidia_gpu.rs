use std::{error::Error, fmt};

use crate::TemperatureCelsius;

const MIN_PLAUSIBLE_GPU_TEMPERATURE_CELSIUS: f64 = 1.0;
const MAX_PLAUSIBLE_GPU_TEMPERATURE_CELSIUS: f64 = 125.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvidiaGpuSelectorKind {
    Uuid,
    PciBusId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvidiaGpuSelector {
    kind: NvidiaGpuSelectorKind,
    normalized: String,
}

impl NvidiaGpuSelector {
    pub fn uuid(value: impl AsRef<str>) -> Result<Self, NvidiaGpuSelectorError> {
        let value = value.as_ref();
        let normalized = normalize_uuid(value)
            .ok_or_else(|| NvidiaGpuSelectorError::InvalidUuid(value.to_owned()))?;
        Ok(Self {
            kind: NvidiaGpuSelectorKind::Uuid,
            normalized,
        })
    }

    pub fn pci_bus_id(value: impl AsRef<str>) -> Result<Self, NvidiaGpuSelectorError> {
        let value = value.as_ref();
        let normalized = normalize_pci_bus_id(value)
            .ok_or_else(|| NvidiaGpuSelectorError::InvalidPciBusId(value.to_owned()))?;
        Ok(Self {
            kind: NvidiaGpuSelectorKind::PciBusId,
            normalized,
        })
    }

    pub const fn kind(&self) -> NvidiaGpuSelectorKind {
        self.kind
    }

    pub fn value(&self) -> &str {
        &self.normalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvidiaGpuSelectorError {
    InvalidUuid(String),
    InvalidPciBusId(String),
}

impl fmt::Display for NvidiaGpuSelectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid(value) => write!(formatter, "invalid NVIDIA GPU UUID: {value}"),
            Self::InvalidPciBusId(value) => {
                write!(formatter, "invalid NVIDIA PCI bus ID: {value}")
            }
        }
    }
}

impl Error for NvidiaGpuSelectorError {}

#[derive(Debug, Clone, PartialEq)]
pub struct NvmlGpuSample {
    uuid: String,
    pci_bus_id: String,
    temperature_celsius: f64,
}

impl NvmlGpuSample {
    pub fn new(
        uuid: impl Into<String>,
        pci_bus_id: impl Into<String>,
        temperature_celsius: f64,
    ) -> Self {
        Self {
            uuid: uuid.into(),
            pci_bus_id: pci_bus_id.into(),
            temperature_celsius,
        }
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn pci_bus_id(&self) -> &str {
        &self.pci_bus_id
    }

    pub const fn temperature_celsius(&self) -> f64 {
        self.temperature_celsius
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmlErrorKind {
    ResetRequired,
    GpuLost,
    NoData,
    NotReady,
    TimedOut,
    InvalidState,
    Unsupported,
    LibraryFailure,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvmlError {
    kind: NvmlErrorKind,
    message: String,
}

impl NvmlError {
    pub fn new(kind: NvmlErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub const fn kind(&self) -> NvmlErrorKind {
        self.kind
    }
}

impl fmt::Display for NvmlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for NvmlError {}

/// Identity-directed NVML access.
///
/// Implementations must look up the target directly by the supplied UUID or PCI bus ID, never by
/// an enumeration index. The returned identity and temperature must come from the same device
/// handle, and every underlying NVML call must have returned `NVML_SUCCESS`.
pub trait NvmlAccess {
    fn sample_by_identity(
        &mut self,
        selector: &NvidiaGpuSelector,
    ) -> Result<NvmlGpuSample, NvmlError>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum NvidiaGpuSampleError {
    Nvml(NvmlError),
    IdentityMismatch {
        expected: NvidiaGpuSelector,
        observed: String,
    },
    InvalidTemperature {
        value: f64,
    },
}

impl fmt::Display for NvidiaGpuSampleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nvml(error) => write!(formatter, "NVML GPU sample failed: {error}"),
            Self::IdentityMismatch { expected, observed } => write!(
                formatter,
                "NVML GPU identity mismatch: expected {} {:?}, observed {observed}",
                expected.value(),
                expected.kind()
            ),
            Self::InvalidTemperature { value } => {
                write!(formatter, "invalid NVML GPU temperature: {value} °C")
            }
        }
    }
}

impl Error for NvidiaGpuSampleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Nvml(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NvmlError> for NvidiaGpuSampleError {
    fn from(error: NvmlError) -> Self {
        Self::Nvml(error)
    }
}

pub fn sample_nvidia_gpu(
    nvml: &mut dyn NvmlAccess,
    expected: &NvidiaGpuSelector,
) -> Result<TemperatureCelsius, NvidiaGpuSampleError> {
    let sample = nvml.sample_by_identity(expected)?;
    let (observed, normalized) = match expected.kind() {
        NvidiaGpuSelectorKind::Uuid => (sample.uuid(), normalize_uuid(sample.uuid())),
        NvidiaGpuSelectorKind::PciBusId => (
            sample.pci_bus_id(),
            normalize_pci_bus_id(sample.pci_bus_id()),
        ),
    };
    if normalized.as_deref() != Some(expected.value()) {
        return Err(NvidiaGpuSampleError::IdentityMismatch {
            expected: expected.clone(),
            observed: observed.to_owned(),
        });
    }

    let value = sample.temperature_celsius();
    if !value.is_finite()
        || value.fract() != 0.0
        || !(MIN_PLAUSIBLE_GPU_TEMPERATURE_CELSIUS..=MAX_PLAUSIBLE_GPU_TEMPERATURE_CELSIUS)
            .contains(&value)
    {
        return Err(NvidiaGpuSampleError::InvalidTemperature { value });
    }

    Ok(TemperatureCelsius::try_from(value).expect("a finite GPU temperature is valid"))
}

fn normalize_uuid(value: &str) -> Option<String> {
    let body = value.strip_prefix("GPU-")?;
    let mut groups = body.split('-');
    for expected_len in [8, 4, 4, 4, 12] {
        let group = groups.next()?;
        if group.len() != expected_len || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
    }
    if groups.next().is_some() {
        return None;
    }
    Some(format!("GPU-{}", body.to_ascii_lowercase()))
}

pub(crate) fn is_nvidia_gpu_uuid(value: &str) -> bool {
    normalize_uuid(value).is_some()
}

fn normalize_pci_bus_id(value: &str) -> Option<String> {
    let (slot, function) = value.split_once('.')?;
    if function.len() != 1 || !function.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let function = u8::from_str_radix(function, 16).ok()?;
    if function > 7 {
        return None;
    }

    let mut fields = slot.split(':');
    let domain = fields.next()?;
    let bus = fields.next()?;
    let device = fields.next()?;
    if fields.next().is_some()
        || !matches!(domain.len(), 4 | 8)
        || bus.len() != 2
        || device.len() != 2
        || !domain.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !bus.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !device.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let domain = u32::from_str_radix(domain, 16).ok()?;
    let bus = u8::from_str_radix(bus, 16).ok()?;
    let device = u8::from_str_radix(device, 16).ok()?;
    if device > 0x1f {
        return None;
    }

    Some(format!("{domain:08x}:{bus:02x}:{device:02x}.{function:x}"))
}
