use fan_control_core::{
    NvidiaGpuSampleError, NvidiaGpuSelector, NvmlAccess, NvmlError, NvmlErrorKind, NvmlGpuSample,
    sample_nvidia_gpu,
};

const EXPECTED_UUID: &str = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const EXPECTED_PCI: &str = "0000:01:00.0";

#[derive(Clone)]
struct StubNvml {
    result: Result<NvmlGpuSample, NvmlError>,
    requests: Vec<NvidiaGpuSelector>,
}

impl StubNvml {
    fn successful(temperature_celsius: f64) -> Self {
        Self {
            result: Ok(NvmlGpuSample::new(
                EXPECTED_UUID,
                "00000000:01:00.0",
                temperature_celsius,
            )),
            requests: Vec::new(),
        }
    }
}

impl NvmlAccess for StubNvml {
    fn sample_by_identity(
        &mut self,
        selector: &NvidiaGpuSelector,
    ) -> Result<NvmlGpuSample, NvmlError> {
        self.requests.push(selector.clone());
        self.result.clone()
    }
}

#[test]
fn samples_by_configured_uuid_without_an_enumeration_index() {
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    let mut nvml = StubNvml::successful(67.0);

    assert_eq!(
        sample_nvidia_gpu(&mut nvml, &selector).unwrap().value(),
        67.0
    );
    assert_eq!(nvml.requests, vec![selector]);
}

#[test]
fn samples_by_normalized_pci_identity_without_an_enumeration_index() {
    let selector = NvidiaGpuSelector::pci_bus_id(EXPECTED_PCI).unwrap();
    let mut nvml = StubNvml::successful(68.0);

    assert_eq!(
        sample_nvidia_gpu(&mut nvml, &selector).unwrap().value(),
        68.0
    );
    assert_eq!(nvml.requests, vec![selector]);
}

#[test]
fn rejects_a_successful_sample_from_a_different_selected_identity() {
    for (selector, sample) in [
        (
            NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap(),
            NvmlGpuSample::new(
                "GPU-ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee",
                "00000000:01:00.0",
                67.0,
            ),
        ),
        (
            NvidiaGpuSelector::pci_bus_id(EXPECTED_PCI).unwrap(),
            NvmlGpuSample::new(EXPECTED_UUID, "00000000:02:00.0", 67.0),
        ),
    ] {
        let mut nvml = StubNvml {
            result: Ok(sample),
            requests: Vec::new(),
        };

        assert!(matches!(
            sample_nvidia_gpu(&mut nvml, &selector),
            Err(NvidiaGpuSampleError::IdentityMismatch { .. })
        ));
    }
}

#[test]
fn every_non_success_nvml_status_is_an_invalid_sample() {
    for kind in [
        NvmlErrorKind::ResetRequired,
        NvmlErrorKind::GpuLost,
        NvmlErrorKind::NoData,
        NvmlErrorKind::NotReady,
        NvmlErrorKind::TimedOut,
        NvmlErrorKind::InvalidState,
        NvmlErrorKind::Unsupported,
        NvmlErrorKind::LibraryFailure,
        NvmlErrorKind::Other,
    ] {
        let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
        let mut nvml = StubNvml {
            result: Err(NvmlError::new(kind, "injected NVML failure")),
            requests: Vec::new(),
        };

        assert!(matches!(
            sample_nvidia_gpu(&mut nvml, &selector),
            Err(NvidiaGpuSampleError::Nvml(error)) if error.kind() == kind
        ));
    }
}

#[test]
fn rejects_non_finite_fractional_or_out_of_range_temperatures() {
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    for value in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -1.0,
        0.0,
        65.5,
        126.0,
    ] {
        let mut nvml = StubNvml::successful(value);
        assert!(matches!(
            sample_nvidia_gpu(&mut nvml, &selector),
            Err(NvidiaGpuSampleError::InvalidTemperature { .. })
        ));
    }
}

#[test]
fn accepts_plausibility_endpoints() {
    let selector = NvidiaGpuSelector::uuid(EXPECTED_UUID).unwrap();
    for value in [1.0, 125.0] {
        let mut nvml = StubNvml::successful(value);
        assert_eq!(
            sample_nvidia_gpu(&mut nvml, &selector).unwrap().value(),
            value
        );
    }
}

#[test]
fn rejects_malformed_configured_identities() {
    for value in [
        "",
        "GPU-not-a-uuid",
        "gpu-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    ] {
        assert!(NvidiaGpuSelector::uuid(value).is_err());
    }
    for value in ["", "1", "0000:01:00", "0000:01:20.0", "0000:01:00.8"] {
        assert!(NvidiaGpuSelector::pci_bus_id(value).is_err());
    }
}
