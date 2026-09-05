use std::{
    env,
    error::Error,
    io::{self, Read},
    path::Path,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use fan_control_core::{
    EvidenceProfile, EvidenceTimestamp, ExternalPower, NvidiaGpuSelector, NvmlErrorKind,
};
use fan_control_daemon::{capture_system_qualification_sample, sample_system_nvidia};
use fan_control_observer::{DEFAULT_SOCKET_PATH, ObserverConfirmation, query_protected_observer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pt31553 qualification harness: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let operation = arguments.next().ok_or("operation is required")?;
    let deadline = arguments
        .next()
        .ok_or("absolute monotonic deadline is required")?
        .parse::<u64>()?;
    if arguments.next().is_some() {
        return Err("unexpected qualification harness argument".into());
    }
    require_before_deadline(deadline)?;
    match operation.as_str() {
        "sample-nvidia" => sample_nvidia(read_request()?, deadline),
        "capture-baseline-starting-conditions" => {
            capture_baseline_starting_conditions(read_request()?, deadline)
        }
        "confirm-endurance-observer" => confirm_endurance_observer(read_request()?, deadline),
        _ => Err(format!("unsupported qualification harness operation: {operation}").into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NvidiaRequest {
    uuid: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum NvidiaResponse {
    Sample {
        uuid: String,
        pci_bus_id: String,
        temperature_celsius: f64,
    },
    Error {
        error_kind: &'static str,
        error: String,
    },
}

fn sample_nvidia(request: NvidiaRequest, deadline: u64) -> Result<(), Box<dyn Error>> {
    let selector = NvidiaGpuSelector::uuid(request.uuid)?;
    let response = match sample_system_nvidia(&selector) {
        Ok(sample) => NvidiaResponse::Sample {
            uuid: sample.uuid().to_owned(),
            pci_bus_id: sample.pci_bus_id().to_owned(),
            temperature_celsius: sample.temperature_celsius(),
        },
        Err(error) => NvidiaResponse::Error {
            error_kind: nvidia_error_kind(error.kind()),
            error: error.to_string(),
        },
    };
    require_before_deadline(deadline)?;
    write_response(&response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineStartingRequest {
    nvidia_gpu_uuid: String,
}

#[derive(Serialize)]
struct BaselineStartingResponse {
    captured_at: EvidenceTimestamp,
    nvidia_gpu_uuid: String,
    ambient_millicelsius: i32,
    cpu_millicelsius: i32,
    gpu_millicelsius: i32,
    power_profile: EvidenceProfile,
}

fn capture_baseline_starting_conditions(
    request: BaselineStartingRequest,
    deadline: u64,
) -> Result<(), Box<dyn Error>> {
    let selector = NvidiaGpuSelector::uuid(&request.nvidia_gpu_uuid)?;
    require_observer(deadline)?;
    let sample = capture_system_qualification_sample(&selector)?;
    let observer = require_observer(deadline)?;
    let response = BaselineStartingResponse {
        captured_at: evidence_timestamp()?,
        nvidia_gpu_uuid: selector.value().to_owned(),
        ambient_millicelsius: observer.ambient_millicelsius,
        cpu_millicelsius: sample.cpu_millicelsius,
        gpu_millicelsius: sample.gpu_millicelsius,
        power_profile: evidence_profile(sample.external_power)?,
    };
    require_before_deadline(deadline)?;
    write_response(&response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

#[derive(Serialize)]
struct ObserverResponse {
    observer_present: bool,
    confirmed: bool,
    observed_at: EvidenceTimestamp,
}

fn confirm_endurance_observer(_: EmptyRequest, deadline: u64) -> Result<(), Box<dyn Error>> {
    let confirmation = query_observer(deadline)?;
    let response = ObserverResponse {
        observer_present: confirmation.observer_present,
        confirmed: confirmation.confirmed,
        observed_at: EvidenceTimestamp {
            monotonic_millis: confirmation.observed_at.monotonic_millis,
            wall_unix_millis: confirmation.observed_at.wall_unix_millis,
        },
    };
    write_response(&response)
}

fn require_observer(deadline: u64) -> Result<ObserverConfirmation, Box<dyn Error>> {
    let confirmation = query_observer(deadline)?;
    if !confirmation.observer_present || !confirmation.confirmed {
        return Err("physical observer presence is not confirmed".into());
    }
    Ok(confirmation)
}

fn query_observer(deadline: u64) -> Result<ObserverConfirmation, Box<dyn Error>> {
    require_before_deadline(deadline)?;
    let confirmation = query_protected_observer(Path::new(DEFAULT_SOCKET_PATH))?;
    require_before_deadline(deadline)?;
    Ok(confirmation)
}

fn evidence_profile(power: ExternalPower) -> Result<EvidenceProfile, Box<dyn Error>> {
    match power {
        ExternalPower::Connected => Ok(EvidenceProfile::Ac),
        ExternalPower::Disconnected => Ok(EvidenceProfile::Battery),
        ExternalPower::Unknown => Err("external power state is unknown".into()),
    }
}

fn nvidia_error_kind(kind: NvmlErrorKind) -> &'static str {
    match kind {
        NvmlErrorKind::ResetRequired => "reset-required",
        NvmlErrorKind::GpuLost => "gpu-lost",
        NvmlErrorKind::NoData => "no-data",
        NvmlErrorKind::NotReady => "not-ready",
        NvmlErrorKind::TimedOut => "timed-out",
        NvmlErrorKind::InvalidState => "invalid-state",
        NvmlErrorKind::Unsupported => "unsupported",
        NvmlErrorKind::LibraryFailure => "library-failure",
        NvmlErrorKind::Other => "other",
    }
}

fn read_request<T: DeserializeOwned>() -> Result<T, Box<dyn Error>> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("qualification harness request has an invalid size".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_response(response: &impl Serialize) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(io::stdout().lock(), response)?;
    Ok(())
}

fn require_before_deadline(deadline: u64) -> Result<u64, Box<dyn Error>> {
    let now = monotonic_millis()?;
    if now >= deadline {
        return Err("qualification harness deadline expired".into());
    }
    Ok(now)
}

fn evidence_timestamp() -> Result<EvidenceTimestamp, Box<dyn Error>> {
    Ok(EvidenceTimestamp {
        monotonic_millis: monotonic_millis()?,
        wall_unix_millis: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()
            .map_err(|_| "wall clock cannot be represented")?,
    })
}

fn monotonic_millis() -> io::Result<u64> {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: timestamp points to writable storage for clock_gettime.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, timestamp.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful clock_gettime initialized timestamp.
    let timestamp = unsafe { timestamp.assume_init() };
    Ok(u64::try_from(timestamp.tv_sec)
        .unwrap_or(u64::MAX)
        .saturating_mul(1_000)
        .saturating_add(u64::try_from(timestamp.tv_nsec).unwrap_or(u64::MAX) / 1_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_profile_requires_a_known_physical_state() {
        assert_eq!(
            evidence_profile(ExternalPower::Connected).unwrap(),
            EvidenceProfile::Ac
        );
        assert_eq!(
            evidence_profile(ExternalPower::Disconnected).unwrap(),
            EvidenceProfile::Battery
        );
        assert!(evidence_profile(ExternalPower::Unknown).is_err());
    }

    #[test]
    fn every_nvidia_failure_has_the_protocol_spelling() {
        assert_eq!(
            nvidia_error_kind(NvmlErrorKind::ResetRequired),
            "reset-required"
        );
        assert_eq!(nvidia_error_kind(NvmlErrorKind::GpuLost), "gpu-lost");
        assert_eq!(nvidia_error_kind(NvmlErrorKind::NoData), "no-data");
        assert_eq!(nvidia_error_kind(NvmlErrorKind::NotReady), "not-ready");
        assert_eq!(nvidia_error_kind(NvmlErrorKind::TimedOut), "timed-out");
        assert_eq!(
            nvidia_error_kind(NvmlErrorKind::InvalidState),
            "invalid-state"
        );
        assert_eq!(nvidia_error_kind(NvmlErrorKind::Unsupported), "unsupported");
        assert_eq!(
            nvidia_error_kind(NvmlErrorKind::LibraryFailure),
            "library-failure"
        );
        assert_eq!(nvidia_error_kind(NvmlErrorKind::Other), "other");
    }

    #[test]
    fn expired_deadline_is_rejected() {
        assert!(require_before_deadline(0).is_err());
    }
}
