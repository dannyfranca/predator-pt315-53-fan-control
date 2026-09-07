use std::{
    error::Error,
    io::{self, BufRead, BufReader, Read, Write},
    path::Path,
    sync::mpsc,
    thread,
    time::Duration,
};

use fan_control_core::{
    CalibrationLevelObservation, CalibrationReadbackSample, CalibrationStep,
    CompletedFanCalibrationRun, ConservativeFanCalibration, ControllerOwnership, EvidenceFan,
    EvidenceTimestamp, Fan, FanCalibrationEvidence, FanEndpointIdentitiesEvidence,
    MatchedWorkloadFanRestoration, QualificationArmedFanControl, QualificationEnvelopeIdentityV1,
    RestorationOutcome, ShutdownRequest, SystemOwnershipPlatform, TerminationSignalHandlers,
    acquire_controller_ownership, arm_both_fans_for_qualification_at_maximum_until,
    build_fan_calibration_record, calibration_level_is_settled,
    command_qualification_calibration_fan_before, observe_qualification_calibration_fan_before,
    qualification_control_monotonic_now,
};
use fan_control_daemon::HWMON_ROOT;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{MAX_REQUEST_BYTES, evidence_timestamp, monotonic_millis, require_observer};

const REQUEST_POLL_MILLIS: u64 = 50;
const LEVEL_SAMPLE_CADENCE_MILLIS: u64 = 500;
const LEVEL_CAPTURE_LIMIT_MILLIS: u64 = 9_000;
const HOLD_SAMPLE_CADENCE_MILLIS: u64 = 1_700;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerRequest {
    operation: String,
    deadline: u64,
    request: Value,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ServerResponse {
    ok: bool,
    response: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationRequest {
    fan: EvidenceFan,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationStepRequest {
    fan: EvidenceFan,
    step: CalibrationStep,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeCalibrationRequest {
    fan: EvidenceFan,
    calibration: FanCalibrationEvidence,
    qualification_envelope: QualificationEnvelopeIdentityV1,
}

#[derive(Debug, Serialize)]
struct ConfirmationResponse {
    observer_present: bool,
    confirmed: bool,
}

#[derive(Debug, Serialize)]
struct ObservedResponse<T> {
    observer_present: bool,
    observation: T,
}

#[derive(Debug)]
struct RestorationEvidence {
    attempted_at: EvidenceTimestamp,
    confirmed_at: EvidenceTimestamp,
    fans: [MatchedWorkloadFanRestoration; 2],
}

#[derive(Debug, Default)]
struct CalibrationSession {
    fan: Option<EvidenceFan>,
    started_at: Option<EvidenceTimestamp>,
    custom_control_confirmed_at: Option<EvidenceTimestamp>,
    armed: Option<QualificationArmedFanControl>,
    protocol: Option<ConservativeFanCalibration>,
    restoration: Option<RestorationEvidence>,
    finalized: bool,
}

#[derive(Debug, Clone, Copy)]
struct MonotonicClockBridge {
    local_origin_in_boot_millis: u64,
}

impl MonotonicClockBridge {
    fn capture(
        ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    ) -> Result<Self, Box<dyn Error>> {
        let boot_millis = monotonic_millis()?;
        let local_millis = duration_millis(qualification_control_monotonic_now(ownership));
        Ok(Self {
            local_origin_in_boot_millis: boot_millis.saturating_sub(local_millis),
        })
    }

    fn local_deadline(
        self,
        ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
        absolute_deadline: u64,
    ) -> Result<Duration, Box<dyn Error>> {
        let local_now = qualification_control_monotonic_now(ownership);
        let boot_now = require_absolute_deadline(absolute_deadline)?;
        let remaining = absolute_deadline - boot_now;
        local_now
            .checked_add(Duration::from_millis(remaining))
            .ok_or_else(|| "qualification I/O deadline overflow".into())
    }

    fn absolutize_sample(self, mut sample: CalibrationReadbackSample) -> CalibrationReadbackSample {
        sample.monotonic_millis = self
            .local_origin_in_boot_millis
            .saturating_add(sample.monotonic_millis);
        sample
    }

    fn absolutize_millis(self, local_millis: u64) -> u64 {
        self.local_origin_in_boot_millis
            .saturating_add(local_millis)
    }
}

pub(crate) fn serve() -> Result<(), Box<dyn Error>> {
    require_root()?;
    let shutdown = ShutdownRequest::new();
    let _signal_handlers = TerminationSignalHandlers::install(shutdown.clone())?;
    let mut platform = SystemOwnershipPlatform::new();
    let mut ownership = acquire_controller_ownership(&mut platform)?;
    let device = ownership.discover_acer_hwmon(Path::new(HWMON_ROOT))?;
    let identities = FanEndpointIdentitiesEvidence::from_device(&device)
        .ok_or("fan endpoint identities are incomplete")?;
    let execution = (|| {
        restore_or_contain(&mut ownership, &device)?;
        let clock = MonotonicClockBridge::capture(&mut ownership)?;
        run_request_loop(&mut ownership, &device, &identities, clock, &shutdown)
    })();
    let cleanup = restore_or_contain(&mut ownership, &device);
    let release = ownership.release().map_err(|error| error.to_string());
    combine_server_exit(execution, cleanup, release)
}

fn run_request_loop(
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    device: &fan_control_core::AcerHwmonDevice,
    identities: &FanEndpointIdentitiesEvidence,
    clock: MonotonicClockBridge,
    shutdown: &ShutdownRequest,
) -> Result<(), Box<dyn Error>> {
    let receiver = spawn_request_reader();
    let mut session = CalibrationSession::default();

    loop {
        if shutdown.is_requested() {
            break;
        }
        let line = match receiver.recv_timeout(Duration::from_millis(REQUEST_POLL_MILLIS)) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) => return Err(error.into()),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let request = match serde_json::from_slice::<ServerRequest>(&line) {
            Ok(request) => request,
            Err(error) => {
                let mut detail = format!("invalid qualification server request: {error}");
                append_failed_restoration(
                    &mut detail,
                    restore_active_session(&mut session, ownership, device, identities),
                );
                write_server_response(ServerResponse::error(detail))?;
                continue;
            }
        };
        let result = dispatch(
            request,
            &mut session,
            ownership,
            device,
            identities,
            clock,
            shutdown,
        );
        let response = match result {
            Ok(value) => ServerResponse::success(value),
            Err(error) => {
                let mut detail = error.to_string();
                append_failed_restoration(
                    &mut detail,
                    restore_active_session(&mut session, ownership, device, identities),
                );
                ServerResponse::error(detail)
            }
        };
        write_server_response(response)?;
    }
    Ok(())
}

fn combine_server_exit(
    execution: Result<(), Box<dyn Error>>,
    cleanup: Result<(), Box<dyn Error>>,
    release: Result<(), String>,
) -> Result<(), Box<dyn Error>> {
    let mut failures = Vec::new();
    if let Err(error) = execution {
        failures.push(error.to_string());
    }
    if let Err(error) = cleanup {
        failures.push(format!(
            "CRITICAL: final Firmware Auto restoration failed: {error}"
        ));
    }
    if let Err(error) = release {
        failures.push(format!("controller release failed: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

fn dispatch(
    request: ServerRequest,
    session: &mut CalibrationSession,
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    device: &fan_control_core::AcerHwmonDevice,
    identities: &FanEndpointIdentitiesEvidence,
    clock: MonotonicClockBridge,
    shutdown: &ShutdownRequest,
) -> Result<Value, Box<dyn Error>> {
    require_absolute_deadline(request.deadline)?;
    match request.operation.as_str() {
        "begin-fan-calibration" => begin_calibration(
            decode(request.request)?,
            request.deadline,
            session,
            ownership,
            device,
            shutdown,
        ),
        "observe-calibration-level" => observe_calibration_level(
            decode(request.request)?,
            request.deadline,
            session,
            ownership,
            clock,
            shutdown,
        ),
        "observe-calibration-hold" => observe_calibration_hold(
            decode(request.request)?,
            request.deadline,
            session,
            ownership,
            clock,
            shutdown,
        ),
        "restore-fan-calibration" => restore_calibration(
            decode(request.request)?,
            session,
            ownership,
            device,
            identities,
        ),
        "finalize-fan-calibration" => {
            finalize_calibration(decode(request.request)?, session, identities)
        }
        operation => Err(format!("unsupported qualification server operation: {operation}").into()),
    }
}

fn begin_calibration(
    request: CalibrationRequest,
    deadline: u64,
    session: &mut CalibrationSession,
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    device: &fan_control_core::AcerHwmonDevice,
    shutdown: &ShutdownRequest,
) -> Result<Value, Box<dyn Error>> {
    if session.fan.is_some() || session.finalized {
        return Err("qualification server permits exactly one calibration".into());
    }
    require_observer(deadline)?;
    let started_at = evidence_timestamp()?;
    let armed = arm_both_fans_for_qualification_at_maximum_until(ownership, device, shutdown)?;
    session.fan = Some(request.fan);
    session.started_at = Some(started_at);
    session.armed = Some(armed);
    session.custom_control_confirmed_at = Some(evidence_timestamp()?);
    session.protocol = Some(ConservativeFanCalibration::start(fan(request.fan)));
    require_observer(deadline)?;
    require_absolute_deadline(deadline)?;
    encode(ConfirmationResponse {
        observer_present: true,
        confirmed: true,
    })
}

fn observe_calibration_level(
    request: CalibrationStepRequest,
    deadline: u64,
    session: &mut CalibrationSession,
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    clock: MonotonicClockBridge,
    shutdown: &ShutdownRequest,
) -> Result<Value, Box<dyn Error>> {
    require_active_fan(session, request.fan)?;
    if session
        .protocol
        .as_ref()
        .is_none_or(|protocol| protocol.next_step() != request.step)
    {
        return Err("calibration level does not match the protected protocol".into());
    }
    if matches!(
        request.step,
        CalibrationStep::HoldFloor { .. } | CalibrationStep::Complete | CalibrationStep::Failed
    ) {
        return Err("calibration level operation received an invalid step".into());
    }
    let pwm = request
        .step
        .pwm_value()
        .ok_or("calibration level has no PWM command")?;
    require_observer(deadline)?;
    let local_deadline = clock.local_deadline(ownership, deadline)?;
    let commanded = command_qualification_calibration_fan_before(
        ownership,
        session.armed.as_ref().ok_or("calibration is not armed")?,
        fan(request.fan),
        pwm,
        local_deadline,
    )?;
    let commanded_at = clock.absolutize_millis(commanded.commanded_at_monotonic_millis);
    let mut observation = CalibrationLevelObservation {
        commanded_at_monotonic_millis: commanded_at,
        samples: vec![clock.absolutize_sample(commanded.sample)],
        stall_observed: false,
        unexplained_rpm_collapse_observed: false,
    };
    let capture_limit = commanded_at.saturating_add(LEVEL_CAPTURE_LIMIT_MILLIS);
    let mut sample_number = 1_u64;
    loop {
        if calibration_level_is_settled(&observation).is_ok_and(|settled| settled) {
            break;
        }
        let target =
            commanded_at.saturating_add(sample_number.saturating_mul(LEVEL_SAMPLE_CADENCE_MILLIS));
        if target > capture_limit {
            break;
        }
        wait_until(target, deadline, shutdown)?;
        require_observer(deadline)?;
        let local_deadline = clock.local_deadline(ownership, deadline)?;
        let sample = observe_qualification_calibration_fan_before(
            ownership,
            session.armed.as_ref().ok_or("calibration is not armed")?,
            fan(request.fan),
            pwm,
            local_deadline,
        )?;
        observation.samples.push(clock.absolutize_sample(sample));
        sample_number = sample_number.saturating_add(1);
    }
    require_absolute_deadline(deadline)?;
    session
        .protocol
        .as_mut()
        .ok_or("calibration protocol is unavailable")?
        .record_level(observation.clone())?;
    encode(ObservedResponse {
        observer_present: true,
        observation,
    })
}

fn observe_calibration_hold(
    request: CalibrationStepRequest,
    deadline: u64,
    session: &mut CalibrationSession,
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    clock: MonotonicClockBridge,
    shutdown: &ShutdownRequest,
) -> Result<Value, Box<dyn Error>> {
    require_active_fan(session, request.fan)?;
    if session
        .protocol
        .as_ref()
        .is_none_or(|protocol| protocol.next_step() != request.step)
    {
        return Err("calibration hold does not match the protected protocol".into());
    }
    let (pwm, required_duration_millis) = match request.step {
        CalibrationStep::HoldFloor {
            pwm_value,
            required_duration_millis,
            ..
        } if required_duration_millis == fan_control_core::REQUIRED_FLOOR_HOLD_MILLIS => {
            (pwm_value, required_duration_millis)
        }
        _ => return Err("calibration hold operation received an invalid step".into()),
    };
    require_observer(deadline)?;
    let local_deadline = clock.local_deadline(ownership, deadline)?;
    let first = observe_qualification_calibration_fan_before(
        ownership,
        session.armed.as_ref().ok_or("calibration is not armed")?,
        fan(request.fan),
        pwm,
        local_deadline,
    )?;
    let first = clock.absolutize_sample(first);
    let hold_until = first
        .monotonic_millis
        .checked_add(required_duration_millis)
        .ok_or("calibration hold deadline overflow")?;
    let mut samples = vec![first];
    let mut sample_number = 1_u64;
    while samples
        .last()
        .is_some_and(|sample| sample.monotonic_millis < hold_until)
    {
        let target = samples[0]
            .monotonic_millis
            .saturating_add(sample_number.saturating_mul(HOLD_SAMPLE_CADENCE_MILLIS));
        wait_until(target.min(hold_until), deadline, shutdown)?;
        let local_deadline = clock.local_deadline(ownership, deadline)?;
        let sample = observe_qualification_calibration_fan_before(
            ownership,
            session.armed.as_ref().ok_or("calibration is not armed")?,
            fan(request.fan),
            pwm,
            local_deadline,
        )?;
        samples.push(clock.absolutize_sample(sample));
        require_observer(deadline)?;
        sample_number = sample_number.saturating_add(1);
    }
    let observation = fan_control_core::FanHoldObservation {
        samples,
        stall_observed: false,
        unexplained_rpm_collapse_observed: false,
    };
    session
        .protocol
        .as_mut()
        .ok_or("calibration protocol is unavailable")?
        .record_hold(observation.clone())?;
    encode(ObservedResponse {
        observer_present: true,
        observation,
    })
}

fn restore_calibration(
    request: CalibrationRequest,
    session: &mut CalibrationSession,
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    device: &fan_control_core::AcerHwmonDevice,
    identities: &FanEndpointIdentitiesEvidence,
) -> Result<Value, Box<dyn Error>> {
    if session.fan.is_none() {
        return Err("calibration has not started".into());
    }
    if session.restoration.is_none() {
        session.armed.take();
        session.restoration = Some(restore_with_evidence(ownership, device, identities)?);
    }
    let restoration = session.restoration.as_ref().expect("created above");
    let index = match request.fan {
        EvidenceFan::Cpu => 0,
        EvidenceFan::Gpu => 1,
    };
    encode(restoration.fans[index].clone())
}

fn finalize_calibration(
    request: FinalizeCalibrationRequest,
    session: &mut CalibrationSession,
    identities: &FanEndpointIdentitiesEvidence,
) -> Result<Value, Box<dyn Error>> {
    if session.finalized {
        return Err("calibration evidence was already finalized".into());
    }
    if session.fan != Some(request.fan) || request.calibration.fan != request.fan {
        return Err("calibration fan does not match the active session".into());
    }
    if session
        .protocol
        .as_ref()
        .and_then(ConservativeFanCalibration::evidence)
        != Some(&request.calibration)
    {
        return Err("calibration evidence does not match the protected server protocol".into());
    }
    let restoration = session
        .restoration
        .as_ref()
        .ok_or("Firmware Auto must be confirmed before finalization")?;
    let record = build_fan_calibration_record(CompletedFanCalibrationRun {
        qualification_envelope: request.qualification_envelope,
        calibration: request.calibration,
        endpoint_identities: identities.clone(),
        started_at: session
            .started_at
            .ok_or("calibration start is unavailable")?,
        custom_control_confirmed_at: session
            .custom_control_confirmed_at
            .ok_or("Custom control confirmation time is unavailable")?,
        restoration_attempted_at: restoration.attempted_at,
        restoration_confirmed_at: restoration.confirmed_at,
        completed_at: evidence_timestamp()?,
    })?;
    session.finalized = true;
    encode(record)
}

fn require_active_fan(
    session: &CalibrationSession,
    requested: EvidenceFan,
) -> Result<(), Box<dyn Error>> {
    if session.fan != Some(requested) {
        return Err("calibration fan does not match the active session".into());
    }
    if session.armed.is_none()
        || session.protocol.is_none()
        || session.restoration.is_some()
        || session.finalized
    {
        return Err("calibration is not in active Custom control".into());
    }
    Ok(())
}

fn restore_active_session(
    session: &mut CalibrationSession,
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    device: &fan_control_core::AcerHwmonDevice,
    identities: &FanEndpointIdentitiesEvidence,
) -> Result<(), Box<dyn Error>> {
    if session.armed.take().is_some() && session.restoration.is_none() {
        session.restoration = Some(restore_with_evidence(ownership, device, identities)?);
    }
    Ok(())
}

fn restore_with_evidence(
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    device: &fan_control_core::AcerHwmonDevice,
    identities: &FanEndpointIdentitiesEvidence,
) -> Result<RestorationEvidence, Box<dyn Error>> {
    let attempted_at = evidence_timestamp()?;
    restore_or_contain(ownership, device)?;
    let confirmed_at = evidence_timestamp()?;
    Ok(RestorationEvidence {
        attempted_at,
        confirmed_at,
        fans: [
            successful_restoration(identities.cpu_enable.clone()),
            successful_restoration(identities.gpu_enable.clone()),
        ],
    })
}

fn successful_restoration(endpoint_identity: String) -> MatchedWorkloadFanRestoration {
    MatchedWorkloadFanRestoration {
        auto_write_succeeded: true,
        enable_readback: Some(2),
        endpoint_identity,
        outcome: RestorationOutcome::FirmwareAutoConfirmed,
    }
}

fn restore_or_contain(
    ownership: &mut ControllerOwnership<'_, SystemOwnershipPlatform>,
    device: &fan_control_core::AcerHwmonDevice,
) -> Result<(), Box<dyn Error>> {
    match ownership.restore_firmware_auto(device) {
        Ok(()) => Ok(()),
        Err(restoration) => {
            let containment = ownership.contain_custom_fans_at_maximum(device);
            Err(format!(
                "Firmware Auto restoration failed: {restoration}; emergency containment: {containment:?}"
            )
            .into())
        }
    }
}

fn append_failed_restoration(detail: &mut String, restoration: Result<(), Box<dyn Error>>) {
    if let Err(error) = restoration {
        detail.push_str(&format!(
            "; CRITICAL: automatic Firmware Auto restoration failed: {error}"
        ));
    }
}

fn wait_until(
    target: u64,
    deadline: u64,
    shutdown: &ShutdownRequest,
) -> Result<(), Box<dyn Error>> {
    if target >= deadline {
        return Err("calibration wait target reaches its absolute deadline".into());
    }
    loop {
        if shutdown.is_requested() {
            return Err("calibration cancelled by termination signal".into());
        }
        let now = require_absolute_deadline(deadline)?;
        if now >= target {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(
            (target - now).min(REQUEST_POLL_MILLIS),
        ));
    }
}

fn require_absolute_deadline(deadline: u64) -> Result<u64, Box<dyn Error>> {
    let now = monotonic_millis()?;
    if now >= deadline {
        return Err("qualification server deadline expired".into());
    }
    Ok(now)
}

fn require_root() -> Result<(), Box<dyn Error>> {
    // SAFETY: geteuid has no preconditions and does not modify process state.
    if unsafe { libc::geteuid() } != 0 {
        return Err("qualification control server must run as root".into());
    }
    Ok(())
}

fn fan(fan: EvidenceFan) -> Fan {
    match fan {
        EvidenceFan::Cpu => Fan::Cpu,
        EvidenceFan::Gpu => Fan::Gpu,
    }
}

fn duration_millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, Box<dyn Error>> {
    serde_json::from_value(value).map_err(Into::into)
}

fn encode(value: impl Serialize) -> Result<Value, Box<dyn Error>> {
    serde_json::to_value(value).map_err(Into::into)
}

impl ServerResponse {
    fn success(response: Value) -> Self {
        Self {
            ok: true,
            response: Some(response),
            error: None,
        }
    }

    fn error(error: String) -> Self {
        Self {
            ok: false,
            response: None,
            error: Some(error),
        }
    }
}

fn spawn_request_reader() -> mpsc::Receiver<Result<Vec<u8>, String>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut input = BufReader::new(io::stdin().lock());
        loop {
            let mut line = Vec::new();
            let read = (&mut input)
                .take(MAX_REQUEST_BYTES + 1)
                .read_until(b'\n', &mut line);
            match read {
                Ok(0) => break,
                Ok(_) if line.len() as u64 > MAX_REQUEST_BYTES => {
                    let _ =
                        sender.send(Err("qualification server request exceeds 1 MiB".to_owned()));
                    break;
                }
                Ok(_) => {
                    while matches!(line.last(), Some(b'\n' | b'\r')) {
                        line.pop();
                    }
                    if sender.send(Ok(line)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(format!(
                        "cannot read qualification server request: {error}"
                    )));
                    break;
                }
            }
        }
    });
    receiver
}

fn write_server_response(response: ServerResponse) -> Result<(), Box<dyn Error>> {
    let encoded = serde_json::to_vec(&response)?;
    if encoded.len() as u64 > MAX_REQUEST_BYTES {
        return Err("qualification server response exceeds 1 MiB".into());
    }
    let mut output = io::stdout().lock();
    output.write_all(&encoded)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_request_rejects_unknown_envelope_fields() {
        let request = br#"{"operation":"begin-fan-calibration","deadline":1,"request":{"fan":"cpu"},"extra":true}"#;
        assert!(serde_json::from_slice::<ServerRequest>(request).is_err());
    }

    #[test]
    fn calibration_requests_reject_unknown_fields() {
        let request = serde_json::json!({"fan": "cpu", "extra": true});
        assert!(decode::<CalibrationRequest>(request).is_err());
    }

    #[test]
    fn clock_bridge_converts_local_sample_times_to_boot_monotonic_times() {
        let bridge = MonotonicClockBridge {
            local_origin_in_boot_millis: 100_000,
        };
        let sample = bridge.absolutize_sample(CalibrationReadbackSample {
            monotonic_millis: 250,
            selected_enable_readback: 1,
            selected_pwm_readback: 128,
            other_enable_readback: 1,
            other_pwm_readback: 255,
            selected_rpm: Some(3_000),
        });
        assert_eq!(sample.monotonic_millis, 100_250);
    }
}
