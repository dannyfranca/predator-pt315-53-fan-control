use fan_control_core::{
    ControlCycleDiagnostic, ExternalPower, FanDiagnostic, Pwm, RestorationAttemptDiagnostic,
    RestorationFanDiagnostic, RestorationReadback, RuntimeEndpoint, RuntimeFault, RuntimeState,
    RuntimeTransition, TemperatureCelsius, emit_control_cycle, emit_fault,
    emit_restoration_attempt, emit_state_transition,
};

mod support;
use support::{diagnostic_field as field, record_diagnostics};

#[test]
fn state_transitions_and_faults_have_stable_identifiers_and_endpoint_identity() {
    let (_, events) = record_diagnostics(|| {
        emit_state_transition(
            RuntimeState::Arming,
            RuntimeState::CustomControl,
            RuntimeTransition::ArmingConfirmed,
        );
        emit_fault(
            RuntimeFault::UnexpectedReadback,
            Some(RuntimeEndpoint::GpuPwm),
        );
    });

    assert_eq!(events.len(), 2);
    assert_eq!(field(&events[0], "event_id"), "pt31553.state-transition.v1");
    assert_eq!(field(&events[0], "from_state"), "arming");
    assert_eq!(field(&events[0], "to_state"), "custom-control");
    assert_eq!(field(&events[0], "reason"), "arming-confirmed");
    assert_eq!(field(&events[1], "event_id"), "pt31553.runtime-fault.v1");
    assert_eq!(field(&events[1], "fault_id"), "unexpected-readback");
    assert_eq!(field(&events[1], "endpoint"), "acer:gpu:pwm2");
}

#[test]
fn completed_cycle_exposes_samples_profile_demand_commands_readbacks_and_rpm() {
    let (_, events) = record_diagnostics(|| {
        emit_control_cycle(ControlCycleDiagnostic {
            cpu_temperature: TemperatureCelsius::try_from(71.5).unwrap(),
            gpu_temperature: TemperatureCelsius::try_from(64.0).unwrap(),
            external_power: ExternalPower::Disconnected,
            demand: fan_control_core::DemandPercent::try_from(63.25).unwrap(),
            cpu: FanDiagnostic {
                command: Pwm::from(fan_control_core::DemandPercent::try_from(63.25).unwrap()),
                readback: Pwm::from(fan_control_core::DemandPercent::try_from(63.25).unwrap()),
                rpm_command: Pwm::from(fan_control_core::DemandPercent::try_from(58.0).unwrap()),
                rpm: 3210,
            },
            gpu: FanDiagnostic {
                command: Pwm::from(fan_control_core::DemandPercent::try_from(63.25).unwrap()),
                readback: Pwm::from(fan_control_core::DemandPercent::try_from(63.25).unwrap()),
                rpm_command: Pwm::from(fan_control_core::DemandPercent::try_from(58.0).unwrap()),
                rpm: 3090,
            },
        });
    });

    let event = &events[0];
    assert_eq!(field(event, "event_id"), "pt31553.control-cycle.v1");
    assert_eq!(field(event, "cpu_temperature_celsius"), "71.5");
    assert_eq!(field(event, "gpu_temperature_celsius"), "64.0");
    assert_eq!(field(event, "external_power"), "disconnected");
    assert_eq!(field(event, "profile"), "battery");
    assert_eq!(field(event, "demand_percent"), "63.25");
    assert_eq!(field(event, "cpu_pwm_endpoint"), "acer:cpu:pwm1");
    assert_eq!(field(event, "cpu_command_pwm"), "162");
    assert_eq!(field(event, "cpu_readback_pwm"), "162");
    assert_eq!(field(event, "cpu_rpm_command_pwm"), "148");
    assert_eq!(field(event, "cpu_rpm"), "3210");
    assert_eq!(field(event, "gpu_pwm_endpoint"), "acer:gpu:pwm2");
    assert_eq!(field(event, "gpu_command_pwm"), "162");
    assert_eq!(field(event, "gpu_readback_pwm"), "162");
    assert_eq!(field(event, "gpu_rpm_command_pwm"), "148");
    assert_eq!(field(event, "gpu_rpm"), "3090");
}

#[test]
fn restoration_attempts_expose_both_enable_endpoints_without_raw_failure_details() {
    let (_, events) = record_diagnostics(|| {
        emit_restoration_attempt(RestorationAttemptDiagnostic {
            attempt: 2,
            cpu: RestorationFanDiagnostic {
                write_succeeded: false,
                readback: RestorationReadback::Unreadable,
            },
            gpu: RestorationFanDiagnostic {
                write_succeeded: true,
                readback: RestorationReadback::FirmwareAuto,
            },
        });
    });

    let event = &events[0];
    assert_eq!(field(event, "event_id"), "pt31553.restoration-attempt.v1");
    assert_eq!(field(event, "attempt"), "2");
    assert_eq!(field(event, "cpu_enable_endpoint"), "acer:cpu:pwm1_enable");
    assert_eq!(field(event, "cpu_write_succeeded"), "false");
    assert_eq!(field(event, "cpu_mode_readback"), "unreadable");
    assert_eq!(field(event, "gpu_enable_endpoint"), "acer:gpu:pwm2_enable");
    assert_eq!(field(event, "gpu_write_succeeded"), "true");
    assert_eq!(field(event, "gpu_mode_readback"), "firmware-auto");
    assert!(
        event
            .keys()
            .all(|name| !name.contains("error") && !name.contains("detail"))
    );
}
