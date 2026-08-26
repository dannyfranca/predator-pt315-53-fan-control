use std::{
    io,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use fan_control_core::{
    SystemFirmwareAutoRecovery, SystemOwnershipPlatform, acquire_controller_ownership,
};

mod sleep_guard;

const HWMON_ROOT: &str = "/sys/class/hwmon";
const RECOVERY_RETRY: Duration = Duration::from_secs(2);
const SLEEP_RESUME_MARKER: &str = "/run/pt31553-fan-sleep-guard/resume-daemon";

fn main() {
    fan_control_core::init_journald_diagnostics();
    match std::env::args_os().nth(1).as_deref() {
        None => {
            println!("fan-control-restore: independent Firmware Auto recovery command");
        }
        Some(value) if value == std::ffi::OsStr::new("--status") => {
            println!("fan-control-restore: independent Firmware Auto recovery command");
        }
        Some(value) if value == std::ffi::OsStr::new("--restore") => {
            if restore_firmware_auto().is_err() {
                emit_generic_failure("independent recovery failed");
                std::process::exit(1);
            }
        }
        Some(value) if value == std::ffi::OsStr::new("--prepare-sleep") => {
            let mut manager = sleep_guard::SystemdDaemonManager::default();
            let marker = sleep_resume_marker();
            let prepared_marker = sleep_prepared_marker(&marker);
            if sleep_guard::prepare_sleep(
                &mut manager,
                &marker,
                &prepared_marker,
                restore_firmware_auto,
            )
            .is_err()
            {
                emit_generic_failure("sleep preparation failed");
                std::process::exit(1);
            }
        }
        Some(value) if value == std::ffi::OsStr::new("--resume-after-sleep") => {
            let mut manager = sleep_guard::SystemdDaemonManager::default();
            let marker = sleep_resume_marker();
            if sleep_guard::resume_after_sleep(&mut manager, &marker).is_err() {
                emit_generic_failure("resume failed");
                std::process::exit(1);
            }
        }
        Some(value) if value == std::ffi::OsStr::new("--restore-after-failed-sleep-guard") => {
            let marker = sleep_resume_marker();
            if sleep_guard::restore_after_failed_guard(
                &sleep_prepared_marker(&marker),
                restore_firmware_auto,
            )
            .is_err()
            {
                emit_generic_failure("cancelled sleep recovery failed");
                std::process::exit(1);
            }
        }
        _ => {
            fan_control_core::emit_fault(
                fan_control_core::RuntimeFault::ConfigurationRejected,
                None,
            );
            eprintln!(
                "usage: fan-control-restore [--status|--restore|--prepare-sleep|--resume-after-sleep|--restore-after-failed-sleep-guard]"
            );
            std::process::exit(2);
        }
    }
}

fn restore_firmware_auto() -> Result<(), io::Error> {
    let mut platform = SystemOwnershipPlatform::new();
    let mut ownership = loop {
        match acquire_controller_ownership(&mut platform) {
            Ok(ownership) => break ownership,
            Err(_) => {
                eprintln!(
                    "fan-control-restore: waiting for recovery ownership; inspect PT31553_FAULT_ID"
                );
                thread::sleep(RECOVERY_RETRY);
            }
        }
    };

    let mut runtime_state = fan_control_core::RuntimeState::Restoring;
    loop {
        if runtime_state == fan_control_core::RuntimeState::EmergencyContainment {
            fan_control_core::emit_state_transition(
                runtime_state,
                fan_control_core::RuntimeState::Restoring,
                fan_control_core::RuntimeTransition::RearmRequested,
            );
            runtime_state = fan_control_core::RuntimeState::Restoring;
        }
        match ownership.discover_acer_hwmon(Path::new(HWMON_ROOT)) {
            Ok(device) => match ownership.recover_system_firmware_auto_cycle(&device) {
                Ok(SystemFirmwareAutoRecovery::Restored) => {
                    fan_control_core::emit_state_transition(
                        runtime_state,
                        fan_control_core::RuntimeState::FirmwareAuto,
                        fan_control_core::RuntimeTransition::RestorationConfirmed,
                    );
                    break;
                }
                Ok(SystemFirmwareAutoRecovery::Contained) => {
                    fan_control_core::emit_state_transition(
                        runtime_state,
                        fan_control_core::RuntimeState::EmergencyContainment,
                        fan_control_core::RuntimeTransition::ContainmentActivated,
                    );
                    eprintln!(
                        "fan-control-restore: emergency containment active; retrying Firmware Auto"
                    );
                    runtime_state = fan_control_core::RuntimeState::EmergencyContainment;
                }
                Err(_) => {
                    eprintln!(
                        "fan-control-restore: recovery cycle failed; inspect PT31553_FAULT_ID"
                    );
                }
            },
            Err(_) => {
                fan_control_core::emit_fault(fan_control_core::RuntimeFault::DeviceChanged, None);
                eprintln!(
                    "fan-control-restore: cannot discover recovery endpoints; inspect PT31553_FAULT_ID"
                );
            }
        }
        thread::sleep(RECOVERY_RETRY);
    }

    ownership
        .release()
        .map_err(|error| io::Error::other(format!("cannot release recovery ownership: {error}")))
}

fn sleep_resume_marker() -> PathBuf {
    PathBuf::from(SLEEP_RESUME_MARKER)
}

fn sleep_prepared_marker(resume_marker: &Path) -> PathBuf {
    resume_marker.with_file_name("resume-daemon-prepared")
}

fn emit_generic_failure(message: &str) {
    fan_control_core::emit_fault(fan_control_core::RuntimeFault::PlatformOperation, None);
    eprintln!("fan-control-restore: {message}; inspect PT31553_FAULT_ID");
}
