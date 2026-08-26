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
    match std::env::args_os().nth(1).as_deref() {
        None => {
            println!("fan-control-restore: independent Firmware Auto recovery command");
        }
        Some(value) if value == std::ffi::OsStr::new("--status") => {
            println!("fan-control-restore: independent Firmware Auto recovery command");
        }
        Some(value) if value == std::ffi::OsStr::new("--restore") => {
            if let Err(error) = restore_firmware_auto() {
                eprintln!("fan-control-restore: {error}");
                std::process::exit(1);
            }
        }
        Some(value) if value == std::ffi::OsStr::new("--prepare-sleep") => {
            let mut manager = sleep_guard::SystemdDaemonManager::default();
            let marker = sleep_resume_marker();
            let prepared_marker = sleep_prepared_marker(&marker);
            if let Err(error) = sleep_guard::prepare_sleep(
                &mut manager,
                &marker,
                &prepared_marker,
                restore_firmware_auto,
            ) {
                eprintln!("fan-control-restore: sleep preparation failed: {error}");
                std::process::exit(1);
            }
        }
        Some(value) if value == std::ffi::OsStr::new("--resume-after-sleep") => {
            let mut manager = sleep_guard::SystemdDaemonManager::default();
            let marker = sleep_resume_marker();
            if let Err(error) = sleep_guard::resume_after_sleep(&mut manager, &marker) {
                eprintln!("fan-control-restore: resume failed: {error}");
                std::process::exit(1);
            }
        }
        Some(value) if value == std::ffi::OsStr::new("--restore-after-failed-sleep-guard") => {
            let marker = sleep_resume_marker();
            if let Err(error) = sleep_guard::restore_after_failed_guard(
                &sleep_prepared_marker(&marker),
                restore_firmware_auto,
            ) {
                eprintln!("fan-control-restore: cancelled sleep recovery failed: {error}");
                std::process::exit(1);
            }
        }
        _ => {
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
            Err(error) => {
                eprintln!("fan-control-restore: waiting for recovery ownership: {error}");
                thread::sleep(RECOVERY_RETRY);
            }
        }
    };

    loop {
        match ownership.discover_acer_hwmon(Path::new(HWMON_ROOT)) {
            Ok(device) => match ownership.recover_system_firmware_auto_cycle(&device) {
                Ok(SystemFirmwareAutoRecovery::Restored) => break,
                Ok(SystemFirmwareAutoRecovery::Contained) => eprintln!(
                    "fan-control-restore: emergency containment active; retrying Firmware Auto"
                ),
                Err(error) => {
                    eprintln!("fan-control-restore: recovery cycle failed; rediscovering: {error}")
                }
            },
            Err(error) => {
                eprintln!("fan-control-restore: cannot discover recovery endpoints: {error}")
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
