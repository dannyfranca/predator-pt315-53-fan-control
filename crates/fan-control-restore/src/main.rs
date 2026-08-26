use std::{io, path::Path, thread, time::Duration};

use fan_control_core::{
    SystemFirmwareAutoRecovery, SystemOwnershipPlatform, acquire_controller_ownership,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";
const RECOVERY_RETRY: Duration = Duration::from_secs(2);

fn main() {
    match std::env::args_os().nth(1).as_deref() {
        None => {
            println!("fan-control-restore: independent Firmware Auto recovery command");
            return;
        }
        Some(value) if value == std::ffi::OsStr::new("--status") => {
            println!("fan-control-restore: independent Firmware Auto recovery command");
            return;
        }
        Some(value) if value == std::ffi::OsStr::new("--restore") => {}
        _ => {
            eprintln!("usage: fan-control-restore [--status|--restore]");
            std::process::exit(2);
        }
    }

    if let Err(error) = restore_firmware_auto() {
        eprintln!("fan-control-restore: {error}");
        std::process::exit(1);
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
