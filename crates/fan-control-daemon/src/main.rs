use std::{env, error::Error, io};

use fan_control_core::{StartupStatus, SystemdNotifier};

fn main() {
    if run().is_err() {
        fan_control_core::init_journald_diagnostics();
        fan_control_core::emit_fault(fan_control_core::RuntimeFault::PlatformOperation, None);
        eprintln!("fan-control-daemon: supervision failed; inspect PT31553_FAULT_ID");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let notifier = SystemdNotifier::from_environment()?;
    // The daemon is still single-threaded here. Clearing the manager-owned variables prevents
    // systemctl probes from inheriting the notify socket and emitting unrelated datagrams.
    unsafe {
        env::remove_var("NOTIFY_SOCKET");
        env::remove_var("WATCHDOG_USEC");
        env::remove_var("WATCHDOG_PID");
    }
    report_unqualified_status();
    if notifier.is_enabled() {
        return Err(io::Error::other(
            "qualification and configuration are required before service readiness",
        )
        .into());
    }
    Ok(())
}

fn report_unqualified_status() {
    println!(
        "fan-control-daemon: {}; Custom fan control is disabled",
        StartupStatus::UnqualifiedNotConfigured
    );
}
