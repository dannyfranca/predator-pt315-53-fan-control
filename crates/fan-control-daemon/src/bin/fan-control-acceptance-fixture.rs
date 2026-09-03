use std::{env, io};

use fan_control_core::{
    ShutdownController, SystemdNotifier, TerminationSignalHandlers, init_journald_diagnostics,
};

fn main() {
    init_journald_diagnostics();
    if let Err(error) = run() {
        eprintln!("fan-control-acceptance-fixture: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), io::Error> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let [scenario] = arguments.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: fan-control-acceptance-fixture SCENARIO",
        ));
    };
    let notifier = SystemdNotifier::from_environment()
        .map_err(|error| io::Error::new(error.kind(), format!("notification setup: {error}")))?;
    // Keep identity-probe children from inheriting the fixture's notification transport.
    unsafe {
        env::remove_var("NOTIFY_SOCKET");
        env::remove_var("WATCHDOG_USEC");
        env::remove_var("WATCHDOG_PID");
    }
    let mut shutdown = ShutdownController::new();
    let _signal_handlers = TerminationSignalHandlers::install(shutdown.request_handle())?;
    fan_control_daemon::run_acceptance_fixture(scenario, notifier, &mut shutdown)
}
