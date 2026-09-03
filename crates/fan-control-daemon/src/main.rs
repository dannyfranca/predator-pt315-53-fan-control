use std::{env, error::Error, fmt, path::Path};

use fan_control_core::{
    QUALIFICATION_RECORD_PATH, RuntimeFault, ShutdownController, StartupStatus,
    SystemOwnershipPlatform, SystemdNotifier, TerminationSignalHandlers,
};
use fan_control_daemon::{
    HWMON_ROOT, ProductionControlLoopError, QualifiedStartupInputs, StartupError,
    SystemSensorSourceDiscovery, discover_system_startup, qualified_startup,
    run_production_control_loop,
};

fn main() {
    fan_control_core::init_journald_diagnostics();
    if let Err(error) = run() {
        fan_control_core::emit_fault(error.runtime_fault(), None);
        eprintln!(
            "fan-control-daemon: supervision failed [{}]: {error}",
            error.diagnostic_id()
        );
        std::process::exit(1);
    }
}

fn run() -> Result<(), DaemonError> {
    match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [argument] if argument == "--status" => {
            report_unqualified_status();
            return Ok(());
        }
        [] => {}
        _ => {
            return Err(DaemonError::Startup(StartupError::Configuration(
                "usage: pt31553-fand [--status]".into(),
            )));
        }
    }

    let notifier = SystemdNotifier::from_environment().map_err(DaemonError::Supervision)?;
    // Do not let child identity probes inherit the manager's notify socket and emit unrelated
    // READY/WATCHDOG datagrams.
    unsafe {
        env::remove_var("NOTIFY_SOCKET");
        env::remove_var("WATCHDOG_USEC");
        env::remove_var("WATCHDOG_PID");
    }

    let mut shutdown = ShutdownController::new();
    let shutdown_request = shutdown.request_handle();
    let _signal_handlers = TerminationSignalHandlers::install(shutdown_request.clone())
        .map_err(DaemonError::Supervision)?;

    let mut discovery = discover_system_startup().map_err(DaemonError::Startup)?;
    let observations = [discovery.observation];
    let mut platform = SystemOwnershipPlatform::new();
    let startup = match qualified_startup(
        &mut platform,
        &discovery.device,
        &mut discovery.sources,
        QualifiedStartupInputs {
            editable_config: &discovery.editable_config,
            compatibility_declaration: &discovery.compatibility_declaration,
            protected_policy: &discovery.protected_policy,
            qualification_record_path: Path::new(QUALIFICATION_RECORD_PATH),
            compatibility_observations: &observations,
            hwmon_root: Path::new(HWMON_ROOT),
        },
        &shutdown_request,
    ) {
        Ok(startup) => startup,
        Err(StartupError::ShutdownRequested) => return Ok(()),
        Err(error) => return Err(DaemonError::Startup(error)),
    };

    let runtime_discovery = SystemSensorSourceDiscovery::for_admitted_sources(&discovery.sources);
    run_production_control_loop(
        startup,
        discovery.sources,
        runtime_discovery,
        &mut shutdown,
        notifier,
    )
    .map_err(DaemonError::ControlLoop)
}

fn report_unqualified_status() {
    println!(
        "fan-control-daemon: {}; Custom fan control is disabled",
        StartupStatus::UnqualifiedNotConfigured
    );
}

#[derive(Debug)]
enum DaemonError {
    Supervision(std::io::Error),
    Startup(StartupError),
    ControlLoop(ProductionControlLoopError<std::io::Error>),
}

impl DaemonError {
    const fn runtime_fault(&self) -> RuntimeFault {
        match self {
            Self::Supervision(_) => RuntimeFault::PlatformOperation,
            Self::Startup(error) => error.runtime_fault(),
            Self::ControlLoop(error) => error.runtime_fault(),
        }
    }

    const fn diagnostic_id(&self) -> &'static str {
        match self {
            Self::Supervision(_) => "platform-operation-failed",
            Self::Startup(error) => error.diagnostic_id(),
            Self::ControlLoop(error) => error.diagnostic_id(),
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supervision(error) => write!(formatter, "notification setup: {error}"),
            Self::Startup(error) => error.fmt(formatter),
            Self::ControlLoop(error) => error.fmt(formatter),
        }
    }
}

impl Error for DaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Supervision(error) => Some(error),
            Self::Startup(error) => Some(error),
            Self::ControlLoop(error) => Some(error),
        }
    }
}
