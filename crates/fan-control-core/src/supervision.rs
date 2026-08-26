use std::{
    env,
    error::Error,
    ffi::OsStr,
    fmt, io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
    path::Path,
    process,
};

use crate::{
    BoundedIdentityBoundFileAccess, Clock, ControllerOwnership, RuntimeLockAccess,
    SensorControlStep, SensorSourceDiscovery, TransientSensorControl, TransientSensorControlError,
};

/// A service-manager notification emitted synchronously by the control loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceNotification {
    Ready,
    Watchdog,
}

/// Narrow notification boundary used by [`ControlLoopHeartbeat`].
pub trait ServiceNotifier {
    type Error;

    fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error>;
}

/// Opaque service-manager state advanced only by [`run_supervised_control_iteration`].
#[derive(Debug)]
pub struct ControlLoopHeartbeat<N> {
    notifier: N,
    ready: bool,
}

impl<N> ControlLoopHeartbeat<N>
where
    N: ServiceNotifier,
{
    pub fn new(notifier: N) -> Self {
        Self {
            notifier,
            ready: false,
        }
    }

    fn completed_control_work(&mut self, establishes_readiness: bool) -> Result<(), N::Error> {
        if !self.ready && !establishes_readiness {
            return Ok(());
        }
        if !self.ready {
            self.notifier.notify(ServiceNotification::Ready)?;
            self.ready = true;
        }
        self.notifier.notify(ServiceNotification::Watchdog)
    }

    #[cfg(test)]
    const fn is_ready(&self) -> bool {
        self.ready
    }

    #[cfg(test)]
    fn into_notifier(self) -> N {
        self.notifier
    }
}

/// Runs one real sensor/control iteration and notifies the service manager only after it returns.
///
/// Keeping the notification call in this function makes it impossible for the daemon to advance
/// readiness or the watchdog from a timer, helper thread, or Firmware Auto-only placeholder loop.
/// In Custom state, [`TransientSensorControl::step`] samples every required input, calculates fan
/// demand, performs bounded PWM writes and readbacks, and validates tachometer response before
/// readiness is emitted. Once ready, successful bounded recovery work also advances the watchdog
/// so normal recovery cannot be mistaken for a blocked loop.
pub fn run_supervised_control_iteration<D, P, N>(
    control: &mut TransientSensorControl<D>,
    ownership: &mut ControllerOwnership<'_, P>,
    heartbeat: &mut ControlLoopHeartbeat<N>,
) -> Result<SensorControlStep, SupervisedControlIterationError<N::Error>>
where
    D: SensorSourceDiscovery,
    P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
    N: ServiceNotifier,
{
    let step = control
        .step(ownership)
        .map_err(SupervisedControlIterationError::Control)?;
    heartbeat
        .completed_control_work(matches!(step, SensorControlStep::Completed(_)))
        .map_err(SupervisedControlIterationError::Notification)?;
    Ok(step)
}

#[derive(Debug)]
pub enum SupervisedControlIterationError<N> {
    Control(TransientSensorControlError),
    Notification(N),
}

impl<N> fmt::Display for SupervisedControlIterationError<N>
where
    N: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(error) => write!(formatter, "control iteration failed: {error}"),
            Self::Notification(error) => write!(formatter, "service notification failed: {error}"),
        }
    }
}

impl<N> Error for SupervisedControlIterationError<N>
where
    N: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Control(error) => Some(error),
            Self::Notification(error) => Some(error),
        }
    }
}

/// Linux `sd_notify` protocol transport without a libsystemd runtime dependency.
///
/// With no `NOTIFY_SOCKET`, notifications are safe no-ops so direct CLI execution still works.
/// When `WATCHDOG_USEC` is absent, zero, malformed, or addressed to another PID, readiness is sent
/// but watchdog messages are suppressed.
#[derive(Debug)]
pub struct SystemdNotifier {
    transport: Option<SystemdNotificationTransport>,
}

#[derive(Debug)]
struct SystemdNotificationTransport {
    socket: UnixDatagram,
    address: SocketAddr,
    watchdog_enabled: bool,
}

impl SystemdNotifier {
    pub fn from_environment() -> io::Result<Self> {
        let Some(notify_socket) = env::var_os("NOTIFY_SOCKET") else {
            return Ok(Self { transport: None });
        };
        let watchdog_enabled = watchdog_enabled_for(
            env::var_os("WATCHDOG_USEC").as_deref(),
            env::var_os("WATCHDOG_PID").as_deref(),
            process::id(),
        );
        Self::connect(&notify_socket, watchdog_enabled)
    }

    /// Connects to an explicit notification address.
    ///
    /// This is public so the daemon boundary can be tested against filesystem and Linux abstract
    /// Unix datagram sockets without mutating process-global environment variables.
    pub fn connect(notify_socket: &OsStr, watchdog_enabled: bool) -> io::Result<Self> {
        let address = parse_notify_socket(notify_socket)?;
        Ok(Self {
            transport: Some(SystemdNotificationTransport {
                socket: UnixDatagram::unbound()?,
                address,
                watchdog_enabled,
            }),
        })
    }

    pub const fn is_enabled(&self) -> bool {
        self.transport.is_some()
    }
}

impl ServiceNotifier for SystemdNotifier {
    type Error = io::Error;

    fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error> {
        let Some(transport) = &self.transport else {
            return Ok(());
        };
        let payload = match notification {
            ServiceNotification::Ready => b"READY=1".as_slice(),
            ServiceNotification::Watchdog if transport.watchdog_enabled => b"WATCHDOG=1".as_slice(),
            ServiceNotification::Watchdog => return Ok(()),
        };
        let sent = transport.socket.send_to_addr(payload, &transport.address)?;
        if sent != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "systemd notification datagram was truncated",
            ));
        }
        Ok(())
    }
}

fn parse_notify_socket(value: &OsStr) -> io::Result<SocketAddr> {
    let bytes = value.as_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET abstract name is empty",
            ));
        }
        return SocketAddr::from_abstract_name(name);
    }

    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET path is not absolute",
        ));
    }
    SocketAddr::from_pathname(path)
}

fn watchdog_enabled_for(
    watchdog_usec: Option<&OsStr>,
    watchdog_pid: Option<&OsStr>,
    process_id: u32,
) -> bool {
    let timeout_is_positive = watchdog_usec
        .and_then(OsStr::to_str)
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0);
    let addressed_to_process = watchdog_pid.is_none_or(|value| {
        value.to_str().and_then(|value| value.parse::<u32>().ok()) == Some(process_id)
    });
    timeout_is_positive && addressed_to_process
}

#[cfg(test)]
mod tests {
    use super::{ControlLoopHeartbeat, ServiceNotification, ServiceNotifier, watchdog_enabled_for};
    use std::{collections::VecDeque, convert::Infallible, ffi::OsStr};

    #[derive(Debug, Default)]
    struct RecordingNotifier {
        notifications: Vec<ServiceNotification>,
    }

    impl ServiceNotifier for RecordingNotifier {
        type Error = Infallible;

        fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error> {
            self.notifications.push(notification);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ScriptedNotifier {
        results: VecDeque<Result<(), &'static str>>,
        notifications: Vec<ServiceNotification>,
    }

    impl ServiceNotifier for ScriptedNotifier {
        type Error = &'static str;

        fn notify(&mut self, notification: ServiceNotification) -> Result<(), Self::Error> {
            self.notifications.push(notification);
            self.results.pop_front().unwrap_or(Ok(()))
        }
    }

    #[test]
    fn readiness_and_watchdog_share_the_completed_iteration_boundary() {
        let mut heartbeat = ControlLoopHeartbeat::new(RecordingNotifier::default());

        heartbeat.completed_control_work(true).unwrap();
        heartbeat.completed_control_work(true).unwrap();

        assert!(heartbeat.is_ready());
        assert_eq!(
            heartbeat.into_notifier().notifications,
            [
                ServiceNotification::Ready,
                ServiceNotification::Watchdog,
                ServiceNotification::Watchdog,
            ]
        );
    }

    #[test]
    fn readiness_failure_does_not_mark_the_loop_ready() {
        let notifier = ScriptedNotifier {
            results: VecDeque::from([Err("ready failed")]),
            notifications: Vec::new(),
        };
        let mut heartbeat = ControlLoopHeartbeat::new(notifier);

        assert_eq!(heartbeat.completed_control_work(true), Err("ready failed"));
        assert!(!heartbeat.is_ready());
        assert_eq!(
            heartbeat.into_notifier().notifications,
            [ServiceNotification::Ready]
        );
    }

    #[test]
    fn watchdog_failure_does_not_repeat_readiness() {
        let notifier = ScriptedNotifier {
            results: VecDeque::from([Ok(()), Err("watchdog failed"), Err("still failed")]),
            notifications: Vec::new(),
        };
        let mut heartbeat = ControlLoopHeartbeat::new(notifier);

        assert_eq!(
            heartbeat.completed_control_work(true),
            Err("watchdog failed")
        );
        assert!(heartbeat.is_ready());
        assert_eq!(heartbeat.completed_control_work(false), Err("still failed"));
        assert_eq!(
            heartbeat.into_notifier().notifications,
            [
                ServiceNotification::Ready,
                ServiceNotification::Watchdog,
                ServiceNotification::Watchdog,
            ]
        );
    }

    #[test]
    fn recovery_work_advances_watchdog_only_after_readiness() {
        let mut heartbeat = ControlLoopHeartbeat::new(RecordingNotifier::default());

        heartbeat.completed_control_work(false).unwrap();
        assert!(!heartbeat.is_ready());
        assert!(heartbeat.into_notifier().notifications.is_empty());

        let mut heartbeat = ControlLoopHeartbeat::new(RecordingNotifier::default());
        heartbeat.completed_control_work(true).unwrap();
        heartbeat.completed_control_work(false).unwrap();
        assert_eq!(
            heartbeat.into_notifier().notifications,
            [
                ServiceNotification::Ready,
                ServiceNotification::Watchdog,
                ServiceNotification::Watchdog,
            ]
        );
    }

    #[test]
    fn watchdog_requires_a_positive_timeout_for_this_process() {
        let pid = 42;
        assert!(watchdog_enabled_for(Some(OsStr::new("6000000")), None, pid));
        assert!(watchdog_enabled_for(
            Some(OsStr::new("6000000")),
            Some(OsStr::new("42")),
            pid,
        ));

        for timeout in [None, Some(OsStr::new("0")), Some(OsStr::new("bad"))] {
            assert!(!watchdog_enabled_for(timeout, None, pid));
        }
        assert!(!watchdog_enabled_for(
            Some(OsStr::new("6000000")),
            Some(OsStr::new("41")),
            pid,
        ));
        assert!(!watchdog_enabled_for(
            Some(OsStr::new("6000000")),
            Some(OsStr::new("bad")),
            pid,
        ));
    }
}
