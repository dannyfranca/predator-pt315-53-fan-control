use std::{
    error::Error,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use signal_hook::{
    SigId,
    consts::{SIGABRT, SIGINT, SIGTERM},
};

use crate::{
    AcerHwmonDevice, BoundedIdentityBoundFileAccess, Clock, ControllerOwnership,
    EmergencyContainmentReport, FirmwareAutoRestorationError, RuntimeLockAccess,
    ownership::FirmwareAutoSafingOutcome,
};

/// A cloneable, async-signal-safe latch that permanently cancels normal control.
#[derive(Debug, Clone)]
pub struct ShutdownRequest {
    state: Arc<AtomicU8>,
}

const SHUTDOWN_OPEN: u8 = 0;
const SHUTDOWN_REQUESTED: u8 = 1;
const PUBLICATION_COMMITTED: u8 = 2;

impl Default for ShutdownRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownRequest {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(SHUTDOWN_OPEN)),
        }
    }

    pub fn request(&self) {
        self.state.fetch_or(SHUTDOWN_REQUESTED, Ordering::AcqRel);
    }

    pub fn is_requested(&self) -> bool {
        self.state.load(Ordering::Acquire) & SHUTDOWN_REQUESTED != 0
    }

    /// Establishes the one-way authorization publication boundary.
    ///
    /// This and [`Self::request`] race on one atomic state. A request observed first prevents the
    /// commit. Once committed, a later signal remains permanently observable without retroactively
    /// withdrawing the authorization.
    pub fn try_commit_publication(&self) -> bool {
        self.state
            .compare_exchange(
                SHUTDOWN_OPEN,
                PUBLICATION_COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// Owns one graceful-cleanup attempt while exposing a permanent cancellation latch.
#[derive(Debug)]
pub struct ShutdownController {
    request: ShutdownRequest,
    cleanup: Option<Result<(), GracefulShutdownFailure>>,
}

impl Default for ShutdownController {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownController {
    pub fn new() -> Self {
        Self {
            request: ShutdownRequest::new(),
            cleanup: None,
        }
    }

    pub fn request_handle(&self) -> ShutdownRequest {
        self.request.clone()
    }

    pub fn request(&self) {
        self.request.request();
    }

    pub fn is_requested(&self) -> bool {
        self.request.is_requested()
    }

    /// Cancels all normal control, then restores or contains both fans exactly once.
    ///
    /// The ownership guard separately refuses release until both fans are confirmed in Firmware
    /// Auto. A failed restoration remains a failed cleanup even if its containment attempt later
    /// observes both fans in Auto.
    pub fn cleanup<P>(
        &mut self,
        ownership: &mut ControllerOwnership<'_, P>,
        device: &AcerHwmonDevice,
    ) -> Result<(), GracefulShutdownFailure>
    where
        P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess + ?Sized,
    {
        self.request();
        if let Some(result) = &self.cleanup {
            return result.clone();
        }

        let result = match ownership.restore_or_contain_firmware_auto(device) {
            FirmwareAutoSafingOutcome::Restored => Ok(()),
            FirmwareAutoSafingOutcome::Contained {
                restoration,
                containment,
            } => Err(GracefulShutdownFailure::Contained {
                restoration: Box::new(restoration),
                containment: Box::new(containment),
            }),
            FirmwareAutoSafingOutcome::Critical {
                restoration,
                containment,
            } => Err(GracefulShutdownFailure::Critical {
                restoration: Box::new(restoration),
                containment: Box::new(containment),
            }),
        };
        self.cleanup = Some(result.clone());
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulShutdownFailure {
    Contained {
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
    Critical {
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
}

impl fmt::Display for GracefulShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contained {
                restoration,
                containment,
            } => write!(
                formatter,
                "graceful shutdown failed to restore Firmware Auto before containment: {restoration}; containment: {containment:?}"
            ),
            Self::Critical {
                restoration,
                containment,
            } => write!(
                formatter,
                "graceful shutdown left Firmware Auto unconfirmed after containment: {restoration}; containment: {containment:?}"
            ),
        }
    }
}

impl Error for GracefulShutdownFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contained { restoration, .. } | Self::Critical { restoration, .. } => {
                Some(restoration.as_ref())
            }
        }
    }
}

/// Process-lifetime SIGTERM/SIGINT/SIGABRT registrations that only set the shutdown latch.
///
/// Dropping this value intentionally leaves the actions registered. `signal-hook` cannot safely
/// restore a replaced default disposition, so unregistering the last action could make a process
/// silently ignore a later termination signal. A partial installation likewise retains the first
/// successful action while returning the second registration error.
#[derive(Debug)]
pub struct TerminationSignalHandlers {
    _registrations: [SigId; 3],
}

impl TerminationSignalHandlers {
    pub fn install(request: ShutdownRequest) -> io::Result<Self> {
        let term_request = request.clone();
        let interrupt_request = request.clone();
        // SAFETY: each handler performs only one lock-free atomic fetch-or through
        // `ShutdownRequest::request`; it neither allocates nor invokes non-signal-safe I/O.
        let term =
            unsafe { signal_hook::low_level::register(SIGTERM, move || term_request.request())? };
        // SAFETY: same atomic-only handler contract as above.
        let interrupt = unsafe {
            signal_hook::low_level::register(SIGINT, move || interrupt_request.request())?
        };
        // SAFETY: same atomic-only handler contract as above.
        let watchdog =
            unsafe { signal_hook::low_level::register(SIGABRT, move || request.request())? };
        Ok(Self {
            _registrations: [term, interrupt, watchdog],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ShutdownRequest;

    #[test]
    fn shutdown_and_publication_have_one_atomic_winner() {
        let shutdown = ShutdownRequest::new();
        shutdown.request();
        assert!(shutdown.is_requested());
        assert!(!shutdown.try_commit_publication());

        let publication = ShutdownRequest::new();
        assert!(publication.try_commit_publication());
        publication.request();
        assert!(publication.is_requested());
        assert!(!publication.try_commit_publication());
    }
}
