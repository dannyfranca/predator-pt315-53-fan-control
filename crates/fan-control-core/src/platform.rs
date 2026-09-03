use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    ffi::CString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformErrorKind {
    NotFound,
    PermissionDenied,
    TimedOut,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformError {
    kind: PlatformErrorKind,
    message: String,
}

impl PlatformError {
    pub fn new(kind: PlatformErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub const fn kind(&self) -> PlatformErrorKind {
        self.kind
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for PlatformError {}

pub trait FileAccess {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError>;

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError>;

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError>;

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError>;
}

/// Reads an authorization artifact only when the complete path is protected by UID 0.
pub trait RootOwnedQualificationRecordAccess {
    fn read_root_owned_qualification_record(
        &mut self,
        path: &Path,
    ) -> Result<String, PlatformError>;

    fn verify_root_owned_supervised_endurance_evidence(
        &mut self,
        path: &Path,
        expected_sha256: &str,
        expected_envelope: &crate::QualificationEnvelopeIdentityV1,
    ) -> Result<(), PlatformError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedFileRequirement {
    Regular,
    Executable,
}

pub fn validate_root_owned_protected_file(
    path: &Path,
    requirement: ProtectedFileRequirement,
) -> Result<(), PlatformError> {
    validate_owned_protected_file(path, requirement, 0)
}

fn validate_owned_protected_file(
    path: &Path,
    requirement: ProtectedFileRequirement,
    required_owner: u32,
) -> Result<(), PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::new(
            PlatformErrorKind::PermissionDenied,
            "protected file path must be absolute",
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            io_platform_error(&format!("cannot inspect {}", current.display()), error)
        })?;
        let has_extended_acl = path_has_extended_acl(&current).map_err(|error| {
            io_platform_error(
                &format!("cannot inspect ACL for {}", current.display()),
                error,
            )
        })?;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != required_owner)
            || metadata.permissions().mode() & 0o022 != 0
            || has_extended_acl
        {
            return Err(PlatformError::new(
                PlatformErrorKind::PermissionDenied,
                format!(
                    "protected file path is not root-owned and protected: {}",
                    current.display()
                ),
            ));
        }
    }
    let metadata = fs::metadata(path)
        .map_err(|error| io_platform_error(&format!("cannot inspect {}", path.display()), error))?;
    if !metadata.is_file()
        || metadata.uid() != required_owner
        || metadata.nlink() != 1
        || (requirement == ProtectedFileRequirement::Executable
            && metadata.permissions().mode() & 0o111 == 0)
    {
        return Err(PlatformError::new(
            PlatformErrorKind::PermissionDenied,
            "protected path is not a suitable regular file",
        ));
    }
    Ok(())
}

pub fn path_has_extended_acl(path: &Path) -> io::Result<bool> {
    let path_name = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains an interior NUL: {}", path.display()),
        )
    })?;
    for acl_name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        // SAFETY: both C strings are NUL-terminated and the null buffer with length zero only
        // queries the attribute size. lgetxattr deliberately does not follow a final symlink.
        let result = unsafe {
            libc::lgetxattr(
                path_name.as_ptr(),
                acl_name.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if result >= 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(code) if code == libc::ENODATA || code == libc::ENOTSUP)
        {
            return Err(error);
        }
    }
    Ok(false)
}

fn verify_supervised_endurance_evidence_source(
    source: &str,
    expected_sha256: &str,
    expected_envelope: &crate::QualificationEnvelopeIdentityV1,
) -> Result<(), PlatformError> {
    use sha2::{Digest, Sha256};

    let digest = format!("{:x}", Sha256::digest(source.as_bytes()));
    let record = crate::parse_evidence_v2(source).map_err(|error| {
        PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("invalid supervised endurance evidence: {error}"),
        )
    })?;
    if digest != expected_sha256
        || &record.qualification_envelope != expected_envelope
        || record.stage != "supervised-endurance"
        || record.outcome.status != crate::RunOutcomeStatus::Passed
        || !crate::endurance::supervised_endurance_is_complete(&record)
    {
        return Err(PlatformError::new(
            PlatformErrorKind::PermissionDenied,
            "supervised endurance evidence does not match its authorization",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    pub const fn from_raw(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    pub const fn device(self) -> u64 {
        self.device
    }

    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// File access that binds operations to one stable backing directory identity.
pub trait IdentityBoundFileAccess: FileAccess {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError>;

    /// Reads one direct child while atomically binding the read to the expected directory identity.
    ///
    /// Implementations must not return contents from a different backing directory that is
    /// temporarily or permanently rebound at `directory`.
    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError>;

    /// Reads one direct child while atomically binding both directory and child identities.
    fn read_child_bound(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
    ) -> Result<String, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        if self.identity(&path)? != expected_child {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("endpoint identity changed: {}", path.display()),
            ));
        }
        let value = self.read_bound(directory, expected_directory, child)?;
        if self.identity(&path)? != expected_child {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("endpoint identity changed: {}", path.display()),
            ));
        }
        Ok(value)
    }

    /// Lists direct children while atomically binding the listing to the expected identity.
    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError>;
}

/// Read-only filesystem operations for stable sensor discovery and sampling.
pub trait IdentityBoundReadAccess {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError>;

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError>;

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError>;

    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError>;

    fn permissions_child_bound(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
    ) -> Result<FilePermissions, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        if self.identity(directory)? != expected_directory
            || self.identity(&path)? != expected_child
        {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("endpoint identity changed: {}", path.display()),
            ));
        }
        let permissions = self.permissions(&path)?;
        if self.identity(directory)? != expected_directory
            || self.identity(&path)? != expected_child
        {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("endpoint identity changed: {}", path.display()),
            ));
        }
        Ok(permissions)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError>;

    fn read_child_bound(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
    ) -> Result<String, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        if self.identity(&path)? != expected_child {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("endpoint identity changed: {}", path.display()),
            ));
        }
        let value = self.read_bound(directory, expected_directory, child)?;
        if self.identity(&path)? != expected_child {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("endpoint identity changed: {}", path.display()),
            ));
        }
        Ok(value)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError>;
}

impl<T> IdentityBoundReadAccess for T
where
    T: IdentityBoundFileAccess + ?Sized,
{
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        FileAccess::read(self, path)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        FileAccess::list(self, directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        FileAccess::permissions(self, path)
    }

    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        IdentityBoundFileAccess::identity(self, path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        IdentityBoundFileAccess::read_bound(self, directory, expected, child)
    }

    fn read_child_bound(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
    ) -> Result<String, PlatformError> {
        IdentityBoundFileAccess::read_child_bound(
            self,
            directory,
            expected_directory,
            child,
            expected_child,
        )
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        IdentityBoundFileAccess::list_bound(self, directory, expected)
    }
}

/// File access that rejects operations which complete at or after an absolute monotonic deadline.
///
/// A production implementation must use local, nonblocking kernel interfaces. The deadline is an
/// admission and completion check, not a claim that a userspace task can preempt an in-progress
/// kernel system call. Callers must treat `TimedOut` as an indeterminate write and immediately run
/// their fail-safe recovery path.
pub trait BoundedFileAccess {
    fn read_before(&mut self, path: &Path, deadline: Duration) -> Result<String, PlatformError>;

    fn list_before(
        &mut self,
        directory: &Path,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError>;

    fn write_before(
        &mut self,
        path: &Path,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError>;
}

/// Deadline-bounded I/O tied to one discovered directory and endpoint generation.
pub trait BoundedIdentityBoundFileAccess: BoundedFileAccess + IdentityBoundFileAccess {
    fn identity_before(
        &mut self,
        path: &Path,
        deadline: Duration,
    ) -> Result<FileIdentity, PlatformError>;

    fn read_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError>;

    fn list_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError>;

    fn permissions_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<FilePermissions, PlatformError>;

    #[allow(clippy::too_many_arguments)]
    /// Validates the directory and child identities, checks every guard, and writes while the
    /// caller holds exclusive controller ownership.
    ///
    /// Atomicity is relative to controller participants honoring that ownership lock: raw sysfs
    /// writers outside the controller trust boundary cannot be excluded by a userspace adapter.
    /// Implementations must pin all checks and the target write to the same backing directory and
    /// endpoint generation, perform no voluntary yield between the final guard check and write,
    /// and check `deadline` immediately before and after the write becomes visible.
    fn write_bound_if_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        expected_children: &[(&str, FileIdentity)],
        guards: &[(&str, &str)],
        target_child: &str,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError>;
}

fn direct_bound_child(directory: &Path, child: &str) -> Result<PathBuf, PlatformError> {
    let child_path = Path::new(child);
    let mut components = child_path.components();
    let direct_child = matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if !direct_child {
        return Err(PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("bound operation is not a direct child: {child}"),
        ));
    }
    Ok(directory.join(child))
}

#[derive(Debug, Clone, Copy)]
pub struct FilePermissions {
    mode: u32,
    extended_acl: bool,
    owner_uid: u32,
}

impl PartialEq for FilePermissions {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode && self.extended_acl == other.extended_acl
    }
}

impl Eq for FilePermissions {}

impl FilePermissions {
    pub const NONE: Self = Self::from_mode(0o000);
    pub const READ_ONLY: Self = Self::from_mode(0o444);
    pub const WRITE_ONLY: Self = Self::from_mode(0o200);
    pub const READ_WRITE: Self = Self::from_mode(0o644);

    pub const fn from_mode(mode: u32) -> Self {
        Self {
            mode: mode & 0o7777,
            extended_acl: false,
            owner_uid: 0,
        }
    }

    pub const fn with_extended_acl(mut self) -> Self {
        self.extended_acl = true;
        self
    }

    pub const fn with_owner_uid(mut self, owner_uid: u32) -> Self {
        self.owner_uid = owner_uid;
        self
    }

    pub const fn mode(self) -> u32 {
        self.mode
    }

    pub const fn readable(self) -> bool {
        self.mode & 0o444 != 0
    }

    pub const fn writable(self) -> bool {
        self.mode & 0o222 != 0
    }

    pub const fn has_extended_acl(self) -> bool {
        self.extended_acl
    }

    pub const fn owner_uid(self) -> u32 {
        self.owner_uid
    }
}

pub trait ServiceAccess {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError>;
}

/// Atomic non-blocking access to a lock file owned by UID 0.
///
/// Implementations must reject lock files not owned by root and keep the lock held until either
/// `release_runtime_lock` succeeds or the owning process exits.
pub trait RuntimeLockAccess {
    type RuntimeLock;

    fn try_acquire_root_runtime_lock(
        &mut self,
        path: &Path,
    ) -> Result<Self::RuntimeLock, RuntimeLockError>;

    fn release_runtime_lock(
        &mut self,
        lock: Self::RuntimeLock,
    ) -> Result<(), (Self::RuntimeLock, PlatformError)>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeLockError {
    AlreadyHeld,
    NotRootOwned,
    Platform(PlatformError),
}

/// Linux ownership boundary used by the daemon and recovery executables.
#[derive(Debug)]
pub struct SystemOwnershipPlatform {
    required_lock_owner: u32,
    started_at: Instant,
    #[cfg(test)]
    fail_firmware_auto_writes: bool,
}

impl Default for SystemOwnershipPlatform {
    fn default() -> Self {
        Self {
            required_lock_owner: 0,
            started_at: Instant::now(),
            #[cfg(test)]
            fail_firmware_auto_writes: false,
        }
    }
}

impl SystemOwnershipPlatform {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_required_lock_owner(required_lock_owner: u32) -> Self {
        Self {
            required_lock_owner,
            ..Self::default()
        }
    }

    #[cfg(test)]
    fn with_failed_firmware_auto_writes() -> Self {
        Self {
            fail_firmware_auto_writes: true,
            ..Self::default()
        }
    }
}

impl SystemOwnershipPlatform {
    fn metadata(path: &Path) -> Result<fs::Metadata, PlatformError> {
        fs::metadata(path).map_err(|error| {
            io_platform_error(&format!("cannot inspect {}", path.display()), error)
        })
    }

    fn read_file(path: &Path) -> Result<String, PlatformError> {
        fs::read_to_string(path)
            .map_err(|error| io_platform_error(&format!("cannot read {}", path.display()), error))
    }

    fn write_file(path: &Path, contents: &str) -> Result<(), PlatformError> {
        let mut file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                io_platform_error(
                    &format!("cannot open {} for writing", path.display()),
                    error,
                )
            })?;
        file.write_all(contents.as_bytes())
            .map_err(|error| io_platform_error(&format!("cannot write {}", path.display()), error))
    }

    fn list_directory(directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        let entries = fs::read_dir(directory).map_err(|error| {
            io_platform_error(&format!("cannot list {}", directory.display()), error)
        })?;
        entries
            .map(|entry| {
                entry.map(|entry| entry.path()).map_err(|error| {
                    io_platform_error(
                        &format!("cannot read directory entry in {}", directory.display()),
                        error,
                    )
                })
            })
            .collect()
    }

    fn file_identity(path: &Path) -> Result<FileIdentity, PlatformError> {
        let metadata = Self::metadata(path)?;
        Ok(FileIdentity::from_raw(metadata.dev(), metadata.ino()))
    }

    pub(crate) fn restore_firmware_auto_cycle(
        &mut self,
        device: &crate::AcerHwmonDevice,
    ) -> Result<crate::SystemFirmwareAutoRecovery, PlatformError> {
        let pinned = PinnedAcerHwmon::open(device).inspect_err(|_| {
            crate::emit_fault(crate::RuntimeFault::DeviceChanged, None);
        })?;
        for attempt in 1..=3 {
            let cpu_write_succeeded = self
                .write_firmware_auto(&pinned, device.cpu().enable())
                .is_ok();
            let gpu_write_succeeded = self
                .write_firmware_auto(&pinned, device.gpu().enable())
                .is_ok();
            let cpu = pinned.read(device.cpu().enable());
            let gpu = pinned.read(device.gpu().enable());
            crate::emit_restoration_attempt(crate::RestorationAttemptDiagnostic {
                attempt,
                cpu: crate::RestorationFanDiagnostic {
                    write_succeeded: cpu_write_succeeded,
                    readback: system_restoration_readback(&cpu),
                },
                gpu: crate::RestorationFanDiagnostic {
                    write_succeeded: gpu_write_succeeded,
                    readback: system_restoration_readback(&gpu),
                },
            });
            if matches!(cpu, Ok(ref mode) if mode.trim() == "2")
                && matches!(gpu, Ok(ref mode) if mode.trim() == "2")
            {
                return Ok(crate::SystemFirmwareAutoRecovery::Restored);
            }
        }

        crate::emit_fault(crate::RuntimeFault::RestorationUnconfirmed, None);
        let cpu = pinned.contain(
            device.cpu(),
            crate::RuntimeEndpoint::CpuEnable,
            crate::RuntimeEndpoint::CpuPwm,
        );
        let gpu = pinned.contain(
            device.gpu(),
            crate::RuntimeEndpoint::GpuEnable,
            crate::RuntimeEndpoint::GpuPwm,
        );
        match (cpu, gpu) {
            (Ok(()), Ok(())) => Ok(crate::SystemFirmwareAutoRecovery::Contained),
            (cpu, gpu) => Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("recovery containment incomplete (CPU: {cpu:?}, GPU: {gpu:?})"),
            )),
        }
    }

    fn write_firmware_auto(
        &self,
        pinned: &PinnedAcerHwmon<'_>,
        endpoint: &Path,
    ) -> Result<(), PlatformError> {
        #[cfg(test)]
        if self.fail_firmware_auto_writes {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!(
                    "injected Firmware Auto write failure: {}",
                    endpoint.display()
                ),
            ));
        }
        pinned.write(endpoint, "2")
    }
}

fn system_restoration_readback(
    result: &Result<String, PlatformError>,
) -> crate::RestorationReadback {
    match result {
        Ok(value) if value.trim() == "2" => crate::RestorationReadback::FirmwareAuto,
        Ok(value) if value.trim() == "1" => crate::RestorationReadback::Custom,
        Ok(_) => crate::RestorationReadback::Other,
        Err(_) => crate::RestorationReadback::Unreadable,
    }
}

impl FileAccess for SystemOwnershipPlatform {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        Self::read_file(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        Self::write_file(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        Self::list_directory(directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        let metadata = Self::metadata(path)?;
        let mut permissions = FilePermissions::from_mode(metadata.permissions().mode())
            .with_owner_uid(metadata.uid());
        if path_has_extended_acl(path).map_err(|error| {
            io_platform_error(&format!("cannot inspect ACL for {}", path.display()), error)
        })? {
            permissions = permissions.with_extended_acl();
        }
        Ok(permissions)
    }
}

impl RootOwnedQualificationRecordAccess for SystemOwnershipPlatform {
    fn read_root_owned_qualification_record(
        &mut self,
        path: &Path,
    ) -> Result<String, PlatformError> {
        validate_root_owned_protected_file(path, ProtectedFileRequirement::Regular)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                io_platform_error(
                    &format!("cannot open qualification record {}", path.display()),
                    error,
                )
            })?;
        let metadata = file.metadata().map_err(|error| {
            io_platform_error(
                &format!("cannot inspect qualification record {}", path.display()),
                error,
            )
        })?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(PlatformError::new(
                PlatformErrorKind::PermissionDenied,
                "qualification record is not a protected root-owned regular file",
            ));
        }
        let mut source = String::new();
        file.read_to_string(&mut source).map_err(|error| {
            io_platform_error(
                &format!("cannot read qualification record {}", path.display()),
                error,
            )
        })?;
        Ok(source)
    }

    fn verify_root_owned_supervised_endurance_evidence(
        &mut self,
        path: &Path,
        expected_sha256: &str,
        expected_envelope: &crate::QualificationEnvelopeIdentityV1,
    ) -> Result<(), PlatformError> {
        let source = self.read_root_owned_qualification_record(path)?;
        verify_supervised_endurance_evidence_source(&source, expected_sha256, expected_envelope)
    }
}

impl IdentityBoundFileAccess for SystemOwnershipPlatform {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        Self::file_identity(path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        let directory_handle = open_directory_bound(directory, expected)?;
        let mut file = open_direct_child(&directory_handle, &path, libc::O_RDONLY)?;
        let mut value = String::new();
        file.read_to_string(&mut value).map_err(|error| {
            io_platform_error(&format!("cannot read {}", path.display()), error)
        })?;
        Ok(value)
    }

    fn read_child_bound(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
    ) -> Result<String, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        let directory_handle = open_directory_bound(directory, expected_directory)?;
        let mut file = open_direct_child(&directory_handle, &path, libc::O_RDONLY)?;
        require_open_file_identity(&file, &path, expected_child)?;
        let mut value = String::new();
        file.read_to_string(&mut value).map_err(|error| {
            io_platform_error(&format!("cannot read {}", path.display()), error)
        })?;
        Ok(value)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        let directory_handle = open_directory_bound(directory, expected)?;
        let pinned_path = PathBuf::from(format!("/proc/self/fd/{}", directory_handle.as_raw_fd()));
        let entries = fs::read_dir(&pinned_path).map_err(|error| {
            io_platform_error(&format!("cannot list {}", directory.display()), error)
        })?;
        entries
            .map(|entry| {
                entry
                    .map(|entry| directory.join(entry.file_name()))
                    .map_err(|error| {
                        io_platform_error(
                            &format!("cannot read directory entry in {}", directory.display()),
                            error,
                        )
                    })
            })
            .collect()
    }
}

impl SystemOwnershipPlatform {
    fn require_deadline(
        &self,
        deadline: Duration,
        path: &Path,
        operation: &str,
    ) -> Result<(), PlatformError> {
        if self.started_at.elapsed() >= deadline {
            return Err(PlatformError::new(
                PlatformErrorKind::TimedOut,
                format!("{operation} deadline exceeded: {}", path.display()),
            ));
        }
        Ok(())
    }
}

const BOUNDED_READ_LIMIT: usize = 64 * 1024;

/// Reads an already identity-pinned descriptor in an isolated process so a blocked kernel read
/// cannot stall the controller or its watchdog beyond the caller's remaining budget.
fn read_open_file_before(
    file: &File,
    path: &Path,
    timeout: Duration,
) -> Result<String, PlatformError> {
    if timeout.is_zero() {
        return Err(bounded_read_timeout(path));
    }

    let mut pipe_fds = [-1; 2];
    // SAFETY: `pipe_fds` points to two writable integers and no descriptors escape on exec.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io_platform_error(
            &format!("cannot create bounded reader for {}", path.display()),
            io::Error::last_os_error(),
        ));
    }

    // SAFETY: the child performs only async-signal-safe syscalls before `_exit`.
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        close_fd(pipe_fds[0]);
        close_fd(pipe_fds[1]);
        return Err(io_platform_error(
            &format!("cannot start bounded reader for {}", path.display()),
            io::Error::last_os_error(),
        ));
    }
    if pid == 0 {
        close_fd(pipe_fds[0]);
        bounded_read_child(file.as_raw_fd(), pipe_fds[1]);
    }

    close_fd(pipe_fds[1]);
    // SAFETY: the parent uniquely owns the read descriptor after closing the write end.
    let mut output_pipe = unsafe { File::from_raw_fd(pipe_fds[0]) };
    if let Err(error) = set_fd_nonblocking(output_pipe.as_raw_fd()) {
        terminate_and_reap_pid(pid);
        return Err(io_platform_error(
            &format!("cannot monitor bounded reader for {}", path.display()),
            error,
        ));
    }

    let deadline = Instant::now() + timeout;
    let mut output = Vec::new();
    loop {
        let mut buffer = [0_u8; 4096];
        loop {
            match output_pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) if output.len().saturating_add(length) <= BOUNDED_READ_LIMIT => {
                    output.extend_from_slice(&buffer[..length]);
                }
                Ok(_) => {
                    terminate_and_reap_pid(pid);
                    return Err(PlatformError::new(
                        PlatformErrorKind::Unavailable,
                        format!("bounded read exceeded 64 KiB: {}", path.display()),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    terminate_and_reap_pid(pid);
                    return Err(io_platform_error(
                        &format!("cannot read {}", path.display()),
                        error,
                    ));
                }
            }
        }

        let mut status = 0;
        // SAFETY: `pid` names this function's child and `status` is writable.
        match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
            completed if completed == pid => {
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    drain_completed_bounded_read(&mut output_pipe, &mut output, path)?;
                    return String::from_utf8(output).map_err(|error| {
                        io_platform_error(
                            &format!("cannot decode {}", path.display()),
                            io::Error::new(io::ErrorKind::InvalidData, error),
                        )
                    });
                }
                return Err(PlatformError::new(
                    PlatformErrorKind::Unavailable,
                    format!("bounded read worker failed: {}", path.display()),
                ));
            }
            0 => {}
            -1 => {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ECHILD) {
                    terminate_and_reap_pid(pid);
                }
                return Err(io_platform_error(
                    &format!("cannot wait for bounded reader of {}", path.display()),
                    error,
                ));
            }
            _ => unreachable!("waitpid returned an unrelated child"),
        }

        if Instant::now() >= deadline {
            terminate_and_reap_pid(pid);
            return Err(bounded_read_timeout(path));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn drain_completed_bounded_read(
    pipe: &mut File,
    output: &mut Vec<u8>,
    path: &Path,
) -> Result<(), PlatformError> {
    let mut buffer = [0_u8; 4096];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(length) if output.len().saturating_add(length) <= BOUNDED_READ_LIMIT => {
                output.extend_from_slice(&buffer[..length]);
            }
            Ok(_) => {
                return Err(PlatformError::new(
                    PlatformErrorKind::Unavailable,
                    format!("bounded read exceeded 64 KiB: {}", path.display()),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(io_platform_error(
                    &format!("cannot read {}", path.display()),
                    error,
                ));
            }
        }
    }
}

fn bounded_read_timeout(path: &Path) -> PlatformError {
    PlatformError::new(
        PlatformErrorKind::TimedOut,
        format!("bound read deadline exceeded: {}", path.display()),
    )
}

fn set_fd_nonblocking(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor and fcntl retains no pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1
        // SAFETY: the same descriptor remains live for this immediate flag update.
        || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn close_fd(fd: libc::c_int) {
    // SAFETY: callers transfer or relinquish ownership of this raw descriptor exactly once.
    unsafe {
        libc::close(fd);
    }
}

fn bounded_read_child(input_fd: libc::c_int, output_fd: libc::c_int) -> ! {
    let mut total = 0_usize;
    let mut buffer = [0_u8; 4096];
    loop {
        // SAFETY: both descriptors are inherited and the buffer is valid for its full length.
        let length = unsafe {
            libc::read(
                input_fd,
                buffer.as_mut_ptr().cast(),
                buffer.len() as libc::size_t,
            )
        };
        if length == 0 {
            // SAFETY: `_exit` terminates only the fork child without running Rust destructors.
            unsafe { libc::_exit(0) }
        }
        if length == -1 {
            // SAFETY: errno is thread-local state for this fork child.
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            // SAFETY: see the successful exit above.
            unsafe { libc::_exit(1) }
        }
        let length = length as usize;
        total = total.saturating_add(length);
        if total > BOUNDED_READ_LIMIT {
            // SAFETY: see the successful exit above.
            unsafe { libc::_exit(2) }
        }
        let mut written = 0;
        while written < length {
            // SAFETY: `written..length` remains within the initialized portion of `buffer`.
            let result = unsafe {
                libc::write(
                    output_fd,
                    buffer[written..length].as_ptr().cast(),
                    (length - written) as libc::size_t,
                )
            };
            if result == -1 {
                // SAFETY: errno is thread-local state for this fork child.
                if unsafe { *libc::__errno_location() } == libc::EINTR {
                    continue;
                }
                // SAFETY: see the successful exit above.
                unsafe { libc::_exit(3) }
            }
            written += result as usize;
        }
    }
}

fn terminate_and_reap_pid(pid: libc::pid_t) {
    // SAFETY: `pid` is the positive ID returned by this function's fork.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let reaper = thread::Builder::new()
        .name("pt31553-bounded-read-reaper".into())
        .spawn(move || {
            let mut status = 0;
            loop {
                // SAFETY: this thread is the sole remaining waiter for `pid`.
                let result = unsafe { libc::waitpid(pid, &mut status, 0) };
                if result == pid
                    || (result == -1
                        && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
                {
                    return;
                }
            }
        });
    if reaper.is_err() {
        let mut status = 0;
        // SAFETY: thread creation failed, so this remains the sole waiter for the killed child.
        unsafe {
            while libc::waitpid(pid, &mut status, 0) == -1
                && *libc::__errno_location() == libc::EINTR
            {}
        }
    }
}

impl BoundedFileAccess for SystemOwnershipPlatform {
    fn read_before(&mut self, path: &Path, deadline: Duration) -> Result<String, PlatformError> {
        self.require_deadline(deadline, path, "read")?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| {
                io_platform_error(&format!("cannot open {}", path.display()), error)
            })?;
        let remaining = deadline.saturating_sub(self.started_at.elapsed());
        let value = read_open_file_before(&file, path, remaining)?;
        self.require_deadline(deadline, path, "read")?;
        Ok(value)
    }

    fn list_before(
        &mut self,
        directory: &Path,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.require_deadline(deadline, directory, "list")?;
        let entries = Self::list_directory(directory)?;
        self.require_deadline(deadline, directory, "list")?;
        Ok(entries)
    }

    fn write_before(
        &mut self,
        path: &Path,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        self.require_deadline(deadline, path, "write")?;
        let mut file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| {
                io_platform_error(
                    &format!("cannot open {} for writing", path.display()),
                    error,
                )
            })?;
        self.require_deadline(deadline, path, "write")?;
        file.write_all(contents.as_bytes()).map_err(|error| {
            io_platform_error(&format!("cannot write {}", path.display()), error)
        })?;
        self.require_deadline(deadline, path, "write")
    }
}

impl BoundedIdentityBoundFileAccess for SystemOwnershipPlatform {
    fn identity_before(
        &mut self,
        path: &Path,
        deadline: Duration,
    ) -> Result<FileIdentity, PlatformError> {
        self.require_deadline(deadline, path, "identity")?;
        let identity = Self::file_identity(path)?;
        self.require_deadline(deadline, path, "identity")?;
        Ok(identity)
    }

    fn read_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        self.require_deadline(deadline, &path, "bound read")?;
        let directory_handle = open_directory_bound(directory, expected_directory)?;
        let file = open_direct_child(&directory_handle, &path, libc::O_RDONLY | libc::O_NONBLOCK)?;
        require_open_file_identity(&file, &path, expected_child)?;
        let remaining = deadline.saturating_sub(self.started_at.elapsed());
        let value = read_open_file_before(&file, &path, remaining)?;
        self.require_deadline(deadline, &path, "bound read")?;
        Ok(value)
    }

    fn list_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.require_deadline(deadline, directory, "bound list")?;
        let entries = IdentityBoundFileAccess::list_bound(self, directory, expected_directory)?;
        self.require_deadline(deadline, directory, "bound list")?;
        Ok(entries)
    }

    fn permissions_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<FilePermissions, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        self.require_deadline(deadline, &path, "bound permissions")?;
        let directory_handle = open_directory_bound(directory, expected_directory)?;
        let file = open_direct_child(&directory_handle, &path, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let metadata = require_open_file_identity(&file, &path, expected_child)?;
        self.require_deadline(deadline, &path, "bound permissions")?;
        Ok(
            FilePermissions::from_mode(metadata.permissions().mode())
                .with_owner_uid(metadata.uid()),
        )
    }

    fn write_bound_if_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        expected_children: &[(&str, FileIdentity)],
        guards: &[(&str, &str)],
        target_child: &str,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        let target = direct_bound_child(directory, target_child)?;
        self.require_deadline(deadline, &target, "guarded write")?;
        let directory_handle = open_directory_bound(directory, expected_directory)?;

        let mut children = BTreeMap::new();
        for (child, expected) in expected_children {
            let path = direct_bound_child(directory, child)?;
            let file =
                open_direct_child(&directory_handle, &path, libc::O_RDONLY | libc::O_NONBLOCK)?;
            require_open_file_identity(&file, &path, *expected)?;
            if children.insert(*child, (file, *expected)).is_some() {
                return Err(PlatformError::new(
                    PlatformErrorKind::Unavailable,
                    format!("guarded write has duplicate identity for {child}"),
                ));
            }
        }
        for (child, expected_contents) in guards {
            let path = direct_bound_child(directory, child)?;
            let (file, _) = children.get_mut(child).ok_or_else(|| {
                PlatformError::new(
                    PlatformErrorKind::Unavailable,
                    format!("guarded write has no identity for {child}"),
                )
            })?;
            let mut actual = String::new();
            file.read_to_string(&mut actual).map_err(|error| {
                io_platform_error(&format!("cannot read guard {}", path.display()), error)
            })?;
            if actual.trim() != *expected_contents {
                return Err(PlatformError::new(
                    PlatformErrorKind::Unavailable,
                    format!(
                        "guarded write expected {expected_contents:?} at {}, got {actual:?}",
                        path.display()
                    ),
                ));
            }
        }

        for (child, (file, expected)) in &children {
            let path = direct_bound_child(directory, child)?;
            require_open_file_identity(file, &path, *expected)?;
        }
        // `ControllerOwnership` excludes every supported writer for this synchronous critical
        // section. Linux offers no cross-file sysfs transaction, so guard atomicity is explicitly
        // relative to processes honoring that ownership boundary.
        self.require_deadline(deadline, &target, "guarded write")?;
        let (_, expected_target) = children.get(target_child).ok_or_else(|| {
            PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("guarded write has no identity for {target_child}"),
            )
        })?;
        // Guard reads advance their descriptors. A fresh write-only descriptor guarantees offset
        // zero for sysfs attributes, including when the target is itself one of the guards.
        let mut file = open_direct_child(
            &directory_handle,
            &target,
            libc::O_WRONLY | libc::O_NONBLOCK,
        )?;
        require_open_file_identity(&file, &target, *expected_target)?;
        file.write_all(contents.as_bytes()).map_err(|error| {
            io_platform_error(&format!("cannot write {}", target.display()), error)
        })?;
        self.require_deadline(deadline, &target, "guarded write")
    }
}

impl Clock for SystemOwnershipPlatform {
    fn monotonic_now(&mut self) -> Duration {
        self.started_at.elapsed()
    }

    fn delay(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

fn require_open_file_identity(
    file: &File,
    path: &Path,
    expected: FileIdentity,
) -> Result<fs::Metadata, PlatformError> {
    let metadata = file.metadata().map_err(|error| {
        io_platform_error(&format!("cannot inspect pinned {}", path.display()), error)
    })?;
    if FileIdentity::from_raw(metadata.dev(), metadata.ino()) != expected {
        return Err(PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("backing identity changed: {}", path.display()),
        ));
    }
    Ok(metadata)
}

fn open_directory_bound(directory: &Path, expected: FileIdentity) -> Result<File, PlatformError> {
    let path = CString::new(directory.as_os_str().as_bytes()).map_err(|_| {
        PlatformError::new(
            PlatformErrorKind::Unavailable,
            "directory path contains a NUL byte",
        )
    })?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_platform_error(
            &format!("cannot pin {}", directory.display()),
            io::Error::last_os_error(),
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| {
        io_platform_error(
            &format!("cannot inspect pinned {}", directory.display()),
            error,
        )
    })?;
    if FileIdentity::from_raw(metadata.dev(), metadata.ino()) != expected {
        return Err(PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("backing identity changed: {}", directory.display()),
        ));
    }
    Ok(file)
}

fn open_direct_child(
    directory: &File,
    path: &Path,
    flags: libc::c_int,
) -> Result<File, PlatformError> {
    let child = path.file_name().ok_or_else(|| {
        PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("bound endpoint has no filename: {}", path.display()),
        )
    })?;
    let child = CString::new(child.as_bytes()).map_err(|_| {
        PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("bound endpoint contains a NUL byte: {}", path.display()),
        )
    })?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            child.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io_platform_error(
            &format!("cannot open pinned endpoint {}", path.display()),
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

struct PinnedAcerHwmon<'a> {
    directory: File,
    device: &'a crate::AcerHwmonDevice,
}

impl<'a> PinnedAcerHwmon<'a> {
    fn open(device: &'a crate::AcerHwmonDevice) -> Result<Self, PlatformError> {
        Ok(Self {
            directory: open_directory_bound(device.root(), device.backing_identity())?,
            device,
        })
    }

    fn open_endpoint(&self, path: &Path, flags: libc::c_int) -> Result<File, PlatformError> {
        let file = open_direct_child(&self.directory, path, flags)?;
        let metadata = file.metadata().map_err(|error| {
            io_platform_error(&format!("cannot inspect {}", path.display()), error)
        })?;
        let actual = FileIdentity::from_raw(metadata.dev(), metadata.ino());
        if self.device.endpoint_identity(path) != Some(actual) {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("fan endpoint identity changed: {}", path.display()),
            ));
        }
        Ok(file)
    }

    fn read(&self, path: &Path) -> Result<String, PlatformError> {
        let mut file = self.open_endpoint(path, libc::O_RDONLY)?;
        let mut value = String::new();
        file.read_to_string(&mut value).map_err(|error| {
            io_platform_error(&format!("cannot read {}", path.display()), error)
        })?;
        Ok(value)
    }

    fn write(&self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        let mut file = self.open_endpoint(path, libc::O_WRONLY)?;
        file.write_all(contents.as_bytes())
            .map_err(|error| io_platform_error(&format!("cannot write {}", path.display()), error))
    }

    fn contain(
        &self,
        fan: &crate::FanEndpoints,
        enable_endpoint: crate::RuntimeEndpoint,
        pwm_endpoint: crate::RuntimeEndpoint,
    ) -> Result<(), PlatformError> {
        match self.read(fan.enable()) {
            Ok(mode) if mode.trim() == "2" => Ok(()),
            Ok(mode) if mode.trim() == "1" => {
                self.write(fan.pwm(), "255").inspect_err(|_| {
                    crate::emit_fault(
                        crate::RuntimeFault::ContainmentUnconfirmed,
                        Some(pwm_endpoint),
                    );
                })?;
                let readback = self.read(fan.pwm()).inspect_err(|_| {
                    crate::emit_fault(
                        crate::RuntimeFault::ContainmentUnconfirmed,
                        Some(pwm_endpoint),
                    );
                })?;
                if readback.trim() == "255" {
                    Ok(())
                } else {
                    crate::emit_fault(
                        crate::RuntimeFault::ContainmentUnconfirmed,
                        Some(pwm_endpoint),
                    );
                    Err(PlatformError::new(
                        PlatformErrorKind::Unavailable,
                        format!("maximum PWM readback failed: {}", fan.pwm().display()),
                    ))
                }
            }
            Ok(mode) => {
                crate::emit_fault(
                    crate::RuntimeFault::ContainmentUnconfirmed,
                    Some(enable_endpoint),
                );
                Err(PlatformError::new(
                    PlatformErrorKind::Unavailable,
                    format!("unexpected fan mode {mode:?}: {}", fan.enable().display()),
                ))
            }
            Err(error) => {
                crate::emit_fault(
                    crate::RuntimeFault::ContainmentUnconfirmed,
                    Some(enable_endpoint),
                );
                Err(error)
            }
        }
    }
}

#[derive(Debug)]
pub struct SystemRuntimeLock {
    file: Option<File>,
    path: PathBuf,
}

impl Drop for SystemRuntimeLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            std::mem::forget(file);
        }
    }
}

impl ServiceAccess for SystemOwnershipPlatform {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        let output = Command::new("systemctl")
            .args([
                "show",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                service,
            ])
            .output()
            .map_err(|error| io_platform_error("cannot execute systemctl", error))?;
        let status = String::from_utf8(output.stdout).map_err(|error| {
            PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("systemctl returned non-UTF-8 status for {service}: {error}"),
            )
        })?;
        parse_systemd_service_status(service, &status)
    }
}

fn parse_systemd_service_status(service: &str, status: &str) -> Result<bool, PlatformError> {
    let mut load_state = None;
    let mut active_state = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            load_state = Some(value);
        } else if let Some(value) = line.strip_prefix("ActiveState=") {
            active_state = Some(value);
        }
    }
    if load_state == Some("not-found") {
        return Err(PlatformError::new(
            PlatformErrorKind::NotFound,
            format!("service does not exist: {service}"),
        ));
    }
    if load_state != Some("loaded") {
        return Err(PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("cannot establish load state for service {service}"),
        ));
    }
    match active_state {
        Some("active" | "activating" | "reloading" | "deactivating") => Ok(true),
        Some("inactive" | "failed" | "maintenance") => Ok(false),
        _ => Err(PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("cannot establish active state for service {service}"),
        )),
    }
}

impl RuntimeLockAccess for SystemOwnershipPlatform {
    type RuntimeLock = SystemRuntimeLock;

    fn try_acquire_root_runtime_lock(
        &mut self,
        path: &Path,
    ) -> Result<Self::RuntimeLock, RuntimeLockError> {
        let parent = path.parent().ok_or_else(|| {
            RuntimeLockError::Platform(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("runtime lock has no parent directory: {}", path.display()),
            ))
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            RuntimeLockError::Platform(io_platform_error(
                "cannot create runtime lock directory",
                error,
            ))
        })?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
            RuntimeLockError::Platform(io_platform_error(
                "cannot inspect runtime lock directory",
                error,
            ))
        })?;
        if !parent_metadata.file_type().is_dir()
            || parent_metadata.uid() != self.required_lock_owner
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(RuntimeLockError::NotRootOwned);
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                RuntimeLockError::Platform(io_platform_error("cannot open runtime lock", error))
            })?;
        let metadata = file.metadata().map_err(|error| {
            RuntimeLockError::Platform(io_platform_error("cannot inspect runtime lock", error))
        })?;
        if metadata.uid() != self.required_lock_owner || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(RuntimeLockError::NotRootOwned);
        }

        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            return if matches!(error.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                Err(RuntimeLockError::AlreadyHeld)
            } else {
                Err(RuntimeLockError::Platform(io_platform_error(
                    "cannot acquire runtime lock",
                    error,
                )))
            };
        }

        Ok(SystemRuntimeLock {
            file: Some(file),
            path: path.to_path_buf(),
        })
    }

    fn release_runtime_lock(
        &mut self,
        mut lock: Self::RuntimeLock,
    ) -> Result<(), (Self::RuntimeLock, PlatformError)> {
        let file = lock
            .file
            .as_ref()
            .expect("held runtime lock must own a file");
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        if result == 0 {
            drop(lock.file.take());
            Ok(())
        } else {
            let error = io_platform_error(
                &format!("cannot release runtime lock {}", lock.path.display()),
                io::Error::last_os_error(),
            );
            Err((lock, error))
        }
    }
}

fn io_platform_error(context: &str, error: io::Error) -> PlatformError {
    let kind = match error.kind() {
        io::ErrorKind::NotFound => PlatformErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => PlatformErrorKind::PermissionDenied,
        io::ErrorKind::TimedOut => PlatformErrorKind::TimedOut,
        _ => PlatformErrorKind::Unavailable,
    };
    PlatformError::new(kind, format!("{context}: {error}"))
}

impl fmt::Display for RuntimeLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyHeld => formatter.write_str("runtime lock is already held"),
            Self::NotRootOwned => formatter.write_str("runtime lock is not owned by root"),
            Self::Platform(error) => write!(formatter, "runtime lock failed: {error}"),
        }
    }
}

impl Error for RuntimeLockError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AlreadyHeld | Self::NotRootOwned => None,
            Self::Platform(error) => Some(error),
        }
    }
}

pub trait Clock {
    fn monotonic_now(&mut self) -> Duration;

    fn delay(&mut self, duration: Duration);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformOperation {
    Read(PathBuf),
    Write { path: PathBuf, contents: String },
    List(PathBuf),
    Permissions(PathBuf),
    Identity(PathBuf),
    ServiceStatus(String),
    AcquireRuntimeLock(PathBuf),
    ReleaseRuntimeLock(PathBuf),
    MonotonicNow,
    Delay(Duration),
}

#[derive(Debug)]
struct FakeFile {
    contents: String,
    permissions: FilePermissions,
    root_owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeStep {
    Pass,
    Fail(PlatformError),
    Disappear(PathBuf),
    ReplaceContents { path: PathBuf, contents: String },
    Advance(Duration),
}

#[derive(Debug)]
struct FakeRuntimeLockState {
    root_owned: bool,
    locks: BTreeMap<PathBuf, u64>,
    next_identity: u64,
}

/// Shared fake backend that models an OS lock visible to independent processes.
#[derive(Debug, Clone)]
pub struct FakeRuntimeLockBackend {
    state: Arc<Mutex<FakeRuntimeLockState>>,
}

impl Default for FakeRuntimeLockBackend {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeRuntimeLockState {
                root_owned: true,
                locks: BTreeMap::new(),
                next_identity: 0,
            })),
        }
    }
}

impl FakeRuntimeLockBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_root_owned(&self, root_owned: bool) {
        self.state
            .lock()
            .expect("fake runtime lock mutex must not be poisoned")
            .root_owned = root_owned;
    }
}

/// Opaque hold returned by [`FakePlatform`]'s shared runtime-lock backend.
#[derive(Debug)]
pub struct FakeRuntimeLock {
    backend: Arc<Mutex<FakeRuntimeLockState>>,
    path: PathBuf,
    identity: u64,
}

#[derive(Debug, Default)]
pub struct FakePlatform {
    files: BTreeMap<PathBuf, FakeFile>,
    directories: BTreeSet<PathBuf>,
    identities: BTreeMap<PathBuf, FileIdentity>,
    next_inode: u64,
    services: BTreeMap<String, bool>,
    runtime_lock_backend: FakeRuntimeLockBackend,
    monotonic_time: Duration,
    delays: Vec<Duration>,
    steps: VecDeque<FakeStep>,
    file_steps: VecDeque<FakeStep>,
    runtime_lock_steps: VecDeque<FakeStep>,
    operations: Vec<PlatformOperation>,
    bounded_write_attempts: Vec<PlatformOperation>,
}

impl FakePlatform {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_runtime_lock_backend(runtime_lock_backend: FakeRuntimeLockBackend) -> Self {
        Self {
            runtime_lock_backend,
            ..Self::default()
        }
    }

    pub fn runtime_lock_backend(&self) -> FakeRuntimeLockBackend {
        self.runtime_lock_backend.clone()
    }

    pub fn insert_directory(&mut self, directory: impl Into<PathBuf>) {
        let directory = directory.into();
        self.insert_ancestor_directories(&directory);
        self.ensure_identity(&directory);
        self.directories.insert(directory);
    }

    pub fn insert_file(&mut self, path: impl Into<PathBuf>, contents: impl Into<String>) {
        self.insert_file_with_permissions(path, contents, FilePermissions::READ_WRITE);
    }

    pub fn insert_file_with_permissions(
        &mut self,
        path: impl Into<PathBuf>,
        contents: impl Into<String>,
        permissions: FilePermissions,
    ) {
        let path = path.into();
        self.insert_ancestor_directories(&path);
        self.ensure_identity(&path);
        self.files.insert(
            path,
            FakeFile {
                contents: contents.into(),
                permissions,
                root_owned: true,
            },
        );
    }

    pub fn set_file_root_owned(&mut self, path: impl AsRef<Path>, root_owned: bool) {
        if let Some(file) = self.files.get_mut(path.as_ref()) {
            file.root_owned = root_owned;
        }
    }

    pub fn set_file_permissions(&mut self, path: impl AsRef<Path>, permissions: FilePermissions) {
        if let Some(file) = self.files.get_mut(path.as_ref()) {
            file.permissions = permissions;
        }
    }

    pub fn remove_path(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        self.files
            .retain(|candidate, _| candidate != path && !candidate.starts_with(path));
        self.directories
            .retain(|candidate| candidate != path && !candidate.starts_with(path));
        self.identities
            .retain(|candidate, _| candidate != path && !candidate.starts_with(path));
    }

    /// Simulates a path being rebound to a different backing object without changing contents.
    pub fn rebind_path_identity(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        assert!(
            self.identities.contains_key(path),
            "fake path must exist before its identity can be rebound"
        );
        self.next_inode = self.next_inode.saturating_add(1);
        self.identities.insert(
            path.to_path_buf(),
            FileIdentity::from_raw(0, self.next_inode),
        );
    }

    pub fn file_contents(&self, path: impl AsRef<Path>) -> Option<&str> {
        self.files
            .get(path.as_ref())
            .map(|file| file.contents.as_str())
    }

    pub fn insert_service(&mut self, service: impl Into<String>, active: bool) {
        self.services.insert(service.into(), active);
    }

    pub fn advance_monotonic_time_to(&mut self, time: Duration) {
        assert!(
            time >= self.monotonic_time,
            "fake monotonic time cannot move backwards"
        );
        self.monotonic_time = time;
    }

    pub fn queue_steps(&mut self, steps: impl IntoIterator<Item = FakeStep>) {
        self.steps.extend(steps);
    }

    /// Queues failures scoped to file operations, independently of admission
    /// service probes and runtime-lock operations.
    pub fn queue_file_steps(&mut self, steps: impl IntoIterator<Item = FakeStep>) {
        self.file_steps.extend(steps);
    }

    /// Queues failures scoped to runtime-lock acquire/release operations.
    pub fn queue_runtime_lock_steps(&mut self, steps: impl IntoIterator<Item = FakeStep>) {
        self.runtime_lock_steps.extend(steps);
    }

    pub fn pending_steps(&self) -> usize {
        self.steps.len()
    }

    pub fn operations(&self) -> &[PlatformOperation] {
        &self.operations
    }

    /// Calls made through the identity-bound write API, including calls rejected before a write.
    pub fn bounded_write_attempts(&self) -> &[PlatformOperation] {
        &self.bounded_write_attempts
    }

    pub fn delays(&self) -> &[Duration] {
        &self.delays
    }

    fn insert_ancestor_directories(&mut self, path: &Path) {
        let mut parent = path.parent();
        while let Some(directory) = parent {
            self.ensure_identity(directory);
            self.directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }

    fn ensure_identity(&mut self, path: &Path) {
        if !self.identities.contains_key(path) {
            self.next_inode = self.next_inode.saturating_add(1);
            self.identities.insert(
                path.to_path_buf(),
                FileIdentity::from_raw(0, self.next_inode),
            );
        }
    }

    fn apply_next_step(&mut self) -> Result<(), PlatformError> {
        match self.steps.pop_front().unwrap_or(FakeStep::Pass) {
            FakeStep::Pass => Ok(()),
            FakeStep::Fail(error) => Err(error),
            FakeStep::Disappear(path) => {
                self.remove_path(path);
                Ok(())
            }
            FakeStep::ReplaceContents { path, contents } => self.replace_contents(&path, contents),
            FakeStep::Advance(duration) => {
                self.monotonic_time = self.monotonic_time.saturating_add(duration);
                Ok(())
            }
        }
    }

    fn apply_next_file_step(&mut self) -> Result<(), PlatformError> {
        let Some(step) = self.file_steps.pop_front() else {
            return self.apply_next_step();
        };
        match step {
            FakeStep::Pass => Ok(()),
            FakeStep::Fail(error) => Err(error),
            FakeStep::Disappear(path) => {
                self.remove_path(path);
                Ok(())
            }
            FakeStep::ReplaceContents { path, contents } => self.replace_contents(&path, contents),
            FakeStep::Advance(duration) => {
                self.monotonic_time = self.monotonic_time.saturating_add(duration);
                Ok(())
            }
        }
    }

    fn apply_next_runtime_lock_step(&mut self) -> Result<(), PlatformError> {
        let Some(step) = self.runtime_lock_steps.pop_front() else {
            return self.apply_next_step();
        };
        match step {
            FakeStep::Pass => Ok(()),
            FakeStep::Fail(error) => Err(error),
            FakeStep::Disappear(path) => {
                self.remove_path(path);
                Ok(())
            }
            FakeStep::ReplaceContents { path, contents } => self.replace_contents(&path, contents),
            FakeStep::Advance(duration) => {
                self.monotonic_time = self.monotonic_time.saturating_add(duration);
                Ok(())
            }
        }
    }

    fn missing(path: &Path) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::NotFound,
            format!("platform path does not exist: {}", path.display()),
        )
    }

    fn permission_denied(path: &Path, operation: &str) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::PermissionDenied,
            format!("platform path is not {operation}: {}", path.display()),
        )
    }

    fn timed_out(path: &Path, operation: &str) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::TimedOut,
            format!(
                "platform {operation} exceeded its deadline: {}",
                path.display()
            ),
        )
    }

    fn apply_next_step_before(
        &mut self,
        path: &Path,
        operation: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        if self.monotonic_time >= deadline {
            return Err(Self::timed_out(path, operation));
        }

        match self.steps.pop_front().unwrap_or(FakeStep::Pass) {
            FakeStep::Advance(duration) => {
                let completion = self.monotonic_time.saturating_add(duration);
                if completion > deadline {
                    self.monotonic_time = deadline;
                    Err(Self::timed_out(path, operation))
                } else {
                    self.monotonic_time = completion;
                    Ok(())
                }
            }
            FakeStep::Pass => Ok(()),
            FakeStep::Fail(error) => Err(error),
            FakeStep::Disappear(path) => {
                self.remove_path(path);
                Ok(())
            }
            FakeStep::ReplaceContents { path, contents } => self.replace_contents(&path, contents),
        }
    }

    fn apply_next_file_step_before(
        &mut self,
        path: &Path,
        operation: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        if self.file_steps.is_empty() {
            return self.apply_next_step_before(path, operation, deadline);
        }
        if self.monotonic_time >= deadline {
            return Err(Self::timed_out(path, operation));
        }

        match self.file_steps.pop_front().expect("file step is present") {
            FakeStep::Advance(duration) => {
                let completion = self.monotonic_time.saturating_add(duration);
                if completion > deadline {
                    self.monotonic_time = deadline;
                    Err(Self::timed_out(path, operation))
                } else {
                    self.monotonic_time = completion;
                    Ok(())
                }
            }
            FakeStep::Pass => Ok(()),
            FakeStep::Fail(error) => Err(error),
            FakeStep::Disappear(path) => {
                self.remove_path(path);
                Ok(())
            }
            FakeStep::ReplaceContents { path, contents } => self.replace_contents(&path, contents),
        }
    }

    fn replace_contents(&mut self, path: &Path, contents: String) -> Result<(), PlatformError> {
        let file = self
            .files
            .get_mut(path)
            .ok_or_else(|| Self::missing(path))?;
        file.contents = contents;
        Ok(())
    }

    fn read_file(&self, path: &Path) -> Result<String, PlatformError> {
        let file = self.files.get(path).ok_or_else(|| Self::missing(path))?;
        if !file.permissions.readable() {
            return Err(Self::permission_denied(path, "readable"));
        }
        Ok(file.contents.clone())
    }

    fn write_file(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        let file = self
            .files
            .get_mut(path)
            .ok_or_else(|| Self::missing(path))?;
        if !file.permissions.writable() {
            return Err(Self::permission_denied(path, "writable"));
        }
        contents.clone_into(&mut file.contents);
        Ok(())
    }

    fn list_directory(&self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        if !self.directories.contains(directory) {
            return Err(Self::missing(directory));
        }

        Ok(self
            .directories
            .iter()
            .chain(self.files.keys())
            .filter_map(|path| {
                let relative = path.strip_prefix(directory).ok()?;
                let child = relative.components().next()?;
                Some(directory.join(child.as_os_str()))
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    fn require_bound_identities(
        &self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &Path,
        expected_child: FileIdentity,
    ) -> Result<(), PlatformError> {
        if self.identities.get(directory).copied() != Some(expected_directory) {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!(
                    "backing directory identity changed: {}",
                    directory.display()
                ),
            ));
        }
        if self.identities.get(child).copied() != Some(expected_child) {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("endpoint identity changed: {}", child.display()),
            ));
        }
        Ok(())
    }
}

impl FileAccess for FakePlatform {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        self.operations
            .push(PlatformOperation::Read(path.to_path_buf()));
        self.apply_next_file_step()?;
        self.read_file(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.operations.push(PlatformOperation::Write {
            path: path.to_path_buf(),
            contents: contents.to_owned(),
        });
        self.apply_next_file_step()?;
        self.write_file(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        self.operations
            .push(PlatformOperation::List(directory.to_path_buf()));
        self.apply_next_file_step()?;
        self.list_directory(directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        self.operations
            .push(PlatformOperation::Permissions(path.to_path_buf()));
        self.apply_next_file_step()?;
        self.files
            .get(path)
            .map(|file| file.permissions)
            .ok_or_else(|| Self::missing(path))
    }
}

impl RootOwnedQualificationRecordAccess for FakePlatform {
    fn read_root_owned_qualification_record(
        &mut self,
        path: &Path,
    ) -> Result<String, PlatformError> {
        self.operations
            .push(PlatformOperation::Read(path.to_path_buf()));
        self.apply_next_file_step()?;
        let file = self.files.get(path).ok_or_else(|| Self::missing(path))?;
        if !path.is_absolute()
            || !file.root_owned
            || file.permissions.mode() & 0o022 != 0
            || !file.permissions.readable()
        {
            return Err(Self::permission_denied(
                path,
                "protected root-owned regular file",
            ));
        }
        Ok(file.contents.clone())
    }

    fn verify_root_owned_supervised_endurance_evidence(
        &mut self,
        path: &Path,
        expected_sha256: &str,
        expected_envelope: &crate::QualificationEnvelopeIdentityV1,
    ) -> Result<(), PlatformError> {
        let source = self.read_root_owned_qualification_record(path)?;
        verify_supervised_endurance_evidence_source(&source, expected_sha256, expected_envelope)
    }
}

impl IdentityBoundFileAccess for FakePlatform {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        self.operations
            .push(PlatformOperation::Identity(path.to_path_buf()));
        self.apply_next_file_step()?;
        self.identities
            .get(path)
            .copied()
            .ok_or_else(|| Self::missing(path))
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        let child_path = Path::new(child);
        let mut components = child_path.components();
        let direct_child = matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none();
        if !direct_child {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("bound read is not a direct child: {child}"),
            ));
        }
        let path = directory.join(child);
        self.operations
            .push(PlatformOperation::Read(path.to_path_buf()));
        self.apply_next_file_step()?;
        if self.identities.get(directory).copied() != Some(expected) {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!(
                    "backing directory identity changed: {}",
                    directory.display()
                ),
            ));
        }
        self.read_file(&path)
    }

    fn read_child_bound(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
    ) -> Result<String, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        self.operations.push(PlatformOperation::Read(path.clone()));
        self.apply_next_file_step()?;
        self.require_bound_identities(directory, expected_directory, &path, expected_child)?;
        self.read_file(&path)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.operations
            .push(PlatformOperation::List(directory.to_path_buf()));
        self.apply_next_file_step()?;
        if self.identities.get(directory).copied() != Some(expected) {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!(
                    "backing directory identity changed: {}",
                    directory.display()
                ),
            ));
        }
        self.list_directory(directory)
    }
}

impl BoundedFileAccess for FakePlatform {
    fn read_before(&mut self, path: &Path, deadline: Duration) -> Result<String, PlatformError> {
        self.operations
            .push(PlatformOperation::Read(path.to_path_buf()));
        self.apply_next_file_step_before(path, "read", deadline)?;
        self.read_file(path)
    }

    fn list_before(
        &mut self,
        directory: &Path,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.operations
            .push(PlatformOperation::List(directory.to_path_buf()));
        self.apply_next_file_step_before(directory, "list", deadline)?;
        self.list_directory(directory)
    }

    fn write_before(
        &mut self,
        path: &Path,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        self.operations.push(PlatformOperation::Write {
            path: path.to_path_buf(),
            contents: contents.to_owned(),
        });
        self.apply_next_file_step_before(path, "write", deadline)?;
        self.write_file(path, contents)
    }
}

impl BoundedIdentityBoundFileAccess for FakePlatform {
    fn identity_before(
        &mut self,
        path: &Path,
        deadline: Duration,
    ) -> Result<FileIdentity, PlatformError> {
        self.operations
            .push(PlatformOperation::Identity(path.to_path_buf()));
        self.apply_next_file_step_before(path, "identity", deadline)?;
        self.identities
            .get(path)
            .copied()
            .ok_or_else(|| Self::missing(path))
    }

    fn read_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<String, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        self.operations.push(PlatformOperation::Read(path.clone()));
        self.apply_next_file_step_before(&path, "read", deadline)?;
        self.require_bound_identities(directory, expected_directory, &path, expected_child)?;
        self.read_file(&path)
    }

    fn list_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        deadline: Duration,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.operations
            .push(PlatformOperation::List(directory.to_path_buf()));
        self.apply_next_file_step_before(directory, "bound list", deadline)?;
        if self.identities.get(directory).copied() != Some(expected_directory) {
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!(
                    "backing directory identity changed: {}",
                    directory.display()
                ),
            ));
        }
        self.list_directory(directory)
    }

    fn permissions_bound_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
        deadline: Duration,
    ) -> Result<FilePermissions, PlatformError> {
        let path = direct_bound_child(directory, child)?;
        self.operations
            .push(PlatformOperation::Permissions(path.clone()));
        self.apply_next_file_step_before(&path, "permissions", deadline)?;
        self.require_bound_identities(directory, expected_directory, &path, expected_child)?;
        self.files
            .get(&path)
            .map(|file| file.permissions)
            .ok_or_else(|| Self::missing(&path))
    }

    fn write_bound_if_before(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        expected_children: &[(&str, FileIdentity)],
        guards: &[(&str, &str)],
        target_child: &str,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError> {
        let target = direct_bound_child(directory, target_child)?;
        self.bounded_write_attempts.push(PlatformOperation::Write {
            path: target.clone(),
            contents: contents.to_owned(),
        });
        self.apply_next_file_step_before(&target, "guarded write", deadline)?;
        for (child, expected) in expected_children {
            let path = direct_bound_child(directory, child)?;
            self.require_bound_identities(directory, expected_directory, &path, *expected)?;
        }
        for (child, expected_contents) in guards {
            let path = direct_bound_child(directory, child)?;
            self.operations.push(PlatformOperation::Read(path.clone()));
            let actual = self.read_file(&path)?;
            if actual.trim() != *expected_contents {
                return Err(PlatformError::new(
                    PlatformErrorKind::Unavailable,
                    format!(
                        "guarded write expected {expected_contents:?} at {}, got {actual:?}",
                        path.display()
                    ),
                ));
            }
        }
        if self.monotonic_time >= deadline {
            return Err(Self::timed_out(&target, "guarded write"));
        }
        for (child, expected) in expected_children {
            let path = direct_bound_child(directory, child)?;
            self.require_bound_identities(directory, expected_directory, &path, *expected)?;
        }
        self.operations.push(PlatformOperation::Write {
            path: target.clone(),
            contents: contents.to_owned(),
        });
        self.write_file(&target, contents)
    }
}

impl ServiceAccess for FakePlatform {
    fn is_service_active(&mut self, service: &str) -> Result<bool, PlatformError> {
        self.operations
            .push(PlatformOperation::ServiceStatus(service.to_owned()));
        self.apply_next_step()?;
        self.services.get(service).copied().ok_or_else(|| {
            PlatformError::new(
                PlatformErrorKind::NotFound,
                format!("service does not exist: {service}"),
            )
        })
    }
}

impl RuntimeLockAccess for FakePlatform {
    type RuntimeLock = FakeRuntimeLock;

    fn try_acquire_root_runtime_lock(
        &mut self,
        path: &Path,
    ) -> Result<Self::RuntimeLock, RuntimeLockError> {
        self.operations
            .push(PlatformOperation::AcquireRuntimeLock(path.to_path_buf()));
        self.apply_next_runtime_lock_step()
            .map_err(RuntimeLockError::Platform)?;
        let mut state = self.runtime_lock_backend.state.lock().map_err(|_| {
            RuntimeLockError::Platform(PlatformError::new(
                PlatformErrorKind::Unavailable,
                "runtime lock backend is unavailable",
            ))
        })?;
        if !state.root_owned {
            return Err(RuntimeLockError::NotRootOwned);
        }
        if state.locks.contains_key(path) {
            return Err(RuntimeLockError::AlreadyHeld);
        }

        state.next_identity = state.next_identity.saturating_add(1);
        let identity = state.next_identity;
        state.locks.insert(path.to_path_buf(), identity);
        Ok(FakeRuntimeLock {
            backend: self.runtime_lock_backend.state.clone(),
            path: path.to_path_buf(),
            identity,
        })
    }

    fn release_runtime_lock(
        &mut self,
        lock: Self::RuntimeLock,
    ) -> Result<(), (Self::RuntimeLock, PlatformError)> {
        self.operations
            .push(PlatformOperation::ReleaseRuntimeLock(lock.path.clone()));
        if let Err(error) = self.apply_next_runtime_lock_step() {
            return Err((lock, error));
        }
        if !Arc::ptr_eq(&lock.backend, &self.runtime_lock_backend.state) {
            return Err((
                lock,
                PlatformError::new(
                    PlatformErrorKind::Unavailable,
                    "runtime lock belongs to a different backend",
                ),
            ));
        }
        let mut state = match self.runtime_lock_backend.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return Err((
                    lock,
                    PlatformError::new(
                        PlatformErrorKind::Unavailable,
                        "runtime lock backend is unavailable",
                    ),
                ));
            }
        };
        match state.locks.get(&lock.path) {
            Some(identity) if *identity == lock.identity => {
                state.locks.remove(&lock.path);
                Ok(())
            }
            _ => {
                drop(state);
                Err((
                    lock,
                    PlatformError::new(
                        PlatformErrorKind::Unavailable,
                        "runtime lock token is no longer held",
                    ),
                ))
            }
        }
    }
}

impl Clock for FakePlatform {
    fn monotonic_now(&mut self) -> Duration {
        self.operations.push(PlatformOperation::MonotonicNow);
        self.monotonic_time
    }

    fn delay(&mut self, duration: Duration) {
        self.operations.push(PlatformOperation::Delay(duration));
        self.delays.push(duration);
        self.monotonic_time = self.monotonic_time.saturating_add(duration);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        io::{BufRead, Read, Write},
        process::{Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    use super::*;

    const CHILD_LOCK_PATH: &str = "FAN_CONTROL_TEST_LOCK_PATH";
    const CHILD_EXPECTATION: &str = "FAN_CONTROL_TEST_LOCK_EXPECTATION";

    #[test]
    fn bounded_reader_returns_at_deadline_when_the_underlying_read_blocks() {
        let mut pipe_fds = [-1; 2];
        // SAFETY: `pipe_fds` points to two writable integers.
        assert_eq!(
            unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: this test takes unique ownership of both new descriptors.
        let blocked_reader = unsafe { File::from_raw_fd(pipe_fds[0]) };
        // Keep the write end open without sending data so the child blocks instead of seeing EOF.
        // SAFETY: this test takes unique ownership of the second new descriptor.
        let _open_writer = unsafe { File::from_raw_fd(pipe_fds[1]) };
        let started = Instant::now();

        let error = read_open_file_before(
            &blocked_reader,
            Path::new("/test/blocked-sysfs-read"),
            Duration::from_millis(25),
        )
        .unwrap_err();

        assert_eq!(error.kind(), PlatformErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn protected_file_validation_rejects_symlinks_hardlinks_and_special_files() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        // SAFETY: geteuid has no preconditions and does not mutate process state.
        let owner = unsafe { libc::geteuid() };
        let directory = env::current_dir().unwrap().join("target").join(format!(
            "fan-control-protected-input-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let regular = directory.join("regular");
        fs::write(&regular, "evidence").unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            validate_owned_protected_file(&regular, ProtectedFileRequirement::Regular, owner)
                .is_ok()
        );

        let symlink = directory.join("symlink");
        std::os::unix::fs::symlink(&regular, &symlink).unwrap();
        assert!(
            validate_owned_protected_file(&symlink, ProtectedFileRequirement::Regular, owner)
                .is_err()
        );
        let hardlink = directory.join("hardlink");
        fs::hard_link(&regular, &hardlink).unwrap();
        assert!(
            validate_owned_protected_file(&regular, ProtectedFileRequirement::Regular, owner)
                .is_err()
        );

        let fifo = directory.join("fifo");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_name is a valid NUL-terminated path and mode has no invalid bits.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(
            validate_owned_protected_file(&fifo, ProtectedFileRequirement::Regular, owner).is_err()
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn system_recovery_completion_restores_both_fans() {
        let base = env::temp_dir().join(format!(
            "fan-control-supervised-recovery-{}",
            std::process::id()
        ));
        let device_root = base.join("hwmon7");
        fs::create_dir_all(&base).unwrap();
        create_hwmon_fixture(&device_root);
        let mut platform = SystemOwnershipPlatform::new();
        let device = crate::discover_acer_hwmon(&mut platform, &base).unwrap();

        let (outcome, diagnostic_events) = crate::diagnostics::record_test_diagnostics(|| {
            platform.restore_firmware_auto_cycle(&device).unwrap()
        });
        assert_eq!(outcome, crate::SystemFirmwareAutoRecovery::Restored);
        assert_restoration_diagnostics(
            &diagnostic_events,
            &[(1, true, "firmware-auto", true, "firmware-auto")],
        );
        assert_eq!(
            fs::read_to_string(device_root.join("pwm1_enable")).unwrap(),
            "2"
        );
        assert_eq!(
            fs::read_to_string(device_root.join("pwm2_enable")).unwrap(),
            "2"
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn guarded_write_uses_offset_zero_when_the_target_is_also_a_guard() {
        let directory = env::temp_dir().join(format!(
            "fan-control-guarded-write-offset-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join("pwm1_enable");
        fs::write(&target, "2\n").unwrap();
        let directory_metadata = fs::metadata(&directory).unwrap();
        let target_metadata = fs::metadata(&target).unwrap();
        let directory_identity =
            FileIdentity::from_raw(directory_metadata.dev(), directory_metadata.ino());
        let target_identity = FileIdentity::from_raw(target_metadata.dev(), target_metadata.ino());
        let mut platform = SystemOwnershipPlatform::new();

        platform
            .write_bound_if_before(
                &directory,
                directory_identity,
                &[("pwm1_enable", target_identity)],
                &[("pwm1_enable", "2")],
                "pwm1_enable",
                "1\n",
                Duration::MAX,
            )
            .unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "1\n");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_system_auto_writes_contain_both_confirmed_custom_fans_at_maximum() {
        let base = env::temp_dir().join(format!(
            "fan-control-system-recovery-failure-{}",
            std::process::id()
        ));
        let device_root = base.join("hwmon7");
        fs::create_dir_all(&base).unwrap();
        create_hwmon_fixture(&device_root);
        let mut discovery_platform = SystemOwnershipPlatform::new();
        let device = crate::discover_acer_hwmon(&mut discovery_platform, &base).unwrap();
        let mut recovery_platform = SystemOwnershipPlatform::with_failed_firmware_auto_writes();

        let (outcome, diagnostic_events) = crate::diagnostics::record_test_diagnostics(|| {
            recovery_platform
                .restore_firmware_auto_cycle(&device)
                .unwrap()
        });
        assert_eq!(outcome, crate::SystemFirmwareAutoRecovery::Contained);
        assert_restoration_diagnostics(
            &diagnostic_events,
            &[
                (1, false, "custom", false, "custom"),
                (2, false, "custom", false, "custom"),
                (3, false, "custom", false, "custom"),
            ],
        );
        assert_eq!(
            fs::read_to_string(device_root.join("pwm1_enable")).unwrap(),
            "1"
        );
        assert_eq!(
            fs::read_to_string(device_root.join("pwm2_enable")).unwrap(),
            "1"
        );
        assert_eq!(fs::read_to_string(device_root.join("pwm1")).unwrap(), "255");
        assert_eq!(fs::read_to_string(device_root.join("pwm2")).unwrap(), "255");
        fs::remove_dir_all(base).unwrap();
    }

    fn assert_restoration_diagnostics(
        events: &[BTreeMap<String, String>],
        expected: &[(u8, bool, &str, bool, &str)],
    ) {
        let restoration_events = events
            .iter()
            .filter(|event| {
                event.get("event_id").map(|value| value.trim_matches('"'))
                    == Some(crate::RESTORATION_ATTEMPT_EVENT_ID)
            })
            .collect::<Vec<_>>();
        assert_eq!(restoration_events.len(), expected.len());
        for (event, (attempt, cpu_write, cpu_readback, gpu_write, gpu_readback)) in
            restoration_events.into_iter().zip(expected)
        {
            let field = |name: &str| event.get(name).unwrap().trim_matches('"');
            assert_eq!(field("attempt"), attempt.to_string());
            assert_eq!(field("cpu_enable_endpoint"), "acer:cpu:pwm1_enable");
            assert_eq!(field("cpu_write_succeeded"), cpu_write.to_string());
            assert_eq!(field("cpu_mode_readback"), *cpu_readback);
            assert_eq!(field("gpu_enable_endpoint"), "acer:gpu:pwm2_enable");
            assert_eq!(field("gpu_write_succeeded"), gpu_write.to_string());
            assert_eq!(field("gpu_mode_readback"), *gpu_readback);
        }
    }

    #[test]
    fn pinned_recovery_write_stays_on_the_discovered_device_after_hwmon_rebind() {
        let base = env::temp_dir().join(format!(
            "fan-control-pinned-recovery-{}",
            std::process::id()
        ));
        let hwmon_root = base.join("class-hwmon");
        let original = base.join("original");
        let replacement = base.join("replacement");
        fs::create_dir_all(&hwmon_root).unwrap();
        create_hwmon_fixture(&original);
        create_hwmon_fixture(&replacement);
        let candidate = hwmon_root.join("hwmon7");
        std::os::unix::fs::symlink(&original, &candidate).unwrap();
        let mut platform = SystemOwnershipPlatform::new();
        let device = crate::discover_acer_hwmon(&mut platform, &hwmon_root).unwrap();
        let pinned = PinnedAcerHwmon::open(&device).unwrap();

        fs::remove_file(&candidate).unwrap();
        std::os::unix::fs::symlink(&replacement, &candidate).unwrap();
        pinned.write(device.cpu().enable(), "2").unwrap();

        assert_eq!(
            fs::read_to_string(original.join("pwm1_enable")).unwrap(),
            "2"
        );
        assert_eq!(
            fs::read_to_string(replacement.join("pwm1_enable")).unwrap(),
            "1"
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn bound_reads_never_escape_during_aba_directory_rebind() {
        let base =
            env::temp_dir().join(format!("fan-control-bound-read-aba-{}", std::process::id()));
        let original = base.join("original");
        let replacement = base.join("replacement");
        let candidate = base.join("hwmon7");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&replacement).unwrap();
        let expected_value = "original\n".repeat(8_192);
        let foreign_value = "foreign!\n".repeat(8_192);
        fs::write(original.join("name"), &expected_value).unwrap();
        fs::write(replacement.join("name"), foreign_value).unwrap();
        std::os::unix::fs::symlink(&original, &candidate).unwrap();

        let expected = SystemOwnershipPlatform::file_identity(&candidate).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let toggle_running = running.clone();
        let toggle_base = base.clone();
        let toggle_candidate = candidate.clone();
        let toggle_original = original.clone();
        let toggle_replacement = replacement.clone();
        let toggler = thread::spawn(move || {
            let mut replacement_active = true;
            while toggle_running.load(Ordering::Relaxed) {
                let target = if replacement_active {
                    &toggle_replacement
                } else {
                    &toggle_original
                };
                let next = toggle_base.join("next-link");
                std::os::unix::fs::symlink(target, &next).unwrap();
                fs::rename(&next, &toggle_candidate).unwrap();
                replacement_active = !replacement_active;
            }
        });

        let mut platform = SystemOwnershipPlatform::new();
        for _ in 0..256 {
            match IdentityBoundFileAccess::read_bound(&mut platform, &candidate, expected, "name") {
                Ok(value) => assert_eq!(value, expected_value),
                Err(error) => assert_eq!(error.kind(), PlatformErrorKind::Unavailable),
            }
        }
        running.store(false, Ordering::Relaxed);
        toggler.join().unwrap();

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn system_runtime_lock_serializes_separate_processes() {
        let directory =
            env::temp_dir().join(format!("fan-control-runtime-lock-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("lock");
        let owner = unsafe { libc::geteuid() };
        let mut platform = SystemOwnershipPlatform::with_required_lock_owner(owner);
        let lock = platform.try_acquire_root_runtime_lock(&path).unwrap();

        run_lock_child(&path, "held");
        platform.release_runtime_lock(lock).unwrap();
        run_lock_child(&path, "free");
        run_dropped_lock_holder(&path);
        run_lock_child(&path, "free");

        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn production_runtime_lock_rejects_non_root_ownership() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let directory = env::temp_dir().join(format!(
            "fan-control-root-lock-check-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("lock");
        let mut platform = SystemOwnershipPlatform::new();

        assert!(matches!(
            platform.try_acquire_root_runtime_lock(&path),
            Err(RuntimeLockError::NotRootOwned)
        ));

        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn runtime_lock_rejects_group_or_world_writable_directory() {
        let directory = env::temp_dir().join(format!(
            "fan-control-writable-lock-check-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        let path = directory.join("lock");
        let owner = unsafe { libc::geteuid() };
        let mut platform = SystemOwnershipPlatform::with_required_lock_owner(owner);

        assert!(matches!(
            platform.try_acquire_root_runtime_lock(&path),
            Err(RuntimeLockError::NotRootOwned)
        ));

        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn production_acl_probe_rejects_default_directory_acls() {
        let directory = env::current_dir().unwrap().join("target").join(format!(
            "fan-control-default-acl-check-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let executable = directory.join("qualification-harness");
        fs::write(&executable, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let owner = unsafe { libc::geteuid() };
        let path = CString::new(directory.as_os_str().as_bytes()).unwrap();
        // Linux POSIX ACL xattr: version 2 plus owner/group/other entries.
        let acl: [u8; 28] = [
            2, 0, 0, 0, // version
            1, 0, 7, 0, 255, 255, 255, 255, // user::rwx
            4, 0, 5, 0, 255, 255, 255, 255, // group::r-x
            32, 0, 5, 0, 255, 255, 255, 255, // other::r-x
        ];
        // SAFETY: path and attribute name are NUL-terminated; acl is valid for its byte length.
        let result = unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"system.posix_acl_default".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        assert_eq!(
            result,
            0,
            "cannot create default ACL: {}",
            io::Error::last_os_error()
        );

        assert!(path_has_extended_acl(&directory).unwrap());
        assert!(matches!(
            validate_owned_protected_file(
                &executable,
                ProtectedFileRequirement::Executable,
                owner,
            ),
            Err(error) if error.kind() == PlatformErrorKind::PermissionDenied
        ));
        let mut platform = SystemOwnershipPlatform::new();
        assert!(
            FileAccess::permissions(&mut platform, &directory)
                .unwrap()
                .has_extended_acl()
        );

        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn deactivating_competing_service_remains_active_for_admission() {
        assert_eq!(
            parse_systemd_service_status(
                "fancontrol.service",
                "LoadState=loaded\nActiveState=deactivating\n",
            ),
            Ok(true)
        );
    }

    #[test]
    fn system_runtime_lock_child_probe() {
        let Ok(path) = env::var(CHILD_LOCK_PATH) else {
            return;
        };
        let expectation = env::var(CHILD_EXPECTATION).unwrap();
        let owner = unsafe { libc::geteuid() };
        let mut platform = SystemOwnershipPlatform::with_required_lock_owner(owner);
        let result = platform.try_acquire_root_runtime_lock(Path::new(&path));
        match expectation.as_str() {
            "held" => assert!(matches!(result, Err(RuntimeLockError::AlreadyHeld))),
            "free" => assert!(result.is_ok()),
            "drop-hold" => {
                drop(result.unwrap());
                println!("ready");
                std::io::stdout().flush().unwrap();
                let mut signal = [0_u8];
                std::io::stdin().read_exact(&mut signal).unwrap();
            }
            other => panic!("unknown child lock expectation: {other}"),
        }
    }

    fn run_lock_child(path: &Path, expectation: &str) {
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::tests::system_runtime_lock_child_probe",
                "--nocapture",
            ])
            .env(CHILD_LOCK_PATH, path)
            .env(CHILD_EXPECTATION, expectation)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn run_dropped_lock_holder(path: &Path) {
        let mut child = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::tests::system_runtime_lock_child_probe",
                "--nocapture",
            ])
            .env(CHILD_LOCK_PATH, path)
            .env(CHILD_EXPECTATION, "drop-hold")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(stdout.read_line(&mut line).unwrap(), 0);
            if line.contains("ready") {
                break;
            }
        }
        run_lock_child(path, "held");
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
        let mut remainder = String::new();
        stdout.read_to_string(&mut remainder).unwrap();
        assert!(child.wait().unwrap().success());
    }

    fn create_hwmon_fixture(root: &Path) {
        fs::create_dir_all(root).unwrap();
        for (name, contents, mode) in [
            ("name", "acer\n", 0o444),
            ("pwm1", "100", 0o644),
            ("pwm1_enable", "1", 0o644),
            ("fan1_input", "2000", 0o444),
            ("pwm2", "100", 0o644),
            ("pwm2_enable", "1", 0o644),
            ("fan2_input", "2000", 0o444),
        ] {
            let path = root.join(name);
            fs::write(&path, contents).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }
}
