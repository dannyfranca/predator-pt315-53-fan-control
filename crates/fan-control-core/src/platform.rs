use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
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

    /// Lists direct children while atomically binding the listing to the expected identity.
    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError>;
}

/// File access that returns no later than an absolute monotonic deadline.
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
    /// Atomically validates the directory and child identities, checks every guard, and writes.
    ///
    /// Implementations must bind all checks and the target write to the same backing directory
    /// handle without an interleaving point, and must enforce `deadline` immediately before the
    /// write becomes visible.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilePermissions {
    mode: u32,
}

impl FilePermissions {
    pub const NONE: Self = Self::from_mode(0o000);
    pub const READ_ONLY: Self = Self::from_mode(0o444);
    pub const WRITE_ONLY: Self = Self::from_mode(0o200);
    pub const READ_WRITE: Self = Self::from_mode(0o644);

    pub const fn from_mode(mode: u32) -> Self {
        Self {
            mode: mode & 0o7777,
        }
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
#[derive(Debug, Default)]
pub struct SystemOwnershipPlatform {
    required_lock_owner: u32,
}

impl SystemOwnershipPlatform {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_required_lock_owner(required_lock_owner: u32) -> Self {
        Self {
            required_lock_owner,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeStep {
    Pass,
    Fail(PlatformError),
    Disappear(PathBuf),
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
    operations: Vec<PlatformOperation>,
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
            },
        );
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

    pub fn pending_steps(&self) -> usize {
        self.steps.len()
    }

    pub fn operations(&self) -> &[PlatformOperation] {
        &self.operations
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
        }
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
        self.apply_next_step().map_err(RuntimeLockError::Platform)?;
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
        if let Err(error) = self.apply_next_step() {
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
    };

    use super::*;

    const CHILD_LOCK_PATH: &str = "FAN_CONTROL_TEST_LOCK_PATH";
    const CHILD_EXPECTATION: &str = "FAN_CONTROL_TEST_LOCK_EXPECTATION";

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
}
