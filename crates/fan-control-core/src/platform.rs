use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    path::{Path, PathBuf},
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

/// File access that returns no later than an absolute monotonic deadline.
pub trait BoundedFileAccess {
    fn read_before(&mut self, path: &Path, deadline: Duration) -> Result<String, PlatformError>;

    fn write_before(
        &mut self,
        path: &Path,
        contents: &str,
        deadline: Duration,
    ) -> Result<(), PlatformError>;
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
    ServiceStatus(String),
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

#[derive(Debug, Default)]
pub struct FakePlatform {
    files: BTreeMap<PathBuf, FakeFile>,
    directories: BTreeSet<PathBuf>,
    services: BTreeMap<String, bool>,
    monotonic_time: Duration,
    delays: Vec<Duration>,
    steps: VecDeque<FakeStep>,
    operations: Vec<PlatformOperation>,
}

impl FakePlatform {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_directory(&mut self, directory: impl Into<PathBuf>) {
        let directory = directory.into();
        self.insert_ancestor_directories(&directory);
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
            self.directories.insert(directory.to_path_buf());
            parent = directory.parent();
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
}

impl FileAccess for FakePlatform {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        self.operations
            .push(PlatformOperation::Read(path.to_path_buf()));
        self.apply_next_step()?;
        self.read_file(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.operations.push(PlatformOperation::Write {
            path: path.to_path_buf(),
            contents: contents.to_owned(),
        });
        self.apply_next_step()?;
        self.write_file(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        self.operations
            .push(PlatformOperation::List(directory.to_path_buf()));
        self.apply_next_step()?;
        if !self.directories.contains(directory) {
            return Err(Self::missing(directory));
        }

        let entries = self
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
            .collect();
        Ok(entries)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        self.operations
            .push(PlatformOperation::Permissions(path.to_path_buf()));
        self.apply_next_step()?;
        self.files
            .get(path)
            .map(|file| file.permissions)
            .ok_or_else(|| Self::missing(path))
    }
}

impl BoundedFileAccess for FakePlatform {
    fn read_before(&mut self, path: &Path, deadline: Duration) -> Result<String, PlatformError> {
        self.operations
            .push(PlatformOperation::Read(path.to_path_buf()));
        self.apply_next_step_before(path, "read", deadline)?;
        self.read_file(path)
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
        self.apply_next_step_before(path, "write", deadline)?;
        self.write_file(path, contents)
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
