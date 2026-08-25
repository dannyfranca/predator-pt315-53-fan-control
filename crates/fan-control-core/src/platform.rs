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
    ServiceStatus(String),
    MonotonicNow,
    Delay(Duration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeStep {
    Pass,
    Fail(PlatformError),
    Disappear(PathBuf),
}

#[derive(Debug, Default)]
pub struct FakePlatform {
    files: BTreeMap<PathBuf, String>,
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
        let path = path.into();
        self.insert_ancestor_directories(&path);
        self.files.insert(path, contents.into());
    }

    pub fn remove_path(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        self.files
            .retain(|candidate, _| candidate != path && !candidate.starts_with(path));
        self.directories
            .retain(|candidate| candidate != path && !candidate.starts_with(path));
    }

    pub fn file_contents(&self, path: impl AsRef<Path>) -> Option<&str> {
        self.files.get(path.as_ref()).map(String::as_str)
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
        }
    }

    fn missing(path: &Path) -> PlatformError {
        PlatformError::new(
            PlatformErrorKind::NotFound,
            format!("platform path does not exist: {}", path.display()),
        )
    }
}

impl FileAccess for FakePlatform {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        self.operations
            .push(PlatformOperation::Read(path.to_path_buf()));
        self.apply_next_step()?;
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| Self::missing(path))
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.operations.push(PlatformOperation::Write {
            path: path.to_path_buf(),
            contents: contents.to_owned(),
        });
        self.apply_next_step()?;
        let stored = self
            .files
            .get_mut(path)
            .ok_or_else(|| Self::missing(path))?;
        contents.clone_into(stored);
        Ok(())
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
