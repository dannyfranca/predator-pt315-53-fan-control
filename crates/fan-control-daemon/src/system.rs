use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};

use fan_control_core::{
    AcerHwmonDevice, BoundedIdentityBoundFileAccess, BoundedIdentityBoundReadAccess, Clock,
    CompatibilityDeclarationV1, CompatibilityObservation, CoretempDevice, EvidenceCompleteness,
    ExternalPower, FanWriteBackend, FileIdentity, FilePermissions, HardwareIdentity,
    IdentityBoundReadAccess, ModuleIdentity, ModuleProvenance, NvidiaGpuSelector, NvmlAccess,
    NvmlError, NvmlErrorKind, NvmlGpuSample, ObservedFanAbi, ObservedSample,
    PackageProvenanceModuleV1, PackageProvenanceV1, PlatformError, PlatformErrorKind,
    RootOwnedQualificationRecordAccess, SENSOR_REDISCOVERY_WINDOW, SampleCapture,
    SampleSourceError, SampleSources, SensorSourceDiscovery, SystemOwnershipPlatform,
    TemperatureCelsius, discover_acer_hwmon, discover_coretemp, parse_compatibility_v1,
    sample_nvidia_gpu, validate_package_provenance_compatibility_v1,
    validate_package_provenance_v1,
};
use object::{Object, ObjectSection};
use sha2::{Digest, Sha256};

use crate::StartupError;

pub const EDITABLE_CONFIG_PATH: &str = "/etc/pt31553-fan-control/config.toml";
pub const COMPATIBILITY_DECLARATION_PATH: &str = "/usr/lib/pt31553-fan-control/compatibility.toml";
const QUALIFIED_ARCHIVE_PARENT: &str = "/var/lib/pt31553-fan-control/rollback";
const QUALIFIED_KERNEL_PACKAGE: &str = "linux-cachyos-pt31553";
pub const HWMON_ROOT: &str = "/sys/class/hwmon";
pub const POWER_SUPPLY_ROOT: &str = "/sys/class/power_supply";

pub struct SystemStartupDiscovery {
    pub editable_config: String,
    pub compatibility_declaration: String,
    pub protected_policy: String,
    pub observation: CompatibilityObservation,
    pub device: AcerHwmonDevice,
    pub sources: SystemSampleSources,
}

#[derive(Debug)]
pub(crate) struct StartupDiscovery<S> {
    pub(crate) editable_config: String,
    pub(crate) compatibility_declaration: String,
    pub(crate) protected_policy: String,
    pub(crate) observation: CompatibilityObservation,
    pub(crate) device: AcerHwmonDevice,
    pub(crate) sources: S,
}

/// Boundary around host files, package commands, device discovery, and live identity probes.
/// Keeping the admission orchestration generic makes its exact production wiring fixture-testable.
pub(crate) trait StartupDiscoveryEnvironment {
    type Sources: SampleSources;

    fn read_editable_config(&mut self) -> Result<String, StartupError>;
    fn load_compatibility_declaration(
        &mut self,
    ) -> Result<(String, CompatibilityDeclarationV1), StartupError>;
    fn load_qualified_archive(
        &mut self,
    ) -> Result<(QualifiedArchivePaths, String, PackageProvenanceV1), StartupError>;
    fn discover_sources(&mut self) -> Result<Self::Sources, StartupError>;
    fn discover_acer_device(
        &mut self,
        sources: &mut Self::Sources,
    ) -> Result<AcerHwmonDevice, StartupError>;
    fn observe_live_identity(
        &mut self,
        declaration: &CompatibilityDeclarationV1,
        provenance: &PackageProvenanceV1,
        archive: &QualifiedArchivePaths,
        device: &AcerHwmonDevice,
    ) -> Result<CompatibilityObservation, StartupError>;
}

struct ProductionStartupDiscoveryEnvironment {
    protected_files: SystemOwnershipPlatform,
}

trait LiveIdentityAccess {
    fn command_one_line(
        &mut self,
        command: &str,
        arguments: &[&str],
    ) -> Result<String, StartupError>;
    fn run_command(&mut self, command: &str, arguments: &[&str]) -> Result<String, StartupError>;
    fn run_command_bytes(&mut self, command: &str, arguments: &[&str]) -> Result<Vec<u8>, String>;
    fn read_trimmed(&mut self, path: &str) -> Result<String, StartupError>;
    fn read_trimmed_allow_empty(&mut self, path: &str) -> Result<String, StartupError>;
    fn read_bytes(&mut self, path: &Path) -> Result<Vec<u8>, StartupError>;
    fn protected_bytes(&mut self, path: &Path) -> Result<Vec<u8>, StartupError>;
    fn is_directory(&mut self, path: &Path) -> bool;
    fn sha256_file(&mut self, path: &Path) -> Result<String, StartupError>;
    fn installed_module_build_id_note(&mut self, path: &Path) -> Result<Vec<u8>, StartupError>;
    fn secure_boot_enabled(&mut self) -> Result<bool, StartupError>;
    fn verify_running_kernel_build(&mut self, image_path: &str) -> Result<(), StartupError>;
}

struct SystemLiveIdentityAccess;

impl LiveIdentityAccess for SystemLiveIdentityAccess {
    fn command_one_line(
        &mut self,
        command: &str,
        arguments: &[&str],
    ) -> Result<String, StartupError> {
        command_one_line(command, arguments)
    }

    fn run_command(&mut self, command: &str, arguments: &[&str]) -> Result<String, StartupError> {
        run_command(command, arguments)
    }

    fn run_command_bytes(&mut self, command: &str, arguments: &[&str]) -> Result<Vec<u8>, String> {
        run_command_bytes(command, arguments)
    }

    fn read_trimmed(&mut self, path: &str) -> Result<String, StartupError> {
        read_trimmed(path)
    }

    fn read_trimmed_allow_empty(&mut self, path: &str) -> Result<String, StartupError> {
        read_trimmed_allow_empty(path)
    }

    fn read_bytes(&mut self, path: &Path) -> Result<Vec<u8>, StartupError> {
        fs::read(path).map_err(|error| compatibility_error(&path.display().to_string(), error))
    }

    fn protected_bytes(&mut self, path: &Path) -> Result<Vec<u8>, StartupError> {
        protected_bytes(path)
    }

    fn is_directory(&mut self, path: &Path) -> bool {
        path.is_dir()
    }

    fn sha256_file(&mut self, path: &Path) -> Result<String, StartupError> {
        sha256_file(path)
    }

    fn installed_module_build_id_note(&mut self, path: &Path) -> Result<Vec<u8>, StartupError> {
        installed_module_build_id_note(path)
    }

    fn secure_boot_enabled(&mut self) -> Result<bool, StartupError> {
        secure_boot_enabled()
    }

    fn verify_running_kernel_build(&mut self, image_path: &str) -> Result<(), StartupError> {
        verify_running_kernel_build(image_path)
    }
}

impl ProductionStartupDiscoveryEnvironment {
    fn new() -> Self {
        Self {
            protected_files: SystemOwnershipPlatform::new(),
        }
    }
}

pub(crate) struct QualifiedArchivePaths {
    protected_policy: PathBuf,
    package_provenance: PathBuf,
    kernel_image_certificate: PathBuf,
    package_manifest: PathBuf,
    package_manifest_signature: PathBuf,
    package_signing_certificate: PathBuf,
    package_artifacts: PathBuf,
}

fn qualified_archive_paths() -> Result<QualifiedArchivePaths, StartupError> {
    let installed = command_one_line("pacman", &["-Q", QUALIFIED_KERNEL_PACKAGE])?;
    let fields = installed.split_ascii_whitespace().collect::<Vec<_>>();
    let [package, version] = fields.as_slice() else {
        return Err(StartupError::Compatibility(
            "installed qualified-kernel identity is malformed".into(),
        ));
    };
    if *package != QUALIFIED_KERNEL_PACKAGE
        || version.is_empty()
        || !version.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'-')
        })
    {
        return Err(StartupError::Compatibility(
            "installed qualified-kernel identity is unsafe".into(),
        ));
    }
    Ok(qualified_archive_paths_for_version(version))
}

pub(crate) fn qualified_archive_paths_for_version(version: &str) -> QualifiedArchivePaths {
    let root =
        Path::new(QUALIFIED_ARCHIVE_PARENT).join(format!("pt31553-last-qualified-{version}"));
    QualifiedArchivePaths {
        protected_policy: root.join("protected-policy.toml"),
        package_provenance: root.join("package-provenance-v1.json"),
        kernel_image_certificate: root.join("enrolled-image-signing-certificate.pem"),
        package_manifest: root.join("build-output/SHA256SUMS"),
        package_manifest_signature: root.join("package-set-manifest.p7s"),
        package_signing_certificate: root.join("package-signing-certificate.pem"),
        package_artifacts: root.join("build-output"),
    }
}

/// Loads immutable authority inputs and verifies the live platform before ownership is acquired.
pub fn discover_system_startup() -> Result<SystemStartupDiscovery, StartupError> {
    let discovered = discover_startup_with(&mut ProductionStartupDiscoveryEnvironment::new())?;
    Ok(SystemStartupDiscovery {
        editable_config: discovered.editable_config,
        compatibility_declaration: discovered.compatibility_declaration,
        protected_policy: discovered.protected_policy,
        observation: discovered.observation,
        device: discovered.device,
        sources: discovered.sources,
    })
}

pub(crate) fn discover_startup_with<E>(
    environment: &mut E,
) -> Result<StartupDiscovery<E::Sources>, StartupError>
where
    E: StartupDiscoveryEnvironment,
{
    let editable_config = environment.read_editable_config()?;
    let (compatibility_declaration, declaration) = environment.load_compatibility_declaration()?;
    let (archive, protected_policy, provenance) = environment.load_qualified_archive()?;
    let mut sources = environment.discover_sources()?;
    let device = environment.discover_acer_device(&mut sources)?;
    let observation =
        environment.observe_live_identity(&declaration, &provenance, &archive, &device)?;

    Ok(StartupDiscovery {
        editable_config,
        compatibility_declaration,
        protected_policy,
        observation,
        device,
        sources,
    })
}

impl StartupDiscoveryEnvironment for ProductionStartupDiscoveryEnvironment {
    type Sources = SystemSampleSources;

    fn read_editable_config(&mut self) -> Result<String, StartupError> {
        fs::read_to_string(EDITABLE_CONFIG_PATH)
            .map_err(|error| configuration_error(EDITABLE_CONFIG_PATH, error))
    }

    fn load_compatibility_declaration(
        &mut self,
    ) -> Result<(String, CompatibilityDeclarationV1), StartupError> {
        let source = self
            .protected_files
            .read_root_owned_qualification_record(Path::new(COMPATIBILITY_DECLARATION_PATH))
            .map_err(|error| compatibility_error(COMPATIBILITY_DECLARATION_PATH, error))?;
        let declaration = parse_compatibility_v1(&source)
            .map_err(|error| StartupError::Compatibility(error.to_string()))?;
        Ok((source, declaration))
    }

    fn load_qualified_archive(
        &mut self,
    ) -> Result<(QualifiedArchivePaths, String, PackageProvenanceV1), StartupError> {
        let archive = qualified_archive_paths()?;
        let protected_policy = self
            .protected_files
            .read_root_owned_qualification_record(&archive.protected_policy)
            .map_err(|error| {
                compatibility_error(&archive.protected_policy.display().to_string(), error)
            })?;
        let provenance_source = self
            .protected_files
            .read_root_owned_qualification_record(&archive.package_provenance)
            .map_err(|error| {
                compatibility_error(&archive.package_provenance.display().to_string(), error)
            })?;
        let provenance = validate_package_provenance_v1(provenance_source.as_bytes())
            .map_err(|error| StartupError::Compatibility(error.to_string()))?;
        Ok((archive, protected_policy, provenance))
    }

    fn discover_sources(&mut self) -> Result<Self::Sources, StartupError> {
        SystemSampleSources::discover()
    }

    fn discover_acer_device(
        &mut self,
        sources: &mut Self::Sources,
    ) -> Result<AcerHwmonDevice, StartupError> {
        discover_acer_hwmon(sources.platform_mut(), Path::new(HWMON_ROOT))
            .map_err(|error| StartupError::Device(error.to_string()))
    }

    fn observe_live_identity(
        &mut self,
        declaration: &CompatibilityDeclarationV1,
        provenance: &PackageProvenanceV1,
        archive: &QualifiedArchivePaths,
        device: &AcerHwmonDevice,
    ) -> Result<CompatibilityObservation, StartupError> {
        observe_live_compatibility_with(
            &mut SystemLiveIdentityAccess,
            declaration,
            provenance,
            archive,
            device,
        )
    }
}

pub struct SystemSampleSources {
    platform: SystemOwnershipPlatform,
    coretemp: CoretempDevice,
    nvidia: NvidiaSmi,
    power: BoundExternalPower,
}

impl SystemSampleSources {
    fn discover() -> Result<Self, StartupError> {
        let mut platform = SystemOwnershipPlatform::new();
        let coretemp = discover_coretemp(&mut platform, Path::new(HWMON_ROOT))
            .map_err(|error| StartupError::Device(error.to_string()))?;
        let nvidia = NvidiaSmi::discover()?;
        let power = BoundExternalPower::discover(&mut platform, Path::new(POWER_SUPPLY_ROOT))?;
        Ok(Self {
            platform,
            coretemp,
            nvidia,
            power,
        })
    }

    fn platform_mut(&mut self) -> &mut SystemOwnershipPlatform {
        &mut self.platform
    }

    fn rediscover_with(
        files: &mut dyn IdentityBoundReadAccess,
        expected_nvidia: &NvidiaGpuSelector,
        window: Duration,
    ) -> Result<Self, StartupError> {
        let started = Instant::now();
        let coretemp = discover_coretemp(files, Path::new(HWMON_ROOT))
            .map_err(|error| StartupError::Device(error.to_string()))?;
        let remaining = window.checked_sub(started.elapsed()).ok_or_else(|| {
            StartupError::Device("sensor rediscovery exceeded its deadline".into())
        })?;
        let nvidia = NvidiaSmi::rediscover_with_timeout(expected_nvidia, remaining)?;
        let power = BoundExternalPower::discover_readonly(files, Path::new(POWER_SUPPLY_ROOT))?;
        Ok(Self {
            platform: SystemOwnershipPlatform::new(),
            coretemp,
            nvidia,
            power,
        })
    }
}

impl SampleSources for SystemSampleSources {
    fn sample_cpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        let deadline = source_platform_deadline(capture, &mut self.platform)?;
        let value = self
            .coretemp
            .sample(&mut DeadlineReadAccess {
                files: &mut self.platform,
                deadline,
            })
            .map_err(|error| SampleSourceError::new(error.to_string()))?;
        Ok(capture.capture(value))
    }

    fn sample_gpu(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
        let selector = self.nvidia.selector.clone();
        let timeout = capture
            .remaining()
            .ok_or_else(|| SampleSourceError::new("GPU sample deadline expired"))?;
        let value = sample_nvidia_gpu(
            &mut TimedNvidiaSmi {
                inner: &mut self.nvidia,
                timeout,
            },
            &selector,
        )
        .map_err(|error| SampleSourceError::new(error.to_string()))?;
        Ok(capture.capture(value))
    }

    fn observe_external_power(
        &mut self,
        capture: &mut SampleCapture<'_>,
    ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
        let deadline = source_platform_deadline(capture, &mut self.platform)?;
        let value = self.power.observe_before(&mut self.platform, deadline);
        Ok(capture.capture(value))
    }
}

fn source_platform_deadline(
    capture: &mut SampleCapture<'_>,
    platform: &mut SystemOwnershipPlatform,
) -> Result<Duration, SampleSourceError> {
    let remaining = capture
        .remaining()
        .ok_or_else(|| SampleSourceError::new("sample deadline expired"))?;
    platform
        .monotonic_now()
        .checked_add(remaining)
        .ok_or_else(|| SampleSourceError::new("sample deadline overflowed"))
}

/// Fresh production CPU/GPU/power source discovery used after a recoverable sensor fault.
pub struct SystemSensorSourceDiscovery<S = SystemSampleSources> {
    rediscover: Box<RediscoverSources<S>>,
}

type RediscoverSources<S> =
    dyn FnMut(&mut dyn IdentityBoundReadAccess, Duration) -> Result<S, SampleSourceError>;

struct DeadlineReadAccess<'a> {
    files: &'a mut dyn BoundedIdentityBoundReadAccess,
    deadline: Duration,
}

impl IdentityBoundReadAccess for DeadlineReadAccess<'_> {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        self.files.read_before(path, self.deadline)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        self.files.list_before(directory, self.deadline)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        let (directory, child) = direct_child_parts(path)?;
        let directory_identity = self.files.identity_before(directory, self.deadline)?;
        let child_identity = self.files.identity_before(path, self.deadline)?;
        self.files.permissions_bound_before(
            directory,
            directory_identity,
            child,
            child_identity,
            self.deadline,
        )
    }

    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        self.files.identity_before(path, self.deadline)
    }

    fn permissions_child_bound(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
    ) -> Result<FilePermissions, PlatformError> {
        self.files.permissions_bound_before(
            directory,
            expected_directory,
            child,
            expected_child,
            self.deadline,
        )
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        let path = direct_child_path(directory, child)?;
        let child_identity = self.files.identity_before(&path, self.deadline)?;
        self.files
            .read_bound_before(directory, expected, child, child_identity, self.deadline)
    }

    fn read_child_bound(
        &mut self,
        directory: &Path,
        expected_directory: FileIdentity,
        child: &str,
        expected_child: FileIdentity,
    ) -> Result<String, PlatformError> {
        self.files.read_bound_before(
            directory,
            expected_directory,
            child,
            expected_child,
            self.deadline,
        )
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.files
            .list_bound_before(directory, expected, self.deadline)
    }
}

fn direct_child_parts(path: &Path) -> Result<(&Path, &str), PlatformError> {
    let directory = path.parent().ok_or_else(|| {
        PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("sensor endpoint has no parent: {}", path.display()),
        )
    })?;
    let child = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            PlatformError::new(
                PlatformErrorKind::Unavailable,
                format!("sensor endpoint is not UTF-8: {}", path.display()),
            )
        })?;
    Ok((directory, child))
}

fn direct_child_path(directory: &Path, child: &str) -> Result<PathBuf, PlatformError> {
    let path = directory.join(child);
    if path.parent() != Some(directory) {
        return Err(PlatformError::new(
            PlatformErrorKind::Unavailable,
            format!("sensor endpoint is not a direct child: {child}"),
        ));
    }
    Ok(path)
}

impl std::fmt::Debug for SystemSensorSourceDiscovery<SystemSampleSources> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemSensorSourceDiscovery")
            .finish_non_exhaustive()
    }
}

impl SystemSensorSourceDiscovery<SystemSampleSources> {
    pub fn for_admitted_sources(sources: &SystemSampleSources) -> Self {
        let expected_nvidia = sources.nvidia.selector.clone();
        Self {
            rediscover: Box::new(move |files, window| {
                SystemSampleSources::rediscover_with(files, &expected_nvidia, window)
                    .map_err(|error| SampleSourceError::new(error.to_string()))
            }),
        }
    }
}

impl<S> SystemSensorSourceDiscovery<S> {
    #[cfg(feature = "acceptance-fixture")]
    pub(crate) fn injected(
        rediscover: impl FnMut(
            &mut dyn IdentityBoundReadAccess,
            Duration,
        ) -> Result<S, SampleSourceError>
        + 'static,
    ) -> Self {
        Self {
            rediscover: Box::new(rediscover),
        }
    }
}

impl<S> SensorSourceDiscovery for SystemSensorSourceDiscovery<S>
where
    S: SampleSources,
{
    type Sources = S;

    fn rediscover(
        &mut self,
        files: &mut dyn BoundedIdentityBoundReadAccess,
        deadline: Duration,
    ) -> Result<Self::Sources, SampleSourceError> {
        (self.rediscover)(
            &mut DeadlineReadAccess { files, deadline },
            SENSOR_REDISCOVERY_WINDOW,
        )
    }
}

struct BoundExternalPower {
    root: PathBuf,
    root_identity: FileIdentity,
    supplies: Vec<BoundPowerSupply>,
}

struct BoundPowerSupply {
    path: PathBuf,
    identity: FileIdentity,
    type_identity: FileIdentity,
    kind: String,
    online_identity: Option<FileIdentity>,
}

impl BoundExternalPower {
    fn discover_readonly(
        files: &mut dyn IdentityBoundReadAccess,
        root: &Path,
    ) -> Result<Self, StartupError> {
        let root_identity = files
            .identity(root)
            .map_err(|error| StartupError::Device(error.to_string()))?;
        let mut candidates = files
            .list_bound(root, root_identity)
            .map_err(|error| StartupError::Device(error.to_string()))?;
        candidates.sort();
        let mut supplies = Vec::with_capacity(candidates.len());
        for path in candidates {
            if path.parent() != Some(root) {
                return Err(StartupError::Device(
                    "power-supply discovery returned a non-child path".into(),
                ));
            }
            let identity = files
                .identity(&path)
                .map_err(|error| StartupError::Device(error.to_string()))?;
            let type_path = path.join("type");
            let type_identity = files
                .identity(&type_path)
                .map_err(|error| StartupError::Device(error.to_string()))?;
            let kind = files
                .read_child_bound(&path, identity, "type", type_identity)
                .map_err(|error| StartupError::Device(error.to_string()))?;
            let online_identity = if kind == "Mains\n" {
                Some(
                    files
                        .identity(&path.join("online"))
                        .map_err(|error| StartupError::Device(error.to_string()))?,
                )
            } else {
                None
            };
            supplies.push(BoundPowerSupply {
                path,
                identity,
                type_identity,
                kind,
                online_identity,
            });
        }
        if !supplies
            .iter()
            .any(|supply| supply.online_identity.is_some())
        {
            return Err(StartupError::Device(
                "no identity-bound Mains power supply found".into(),
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
            root_identity,
            supplies,
        })
    }

    fn discover(
        files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
        root: &Path,
    ) -> Result<Self, StartupError> {
        let root_identity = files
            .identity_before(root, Duration::MAX)
            .map_err(|error| StartupError::Device(error.to_string()))?;
        let mut candidates = files
            .list_bound_before(root, root_identity, Duration::MAX)
            .map_err(|error| StartupError::Device(error.to_string()))?;
        candidates.sort();
        let mut supplies = Vec::with_capacity(candidates.len());
        for path in candidates {
            if path.parent() != Some(root) {
                return Err(StartupError::Device(
                    "power-supply discovery returned a non-child path".into(),
                ));
            }
            let identity = files
                .identity_before(&path, Duration::MAX)
                .map_err(|error| StartupError::Device(error.to_string()))?;
            let type_path = path.join("type");
            let type_identity = files
                .identity_before(&type_path, Duration::MAX)
                .map_err(|error| StartupError::Device(error.to_string()))?;
            let kind = files
                .read_bound_before(&path, identity, "type", type_identity, Duration::MAX)
                .map_err(|error| StartupError::Device(error.to_string()))?;
            let online_identity = if kind == "Mains\n" {
                Some(
                    files
                        .identity_before(&path.join("online"), Duration::MAX)
                        .map_err(|error| StartupError::Device(error.to_string()))?,
                )
            } else {
                None
            };
            supplies.push(BoundPowerSupply {
                path,
                identity,
                type_identity,
                kind,
                online_identity,
            });
        }
        if !supplies
            .iter()
            .any(|supply| supply.online_identity.is_some())
        {
            return Err(StartupError::Device(
                "no identity-bound Mains power supply found".into(),
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
            root_identity,
            supplies,
        })
    }

    #[cfg(test)]
    fn observe(&self, files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized)) -> ExternalPower {
        self.observe_before(files, Duration::MAX)
    }

    fn observe_before(
        &self,
        files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
        deadline: Duration,
    ) -> ExternalPower {
        let Some(first) = self.observe_once(files, deadline) else {
            return ExternalPower::Unknown;
        };
        let Some(second) = self.observe_once(files, deadline) else {
            return ExternalPower::Unknown;
        };
        if first != second {
            return ExternalPower::Unknown;
        }
        if first.values().all(|online| *online) {
            ExternalPower::Connected
        } else if first.values().all(|online| !*online) {
            ExternalPower::Disconnected
        } else {
            ExternalPower::Unknown
        }
    }

    fn observe_once(
        &self,
        files: &mut (impl BoundedIdentityBoundFileAccess + ?Sized),
        deadline: Duration,
    ) -> Option<BTreeMap<PathBuf, bool>> {
        let mut current = files
            .list_bound_before(&self.root, self.root_identity, deadline)
            .ok()?;
        current.sort();
        if current
            != self
                .supplies
                .iter()
                .map(|supply| supply.path.clone())
                .collect::<Vec<_>>()
        {
            return None;
        }
        let mut mains = BTreeMap::new();
        for supply in &self.supplies {
            if files.identity_before(&supply.path, deadline).ok()? != supply.identity
                || files
                    .identity_before(&supply.path.join("type"), deadline)
                    .ok()?
                    != supply.type_identity
                || files
                    .read_bound_before(
                        &supply.path,
                        supply.identity,
                        "type",
                        supply.type_identity,
                        deadline,
                    )
                    .ok()?
                    != supply.kind
            {
                return None;
            }
            let Some(online_identity) = supply.online_identity else {
                continue;
            };
            if files
                .identity_before(&supply.path.join("online"), deadline)
                .ok()?
                != online_identity
            {
                return None;
            }
            let online = match files
                .read_bound_before(
                    &supply.path,
                    supply.identity,
                    "online",
                    online_identity,
                    deadline,
                )
                .ok()?
                .as_str()
            {
                "1\n" => true,
                "0\n" => false,
                _ => return None,
            };
            mains.insert(supply.path.clone(), online);
        }
        (!mains.is_empty()).then_some(mains)
    }
}

#[derive(Debug)]
struct NvidiaSmi {
    selector: NvidiaGpuSelector,
}

impl NvidiaSmi {
    fn discover() -> Result<Self, StartupError> {
        let output = run_nvidia_smi(&[
            "--query-gpu=uuid,pci.bus_id,temperature.gpu",
            "--format=csv,noheader,nounits",
        ])
        .map_err(StartupError::Device)?;
        Self::from_discovery_output(&output)
    }

    #[cfg(test)]
    fn discover_with(access: &mut impl LiveIdentityAccess) -> Result<Self, StartupError> {
        let output = access
            .run_command(
                "nvidia-smi",
                &[
                    "--query-gpu=uuid,pci.bus_id,temperature.gpu",
                    "--format=csv,noheader,nounits",
                ],
            )
            .map_err(|error| StartupError::Device(error.to_string()))?;
        Self::from_discovery_output(&output)
    }

    fn from_discovery_output(output: &str) -> Result<Self, StartupError> {
        let rows = output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(StartupError::Device(format!(
                "NVIDIA GPU discovery expected one device, found {}",
                rows.len()
            )));
        }
        let sample = parse_nvidia_smi_row(rows[0])?;
        let selector = NvidiaGpuSelector::uuid(sample.uuid())
            .map_err(|error| StartupError::Device(error.to_string()))?;
        Ok(Self { selector })
    }

    fn rediscover_with_timeout(
        expected: &NvidiaGpuSelector,
        timeout: Duration,
    ) -> Result<Self, StartupError> {
        let id = format!("--id={}", expected.value());
        let output = run_nvidia_smi_command(
            Path::new("nvidia-smi"),
            &[
                id.as_str(),
                "--query-gpu=uuid,pci.bus_id,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            timeout,
        )
        .map_err(StartupError::Device)?;
        Self::from_rediscovery_output(&output, expected)
    }

    fn sample_by_identity_with_timeout(
        &mut self,
        selector: &NvidiaGpuSelector,
        timeout: Duration,
    ) -> Result<NvmlGpuSample, NvmlError> {
        let id = format!("--id={}", selector.value());
        let output = run_nvidia_smi_command(
            Path::new("nvidia-smi"),
            &[
                id.as_str(),
                "--query-gpu=uuid,pci.bus_id,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            timeout,
        )
        .map_err(|message| NvmlError::new(NvmlErrorKind::LibraryFailure, message))?;
        let rows = output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(NvmlError::new(
                NvmlErrorKind::InvalidState,
                format!(
                    "identity-directed NVIDIA query returned {} rows",
                    rows.len()
                ),
            ));
        }
        parse_nvidia_smi_row_raw(rows[0])
            .map_err(|message| NvmlError::new(NvmlErrorKind::InvalidState, message))
    }

    fn from_rediscovery_output(
        output: &str,
        expected: &NvidiaGpuSelector,
    ) -> Result<Self, StartupError> {
        let rows = output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(StartupError::Device(format!(
                "identity-directed NVIDIA rediscovery returned {} rows",
                rows.len()
            )));
        }
        let sample = parse_nvidia_smi_row(rows[0])?;
        let observed = NvidiaGpuSelector::uuid(sample.uuid())
            .map_err(|error| StartupError::Device(error.to_string()))?;
        if &observed != expected {
            return Err(StartupError::Device(format!(
                "NVIDIA GPU identity changed during rediscovery: expected {}, observed {}",
                expected.value(),
                observed.value()
            )));
        }
        Ok(Self {
            selector: expected.clone(),
        })
    }
}

impl NvmlAccess for NvidiaSmi {
    fn sample_by_identity(
        &mut self,
        selector: &NvidiaGpuSelector,
    ) -> Result<NvmlGpuSample, NvmlError> {
        self.sample_by_identity_with_timeout(selector, Duration::from_secs(1))
    }
}

struct TimedNvidiaSmi<'a> {
    inner: &'a mut NvidiaSmi,
    timeout: Duration,
}

impl NvmlAccess for TimedNvidiaSmi<'_> {
    fn sample_by_identity(
        &mut self,
        selector: &NvidiaGpuSelector,
    ) -> Result<NvmlGpuSample, NvmlError> {
        self.inner
            .sample_by_identity_with_timeout(selector, self.timeout)
    }
}

fn parse_nvidia_smi_row(row: &str) -> Result<NvmlGpuSample, StartupError> {
    parse_nvidia_smi_row_raw(row).map_err(StartupError::Device)
}

fn parse_nvidia_smi_row_raw(row: &str) -> Result<NvmlGpuSample, String> {
    let fields = row.split(',').map(str::trim).collect::<Vec<_>>();
    let [uuid, pci_bus_id, temperature] = fields.as_slice() else {
        return Err("NVIDIA query returned a malformed row".into());
    };
    let temperature = temperature
        .parse::<f64>()
        .map_err(|_| "NVIDIA query returned a malformed temperature".to_owned())?;
    Ok(NvmlGpuSample::new(*uuid, *pci_bus_id, temperature))
}

fn observe_live_compatibility_with(
    access: &mut impl LiveIdentityAccess,
    declaration: &CompatibilityDeclarationV1,
    provenance: &PackageProvenanceV1,
    archive: &QualifiedArchivePaths,
    device: &AcerHwmonDevice,
) -> Result<CompatibilityObservation, StartupError> {
    validate_provenance(declaration, provenance)?;
    verify_package_set_signature(access, provenance, archive)?;
    verify_installed_packages(access, provenance)?;
    verify_installed_modules(access, provenance)?;
    verify_kernel_image_signature(access, provenance, &archive.kernel_image_certificate)?;

    let hardware = HardwareIdentity {
        dmi_product_name: access.read_trimmed("/sys/class/dmi/id/product_name")?,
        dmi_board_name: access.read_trimmed("/sys/class/dmi/id/board_name")?,
        bios_version: access.read_trimmed("/sys/class/dmi/id/bios_version")?,
    };
    let release = access.read_trimmed("/proc/sys/kernel/osrelease")?;
    let module_path = access.command_one_line("modinfo", &["-n", "acer_wmi"])?;
    let vermagic = access.command_one_line("modinfo", &["-F", "vermagic", "acer_wmi"])?;
    let installed_srcversion =
        access.command_one_line("modinfo", &["-F", "srcversion", "acer_wmi"])?;
    let loaded_srcversion = access.read_trimmed("/sys/module/acer_wmi/srcversion")?;
    if installed_srcversion != loaded_srcversion {
        return Err(StartupError::Compatibility(
            "loaded acer_wmi identity or signature is untrusted".into(),
        ));
    }
    let taint = access.read_trimmed_allow_empty("/sys/module/acer_wmi/taint")?;
    if !taint.is_empty() {
        return Err(StartupError::Compatibility(format!(
            "loaded acer_wmi is tainted: {taint}"
        )));
    }
    if module_path != declaration.module.path {
        return Err(StartupError::Compatibility(format!(
            "module path mismatch: {module_path}"
        )));
    }
    require_package_owner(
        access,
        &provenance.kernel.image_path,
        &declaration.kernel.package,
    )?;
    require_package_owner(
        access,
        &declaration.module.path,
        &declaration.kernel.package,
    )?;

    let image_sha256 = access.sha256_file(Path::new(&provenance.kernel.image_path))?;
    let module_sha256 = access.sha256_file(Path::new(&declaration.module.path))?;
    let config_sha256 = access.sha256_file(Path::new(&provenance.kernel.config_path))?;
    let module_certificate_sha256 =
        access.sha256_file(Path::new(&provenance.kernel.module_trust_certificate_path))?;
    if config_sha256 != provenance.kernel.config_sha256
        || module_certificate_sha256 != provenance.kernel.module_trust_certificate_fingerprint
    {
        return Err(StartupError::Compatibility(
            "installed kernel trust artifacts do not match package provenance".into(),
        ));
    }
    let secure_boot_enabled = access.secure_boot_enabled()?;

    Ok(CompatibilityObservation {
        hardware,
        kernel: fan_control_core::KernelIdentity {
            release,
            package: provenance.kernel.package.clone(),
            source_commit: provenance.build.source_commit.clone(),
            image_sha256: image_sha256.clone(),
            image_signer_fingerprint: provenance.kernel.image_signer_fingerprint.clone(),
        },
        module: ModuleIdentity {
            name: "acer_wmi".into(),
            path: module_path,
            sha256: module_sha256.clone(),
            signer_fingerprint: provenance
                .kernel
                .module_trust_certificate_fingerprint
                .clone(),
            vermagic,
            provenance: ModuleProvenance::InTree,
        },
        secure_boot_enabled,
        kernel_image_trusted: secure_boot_enabled
            && image_sha256 == declaration.kernel.image_sha256,
        module_signature_trusted: secure_boot_enabled && module_sha256 == declaration.module.sha256,
        fan_abi: ObservedFanAbi {
            hwmon_name: "acer".into(),
            endpoints: device_endpoint_names(device),
        },
        backend_evidence_completeness: EvidenceCompleteness::Complete,
        backends: vec![FanWriteBackend::AcerHwmon],
        capability_evidence_completeness: EvidenceCompleteness::Complete,
        enabled_capabilities: Vec::new(),
    })
}

fn verify_package_set_signature(
    access: &mut impl LiveIdentityAccess,
    provenance: &PackageProvenanceV1,
    archive: &QualifiedArchivePaths,
) -> Result<(), StartupError> {
    let expected_signature_sha256 = provenance
        .build
        .package_manifest_signature_sha256
        .as_deref()
        .ok_or_else(|| {
            StartupError::Compatibility("package manifest signature identity is missing".into())
        })?;
    let manifest = access.protected_bytes(&archive.package_manifest)?;
    let signature = access.protected_bytes(&archive.package_manifest_signature)?;
    let certificate = access.protected_bytes(&archive.package_signing_certificate)?;
    if format!("{:x}", Sha256::digest(&signature)) != expected_signature_sha256 {
        return Err(StartupError::Compatibility(
            "package manifest signature hash mismatch".into(),
        ));
    }

    let manifest_file = stage_verified_file("pt31553-package-manifest-", &manifest)?;
    let signature_file = stage_verified_file("pt31553-package-signature-", &signature)?;
    let certificate_file = stage_verified_file("pt31553-package-certificate-", &certificate)?;
    let manifest_path = utf8_temporary_path(&manifest_file)?;
    let signature_path = utf8_temporary_path(&signature_file)?;
    let certificate_path = utf8_temporary_path(&certificate_file)?;

    let certificate_der = access
        .run_command_bytes(
            "openssl",
            &["x509", "-in", certificate_path, "-outform", "DER"],
        )
        .map_err(StartupError::Compatibility)?;
    if certificate.is_empty()
        || format!("{:x}", Sha256::digest(certificate_der))
            != provenance.build.package_manifest_signer_fingerprint
    {
        return Err(StartupError::Compatibility(
            "package manifest signer certificate mismatch".into(),
        ));
    }
    access.run_command(
        "openssl",
        &[
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            signature_path,
            "-content",
            manifest_path,
            "-certfile",
            certificate_path,
            "-nointern",
            "-noverify",
            "-out",
            "/dev/null",
        ],
    )?;

    let manifest_hashes = parse_sha256_manifest(&manifest)?;
    for package in &provenance.packages {
        let filename = format!(
            "{}-{}-{}.pkg.tar.zst",
            package.name, package.version, package.architecture
        );
        if manifest_hashes.get(&filename) != Some(&package.sha256) {
            return Err(StartupError::Compatibility(format!(
                "signed package manifest mismatch: {}",
                package.name
            )));
        }
        let archive_path = archive.package_artifacts.join(&filename);
        if access.sha256_file(&archive_path)? != package.sha256 {
            return Err(StartupError::Compatibility(format!(
                "retained package artifact hash mismatch: {}",
                package.name
            )));
        }
    }
    Ok(())
}

fn parse_sha256_manifest(source: &[u8]) -> Result<BTreeMap<String, String>, StartupError> {
    let source = std::str::from_utf8(source)
        .map_err(|_| StartupError::Compatibility("package manifest is not UTF-8".into()))?;
    let mut hashes = BTreeMap::new();
    for line in source.lines() {
        let Some((hash, path)) = line.split_once("  ") else {
            return Err(StartupError::Compatibility(
                "package manifest contains a malformed entry".into(),
            ));
        };
        if !valid_hash(hash)
            || path.is_empty()
            || Path::new(path).is_absolute()
            || Path::new(path).components().count() != 1
            || hashes.insert(path.to_owned(), hash.to_owned()).is_some()
        {
            return Err(StartupError::Compatibility(
                "package manifest contains an unsafe or duplicate entry".into(),
            ));
        }
    }
    if hashes.is_empty() {
        return Err(StartupError::Compatibility(
            "package manifest is empty".into(),
        ));
    }
    Ok(hashes)
}

fn stage_verified_file(
    prefix: &str,
    contents: &[u8],
) -> Result<tempfile::NamedTempFile, StartupError> {
    let mut file = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile()
        .map_err(|error| {
            StartupError::Compatibility(format!("cannot stage verified artifact: {error}"))
        })?;
    file.write_all(contents).map_err(|error| {
        StartupError::Compatibility(format!("cannot stage verified artifact: {error}"))
    })?;
    file.as_file().sync_all().map_err(|error| {
        StartupError::Compatibility(format!("cannot stage verified artifact: {error}"))
    })?;
    Ok(file)
}

fn utf8_temporary_path(file: &tempfile::NamedTempFile) -> Result<&str, StartupError> {
    file.path()
        .to_str()
        .ok_or_else(|| StartupError::Compatibility("temporary artifact path is not UTF-8".into()))
}

fn verify_installed_packages(
    access: &mut impl LiveIdentityAccess,
    provenance: &PackageProvenanceV1,
) -> Result<(), StartupError> {
    for package in &provenance.packages {
        let installed = access.command_one_line("pacman", &["-Q", &package.name])?;
        let expected = format!("{} {}", package.name, package.version);
        if installed != expected {
            return Err(StartupError::Compatibility(format!(
                "installed package mismatch: expected {expected}, got {installed}"
            )));
        }
    }
    Ok(())
}

fn verify_installed_modules(
    access: &mut impl LiveIdentityAccess,
    provenance: &PackageProvenanceV1,
) -> Result<(), StartupError> {
    let certificate_key_id = certificate_subject_key_id(
        access,
        &provenance.kernel.module_trust_certificate_path,
        "DER",
    )?;
    for module in &provenance.modules {
        require_package_owner(access, &module.path, &module.package)?;
        if access.sha256_file(Path::new(&module.path))? != module.sha256 {
            return Err(StartupError::Compatibility(format!(
                "installed module hash mismatch: {}",
                module.name
            )));
        }
        let vermagic = access.command_one_line("modinfo", &["-F", "vermagic", &module.path])?;
        let signer = access.command_one_line("modinfo", &["-F", "signer", &module.path])?;
        let signature_key = normalize_key_id(
            &access.command_one_line("modinfo", &["-F", "sig_key", &module.path])?,
        );
        if vermagic != module.vermagic || signer.is_empty() || signature_key != certificate_key_id {
            return Err(StartupError::Compatibility(format!(
                "installed module signature or ABI mismatch: {}",
                module.name
            )));
        }

        let loaded_directory = format!("/sys/module/{}", module.name);
        if access.is_directory(Path::new(&loaded_directory)) {
            verify_loaded_module_identity(access, module)?;
        }
    }

    let nvidia = provenance
        .modules
        .iter()
        .find(|module| module.name == "nvidia")
        .ok_or_else(|| StartupError::Compatibility("NVIDIA module provenance missing".into()))?;
    let installed_version = access.command_one_line("modinfo", &["-F", "version", "nvidia"])?;
    let loaded_version = access.read_trimmed("/sys/module/nvidia/version")?;
    if installed_version != nvidia.source.revision || loaded_version != nvidia.source.revision {
        return Err(StartupError::Compatibility(
            "loaded NVIDIA module version does not match provenance".into(),
        ));
    }
    Ok(())
}

fn verify_loaded_module_identity(
    access: &mut impl LiveIdentityAccess,
    module: &PackageProvenanceModuleV1,
) -> Result<(), StartupError> {
    let resolved_path = access.command_one_line("modinfo", &["-n", &module.name])?;
    if resolved_path != module.path {
        return Err(StartupError::Compatibility(format!(
            "loaded module path mismatch: {}",
            module.name
        )));
    }

    let installed_srcversion =
        access.command_one_line("modinfo", &["-F", "srcversion", &module.path])?;
    let loaded_srcversion =
        access.read_trimmed(&format!("/sys/module/{}/srcversion", module.name))?;
    if installed_srcversion != loaded_srcversion {
        return Err(StartupError::Compatibility(format!(
            "loaded module source identity mismatch: {}",
            module.name
        )));
    }

    let installed_note = access.installed_module_build_id_note(Path::new(&module.path))?;
    let loaded_note = access.read_bytes(Path::new(&format!(
        "/sys/module/{}/notes/.note.gnu.build-id",
        module.name
    )))?;
    if installed_note != loaded_note {
        return Err(StartupError::Compatibility(format!(
            "loaded module build identity mismatch: {}",
            module.name
        )));
    }
    Ok(())
}

fn installed_module_build_id_note(path: &Path) -> Result<Vec<u8>, StartupError> {
    let bytes =
        fs::read(path).map_err(|error| compatibility_error(&path.display().to_string(), error))?;
    let image = if path.extension().is_some_and(|extension| extension == "zst") {
        zstd::stream::decode_all(bytes.as_slice()).map_err(|error| {
            StartupError::Compatibility(format!(
                "cannot decompress installed module {}: {error}",
                path.display()
            ))
        })?
    } else {
        bytes
    };
    let object = object::File::parse(image.as_slice()).map_err(|error| {
        StartupError::Compatibility(format!(
            "cannot parse installed module {}: {error}",
            path.display()
        ))
    })?;
    object
        .section_by_name(".note.gnu.build-id")
        .ok_or_else(|| {
            StartupError::Compatibility(format!(
                "installed module has no build identity: {}",
                path.display()
            ))
        })?
        .data()
        .map(Vec::from)
        .map_err(|error| {
            StartupError::Compatibility(format!(
                "cannot read installed module build identity {}: {error}",
                path.display()
            ))
        })
}

fn verify_kernel_image_signature(
    access: &mut impl LiveIdentityAccess,
    provenance: &PackageProvenanceV1,
    kernel_image_certificate: &Path,
) -> Result<(), StartupError> {
    let certificate = access.protected_bytes(kernel_image_certificate)?;
    let mut verified_certificate = tempfile::Builder::new()
        .prefix("pt31553-verified-certificate-")
        .tempfile()
        .map_err(|error| {
            StartupError::Compatibility(format!("cannot stage verified certificate: {error}"))
        })?;
    verified_certificate
        .write_all(&certificate)
        .map_err(|error| {
            StartupError::Compatibility(format!("cannot stage verified certificate: {error}"))
        })?;
    verified_certificate.as_file().sync_all().map_err(|error| {
        StartupError::Compatibility(format!("cannot stage verified certificate: {error}"))
    })?;
    let certificate_path = verified_certificate.path().to_str().ok_or_else(|| {
        StartupError::Compatibility("temporary certificate path is not UTF-8".into())
    })?;
    let certificate_der = access
        .run_command_bytes(
            "openssl",
            &["x509", "-in", certificate_path, "-outform", "DER"],
        )
        .map_err(StartupError::Compatibility)?;
    if certificate.is_empty()
        || format!("{:x}", Sha256::digest(certificate_der))
            != provenance.kernel.image_signer_fingerprint
    {
        return Err(StartupError::Compatibility(
            "kernel image signer certificate mismatch".into(),
        ));
    }
    access.run_command(
        "sbverify",
        &["--cert", certificate_path, &provenance.kernel.image_path],
    )?;
    access.verify_running_kernel_build(&provenance.kernel.image_path)?;
    Ok(())
}

fn verify_running_kernel_build(image_path: &str) -> Result<(), StartupError> {
    // Linux boot protocol: the compressed payload starts at the protected-mode kernel base plus
    // `payload_offset`. The qualified package fixes Zstandard as the payload format.
    const SETUP_SECTS_OFFSET: usize = 0x1f1;
    const PAYLOAD_OFFSET_OFFSET: usize = 0x248;
    const PAYLOAD_LENGTH_OFFSET: usize = 0x24c;
    const DEFAULT_SETUP_SECTS: usize = 4;
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

    let image = fs::read(image_path).map_err(|error| compatibility_error(image_path, error))?;
    let setup_sects = image
        .get(SETUP_SECTS_OFFSET)
        .copied()
        .ok_or_else(|| StartupError::Compatibility("kernel image header is truncated".into()))?;
    let setup_sects = if setup_sects == 0 {
        DEFAULT_SETUP_SECTS
    } else {
        usize::from(setup_sects)
    };
    let payload_offset = little_endian_u32(&image, PAYLOAD_OFFSET_OFFSET)? as usize;
    let payload_length = little_endian_u32(&image, PAYLOAD_LENGTH_OFFSET)? as usize;
    let payload_start = (setup_sects + 1)
        .checked_mul(512)
        .and_then(|base| base.checked_add(payload_offset))
        .ok_or_else(|| StartupError::Compatibility("kernel payload offset overflow".into()))?;
    let payload_end = payload_start
        .checked_add(payload_length)
        .ok_or_else(|| StartupError::Compatibility("kernel payload length overflow".into()))?;
    let payload = image
        .get(payload_start..payload_end)
        .ok_or_else(|| StartupError::Compatibility("kernel payload is truncated".into()))?;
    if !payload.starts_with(&ZSTD_MAGIC) {
        return Err(StartupError::Compatibility(
            "qualified kernel payload is not Zstandard".into(),
        ));
    }
    let mut decoder = zstd::stream::read::Decoder::with_buffer(payload)
        .map_err(|error| {
            StartupError::Compatibility(format!("cannot open qualified kernel payload: {error}"))
        })?
        .single_frame();
    let mut vmlinux = Vec::new();
    decoder.read_to_end(&mut vmlinux).map_err(|error| {
        StartupError::Compatibility(format!("cannot decompress qualified kernel image: {error}"))
    })?;
    let object = object::File::parse(vmlinux.as_slice()).map_err(|error| {
        StartupError::Compatibility(format!("cannot parse qualified kernel image: {error}"))
    })?;
    let installed_notes = object
        .section_by_name(".notes")
        .ok_or_else(|| StartupError::Compatibility("kernel image has no build notes".into()))?
        .data()
        .map_err(|error| {
            StartupError::Compatibility(format!("cannot read kernel image build notes: {error}"))
        })?;
    let running_notes = fs::read("/sys/kernel/notes")
        .map_err(|error| compatibility_error("/sys/kernel/notes", error))?;
    if installed_notes != running_notes {
        return Err(StartupError::Compatibility(
            "running kernel build identity does not match the signed installed image".into(),
        ));
    }
    Ok(())
}

fn little_endian_u32(bytes: &[u8], offset: usize) -> Result<u32, StartupError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| StartupError::Compatibility("kernel image header is truncated".into()))?;
    Ok(u32::from_le_bytes(value))
}

fn certificate_subject_key_id(
    access: &mut impl LiveIdentityAccess,
    path: &str,
    format: &str,
) -> Result<String, StartupError> {
    let output = access.run_command(
        "openssl",
        &[
            "x509",
            "-inform",
            format,
            "-in",
            path,
            "-noout",
            "-ext",
            "subjectKeyIdentifier",
        ],
    )?;
    let key_id = output
        .lines()
        .map(normalize_key_id)
        .find(|line| line.len() >= 40)
        .ok_or_else(|| StartupError::Compatibility("module certificate has no key ID".into()))?;
    Ok(key_id)
}

fn normalize_key_id(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_hexdigit)
        .flat_map(char::to_lowercase)
        .collect()
}

fn protected_bytes(path: &Path) -> Result<Vec<u8>, StartupError> {
    fan_control_core::validate_root_owned_protected_file(
        path,
        fan_control_core::ProtectedFileRequirement::Regular,
    )
    .map_err(|error| compatibility_error(&path.display().to_string(), error))?;
    fs::read(path).map_err(|error| compatibility_error(&path.display().to_string(), error))
}

fn device_endpoint_names(device: &AcerHwmonDevice) -> Vec<String> {
    [
        device.cpu().pwm(),
        device.cpu().enable(),
        device.cpu().tachometer(),
        device.gpu().pwm(),
        device.gpu().enable(),
        device.gpu().tachometer(),
    ]
    .into_iter()
    .filter_map(|path| path.file_name()?.to_str().map(str::to_owned))
    .collect()
}

fn validate_provenance(
    declaration: &CompatibilityDeclarationV1,
    provenance: &PackageProvenanceV1,
) -> Result<(), StartupError> {
    validate_package_provenance_compatibility_v1(provenance, declaration)
        .map_err(|error| StartupError::Compatibility(error.to_string()))?;
    let valid = valid_identity_hash(&provenance.build.package_manifest_signer_fingerprint)
        && provenance
            .build
            .package_manifest_signature_sha256
            .as_ref()
            .is_some_and(|hash| valid_identity_hash(hash))
        && provenance.modules.iter().all(|module| {
            valid_identity_hash(&module.sha256) && valid_identity_hash(&module.signer_fingerprint)
        })
        && provenance
            .packages
            .iter()
            .all(|package| valid_identity_hash(&package.sha256))
        && valid_identity_hash(&provenance.kernel.image_sha256)
        && valid_identity_hash(&provenance.kernel.image_signer_fingerprint)
        && valid_identity_hash(&provenance.kernel.module_trust_certificate_fingerprint)
        && valid_identity_hash(&provenance.kernel.config_sha256)
        && valid_identity_hash(&provenance.build.source_lock_sha256)
        && valid_identity_hash(&provenance.build.build_environment_sha256)
        && valid_identity_hash(&provenance.build.build_attestation_sha256)
        && valid_identity_hash(&provenance.build.pkgbuild_sha256)
        && valid_identity_hash(&provenance.build.package_set_srcinfo_sha256);
    if !valid {
        return Err(StartupError::Compatibility(
            "package provenance is incomplete, placeholder, or mismatched".into(),
        ));
    }
    Ok(())
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_identity_hash(value: &str) -> bool {
    valid_hash(value) && value != "0".repeat(64) && value != "f".repeat(64)
}

fn secure_boot_enabled() -> Result<bool, StartupError> {
    let directory = Path::new("/sys/firmware/efi/efivars");
    let entries = fs::read_dir(directory)
        .map_err(|error| StartupError::Compatibility(format!("Secure Boot state: {error}")))?;
    let mut matches = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| StartupError::Compatibility(format!("Secure Boot state: {error}")))?
            .path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("SecureBoot-"))
        {
            matches.push(path);
        }
    }
    if matches.len() != 1 {
        return Err(StartupError::Compatibility(format!(
            "Secure Boot state is ambiguous: {} variables",
            matches.len()
        )));
    }
    let bytes = fs::read(&matches[0])
        .map_err(|error| StartupError::Compatibility(format!("Secure Boot state: {error}")))?;
    match bytes.as_slice() {
        [_, _, _, _, 1] => Ok(true),
        [_, _, _, _, 0] => Ok(false),
        _ => Err(StartupError::Compatibility(
            "Secure Boot variable is malformed".into(),
        )),
    }
}

fn require_package_owner(
    access: &mut impl LiveIdentityAccess,
    path: &str,
    expected: &str,
) -> Result<(), StartupError> {
    let owner = access.command_one_line("pacman", &["-Qoq", path])?;
    if owner != expected {
        return Err(StartupError::Compatibility(format!(
            "package owner mismatch for {path}: {owner}"
        )));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, StartupError> {
    let bytes = fs::read(path).map_err(|error| {
        StartupError::Compatibility(format!("cannot hash {}: {error}", path.display()))
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn read_trimmed(path: &str) -> Result<String, StartupError> {
    let value = read_trimmed_allow_empty(path)?;
    if value.is_empty() {
        return Err(StartupError::Compatibility(format!(
            "empty identity at {path}"
        )));
    }
    Ok(value)
}

fn read_trimmed_allow_empty(path: &str) -> Result<String, StartupError> {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .map_err(|error| compatibility_error(path, error))
}

fn command_one_line(command: &str, arguments: &[&str]) -> Result<String, StartupError> {
    let output = run_command(command, arguments)?;
    let lines = output.lines().collect::<Vec<_>>();
    if lines.len() != 1 || lines[0].trim().is_empty() {
        return Err(StartupError::Compatibility(format!(
            "{command} returned a missing or ambiguous identity"
        )));
    }
    Ok(lines[0].trim().to_owned())
}

fn run_command(command: &str, arguments: &[&str]) -> Result<String, StartupError> {
    run_command_raw(command, arguments).map_err(StartupError::Compatibility)
}

fn run_command_raw(command: &str, arguments: &[&str]) -> Result<String, String> {
    String::from_utf8(run_command_bytes(command, arguments)?)
        .map_err(|_| format!("{command} returned non-UTF-8 output"))
}

fn run_command_bytes(command: &str, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new(command)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot execute {command}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{command} exited with {}", output.status));
    }
    Ok(output.stdout)
}

fn run_nvidia_smi(arguments: &[&str]) -> Result<String, String> {
    const QUERY_TIMEOUT: Duration = Duration::from_secs(1);
    run_nvidia_smi_command(Path::new("nvidia-smi"), arguments, QUERY_TIMEOUT)
}

fn run_nvidia_smi_command(
    command: &Path,
    arguments: &[&str],
    timeout: Duration,
) -> Result<String, String> {
    run_nvidia_smi_command_with(
        command,
        arguments,
        timeout,
        set_nonblocking,
        std::process::Child::try_wait,
    )
}

fn run_nvidia_smi_command_with<SetNonblocking, TryWait>(
    command: &Path,
    arguments: &[&str],
    timeout: Duration,
    set_nonblocking_fn: SetNonblocking,
    mut try_wait_fn: TryWait,
) -> Result<String, String>
where
    SetNonblocking: FnOnce(&std::process::ChildStdout) -> io::Result<()>,
    TryWait: FnMut(&mut std::process::Child) -> io::Result<Option<std::process::ExitStatus>>,
{
    const OUTPUT_LIMIT: usize = 64 * 1024;
    let command_name = command.display();
    if timeout.is_zero() {
        return Err(format!("{command_name} received no execution budget"));
    }
    let mut command_builder = Command::new(command);
    command_builder
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: setpgid is async-signal-safe, touches no shared Rust state, and creates a group
    // containing only this freshly forked command and any descendants it may spawn.
    unsafe {
        command_builder.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command_builder
        .spawn()
        .map_err(|error| format!("cannot execute {command_name}: {error}"))?;
    let mut stdout = child
        .stdout
        .take()
        .expect("piped command stdout must be present");
    let deadline = Instant::now() + timeout;
    if let Err(error) = set_nonblocking_fn(&stdout) {
        kill_and_reap_until(child, deadline);
        return Err(format!("cannot bound {command_name} output: {error}"));
    }
    let cleanup_grace = std::cmp::min(timeout / 4, Duration::from_millis(50));
    let execution_deadline = deadline - cleanup_grace;
    let mut output = Vec::new();
    loop {
        if let Err(error) = drain_bounded_output(&mut stdout, &mut output, OUTPUT_LIMIT) {
            kill_and_reap_until(child, deadline);
            return Err(format!("cannot read {command_name} output: {error}"));
        }
        let status = match try_wait_fn(&mut child) {
            Ok(status) => status,
            Err(error) => {
                kill_and_reap_until(child, deadline);
                return Err(format!("cannot wait for {command_name}: {error}"));
            }
        };
        if let Some(status) = status {
            // The direct child may have left descendants holding stdout. Terminate the isolated
            // group and return only bytes already available; never block waiting for pipe EOF.
            kill_process_group(child.id());
            drain_bounded_output(&mut stdout, &mut output, OUTPUT_LIMIT)
                .map_err(|error| format!("cannot read {command_name} output: {error}"))?;
            if !status.success() {
                return Err(format!("{command_name} exited with {status}"));
            }
            return String::from_utf8(output)
                .map_err(|_| format!("{command_name} returned non-UTF-8 output"));
        }
        if Instant::now() >= execution_deadline {
            kill_and_reap_until(child, deadline);
            return Err(format!("{command_name} exceeded its execution deadline"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn set_nonblocking(file: &impl AsRawFd) -> io::Result<()> {
    let descriptor = file.as_raw_fd();
    // SAFETY: fcntl is called on a live owned descriptor and does not retain pointers.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the same live descriptor remains valid for this immediate flag update.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain_bounded_output(
    stdout: &mut impl Read,
    output: &mut Vec<u8>,
    limit: usize,
) -> io::Result<()> {
    let mut buffer = [0_u8; 4096];
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(length) if output.len().saturating_add(length) <= limit => {
                output.extend_from_slice(&buffer[..length]);
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "command output exceeded 64 KiB",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn kill_process_group(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: the child was placed in a process group whose id equals its positive pid.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

fn kill_and_reap_until(mut child: std::process::Child, deadline: Instant) {
    kill_process_group(child.id());
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => thread::sleep(Duration::from_millis(1)),
        }
    }
    defer_child_reap(child);
}

fn defer_child_reap(child: std::process::Child) {
    static REAPER: OnceLock<Option<mpsc::Sender<std::process::Child>>> = OnceLock::new();
    let sender = REAPER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<std::process::Child>();
        thread::Builder::new()
            .name("pt31553-nvidia-reaper".into())
            .spawn(move || {
                for mut child in receiver {
                    let _ = child.wait();
                }
            })
            .ok()
            .map(|_| sender)
    });
    match sender {
        Some(sender) => {
            if let Err(error) = sender.send(child) {
                let mut child = error.0;
                let _ = child.wait();
            }
        }
        None => {
            let mut child = child;
            let _ = child.wait();
        }
    }
}

fn configuration_error(path: &str, error: impl std::fmt::Display) -> StartupError {
    StartupError::Configuration(format!("cannot read {path}: {error}"))
}

fn compatibility_error(path: &str, error: impl std::fmt::Display) -> StartupError {
    StartupError::Compatibility(format!("cannot read {path}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fan_control_core::{FakePlatform, FakeStep, FilePermissions, PlatformError};
    use std::os::unix::fs::PermissionsExt;

    #[derive(Debug)]
    struct FixtureSources;

    impl SampleSources for FixtureSources {
        fn sample_cpu(
            &mut self,
            capture: &mut SampleCapture<'_>,
        ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
            Ok(capture.capture(TemperatureCelsius::try_from(60.0).unwrap()))
        }

        fn sample_gpu(
            &mut self,
            capture: &mut SampleCapture<'_>,
        ) -> Result<ObservedSample<TemperatureCelsius>, SampleSourceError> {
            Ok(capture.capture(TemperatureCelsius::try_from(55.0).unwrap()))
        }

        fn observe_external_power(
            &mut self,
            capture: &mut SampleCapture<'_>,
        ) -> Result<ObservedSample<ExternalPower>, SampleSourceError> {
            Ok(capture.capture(ExternalPower::Connected))
        }
    }

    struct FixtureDiscoveryEnvironment {
        calls: Vec<&'static str>,
        identity_failure: bool,
    }

    impl FixtureDiscoveryEnvironment {
        fn new(identity_failure: bool) -> Self {
            Self {
                calls: Vec::new(),
                identity_failure,
            }
        }
    }

    impl StartupDiscoveryEnvironment for FixtureDiscoveryEnvironment {
        type Sources = FixtureSources;

        fn read_editable_config(&mut self) -> Result<String, StartupError> {
            self.calls.push("editable-config");
            Ok("schema_version = 1\n".into())
        }

        fn load_compatibility_declaration(
            &mut self,
        ) -> Result<(String, CompatibilityDeclarationV1), StartupError> {
            self.calls.push("compatibility-declaration");
            let source = include_str!("../../../compatibility/pt315-53.toml").to_owned();
            let declaration = parse_compatibility_v1(&source).unwrap();
            Ok((source, declaration))
        }

        fn load_qualified_archive(
            &mut self,
        ) -> Result<(QualifiedArchivePaths, String, PackageProvenanceV1), StartupError> {
            self.calls.push("qualified-archive");
            let provenance = serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "candidate": "fixture",
                "build": {
                    "source_commit": "fixture",
                    "source_lock_sha256": "fixture",
                    "build_environment_sha256": "fixture",
                    "build_attestation_sha256": "fixture",
                    "pkgbuild_sha256": "fixture",
                    "package_set_srcinfo_sha256": "fixture",
                    "package_manifest_signature_sha256": null,
                    "package_manifest_signer_fingerprint": "fixture"
                },
                "kernel": {
                    "release": "fixture",
                    "package": "fixture",
                    "image_path": "/fixture/vmlinuz",
                    "image_sha256": "fixture",
                    "image_signer_fingerprint": "fixture",
                    "config_path": "/fixture/config",
                    "config_sha256": "fixture",
                    "module_trust_certificate_path": "/fixture/cert",
                    "module_trust_certificate_fingerprint": "fixture"
                },
                "modules": [],
                "packages": []
            }))
            .unwrap();
            Ok((
                qualified_archive_paths_for_version("fixture"),
                "protected fixture policy".into(),
                provenance,
            ))
        }

        fn discover_sources(&mut self) -> Result<Self::Sources, StartupError> {
            self.calls.push("sample-sources");
            Ok(FixtureSources)
        }

        fn discover_acer_device(
            &mut self,
            _sources: &mut Self::Sources,
        ) -> Result<AcerHwmonDevice, StartupError> {
            self.calls.push("acer-device");
            let root = Path::new(HWMON_ROOT).join("hwmon7");
            let mut platform = FakePlatform::new();
            platform.insert_file_with_permissions(
                root.join("name"),
                "acer\n",
                FilePermissions::READ_ONLY,
            );
            platform.insert_file(root.join("pwm1"), "255\n");
            platform.insert_file(root.join("pwm1_enable"), "2\n");
            platform.insert_file_with_permissions(
                root.join("fan1_input"),
                "3500\n",
                FilePermissions::READ_ONLY,
            );
            platform.insert_file(root.join("pwm2"), "255\n");
            platform.insert_file(root.join("pwm2_enable"), "2\n");
            platform.insert_file_with_permissions(
                root.join("fan2_input"),
                "3500\n",
                FilePermissions::READ_ONLY,
            );
            discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT))
                .map_err(|error| StartupError::Device(error.to_string()))
        }

        fn observe_live_identity(
            &mut self,
            declaration: &CompatibilityDeclarationV1,
            _provenance: &PackageProvenanceV1,
            archive: &QualifiedArchivePaths,
            device: &AcerHwmonDevice,
        ) -> Result<CompatibilityObservation, StartupError> {
            self.calls.push("live-identity");
            assert!(
                archive
                    .kernel_image_certificate
                    .ends_with("enrolled-image-signing-certificate.pem")
            );
            assert_eq!(
                device_endpoint_names(device),
                declaration.fan_control.endpoints
            );
            if self.identity_failure {
                return Err(StartupError::Compatibility("fixture DMI mismatch".into()));
            }
            Ok(CompatibilityObservation {
                hardware: declaration.hardware.clone(),
                kernel: declaration.kernel.clone(),
                module: declaration.module.clone(),
                secure_boot_enabled: true,
                kernel_image_trusted: true,
                module_signature_trusted: true,
                fan_abi: ObservedFanAbi {
                    hwmon_name: declaration.fan_control.hwmon_name.clone(),
                    endpoints: declaration.fan_control.endpoints.clone(),
                },
                backend_evidence_completeness: EvidenceCompleteness::Complete,
                backends: vec![FanWriteBackend::AcerHwmon],
                capability_evidence_completeness: EvidenceCompleteness::Complete,
                enabled_capabilities: Vec::new(),
            })
        }
    }

    #[test]
    fn injected_fixture_exercises_the_complete_startup_discovery_wiring() {
        let mut environment = FixtureDiscoveryEnvironment::new(false);
        let discovery = discover_startup_with(&mut environment).unwrap();

        assert_eq!(discovery.editable_config, "schema_version = 1\n");
        assert_eq!(discovery.protected_policy, "protected fixture policy");
        assert!(discovery.observation.secure_boot_enabled);
        assert_eq!(
            environment.calls,
            [
                "editable-config",
                "compatibility-declaration",
                "qualified-archive",
                "sample-sources",
                "acer-device",
                "live-identity",
            ]
        );
    }

    #[test]
    fn injected_fixture_propagates_live_identity_rejection() {
        let mut environment = FixtureDiscoveryEnvironment::new(true);
        let error = discover_startup_with(&mut environment).unwrap_err();

        assert!(
            matches!(error, StartupError::Compatibility(message) if message == "fixture DMI mismatch")
        );
        assert_eq!(environment.calls.last(), Some(&"live-identity"));
    }

    struct FixtureLiveIdentityAccess {
        calls: Vec<String>,
        package_mismatch: bool,
        signature_tampered: bool,
        nvidia_unavailable: bool,
        certificate_der: Vec<u8>,
        hash: String,
        module_path: String,
        release: String,
        vermagic: String,
    }

    impl FixtureLiveIdentityAccess {
        fn new(declaration: &CompatibilityDeclarationV1) -> Self {
            Self {
                calls: Vec::new(),
                package_mismatch: false,
                signature_tampered: false,
                nvidia_unavailable: false,
                certificate_der: b"fixture certificate der".to_vec(),
                hash: "a".repeat(64),
                module_path: declaration.module.path.clone(),
                release: declaration.kernel.release.clone(),
                vermagic: declaration.module.vermagic.clone(),
            }
        }

        fn record(&mut self, command: &str, arguments: &[&str]) {
            self.calls
                .push(format!("{command} {}", arguments.join(" ")));
        }
    }

    impl LiveIdentityAccess for FixtureLiveIdentityAccess {
        fn command_one_line(
            &mut self,
            command: &str,
            arguments: &[&str],
        ) -> Result<String, StartupError> {
            self.record(command, arguments);
            let result = match (command, arguments) {
                ("pacman", ["-Q", package]) => {
                    if self.package_mismatch {
                        format!("{package} wrong-version")
                    } else {
                        format!("{package} 7.1.8-1")
                    }
                }
                ("pacman", ["-Qoq", path]) if path.contains("nvidia") => {
                    "linux-cachyos-pt31553-nvidia-open".into()
                }
                ("pacman", ["-Qoq", _]) => "linux-cachyos-pt31553".into(),
                ("modinfo", ["-n", "acer_wmi"]) => self.module_path.clone(),
                ("modinfo", ["-F", "vermagic", _]) => self.vermagic.clone(),
                ("modinfo", ["-F", "signer", _]) => "Fixture Signer".into(),
                ("modinfo", ["-F", "sig_key", _]) => self.hash.clone(),
                ("modinfo", ["-F", "srcversion", _]) => "FIXTURESRC".into(),
                ("modinfo", ["-F", "version", "nvidia"]) => "610.57.04".into(),
                _ => {
                    return Err(StartupError::Compatibility(format!(
                        "unexpected fixture command: {command} {arguments:?}"
                    )));
                }
            };
            Ok(result)
        }

        fn run_command(
            &mut self,
            command: &str,
            arguments: &[&str],
        ) -> Result<String, StartupError> {
            self.record(command, arguments);
            match command {
                "openssl" => Ok(format!("Subject Key Identifier:\n{}", self.hash)),
                "sbverify" => Ok(String::new()),
                "nvidia-smi" if self.nvidia_unavailable => {
                    Err(StartupError::Compatibility("nvidia-smi unavailable".into()))
                }
                "nvidia-smi" => {
                    Ok("GPU-12345678-1234-1234-1234-123456789abc, 00000000:01:00.0, 55\n".into())
                }
                _ => Err(StartupError::Compatibility(format!(
                    "unexpected fixture command: {command}"
                ))),
            }
        }

        fn run_command_bytes(
            &mut self,
            command: &str,
            arguments: &[&str],
        ) -> Result<Vec<u8>, String> {
            self.record(command, arguments);
            (command == "openssl")
                .then(|| self.certificate_der.clone())
                .ok_or_else(|| format!("unexpected fixture command: {command}"))
        }

        fn read_trimmed(&mut self, path: &str) -> Result<String, StartupError> {
            self.calls.push(format!("read {path}"));
            match path {
                "/sys/class/dmi/id/product_name" => Ok("Predator PT315-53".into()),
                "/sys/class/dmi/id/board_name" => Ok("Civic_TLS".into()),
                "/sys/class/dmi/id/bios_version" => Ok("V1.17".into()),
                "/proc/sys/kernel/osrelease" => Ok(self.release.clone()),
                "/sys/module/acer_wmi/srcversion" => Ok("FIXTURESRC".into()),
                "/sys/module/nvidia/version" => Ok("610.57.04".into()),
                _ => Err(StartupError::Compatibility(format!(
                    "unexpected fixture read: {path}"
                ))),
            }
        }

        fn read_trimmed_allow_empty(&mut self, path: &str) -> Result<String, StartupError> {
            self.calls.push(format!("read-allow-empty {path}"));
            if path == "/sys/module/acer_wmi/taint" {
                Ok(String::new())
            } else {
                Err(StartupError::Compatibility(format!(
                    "unexpected fixture read: {path}"
                )))
            }
        }

        fn read_bytes(&mut self, path: &Path) -> Result<Vec<u8>, StartupError> {
            self.calls.push(format!("read-bytes {}", path.display()));
            Ok(b"fixture build id".to_vec())
        }

        fn protected_bytes(&mut self, path: &Path) -> Result<Vec<u8>, StartupError> {
            self.calls
                .push(format!("read-protected {}", path.display()));
            if path.ends_with("SHA256SUMS") {
                Ok(format!(
                    "{}  linux-cachyos-pt31553-7.1.8-1-x86_64.pkg.tar.zst\n",
                    self.hash
                )
                .into_bytes())
            } else if path.ends_with("package-set-manifest.p7s") {
                Ok(if self.signature_tampered {
                    b"tampered package signature".to_vec()
                } else {
                    b"fixture package signature".to_vec()
                })
            } else {
                Ok(b"fixture certificate pem".to_vec())
            }
        }

        fn is_directory(&mut self, path: &Path) -> bool {
            self.calls.push(format!("is-directory {}", path.display()));
            false
        }

        fn sha256_file(&mut self, path: &Path) -> Result<String, StartupError> {
            self.calls.push(format!("sha256 {}", path.display()));
            Ok(self.hash.clone())
        }

        fn installed_module_build_id_note(&mut self, path: &Path) -> Result<Vec<u8>, StartupError> {
            self.calls
                .push(format!("installed-build-id {}", path.display()));
            Ok(b"fixture build id".to_vec())
        }

        fn secure_boot_enabled(&mut self) -> Result<bool, StartupError> {
            self.calls.push("secure-boot".into());
            Ok(true)
        }

        fn verify_running_kernel_build(&mut self, image_path: &str) -> Result<(), StartupError> {
            self.calls
                .push(format!("verify-running-kernel {image_path}"));
            Ok(())
        }
    }

    fn live_identity_fixture() -> (
        CompatibilityDeclarationV1,
        PackageProvenanceV1,
        AcerHwmonDevice,
    ) {
        let mut declaration =
            parse_compatibility_v1(include_str!("../../../compatibility/pt315-53.toml")).unwrap();
        let hash = "a".repeat(64);
        let image_signer = format!("{:x}", Sha256::digest(b"fixture certificate der"));
        let package_signature_sha256 =
            format!("{:x}", Sha256::digest(b"fixture package signature"));
        declaration.kernel.image_sha256 = hash.clone();
        declaration.kernel.image_signer_fingerprint = image_signer.clone();
        declaration.module.sha256 = hash.clone();
        declaration.module.signer_fingerprint = hash.clone();

        let acer_path = declaration.module.path.clone();
        let vermagic = declaration.module.vermagic.clone();
        let release = declaration.kernel.release.clone();
        let kernel_package = declaration.kernel.package.clone();
        let provenance = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "candidate": "linux-cachyos-pt31553-7.1.8-1-package-set",
            "build": {
                "source_commit": declaration.kernel.source_commit,
                "source_lock_sha256": hash,
                "build_environment_sha256": hash,
                "build_attestation_sha256": hash,
                "pkgbuild_sha256": hash,
                "package_set_srcinfo_sha256": hash,
                "package_manifest_signature_sha256": package_signature_sha256,
                "package_manifest_signer_fingerprint": image_signer
            },
            "kernel": {
                "release": release,
                "package": kernel_package,
                "image_path": format!("/usr/lib/modules/{}/vmlinuz", declaration.kernel.release),
                "image_sha256": hash,
                "image_signer_fingerprint": image_signer,
                "config_path": format!("/usr/lib/modules/{}/build/.config", declaration.kernel.release),
                "config_sha256": hash,
                "module_trust_certificate_path": format!("/usr/lib/modules/{}/build/certs/signing_key.x509", declaration.kernel.release),
                "module_trust_certificate_fingerprint": hash
            },
            "modules": [
                {
                    "name": "acer_wmi", "path": acer_path, "sha256": hash,
                    "signer_fingerprint": hash, "vermagic": vermagic,
                    "provenance": "in-tree", "package": "linux-cachyos-pt31553",
                    "source": { "kind": "kernel-tree", "revision": declaration.kernel.source_commit }
                },
                {
                    "name": "nvidia", "path": format!("/usr/lib/modules/{}/extramodules/nvidia.ko.zst", declaration.kernel.release),
                    "sha256": hash, "signer_fingerprint": hash, "vermagic": declaration.module.vermagic,
                    "provenance": "nvidia-open", "package": "linux-cachyos-pt31553-nvidia-open",
                    "source": { "kind": "nvidia-open", "revision": "610.57.04" }
                }
            ],
            "packages": [
                { "name": "linux-cachyos-pt31553", "version": "7.1.8-1", "architecture": "x86_64", "sha256": hash }
            ]
        }))
        .unwrap();

        let root = Path::new(HWMON_ROOT).join("hwmon7");
        let mut platform = FakePlatform::new();
        platform.insert_file_with_permissions(
            root.join("name"),
            "acer\n",
            FilePermissions::READ_ONLY,
        );
        platform.insert_file(root.join("pwm1"), "255\n");
        platform.insert_file(root.join("pwm1_enable"), "2\n");
        platform.insert_file_with_permissions(
            root.join("fan1_input"),
            "3500\n",
            FilePermissions::READ_ONLY,
        );
        platform.insert_file(root.join("pwm2"), "255\n");
        platform.insert_file(root.join("pwm2_enable"), "2\n");
        platform.insert_file_with_permissions(
            root.join("fan2_input"),
            "3500\n",
            FilePermissions::READ_ONLY,
        );
        let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();
        (declaration, provenance, device)
    }

    #[test]
    fn live_identity_adapter_exercises_exact_files_commands_and_successful_assembly() {
        let (declaration, provenance, device) = live_identity_fixture();
        let mut access = FixtureLiveIdentityAccess::new(&declaration);

        let observation = observe_live_compatibility_with(
            &mut access,
            &declaration,
            &provenance,
            &qualified_archive_paths_for_version("fixture"),
            &device,
        )
        .unwrap();

        assert_eq!(observation.hardware, declaration.hardware);
        assert!(
            access
                .calls
                .contains(&format!("pacman -Q {}", declaration.kernel.package))
        );
        assert!(
            access
                .calls
                .contains(&format!("modinfo -F sig_key {}", declaration.module.path))
        );
        assert!(access.calls.iter().any(|call| {
            call.starts_with("sbverify --cert /tmp/pt31553-verified-certificate-")
                && call.ends_with(&provenance.kernel.image_path)
        }));
        assert!(access.calls.contains(&format!(
            "verify-running-kernel {}",
            provenance.kernel.image_path
        )));
    }

    #[test]
    fn live_identity_adapter_rejects_an_installed_package_mismatch() {
        let (declaration, provenance, device) = live_identity_fixture();
        let mut access = FixtureLiveIdentityAccess::new(&declaration);
        access.package_mismatch = true;

        let error = observe_live_compatibility_with(
            &mut access,
            &declaration,
            &provenance,
            &qualified_archive_paths_for_version("fixture"),
            &device,
        )
        .unwrap_err();

        assert!(
            matches!(error, StartupError::Compatibility(message) if message.contains("installed package mismatch"))
        );
    }

    #[test]
    fn live_identity_adapter_rejects_a_tampered_package_set_signature() {
        let (declaration, provenance, device) = live_identity_fixture();
        let mut access = FixtureLiveIdentityAccess::new(&declaration);
        access.signature_tampered = true;

        let error = observe_live_compatibility_with(
            &mut access,
            &declaration,
            &provenance,
            &qualified_archive_paths_for_version("fixture"),
            &device,
        )
        .unwrap_err();

        assert!(
            matches!(error, StartupError::Compatibility(message) if message == "package manifest signature hash mismatch")
        );
        assert!(!access.calls.iter().any(|call| call.starts_with("pacman ")));
    }

    #[test]
    fn nvidia_discovery_command_failure_is_a_sensor_diagnostic() {
        let (declaration, _, _) = live_identity_fixture();
        let mut access = FixtureLiveIdentityAccess::new(&declaration);
        access.nvidia_unavailable = true;

        let error = NvidiaSmi::discover_with(&mut access).unwrap_err();

        assert!(matches!(error, StartupError::Device(_)));
        assert_eq!(error.diagnostic_id(), "sensor-unavailable");
    }

    #[test]
    fn nvidia_row_requires_exact_identity_and_integer_temperature_fields() {
        let sample = parse_nvidia_smi_row_raw(
            "GPU-12345678-1234-1234-1234-123456789abc, 00000000:01:00.0, 61",
        )
        .unwrap();
        assert_eq!(sample.uuid(), "GPU-12345678-1234-1234-1234-123456789abc");
        assert_eq!(sample.pci_bus_id(), "00000000:01:00.0");
        assert_eq!(sample.temperature_celsius(), 61.0);
        assert!(parse_nvidia_smi_row_raw("GPU-x, 61").is_err());
        assert!(parse_nvidia_smi_row_raw("GPU-x, pci, unknown").is_err());
    }

    #[test]
    fn nvidia_rediscovery_rejects_a_substituted_gpu() {
        let expected = NvidiaGpuSelector::uuid("GPU-12345678-1234-1234-1234-123456789abc").unwrap();
        let error = NvidiaSmi::from_rediscovery_output(
            "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, 00000000:02:00.0, 61",
            &expected,
        )
        .unwrap_err();

        assert!(
            matches!(error, StartupError::Device(message) if message.contains("identity changed"))
        );
    }

    #[test]
    fn nvidia_process_runner_reports_exit_and_kills_a_timed_out_child() {
        let success = executable_script("#!/bin/sh\nprintf 'GPU-ok, pci, 61\\n'\n");
        assert_eq!(
            run_nvidia_smi_command(&success.1, &[], Duration::from_secs(1)).unwrap(),
            "GPU-ok, pci, 61\n"
        );

        let failure = executable_script("#!/bin/sh\nexit 7\n");
        assert!(
            run_nvidia_smi_command(&failure.1, &[], Duration::from_secs(1))
                .unwrap_err()
                .contains("exit status: 7")
        );

        let inherited_stdout =
            executable_script("#!/bin/sh\n(sleep 30) &\nprintf 'GPU-ok, pci, 61\\n'\n");
        let started = Instant::now();
        assert_eq!(
            run_nvidia_smi_command(&inherited_stdout.1, &[], Duration::from_secs(1)).unwrap(),
            "GPU-ok, pci, 61\n"
        );
        assert!(started.elapsed() < Duration::from_secs(1));

        let timeout = executable_script("#!/bin/sh\necho $$ > \"$1\"\nwhile :; do :; done\n");
        let pid_path = timeout.0.path().join("pid");
        let started = Instant::now();
        let error = run_nvidia_smi_command(
            &timeout.1,
            &[pid_path.to_str().unwrap()],
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.contains("execution deadline"));
        assert!(started.elapsed() < Duration::from_secs(1));
        let pid = fs::read_to_string(&pid_path).unwrap();
        let process_path = Path::new("/proc").join(pid.trim());
        let disappearance_deadline = Instant::now() + Duration::from_secs(1);
        while process_path.exists() && Instant::now() < disappearance_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!process_path.exists());
    }

    #[test]
    fn nvidia_process_runner_kills_children_after_post_spawn_setup_or_wait_errors() {
        for fault in ["setup", "wait"] {
            let fixture = executable_script(
                "#!/bin/sh\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 1; done\n",
            );
            let pid_path = fixture.0.path().join(format!("{fault}.pid"));
            let wait_for_pid = || {
                let deadline = Instant::now() + Duration::from_millis(250);
                while !pid_path.exists() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(1));
                }
            };
            let error = if fault == "setup" {
                run_nvidia_smi_command_with(
                    &fixture.1,
                    &[pid_path.to_str().unwrap()],
                    Duration::from_secs(1),
                    |_| {
                        wait_for_pid();
                        Err(io::Error::other("injected setup failure"))
                    },
                    std::process::Child::try_wait,
                )
                .unwrap_err()
            } else {
                run_nvidia_smi_command_with(
                    &fixture.1,
                    &[pid_path.to_str().unwrap()],
                    Duration::from_secs(1),
                    set_nonblocking,
                    |_| {
                        wait_for_pid();
                        Err(io::Error::other("injected wait failure"))
                    },
                )
                .unwrap_err()
            };
            assert!(error.contains(&format!("injected {fault} failure")));
            let pid = fs::read_to_string(&pid_path).unwrap();
            let process_path = Path::new("/proc").join(pid.trim());
            let deadline = Instant::now() + Duration::from_secs(1);
            while process_path.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(!process_path.exists(), "{fault} child survived cleanup");
        }
    }

    #[test]
    fn nvidia_process_runner_reaps_a_child_after_the_cleanup_deadline() {
        let fixture = executable_script(
            "#!/bin/sh\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 1; done\n",
        );
        let pid_path = fixture.0.path().join("deferred.pid");
        let mut command = Command::new(&fixture.1);
        command.arg(pid_path.to_str().unwrap());
        // SAFETY: setpgid is async-signal-safe and runs before the child executes the fixture.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let pid_deadline = Instant::now() + Duration::from_millis(250);
        while !pid_path.exists() && Instant::now() < pid_deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let pid = fs::read_to_string(&pid_path).unwrap();
        let process_path = Path::new("/proc").join(pid.trim());

        kill_and_reap_until(child, Instant::now());

        let disappearance_deadline = Instant::now() + Duration::from_secs(1);
        while process_path.exists() && Instant::now() < disappearance_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!process_path.exists(), "deferred child remained unreaped");
    }

    #[test]
    fn signer_hashes_reject_placeholders() {
        assert!(valid_identity_hash(&"a".repeat(64)));
        assert!(!valid_identity_hash(&"0".repeat(64)));
        assert!(!valid_identity_hash(&"f".repeat(64)));
        assert!(!valid_identity_hash("ABC"));
    }

    #[test]
    fn module_key_ids_are_compared_in_canonical_form() {
        assert_eq!(normalize_key_id("12:AB:cd:EF"), "12abcdef");
    }

    #[test]
    fn runtime_authority_tracks_the_installed_qualified_package_version() {
        let paths = qualified_archive_paths_for_version("7.2.1-3");
        let root = "/var/lib/pt31553-fan-control/rollback/pt31553-last-qualified-7.2.1-3/";
        assert!(paths.protected_policy.to_str().unwrap().starts_with(root));
        assert!(paths.package_provenance.to_str().unwrap().starts_with(root));
        assert!(
            paths
                .kernel_image_certificate
                .to_str()
                .unwrap()
                .starts_with(root)
        );
    }

    #[test]
    fn kernel_header_integer_requires_four_bytes() {
        assert_eq!(little_endian_u32(&[0, 1, 2, 3, 4], 1).unwrap(), 0x0403_0201);
        assert!(little_endian_u32(&[0, 1, 2], 0).is_err());
    }

    #[test]
    fn external_power_rejects_a_rebound_online_endpoint() {
        let root = Path::new(POWER_SUPPLY_ROOT);
        let mut platform = FakePlatform::new();
        platform.insert_file(root.join("ACAD/type"), "Mains\n");
        platform.insert_file(root.join("ACAD/online"), "1\n");
        platform.insert_file(root.join("BAT1/type"), "Battery\n");
        let power = BoundExternalPower::discover(&mut platform, root).unwrap();
        assert_eq!(power.observe(&mut platform), ExternalPower::Connected);

        platform.rebind_path_identity(root.join("ACAD/online"));
        assert_eq!(power.observe(&mut platform), ExternalPower::Unknown);
    }

    #[test]
    fn readonly_power_rediscovery_rejects_a_rebound_type_endpoint() {
        let root = Path::new(POWER_SUPPLY_ROOT);
        let mut platform = FakePlatform::new();
        platform.insert_file(root.join("ACAD/type"), "Mains\n");
        platform.insert_file(root.join("ACAD/online"), "1\n");
        let mut access = RebindTypeOnRead {
            inner: platform,
            rebound: false,
        };

        let error = match BoundExternalPower::discover_readonly(&mut access, root) {
            Ok(_) => panic!("rebound type endpoint was accepted"),
            Err(error) => error,
        };
        assert!(
            matches!(error, StartupError::Device(message) if message.contains("identity changed"))
        );
    }

    #[test]
    fn runtime_rediscovery_reads_share_one_absolute_deadline() {
        let path = Path::new("/sys/class/power_supply/ACAD/type");
        let mut platform = FakePlatform::new();
        platform.insert_file(path, "Mains\n");
        platform.queue_file_steps([FakeStep::Advance(Duration::from_secs(2))]);
        let mut access = DeadlineReadAccess {
            files: &mut platform,
            deadline: Duration::from_secs(1),
        };

        let error = access.read(path).unwrap_err();
        assert_eq!(error.kind(), PlatformErrorKind::TimedOut);
    }

    #[test]
    fn production_cpu_and_power_reads_stop_at_the_shared_sample_deadline() {
        let hwmon = Path::new(HWMON_ROOT).join("hwmon47");
        let mut cpu_platform = FakePlatform::new();
        for (path, contents) in [
            (hwmon.join("name"), "coretemp\n"),
            (hwmon.join("temp1_label"), "Package id 0\n"),
            (hwmon.join("temp1_input"), "68000\n"),
            (hwmon.join("temp1_crit"), "100000\n"),
        ] {
            cpu_platform.insert_file_with_permissions(path, contents, FilePermissions::READ_ONLY);
        }
        let cpu = discover_coretemp(&mut cpu_platform, Path::new(HWMON_ROOT)).unwrap();
        cpu_platform.queue_file_steps([FakeStep::Advance(Duration::from_secs(2))]);
        let error = cpu
            .sample(&mut DeadlineReadAccess {
                files: &mut cpu_platform,
                deadline: Duration::from_secs(1),
            })
            .unwrap_err();
        assert!(error.to_string().contains("deadline"));

        let power_root = Path::new(POWER_SUPPLY_ROOT);
        let mut power_platform = FakePlatform::new();
        power_platform.insert_file(power_root.join("ACAD/type"), "Mains\n");
        power_platform.insert_file(power_root.join("ACAD/online"), "1\n");
        let power = BoundExternalPower::discover(&mut power_platform, power_root).unwrap();
        power_platform.queue_file_steps([FakeStep::Advance(Duration::from_secs(2))]);
        assert_eq!(
            power.observe_before(&mut power_platform, Duration::from_secs(1)),
            ExternalPower::Unknown
        );
        assert_eq!(power_platform.monotonic_now(), Duration::from_secs(1));
    }

    struct RebindTypeOnRead {
        inner: FakePlatform,
        rebound: bool,
    }

    impl IdentityBoundReadAccess for RebindTypeOnRead {
        fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
            IdentityBoundReadAccess::read(&mut self.inner, path)
        }

        fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
            IdentityBoundReadAccess::list(&mut self.inner, directory)
        }

        fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
            IdentityBoundReadAccess::permissions(&mut self.inner, path)
        }

        fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
            IdentityBoundReadAccess::identity(&mut self.inner, path)
        }

        fn read_bound(
            &mut self,
            directory: &Path,
            expected: FileIdentity,
            child: &str,
        ) -> Result<String, PlatformError> {
            if child == "type" && !self.rebound {
                self.inner.rebind_path_identity(directory.join(child));
                self.rebound = true;
            }
            IdentityBoundReadAccess::read_bound(&mut self.inner, directory, expected, child)
        }

        fn list_bound(
            &mut self,
            directory: &Path,
            expected: FileIdentity,
        ) -> Result<Vec<PathBuf>, PlatformError> {
            IdentityBoundReadAccess::list_bound(&mut self.inner, directory, expected)
        }
    }

    fn executable_script(source: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nvidia-smi-fixture");
        fs::write(&path, source).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (directory, path)
    }

    #[test]
    #[ignore = "requires a booted Linux system with its installed kernel image"]
    fn installed_kernel_build_notes_match_the_running_kernel() {
        let release = read_trimmed("/proc/sys/kernel/osrelease").unwrap();
        let image = format!("/usr/lib/modules/{release}/vmlinuz");
        verify_running_kernel_build(&image).unwrap();
    }
}
