use std::path::{Path, PathBuf};

use fan_control_core::{
    AcerHwmonDiscoveryError, FakePlatform, FakeStep, FileAccess, FileIdentity, FilePermissions,
    IdentityBoundFileAccess, PlatformError, PlatformErrorKind, discover_acer_hwmon,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";

fn install_acer(platform: &mut FakePlatform, index: usize) -> PathBuf {
    let root = Path::new(HWMON_ROOT).join(format!("hwmon{index}"));
    platform.insert_file_with_permissions(root.join("name"), "acer\n", FilePermissions::READ_ONLY);
    for channel in 1..=2 {
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}")),
            "128\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("pwm{channel}_enable")),
            "2\n",
            FilePermissions::READ_WRITE,
        );
        platform.insert_file_with_permissions(
            root.join(format!("fan{channel}_input")),
            "2400\n",
            FilePermissions::READ_ONLY,
        );
    }
    root
}

#[test]
fn discovers_by_identity_at_any_numeric_index_and_maps_both_fans() {
    let mut platform = FakePlatform::new();
    platform.insert_file_with_permissions(
        Path::new(HWMON_ROOT).join("hwmon0/name"),
        "coretemp\n",
        FilePermissions::READ_ONLY,
    );
    let acer_root = install_acer(&mut platform, 47);

    let device = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();

    assert_eq!(device.root(), acer_root);
    assert_eq!(device.cpu().pwm(), acer_root.join("pwm1"));
    assert_eq!(device.cpu().enable(), acer_root.join("pwm1_enable"));
    assert_eq!(device.cpu().tachometer(), acer_root.join("fan1_input"));
    assert_eq!(device.gpu().pwm(), acer_root.join("pwm2"));
    assert_eq!(device.gpu().enable(), acer_root.join("pwm2_enable"));
    assert_eq!(device.gpu().tachometer(), acer_root.join("fan2_input"));
}

#[test]
fn rediscovery_distinguishes_an_invisible_backing_device_rebind() {
    let mut platform = FakePlatform::new();
    let root = install_acer(&mut platform, 7);
    let before = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();

    platform.rebind_path_identity(&root);
    let after = discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)).unwrap();

    assert_ne!(after, before);
    assert_eq!(after.root(), before.root());
}

#[test]
fn rejects_missing_and_partial_two_fan_abis() {
    for missing in [
        "pwm1",
        "pwm1_enable",
        "fan1_input",
        "pwm2",
        "pwm2_enable",
        "fan2_input",
    ] {
        let mut platform = FakePlatform::new();
        let root = install_acer(&mut platform, 7);
        platform.remove_path(root.join(missing));

        assert!(matches!(
            discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)),
            Err(AcerHwmonDiscoveryError::InvalidAbi { .. })
        ));
    }
}

#[test]
fn rejects_duplicate_acer_devices_and_absent_acer_device() {
    let mut duplicates = FakePlatform::new();
    install_acer(&mut duplicates, 2);
    install_acer(&mut duplicates, 91);
    assert!(matches!(
        discover_acer_hwmon(&mut duplicates, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::AmbiguousDevices { count: 2 })
    ));

    let mut absent = FakePlatform::new();
    absent.insert_file_with_permissions(
        Path::new(HWMON_ROOT).join("hwmon3/name"),
        "coretemp\n",
        FilePermissions::READ_ONLY,
    );
    assert!(matches!(
        discover_acer_hwmon(&mut absent, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::NoDevice)
    ));
}

#[test]
fn rejects_extra_or_mismatched_fan_channels() {
    for extra in [
        "pwm3",
        "pwm3_enable",
        "fan3_input",
        "pwm01",
        "pwm01_enable",
        "fan01_input",
        "pwm999999999999999999999999999999999999",
    ] {
        let mut platform = FakePlatform::new();
        let root = install_acer(&mut platform, 7);
        platform.insert_file_with_permissions(root.join(extra), "1\n", FilePermissions::READ_ONLY);

        assert!(matches!(
            discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)),
            Err(AcerHwmonDiscoveryError::InvalidAbi { .. })
        ));
    }
}

#[test]
fn rejects_endpoints_with_unexpected_permissions() {
    let cases = [
        ("name", FilePermissions::READ_WRITE),
        ("name", FilePermissions::from_mode(0o400)),
        ("pwm1", FilePermissions::READ_ONLY),
        ("pwm1", FilePermissions::from_mode(0o666)),
        ("pwm1", FilePermissions::from_mode(0o1644)),
        ("pwm1_enable", FilePermissions::READ_ONLY),
        ("fan1_input", FilePermissions::READ_WRITE),
        ("fan1_input", FilePermissions::from_mode(0o400)),
        ("pwm2", FilePermissions::NONE),
        ("pwm2_enable", FilePermissions::WRITE_ONLY),
        ("fan2_input", FilePermissions::NONE),
    ];

    for (endpoint, permissions) in cases {
        let mut platform = FakePlatform::new();
        let root = install_acer(&mut platform, 7);
        platform.set_file_permissions(root.join(endpoint), permissions);

        assert!(matches!(
            discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)),
            Err(AcerHwmonDiscoveryError::InvalidPermissions { .. })
        ));
    }
}

#[test]
fn rejects_normalized_or_malformed_acer_identity_payloads() {
    for name in ["acer", " acer\n", "acer \n", "acer\n\n", "\tacer\n"] {
        let mut platform = FakePlatform::new();
        let root = install_acer(&mut platform, 7);
        platform.insert_file_with_permissions(root.join("name"), name, FilePermissions::READ_ONLY);

        assert!(matches!(
            discover_acer_hwmon(&mut platform, Path::new(HWMON_ROOT)),
            Err(AcerHwmonDiscoveryError::NoDevice)
        ));
    }
}

#[test]
fn unreadable_identity_or_directory_failure_fails_closed() {
    let mut unreadable = FakePlatform::new();
    unreadable.insert_file_with_permissions(
        Path::new(HWMON_ROOT).join("hwmon4/name"),
        "acer\n",
        FilePermissions::NONE,
    );
    assert!(matches!(
        discover_acer_hwmon(&mut unreadable, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::Platform(error))
            if error.kind() == PlatformErrorKind::PermissionDenied
    ));

    let mut missing_root = FakePlatform::new();
    assert!(matches!(
        discover_acer_hwmon(&mut missing_root, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::Platform(error))
            if error.kind() == PlatformErrorKind::NotFound
    ));
}

#[test]
fn endpoint_or_identity_disappearance_during_validation_fails_closed() {
    let mut endpoint_disappears = FakePlatform::new();
    let root = install_acer(&mut endpoint_disappears, 7);
    endpoint_disappears.queue_steps([
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Disappear(root.join("pwm1")),
    ]);
    assert!(discover_acer_hwmon(&mut endpoint_disappears, Path::new(HWMON_ROOT)).is_err());

    let mut identity_disappears = FakePlatform::new();
    let root = install_acer(&mut identity_disappears, 7);
    identity_disappears.queue_steps([
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Pass,
        FakeStep::Disappear(root.join("name")),
    ]);
    assert!(discover_acer_hwmon(&mut identity_disappears, Path::new(HWMON_ROOT)).is_err());
}

struct InjectedRootListing {
    platform: FakePlatform,
    directory: PathBuf,
    entries: Vec<PathBuf>,
}

impl FileAccess for InjectedRootListing {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        self.platform.read(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.platform.write(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        if directory == self.directory {
            Ok(self.entries.clone())
        } else {
            self.platform.list(directory)
        }
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        self.platform.permissions(path)
    }
}

impl IdentityBoundFileAccess for InjectedRootListing {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        self.platform.identity(path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        self.platform.read_bound(directory, expected, child)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        if directory == self.directory {
            self.platform.list_bound(directory, expected)?;
            Ok(self.entries.clone())
        } else {
            self.platform.list_bound(directory, expected)
        }
    }
}

#[test]
fn rejects_malformed_or_out_of_root_candidate_listings() {
    for invalid in [
        Path::new(HWMON_ROOT).join("hwmonx"),
        Path::new(HWMON_ROOT).join("nested/hwmon7"),
        PathBuf::from("/other/hwmon7"),
    ] {
        let mut platform = FakePlatform::new();
        let valid = install_acer(&mut platform, 7);
        let mut injected = InjectedRootListing {
            platform,
            directory: PathBuf::from(HWMON_ROOT),
            entries: vec![valid, invalid],
        };

        assert!(matches!(
            discover_acer_hwmon(&mut injected, Path::new(HWMON_ROOT)),
            Err(AcerHwmonDiscoveryError::InvalidAbi { .. })
        ));
    }
}

#[test]
fn rejects_duplicate_identity_or_endpoint_directory_entries() {
    let mut platform = FakePlatform::new();
    let root = install_acer(&mut platform, 7);
    let duplicate_root = root.clone();
    let mut duplicate_identity = InjectedRootListing {
        platform,
        directory: PathBuf::from(HWMON_ROOT),
        entries: vec![root, duplicate_root],
    };
    assert!(matches!(
        discover_acer_hwmon(&mut duplicate_identity, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::AmbiguousDevices { count: 2 })
    ));

    let mut platform = FakePlatform::new();
    let root = install_acer(&mut platform, 7);
    let mut entries = platform.list(&root).unwrap();
    entries.push(root.join("pwm1"));
    let mut duplicate_endpoint = InjectedRootListing {
        platform,
        directory: root,
        entries,
    };
    assert!(matches!(
        discover_acer_hwmon(&mut duplicate_endpoint, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::InvalidAbi { .. })
    ));

    let mut platform = FakePlatform::new();
    let root = install_acer(&mut platform, 7);
    let mut entries = platform.list(&root).unwrap();
    entries.push(root.join("nested/pwm1"));
    let mut nested_endpoint = InjectedRootListing {
        platform,
        directory: root,
        entries,
    };
    assert!(matches!(
        discover_acer_hwmon(&mut nested_endpoint, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::InvalidAbi { .. })
    ));
}

struct ChangingPermissions {
    platform: FakePlatform,
    path: PathBuf,
    calls: usize,
}

impl FileAccess for ChangingPermissions {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        self.platform.read(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.platform.write(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        self.platform.list(directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        if path == self.path {
            self.calls += 1;
            if self.calls >= 3 {
                return Ok(FilePermissions::READ_ONLY);
            }
        }
        self.platform.permissions(path)
    }
}

impl IdentityBoundFileAccess for ChangingPermissions {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        self.platform.identity(path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        self.platform.read_bound(directory, expected, child)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.platform.list_bound(directory, expected)
    }
}

#[test]
fn endpoint_permissions_changing_before_final_validation_fail_closed() {
    let mut platform = FakePlatform::new();
    let root = install_acer(&mut platform, 7);
    let mut changing = ChangingPermissions {
        platform,
        path: root.join("pwm1"),
        calls: 0,
    };

    assert!(matches!(
        discover_acer_hwmon(&mut changing, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::InvalidPermissions { .. })
    ));
}

struct ChangingIdentity {
    platform: FakePlatform,
    path: PathBuf,
    reads: usize,
}

impl FileAccess for ChangingIdentity {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        if path == self.path {
            self.reads += 1;
            if self.reads > 1 {
                return Ok("acer\n".into());
            }
        }
        self.platform.read(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.platform.write(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        self.platform.list(directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        self.platform.permissions(path)
    }
}

impl IdentityBoundFileAccess for ChangingIdentity {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        self.platform.identity(path)
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        let path = directory.join(child);
        if path == self.path {
            self.reads += 1;
            if self.reads > 1 {
                return Ok("acer\n".into());
            }
        }
        self.platform.read_bound(directory, expected, child)
    }

    fn list_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
    ) -> Result<Vec<PathBuf>, PlatformError> {
        self.platform.list_bound(directory, expected)
    }
}

#[test]
fn identity_becoming_ambiguous_during_validation_fails_closed() {
    let mut platform = FakePlatform::new();
    install_acer(&mut platform, 7);
    let changing_name = Path::new(HWMON_ROOT).join("hwmon8/name");
    platform.insert_file_with_permissions(&changing_name, "coretemp\n", FilePermissions::READ_ONLY);
    let mut changing = ChangingIdentity {
        platform,
        path: changing_name,
        reads: 0,
    };

    assert!(matches!(
        discover_acer_hwmon(&mut changing, Path::new(HWMON_ROOT)),
        Err(AcerHwmonDiscoveryError::AmbiguousDevices { count: 2 })
    ));
}
