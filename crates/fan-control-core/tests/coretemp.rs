use std::path::{Path, PathBuf};

use fan_control_core::{
    CoretempError, FakePlatform, FileAccess, FileIdentity, FilePermissions,
    IdentityBoundFileAccess, PlatformError, PlatformErrorKind, PlatformOperation,
    discover_coretemp,
};

const HWMON_ROOT: &str = "/sys/class/hwmon";

fn install_coretemp(platform: &mut FakePlatform, index: usize) -> PathBuf {
    let root = Path::new(HWMON_ROOT).join(format!("hwmon{index}"));
    platform.insert_file_with_permissions(
        root.join("name"),
        "coretemp\n",
        FilePermissions::READ_ONLY,
    );
    root
}

fn install_channel(
    platform: &mut FakePlatform,
    root: &Path,
    index: usize,
    label: &str,
    input_millicelsius: &str,
    tjmax_millicelsius: &str,
) {
    for (suffix, contents) in [
        ("label", format!("{label}\n")),
        ("input", format!("{input_millicelsius}\n")),
        ("crit", format!("{tjmax_millicelsius}\n")),
    ] {
        platform.insert_file_with_permissions(
            root.join(format!("temp{index}_{suffix}")),
            contents,
            FilePermissions::READ_ONLY,
        );
    }
}

#[test]
fn discovers_by_name_and_labels_at_arbitrary_indices_and_samples_the_hottest_channel() {
    let mut platform = FakePlatform::new();
    platform.insert_file_with_permissions(
        Path::new(HWMON_ROOT).join("hwmon0/name"),
        "acer\n",
        FilePermissions::READ_ONLY,
    );
    let root = install_coretemp(&mut platform, 47);
    install_channel(&mut platform, &root, 8, "Core 1", "71000", "100000");
    install_channel(&mut platform, &root, 19, "Package id 0", "68000", "100000");
    install_channel(&mut platform, &root, 2, "Core 0", "69000", "100000");
    install_channel(&mut platform, &root, 4, "Graphics", "99000", "100000");

    let device = discover_coretemp(&mut platform, Path::new(HWMON_ROOT)).unwrap();
    let sample = device.sample(&mut platform).unwrap();

    assert_eq!(device.root(), root);
    assert_eq!(sample.value(), 71.0);
}

#[test]
fn rejects_absent_or_ambiguous_coretemp_devices() {
    let mut absent = FakePlatform::new();
    absent.insert_file_with_permissions(
        Path::new(HWMON_ROOT).join("hwmon3/name"),
        "acer\n",
        FilePermissions::READ_ONLY,
    );
    assert!(matches!(
        discover_coretemp(&mut absent, Path::new(HWMON_ROOT)),
        Err(CoretempError::NoDevice)
    ));

    let mut duplicate = FakePlatform::new();
    let first = install_coretemp(&mut duplicate, 2);
    install_channel(&mut duplicate, &first, 1, "Package id 0", "50000", "100000");
    let second = install_coretemp(&mut duplicate, 90);
    install_channel(
        &mut duplicate,
        &second,
        1,
        "Package id 0",
        "50000",
        "100000",
    );
    assert!(matches!(
        discover_coretemp(&mut duplicate, Path::new(HWMON_ROOT)),
        Err(CoretempError::AmbiguousDevices { count: 2 })
    ));
}

struct InjectedListing {
    platform: FakePlatform,
    directory: PathBuf,
    entries: Vec<PathBuf>,
}

impl FileAccess for InjectedListing {
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

impl IdentityBoundFileAccess for InjectedListing {
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
            Ok(self.entries.clone())
        } else {
            self.platform.list_bound(directory, expected)
        }
    }
}

#[test]
fn rejects_malformed_out_of_root_or_duplicate_discovery_listings() {
    for invalid in [
        Path::new(HWMON_ROOT).join("hwmonx"),
        Path::new(HWMON_ROOT).join("nested/hwmon7"),
        PathBuf::from("/other/hwmon7"),
    ] {
        let mut platform = FakePlatform::new();
        let root = install_coretemp(&mut platform, 7);
        install_channel(&mut platform, &root, 1, "Package id 0", "50000", "100000");
        let mut injected = InjectedListing {
            platform,
            directory: PathBuf::from(HWMON_ROOT),
            entries: vec![root, invalid],
        };

        assert!(matches!(
            discover_coretemp(&mut injected, Path::new(HWMON_ROOT)),
            Err(CoretempError::InvalidAbi { .. })
        ));
    }

    let mut platform = FakePlatform::new();
    let root = install_coretemp(&mut platform, 7);
    install_channel(&mut platform, &root, 1, "Package id 0", "50000", "100000");
    let mut duplicate_device = InjectedListing {
        platform,
        directory: PathBuf::from(HWMON_ROOT),
        entries: vec![root.clone(), root],
    };
    assert!(matches!(
        discover_coretemp(&mut duplicate_device, Path::new(HWMON_ROOT)),
        Err(CoretempError::AmbiguousDevices { count: 2 })
    ));

    let mut platform = FakePlatform::new();
    let root = install_coretemp(&mut platform, 7);
    install_channel(&mut platform, &root, 1, "Package id 0", "50000", "100000");
    let mut entries = platform.list(&root).unwrap();
    entries.push(root.join("temp1_label"));
    let mut duplicate_channel = InjectedListing {
        platform,
        directory: root,
        entries,
    };
    assert!(matches!(
        discover_coretemp(&mut duplicate_channel, Path::new(HWMON_ROOT)),
        Err(CoretempError::InvalidAbi { .. })
    ));
}

#[test]
fn rejects_unreadable_discovery_data_and_listing_failures() {
    let mut unreadable_name = FakePlatform::new();
    let root = install_coretemp(&mut unreadable_name, 7);
    unreadable_name.set_file_permissions(root.join("name"), FilePermissions::NONE);
    assert!(matches!(
        discover_coretemp(&mut unreadable_name, Path::new(HWMON_ROOT)),
        Err(CoretempError::Platform(error))
            if error.kind() == PlatformErrorKind::PermissionDenied
    ));

    let mut unreadable_label = FakePlatform::new();
    let root = install_coretemp(&mut unreadable_label, 7);
    install_channel(
        &mut unreadable_label,
        &root,
        1,
        "Package id 0",
        "50000",
        "100000",
    );
    unreadable_label.set_file_permissions(root.join("temp1_label"), FilePermissions::NONE);
    assert!(matches!(
        discover_coretemp(&mut unreadable_label, Path::new(HWMON_ROOT)),
        Err(CoretempError::Platform(error))
            if error.kind() == PlatformErrorKind::PermissionDenied
    ));

    let mut missing_root = FakePlatform::new();
    assert!(matches!(
        discover_coretemp(&mut missing_root, Path::new(HWMON_ROOT)),
        Err(CoretempError::Platform(error)) if error.kind() == PlatformErrorKind::NotFound
    ));
}

#[test]
fn requires_a_package_channel_and_rejects_duplicate_selected_labels() {
    let mut no_package = FakePlatform::new();
    let root = install_coretemp(&mut no_package, 7);
    install_channel(&mut no_package, &root, 2, "Core 0", "50000", "100000");
    assert!(matches!(
        discover_coretemp(&mut no_package, Path::new(HWMON_ROOT)),
        Err(CoretempError::MissingPackageChannel)
    ));

    let mut duplicate_label = FakePlatform::new();
    let root = install_coretemp(&mut duplicate_label, 7);
    install_channel(
        &mut duplicate_label,
        &root,
        1,
        "Package id 0",
        "50000",
        "100000",
    );
    install_channel(
        &mut duplicate_label,
        &root,
        9,
        "Package id 0",
        "51000",
        "100000",
    );
    assert!(matches!(
        discover_coretemp(&mut duplicate_label, Path::new(HWMON_ROOT)),
        Err(CoretempError::InvalidAbi { .. })
    ));
}

#[test]
fn rejects_missing_or_unreadable_selected_inputs() {
    let mut missing = FakePlatform::new();
    let root = install_coretemp(&mut missing, 7);
    install_channel(&mut missing, &root, 1, "Package id 0", "50000", "100000");
    missing.remove_path(root.join("temp1_input"));
    let device = discover_coretemp(&mut missing, Path::new(HWMON_ROOT)).unwrap();
    assert!(matches!(
        device.sample(&mut missing),
        Err(CoretempError::Platform(error)) if error.kind() == PlatformErrorKind::NotFound
    ));

    let mut unreadable = FakePlatform::new();
    let root = install_coretemp(&mut unreadable, 7);
    install_channel(&mut unreadable, &root, 1, "Package id 0", "50000", "100000");
    unreadable.set_file_permissions(root.join("temp1_input"), FilePermissions::NONE);
    let device = discover_coretemp(&mut unreadable, Path::new(HWMON_ROOT)).unwrap();
    assert!(matches!(
        device.sample(&mut unreadable),
        Err(CoretempError::Platform(error)) if error.kind() == PlatformErrorKind::PermissionDenied
    ));
}

#[test]
fn rejects_faulted_or_critical_alarm_channels() {
    for suffix in ["fault", "crit_alarm"] {
        let mut platform = FakePlatform::new();
        let root = install_coretemp(&mut platform, 7);
        install_channel(&mut platform, &root, 1, "Package id 0", "50000", "100000");
        platform.insert_file_with_permissions(
            root.join(format!("temp1_{suffix}")),
            "1\n",
            FilePermissions::READ_ONLY,
        );

        let device = discover_coretemp(&mut platform, Path::new(HWMON_ROOT)).unwrap();
        assert!(matches!(
            device.sample(&mut platform),
            Err(CoretempError::InvalidSample { .. })
        ));
    }
}

#[test]
fn accepts_absent_optional_health_flags_but_rejects_unreadable_or_malformed_flags() {
    let mut healthy = FakePlatform::new();
    let root = install_coretemp(&mut healthy, 7);
    install_channel(&mut healthy, &root, 1, "Package id 0", "50000", "100000");
    assert_eq!(
        discover_coretemp(&mut healthy, Path::new(HWMON_ROOT))
            .unwrap()
            .sample(&mut healthy)
            .unwrap()
            .value(),
        50.0
    );

    for contents in ["2\n", "false\n", "0"] {
        let mut malformed = FakePlatform::new();
        let root = install_coretemp(&mut malformed, 7);
        install_channel(&mut malformed, &root, 1, "Package id 0", "50000", "100000");
        malformed.insert_file_with_permissions(
            root.join("temp1_fault"),
            contents,
            FilePermissions::READ_ONLY,
        );
        let device = discover_coretemp(&mut malformed, Path::new(HWMON_ROOT)).unwrap();
        assert!(matches!(
            device.sample(&mut malformed),
            Err(CoretempError::InvalidSample { .. })
        ));
    }

    let mut unreadable = FakePlatform::new();
    let root = install_coretemp(&mut unreadable, 7);
    install_channel(&mut unreadable, &root, 1, "Package id 0", "50000", "100000");
    unreadable.insert_file_with_permissions(
        root.join("temp1_crit_alarm"),
        "0\n",
        FilePermissions::NONE,
    );
    let device = discover_coretemp(&mut unreadable, Path::new(HWMON_ROOT)).unwrap();
    assert!(matches!(
        device.sample(&mut unreadable),
        Err(CoretempError::Platform(error)) if error.kind() == PlatformErrorKind::PermissionDenied
    ));
}

#[test]
fn rejects_malformed_negative_or_above_tjmax_samples_and_invalid_tjmax() {
    for (input, tjmax) in [
        ("not-a-number", "100000"),
        ("50000 ", "100000"),
        ("-1", "100000"),
        ("-0", "100000"),
        ("1", "100000"),
        ("50001", "100000"),
        ("100001", "100000"),
        ("50000", "0"),
        ("50000", "69000"),
        ("50000", "100001"),
        ("50000", "126000"),
        ("50000", "not-a-number"),
    ] {
        let mut platform = FakePlatform::new();
        let root = install_coretemp(&mut platform, 7);
        install_channel(&mut platform, &root, 1, "Package id 0", input, tjmax);
        let device = discover_coretemp(&mut platform, Path::new(HWMON_ROOT)).unwrap();

        assert!(matches!(
            device.sample(&mut platform),
            Err(CoretempError::InvalidSample { .. })
        ));
    }
}

#[test]
fn accepts_documented_coretemp_temperature_and_tjmax_endpoints() {
    for (input, tjmax, expected) in [("0", "70000", 0.0), ("125000", "125000", 125.0)] {
        let mut platform = FakePlatform::new();
        let root = install_coretemp(&mut platform, 7);
        install_channel(&mut platform, &root, 1, "Package id 0", input, tjmax);

        assert_eq!(
            discover_coretemp(&mut platform, Path::new(HWMON_ROOT))
                .unwrap()
                .sample(&mut platform)
                .unwrap()
                .value(),
            expected
        );
    }
}

struct ChangingRead {
    platform: FakePlatform,
    path: PathBuf,
    stable_reads: usize,
    reads: usize,
    replacement: String,
}

impl FileAccess for ChangingRead {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        if path == self.path {
            self.reads += 1;
            if self.reads > self.stable_reads {
                return Ok(self.replacement.clone());
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

impl IdentityBoundFileAccess for ChangingRead {
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
            if self.reads > self.stable_reads {
                return Ok(self.replacement.clone());
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
fn rejects_identity_or_channel_rebinding_before_and_after_channel_reads() {
    for (suffix, replacement) in [("temp1_label", "Core 0\n"), ("name", "acer\n")] {
        for stable_reads in [2, 4] {
            let mut platform = FakePlatform::new();
            let root = install_coretemp(&mut platform, 7);
            install_channel(&mut platform, &root, 1, "Package id 0", "50000", "100000");
            let input = root.join("temp1_input");
            let mut changing = ChangingRead {
                platform,
                path: root.join(suffix),
                stable_reads,
                reads: 0,
                replacement: replacement.into(),
            };
            let device = discover_coretemp(&mut changing, Path::new(HWMON_ROOT)).unwrap();

            assert!(device.sample(&mut changing).is_err());
            let input_was_read = changing
                .platform
                .operations()
                .contains(&PlatformOperation::Read(input));
            assert_eq!(input_was_read, stable_reads == 4);
        }
    }
}

struct SameLabelRebinding {
    platform: FakePlatform,
    root: PathBuf,
    input: PathBuf,
    rebound: bool,
}

impl FileAccess for SameLabelRebinding {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        let result = self.platform.read(path);
        if path == self.input {
            self.rebound = true;
        }
        result
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

impl IdentityBoundFileAccess for SameLabelRebinding {
    fn identity(&mut self, path: &Path) -> Result<FileIdentity, PlatformError> {
        if path == self.root && self.rebound {
            Ok(FileIdentity::from_raw(u64::MAX, u64::MAX))
        } else {
            self.platform.identity(path)
        }
    }

    fn read_bound(
        &mut self,
        directory: &Path,
        expected: FileIdentity,
        child: &str,
    ) -> Result<String, PlatformError> {
        if child == "temp1_input" {
            self.rebound = true;
            return Err(PlatformError::new(
                PlatformErrorKind::Unavailable,
                "backing directory identity changed",
            ));
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
fn rejects_same_name_and_labels_when_the_backing_device_rebinds_during_sampling() {
    let mut platform = FakePlatform::new();
    let root = install_coretemp(&mut platform, 7);
    install_channel(&mut platform, &root, 1, "Package id 0", "50000", "100000");
    let input = root.join("temp1_input");
    let mut rebinding = SameLabelRebinding {
        platform,
        root,
        input,
        rebound: false,
    };
    let device = discover_coretemp(&mut rebinding, Path::new(HWMON_ROOT)).unwrap();

    assert!(matches!(
        device.sample(&mut rebinding),
        Err(CoretempError::Platform(error))
            if error.kind() == PlatformErrorKind::Unavailable
    ));
}

struct AbaRebinding {
    platform: FakePlatform,
    root: PathBuf,
}

impl FileAccess for AbaRebinding {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        if path == self.root.join("temp1_input") {
            return Ok("10000\n".into());
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

impl IdentityBoundFileAccess for AbaRebinding {
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
fn identity_bound_reads_prevent_an_invisible_a_to_b_to_a_rebind() {
    let mut platform = FakePlatform::new();
    let root = install_coretemp(&mut platform, 7);
    install_channel(&mut platform, &root, 1, "Package id 0", "50000", "100000");
    let mut aba = AbaRebinding { platform, root };
    let device = discover_coretemp(&mut aba, Path::new(HWMON_ROOT)).unwrap();

    assert_eq!(device.sample(&mut aba).unwrap().value(), 50.0);
}

struct AbaDiscovery {
    platform: FakePlatform,
    rebound_label: PathBuf,
}

impl FileAccess for AbaDiscovery {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        if path == self.rebound_label {
            return Ok("Core 0\n".into());
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

impl IdentityBoundFileAccess for AbaDiscovery {
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
fn identity_bound_discovery_ignores_an_invisible_a_to_b_to_a_label_rebind() {
    let mut platform = FakePlatform::new();
    let root = install_coretemp(&mut platform, 7);
    install_channel(&mut platform, &root, 1, "Package id 0", "50000", "100000");
    install_channel(&mut platform, &root, 2, "Graphics", "120000", "125000");
    let rebound_label = root.join("temp2_label");
    let mut aba = AbaDiscovery {
        platform,
        rebound_label,
    };

    assert_eq!(
        discover_coretemp(&mut aba, Path::new(HWMON_ROOT))
            .unwrap()
            .sample(&mut aba)
            .unwrap()
            .value(),
        50.0
    );
}
