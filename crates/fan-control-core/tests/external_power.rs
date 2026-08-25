use std::path::{Path, PathBuf};

use fan_control_core::{
    ExternalPower, FakePlatform, FileAccess, FilePermissions, PlatformError, observe_external_power,
};

const POWER_SUPPLY_ROOT: &str = "/sys/class/power_supply";

#[test]
fn stable_online_and_offline_mains_map_to_ac_and_battery() {
    let mut online = platform_with_supply("ACAD", "Mains\n", Some("1\n"));
    assert_eq!(
        observe_external_power(&mut online, Path::new(POWER_SUPPLY_ROOT)),
        ExternalPower::Connected
    );

    let mut offline = platform_with_supply("ACAD", "Mains\n", Some("0\n"));
    assert_eq!(
        observe_external_power(&mut offline, Path::new(POWER_SUPPLY_ROOT)),
        ExternalPower::Disconnected
    );
}

#[test]
fn battery_supplies_are_not_mistaken_for_external_power() {
    let mut platform = platform_with_supply("BAT0", "Battery\n", None);
    install_supply(&mut platform, "ACAD", "Mains\n", Some("0\n"));

    assert_eq!(
        observe_external_power(&mut platform, Path::new(POWER_SUPPLY_ROOT)),
        ExternalPower::Disconnected
    );
}

#[test]
fn missing_or_invalid_observations_are_unknown() {
    let mut missing_root = FakePlatform::new();
    assert_unknown(&mut missing_root);

    let mut no_mains = platform_with_supply("BAT0", "Battery\n", None);
    assert_unknown(&mut no_mains);

    let mut missing_online = platform_with_supply("ACAD", "Mains\n", None);
    assert_unknown(&mut missing_online);

    for payload in ["", "2\n", "true\n", "0", " 0\n", "0\n1\n"] {
        let mut malformed = platform_with_supply("ACAD", "Mains\n", Some(payload));
        assert_unknown(&mut malformed);
    }

    let mut unreadable_type = platform_with_supply("ACAD", "Mains\n", Some("1\n"));
    unreadable_type.set_file_permissions(
        Path::new(POWER_SUPPLY_ROOT).join("ACAD/type"),
        FilePermissions::NONE,
    );
    assert_unknown(&mut unreadable_type);
}

#[test]
fn conflicting_mains_observations_are_unknown() {
    let mut platform = platform_with_supply("AC0", "Mains\n", Some("1\n"));
    install_supply(&mut platform, "AC1", "Mains\n", Some("0\n"));

    assert_unknown(&mut platform);
}

#[test]
fn a_transition_between_snapshot_passes_is_unknown() {
    let platform = platform_with_supply("ACAD", "Mains\n", Some("0\n"));
    let online_path = Path::new(POWER_SUPPLY_ROOT).join("ACAD/online");
    let mut transitioning = ChangingRead::new(platform, online_path, "0\n", "1\n");

    assert_eq!(
        observe_external_power(&mut transitioning, Path::new(POWER_SUPPLY_ROOT)),
        ExternalPower::Unknown
    );
}

fn assert_unknown(platform: &mut dyn FileAccess) {
    assert_eq!(
        observe_external_power(platform, Path::new(POWER_SUPPLY_ROOT)),
        ExternalPower::Unknown
    );
}

fn platform_with_supply(name: &str, kind: &str, online: Option<&str>) -> FakePlatform {
    let mut platform = FakePlatform::new();
    install_supply(&mut platform, name, kind, online);
    platform
}

fn install_supply(platform: &mut FakePlatform, name: &str, kind: &str, online: Option<&str>) {
    let root = Path::new(POWER_SUPPLY_ROOT).join(name);
    platform.insert_file(root.join("type"), kind);
    if let Some(online) = online {
        platform.insert_file(root.join("online"), online);
    }
}

struct ChangingRead {
    inner: FakePlatform,
    path: PathBuf,
    first: String,
    later: String,
    reads: usize,
}

impl ChangingRead {
    fn new(
        inner: FakePlatform,
        path: PathBuf,
        first: impl Into<String>,
        later: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            path,
            first: first.into(),
            later: later.into(),
            reads: 0,
        }
    }
}

impl FileAccess for ChangingRead {
    fn read(&mut self, path: &Path) -> Result<String, PlatformError> {
        if path == self.path {
            self.reads += 1;
            return Ok(if self.reads == 1 {
                self.first.clone()
            } else {
                self.later.clone()
            });
        }
        self.inner.read(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> Result<(), PlatformError> {
        self.inner.write(path, contents)
    }

    fn list(&mut self, directory: &Path) -> Result<Vec<PathBuf>, PlatformError> {
        self.inner.list(directory)
    }

    fn permissions(&mut self, path: &Path) -> Result<FilePermissions, PlatformError> {
        self.inner.permissions(path)
    }
}
