use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use crate::{ExternalPower, FileAccess};

const MAINS_TYPE: &str = "Mains\n";
const BATTERY_TYPE: &str = "Battery\n";
const ONLINE: &str = "1\n";
const OFFLINE: &str = "0\n";

/// Observes one conservative external-power snapshot.
///
/// Only two identical passes over one or more unambiguous `Mains` supplies are trusted. Any
/// missing, changing, conflicting, malformed, or unreadable observation is `Unknown`; output
/// selection treats that state as AC without changing CPU/GPU sample validity.
pub fn observe_external_power(
    files: &mut dyn FileAccess,
    power_supply_root: &Path,
) -> ExternalPower {
    let Some(first) = observe_mains(files, power_supply_root) else {
        return ExternalPower::Unknown;
    };
    let Some(second) = observe_mains(files, power_supply_root) else {
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

fn observe_mains(
    files: &mut dyn FileAccess,
    power_supply_root: &Path,
) -> Option<BTreeMap<PathBuf, bool>> {
    let candidates = files.list(power_supply_root).ok()?;
    let mut seen = BTreeSet::new();
    let mut mains = BTreeMap::new();

    for candidate in candidates {
        if candidate.parent() != Some(power_supply_root)
            || candidate
                .file_name()
                .and_then(|name| name.to_str())
                .is_none()
            || !seen.insert(candidate.clone())
        {
            return None;
        }

        match files.read(&candidate.join("type")).ok()?.as_str() {
            BATTERY_TYPE => {}
            MAINS_TYPE => {
                let online = match files.read(&candidate.join("online")).ok()?.as_str() {
                    ONLINE => true,
                    OFFLINE => false,
                    _ => return None,
                };
                mains.insert(candidate, online);
            }
            _ => return None,
        }
    }

    (!mains.is_empty()).then_some(mains)
}
