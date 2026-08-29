const README: &str = include_str!("../../../README.md");

use std::path::Path;
use std::process::{Command, Stdio};

fn recovery_runbook() -> &'static str {
    README
        .split_once("## Side-by-side candidate install and recovery")
        .expect("README must contain the side-by-side recovery runbook")
        .1
        .split_once("## Project boundary")
        .expect("the recovery runbook must remain a distinct README section")
        .0
}

fn assert_in_order(haystack: &str, needles: &[&str]) {
    let mut remaining = haystack;
    for needle in needles {
        let offset = remaining
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered runbook step: {needle}"));
        remaining = &remaining[offset + needle.len()..];
    }
}

fn section<'a>(runbook: &'a str, start: &str, end: &str) -> &'a str {
    runbook
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"))
        .0
}

fn shell_block_after<'a>(source: &'a str, marker: &str) -> &'a str {
    source
        .split_once(marker)
        .unwrap_or_else(|| panic!("missing shell-block marker: {marker}"))
        .1
        .split_once("```sh\n")
        .expect("marker must be followed by a shell block")
        .1
        .split_once("```")
        .expect("shell block must be closed")
        .0
}

fn has_exact_line(source: &str, expected: &str) -> bool {
    source.lines().any(|line| line.trim() == expected)
}

#[test]
fn candidate_install_keeps_both_stock_entries_and_the_controller_disabled() {
    let runbook = recovery_runbook();
    let preinstall = section(
        runbook,
        "### Record the stock recovery entries",
        "### Install without changing the default",
    );
    let install = section(
        runbook,
        "### Install without changing the default",
        "### Return to stock before removal",
    );
    let one_shot = section(
        install,
        "Do not persistently change the default",
        "After boot, verify the exact candidate",
    );
    let candidate_boot = section(
        install,
        "After boot, verify the exact candidate",
        "The candidate entry must show `selected`",
    );
    let install_gate = shell_block_after(
        install,
        "Installing this unique package set together does not\nreplace either stock package:",
    );
    let candidate_entry_creation = shell_block_after(
        install,
        "XBOOTLDR mount cannot silently redirect this step:",
    );

    for package in [
        "linux-cachyos",
        "linux-cachyos-lts",
        "linux-cachyos-pt31553",
        "linux-cachyos-pt31553-headers",
        "linux-cachyos-pt31553-nvidia-open",
    ] {
        assert!(runbook.contains(package), "runbook omits {package}");
    }

    assert!(preinstall.contains("linux-cachyos-lts 6.18"));
    assert!(preinstall.contains("Product: systemd-boot"));
    assert_in_order(
        preinstall,
        &[
            "bootctl_status=$(/usr/bin/env LC_ALL=C /usr/bin/bootctl status --no-pager)",
            "case \"$bootctl_status\" in",
        ],
    );
    assert!(preinstall.contains("paths(by_id[stock_id], \"linux\")"));
    assert!(preinstall.contains("/vmlinuz-linux-cachyos"));
    assert!(preinstall.contains("/initramfs-linux-cachyos.img"));
    assert!(preinstall.contains("paths(by_id[lts_id], \"linux\")"));
    assert!(preinstall.contains("/vmlinuz-linux-cachyos-lts"));
    assert!(preinstall.contains("/initramfs-linux-cachyos-lts.img"));
    assert!(preinstall.contains("def require_loader_files(entry):"));
    assert!(preinstall.contains("host_path.is_file() and host_path.stat().st_size > 0"));
    assert!(preinstall.contains("require_loader_files(by_id[stock_id])"));
    assert!(preinstall.contains("require_loader_files(by_id[lts_id])"));
    assert!(has_exact_line(
        preinstall,
        "assert expected_default_id in {stock_id, lts_id}"
    ));
    assert!(has_exact_line(
        preinstall,
        "assert selected[0] in {stock_id, lts_id}"
    ));
    assert!(preinstall.contains("running_module_owner"));
    assert!(has_exact_line(
        preinstall,
        "test \"$(/usr/bin/systemctl is-enabled \"$unit\")\" = disabled"
    ));
    assert!(has_exact_line(
        preinstall,
        "test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive"
    ));
    assert!(preinstall.contains("systemctl cat \"$unit\""));
    assert!(preinstall.contains("test -x /usr/bin/pt31553-fan-restore"));
    assert_in_order(
        preinstall,
        &[
            "--property=ActiveEnterTimestampMonotonic --value",
            "--property=InactiveEnterTimestampMonotonic --value",
            "_EXE=/usr/bin/pt31553-fand",
            "pgrep -x pt31553-fand",
            "tee /run/pt31553-clean-stock-boot-id",
        ],
    );

    assert!(install.contains("scripts/verify-package-provenance"));
    assert!(install.contains("/usr/bin/cmp \"$provenance_record\""));
    assert!(install.contains("record[\"kernel\"][\"image_sha256\"]"));
    assert!(install.contains("candidate_config_dir="));
    assert!(install.contains("sudo /usr/bin/mkinitcpio -k \"$candidate_release\""));
    assert!(install.contains("/usr/bin/cmp \"$packaged_candidate_image\" \"$candidate_image\""));
    assert!(install.contains("linux-cachyos-pt31553.conf"));
    assert_in_order(
        install,
        &[
            "assert not candidate_config.exists() and not candidate_config.is_symlink()",
            "assert not any(entry.get(\"linux\") == \"/vmlinuz-linux-cachyos-pt31553\"",
            "if test -e \"$candidate_image\" || test -e \"$candidate_initramfs\"; then",
            "rm -f -- \"$candidate_image\" \"$candidate_initramfs\"",
            "test ! -e \"$candidate_image\"",
            "test ! -e \"$candidate_initramfs\"",
            "candidate_image_tmp=$(sudo /usr/bin/mktemp",
        ],
    );
    assert_in_order(
        candidate_entry_creation,
        &[
            "candidate_config=\"$candidate_config_dir/linux-cachyos-pt31553.conf\"",
            "test ! -e \"$candidate_config\"",
            "test ! -L \"$candidate_config\"",
            "candidate_config_source_tmp=$(/usr/bin/mktemp)",
            "candidate_config_publish_tmp=$(sudo /usr/bin/mktemp",
            "sudo /usr/bin/bootctl set-default \"$default_entry\"",
            "verify_pinned_stock_default absent",
            "sudo /usr/bin/install -o root -g root -m 0644",
            "sudo /usr/bin/sync -f \"$candidate_config_publish_tmp\"",
            "sudo /usr/bin/mv -T \"$candidate_config_publish_tmp\" \"$candidate_config\"",
            "test -f \"$candidate_config\"",
            "verify_pinned_stock_default present",
        ],
    );
    assert!(install.contains("stock.get(\"options\")"));
    assert!(install.contains("sudo /usr/bin/install -o root -g root -m 0644"));
    assert!(install.contains("candidate_path == stock_path.parent"));
    assert!(install.contains("candidate_image=\"$candidate_boot_root/"));
    assert!(install.contains("for entry_id in (stock_id, lts_id, candidate_id):"));
    assert_eq!(
        runbook
            .matches("default_entry='REPLACE_WITH_CURRENT_DEFAULT_STOCK_ENTRY_ID'")
            .count(),
        3
    );
    assert_eq!(
        runbook
            .matches("default_entry=$(sudo /usr/bin/cat /run/pt31553-stock-default-entry)")
            .count(),
        4
    );
    assert!(install.contains("stock_entry='REPLACE_WITH_STOCK_STANDARD_ENTRY_ID'"));
    assert!(install.contains("lts_entry='REPLACE_WITH_STOCK_LTS_ENTRY_ID'"));
    assert!(install.contains("candidate_entry='REPLACE_WITH_PT31553_CANDIDATE_ENTRY_ID'"));
    assert!(install.contains("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c\") == 0"));
    assert!(install.contains("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c\") == 1"));
    assert!(install.contains("efi-readvar -v db"));
    assert!(install.contains("sig-list-to-certs"));
    assert!(!install.contains("sbctl sign"));
    assert!(install.contains("sbverify --cert \"$image_cert\""));
    assert!(install.contains("expected_image_cert_sha256"));
    assert!(has_exact_line(
        install,
        "assert default_id in {stock_id, lts_id}"
    ));
    let default_repair = shell_block_after(
        install,
        "Installation hooks must not move the persistent default",
    );
    assert_in_order(
        default_repair,
        &[
            "assert expected_default_id in {stock_id, lts_id}",
            "bootctl set-default \"$default_entry\"",
        ],
    );
    assert!(has_exact_line(install, "assert candidate_id != default_id"));
    assert!(has_exact_line(install, "assert selected == [candidate_id]"));
    assert!(install.contains("assert defaults == [expected_default_id]"));
    assert!(install.contains("/vmlinuz-linux-cachyos-pt31553"));
    assert!(install.contains("/initramfs-linux-cachyos-pt31553.img"));
    assert_in_order(
        install_gate,
        &[
            "scripts/verify-package-provenance",
            "/usr/bin/cmp \"$provenance_record\"",
            "bootctl set-default \"$default_entry\"",
            "chattr +i \"$default_efi_variable\"",
            "trap restore_writable_stock_default EXIT HUP INT TERM",
            "sudo /usr/bin/pacman -U",
            "restore_writable_stock_default",
            "trap - EXIT HUP INT TERM",
            "/usr/bin/pacman -Q",
            "paths(entry, field)",
            "host_path.is_file() and host_path.stat().st_size > 0",
        ],
    );
    assert_in_order(
        candidate_entry_creation,
        &[
            "bootctl set-default \"$default_entry\"",
            "verify_pinned_stock_default absent",
            "sudo /usr/bin/install -o root -g root -m 0644",
            "entry_status=$?",
            "test \"$entry_status\" = 0",
            "verify_pinned_stock_default present",
            "/usr/bin/bootctl list --no-pager",
        ],
    );
    assert_in_order(
        install,
        &[
            "sudo /usr/bin/pacman -U",
            "sudo /usr/bin/mkinitcpio -k \"$candidate_release\"",
            "sudo /usr/bin/mv -T \"$candidate_image_tmp\" \"$candidate_image\"",
            "Create the candidate's BLS Type #1 entry",
            "bootctl set-default \"$default_entry\"",
            "entry_status=$?",
            "verify_pinned_stock_default present",
            "Register the loader-visible candidate image",
            "sbverify --cert \"$image_cert\"",
        ],
    );

    assert_in_order(
        one_shot,
        &[
            "cat /proc/sys/kernel/random/boot_id",
            "cat /run/pt31553-clean-stock-boot-id",
            "assert len(matching) == 1",
            "assert expected_default_id in {stock_id, lts_id}",
            "assert defaults == [expected_default_id]",
            "assert candidate_id != expected_default_id",
            "assert paths(candidate, \"initrd\") == expected_initrds",
            "assert candidate_options == stock_options",
            "pt31553-verified-candidate-image-sha256",
            "pt31553-verified-candidate-initramfs-sha256",
            "sbverify --cert \"$image_cert\" \"$candidate_image\"",
            "test \"$(/usr/bin/systemctl is-enabled \"$unit\")\" = disabled",
            "test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive",
            "--property=ActiveEnterTimestampMonotonic --value",
            "--property=InactiveEnterTimestampMonotonic --value",
            "_EXE=/usr/bin/pt31553-fand",
            "pgrep -x pt31553-fand",
            "assert all(sum(entry.get(\"id\") == entry_id for entry in entries) == 1",
            "assert defaults == [expected_default_id]",
            "assert candidate_id != expected_default_id",
            "systemctl reboot --boot-loader-entry=\"$candidate_entry\"",
        ],
    );
    assert!(has_exact_line(
        one_shot,
        "test \"$(/usr/bin/systemctl is-enabled \"$unit\")\" = disabled"
    ));
    assert!(has_exact_line(
        one_shot,
        "test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive"
    ));
    let before_candidate_reboot = runbook
        .split_once("systemctl reboot --boot-loader-entry=\"$candidate_entry\"")
        .expect("runbook must contain the candidate one-shot reboot")
        .0;
    assert!(!before_candidate_reboot.contains("pt31553-fan-restore --restore"));
    assert_in_order(
        candidate_boot,
        &[
            "assert selected == [candidate_id]",
            "assert defaults == [expected_default_id]",
            "--property=ActiveEnterTimestampMonotonic --value",
            "--property=InactiveEnterTimestampMonotonic --value",
            "_EXE=/usr/bin/pt31553-fand",
            "pgrep -x pt31553-fand",
            "pt31553-fan-restore --restore",
        ],
    );
    assert_in_order(
        runbook,
        &[
            "full power-off/power-on",
            "assert selected[0] in {stock_id, lts_id}",
            "test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive",
            "/run/pt31553-clean-stock-boot-id",
            "cat /proc/sys/kernel/random/boot_id",
            "systemctl reboot --boot-loader-entry=\"$candidate_entry\"",
        ],
    );
    for line in runbook
        .lines()
        .filter(|line| line.contains("/usr/bin/python3"))
    {
        assert!(
            line.contains("-I"),
            "non-isolated Python safety gate: {line}"
        );
    }
    let optimized_assert = Command::new("/usr/bin/python3")
        .args(["-I", "-c", "assert False"])
        .env("PYTHONOPTIMIZE", "1")
        .stderr(Stdio::null())
        .status()
        .expect("isolated Python must be runnable");
    assert!(!optimized_assert.success());
    assert!(!runbook.contains("bootctl set-default \"$candidate_entry\""));
    assert!(runbook.contains("bootctl set-default \"$default_entry\""));
}

#[test]
fn secure_boot_checks_only_the_global_efi_variables() {
    let runbook = recovery_runbook();
    let global_guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
    let foreign_guid = "00000000-0000-0000-0000-000000000000";

    assert!(runbook.contains(&format!("SetupMode-{global_guid}")));
    assert!(runbook.contains(&format!("SecureBoot-{global_guid}")));
    assert!(!runbook.contains("glob(f\"{name}-*\")"));
    assert_ne!(
        format!("SecureBoot-{global_guid}"),
        format!("SecureBoot-{foreign_guid}")
    );
}

#[test]
fn lts_recovery_rejects_a_stale_candidate_initramfs() {
    let expected = ["/intel-ucode.img", "/initramfs-linux-cachyos-lts.img"];
    let stale = [
        "/intel-ucode.img",
        "/initramfs-linux-cachyos-lts.img",
        "/initramfs-linux-cachyos-pt31553.img",
    ];

    assert_ne!(stale.as_slice(), expected.as_slice());
    assert!(!expected.contains(&"/initramfs-linux-cachyos-pt31553.img"));
    assert_eq!(
        recovery_runbook()
            .matches(
                "assert initrds == [\"/intel-ucode.img\", \"/initramfs-linux-cachyos-lts.img\"]"
            )
            .count(),
        2
    );
}

#[test]
fn bootctl_json_origin_label_is_not_treated_as_the_entry_path() {
    let fixture = serde_json::json!({
        "type": "type1",
        "source": "esp",
        "id": "linux-cachyos.conf",
        "path": "/boot/loader/entries/linux-cachyos.conf",
        "root": "/boot",
        "linux": "/vmlinuz-linux-cachyos",
        "initrd": ["/initramfs-linux-cachyos.img"]
    });
    let root = Path::new(fixture["root"].as_str().unwrap());
    let path = Path::new(fixture["path"].as_str().unwrap());

    assert_eq!(fixture["source"], "esp");
    assert_eq!(
        path,
        root.join("loader")
            .join("entries")
            .join(fixture["id"].as_str().unwrap())
    );

    let runbook = recovery_runbook();
    assert!(runbook.contains("entry.get(\"type\") == \"type1\""));
    assert!(runbook.contains("entry.get(\"source\") in {\"esp\", \"xbootldr\"}"));
    assert!(runbook.contains("pathlib.Path(entry[\"root\"])"));
    assert!(runbook.contains("pathlib.Path(entry[\"path\"])"));
    assert!(!runbook.contains("pathlib.Path(entry[\"source\"])"));
    assert!(!runbook.contains("pathlib.Path(stock[\"source\"])"));

    let duplicate_fixture = serde_json::json!([
        fixture,
        {
            "type": "type1",
            "source": "xbootldr",
            "id": "linux-cachyos.conf",
            "path": "/efi/loader/entries/linux-cachyos.conf",
            "root": "/efi",
            "linux": "/vmlinuz-linux-cachyos",
            "initrd": ["/initramfs-linux-cachyos.img"]
        }
    ]);
    let duplicate_count = duplicate_fixture
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["id"] == "linux-cachyos.conf")
        .count();
    assert_eq!(duplicate_count, 2);
    assert!(
        runbook.contains("assert all(sum(entry.get(\"id\") == entry_id for entry in entries) == 1")
    );
    assert_in_order(
        runbook,
        &[
            "sum(entry.get(\"id\") == entry_id for entry in entries) == 1",
            "sudo /usr/bin/pacman -U",
        ],
    );
}

#[test]
fn recovery_confirms_firmware_auto_before_removing_any_package() {
    let runbook = recovery_runbook();
    let recovery = section(
        runbook,
        "### Return to stock before removal",
        "### Reverify the retained candidate before a successor",
    );
    let removal = recovery
        .split_once("Only after every preceding Auto and stock check passes")
        .expect("recovery must gate removal on Auto and stock checks")
        .1;
    let before_removal = recovery
        .split_once("Only after every preceding Auto and stock check passes")
        .expect("recovery must gate removal on Auto and stock checks")
        .0;

    assert_in_order(
        recovery,
        &[
            "systemctl stop pt31553-fan-sleep-guard.service",
            "systemctl stop pt31553-fand.service",
            "systemctl is-active pt31553-fan-sleep-guard.service",
            "/usr/bin/pt31553-fan-restore --restore",
            "systemctl reboot --boot-loader-entry=\"$lts_entry\"",
            "modinfo -n acer_wmi",
            "stock_acer_hwmon=",
            "pacman -R pt31553-fan-control",
            "for package in linux-cachyos-pt31553-nvidia-open",
            "pacman -R \"$package\"",
        ],
    );
    assert!(!runbook.contains("/usr/bin/pt31553-fan-restore --restore || true"));
    let stock_return = shell_block_after(recovery, "use the emergency guidance in `SECURITY.md`.");
    assert_eq!(
        stock_return
            .matches("/usr/bin/pt31553-fan-restore --restore")
            .count(),
        2
    );
    assert!(has_exact_line(
        stock_return,
        "sudo /usr/bin/systemctl stop pt31553-fan-sleep-guard.service"
    ));
    assert!(has_exact_line(
        stock_return,
        "sudo /usr/bin/systemctl stop pt31553-fand.service || true"
    ));
    assert!(has_exact_line(
        stock_return,
        "test \"$(/usr/bin/systemctl is-active pt31553-fan-sleep-guard.service || true)\" = inactive"
    ));
    assert_in_order(
        stock_return,
        &[
            "sudo /usr/bin/systemctl stop pt31553-fan-sleep-guard.service",
            "sudo /usr/bin/systemctl stop pt31553-fand.service || true",
            "sudo /usr/bin/pt31553-fan-restore --restore",
            "sudo /usr/bin/systemctl disable",
            "sudo /usr/bin/systemctl stop pt31553-fand.service",
            "sudo /usr/bin/systemctl reset-failed pt31553-fand.service",
            "sudo /usr/bin/pt31553-fan-restore --restore",
            "test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive",
            "firmware_auto_confirmed\": True",
            "sudo /usr/bin/sync -f \"$attestation_target\"",
            "sudo /usr/bin/mv -T \"$attestation_target\" \"$recovery_attestation\"",
            "/usr/bin/pacman -Q linux-cachyos-lts",
            "assert lts.get(\"linux\") == \"/vmlinuz-linux-cachyos-lts\"",
            "host_path.is_file() and host_path.stat().st_size > 0",
            "test \"$(/usr/bin/pacman -Qqo \"$lts_packaged_image\")\" = linux-cachyos-lts",
            "/usr/bin/cmp \"$lts_packaged_image\" \"$lts_image\"",
            "/usr/bin/lsinitcpio \"$lts_initramfs\" >/dev/null",
            "sudo /usr/bin/systemctl reboot --boot-loader-entry=\"$lts_entry\"",
        ],
    );
    assert!(has_exact_line(
        stock_return,
        "sudo /usr/bin/systemctl reboot --boot-loader-entry=\"$lts_entry\""
    ));
    assert!(!stock_return.contains("stop pt31553-fan-sleep-guard.service || true"));
    assert!(!stock_return.contains("pt31553-fan-restore --restore ||"));
    assert!(runbook.contains("selected == [recovery_id]"));
    assert!(runbook.contains("/vmlinuz-linux-cachyos-lts"));
    assert!(runbook.contains("pacman -Qqo \"$recovery_module\""));
    assert!(runbook.contains("test \"$recovery_module_owner\" = linux-cachyos-lts"));
    assert!(runbook.contains("assert len(matches) <= 1"));
    assert!(!runbook.contains("except OSError"));
    assert!(runbook.contains("test ! -e \"$stock_acer_hwmon/$endpoint\""));
    assert!(runbook.contains("! /usr/bin/pgrep -x pt31553-fand"));
    assert!(runbook.contains("not marked `recovery_pwm_capable`"));
    assert!(!before_removal.contains("pacman -R "));
    assert_eq!(runbook.matches("pacman -R ").count(), 2);

    assert!(removal.contains("for entry_id in (stock_id, lts_id))"));
    assert!(removal.contains("assert removed_candidate_id not in by_id"));
    assert!(removal.contains("paths(by_id[stock_id], \"linux\")"));
    assert!(removal.contains("paths(by_id[lts_id], \"linux\")"));
    assert!(removal.contains("defaults[0] in {stock_id, lts_id}"));
    assert!(removal.contains("candidate_packages_installed"));
    assert!(removal.contains("case \"$candidate_packages_installed\" in 0|1|2|3)"));
    assert!(removal.contains("candidate_kernel_installed=0"));
    assert!(removal.contains("candidate_image_entries"));
    assert!(removal.contains("candidate_id_entries"));
    assert!(removal.contains("assert candidate_image_entries == candidate_id_entries"));
    assert!(removal.contains("assert candidate.get(\"type\") == \"type1\""));
    assert!(
        removal
            .contains("assert paths(candidate, \"linux\") == [\"/vmlinuz-linux-cachyos-pt31553\"]")
    );
    assert!(removal.contains("assert paths(candidate, \"initrd\") == expected_initrds"));
    assert!(removal.contains("assert candidate_options == stock_options"));
    assert!(removal.contains("require_loader_files(candidate)"));
    assert!(removal.contains("if test \"$candidate_kernel_installed\" = 1"));
    assert!(removal.contains("remove_controller=0"));
    assert!(removal.contains("case \"$remove_controller\" in 0|1)"));
    assert!(removal.contains("root:root:400"));
    assert!(removal.contains("attestation[\"firmware_auto_confirmed\"] is True"));
    assert!(removal.contains("attestation[\"source_boot_id\"] != current_boot_id"));
    assert!(removal.contains("journalctl --list-boots --no-pager --quiet"));
    assert!(removal.contains("source_boot_id\"].replace(\"-\", \"\") == sys.argv[4]"));
    assert_in_order(
        removal,
        &[
            "assert selected == [lts_id]",
            "assert paths(by_id[stock_id], \"linux\") == [\"/vmlinuz-linux-cachyos\"]",
            "require_loader_files(by_id[stock_id])",
            "require_loader_files(by_id[lts_id])",
            "assert candidate_options == stock_options",
            "require_loader_files(candidate)",
            "print(by_id[stock_id][\"root\"])",
            "if test \"$remove_controller\" = 1; then",
            "pacman -R pt31553-fan-control",
            "rm -f -- \"$candidate_config\"",
        ],
    );
    assert_in_order(
        removal,
        &[
            "attestation[\"firmware_auto_confirmed\"] is True",
            "assert selected == [lts_id]",
            "assert defaults[0] in {stock_id, lts_id}",
            "if test \"$remove_controller\" = 1; then",
            "pacman -R pt31553-fan-control",
            "rm -f -- \"$candidate_config\"",
            "assert sys.argv[1] not in {entry[\"id\"] for entry in entries}",
            "rm -f -- \"$candidate_image\" \"$candidate_initramfs\"",
            "test ! -e \"$candidate_initramfs\"",
            "for package in linux-cachyos-pt31553-nvidia-open",
            "pacman -R \"$package\"",
            "assert removed_candidate_id not in by_id",
            "rm -f -- \"$recovery_attestation\"",
        ],
    );
    assert_in_order(
        runbook,
        &[
            "sudo /usr/bin/pacman -R pt31553-fan-control",
            "### Reverify the retained candidate before a successor",
            "test -x \"$last_qualified/pt31553-fan-qualify\"",
            "\"$last_qualified/pt31553-fan-qualify\" validate-records",
        ],
    );
}

#[test]
fn stale_recovery_attestation_does_not_match_the_immediately_previous_boot() {
    fn matches_transition(
        source_boot_id: &str,
        current_boot_id: &str,
        previous_boot_id: &str,
    ) -> bool {
        source_boot_id != current_boot_id && source_boot_id.replace('-', "") == previous_boot_id
    }

    let stale_candidate = "11111111-1111-1111-1111-111111111111";
    let later_candidate = "22222222222222222222222222222222";
    let current_lts = "33333333-3333-3333-3333-333333333333";

    assert_ne!(stale_candidate, current_lts);
    assert!(!matches_transition(
        stale_candidate,
        current_lts,
        later_candidate
    ));
    assert!(
        recovery_runbook()
            .contains("attestation[\"source_boot_id\"].replace(\"-\", \"\") == sys.argv[4]")
    );
}

#[test]
fn last_qualified_candidate_is_retained_until_its_successor_passes() {
    let runbook = recovery_runbook();
    let retention = runbook
        .split_once("### Retain the last qualified candidate")
        .expect("runbook must define last-qualified retention")
        .1;
    let prose = retention.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(prose.contains("last-qualified candidate"));
    assert!(prose.contains("successor has passed every required qualification gate"));
    assert!(prose.contains("must not delete the last-qualified artifacts"));
    assert!(retention.contains("/usr/bin/cp -a -- \"$artifact_dir\""));
    assert!(retention.contains("package-set-manifest.p7s"));
    assert!(
        retention.contains("qualification_record=/var/lib/pt31553-fan-control/qualification.json")
    );
    assert!(retention.contains("supervised-endurance.json"));
    assert_eq!(
        retention
            .matches("pt31553-fan-qualify\" validate-records")
            .count(),
        3
    );
    assert!(retention.contains("/usr/bin/pt31553-fan-qualify"));
    assert!(retention.contains("$archive_target/pt31553-fan-qualify"));
    assert!(retention.contains("bsdtar -xOf"));
    assert!(retention.contains("usr/bin/pt31553-fan-qualify"));
    assert!(retention.contains("cmp \"$validator_recheck\""));
    assert!(retention.contains("pt31553-fan-control.pkg.tar.zst"));
    assert!(retention.contains("controller-package.sha256"));
    assert!(retention.contains("cat \"$last_qualified/controller-package.sha256\""));
    assert!(retention.contains("\"$controller_package_sha256\""));
    assert!(retention.contains("\"$last_qualified/pt31553-fan-control.pkg.tar.zst\")\" ="));
    assert!(
        retention.contains(
            "protected_policy=/absolute/path/to/qualified-root-owned-protected-policy.toml"
        )
    );
    assert!(retention.contains("$archive_target/protected-policy.toml"));
    assert!(retention.contains("$last_qualified/protected-policy.toml"));
    assert!(retention.contains("policy_sha256 == qualification[\"protected_policy_sha256\"]"));
    assert!(retention.contains("pacman-key --verify"));
    assert!(!retention.contains("/usr/bin/fan-control-qualify"));
    assert!(retention.contains("--authorized-evidence-path"));
    assert!(retention.contains("qualified_kernel[field] == provenance[\"kernel\"][field]"));
    assert!(retention.contains("verifier-source.bundle"));
    assert!(retention.contains("verifier-commit"));
    assert!(retention.contains("verifier-checkout/scripts/verify-package-provenance"));
    assert!(retention.contains("pt31553-locked-archive-recheck.XXXXXX"));
    assert!(retention.contains("locked_recheck/verifier/scripts/verify-package-provenance"));
    assert!(retention.contains("recheck_dir/verifier/scripts/verify-package-provenance"));
    assert!(retention.contains("/usr/bin/cmp \"$last_qualified/package-provenance-v1.json\""));
    assert!(retention.contains("/usr/bin/chmod -R a-w \"$archive_target\""));
    assert!(retention.contains("archive_parent=/var/lib/pt31553-fan-control/rollback"));
    assert!(retention.contains("stat -c '%U:%G:%a' \"$archive_parent\""));
    assert!(retention.contains("chown -R root:root \"$archive_target\""));
    assert!(retention.contains("find \"$archive_target\" -perm /222"));
    assert!(retention.contains("sync -f \"$archive_target\""));
    assert!(retention.contains("sync -f \"$archive_parent\""));
    assert!(retention.contains("if test -e \"$last_qualified\"; then"));
    assert!(retention.contains("find \"$last_qualified\" -perm /222"));
    assert!(retention.contains("pt31553-pre-removal-recheck.XXXXXX"));
    assert!(retention.contains("archive_recheck/verifier/scripts/verify-package-provenance"));
    assert!(retention.contains(".pt31553-last-qualified-staging.XXXXXX"));
    assert!(retention.contains("/usr/bin/mv -T \"$archive_target\" \"$last_qualified\""));
    assert!(retention.contains("previous_qualified="));
    assert!(retention.contains("test \"$previous_qualified\" != \"$last_qualified\""));
    assert!(retention.contains("test -d \"$previous_qualified\""));
    assert!(retention.contains("Only then may the operator retire `previous_qualified`"));
    assert!(retention.contains("installed_controller_version=$(/usr/bin/pacman -Q"));
    assert!(retention.contains(
        "if test \"$installed_controller_version\" != \"$archived_controller_version\"; then"
    ));
    assert_in_order(
        retention,
        &[
            "if test -n \"$installed_controller_version\"; then",
            "test \"$(/usr/bin/systemctl is-active \"$unit\" || true)\" = inactive",
            "sudo /usr/bin/pt31553-fan-restore --restore",
            "if test \"$installed_controller_version\" != \"$archived_controller_version\"; then",
            "sudo /usr/bin/pacman -U \"$archived_controller\"",
        ],
    );
    assert_in_order(
        retention,
        &[
            "if test -n \"$previous_qualified\"; then",
            "test -d \"$previous_qualified\"",
            "if test -e \"$last_qualified\"; then",
            "archive_recheck/verifier/scripts/verify-package-provenance",
            "else",
            ".pt31553-last-qualified-staging.XXXXXX",
            "/usr/bin/chmod -R a-w \"$archive_target\"",
            "sudo /usr/bin/chown -R root:root \"$archive_target\"",
            "locked_recheck/verifier/scripts/verify-package-provenance",
            "policy_sha256 == qualification[\"protected_policy_sha256\"]",
            "sudo /usr/bin/sync -f \"$archive_target\"",
            "test ! -e \"$last_qualified\"",
            "/usr/bin/mv -T \"$archive_target\" \"$last_qualified\"",
            "sudo /usr/bin/sync -f \"$archive_parent\"",
            "test -d \"$last_qualified\"",
            "if test -n \"$previous_qualified\"; then",
            "test -d \"$previous_qualified\"",
            "Only then may the operator retire `previous_qualified`",
            "Before\ninstalling the next candidate",
        ],
    );
    assert_in_order(
        retention,
        &[
            "verified inputs outside the source tree",
            "/usr/bin/cp -a",
            "verifier-checkout/scripts/verify-package-provenance",
            "### Return to stock before removal",
            "pacman -R pt31553-fan-control",
            "for package in linux-cachyos-pt31553-nvidia-open",
            "pacman -R \"$package\"",
            "Before installing a successor",
            "recheck_dir/verifier/scripts/verify-package-provenance",
            "archived_controller=\"$last_qualified/pt31553-fan-control.pkg.tar.zst\"",
            "sudo /usr/bin/pacman -U \"$archived_controller\"",
            "test -x /usr/bin/pt31553-fan-restore",
            "/usr/bin/systemctl cat \"$unit\"",
            "Retire them only after the successor",
        ],
    );
}

#[test]
fn last_qualified_records_use_authoritative_validation_before_publication_and_reuse() {
    let retention = recovery_runbook()
        .split_once("### Retain the last qualified candidate")
        .unwrap()
        .1;
    let archive_block = shell_block_after(retention, "optional controller removal:");
    assert_in_order(
        archive_block,
        &[
            "if test -e \"$last_qualified\"; then",
            "\"$last_qualified/pt31553-fan-qualify\" validate-records",
            "else",
            "sudo /usr/bin/install -o \"$operator_uid\"",
            "\"$protected_policy\" \"$archive_target/protected-policy.toml\"",
            "usr/bin/pt31553-fan-qualify >\"$archive_target/pt31553-fan-qualify\"",
            "/usr/bin/chmod -R a-w \"$archive_target\"",
            "policy_sha256 == qualification[\"protected_policy_sha256\"]",
            "qualified_kernel[field] == provenance[\"kernel\"][field]",
            "sudo /usr/bin/chown -R root:root \"$archive_target\"",
            "locked_recheck/verifier/scripts/verify-package-provenance",
            "/usr/bin/cmp \"$validator_recheck\" \"$archive_target/pt31553-fan-qualify\"",
            "\"$archive_target/pt31553-fan-qualify\" validate-records",
            "policy_sha256 == qualification[\"protected_policy_sha256\"]",
            "sudo /usr/bin/sync -f \"$archive_target\"",
            "/usr/bin/mv -T \"$archive_target\" \"$last_qualified\"",
        ],
    );
}
