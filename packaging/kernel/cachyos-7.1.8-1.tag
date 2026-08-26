object 7a84732fd5e4350c1312fd0ed0c72ffa139fb766
type commit
tag cachyos-7.1.8-1
tagger Peter Jung <admin@ptr1337.dev> 1786377406 +0200

Based on Linux 7.1.8
Previous release: `cachyos-7.1.7-1`

- Rebased to upstream: `7.1.7` → `7.1.8`
- Added branch: **7.1/fixes**
- Removed branch: **7.1/fixes-dev**

- `ab54aee95b82` mm/page_alloc: Optimize free_contig_range()
- `273b08c227bc` vmalloc: Optimize vfree with free_pages_bulk()
- `66af5b1cf07d` mm/page_alloc: Optimize __free_contig_frozen_range()
- `90f7bcb68f3e` mm/vmalloc: extract vm_area_free_pages() helper from vfree()
- `c2174264b3c7` mm/vmalloc: use physical page count for vrealloc() grow-in-place check
- `10bf8c793ec7` mm/vmalloc: use physical page count in vread_iter() for VM_ALLOC areas
- `30c8b9b5cfd4` mm/vmalloc: free unused pages on vrealloc() shrink
- `a906de422555` lib/test_vmalloc: add vrealloc test case

- `e454d82dadab` drm/edid: rename VESA block parsing functions to more generic name
- `a7a92ca8f96e` drm/edid: prepare for VESA vendor-specific data block extension
- `0e2baabe1047` drm/edid: MSO should only be used for non-eDP displays
- `5312678461c5` drm/edid: parse DSC DPP passthru support flag for mode VII timings
- `e04b02bcec24` drm/edid: for consistency, use mask everywhere for block rev parsing
- `c85b54e1798a` drm/edid: parse DRM VESA dsc bpp target
- `a8e19b5daef9` drm/amd: use fixed dsc bits-per-pixel from edid
- `b19d55f179bb` drm/amdgpu: dsc: Fix max_qp limits to match VESA DSC 1.1 spec

- `a3a672eaaf6f` Introduce applesmc-t2
- `fe33f9ded9b1` Add apple-bce driver
- `5d4b3b3a919d` Put apple-bce in drivers/staging
- `acd1230545a6` i915: 4 lane quirk for mbp15,1
- `62561dea90d9` apple-gmux: allow switching to igpu at probe
- `ad4a73a0d0cb` applesmc: convert static structures to drvdata
- `77fb61ee6311` applesmc: make io port base addr dynamic
- `eb04c640c276` applesmc: switch to acpi_device (from platform)
- `bbc7f399f85b` applesmc: key interface wrappers
- `ef62b347f9ec` applesmc: basic mmio interface implementation
- `76c83348b269` applesmc: fan support on T2 Macs
- `6a81e7201854` applesmc: Add iMacPro to applesmc_whitelist
- `adb80bc3168f` applesmc: make applesmc_remove void
- `71bb6fc2cc98` applesmc: battery charge limiter
- `bd3ae0411b19` HID: add device IDs for Apple SPI HID devices
- `a10811224535` HID: add HOST vendor/device IDs for Apple MTP devices
- `8eca32550044` HID: core: Handle HOST bus type when announcing devices
- `3c56cd99779d` HID: Bump maximum report size to 16384
- `efbc8b1e0939` HID: apple: Bind Apple silicon SPI devices
- `a714c8facb34` HID: apple: Bind to HOST devices for MTP
- `7e717c0dbc5a` HID: magicmouse: use a define of the max number of touch contacts
- `78394485e777` HID: magicmouse: use struct input_mt_pos for X/Y
- `cef844cb8d83` HID: magicmouse: use ops function pointers for input functionality
- `35d1bb156c65` HID: magicmouse: add support for Macbook trackpads
- `400b3a178917` HID: magicmouse: Add MTP multi-touch device support
- `080a7fd13fe5` HID: magicmouse: Add .reset_resume for SPI trackpads
- `5fc558f8c89f` HID: magicmouse: Handle touch controller resets on SPI devices
- `3f6d16278452` HID: magicmouse: Query device dimensions via HID report
- `59241d81f880` WIP: HID: transport: spi: add Apple SPI transport
- `d6240a34416f` soc: apple: Add DockChannel driver
- `33902fd29138` HID: Add Apple DockChannel HID transport driver
- `ce7fb5ddc078` soc: apple: Add RTKit helper driver
- `3f6dde9e9aac` HID: apple: ignore the trackpad on T2 Macs
- `b42d05d4ab7c` HID: magicmouse: Add support for trackpads found on T2 Macs
- `7ed36b5c1ea8` HID: magicmouse: fix regression breaking support for Magic Trackpad 1
- `f94de6a850a5` HID: appletb-kbd: add option to switch default layer on double pressing fn key
- `edddc1ce67ea` drm/i915: Discard large BIOS framebuffers causing display corruption.
- `727b0aa113b3` applesmc-t2: Only load for T2 Macbooks
- `bf0f465f130a` applesmc: Do not probe for T2 Macbooks
- `413ae682012e` vga_switcheroo: Defer probe of display devices on T2 Macs
- `619daadb19af` cachy-t2: Define t2_mac_tbl in header instead

- `52f2581042cd` Sound support for the Samsung Galaxy Book 4
- `ea70712456a2` Rename model number of Book4 360 and Book4 Pro
- `11211e7ea6ea` Added fixup model
- `0dcebdf50644` Typo: Book 4 360 was a Book 4 Pro 360
- `606d8838abf4` Added Galaxy Book 5 and removed duplicated line
- `bb2ce59a2b16` Added support for Book4 Pro 16-inch and Book4 Ultra
- `c9fcfc06e593` Put the new biquads from the official Samsung firmware in the firmware blob
- `a760f2b95593` hda/max98390: Remove unused variables
- `3fa3e0008ef1` ALSA: hda: add AW88399 side codec support
- `76b6831e9c9e` ALSA: hda/realtek: Enable internal speakers on Razer Blade 16 (2025)

- `6aba7e2843ec` sched/fair: Check CPU capacity before comparing group types during load balance
- `88cfa4e16699` sched/fair: Skip misfit load accounting when the destination CPU cannot help
- `445254d9d909` sched/fair: Allow load balancing between CPUs of identical capacity
- `95619ca8415a` sched/topology: Do not clear SD_PREFER_SIBLING in domains with clusters

- `03660bc6a502` smp: Disable preemption explicitly in __csd_lock_wait()
- `3e17f6b8936a` smp: Enable preemption early in smp_call_function_single()
- `3d3b8bf4c592` smp: Refactor remote CPU selection in smp_call_function_any()
- `f8a74a53f6b6` smp: Use task-local IPI cpumask in smp_call_function_many_cond()
- `2923f76064bf` smp: Alloc percpu csd data in smpcfd_prepare_cpu() only once
- `f425e79e7912` smp: Enable preemption early in smp_call_function_many_cond()
- `122136ba1f70` smp: Remove preempt_disable() from smp_call_function()
- `1991ae11b9a3` smp: Remove preempt_disable() from on_each_cpu_cond_mask()
- `9c8bcc7826fb` scftorture: Remove preempt_disable() in scftorture_invoke_one()
- `73b46e0db137` x86/mm: Factor out flush_tlb_info initialization
- `609303b97893` x86/mm: Cap flush_tlb_info alignment at 64 bytes
- `0c14a4b12ed5` x86/mm: Move flush_tlb_info back to the stack
- `e9fdac7d0820` x86/kvm: Disable preemption in kvm_flush_tlb_multi()
- `5257fc22441c` x86/mm: Re-enable preemption before flush_tlb_multi()

- `63fb8e121a21` mm/mglru: consolidate common code for retrieving evictable size
- `133a6b2c32d0` mm/mglru: rename variables related to aging and rotation
- `15b0711e696d` mm/mglru: relocate the LRU scan batch limit to callers
- `0c079358841c` mm/mglru: restructure the reclaim loop
- `f1041f30049e` mm/mglru: scan and count the exact number of folios
- `e7270ca42877` mm/mglru: avoid reclaim type fall back when isolation makes no progress
- `2e50314fc3dd` mm/mglru: use a smaller batch for reclaim
- `e32de90c1cae` mm/mglru: don't abort scan immediately right after aging
- `a98ff180418a` mm/mglru: remove redundant swap constrained check upon isolation
- `ca9634f1217e` mm/mglru: use the common routine for dirty/writeback reactivation
- `5cde888dcd13` mm/mglru: simplify and improve dirty writeback handling
- `8025774c3930` mm/mglru: remove no longer used reclaim argument for folio protection
- `b66378197618` mm/vmscan: remove sc->file_taken
- `68f95511d9af` mm/vmscan: remove sc->unqueued_dirty
- `6f80b5c9567f` mm/vmscan: unify writeback reclaim statistic and throttling

- `39de676b3fd4` platform/x86: lenovo-wmi-other: Add missing CPU tunable attributes
- `a58a2d2343fa` platform/x86: lenovo-wmi-other: Add GPU tunable attributes
- `f778f9d596c2` platform/x86: lenovo-wmi-other: Rename LWMI_OM_FW_ATTR_BASE_PATH
- `3c615b85c885` platform/x86: lenovo-wmi-other: Add WMI battery charge limiting
- `c04089bf156d` platform/x86: lenovo-wmi-other: Add force_load_psy_ext module parameter
- `b8a7a707d838` platform/x86: lenovo-wmi-helpers: Add helper for creating per-device debugfs dir
- `dff7f95a7803` platform/x86: lenovo-wmi-capdata: Add debugfs file for dumping capdata

- `4a9fee1f68a2` drm/amd/display: Refactor amdgpu_dm_update_freesync_caps()
- `60eaca877566` Do not modify display_info in freesync_caps
- `b89000f46a95` Modify display range if freesync capable
- `044c57f887a0` drm/amd/display: Remove redundant edid checks
- `68fef123e6eb` drm/amd/display: Move DisplayID vrr parsing
- `56299d65c4ba` drm/amd/display: Always try to parse AMD vsdb
- `ffd4ccd29a67` drm/amd/display: Check for VRR range in CEA AMD vsdb
- `7dd6c77d8e9c` drm/amd/display: Use bigger VRR range if found in AMD vsdb
- `6bc9fa2daf96` drm/amd/display: Separate DP/eDP and PCON paths completely
- `73c558a95236` drm/amd/display: Refactor PCON VRR compatibility check
- `1e5772e9f59f` drm/amd/display: Add PCON VRR ID check override
- `fb9fadaea340` drm/amd/display: Add CH7218 PCON ID
- `f8fbf60ae5cc` drm/edid: Parse more info from HDMI Forum vsdb
- `c54d65ce6063` drm/amd/display: Rename PCON adaptive sync types
- `51a1d84fad76` drm/amd/display: Enable HDMI VRR over PCON
- `155b6185efe7` drm/amd/display: Support HDMI VRRmax=0
- `487c0ace279b` drm/amd/display: Build HDMI vsif in correct slot
- `c60b45f3b9ed` drm/amd/display: Save HDMI gaming info to edid caps
- `2e8d30b6efb7` drm/amd/display: Restore ALLM support in HDMI vsif
- `e9fae57a1337` drm/amd/display: Trigger ALLM if it's available
- `544471b954dd` drm/amd/display: Reintroduce VTEM info frame
- `f8f5fe907d73` drm/amd/display: Enable HDMI VRR
- `964d7f587f72` Merge HDMI and PCON paths
- `6132a9134b4d` drm/amd/display: freesync_on_desktop support for HDMI VRR
- `e2e05a94e30e` Force freesync_on_desktop for HDMI
- `9d0217782b41` drm: Add ALLM properties to connector
- `babafcc4d70a` drm/amd/display: Use ALLM properties in amdgpu
- `650271c965f5` fixu

- `980665d6fb90` drm/i915/rc6: Disable RC6 for InfinityBook Pro Gen8
- `8923add8ceaa` drm/i915/rc6: Add another Boardname to "Disable RC6 for InfinityBook Pro Gen8"
- `390dbae6c997` Add BT support for PRIME B650M-A AX6 II motherboard
- `e885a3eb114b` bluetooth: btusb: Add VID/PID 13d3:3625
- `8d1287a06fe7` sched/fair: do not scan twice in detach_tasks()
- `694840d2d31d` Input: xpad - add support for EasySMX 05 Pro
- `9d6bc2f663e4` x86/cpu/amd: Don't clear RDSEED32 bit on znver5
- `e5821a4ead73` sched/idle: Fix avg_idle saturation by establishing symmetric idle entry hook
- `469b36eeece7` sched/core: Make finish_task_switch() and its subfunctions always inline
- `6a2950c2d47e` mm/lruvec: preemptively free dead folios during lru_add drain
- `63f0e52c5da9` USB: core: sanitize string descriptors against C0 control characters
- `521e0f4164f1` sched/membarrier: Use per-CPU mutexes for targeted commands
- `950ec9617b23` sched/membarrier: Modernize membarrier_global_expedited with cleanup guards
- `f0f450008b11` drm/i915/psr: Accept PSR2 Early Transport panels without explicit Y-coord bit
- `0d1222360801` drm/i915/alpm: limit Panel Replay ALPM programming to PR
- `000b5851e267` drm/edid: populate monitor range from DisplayID adaptive sync
- `048ec5b1cfda` drm/i915/psr: exit Panel Replay during updates to work around ALPM lag
- `55ba4bd1a77c` platform/x86: hp-wmi: Add support for OMEN Slim 16t-an000 (8D40)
- `78bc10896a77` drm/nouveau: Wire up dmem cgroups
- `8facb3e950d0` i2c: Force ASUE140D touchpad i2c freq to 100khz
- `d5eb98f69817` ALSA: hda/realtek: Fix muffled internal speakers on ASUS ROG Strix G7332
- `15ea36036974` wifi: iwlwifi: mld: skip TX when firmware is dead
- `9464d6466fa6` ASoC: tas2783A: Use firmware file from linux-firmware
- `dc78c119d5bd` ASoC: amd: acp: Add DMI override for ASUS TUF Gaming A14 2026
- `d47437df9830` ASoC: amd: acp: Add DMI override for ASUS Vivobook 18
- `73dbcbd9b29f` drm/xe: Enable Wa_14025515070
- `108ddcb8f8f8` drm/amd/display: Use lockdep_assert_held() for dc_lock check
- `bba31bce671c` ASoC: amd: yc: Add quirk for Acer Aspire A314-23P
- `a9bff68c4f76` drm/amd/display: fix compressed buffer config routine waiting time
- `13b75a71f441` sof: Add quirk for Dell XPS 13 DX13260
- `0d61333f6e03` block: try slab allocation in bio_alloc_bioset() before mempool
- `f9490d6abf76` udmabuf: Do not create malformed scatterlists
- `0db2dc79624c` PCI: Skip Target Speed quirk on clamped ports with no link

- `c2bb1a9ca961` cgroup/dmem: Add queries for protection values
- `59635b1e7b2c` cgroup,cgroup/dmem: Add (dmem_)cgroup_common_ancestor helper
- `b84759eb8805` drm/ttm: Extract code for attempting allocation in a place
- `218d089785b5` drm/ttm: Split cgroup charge and resource allocation
- `137f50e83a85` drm/ttm: Be more aggressive when allocating below protection limit
- `c1b70e3da0d2` drm/ttm: Use common ancestor of evictor and evictee as limit pool

- `b7a7932d8b55` add sysctl to allow disabling unprivileged CLONE_NEWUSER
- `1baa36a0f1ae` Kconfig: Add CONFIG_CACHY
- `4df80fa4b094` Kconfig.hz: Add additional timer frequency options
- `3d8e4a92c777` mm: Increase VM_READAHEAD_PAGES to 256K
- `0345998f356d` mm/swap: Disable swap-in readahead
- `02bfc818e285` CACHY: mm/vmscan: Increase vm_swappiness to 100
- `27c90b0512e2` CACHY: sched/fair: Tweak EEVDF for interactivity
- `8d0a86534972` Kconfig: Restore CONFIG_OPTIMIZE_FOR_PERFORMANCE_O3
- `353df2934946` kbuild: Add GCC SMS-based modulo scheduling
- `557bcc22311f` drivers/pci: Add ACS override support
- `289a405e2555` PCI: Add Intel remapped NVMe device support
- `1e543e8f0521` Input: evdev - use call_rcu when detaching client
- `5b58e36667ec` CACHY: Enable background reclaim of hugepages
- `b6bda1c1442b` CACHY: Disable watermark boosting by default
- `a82260b14c2d` CACHY: Disable proactive compaction by default
- `0ec29b87c62a` drm/amd: Move AMD_PRIVATE_COLOR to Kconfig
- `095ef235d4b5` CACHY: v4l2-core: add v4l2loopback
- `4bab00a4e47c` Initialize ata before graphics
- `f162261b9520` intel-pstate: Implement "enable" parameter
- `178c8a65debf` scsi: Add VHBA driver
- `c0873c47b7d9` Kconfig.preempt: Remove CONFIG_EXPERT dependency from PREEMPT_RT
- `06510acaa178` arch/x86: Add x86_64 ISA and Zen4 compiler optimizations
- `63e9de3f839a` CACHY: Disable split lock mitigation by default
- `ae5718fe7ab5` linux7.1-rc1-ADIOS-3.2.0
- `12f3350a6581` CACHY: Use BFQ for SQ devices and mq-deadline for MQ devices
- `10c87173a39f` drm/amdgpu/pm: Allow override of min_power_limit with ignore_min_pcap
- `1f8fe8d07f47` ACPI: processor: Disable bus master check for AMD
- `bb8ee041e40e` drm/amd/display: Fix high busy wait load in dmub_srv_wait_for_idle()
- `e6be53589245` tag-release: Add script to easier create a release and tag
- `410ea04c1aac` tag-release: Update script to include commits from branches
- `ac8396e8eb11` sched/core: Further optimize sched_move_task by avoiding lock acquisition when autogroup is enabled
- `b64bbfd785a6` CACHY: Decrease timer_slack_ns default
- `d564db6f5da9` tag-release: Move tarball to pkgbuilds dir for naim
- `127bf0236367` CACHY: mm: lru-gen: Protect the working set of the last 100 jiffies
- `7cb9ac2f2d96` kbuild: add resolve_btfids to pacman PKGBUILD
- `93f271ce9983` sched/wait: Do accept() in LIFO order for cache efficiency
- `86d51005cd0d` tag-release: Update script
- `7f114b2b0566` Kbuild: Enable LLVM machine pipeliner
- `fd7a8fec675d` tag-release: Update script
- `87798ea980bb` kbuild: move vmlinux.a build rule to scripts/Makefile.vmlinux_a
- `fea71b1c6d05` kbuild: change --thin back to 'T' in $(AR)
- `536cd5fe2e0a` kbuild: distributed build support for Clang ThinLTO
- `a6aadc8d1766` sched/fair: Prefer the previous cpu for wakeup
- `1f958d71de32` readdir: add unlikely hint on len check
- `c3460649f01d` memcg: increase MEMCG_CHARGE_BATCH to 128
- `d615eb2e9854` sched/core: add some branch hints based on gcov analysis
- `926320439533` Revert "CACHY: Decrease timer_slack_ns default"
- `a55e8d77095d` Revert "memcg: increase MEMCG_CHARGE_BATCH to 128"
- `5aecdca15236` Revert "drm/amd/display: Fix high busy wait load in dmub_srv_wait_for_idle()"
- `8543c49d89b4` POC 2.6.2
- `121b523ccf0d` Revert "sched/core: Further optimize sched_move_task by avoiding lock acquisition when autogroup is enabled"
- `91e12a24bb91` tag-release.sh: GPG-sign release tarballs before upload
- `5875ea74088e` kbuild: update thin-lto to v12
- `2903d535d902` kbuild: Remove unnecessary 'T' modifier in cmd_ar_builtin_fixup
- `f17a3b13537e` tag-release: Update to include .0
- `76f1042d885d` Revert "sched/wait: Do accept() in LIFO order for cache efficiency"
- `e109164e8ee5` v4l2loopback: 0.15.4
- `51cd2b9444fc` POC 2.6.3

- `c041d7628e19` tcp/bbr3: add BBRv3 congestion control
- `264ff00c4136` bbr: Fix bbr name to bbr3

- `ffaae68f0e99` media: platform: amd: Introduce amd isp4 capture driver
- `256658a10f43` media: platform: amd: low level support for isp4 firmware
- `6212b4619ff4` media: platform: amd: Add isp4 fw and hw interface
- `1fae51b84784` media: platform: amd: isp4 subdev and firmware loading handling added
- `61965afc8f82` media: platform: amd: isp4 video node and buffers handling added
- `9cb3af9520ca` media: platform: amd: isp4 debug fs logging and more descriptive errors
- `6a9038cdf699` Documentation: add documentation of AMD isp 4 driver
- `b4b50d30f8de` media: platform: amd: isp4: drop stale list reinit before free
-----BEGIN PGP SIGNATURE-----

iQGzBAABCgAdFiEE6LmqOfBU4w6CkNSSw8SCCFf2VP4FAmp59L4ACgkQw8SCCFf2
VP4QzAv+LsXl554wWmyRkL4GmFd3nbIuvVzwb30z3m4Ri94T7E33xnDNzDeOFUm9
u4YnHpvBZIpdJV0xulmyaBpOq/NwAZmifc6n+LgEs1MgFcXaXM6+N3Ft68H7mCqv
+Fyt4RlK1v7KdU6QbnTWpGylB8q4uajp+7MNdbK8gpbUTQcgtNRWD0nMLvz97iFt
guoL9brhDQD5qknMhVmyw32lMWnUcbDw8d+DfxYEW/6VEDVphhCW6042IoZzWEpK
hR8jr1yR2gEoo41l57HREKOxm+oUX3JOTYKiWNSj8GPaPfXrzomwwDy0eFTm+rbD
w6yTCD1U9L04k8kCW5X+WXe34aXePcGSzWAvR1ttkjQY6mOXlrt/trAe1sWMPQwW
7MU/jnVinZPXz4PKJ/GIKO0+fot4r9nrWJQCGxhwR50Ni3RPTO741Zo2clx+6J6Q
CgzK6RACo2MZgVAQ+FtT3OXG85LSigEHW0zau4EYlflORwCvM16xHQ0tRUI6cSna
G6ILUp6n
=Y9QE
-----END PGP SIGNATURE-----
