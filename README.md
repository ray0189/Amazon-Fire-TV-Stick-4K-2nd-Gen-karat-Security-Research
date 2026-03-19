# Amazon Fire TV Stick 4K 2nd Gen (karat) — Security Research

> First documented bootloader, firmware, DTB and hardware analysis of the Amazon Fire TV Stick 4K 2nd Gen (2023).  
> **No public root exists as of March 2026.** UART serial output confirmed. BROM hunt in progress.

---

## Background

Spent the better part of 24 hours on this device. Started after bricking a Xiaomi TV Box S 3rd Gen (MDZ-32-AA) attempting to root it — pivoted to the Fire Stick 4K 2nd Gen which was sitting on the same desk. Couldn't find a single piece of prior technical documentation anywhere so posting everything here.

This is the first documented analysis of the karat bootloader, firmware, DTB, and hardware as far as I can tell. No root, no custom recovery, nothing exists publicly. Hopefully this gives the community something to build on.

---

## Device Specifications

| Parameter | Value |
|-----------|-------|
| Codename | KARAT / AFTKM / AFTKRT / AFTMA08C15 |
| Serial | G072JN09432608JD |
| SoC | MediaTek MT8696D (Quad-core Cortex-A55 @ 1.7GHz) |
| GPU | Imagination GE9215 @ 650MHz |
| RAM | 2GB LPDDR4X |
| eMMC | SanDisk SD1NBDG4-8G (8GB) — confirmed via teardown |
| WiFi/BT | MediaTek MT7961 (WiFi 6 / BT 5.0) |
| Board Revision | **30-007919 REV 01** |
| OS | Fire OS 8 / Android 11 |
| Build Fingerprint | `Amazon/karat/karat:11/RS8149.3133N/0028723395972:user/amz-p,release-keys` |
| Bootloader | Little Kernel (LK) v0.5 |
| Preloader | v0.1.00 |
| Security Patch | 2022-07-05 |
| Widevine | L1 |

---

## Boot Chain

```
Stage 0  BROM (Boot ROM)
         On-chip, immutable, MediaTek silicon
         ← Target for test point attack

Stage 1  Preloader
         /dev/block/mmcblk0boot0
         Signed by Amazon + MTK
         Amazon blocks USB preloader exposure

Stage 2  Little Kernel (LK) v0.5
         /dev/block/by-name/lk
         Amazon custom build
         RPMB enforcement lives here ← THE WALL

Stage 3  Boot image (kernel + ramdisk)
         /dev/block/by-name/boot (41.9MB)
         AVB 2.0 verified

Stage 4  Fire OS 8 / Android 11
         Super partition — system + vendor + product
```

---

## Fastboot — Full `getvar all` Output

```
version: 0.5
version-bootloader: 0.5
version-preloader: 0.1.00
unlocked: yes              ← ANOMALY — cosmetic, not enforced
unlock_status: false       ← TRUE hardware lock state
secure: no                 ← contradicts getvar secure (returns yes)
prod: 1
warranty: no               ← pre-voided on brand new unit
rpmb_state: 1              ← RPMB keyed and enforcing
arb_state: 1               ← anti-rollback active
dev_type: karat
product: KARAT
kernel: lk
max-download-size: 0x8000000
is-userspace: yes
partition-size:boot: 0x2800000
partition-size:super: 0x60e00000
partition-size:recovery: 0x2800000
partition-type:super: raw data
```

### The `unlocked: yes` Paradox

Brand new unit from Amazon. Reports `unlocked: yes` and `warranty: no` straight out of the box. Looked like a golden ticket — it isn't. `unlock_status: false` and `rpmb_state: 1` are the real story. Every flash command returns:

```
FAILED (remote: 'the command is restricted on locked hw')
```

Also notable — `getvar secure` returns `yes`, but `getvar all` shows `secure: no`. Two contradictory values from the same LK binary. Amazon's custom LK is quirky.

---

## Every Command Tested

| Command | Result | Notes |
|---------|--------|-------|
| `fastboot flash boot <magisk>` | ❌ restricted on locked hw | RPMB blocks |
| `fastboot boot <img>` | ❌ restricted on locked hw | RAM boot blocked |
| `fastboot flashing unlock` | ❌ restricted on locked hw | RPMB blocks |
| `fastboot flashing unlock_critical` | ❌ restricted on locked hw | RPMB blocks |
| `fastboot reboot recovery` | ❌ restricted on locked hw | RPMB blocks |
| `fastboot flash system <gsi>` | ❌ restricted on locked hw | RPMB blocks |
| `fastboot oem device-info` | ❌ restricted on locked hw | All OEM cmds blocked |
| `fastboot oem get-unlock-data` | ❌ restricted on locked hw | RPMB blocks |
| `fastboot fetch boot boot.img` | ❌ fetch not supported | Read ops disabled |
| `fastboot wipe-super` | ⚠️ ANDROID_PRODUCT_OUT not set | **Client-side abort — NOT hardware block** |
| `fastboot getvar all` | ✅ OKAY | Read-only works |
| `fastboot reboot` | ✅ OKAY | Always permitted |

> **Critical anomaly:** `wipe-super` returns a client-side environment variable error — NOT `restricted on locked hw`. The fastboot client aborted before sending the command to the device. Setting `ANDROID_PRODUCT_OUT` and retrying has not been tested. May indicate different RPMB enforcement on the super partition.

---

## Why Nothing Works — RPMB

RPMB (Replay Protected Memory Block, JEDEC standard) is implemented in the SanDisk eMMC. Authentication uses HMAC-SHA256 with a device-unique shared secret provisioned between the eMMC hardware and MediaTek's OP-TEE TrustZone at the factory.

```
fastboot write request
        ↓
LK receives command
        ↓
LK calls into OP-TEE secure world
        ↓
OP-TEE generates HMAC-SHA256 auth token
using device-unique RPMB key
        ↓
eMMC verifies token against its internal key
        ↓
PASS → write executes
FAIL → "restricted on locked hw"
```

The RPMB key is:
- Device-unique — not universal
- Stored in eMMC secure partition hardware and OP-TEE secure storage
- Cannot be extracted via ADB, fastboot, or OS-level exploits
- Only bypassed via physical BROM access or eMMC chip-off

---

## Firmware Analysis

Downloaded Fire OS 8.1.6.0 OTA (RS8160/3380) from [ftvdb.com](https://ftvdb.com).
Format: SignApk-signed ZIP — standard Android OTA, not Amlogic .img format.

```
├── boot.img                    41.9MB  ← PRIMARY ROOT TARGET
├── system.new.dat.br          647.2MB  ← Brotli compressed block map
├── vendor.new.dat.br           66.1MB
├── product.new.dat.br           9.6MB
├── images/
│   ├── lk.bin                  ~4MB   ← LK binary — needs Ghidra analysis
│   ├── dtbo.img                ~2MB
│   └── logo.bin
└── dynamic_partitions_op_list   534B
```

### Dynamic Partition Layout

```
super:   1,623,195,648 bytes  (1.51GB container)
system:  1,232,580,608 bytes  (1.15GB)
vendor:    135,032,832 bytes  (128MB)
product:    17,121,280 bytes  (16MB)
free:      238,461,248 bytes  (~227MB unallocated)
```

---

## Ramdisk Analysis

```
boot.img-ramdisk/
├── avb/
│   ├── q-gsi.avbpubkey    ← Android Q GSI signing key
│   ├── r-gsi.avbpubkey    ← Android R GSI signing key (matches Android 11)
│   └── s-gsi.avbpubkey    ← Android S GSI signing key
├── debug_ramdisk/         ← EXISTS but EMPTY — Amazon stripped it
├── fstab.mt8696           ← partition mount config
└── init.recovery.mt8696.rc
```

### GSI Keys — Critical Finding

From `fstab.mt8696`:
```
system /system ext4 ro,barrier=1 wait,logical,first_stage_mount,
  avb=vbmeta,avb_keys=/avb/q-gsi.avbpubkey:
                       /avb/r-gsi.avbpubkey:
                       /avb/s-gsi.avbpubkey
```

Google Q/R/S GSI public keys are embedded in the ramdisk. The system partition accepts Google-signed GSIs without Amazon's keys. **AVB is NOT the blocker — RPMB is.** Once flashing is possible, a rooted ARM32 GSI is the fastest root path. No additional AVB work needed.

### Recovery Init — Deliberately Disabled

From `init.recovery.mt8696.rc`:
```
service console /system/bin/sh
    user root
    disabled        ← Amazon explicitly disabled

service adbd /system/bin/adbd
    disabled        ← Amazon explicitly disabled

on boot
    setprop service.adb.tcp.port 5555  ← configured but never starts
```

Root ADB shell configured, explicitly disabled. Confirmed via testing — zero ADB output from recovery over USB.

---

## DTB Analysis

Decompiled using:
```bash
dtc -I dtb -O dts -o MT8696.dts 01_dtbdump_MT8696.dtb
```

### UART Boot Console — Hardware Confirmed Present

```
chosen {
    bootargs = "console=tty0 console=ttyS1,921600n1
                earlycon=uart8250,mmio32,0x11002400
                root=/dev/ram vmalloc=300M
                androidboot.hardware=mt8696";
};

uart0 @ 0x11002000  — status: disabled
uart1 @ 0x11002400  — status: disabled  ← BOOT CONSOLE (921600 baud 8N1)
uart2 @ 0x10049000  — status: disabled
```

Amazon set `status: disabled` in the DTB but the kernel bootargs still reference `0x11002400`. The hardware UART is physically present on the board.

### Hardware Interface Map

| Interface | Address | Status | Notes |
|-----------|---------|--------|-------|
| UART1 (boot console) | 0x11002400 | disabled | 921600n1 — HW present |
| UART0 | 0x11002000 | disabled | Inactive |
| UART2 | 0x10049000 | disabled | Inactive |
| ICE Debug | internal | present | MediaTek In-Circuit Emulator |
| USB OTG | 0x11201000 | active | ADB/fastboot interface |
| eMMC | 0x11230000 | active | Contains RPMB |
| GPIO/Pinctrl | 0x10005000 | active | 157 GPIOs — UART pin map stripped |

---

## Project Treble & GSI Path

```
ro.treble.enabled = true
ro.boot.dynamic_partitions = true
ro.product.cpu.abi = armeabi-v7a   ← ARM32 only despite 64-bit SoC
ro.build.version.release = 11
```

ARM32-only userspace on a 64-bit capable SoC. For GSI: need `arm_bvS` variant (PHH-Treble or equivalent).

From `BoardConfig.mk` (auto-generated by aospdtgen):
```makefile
TARGET_ARCH := arm
TARGET_CPU_VARIANT_RUNTIME := cortex-a55
TARGET_USES_64_BIT_BINDER := true
BOARD_KERNEL_BASE := 0x40078000
BOARD_KERNEL_PAGESIZE := 2048
BOARD_BOOTIMG_HEADER_VERSION := 2
TARGET_BOARD_PLATFORM := mt8696
BOARD_AVB_ENABLE := true
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 3
VENDOR_SECURITY_PATCH := 2022-07-05
BOARD_BOOTIMAGE_PARTITION_SIZE := 41943040
# NOTE: Auto-generated BOARD_SUPER_PARTITION_SIZE is wrong (~9GB)
# Correct value: 1,623,195,648 (from dynamic_partitions_op_list)
```

---

## Physical Board Analysis

**Board Revision: 30-007919 REV 01**

```
Side A (components):
  ├── SanDisk SD1NBDG4-8G eMMC — label confirmed via teardown
  ├── Power management ICs
  ├── MediaTek MT7961 WiFi/BT module
  └── 4-pad header adjacent to micro USB port
      ← Serial output confirmed from this header

Side B (under full metal shield):
  ├── MT8696D SoC
  ├── 2GB LPDDR4X RAM
  └── BROM test point — location unknown
      Shield is soldered down — hot air required to remove
```

---

## UART — Serial Output Confirmed

A 4-pad header was identified directly adjacent to the micro USB port on the PCB. Connected an FT232 USB-UART adapter and confirmed serial output is present. Currently garbled — correct baud rate still being determined.

| Baud Rate | Result |
|-----------|--------|
| 921600 | Garbled output |
| 115200 | Garbled output |
| 460800 | Pending |
| 1500000 | Pending |
| 3000000 | Pending |

**Will update with full bootlog when readable output is captured.**

---

## mtkclient Results

```bash
python mtk.py crash           → Handshake failed (repeated indefinitely)
python mtk.py gettargetconfig → Handshake failed (repeated indefinitely)
```

Amazon's preloader blocks the standard MTK USB handshake. Software BROM crash does not work. Physical test point required.

---

## Attack Surface

| Vector | Status | Blocker |
|--------|--------|---------|
| `fastboot flash *` | ❌ BLOCKED | RPMB in LK |
| `fastboot boot` | ❌ BLOCKED | RPMB in LK |
| `fastboot flashing unlock` | ❌ BLOCKED | RPMB in LK |
| ADB root in recovery | ❌ BLOCKED | Amazon disabled adbd |
| GSI flash | ❌ BLOCKED | RPMB in LK |
| OTA sideload unsigned | ❌ BLOCKED | Amazon OTA cert required |
| mtkclient crash | ❌ BLOCKED | Amazon hardened preloader |
| mtkclient BROM software | ❌ BLOCKED | Preloader USB blocked |
| UART tap | 🔄 IN PROGRESS | Serial confirmed — baud TBD |
| BROM test point | ❓ UNKNOWN | Under soldered shield |
| lk.bin reversing | ❓ UNTESTED | Binary available |
| wipe-super (PRODUCT_OUT set) | ❓ UNTESTED | Client-side abort only |
| eMMC chip-off | ⚠️ POSSIBLE | Destructive — last resort |

---

## What Needs to Happen Next

### Immediate
- Determine correct UART baud rate — trying 460800, 1500000, 3000000
- Capture full LK bootlog — may reveal debug commands
- Test `fastboot wipe-super` with `ANDROID_PRODUCT_OUT` set
- Enumerate fastboot oem commands exhaustively

### Medium Term
- Ghidra analysis of `lk.bin` — search for debug commands, RPMB handling, hidden unlock sequences
- Map BROM test point on MT8696D — board rev **30-007919 REV 01**, SoC under soldered shield
- Attempt mtkclient on native Linux — Mac USB stack unreliable for MTK

### Long Term
- BROM test point short — bypasses LK and RPMB entirely once identified
- Flash rooted ARM32 GSI — AVB already accepts GSI keys
- eMMC chip-off — last resort

---

## CVE Note

**CVE-2026-20435** (published 2026-03-02) affects MT8696. Logic error in MediaTek preloader — allows reading device unique identifiers with physical access. Does not provide write access or RPMB bypass but relevant for further preloader research.

---

## Progress Log

| Date | Finding |
|------|---------|
| 2026-03-18 | Initial fastboot analysis — `unlocked: yes` anomaly documented |
| 2026-03-18 | OTA firmware downloaded and extracted |
| 2026-03-18 | DTB decompiled — UART1 boot console at 0x11002400 discovered |
| 2026-03-18 | Ramdisk analysed — GSI keys found, debug_ramdisk empty |
| 2026-03-18 | mtkclient attempted — preloader handshake blocked |
| 2026-03-19 | Board opened — 4-pad UART header identified |
| 2026-03-19 | **Serial output confirmed from UART header via FT232** |
| TBD | Correct UART baud rate |
| TBD | Full LK bootlog capture |
| TBD | BROM test point identification |

---

## Files

| File | Description |
|------|-------------|
| `MT8696.dts` | Decompiled Device Tree Source |
| `BoardConfig.mk` | Auto-generated LineageOS device tree config |
| `dynamic_partitions_op_list` | Correct partition layout |
| `board-photos/` | PCB photos — both sides |
| `boot.img` | Stock boot image — on request |
| `lk.bin` | LK bootloader binary — on request |
| `system-dump/` | Full system dump RS8158 — on request |

---

## Wanted

- **MT8696D board schematic** or reference design
- **BROM test point location** for MT8696D / board rev 30-007919 REV 01
- **lk.bin reversing** — Ghidra/IDA experience with MTK LK binaries
- **UART baud rate** — serial output confirmed, correct baud unknown
- **wipe-super testing** — does device-side block super partition writes differently?
- Any prior karat research

---

## Researcher

**Rayyan Rahman** — East London, UK  
Research conducted: 18–19 March 2026  
Tools: ADB, fastboot, dtc, payload-dumper-go, mtkclient, Magisk v30.7, FT232, picocom  

*Open an issue or PR if you have MT8696D experience or want to collaborate.*
