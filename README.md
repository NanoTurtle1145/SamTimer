# SamTimer

One-tap Android root for Samsung Galaxy devices, built around the
**CVE-2026-98260** timer exploit (posix-cpu-timers UAF) and a
**KernelSU 3.2.5 KDP/RKP/DEFEX-patched** late-load module.

> Based on the **CVE-2026-98260-aurora** repo — its timer LPE port is what
> `app/src/main/cpp/timer.c` evolved from.

> [!WARNING]
> For devices you own or are explicitly authorized to test. The timer UAF is
> probabilistic — a failed run can leave the system unstable until the next
> reboot. Rebooting always restores the phone to a clean, unrooted state.

**Credits:** [RiosWesley](https://github.com/RiosWesley) (GitHub) · **fntz1** (XDA)

## Overview

| | |
| --- | --- |
| Exploit | CVE-2026-98260 (`timer.c`, built by Gradle) |
| Read/write | pipe_buffer kernel read + pipe merge write |
| Root injection | fake workqueue item → `call_usermodehelper` → `uhexec` |
| Root module | KernelSU **3.2.5** KDP-patched (`ksud-s25u-kdp`) |
| Manager | KernelSU **3.2.5** (`me.weishu.kernelsu`, versionCode 32525) |
| Execution context | Shizuku shell (uid 2000) |
| Root lifetime | Per-boot (ephemeral — cleared on reboot) |

Validated on **SM-S928B** (e3q, Snapdragon 8 Gen 3), kernel
`6.1.162-android14-11`, OneUI 8 / EZIF, on a clean boot, twice.

The KernelSU **3.3.x official LKM panics** on this Samsung kernel; this app
therefore ships the stable KDP-patched **3.2.5** module and offers the matching
3.2.5 manager after success. A 3.3.1 manager will show “kernel needs update”.

## Features

- Material 3 Compose UI (English / Korean, follows the system locale)
- Live root badge — detects the loaded KernelSU module every few seconds
- Confirmation dialog before every run; **re-root** button stays available
- **Auto-root after reboot** — boot receiver → WorkManager chain that waits
  for Shizuku, then runs the chain headless with progress notifications;
  a failed run disables the option itself (boot-loop protection)
- Post-success dialog with the official **KernelSU 3.2.5 manager** download link
- The exploit payload is compiled automatically by Gradle

## Requirements

1. **Shizuku** running (wireless debugging). For auto-root: enable Shizuku's
   boot auto-start and grant its permission to SamTimer once.
2. The **KernelSU 3.2.5 manager** — the app offers the download link after
   a successful run, or install it directly:
   [KernelSU_v3.2.5_32525-release.apk](https://github.com/tiann/KernelSU/releases/download/v3.2.5/KernelSU_v3.2.5_32525-release.apk)

## Build

```sh
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

- `app/src/main/cpp/timer.c` is compiled into
  `app/src/main/jniLibs/arm64-v8a/libtimer.so` by the `buildPayload` task
  (NDK is auto-detected: `ANDROID_NDK_HOME` → `local.properties` → SDK →
  `~/android-ndk-r27c`). Windows and Linux NDK hosts are handled.
- `app/src/main/assets/` contains the KDP-patched `ksud-s25u-kdp`, the
  `uhexec` helper and the action script.
- `./gradlew clean` removes all outputs including the generated payload.

## Usage

1. Start Shizuku, open SamTimer
2. Tap **Root now** → confirm → wait 1–7 minutes
3. When it succeeds, tap **KernelSU 3.2.5 manager** and install the matching
   manager APK
4. Grant `su` to your apps in the manager

## Chain

1. `timer.c` leaks the child cred through the kmem trace and derives the
   KASLR slide.
2. The timer UAF gives a controlled 8-byte write; the exploit uses it to
   repoint `pipe->bufs` and builds a stable user-page pipe buffer.
3. It reads `system_unbound_wq` → `dfl_pwq` → `worker_pool`, then links a fake
   work item whose `func` is `call_usermodehelper_exec_work`.
4. The helper runs `uhexec` as root, which bind-mounts the KDP-patched
   `ksud 3.2.5` over `/system/bin/logcat` inside a private mount namespace and
   runs `late-load --package-name me.weishu.kernelsu`.
5. KernelSU 3.2.5 loads; the matching manager can then grant `su`.

## Notes for other devices / EZJ1

- The e3q/EZIF and EZJ1 kernels share the timer, workqueue, pipe and SELinux
  symbol addresses used here; EZJ1 has not yet been device-tested.
- A normal reboot removes the late-loaded module and therefore root. Re-run
  SamTimer after each boot (or enable auto-root).
- Do not use the official 3.3.x KernelSU LKM on this Samsung kernel — it
  panics. Use the KDP-patched 3.2.5 shipped in `assets/`.
