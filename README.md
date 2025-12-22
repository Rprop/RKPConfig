# RKPConfig

An Android tool for managing **Remote Key Provisioning (RKP)**. It lets you view and modify RKP-related system properties on rooted devices, and trigger key provisioning, diagnostics, and cleanup operations.

## Features

| Action | Description |
|--------|-------------|
| **Load / Apply** | Read/write RKP system properties via `getprop` / `setprop` (changes are lost after reboot) |
| **Renew** | Trigger remote key provisioning and attempt Widevine certificate provisioning |
| **Dump** | Output rkpd service diagnostics and current key pool allocation status |
| **CSR** | Generate a Base64-encoded certificate signing request (TEE / StrongBox / AVF) |
| **Certify** | Output the PEM-encoded provisioned certificate chain |
| **Clear** | Wipe rkpd app data and all remotely provisioned keys |
| **RPMB Keys** | (OPlus devices) Open the engineer-mode RPMB status screen |

## Requirements

- **Android 14+** (`minSdk 34`, `targetSdk 36`)
- **Root access** (shell commands run through `su`)
- Device must support Android Remote Key Provisioning (`com.android.rkpdapp` or `com.google.android.rkpdapp`)
- ABIs: `arm64-v8a`, `x86_64`

## Configurable System Properties

| Property | Description |
|----------|-------------|
| `remote_provisioning.enable_rkpd` | Enable or disable RKPD |
| `remote_provisioning.hostname` | Remote provisioning server hostname |
| `remote_provisioning.strongbox.rkp_only` | Force RKP for StrongBox |
| `remote_provisioning.tee.rkp_only` | Force RKP for TEE |
| `remote_provisioning.connect_timeout_millis` | Remote request timeout in milliseconds |

Preset servers:

- `remoteprovisioning.googleapis.com` — default (international)
- `remoteprovisioning.grapheneos.org` — GrapheneOS proxy (recommended in regions where Google endpoints are unreachable)

## Project Structure

```
RKP/
├── build.gradle              # Root build configuration
├── settings.gradle
├── gradle.properties
└── rkp/                      # Main application module
    ├── build.gradle
    ├── CMakeLists.txt        # Native build (rkp executable)
    ├── rkp.jks               # Signing keystore
    └── src/main/
        ├── AndroidManifest.xml
        ├── assets/
        │   └── rkpdapp.apk   # Bundled rkpd app (used for class loading)
        ├── cpp/
        │   └── rkp.cpp       # Native entry: switch mount namespace, then exec
        ├── java/
        │   ├── rp/rkp/
        │   │   ├── MainActivity.java   # Main UI
        │   │   ├── rkpd.java           # rkpd process logic (provisioning core)
        │   │   └── AppLike.java        # Application entry point
        │   └── co/nstant/in/cbor/      # Vendored CBOR codec library
        └── res/
```

## Architecture

The app uses three layers to perform RKP operations under root:

```
MainActivity (UI)
    │  libsu Shell
    ▼
librkp.so (Native)
    │  setns(init mount namespace) → execve
    ▼
app_process → rkpd.main()
    │  Load rkpdapp.apk, run as the system rkpd app identity
    ▼
Provisioner / ServerInterface / WidevineProvisioner
```

1. **MainActivity** — Configuration UI. Uses a root shell to read/write system properties and invoke commands such as `cmd remote_provisioning`.
2. **librkp.so** — A statically linked native binary that switches into init's mount namespace, then `execve`s `app_process` to run the `rkpd` main class.
3. **rkpd.java** — Runs in the context of `com.android.rkpdapp` / `com.google.android.rkpdapp`, reuses the system rkpd `Provisioner` for key provisioning, and additionally handles Widevine provisioning.

## Build

### Prerequisites

- JDK 21
- Android SDK (`compileSdk 36`, Build Tools `36.1.0`)
- Android NDK `29.0.14206865`
- CMake `3.31.6`

### Commands

```bash
# Debug APK
./gradlew :rkp:assembleDebug

# Release APK (ProGuard + resource shrinking enabled)
./gradlew :rkp:assembleRelease

# Release build and copy native artifacts into jniLibs
./gradlew :rkp:genRelease
```

Output APK naming: `rkp-v{versionCode}.apk` (e.g. `rkp-v10.apk`).

### Signing

Both debug and release builds are signed with `rkp/rkp.jks`. Ensure this file exists before building. To use a different keystore, update `signingConfigs.base` in `rkp/build.gradle`.

### Dependencies

Some dependencies are provided as local JARs under `rkp/imp/` and `rkp/ref/` (Android rkpd interfaces). Before building, place the matching rkpd app package at `rkp/src/main/assets/rkpdapp.apk`.

## Usage

1. Install the APK on a rooted device and grant root access.
2. On first launch, a feature guide and risk warning are shown.
3. Configure RKP settings, then tap **Apply** to write system properties (**changes are lost after reboot**; use Magisk or another persistence method if needed).
4. Tap **Renew** to request remote key provisioning.
5. Long-press **Apply** to change the `su` executable path (default: `/system/bin/su`).
6. Long-press the log area to copy output. Logs are also written to `d.log` in the external cache directory.

## Main Dependencies

- [XUI](https://github.com/xuexiangjys/XUI) — UI components
- [libsu](https://github.com/topjohnwu/libsu) — Root shell
- [HiddenApiBypass](https://github.com/LSPosed/AndroidHiddenApiBypass) — Hidden API access
- CBOR library (`co.nstant.in:cbor`, vendored in source)

## Security Notice

> **This tool requires root access. Use at your own risk.**
>
> - Do not install APKs from untrusted sources (the app verifies its signature and exits if it does not match).
> - Clearing remote keys may break key attestation until keys are re-provisioned online or the device falls back to factory keybox material.
> - Properties set via `setprop` are not persistent across reboots.

## License

No open-source license is specified. Evaluate risks and comply with applicable laws before use.
