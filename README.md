# WinPurge

> **A lightweight Windows 11 command-line tool to scan, remove, and audit built-in AppX/UWP components, suppress telemetry, create system restore points, and run VirusTotal lookups — all from a single standalone executable.**

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **System Scan** | Lists every installed AppX/UWP package with full name, version, and install path. |
| 2 | **Remove Component** | Uninstalls any AppX package by its full name. Optionally preserves or wipes application data. Microsoft Edge receives special treatment: its update services and scheduled tasks are disabled, and a registry flag is set to prevent automatic re-installation. |
| 3 | **System Snapshot** | Creates a Windows System Restore point via the native `SRSetRestorePoint` API before you make any changes. |
| 4 | **Disable Telemetry** | Sets the following registry entries to suppress data collection: |
| | | → `HKCU\…\AdvertisingInfo` — disables the Advertising ID |
| | | → `HKCU\…\Siuf\Rules` — disables Windows feedback pop-ups |
| | | → `HKLM\…\SQMClient\Windows` — disables CEIP (Customer Experience Improvement Program) |
| 5 | **Search Component** | Looks up a specific package by its full name and prints its metadata. |
| 6 | **VirusTotal Scan** | Hashes a local file with SHA-256 (via BCrypt) and queries the VirusTotal v3 API. The API key is encrypted at rest using Windows DPAPI and stored in `config.dat` next to the executable. |

---

## Requirements

- Windows 10 (build 1903+) or Windows 11
- Administrator privileges (required for package removal, service control, and HKLM registry writes)
- Visual C++ Redistributable 2022 — if you did **not** build with `/MT`, distribute `vc_redist.x64.exe` alongside the binary (download: https://aka.ms/vs/17/release/vc_redist.x64.exe)

---

## Building from Source

### Prerequisites

| Dependency | How to get |
|------------|-----------|
| Visual Studio 2022 | with **Desktop development with C++** and **C++/WinRT** workloads |
| libcurl (x64) | vcpkg: `vcpkg install curl:x64-windows` |
| nlohmann/json | vcpkg: `vcpkg install nlohmann-json:x64-windows` |
| Windows SDK 10.0.22621+ | included with VS 2022 installer |

### Clone & Build

```bash
git clone https://github.com/KernelPhantom-010/WinPurge---Windows-11-Component-Cleaner.git
cd WinPurge---Windows-11-Component-Cleaner
```

Open `WinPurge.sln` in Visual Studio 2022, set the configuration to **Release / x64**, and build.

> **Tip — avoid DLL dependency issues:** In project settings go to **C/C++ → Code Generation → Runtime Library** and set it to `/MT` (Multi-threaded, static). This links the MSVC runtime into the binary so no `VCRUNTIME140.dll` or `MSVCP140.dll` is needed on the target machine.

### Required Linker Libraries

The following are already referenced via `#pragma comment(lib, …)` in the source:

```
comsuppw.lib   Sfc.lib   uuid.lib   taskschd.lib
```

Make sure your linker also includes:

```
BCrypt.lib   WindowsApp.lib
```

---

## Usage

Run the executable as **Administrator**. Navigate the menu with the arrow keys and confirm with Enter.

```
=== Windows Component Cleaner ===

[ ] Scan System
[+] Remove Component          ← currently selected
[ ] Create System-Snapshot
[ ] Disable Telemetry Reg-Entries
[ ] Search for Component
[ ] Scan Malware (VirusTotal-API Key required)
[ ] Exit
```

### Removing a Component — Example

```
=== Enter the component full-name to remove
    (e.g. Microsoft.WindowsAppRuntime.2_2.3.1.0_x64__8wekyb3d8bbwe) ->
    Microsoft.BingWeather_4.53.51480.0_x64__8wekyb3d8bbwe

=== Remove all application-data? (Y/N) -> Y
```

The tool deprovisions the package for all users and removes it. For Edge-related packages it additionally:
- Stops and disables the `edgeupdate` / `edgeupdatem` services
- Disables the `MicrosoftEdgeUpdateTaskMachineCore` and `MicrosoftEdgeUpdateTaskMachineUA` scheduled tasks
- Writes `DoNotUpdateToEdgeWithChromium = 1` to prevent reinstallation

### VirusTotal Scan — First Run

On first use the tool prompts for your free VirusTotal API key (obtainable at https://www.virustotal.com/gui/sign-in). The key is encrypted with Windows DPAPI and stored in `config.dat` next to the executable — it is never transmitted except as an HTTP header directly to `virustotal.com`.

On subsequent runs the stored key is decrypted automatically.

---

## Project Structure

```
WinPurge/
├── main.cpp          Main source file
├── config.dat        DPAPI-encrypted VirusTotal API key (generated at runtime, not committed)
├── README.md
└── WinPurge.sln / .vcxproj
```

---

## Security Notes

- WinPurge requires and must be run as Administrator. Do not run arbitrary `.exe` files as Administrator that you have not inspected.
- `config.dat` is encrypted with DPAPI and is therefore tied to the Windows user account that created it. It cannot be decrypted on a different machine or by a different Windows user.
- The SHA-256 hash of a file is sent to VirusTotal as part of a file-lookup (`GET /api/v3/files/{hash}`). The file itself is never uploaded.

---

## Disclaimer

Removing built-in Windows components can break system functionality. Always create a system restore point (option 3) before making changes. The author takes no responsibility for any damage caused by misuse of this tool.
WinPurge is an independent, third-party tool and is not affiliated with, endorsed by, or sponsored by Microsoft Corporation. Windows is a trademark of Microsoft.
---

## License

MIT License — see [LICENSE](LICENSE) for details.
