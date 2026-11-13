# Building Nexus

Nexus is a SwiftUI app for iOS 17+. It is built on Linux (developed on NixOS) with
[xtool](https://github.com/xtool-org/xtool); no Mac, Xcode or connected iPhone is
needed to compile and package it. Hosted CI is not used.

Verified toolchain: Swift 6.4.1, xtool 1.24.0, Xcode 27.1 SDK.

## 1. Development shell

```sh
nix develop
./scripts/dev-doctor.sh
```

## 2. Swift toolchain

```sh
./scripts/setup-swift-toolchain.sh
swift --version
```

The script installs Swiftly 1.1.2 after verifying its Swift.org PGP signature, then
the exact version in `.swift-version`. Everything stays user-local; nothing changes
system configuration. On NixOS it selects the official Ubuntu 24.04 toolchain
package, and the Nix shell supplies the runtime libraries it expects.

## 3. xtool

```sh
./scripts/setup-xtool.sh
xtool --help
```

This pins the xtool AppImage, verifies its SHA-256, and installs a wrapper under
`~/.local/share/nexus/tools` and `~/.local/bin`. The Nix shell provides `appimage-run`.

## 4. Apple SDK

Apple's SDK is proprietary and not included. Download a compatible Xcode `.xip`
from Apple's developer site in a browser, then:

```sh
xtool sdk install /path/to/Xcode.xip
swift sdk list   # must list "darwin"
```

Don't automate Apple ID sign-in or put Apple credentials in the repository.

## 5. Build

```sh
./scripts/xtool-build.sh                  # Debug .app
./scripts/xtool-build.sh --release        # Release .app
./scripts/xtool-build.sh --clean          # clear SwiftPM build products first
./scripts/xtool-build.sh --release --ipa  # unsigned IPA at xtool/Nexus.ipa
```

Always build through the script on NixOS: it enters a project FHS environment with
the headers and libraries the Ubuntu toolchain expects and strips Nix host compiler
flags from the iOS cross-compile.

Before each build the script copies `MARKETING_VERSION` and
`CURRENT_PROJECT_VERSION` from `project.yml` into `Config/xtool-Info.plist`,
merges your optional deployment values (see [Configuration](CONFIGURATION.md)), and
restores the file afterwards. IPA builds are then validated: bundle ID, version and
build, unsigned structure, privacy manifest, iPhoneOS executable, SSH runtime
linkage, and the absence of private IPv4 addresses or Tailscale names.

A successful build proves the app compiles and packages. It does not prove it
installs, signs, or reaches your hosts.

## 6. Tests

```sh
./scripts/test-swift.sh           # NexusCore / NexusSSH package tests
bash scripts/test-openssh.sh      # SSH integration against a disposable OpenSSH container
(cd scripts && python3 -m unittest)
```

The gateway, Worker and server-side services have their own tests in
[NexusBackend](https://github.com/ljcatherine/NexusBackend).

On NixOS, the Swift scripts run inside the official `swift:6.4.1-noble` Docker
image, because the host sysroot doesn't match the Swiftly toolchain. They compile
the package sources and tests, not the SwiftUI views.

## 7. Releases

```sh
./scripts/xtool-release.sh
```

This builds, validates and checksums an unsigned IPA, then publishes the IPA,
`.sha256` and metadata JSON as a GitHub Release using an already authenticated
GitHub CLI. It never reads signing certificates or profiles.

Versioning: `project.yml` fixes the major/minor line and minimum patch (currently
`1.0.0`, the first public release). Each release increments the patch (`1.0.0` → `1.0.1` → …) and allocates a build number above every
existing release. Changing major or minor requires updating `project.yml` and setting
`NEXUS_ALLOWED_VERSION_LINE_CHANGE=1` for that first release. Assets are also copied
to the ignored `build/local-release/`; the script refuses to overwrite existing
files or releases.

## Other loops

- `./scripts/xtool-simulator-build.sh --architecture arm64` builds a demo-only arm64
  simulator app with mock data. It never connects to saved hosts.
- `prototypes/expo-nexus` is a mock-only Expo UI sketch (`./scripts/expo-dev.sh`,
  `./scripts/test-expo.sh`). It is not the production app.

## Editor setup

xtool writes `.bsp/xtool.json` (ignored) after a build. Point Zed or VS Code at the
Swiftly Swift 6.4 `sourcekit-lsp` and restart the language server after the first
build. SwiftUI symbols only resolve once the Darwin SDK is installed.

## Dependencies

SSH uses [Citadel](https://github.com/orlandos-nl/Citadel) 0.12.1 on a
swift-nio-ssh fork, and the terminal uses
[SwiftTerm](https://github.com/migueldeicaza/SwiftTerm) 1.10.1. Both are tracked,
license-preserving snapshots under `Vendor/`, and Nexus's changes are listed in
`Vendor/NEXUS-PATCHES.md`. RSA is rejected because Citadel only signs with SHA-1;
use Ed25519 keys.
