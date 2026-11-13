# Troubleshooting

## Builds

**xtool build fails on NixOS.** Check `swift --version`, `swift sdk list` (must list
`darwin`) and `xtool sdk status`. Always build with `./scripts/xtool-build.sh` from
`nix develop`; running the xtool SwiftPM build directly from the plain Nix shell
fails. `prepare-swift-fhs.sh` adds library runpaths to the user-local Swiftly
binaries because Swift Build clears `LD_LIBRARY_PATH`; reinstalling Swiftly undoes
this, and the next build reapplies it.

**AppImage doesn't start.** Run it inside `nix develop`, which provides
`appimage-run`, and re-run `./scripts/setup-xtool.sh` to recheck the pinned checksum.

**Linux Swift tests fail on Security, UIKit or `SwiftGlibc`.** The app target is
iOS-only; Linux only compiles the package sources. On NixOS the host sysroot doesn't
match the Swiftly toolchain, so use `./scripts/test-swift.sh` and
`scripts/test-openssh.sh`, which run in the `swift:6.4.1-noble` container (Docker
required). Don't point the compiler at a mismatched glibc sysroot or weaken
host-key checks to get tests passing.

**IPA validation rejects a private address.** A private IPv4 literal or `*.ts.net`
name ended up in the bundle. Remove it, or see
[Configuration](CONFIGURATION.md#private-addresses-in-the-ipa) if it's your
deliberate default AI endpoint.

**Expo preview doesn't open.** From `prototypes/expo-nexus`, run
`npx expo install --check`, then `npm run web`. Expo only runs the mock prototype,
never the SwiftUI app.

## Connections

**SSH fails or the app closes while connecting.** Check the version and build in
Settings first. A crash report only helps if its `CFBundleVersion` matches. Export it
from Settings → Privacy & Security → Analytics & Improvements → Analytics Data, then:

```sh
python3 scripts/summarize_ios_crash.py /path/to/Nexus.ips
```

This prints the build, exception, faulting thread, a short stack and a SHA-256 so you
can spot duplicates. Never share keys, passphrases, certificates or Keychain exports.

**Tailscale shows "Invalid response from local Tailscale service".** That message
comes from Tailscale's Accounts screen, before Nexus is involved. Update or reinstall
Tailscale, allow the VPN configuration, sign in to the right tailnet, and use
Settings → Bug Report in Tailscale if it persists.

**AI connection errors.** Settings → API Connections → **Test connection** tells you
whether the connection was refused (service stopped or wrong port), DNS failed, there
was no route, it timed out, or TLS verification failed. It doesn't show the URL. Fix
TLS errors on the server; Nexus has no certificate-validation bypass. For private
addresses, test from the same LAN or a connected tailnet, and don't port-forward the
model server.

**Gateway returns 403.** See [Diagnosing 403s](https://github.com/ljcatherine/NexusBackend/blob/main/docs/GATEWAY.md#diagnosing-403s).
