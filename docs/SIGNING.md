# Signing and installing

Nexus builds produce an **unsigned** IPA. The build sets no signing identity and
never reads certificates, provisioning profiles or signing passwords. You sign the
IPA yourself before installing it.

The bundle identifier is `com.ljcatherine.Nexus`. To sign under your own Apple
account, use a provisioning profile for an identifier you control. Changing the
identifier makes a separate app with its own Keychain items and settings.

## Steps

1. Download `Nexus-v<version>-build.<n>-unsigned.ipa` from
   [Releases](https://github.com/ljcatherine/NexusiOS/releases) and check it against the
   `.sha256` file, or build it with `./scripts/xtool-build.sh --release --ipa`.
2. Sign it with a trusted signer and a matching provisioning profile. Check that the
   signed app keeps the bundle identifier you expect; some signing services replace
   it.
3. Install the signed IPA with Apple Configurator, your signing service, or another
   trusted tool. Development-signed apps may need
   [Developer Mode](https://developer.apple.com/documentation/xcode/enabling-developer-mode-on-a-device).

On Linux, a working libimobiledevice/usbmuxd setup can install a signed IPA over USB
after you accept the Trust prompt: `ideviceinstaller install Nexus.ipa` (1.2+) or
`ideviceinstaller -i Nexus.ipa` (1.1.x).

An unsigned IPA can't be installed directly, and a GitHub release download isn't an
over-the-air install manifest.
