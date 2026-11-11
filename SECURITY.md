# Security architecture and threat model

This foundation has not undergone an independent audit. Report vulnerabilities privately through GitHub's **Report a vulnerability** button on the repository's Security tab, not in public issues, and never include credentials in a report.

| Threat | Control and residual risk |
| --- | --- |
| Lost iPhone | Device-only Keychain credentials available only while unlocked; complete protection for device metadata; optional device-authentication app lock. An already compromised/unlocked OS remains outside this boundary. |
| Stolen SSH credential | No source/defaults credential storage, no secret export, no authentication logging. Use dedicated least-privilege accounts and revoke compromised public keys server-side. |
| Host impersonation | Explicit first-use SHA256 confirmation and Keychain pins per endpoint. Changed pins are blocked. Users must verify first use independently; TOFU alone cannot prove identity. |
| Exposed admin API | No public proxy, no open SSH ports, no agent installation. Existing private Tailscale connectivity is used. VPN ACLs and server-side account permissions remain the operator's responsibility. |
| Command injection | Foundation sends user-entered terminal bytes directly, as an SSH terminal should. Generated tmux arguments use a fixed UUID and POSIX quoting. Future generated admin commands must use validated arguments and explicit destructive-action confirmation. |
| Compromised server | Remote clipboard escape sequences and arbitrary terminal link opening are disabled. Terminal output remains untrusted; renderer vulnerabilities and malicious pasted commands remain risks. |
| Dependency compromise | Exact top-level SSH/terminal versions, recorded upstream commits/licenses, reviewed small adapter. Citadel's NIOSSH fork and all transitive packages require continuing review. |
| Expo prototype toolchain | The SDK 57 and SDK 54 locks use upstream `node-forge@1.4.1`; the published RSA verifier was inspected and local malformed-DER regression vectors pass. SDK 57 clean install reports zero npm audit findings. The SDK 54 Snack-compatible development lock still reports one high `image-size` advisory; the available 2.x fix breaks the pinned Metro CommonJS API and is not applied. The GitHub advisory's patched-version field may lag the upstream code. Snack's hosted resolver/runtime has not been verified against the local lock. These remain prototype-tooling risks; do not use Expo tooling with production credentials and recheck dependency advisories regularly. |
| Build and signing credential exposure | Builds run locally with xtool and produce unsigned IPAs only; no hosted CI is used. The build never imports Apple certificates, provisioning profiles or signing credentials, and the IPA validator rejects embedded signing material, private IPv4 addresses and Tailscale names. Release publication uses the developer's locally authenticated GitHub CLI. Whoever signs the IPA must verify the bundle ID and matching profile. |

SSH private keys and passphrases exist transiently in memory while parsing/authenticating; Swift strings cannot promise deterministic secure zeroization. There is no permanent plaintext credential cache. Importing keys is a deliberate user action. Credentials are not synchronized through iCloud. Keychain items may survive app uninstall; do not assume reinstall erases credentials or host trust.

The app lock uses device authentication (biometrics with passcode fallback). Enable a device passcode and app lock before storing important credentials. Backgrounding disconnects sessions; no background execution or remote job termination is promised. A tmux process may remain on the server until the operator ends it.

No server privilege configuration is modified, and no remote administrative command was executed during development. The app contains confirmed service controls and a NixOS dry-build/switch flow; actions rely only on existing non-interactive `sudo -n` policy and require explicit in-app confirmation. The NixOS flow repeats dry-build before switching and warns that SSH may be interrupted. Nexus does not edit NixOS configuration, change sudo policy, update servers, manage backups/restores, or scan networks. TLS defaults are unchanged; no certificate-validation bypass exists.

Changed keys have no quick bypass. Verify server identity and key rotation through a trusted channel. Terminal recovery displays old and new fingerprints and requires typing the exact new fingerprint after out-of-band verification; the saved pin is rechecked before replacement. Never implement automatic pin replacement or pretend deleting a device erases a global endpoint pin.

Automated trust/keychain tests and disposable SSH PTY tests are in `Tests/NexusSSHTests`. Physical-device, actual-server, and Tailscale testing must be recorded separately.
