# Maintained Swift package source overrides

Nexus builds from local source snapshots of the pinned Citadel 0.12.1 and SwiftTerm 1.10.1 releases. The upstream source and license files are retained in each directory. Only the changes listed below are applied; package dependency versions remain controlled by the root `Package.resolved` files.

## Citadel 0.12.1

Source commit: `ae8562f895de06ccb86fdb1cbb65fd99c8976e12` (MIT).

- `OpenSSHKey.swift`: accept bcrypt KDF rounds through 1000. Citadel's upstream `< 32` guard incorrectly applied bcrypt's logarithmic cost restriction to OpenSSH's iteration count; the parser already bounds imported key size and this cap bounds work. The disposable OpenSSH integration fixture verifies encrypted Ed25519 authentication with bcrypt-100.
- `ClientSession.swift`: schedule `bootstrap.connect` on the selected event loop before awaiting the channel future.
- `Client.swift`: schedule SSH handler installation on the channel's event loop.
- `SSHAuthenticationMethod.swift`: expose an SSH `none` authentication offer for Access-authenticated transports whose identity is verified before the SSH stream opens.

The two event-loop changes address the runtime crash path identified in old iPhone reports. They are covered by the real disposable OpenSSH handshake/PTY integration test and the iOS executable linkage gate, but the owner's current iPhone build still requires physical acceptance.

## swift-nio-ssh 0.3.4

Source commit: `b93961a2988607a756cbc21a811f406f27aa9ab6` (Apache-2.0). The root and Linux test manifests use the maintained `Vendor/swift-nio-ssh` snapshot; the Xcode package lock must be regenerated when this dependency changes.

- `SSHKeyExchangeStateMachine.swift`: treat the separate MAC as absent when an OpenSSH AEAD transport (AES-GCM with empty `macNames`) is negotiated. The server may advertise only Encrypt-then-MAC names, which AES-GCM ignores. Non-AEAD ciphers continue requiring a mutually supported MAC. Tests cover both AES-GCM strengths, disjoint directional ETM lists, and required MAC negotiation for AES-CTR.
- `NIOSSHCertifiedPublicKey.swift`: import `CDispatch` on Linux for the `timespec` initializer under Swift 6.4.

This focused source override closes the live failure reproduced against the owner's pinned NixOS host. Do not alter host SSH settings to work around the client negotiation defect.

## SwiftTerm 1.10.1

Source commit: `5c83a9d214e7354697624c11deb4e488bdcfabad` (MIT).

- `Package.swift`: include Apple/iOS sources when xtool evaluates the package from Linux. The upstream host-based manifest excludes these sources whenever the build host is Linux, even when the requested target is iOS.

## Updating these snapshots

Review upstream releases, update the recorded commit and preserved license, reapply only necessary changes, then run Linux Swift tests, both disposable OpenSSH key variants, xtool device and simulator builds, and the Codemagic/Xcode build before removing old pins. Do not patch files under SwiftPM `.build/checkouts`; the maintained diffs belong in these tracked source trees.
