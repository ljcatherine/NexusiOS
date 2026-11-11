# SSH keys

Nexus supports OpenSSH **Ed25519** keys. RSA is rejected because the SSH library
only signs RSA with SHA-1.

## In the app

In a device's connection settings you can either:

- **Import** an existing OpenSSH private key through Files. Enter its passphrase
  when prompted.
- **Generate** an Ed25519 key. It has no OpenSSH passphrase; the private half is
  protected by the device Keychain.

Private keys are stored in the iOS Keychain when you save the profile and are never
included in profile exports. Copy only the displayed **public** line to the server.
Nexus doesn't install keys on servers.

## Installing the public key with a verified host key

`scripts/install-verified-ssh-key.sh` checks the server's Ed25519 host fingerprint
against a value you read on the server itself before running `ssh-copy-id`. It uses
strict host-key checking and your terminal's normal password prompt; it never
accepts or stores a password.

1. On the server, in a trusted local shell:

   ```sh
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
   ```

2. On your computer:

   ```sh
   ./scripts/install-verified-ssh-key.sh \
     server.example.ts.net user \
     ~/.ssh/nexus-ed25519.pub \
     'SHA256:PASTE_THE_FINGERPRINT_READ_ON_THE_SERVER'
   ```

If the fingerprints differ, stop and investigate. Don't bypass the check. The script
only appends to the account's `authorized_keys`; it doesn't change `sshd` or the
firewall.

## Host keys in Nexus

On first contact Nexus shows the server's SHA-256 host-key fingerprint and saves it
only after you confirm it. Compare it with the value read on the server. Pins are
scoped to hostname and port, so a LAN address and a MagicDNS name each need their own
first-use check. A changed key is rejected; rotation is a separate, guarded action.

## Endpoints

A device can have several endpoints (LAN, Tailscale, Cloudflare relay). Nexus tries
lower priority numbers first. For Tailscale endpoints, connect the Tailscale app on
the phone first.

Never put private keys in the repository, chat or the IPA. Keep local key files in
ignored, owner-only locations.
