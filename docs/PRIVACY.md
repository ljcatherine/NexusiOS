# Privacy

Nexus has no analytics, advertising or tracking, and sends no diagnostics or usage
data to the developer. Its privacy manifest declares no collected data and no
tracking.

## On the device

- Device profiles, preferences, metrics history you requested, command recipes and
  minimal run results are stored in the app's protected storage.
- SSH keys, passwords, API tokens, OAuth tokens and trusted host keys are stored in
  the iOS Keychain. Private keys and passwords are never included in profile exports.
- Temporary downloads are removed when the share sheet closes or at the next launch.
- The SSH flow writes short diagnostic breadcrumbs to Apple's on-device unified log:
  fixed stage names, generic error types, and whether a host key changed. They never
  contain addresses, usernames, fingerprints, credentials, commands or terminal
  output, and Nexus doesn't upload them.

## Network connections

Nexus connects only to endpoints you configure, and only when you use a feature.
There's no developer-operated relay and no background polling.

- **SSH/SFTP** sends your commands, terminal input and file operations to the host
  you chose.
- **Tailscale** carries traffic when you pick a Tailscale endpoint, under your
  Tailscale configuration and terms.
- **Your gateway**, if you deploy one, sees the requests routed through it. See
  [Gateway and Cloudflare](https://github.com/ljcatherine/NexusBackend/blob/main/docs/GATEWAY.md).

## AI

Sending a message to a remote AI provider transmits the message and the context that
request uses: earlier turns, attachments, local-knowledge excerpts or skill guidance.
Automatic context compaction also sends older turns to the provider to be
summarised. Before sending, a best-effort local scan warns about common key, token
and credential patterns in the outgoing text. It doesn't inspect images and can't
catch every secret, so don't send secrets to remote AI services. Apple Intelligence
runs on the device and sends nothing to a remote provider.
