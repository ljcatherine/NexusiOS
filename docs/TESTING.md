# Device acceptance checklist

Use this after installing a signed build. Record the Nexus version and build
(Settings → Build) and the iOS version. A successful build or IPA check doesn't
establish any of the items below.

## Install and navigation

- Install over an existing Nexus and confirm saved profiles and Keychain credentials
  remain.
- Open Overview, Devices, AI, Services and Settings. Check safe areas, the keyboard
  and larger text sizes.
- Refresh a host in Overview. Unavailable metrics stay unavailable, values show a
  recent sample time, and the CPU chart only uses real samples.

## SSH and files

- Connect to a saved device over each endpoint type you use.
- On first contact, compare the SHA-256 host-key fingerprint with the value read on
  the server before accepting it.
- Run an interactive program such as `btop`; the terminal resizes to the viewport.
  Dismiss and reopen the keyboard.
- Upload a local file in Files, download it again, and compare the contents.
- For relay profiles, confirm the relay host-key prompt, an interactive shell and
  SFTP through the Worker.

## AI and services

- Check each API connection with **Test connection** and **Test model**, without
  showing tokens in screenshots.
- If you use the gateway, sign in through Cloudflare Access, refresh models, switch
  models, and confirm a new request uses the selected one.
- Send a prompt, stop a long response, and start a new conversation. Errors and
  unavailable models are shown clearly.
- In Services, inspect services and the Minecraft panel. Only test state-changing
  actions deliberately, after reading their confirmation.

## Reporting

Record pass or fail per section. Redact host addresses, emails, tokens, keys and
model paths from screenshots and logs.
