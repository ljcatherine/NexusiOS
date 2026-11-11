# Deployment configuration

The public source contains no deployment-specific values. Nexus works with no
configuration at all: you add devices and AI connections in the app, and every
endpoint, username, token and host-key pin you enter stays on the device (tokens,
keys and pins in the iOS Keychain).

If you run your own gateway (see [Gateway and Cloudflare](GATEWAY.md)), you can bake
a few non-secret values into your build so the app is preconfigured.

## Build-time values

Copy the template into the ignored `local/` folder and edit it:

```sh
mkdir -p local
cp Config/deployment.example.plist local/deployment.plist
```

`scripts/xtool-build.sh` merges this file into the app's Info.plist for that build
only and restores the tracked plist afterwards. Set `NEXUS_DEPLOYMENT_PLIST` to use a
different path. Unknown keys stop the build.

| Key | Type | Effect |
|---|---|---|
| `NexusGatewayHost` | string | Hostname of your Access-protected Worker, e.g. `nexus-gateway.example.workers.dev`. Enables relay SSH endpoints and the default Minecraft panel URL. |
| `NexusAccessIssuer` | string | Cloudflare Access team issuer, e.g. `https://your-team.cloudflareaccess.com`. |
| `NexusAccessClientID` | string | Public Managed OAuth client ID from `scripts/register-cloudflare-access-client.py`. It is an identifier, not a secret. |
| `NexusDefaultAIEndpoint` | string | Prefilled base URL for a new PS5LM Plus connection, e.g. `http://192.168.1.50:8081/v1`. |
| `NexusRelayDevices` | array of `{name, username, target}` | Devices suggested on first launch, each routed through the Worker to the gateway alias `target` (must exist in `NEXUS_SSH_TARGETS_JSON`). A device whose SSH username matches an entry is also offered the relay. |

When `NexusGatewayHost`, `NexusAccessIssuer` and `NexusAccessClientID` are all set,
the app seeds one "Nexus Cloudflare AI" connection that uses Managed OAuth against
the Worker. Relay devices are ignored without a gateway host.

## Private addresses in the IPA

The IPA validator rejects any private IPv4 literal or `*.ts.net` name in the bundle,
so a build can't accidentally ship your network layout. The only exception is the
host of `NexusDefaultAIEndpoint` when it is a private IPv4 address:
`scripts/deployment-allowed-addresses.py` reads it from your deployment plist and
passes it to the validator as `NEXUS_ALLOWED_PRIVATE_ADDRESSES`. If you publish IPAs
for other people, leave `NexusDefaultAIEndpoint` out.

## Server-side configuration

| File | Template | Purpose |
|---|---|---|
| `local/nexus-gateway.env` or `~/.config/nexus-gateway/nexus.env` | `gateway/.env.example` | Gateway policy, upstreams and relay targets |
| workspace agent environment | `workspace-agent/.env.example` | Read-only workspace bridge per host |
| `cloudflare/wrangler.jsonc` | `cloudflare/wrangler.example.jsonc` | Worker name, VPC service binding |

All three real files are git-ignored. Keep them owner-only (`chmod 600`).
