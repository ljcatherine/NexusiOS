# Gateway and Cloudflare

Everything here is optional. Without a gateway, Nexus talks directly to the SSH
hosts and AI endpoints you configure, over your LAN or Tailscale.

The gateway path adds remote access without opening ports:

```
Nexus (iPhone)
  └─ HTTPS + Cloudflare Access (Managed OAuth, PKCE)
       └─ Cloudflare Worker  (cloudflare/worker.mjs, fixed routes only)
            └─ Workers VPC → cloudflared tunnel → gateway on 127.0.0.1:8787
                 ├─ AI upstream (NexusAI or another OpenAI-compatible server)
                 ├─ SSH relay to fixed aliases (server-held key, strict known_hosts)
                 ├─ optional web search (Brave or SearXNG)
                 ├─ optional encrypted conversation sync
                 └─ optional Minecraft panel on 127.0.0.1:8080
```

Workers VPC and Managed OAuth are Cloudflare betas; behaviour can change.

## Gateway (`gateway/`)

A Go service that only binds to loopback and refuses to start with missing policy.
The API contract is in [`gateway/openapi.yaml`](../gateway/openapi.yaml).

| Route | Permission | Notes |
|---|---|---|
| `GET /healthz` | none | Process health only |
| `GET /v1/models` | `ai.models` | Returns only IDs in `NEXUS_AI_ALLOWED_MODELS` |
| `POST /v1/chat/completions` | `ai.chat` | Bounded request subset, streaming, up to three JPEG images; tool calls limited to two read-only snapshot tools that the app answers after user approval |
| `POST /v1/chat/completions/input_tokens` | `ai.chat` | Token count from the upstream llama.cpp server |
| `POST /v1/search` | `ai.search` | Brave or SearXNG; disabled until configured |
| `POST /v1/research` | `ai.chat` + `ai.search` | Plan, search, fetch and answer in one request |
| `/v1/conversations…` | `ai.history` | AES-256-GCM encrypted per subject; disabled until a key is set |
| `GET /v1/ssh/{target}` | `ssh.connect` | WebSocket SSH relay to an alias in `NEXUS_SSH_TARGETS_JSON` |
| Worker root | `minecraft.panel` | Fixed proxy to the panel on `127.0.0.1:8080` |

Security properties:

- JWT access tokens are verified against the issuer's JWKS (issuer, audience,
  signature, time). The verified principal must have the permission in
  `NEXUS_SUBJECT_PERMISSIONS_JSON`; the client can't grant itself anything. The policy
  parser rejects duplicate or ambiguous keys and unknown permissions.
- User tokens are never forwarded upstream. An optional upstream service token comes
  from `NEXUS_AI_UPSTREAM_TOKEN`.
- Upstream URLs can't contain credentials, queries or fragments. Cleartext HTTP is
  allowed only to private, link-local, loopback or Tailscale IPv4 addresses, and
  redirects aren't followed.
- Request size, message count, tokens, rate and concurrency are bounded. Logs and
  audit events never contain tokens, prompts, client IPs or conversation IDs.
- Search page fetches resolve DNS themselves, allow only public unicast addresses,
  pin the connection, cap size, and mark retrieved text as untrusted.

### Run locally

```sh
nix develop
mkdir -p local
cp gateway/.env.example local/nexus-gateway.env
chmod 600 local/nexus-gateway.env   # then replace every example value
./scripts/gateway-dev.sh
```

### Deploy

```sh
cd gateway
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -trimpath -o nexus-gateway .
```

The service units `nexus-gateway.service` (system), `nexus-gateway-user.service`
(user) and `nexus-cloudflared.service` are templates; review them for your host. The
tunnel unit reads its token from a root-owned file with `--token-file` so the token
never appears in process arguments. Never expose port 8787, the inference port or
SSH directly.

## Cloudflare Worker (`cloudflare/`)

The Worker allows only fixed AI routes, fixed SSH aliases and the panel root. It
fails closed unless Cloudflare Access supplies the configured audience and owner
email, and it forwards only Cloudflare's signed `Cf-Access-Jwt-Assertion` to the
gateway (never the OAuth bearer or Access cookie). The gateway verifies that
assertion independently.

### Setup

1. Create the Worker and a Workers VPC service that targets the gateway's loopback
   listener through `cloudflared` 2025.7.0 or newer (QUIC, outbound UDP 7844).
2. Copy `cloudflare/wrangler.example.jsonc` to the ignored `cloudflare/wrangler.jsonc`
   and fill in the VPC `service_id`. Keep `preview_urls` off. Set `keep_vars: true`
   if you manage runtime variables in the dashboard.
3. Protect the Worker hostname with a **hostname-based** Access application (not
   Worker-level Access, which rejects WebSocket upgrades). Use an exact **Emails**
   policy for your address, enable Managed OAuth, and add
   `https://<your-worker>.workers.dev/oauth2redirect` as an allowed redirect URI.
4. Register the public PKCE client:

   ```sh
   python3 scripts/register-cloudflare-access-client.py \
     https://<your-team>.cloudflareaccess.com \
     --resource-url https://<your-worker>.workers.dev
   ```

5. Add runtime variables (**Settings → Bindings → Variables and Secrets**, not build
   variables): `ACCESS_AUDIENCE` (the Access application's AUD tag) and
   `OWNER_EMAIL` (lowercase). The Worker returns 403 until both are set.
6. Configure the gateway: `NEXUS_OIDC_ISSUER` = team issuer, `NEXUS_OIDC_AUDIENCE` =
   AUD tag, `NEXUS_OIDC_JWKS_URL` = `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`,
   `NEXUS_OIDC_PRINCIPAL_CLAIM=email`, and grant your email the permissions you need.
7. Put the Worker host, team issuer and client ID in your
   [deployment plist](CONFIGURATION.md), or enter them in the app under
   Settings → API Connections.

No client secret or service token is embedded in the app or repository.

### Diagnosing 403s

Callers always see a generic `access denied`. The Worker logs safe booleans to
Worker Observability: whether variables are set, whether `ctx.access` exists and
matches, and whether the identity email matched. It never logs emails, audiences,
JWTs, cookies, codes or state.

## SSH relay

Relay profiles have no private key on the phone. The gateway terminates SSH over
the authenticated WebSocket and opens a second SSH connection with a server-held
Ed25519 key and strict `known_hosts`. Keep the upstream key, the relay host key and
`known_hosts` owner-only (0600), and authorize the upstream public key on each
target with `restrict,pty`. Nexus still pins the relay's SSH host key separately
from TLS.

## Minecraft panel

The panel stays bound to loopback with its own login, session cookie and CSRF
checks. Set both `NEXUS_MINECRAFT_PANEL_ORIGIN` (the panel's configured origin) and
`NEXUS_MINECRAFT_PUBLIC_ORIGIN` (your Worker origin), and grant `minecraft.panel`.
Nexus has no RCON implementation.

## Other services

- [`agent-orchestrator/`](../agent-orchestrator) runs agent tasks next to the gateway.
- [`workspace-agent/`](../workspace-agent) is a read-only workspace bridge per host.
- [NexusAI](https://github.com/ljcatherine/NexusAI) is the PS5 inference server.

Each has its own README.
