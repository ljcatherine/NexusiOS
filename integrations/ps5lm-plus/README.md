<div align="center">

<img src="../../docs/design/nexus-icon.svg" width="64" alt="Nexus">

# NexusAI · PS5LM Plus native-control fork

**A reproducible patch to PS5LM Plus that adds an opt-in, authenticated model-control API on :8082.**

![license: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-0B1430?style=flat-square&labelColor=070C18) ![target: PS5LM Plus](https://img.shields.io/badge/target-PS5LM%20Plus-0B1430?style=flat-square&labelColor=070C18&logo=playstation&logoColor=9CBCFF) ![API: opt-in](https://img.shields.io/badge/API-opt--in-0B1430?style=flat-square&labelColor=070C18)

<sub>Part of <a href="../../README.md">Nexus</a> · private</sub>

</div>

---

Fresh clones apply a separate NexusAI dashboard branding patch while retaining
the upstream PS5LM version and all original data/model paths. Experimental
launch metadata uses `NexusAI Test (PS5LM)`; branding does not change the API,
credentials, original installed title or hardware acceptance requirements.

This is a reproducible, **GPL-3.0-or-later** modification to [abhi245y/PS5LM-Plus](https://github.com/abhi245y/PS5LM-Plus), which itself credits Mert Cobanov's PS5LM. This repository retains the fork changes as a patch plus new GPL-licensed sources, rather than embedding an untracked multi-repository copy. The actual modified upstream clone is generated under `build/` and remains independent of Nexus's Swift sources.

Upstream revision: `6729b4acbaf65e23b2e8bc8708b2acba524a7aa8` (2026-11-01 checkout). No additional PS5 signing credentials are included.

## What changes

The original llama-server stays on **:8081** and its GPU inference path is unchanged. A separate **opt-in HTTP controller on :8082** offers:

| API | Result |
|---|---|
| `GET /v1/nexus/status` | Current state, active model ID/label, context used/capacity, measured prompt/generation speed, measured memory pool/free/model/KV values, and nullable load progress |
| `GET /v1/nexus/models` | Models already discovered by PS5LM, stable ID, label, drive, fits/current flags |
| `POST /v1/nexus/models/{16-hex-id}/load` | HTTP 202. Queues the native, GPU-safe app restart into this model |
| `POST /v1/nexus/models/unload` | HTTP 202. Queues a restart with no model |

All calls require `Authorization: Bearer <operator-issued-strong-token>`. The console stores only the token's SHA-256 digest in an owner-readable, owner-only regular file, opened nonblocking and close-on-exec without following symlinks; the raw token stays in the gateway's private configuration and Nexus Keychain. Decimal telemetry is formatted without locale-sensitive output. Model IDs resolve only to PS5LM's existing enumerated, planner-approved GGUF paths. Unknown IDs, incompatible models, concurrent requests and unsupported HTTP methods are rejected. No API for arbitrary paths, writing files, running commands, downloads, or manipulating model server arguments exists. The browser UI and original console controller continue working.

## Installed-model metadata contract

`GET /v1/nexus/models` retains the opaque `id`, `label`, `drive`, `fits` and
`current` fields. The metadata patch adds optional fields:

- `file_size_bytes`: positive exact whole-file bytes measured by the existing
  planner scan, within JSON's exact integer range; otherwise null.
- `architecture`: bounded parsed `general.architecture`, otherwise null.
- `quantization_type`: the canonical UInt32 GGUF `general.file_type`, otherwise
  null. Missing, duplicate, wrong-type or guessed (1024) values are never inferred
  from the filename. Unknown future numeric codes are preserved as unknown.

This file type describes the file's predominant quantization, not every tensor.
Nexus maps known pinned llama types for display and supports legacy responses
without these fields. Cached ModelRow metadata is serialized directly: HTTP
refresh performs no extra model reads. Failed file-size measurement refuses a
memory plan rather than wrapping a negative size or pretending weights are free.
Malformed arrays/unknown types in this scalar field are refused; invalid strings
or other scalar types provide no quantization value. The existing GGUF parser's
broader behavior is retained; this is not a new general-purpose parser or an
independent claim that arbitrary model files are safe.

Fresh clones apply `0004-nexus-model-metadata.patch`; older prepared clones must
apply that app patch before running the current controller test harness. Prior
verified candidate artifacts remain immutable and do not acquire these fields
without a separately built/accepted revision.

## Clone and build

```bash
./integrations/ps5lm-plus/clone-nexus-fork.sh
./integrations/ps5lm-plus/test-nexus-control.sh build/ps5lm-nexus-fork
```

A complete NexusAI experimental PS5 title has now passed local cross-build and offline package checks. It is not installed or hardware-accepted. For an independent PS5 build, inside `build/ps5lm-nexus-fork` use the upstream `docs/CONSOLE.md` setup. Initialize its pinned submodules and PS5_Vulkan/PS5 homebrew SDK, then run `scripts/build-app.sh`. A successful ordinary host-side C++ control test **does not establish** a working PS5 binary or firmware compatibility. Test in a nonproduction PS5 homebrew environment first, and preserve a rollback copy of the original title. The original project requires its own console exploit/homebrew prerequisites; Nexus does not supply them.

## Explicit opt-in security

PS5LM Plus chooses its state folder at runtime (`/data/PS5LM`, or `/download0/PS5LM` when sandboxed). To enable control, securely provision:

- `nexus-control.token` — a single `sha256:<64 lowercase hex digits>` line, mode 0600 or stricter. It stores only SHA-256 of a 32–128-character random alphanumeric, dash/underscore bearer secret; generate the original token on a trusted machine, keep it only in the Debian gateway's private configuration and Nexus Keychain, and write only its hash to PS5 state. Without a valid private regular hash file, the controller does **not** start.
- `nexus-control.lan` — **optional empty marker**, required to bind `0.0.0.0:8082` instead of the default `127.0.0.1:8082`. Without it, a separate Debian gateway cannot reach the API from another host. Avoid binding publicly.

**HTTP on :8082 has no built-in TLS.** Never expose :8081 or :8082 to the public Internet or port-forward them. Route access through the authenticated HTTPS Debian gateway/Cloudflare Access or a private overlay, and firewall :8082 to the Debian gateway only. A bearer token sent over an untrusted LAN can be intercepted; a private network alone is not equivalent to end-to-end encryption. The controller does not handle Cloudflare authentication directly. Keep the management token separate from the inference API credential and store any iOS copy in Keychain. Storing only a hash mitigates simple token disclosure through FTP read access, but does not fix the unauthenticated FTP write path, payload loader, or plaintext LAN transmission; the owner explicitly accepts those risks on their trusted private LAN; WAN isolation and independent controller authentication still require verification. A VLAN or stricter isolation remains optional hardening, not a mandatory blocker solely for the accepted LAN exposure.

A remote switch **restarts PS5LM Plus** to free Vulkan memory, so inference and streaming are interrupted. Poll `/v1/nexus/status` until the target model reports ready; do not promise zero-downtime switching. Context auto-compaction, subagents and remote workspaces run in the separate Debian orchestration and Linux workspace services, **not inside the PS5 native title**. This keeps the PS5 GPU allocated to inference and Linux filesystem access outside the console.

## Tests and limits

**PS5 JSON numeric-parse stability correction:** See
[`JSON-NUMERIC-CRASH.md`](JSON-NUMERIC-CRASH.md) for the observed abort at
vendored `nlohmann/json.hpp:8323`, the exact pinned PS5 SDK locale problem,
the minimal clone-applied compatibility patch, and the offline
original-crashes/patched-passes regression. No hardware validation is claimed.

`native/nexus_control_test.cpp` exercises fail-closed token setup (including nonblocking FIFO refusal), private-file permissions, stored-hash validation, HTTP authentication, JSON escaping, inventory, status, invalid selection, exclusive switching and queue delivery. It compiles with the host C++20 compiler and the pinned upstream SHA-256 implementation against `stats.hpp`, without compiling any proprietary PS5 SDK. A full current-source PS5 title now cross-compiles and passes offline integrity checks. Current-title PS5 runtime, actual Vulkan model load, sustained stability/performance and live authenticated end-to-end testing remain unverified.
