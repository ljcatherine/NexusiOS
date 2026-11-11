<div align="center">

<img src="../docs/design/nexus-icon.svg" width="64" alt="Nexus">

# Nexus workspace agent

**A small, authenticated, read-only-by-default workspace bridge for the Debian laptop and the NixOS PC.**

![Go: 1.22+](https://img.shields.io/badge/Go-1.22%2B-0B1430?style=flat-square&labelColor=070C18&logo=go&logoColor=7CE8CA) ![platform: Linux](https://img.shields.io/badge/platform-Linux-0B1430?style=flat-square&labelColor=070C18&logo=linux&logoColor=E9EDF7) ![dependencies: stdlib only](https://img.shields.io/badge/dependencies-stdlib%20only-0B1430?style=flat-square&labelColor=070C18)

<sub>Part of <a href="../README.md">Nexus</a> · private</sub>

</div>

---

**Status:** Local source is tested on Linux; this revision's expanded capabilities have not received live-host acceptance. The small Go standard-library bridge runs independently on **the Debian laptop** or **the NixOS PC**, with distinct configured roots and credentials. Access is read-only by default; explicitly managed roots support the confined reviewed replacement path documented below. It does not run on the PS5. Source development does not modify remote SSH or service configuration.

The service exposes an authenticated REST/JSON interface to select workspaces, list children, read bounded text files, and request constrained synchronous read-only inspections. Inventory and text search are always available; Git status and file diffs require explicit per-root opt-in and a Linux process sandbox. Its `/v1/subagents/tasks` endpoint accepts only named operations and cannot accept caller-supplied commands, shells, scripts or filesystem writes.

## Requirements and run locally

Requires **Linux**, **Go 1.22+** and a low-privilege dedicated account with read permissions only on the intended project directories. It uses Linux `syscall.Openat` with `O_NOFOLLOW` and intentionally does not build on macOS/Windows. No third-party Go dependencies.

1. On **Debian**, make a private environment file from `.env.example`. Set `NEXUS_WORKSPACE_HOST=debian` and `NEXUS_WORKSPACE_ROOTS_JSON` to **only** the project directories you want the Nexus bridge to read. On **NixOS**, use `NEXUS_WORKSPACE_HOST=nixos`, distinct root paths and a **different** token. Root paths must exist, be absolute, not `/`, and contain no symlinks, including symlink ancestors.
2. Generate each token with `openssl rand -hex 32`. Store tokens with restrictive filesystem permissions (for example, a user-only systemd EnvironmentFile, mode `0600`). Never put tokens in source, command-line arguments, browser URLs, Git, or log output; do not commit real `.env` files.
3. From `workspace-agent/`, use `go test ./...`, `go test -race ./...` and `go vet ./...` to validate. Build with `go build -o nexus-workspace-agent .` and start via your service manager with the configuration variables loaded into its environment. The listener defaults to `127.0.0.1:8896`; all workspace endpoints require `Authorization: Bearer <token>`.
4. Use the host's local connection for testing, for example:

   ```sh
   curl --fail-with-body -H "Authorization: Bearer $NEXUS_WORKSPACE_TOKEN" \
     'http://127.0.0.1:8896/v1/workspaces?host=debian'
   ```

   Use the matching `host=nixos` query **only against the NixOS instance**. The API refuses a mismatch and never sends a request to another machine.

The service does not read `.env` itself. Load environment variables using a protected service-unit EnvironmentFile or your local service runner. If you use systemd, apply `User=...`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only` (or explicit `ReadOnlyPaths`/`BindReadOnlyPaths` depending on root placement), `PrivateTmp=yes`, and no write permissions to configured roots. Test such restrictions against the actual deployment layout before enabling them. The process requires no sudo/root privileges.

## REST/JSON contract

All `/v1` calls require **one** valid Bearer header. The configured host identifier is mandatory in the `host` query (GET) or request body (POST). Omit it, or send the wrong host, and the service returns `400 host_mismatch`. Query path is always **relative to the selected root**; an empty path means the root directory. Identical IDs on Debian and NixOS refer to different local directories and are disambiguated by `host`. All returned path names are **relative**; the real root paths are not returned.

| Route | Example | Response |
| --- | --- | --- |
| `GET /healthz` | No credentials required | `{"status":"ok"}`; no secrets |
| `GET /v1/workspaces?host=debian` | List configured roots | `{"host":"debian","workspaces":[{"id":"projects","name":"Projects"}]}` |
| `GET /v1/workspaces/{id}/files?host=debian&path=src` | List directory, max 128 entries returned (129 inspected to detect truncation) | `{"host":"debian","workspace_id":"projects","path":"src","entries":[{"name":"main.go","path":"src/main.go","kind":"file"}],"truncated":false}` |
| `GET /v1/workspaces/{id}/context?host=debian&path=src/main.go` | Read one allowed regular UTF-8 text file, max 64 KiB | `{"host":"debian","workspace_id":"projects","path":"src/main.go","text":"package main\n","size_bytes":13}` |
| `POST /v1/subagents/tasks` | Run a bounded read-only task synchronously | Request/response examples below |

Inventory task, at most **three directory levels** and **128 returned entries**:

```json
{"host":"debian","workspace_id":"projects","operation":"inventory","path":""}
```

```json
{"host":"debian","workspace_id":"projects","operation":"inventory","status":"completed","entries":[{"name":"src","path":"src","kind":"directory"}],"hits":[],"scanned_files":0,"truncated":false}
```

Search task, **one directory only**, at most **24 eligible files**, **64 KiB per file**, **20 matching lines**, **240 bytes / ~120 characters maximum output for a long line**:

```json
{"host":"nixos","workspace_id":"projects","operation":"find_text","path":"src","query":"Nexus"}
```

```json
{"host":"nixos","workspace_id":"projects","operation":"find_text","status":"completed","entries":[],"hits":[{"path":"src/main.go","line":2,"text":"// Nexus"}],"scanned_files":1,"truncated":false}
```

All task request bodies are limited to **4096 bytes**, reject unknown fields and trailing JSON, and run with a **4-second deadline** and **four simultaneous-task maximum**. Unsupported operations (including `shell`, `exec`, `write`, `apply_patch`, and arbitrary instructions) are rejected. The API performs no model inference, arbitrary command execution, filesystem writes or background jobs.

## Optional Git inspection

Set `git_read:true` only on roots whose repository history/index the authorized user may inspect. When any root opts in, configure absolute `NEXUS_WORKSPACE_GIT_EXECUTABLE`, `NEXUS_WORKSPACE_BWRAP_EXECUTABLE` and `NEXUS_WORKSPACE_PRLIMIT_EXECUTABLE` paths. Executables must have trusted system ownership/ancestry or live in an immutable Nix package. Require **bubblewrap 0.12+**, util-linux `prlimit`, and working Linux user/mount/PID/network namespaces. Missing tools fail startup; a sandbox failure returns `503 git_inspection_unavailable` and never falls back to ordinary host execution. This capability is disabled on all existing roots unless an administrator enables it. No remote configuration is changed by the source update.

Discovery now includes `read_only:true` and the actual `capabilities` array. Roots without Git opt-in advertise `list`, `read_file`, `inventory`, `find_text`. Enabled roots additionally advertise `git_status`, `git_diff`, `git_diff_staged`. Older bridge discovery without capability metadata remains readable by Nexus but does not enable Git controls.

The existing task route accepts these extra operations with an empty/omitted query:

- `git_status`: `path` is an allowed relative directory or empty for the root. Returns at most 128 changed tracked source-file entries, with `path`, `index` and `worktree` porcelain status characters. Untracked files, renames and submodules are excluded; protected/unsupported filenames are filtered. An empty result does not mean the entire repository is clean.
- `git_diff`: `path` is one allowed relative source file. Returns its unstaged diff.
- `git_diff_staged`: the same file constraint, comparing its index with HEAD. Deleted files are allowed if their parent path remains valid.

Successful task responses add `git:{path,changes,diff,truncated}`. Raw Git output is capped at 64 KiB; exceeding the limit terminates the subprocess and returns 413 instead of a partial diff. In addition to the request deadline, the sandbox sets a 512 MiB address-space limit, three CPU seconds, 128 file descriptors, zero regular-file output size and no core dumps. Cancellation terminates the sandbox; there is no persistent Git job. Only normal repositories with an in-root `.git` directory are supported; external gitdirs/linked worktrees and repository configurations requiring extensions are not supported by this path.

The selected root and its descriptor-opened Git metadata are mounted read-only, with only system runtime directories available. Host `/home`, `/etc`, `/run`, `/tmp`, other workspaces and host networking are absent. The environment is cleared and repository configuration is replaced by an empty read-only file: this prevents local clean filters, fsmonitor, external diffs, include files, textconv and hooks from invoking repository-chosen helpers. Git gets fixed arguments, literal pathspecs, no optional index locks, no external diff/textconv, no submodule inspection and no lazy network fetch. Runtime namespace restrictions must be compatible with the service manager's sandbox; test the actual host configuration before enabling. Keep the dedicated service account read-only and keep secrets outside configured roots. Historical/index source content can still contain secrets, so Git access is a deliberate additional grant at each root.

Errors use `{"error":"machine_readable_code"}` with ordinary HTTP statuses: `401` missing/invalid auth; `400` invalid path/host/task; `403` forbidden path; `404` unknown workspace/file; `413` oversized content; `415` invalid UTF-8/non-text; `429` task capacity; `408` task timeout. Successful content is `application/json; charset=utf-8` with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Security and confinement

- **Explicit roots only.** Workspace IDs are configured locally on each host. Filesystem root (`/`), missing roots, symlinked roots, duplicate IDs and ambiguous host names fail startup. Configured absolute paths are never returned to clients.
- **Descriptor-based traversal.** The root directory is opened through `openat` from `/`, rejecting symlink components; every requested segment is independently opened using `O_NOFOLLOW` and directories use `O_DIRECTORY`. File descriptors are created per request. Files that turn into symlinks cannot be followed. Paths containing `..`, `.`, absolute prefixes, empty components, backslashes, NUL, invalid UTF-8 or hidden dot segments are rejected. Symbolic links and special files are omitted from listings.
- **Reduced exposure.** Only the listed source/document extensions may be read. Hidden files, commonly named secrets and private-key artifacts are denied. Binary/NUL-containing files and files larger than 64 KiB are never returned. **These heuristics cannot detect every secret inside an otherwise allowed source file**: configure only folders whose contents the authenticated user may read; put secrets elsewhere. Hard links, bind mounts and directories writable by less-trusted users require OS-level isolation/ACLs, not only string validation.
- **Authentication.** A separate 32–256 character random Bearer token per host is compared using SHA-256 and constant-time comparison. No CORS response headers are emitted. Use TLS over any network path and private network/identity-layer authorization in addition to Bearer auth. Tokens are not OIDC/Cloudflare JWTs: do **not** substitute a Cloudflare Access assertion for the agent's own Bearer token.
- **No writes or arbitrary commands.** All business endpoints are read-only. The task route allowlists inventory/text search and optionally sandboxed Git inspections; callers cannot supply command arguments or executable paths. Run as an unprivileged account with operating-system read-only access, no additional capabilities and appropriate service sandboxing.

## Connecting both hosts through Tailscale / Cloudflare (deployment guide only)

The intended topology is **Nexus iPhone → authenticated Cloudflare Worker and Debian gateway → privately routed workspace agent on Debian or NixOS**. The iPhone need not know either agent token; store each host token only on the trusted orchestration side. Local source now includes the Worker, gateway, orchestrator and iOS proxy path. This workspace-agent service itself remains independently authenticated. Deployment and end-to-end live acceptance are not yet verified.

For Tailscale, install an instance on both hosts and keep both HTTP listeners on `127.0.0.1`. Expose them, if needed, behind **Tailscale Serve HTTPS** bound only to your tailnet, with device/user ACLs that permit only the Debian orchestrator to reach the NixOS agent. Ensure TLS certificate/hostname checks are enabled in the orchestrator. Do not use Tailscale Funnel or a public listener. Do not put a token into the HTTP query string.

For Cloudflare, an alternative is a **private Cloudflare Tunnel** per service guarded by Cloudflare Access with an explicit service-to-service authorization policy, plus a separately validated application Bearer token forwarded to the correct local agent. Restrict paths/methods, forward neither browser cookies nor caller-supplied identity headers as proof, and avoid publishing workspace endpoints without origin verification and rate limits. The existing Nexus Cloudflare Worker/gateway has **not** been updated to proxy these routes. A Cloudflare Access sign-in alone is not a substitute for agent authentication.

No service has been installed, started on a remote machine, or exposed over a network by this work. Review file allowlists, backup/rollback plan and tailnet/Cloudflare policy before any deployment.

## Patch execution groundwork (writes unavailable)

The optional `NEXUS_WORKSPACE_EXECUTOR_TOKEN` is distinct from the normal read token and requires a loopback listener, even when non-loopback reads were explicitly allowed. `NEXUS_WORKSPACE_PATCH_STATE_DIR`, when set, must already be a private owner-only directory; it enables the host receipt ledger and pins configured root descriptor identities. Preserve this directory across restart: deleting it to retry would discard consumption evidence.

The internal apply request binds host, workspace ID, owner digest, approval ID/digest, stable operation ID, relative path, baseline SHA-256, replacement bytes/hash and original expiry with a versioned length-prefixed HMAC. `GET /v1/workspaces/{id}/patches/receipts/{operation_id}` accepts the original bounded signed JSON request body and returns only an existing matching receipt; expiry is not re-enforced for this read-only reconciliation. Do not expose either endpoint through the public Worker or put the executor token in Nexus.

**Application remains unavailable:** `POST /v1/workspaces/{id}/patches/apply` authenticates/validates then returns 503 without staging files or consuming identifiers. `managed_write:true` roots are rejected at startup; `exclusive_writer` documents the necessary trust prerequisite but does not implement it. The ledger cannot certify application. A confined mutation helper, generation-bound snapshots, exact pre-rename identity checks and post-rename crash recovery must be implemented and tested before enabling writes. File preflight alone is not an atomic CAS against unrelated editors.

## Confined mutation helper (not yet enabled through HTTP)

`patch_executor.go` and `patch_helper.go` implement and test actual replacement in temporary managed workspaces. The fixed helper runs in a bubblewrap namespace with only the workspace writable, isolated network/processes and bounded resources. It receives no executor token/proof and runs no project code. The parent journals the staged inode, original version and parent identity before permitting rename. Recovery requires that inode/parent identity plus the approved content hash; it never treats equal bytes alone as an applied receipt. Known uncommitted stages can fail without replay; missing or contradictory evidence blocks the root.

The complete race suite and vet, actual namespace probes and helper crash-injection cases pass locally. This is process-crash evidence, not proof of power-loss behavior on an arbitrary filesystem. Dedicated service-owned private workspaces with no competing unmanaged writers remain mandatory. The public apply route still returns 503 and startup still rejects managed-write roots until generation-bound approvals and authenticated dispatch/reconciliation are connected. Existing read-only roots are unaffected.

## Explicit managed roots and generation-bound execution

The bridge can now enable `managed_write:true` only with `exclusive_writer:true`, a separate executor token, `NEXUS_WORKSPACE_PATCH_STATE_DIR` outside all configured roots, and trusted bubblewrap/prlimit executables. The root must be private and owned by the service. Workspace and receipt state require supported local ext4/XFS/Btrfs storage. Use a dedicated service-owned workspace without unrelated writers; this is not CAS protection against arbitrary same-UID editors. Existing roots default to read-only.

Opaque generations persist with root descriptor identity, appear in discovery and eligible text context, and are required in version-2 signed execution requests. A changed root/host set or legacy anchor without a generation cannot silently enable writes. The normal read credential never grants execution. `POST /v1/workspaces/{id}/patches/apply` checks the signed owner/approval/operation, generation, lease and managed policy before using the confined helper. `POST /v1/workspaces/{id}/patches/receipts/{operation_id}/reconcile` checks the original signed binding even after expiry and only resolves that recorded operation. GET receipt lookup stays non-mutating. No endpoint accepts arbitrary shell commands or caller-selected executables.

Local HTTP and real Python/Go/helper fixtures verify actual disposable-file application and no duplicate mutation. These source capabilities were not enabled or deployed on live hosts. Orchestrator-side review, current user/write-root grants and private executor configuration are independently required before a Nexus approval can cause execution. Legacy proposals lacking a generation remain review-only.

## Restricted command foundation (not exposed)

`commands.go` remains disconnected from service configuration, discovery, HTTP
and model tools. Administrator profiles fix executable/arguments, runtime,
allowed text files and limits. Clients cannot choose shells, executable paths or
arguments. Actual native command approval/execution controls are not available
yet. Current contract/evidence:
[`RESTRICTED-COMMANDS.md`](../docs/integrations/RESTRICTED-COMMANDS.md).

`Prepare` captures at most 128 exact text inputs (64 KiB/file, 1 MiB total),
root ID/generation/device/inode, sorted size/hash manifest, input digest, opaque
snapshot ID, complete policy version and five-minute expiry. Metadata access
returns copies. Captured bytes stay in private process memory; `Close` releases
them. Execution rechecks these bytes and never substitutes later workspace edits.
Results identify the captured snapshot/profile/input digest/generation.

## Runtime and resource boundaries

Profiles may mount individual immutable Nix package closures or one content-pinned
administrator runtime capsule. A capsule supplies an absolute `RuntimeRoot`, exact
`RuntimeDigest`, guest executable and guest `RuntimeLimitPath`; `RuntimePaths`
must be empty. Non-Nix capsules require root-owned protected ancestry and an
entirely non-writable tree. Validation hashes sorted paths/modes/file contents/
links, bounded to 20,000 entries, 2 GiB and depth 32. Special files, setuid/setgid,
foreign mounts and symlinked executable paths are refused. Real `/workspace` and
`/tmp` directories are required. Runtime files must not contain credentials.

Runtime mounting holds the verified root descriptor and passes it to bubblewrap
`--ro-bind-fd`; it does not reopen an unverified path. For input files, the runner
requires canonical private mode-0700 `/run/user/<uid>` on tmpfs and Linux
`O_TMPFILE`. It creates unnamed input inodes, transfers read-only descriptors and
copies bytes into a bounded 8 MiB namespace `/workspace` tmpfs, then remounts that
workspace read-only. All transferred descriptors close before project code.
There is no named temporary input directory to orphan after service death and no
named-file fallback. Namespace scratch remains independently bounded. Immutable
runtime capsules still work with the source-FD offsets after their root handle.

Trusted `systemd-run`/`systemctl`, a working user manager/cgroup v2, prlimit and
bubblewrap 0.12+ are mandatory. A fixed helper pinned through the running agent's
executable verifies actual kernel memory/no-swap/PID/CPU scope limits before
project code. Aggregate memory is 16–512 MiB, at most 32 tasks and one CPU;
execution lasts at most 30 seconds and no later than its signed lease. Bootstrap
also counts toward the task budget. Virtual address allowance is separate
(8 GiB default, at most 16 GiB). Bootstrap permits up to 256 descriptors for
bounded input transfer, then restores the project's 64-descriptor limit. Output
is capped at 64 KiB combined; scratch is at most 16 MiB. No host home/proc/device/
network/service credential or source-workspace descriptor reaches project code.
Unsupported isolation fails closed. Unknown descendant cleanup quarantines jobs.

Profile hash schema is now `nexus.command.profile.v2`, binding the anonymous-input
implementation revision. Older unexecuted captures need fresh preparation/review;
known journal receipts remain recoverable without launching code.

The capsule fixture uses pinned nixpkgs and tracked Git source:

```sh
nix build --impure --no-link --print-out-paths \
  --file workspace-agent/testdata/command-runtime.nix --argstr projectRoot "$PWD"
```

Pass the returned path as `NEXUS_COMMAND_RUNTIME_FIXTURE` to workspace-agent tests.
This is local rootfs evidence, not a deployed Debian toolchain acceptance.

## Admission, persistent snapshots and receipts

A zero-byte owner-only single-link `/run/user/<uid>/nexus-command.lock` serializes
all service processes under that UID. Never remove/replace it while runners are
active. Admission precedes the runner slot and leftover-scope check, and lasts
through verified cleanup. A crash releases the kernel lock, while unknown
surviving scopes still block new jobs.

`command_snapshots.go` maintains a separate exclusive private mode-0700
ext4/XFS/Btrfs snapshot directory. At most eight canonical checksummed records
store owner/host, preparation/root identity and exact bytes, at most 2 MiB encoded
and 1 MiB input each. Save syncs unpublished staging, atomically publishes and
syncs the directory. Ambiguous publication poisons its handle. Cleanup removes
only recognized unpublished stages and validated expired captures, preserves
unknown files and never touches consumption history. Loads restore private
memory, not host temporary input files.

`command_execution.go`/`command_journal.go` bind signed owner/host/root/generation,
exact approval, operation/snapshot/profile/input digest and lease, persist a
claim before code and name the scope from the operation. A distinct exclusive
private ext4/XFS/Btrfs journal directory holds timestamps, checksums and bounded
results. Exact repeats return receipts; changed or reused IDs conflict. An
unfinished claim cannot replay and reconciles only as unknown-exit interruption
when no scopes remain. A completed receipt still requires checking exit/failure/
cancel/timeout/truncation before calling tests successful. Never delete/reset
consumed history to retry. Hash chaining does not defend against trusted-owner
tampering or rollback of the entire directory.

Local evidence: `build/command-anonymous-full-tests.log` passes 70 top-level race
cases, no skips, plus vet. Actual probes cover all 128 inputs, nested/read-only
workspace data, project FD limits and transferred-FD closure, both runtime modes,
forced anonymous-holder death, aggregate limits, snapshot/receipt recovery and
patch/Git regressions. No deployed Linux/iPhone or physical power-loss acceptance
is implied.

Before public exposure: connect separately typed human command review/current
execute scope/root grants, parent durable signed dispatch/reconciliation, owned
cancel/output/audit APIs and native/model tools. HMAC authenticates the trusted
signer; it is not independent evidence of a human decision. Read-only roots do
not automatically acquire command generations/capabilities. No public command
route is enabled by these foundations.
