<div align="center">

<img src="../docs/design/nexus-icon.svg" width="64" alt="Nexus">

# Nexus agent orchestrator

**Durable, owner-scoped agent runs for NexusAI, with human review for every patch and command.**

![Python: 3](https://img.shields.io/badge/Python-3-0B1430?style=flat-square&labelColor=070C18&logo=python&logoColor=F1C07E) ![runs on: Debian gateway host](https://img.shields.io/badge/runs%20on-Debian%20gateway%20host-0B1430?style=flat-square&labelColor=070C18&logo=debian&logoColor=C9ADFF) ![API: REST](https://img.shields.io/badge/API-REST-0B1430?style=flat-square&labelColor=070C18)

<sub>Part of <a href="../README.md">Nexus</a> · private</sub>

</div>

---

## Durable approval navigation metadata

An owned `GET /v1/nexus/agent-runs/{id}` returns optional `approval_id` and
`approval_kind` (`patch` or `command`) for the **currently waiting** original
agent-created review. These fields are derived from a SHA-256-checked saved
checkpoint and its matching owner/digest/agent-origin record in the respective
patch or command approval table, not from mutable progress text. An unknown,
tampered or terminal checkpoint has `null` review metadata. Older servers that
omit the kind are supported by the gateway, but the native app fails closed to
non-actionable status instead of guessing a reviewer. This link is not an
execution grant: fixed-profile commands require independent human approval
**and then a separate owner Execute**, with original signed receipt reconciliation
and no uncertain execution replay.


## Optional Hermes engine

The existing owned agent-run API accepts `engine:"hermes"` when the administrator
configures `NEXUS_HERMES_IMAGE` with a pinned immutable local image ID and
`NEXUS_HERMES_DOCKER` with the trusted absolute Docker executable. Omitted `engine`
continues to use Nexus; unknown or unavailable engines fail closed. Native Nexus
offers the engine selector and persists its choice with each pending request.
Hermes runs networkless and without project mounts or credentials; Nexus retains
PS5 inference, scoped reads, human approval and durable receipt/resume controls.
See [the Hermes integration guide](../integrations/hermes/README.md) for the exact
pin, local build/tests, disabled features and unexecuted deployment/rollback steps.
The 64K context requirement does not establish sustained throughput or headroom.

A dependency-free Python 3.11+ local service that uses PS5LM Plus's OpenAI-compatible `/v1/chat/completions` endpoint for **actual model inference**, while executing read-only workspace discovery and file reference requests exclusively through the separately authenticated Debian/NixOS `workspace-agent` services.

It supports automatic conversation **summary compaction when the active request plus reserved output approaches 90% of the active model context**, using llama.cpp's chat-template-aware tokenizer and `/props` context report. An optional operator context limit can lower the reported model limit but cannot raise it. Missing or malformed runtime capacity/tokenizer data fails closed instead of guessing. Each run returns the exact preflight input token count and effective context limit. Inference calls use a separately configurable, bounded timeout (15 minutes by default); context and metadata requests retain shorter limits. When a selected workspace is present, the model may use a strict JSON fallback to request up to two bounded read-only searches or file reads from that same root. Paths, query shapes, returned data and context budget are validated. Shell/network requests are never run; edit proposals require explicit opt-in and the separate approval/execution path below. Up to three bounded, sequential analytical subagents (`analyzer`, `reviewer`, `planner`) may also provide untrusted suggestions to the final response. Each subagent is an independent local LLM call, **not** a persistent autonomous daemon or shell-capable worker. Running multiple calls sequentially conserves the PS5's limited GPU memory. The model is never granted direct command execution or filesystem write authority.

The persisted model context is limited to 32 messages and 48 KiB of UTF-8 per message, matching the Nexus client. Automatic compaction is required before a successful response would exceed the next-turn message cap; when disabled, an oversized history receives a recoverable 413. Submission bodies are bounded to 2 MiB and agent-run responses to 3 MiB end-to-end. The final answer budget is up to 4,096 tokens, capped at one quarter of the reported model context; every tokenizer preflight reserves that same amount. This is a ceiling, not a guarantee that the server will generate that many tokens or that every large request fits the separate byte limits. The Nexus UI separately stores the full transcript in its file-protected app storage; compaction only changes the context sent to the model.

## Scoped patch proposals and human review

The optional review API stores immutable, owner-bound source/replacement snapshots in the protected run database. Proposals expire after 15 minutes; decisions atomically consume the pending state and bind to the full canonical SHA-256 digest. Baselines are read through the existing authenticated workspace bridge. Source and replacement are each limited to 64 KiB. Submission IDs are stable 32-character lowercase hex values: retrying the same submission returns the same record, including after review, and different contents conflict. Lists contain metadata only (up to the latest 100 matching records); the global history cap is 1,024 records and fails closed when full. No automatic pruning is implemented.

These routes are scoped under `/v1/nexus/workspaces/{debian|nixos}/{root}/patches`:

- `POST` collection: `{path,replacement,submission_id}`, using the normal private orchestrator credential.
- `GET` collection or `GET /{id}`: list metadata or retrieve the captured proposal, using the separate review credential.
- `POST /{id}/decision`: `{digest,decision:"approve"|"reject"}`, using the separate review credential. Conflicting, expired or already reviewed decisions return HTTP 409. Another owner/root sees HTTP 404.
- `POST /{id}/apply`: `{digest}`, using the separate review credential plus explicit current write scope/root grants. Only standalone manual proposals with recorded provenance and a managed generation can execute. A current approval is required; retry returns the same saved operation rather than allocating another write.
- `POST /{id}/reconcile`: `{digest}`, with the same permissions. Recovers an existing operation using its saved request/receipt; it never starts a new replacement. Known uncertain outcomes stay uncertain until verified.

Every route requires the gateway-generated `X-Nexus-Principal` digest. The gateway requires an authenticated user with `nexus.workspace.read`, an explicit matching `NEXUS_WORKSPACE_GRANTS_JSON` root grant, and either `nexus.workspace.propose` for submission or `nexus.approvals.review` for reading/deciding. The Worker strips untrusted principal headers; the gateway reconstructs identity from the validated session. Do not expose the orchestrator directly to clients.

To enable the source implementation, configure the **same separate** `NEXUS_APPROVAL_REVIEW_TOKEN` privately on the gateway and orchestrator (32–256 non-whitespace ASCII characters). It must differ from the normal orchestrator, inference, workspace and PS5 control credentials. The app uses its existing signed-in gateway session; **never copy either private service credential into Nexus**. Missing configuration disables review. The normal orchestrator credential cannot read/approve proposals, and the review credential cannot submit them or run the agent endpoints. This separation prevents an agent request from using its service credential to approve itself; operators must also keep reviewer user credentials out of agent tools and infrastructure.

Native Nexus exposes an inbox and explicit approve/reject confirmation from each selected workspace. It verifies the captured original hash and canonical proposal digest before presenting a decision. Network interruption may occur after a decision was saved: reload to inspect the record instead of assuming failure means it was not recorded. Native Nexus now includes a protected proposal composer that saves and freezes the exact submission before sending. Retry uses the same ID/body after timeout or restart. A changed credential session blocks reuse rather than forwarding a previous identity's pending contents; OIDC refresh is conservatively treated as a credential change until stable verified subject binding is implemented.

Agent requests may explicitly set `allow_proposals:true` (default false), requiring a selected workspace, configured review service and the gateway's `nexus.workspace.propose` permission. A strict `propose_patch` model action saves a full continuation checkpoint and enters `waiting_for_approval`; the PS5 slot is released. Restart reuses the saved proposal instead of regenerating it or replaying earlier subagents. Run status exposes an opaque `approval_id` for the native review link. Rejection/expiry resumes with an explicit no-changes result. Approval alone leaves the task waiting; only a matching applied execution receipt can establish that an edit occurred. Proposal-enabled runs never use the legacy whole-run upstream retry. Managed execution is now implemented and exercised against a real temporary Go workspace bridge and confined helper; model generation and gateway policy in that fixture are explicit test replacements. No live-host deployment or PS5 generation is implied.

**Decision-route behavior:** review envelopes retain `execution_enabled:false` because this HTTP call records a decision rather than synchronously executing it. It is not a promise that an eligible approved agent task will never execute. For generation-bound proposals on explicitly managed roots, the native confirmation authorizes the exact edit; the background dispatcher then rechecks write permission and obtains a verified host receipt before resuming the task. Standalone manual proposals instead offer an explicit native apply confirmation and check-receipt action. Apply/reconcile responses use `execution_enabled:true` and include the verified execution metadata; the flag alone never establishes success. `manual_execution_allowed` in detail responses advertises recorded manual provenance and a managed generation, not current permission. Agent proposals cannot use manual routes. Old records lacking provenance stay manually review-only, including after retry. No live deployment or hardware acceptance is implied by local tests.

## Optional read-only Git tools

When an administrator enables sandboxed Git inspection on a workspace bridge root, discovery preserves `read_only` and the advertised `capabilities`. The native workspace screen exposes only the supported operations. The orchestrated model can select `git_status`, `git_diff`, or `git_diff_staged` through the existing strict JSON action format, counted toward the same two-operation limit as search/read. Status uses a relative directory or the root; diffs require one relative file. Results are validated for host, workspace, operation, path, entry shape and bounded output, and are supplied to inference as untrusted data with tokenizer preflight. Source `workspace-agent/README.md` documents the required opt-in, trusted tools, Linux namespaces, filtering and supported repository layout. This source integration has not been deployed and does not add Git writes or arbitrary command execution.

## Configuration (sample only; don't put real credentials in Git)

```bash
export NEXUS_ORCHESTRATOR_TOKEN='<32+ random chars>'
export NEXUS_ORCHESTRATOR_LISTEN='127.0.0.1:8897'
export NEXUS_PS5_CHAT_URL='http://192.168.1.50:8081/v1'
export NEXUS_PS5_MODEL_ID='auto' # follows the currently loaded model after a PS5 restart
export NEXUS_PS5_ENABLE_THINKING=0 # default; 1 opts into model reasoning tokens
export NEXUS_PS5_REQUEST_TIMEOUT_SECONDS=900 # default; valid range 15–3600 seconds
# Optional safety ceiling; actual context is read from the active model's /props.
# It may lower but never increase that reported capacity.
# export NEXUS_CONTEXT_TOKENS=65536
export NEXUS_ORCHESTRATOR_RUNS_DIR="$HOME/.local/share/nexus-orchestrator/runs" # owner-only durable jobs
# One-time legacy migration only: assign all pre-ownership jobs to this verified principal digest.
# export NEXUS_LEGACY_RUN_OWNER='<64 lowercase hex SHA-256 of the gateway principal>'
# Optional native model switching:
export NEXUS_PS5_CONTROL_URL='http://192.168.1.50:8082/v1'
export NEXUS_PS5_CONTROL_TOKEN='<different token provisioned on PS5>'
# Optional: both workspace agents run on their own hosts behind private authenticated ingress:
export NEXUS_DEBIAN_WORKSPACE_URL='https://<private-gateway>/v1'
export NEXUS_DEBIAN_WORKSPACE_TOKEN='<debian workspace token>'
export NEXUS_NIXOS_WORKSPACE_URL='https://<private-gateway>/v1'
export NEXUS_NIXOS_WORKSPACE_TOKEN='<nixos workspace token>'
python3 agent-orchestrator/server.py
```

The listener defaults to loopback. For nonloopback binding, `NEXUS_ORCHESTRATOR_ALLOW_NON_LOOPBACK=1` is required and **only** appropriate behind an access-controlled HTTPS reverse proxy. All non-health calls need a private service bearer token; review routes require the separate credential described above. Remote URL redirects are rejected. Explicit private IPv4 HTTP upstreams are permitted for local deployment; DNS names over HTTP and public-IP HTTP are rejected. The example PS5 IP is a placeholder — don't hardcode a stale network address.

The orchestrator persists an inference lease before starting each PS5 stream and clears it only on the stream's completion marker. A crash, ambiguous stream failure, or cancellation without that marker leaves inference quarantined. Later orchestrated runs fail without starting inference, and the active-run endpoint stays nonzero so a configured gateway's shared gate also refuses new inference/model actions. After independently verifying that the PS5 is idle and the earlier inference has stopped, stop the orchestrator and run `python3 agent-orchestrator/clear-inference-quarantine.py "$NEXUS_ORCHESTRATOR_RUNS_DIR" --confirmed-ps5-idle`, then restart it. The state directory must already exist and the exclusive lock prevents clearing while this orchestrator is running. Do not clear based solely on a disconnected client. This guard cannot block direct PS5 clients; live cancellation and completion-marker behavior still need hardware verification.

## REST contract

The public gateway authorizes these routes with separate grants:

| Grant | Capability |
|---|---|
| `nexus.model.read` | Read the native model list and status. |
| `nexus.model.control` | Request a model load or unload. Grant `nexus.model.read` separately to observe its progress. |
| `nexus.workspace.read` | List, browse, preview and run the two read-only searches against configured workspaces. |
| `nexus.orchestrate` | List metadata and cancel the caller's own agent runs; cancellation does not return the result. |
| `nexus.orchestrate` + `ai.chat` | Submit a run without a workspace. |
| `nexus.orchestrate` + `ai.chat` + `nexus.workspace.read` | Submit a run that references a workspace. |

Retrieving a run's status and result also requires `ai.chat`; workspace-derived runs additionally require `nexus.workspace.read`. The gateway requires the updated orchestrator's `workspace_required` status metadata and fails closed if it is missing or invalid, so these components must be upgraded together.

`nexus.orchestrate` no longer implies model or workspace access. Before deploying this gateway update, an operator must explicitly add only the needed new grants to the appropriate subjects in the private `NEXUS_SUBJECT_PERMISSIONS_JSON`, retain existing grants, and prepare rollback. This source change does not alter the live configuration.

Set the gateway's private `NEXUS_WORKSPACE_GRANTS_JSON` to a JSON object mapping each exact verified subject to permitted `host:workspace_id` pairs, for example `{"owner@example.invalid":["debian:code","nixos:project"]}`. Subjects still need `nexus.workspace.read` in the separate permission policy. Discovery is filtered, and browsing, workspace tasks, submissions and saved results require a matching pair. An omitted or blank variable and an empty object deny all workspaces; missing or malformed workspace identity fails closed. Existing installations must explicitly configure the new root grants before upgrading. Update the gateway and orchestrator together: saved-result access needs the newer identity metadata and tasks now require the gateway's loopback policy-check endpoint. The orchestrator uses `127.0.0.1:8787` by default; set `NEXUS_GATEWAY_POLICY_PORT` to the gateway's actual loopback port if different. It uses the same dedicated `NEXUS_ORCHESTRATOR_TOKEN` configured in the gateway. A task checks its owner and workspace before execution, at safe boundaries (cached for up to two seconds), and before publishing its result; unavailable policy checks stop work. Policy is loaded when the gateway starts, so apply policy changes by restarting the gateway. A restart or revocation during inference can leave the inference safety guard active until independently verified idle. In-flight blocking operations may take longer than the polling interval to stop.

- `GET /healthz` (unprivileged, no data)
- `GET /v1/nexus/models`, `GET /v1/nexus/status` — authenticated proxy to the native PS5 controller, when configured
- `POST /v1/nexus/models/{16-hex-id}/load`, `POST /v1/nexus/models/unload` — authenticated PS5 model switch; 202 means queued, not loaded
- `GET /v1/nexus/workspaces` — returns configured Debian/NixOS root choices and unavailable hosts
- `GET /v1/nexus/workspaces/{debian|nixos}` — list one configured host's allowlisted workspace roots
- `GET /v1/nexus/workspaces/{host}/{workspace_id}/files?path={relative_path}` — bounded, read-only file listing
- `GET /v1/nexus/workspaces/{host}/{workspace_id}/context?path={relative_path}` — bounded UTF-8 text preview
- `POST /v1/nexus/workspaces/{host}/{workspace_id}/tasks` — bounded read-only `inventory` or `find_text` request; shell/write operations are not accepted
- `POST /v1/nexus/agent-runs` — validates and queues a run, then returns HTTP 202 with its opaque run ID. The one-worker queue keeps subagent and final inference sequential.
- `GET /v1/nexus/agent-runs/{run_id}` — read phase, parent status, result, subagent status and the latest 100 timestamped activity events; poll to completion or reconnect later.
- `GET /v1/nexus/agent-runs/active` — report the number of queued/running tasks for the gateway's shared inference gate.
- `GET /v1/nexus/agent-runs` — list recent run metadata without result bodies.
- `POST /v1/nexus/agent-runs/{run_id}/cancel` — request cancellation at the next safe boundary.
- `POST /v1/nexus/agent-runs/{run_id}/subagents/{subagent_id}/cancel` — stop one subagent at its next inference boundary.

Activity events are durable in the private SQLite job database and survive service restarts. They contain bounded phase/status/subagent metadata only; prompts, workspace contents, model output and exception strings are excluded. Existing job databases are migrated when the service starts.
- `POST /v1/nexus/agent-runs` accepts:

```json
{
  "submission_id": "0123456789abcdef0123456789abcdef",
  "prompt": "Explain this implementation",
  "history": [{"role": "user", "content": "Earlier context"}],
  "workspace": {"host": "debian", "workspace_id": "code", "path": "src/main.py"},
  "subagents": 2,
  "auto_compact": true
}
```

`submission_id` is optional for older clients. A client that supplies it must generate a unique random 32-character lowercase hexadecimal ID and persist the complete request before sending. Retrying the same ID with the same request returns the existing run without starting it again, including after a service restart; a different request returns 409. If the run result has been pruned, the ID marker remains and retry returns 410 instead of repeating the task. Markers contain an ID and request digest, have a 100,000-entry cap, and are not automatically deleted; reaching the cap refuses new idempotent submissions until an operator performs a reviewed migration. Nexus checks the saved run first and retries the original request only if the server confirms it is absent. This requires the updated gateway and orchestrator together.

Job creation, listing, retrieval and cancellation require exactly one `X-Nexus-Principal` header containing the 64-character lowercase SHA-256 digest of the gateway-verified principal. The gateway constructs this header from its verified identity and never forwards a caller-provided value. A run and its submission ID belong to that principal; another principal cannot list, retrieve or cancel it or reuse its ID. This header is an identity assertion, **not a credential**: the dedicated orchestrator bearer token must be held only by the trusted gateway, and the listener must remain private. The global active-run count remains available to the authenticated gateway for inference coordination.

Existing job databases are migrated with unowned records left inaccessible and unowned queued runs held rather than resumed. They still count as active, so they can keep inference blocked. After verifying the ownership of **all** old records and backing up the private database, an operator may explicitly set `NEXUS_LEGACY_RUN_OWNER` to the SHA-256 digest of the exact gateway-verified principal and restart once to assign those records and old submission markers. Do not use this bulk migration if old jobs belong to different people; assign them through an individually reviewed migration instead. No existing live database is changed by these source updates.

The job result contains `response`, `model`, `compacted`, `history_for_next_turn`, `subagents` with role/output, workspace and number of referenced bytes. When supplied by the model server, `finish_reason` records why generation stopped; `length` means the answer reached its output ceiling and may be continued. A summary reporting `length`, a content filter, or a tool-call stop is rejected and the original history is retained. Reuse `history_for_next_turn` on the next turn if using this endpoint as the conversation engine. Run requests, statuses and results are persisted in SQLite with an owner-only directory/database (0700/0600); the default is `$HOME/.local/share/nexus-orchestrator/runs`. The SQLite content is **not encrypted at rest** and can contain prompts and source excerpts, so protect the Debian user's home/disk accordingly. A restart requeues interrupted read-only tasks. At most eight tasks are accepted and the oldest terminal records are pruned beyond 100. Cancellation requests interrupt active orchestrator inference with `DELETE /v1/stream?conv_id=…` when supported by the pinned llama.cpp server; closing the SSE response is the compatibility fallback. The orchestrator also checks cancellation at safe boundaries before scheduling more inference or workspace reads. Direct chat streams remain on Nexus's configured provider unless the operator opts into this job API.

`NEXUS_PS5_MODEL_ID=auto` queries `/v1/models` before each model call, so a remotely selected model becomes active after PS5LM reports readiness; a missing loaded model fails with 503 rather than fabricating one. You can instead pin an explicit model ID.

The orchestrator defaults `chat_template_kwargs.enable_thinking` to `false` for bounded subagent/summary/final-response calls. On a live Qwen thinking-model, low `max_tokens` budgets can otherwise be consumed entirely by reasoning tokens, producing no user-visible answer. Set `NEXUS_PS5_ENABLE_THINKING=1` only when the selected model supports that option and the response budgets are sufficient; this does not modify the separate native Nexus chat streaming settings.

Only user/assistant history roles are accepted. At the 90% boundary, older history is summarized by the selected PS5 model after its summary prompt is preflighted; the most recent four messages are preserved and no history is dropped when the summarization fails. The compacted request is recounted with the exact active tokenizer, including system/workspace/subagent text and reserved output. If it remains at or above 90%, the run returns a recoverable size error rather than looping or silently truncating. Workspace text is treated as untrusted reference material, never instructions. No shell, repository mutation, unattended agent loops, external browser tools, automatic repo commits, or token sharing exists.

```bash
python3 -m unittest discover -s agent-orchestrator -p 'test_*.py' -v
```

**Not deployed.** These scripts do not modify Debian, NixOS, PS5 or the public gateway. To use them securely, configure allowed workspace roots and authenticated private ingress, then test live model connectivity and latency on the actual PS5.

## Workspace write policy groundwork

The loopback-only, normal-orchestrator-bearer `POST /internal/nexus/authorize-workspace-operation` endpoint on the gateway checks `{principal,workspace:{host,id},operation:"propose"|"apply"}`. Checks are uncached at the Python call site. Both operations require current orchestration/chat/read scopes and an explicit read root grant; proposal additionally needs `nexus.workspace.propose`. Apply additionally needs `nexus.workspace.write` and a matching root in the separate default-empty `NEXUS_WORKSPACE_WRITE_GRANTS_JSON`. No existing read/root grant implies write permission. This endpoint returns only a policy decision, performs no side effect and is never exposed by the Worker. An approval and a configured confined host executor are still independently required. No write grants were installed on any live host.

`patch_execution.py` atomically consumes a currently approved snapshot and allocates one durable operation ID. It persists prepared/dispatching/applied/conflict/failed/uncertain states; a lost response or restart never grants a new dispatch. It validates the expected replacement hash but does not by itself authenticate a bridge receipt or perform a write. The private bridge now exposes generation-bound application only for explicitly provisioned managed roots, using the confined helper and durable host receipts. Read-only roots remain the default.

## Private managed-executor configuration

Set `NEXUS_DEBIAN_WORKSPACE_EXECUTOR_TOKEN` and/or `NEXUS_NIXOS_WORKSPACE_EXECUTOR_TOKEN` only for a configured bridge that has explicitly enabled managed roots. Each executor token must be distinct from every read/orchestrator/review/model-control token and from the other host's executor token. Execution ingress must use verified HTTPS or literal loopback (including the authenticated SSH tunnel); cleartext LAN execution is refused. Never put executor/review secrets into Nexus, repository files or model tools.

The dispatcher captures and persists a version-2 HMAC-bound request with a stable operation ID and a short write lease before crossing the side-effect boundary. Network errors/invalid replies remain uncertain; retries reconcile that exact signed request, including after lease expiry, rather than submitting another mutation. Root reconfiguration or missing receipts fail closed. Two bounded background workers keep workspace waits out of the PS5 inference queue. Cancellation is checked before dispatch; an operation already dispatched may have applied and its independently recorded receipt remains authoritative. The review inbox/detail includes safe execution metadata for that audit.

## Typed command approvals (not exposed)

`command_approvals.py` provides a separate durable command-review/consumption
schema in the private run database. It binds fixed administrator invocation and
limits to the exact host/root generation, prepared snapshot/profile/input
manifest and expiry; edit approvals cannot authorize commands. Stable owned
submission IDs preserve proposal identity, one human review decision is recorded,
and atomic consumption creates one operation ID with a once-only dispatch phase.
Strict terminal receipts cannot invent success or change a finished outcome.

These are trusted storage methods, not an authentication boundary. Do not route
a model/native payload's executable/arguments straight into them: future handlers
must obtain fixed invocation/preparation from the host, require the separate
human-review credential and current explicit execute scope/root grant, and use a
durable exact signed dispatcher. Those command routes/native controls remain
unfinished and disabled. See
[`RESTRICTED-COMMANDS.md`](../docs/integrations/RESTRICTED-COMMANDS.md).

## Private command dispatcher (service routes still disabled)

`command_dispatch.py` connects typed approvals to exact saved signed requests,
one send and receipt-only recovery after timeout/restart. Independent optional
`NEXUS_DEBIAN_COMMAND_EXECUTOR_TOKEN` / `NEXUS_NIXOS_COMMAND_EXECUTOR_TOKEN` must
be distinct from every read/review/PS5-control/edit-executor credential and each
other; transport is HTTPS or a loopback tunnel. Root generation, command
capability and exact trusted invocation/version must match. Current internal
execute authorization requires the separate gateway execute scope/root grant.
These internal primitives do not register a human/native command API.

A real local Python/HTTP/Go fixture executes in isolation once, drops its HTTP
reply and recovers the stored result after reopening parent state. Full results
and limitations are in the restricted-command contract.
Host service routes, human review permission wiring, native/model controls and
owned in-flight cancellation/output/audit remain next. No live policy changed.
