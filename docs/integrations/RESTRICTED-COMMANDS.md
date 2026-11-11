# Restricted command host contract

> **Owned run status now distinguishes review type (2026-11-04):** When a durable AI task is `waiting_for_approval`, the private orchestrator status returns `approval_id` and `approval_kind` (`"command"` for `propose_command`, `"patch"` for `propose_patch`) **only** when the saved checkpoint checksum, original owner/request workspace and matching typed approval record/digest/origin are verified. Unknown, corrupted, cancelled or completed checkpoints do not advertise a link. The gateway validates typed IDs/status; a legacy missing/null kind causes the native app to present a non-actionable warning instead of misrouting to patch review. Command-kind navigation deep-links to the original fixed-profile review and never auto-executes; a separate human Execute action, current executor root grant and signed original host receipt remain mandatory. Python 33 focused + 184 full (five optional skips), Go gateway race/vet, Swift package and iPhoneOS Debug local tests pass. No production grants, PS5 console action or iPhone acceptance implied.


> **Final regression verification (2026-11-04):** Full Python command/orchestrator suite completed **183 tests, five optional Hermes skips, otherwise passing** (`build/nexusai-final-python-full-20261104.log`). Local validation only. Agent-origin review must still require active, matching owner/run/step checkpoint and a separate human Execute; no production command root or executor grant was enabled.

> **Agent-command checkpoint update, 2026-11-04:** Gated model action `{"action":"propose_command","profile_id":"fixed_admin_id"}` now persists an owner/run/step-bound approval checkpoint without a model shell. Requires selected command-enabled workspace plus `allow_proposals`; parent independently rechecks execute policy and fixed captured host inventory. Agent-origin proposal uses separate human review and **separate human Execute**, never auto-executes on approval. An agent-origin approve/execute requires checksum-verified checkpoint identity and a still-waiting noncancelled parent; results are derived from verified original host receipts or reported as rejection/expiry/unknown-exit. Model continuation never resends an uncertain original command. Eight focused + full Python 179 tests, Go race/vet, Worker 13, Swift 190+40 and native PS5 host controller tests pass locally; production command root enablement, signed iPhone acceptance and live PS5 are separate **unfinished** gates.

> **Current implementation update, 2026-11-04:** The original "local foundation only" description below is historical. The full authenticated *local code path* now connects fixed Go host profiles/prepare/execute/reconcile/cancel, Python durable manually reviewed proposals and independent owner-execute grants, Go gateway/Cloudflare Worker guarded routes, and the native SwiftUI review/execute/cancel UI. Never equate this with deployed readiness: command roots and execute grants are **not enabled on the live servers**, and no on-device review test exists.

## Versioned private and owner-facing HTTP surfaces (local source, opt-in)

The command-enabled Go host exposes `GET /v1/workspaces/{root}/commands/profiles?host={debian|nixos}` and `POST /v1/workspaces/{root}/commands/prepare` only with its *read* bearer, and `POST /v1/workspaces/{root}/commands/execute`, `POST /v1/workspaces/{root}/commands/receipts/{operation_id}/reconcile`, `POST /v1/workspaces/{root}/commands/receipts/{operation_id}/cancel` with its distinct executor bearer. Host execute/cancel/reconcile POSTs require the exact same original HMAC-signed command request and a matching configured root/profile. The cancel route acknowledges `host`, `workspace_id`, `operation_id`, `cancel_requested`, `receipt_status`; an acknowledgement of cancellation is **not a terminal execution receipt**, and unclaimed/unknown active operations return 409. On cancellation, only the original running thread supervises and persists its final bounded `completed`/`cancelled` result; an interrupted scope after restart remains unknown until explicit reconciliation. No host port may be exposed publicly. Keep an owner-only 0700 snapshot directory and separate 0700 journal directory on persistent ext4/XFS/Btrfs outside all workspace roots, enforce trusted systemd-run/systemctl and bwrap/prlimit runtimes, and bind a fixed administrator profile to the chosen root. Secret-bearing files and shells outside the defined profile must never become inputs.

Python's separate review token exposes `GET/POST /v1/nexus/workspaces/{host}/{root}/commands`, `GET /commands/{review_id}`, and `POST /commands/{review_id}/{decision|execute|reconcile|cancel}` under a verified owner principal digest. POST proposal takes only `profile_id` and `submission_id` (no executable/argv/path). Review decision takes `digest` and `decision`, with `approve` or `reject`; execute/reconcile/cancel take the saved exact `digest`. The command capture/discovery manifest and profile must match live trusted host generation, profile version, inputs and invocation. The gateway requires **all** `nexus.orchestrate`, `ai.chat`, `nexus.workspace.read`, `nexus.approvals.review`, `nexus.workspace.execute`, per-root read grant and per-root execute grant; unconfigured execute grants remain empty (deny). The Worker passes only a valid Access assertion and bounded approved methods/paths/bodies; it never forwards a caller-provided owner header. Python rechecks the current execute grant on every privileged call, including cancel/reconcile/list, and uses a private host executor token distinct from every read/review/edit/PS5 credential. Unconfirmed/dropped response must be recovered from the existing receipt; neither user nor model can cause automatic duplicate execution.

**Documented local acceptance:** Go workspace full race+vet and real cancel/replay/denial (including separate registered HTTP endpoint) PASS; Python full 170 tests, five optional Hermes skips, plus lost-reply/reopened SQLite and owner/revocation/withdrawal/cancel cases PASS; Go gateway full race+vet and Worker 13-case routing suite PASS; Swift Core and SSH 189+40 test cases PASS, including cross-language canonical manifest and tampered displayed receipt; pinned xtool Debug compiles, preserving `com.ljcatherine.Nexus` and SSH linkage. Follow-up pinned native build after credential-scoped retry marker change required before IPA shipping. Local endpoint fixtures are not an iPhone, deployed Cloudflare worker or audited live command profile. Unfinished: external administrator cancel/recovery, agent-run checkpoints, safe host deployment/config and owner-signed iPhone acceptance. No changing PS5 FTP/loader privileges to work around this workstream.

Status: local Go foundation only, not exposed through configuration, discovery,
HTTP, model tools or native UI. The complete human-approval/execute-grant and service API boundaries remain unfinished. Do not enable a route
that merely calls this runner with a model-supplied command.

## Input and authority boundary

Administrator profiles define fixed executable/arguments, toolchain capsule or
immutable package roots, exact text input allowlists and resource/output limits.
Preparation captures bytes and hashes, profile version, root generation/inode,
opaque snapshot ID and expiry. Execution verifies private copies of those captured
bytes. Later working-tree edits do not alter the job and are not covered by its
result. Text/name checks do not detect secrets; administrators must exclude
credential-bearing inputs and runtime files.

`commandRequest` is an internal trusted-dispatcher binding. HMAC authenticates
that dispatcher; it does not establish a human decision. The dispatcher must
separately check the exact typed command approval, owner, current independent
execute scope/root grant and atomically consume the approval before dispatch.
Read or patch-write permission must not implicitly authorize commands.

## Versioned signing format

The byte prefix is `nexus.workspace.command.v1` followed by a NUL byte. Append
these fields in order, each prefixed by its UTF-8 byte length as uint32 big endian:

1. Host identifier.
2. Workspace identifier.
3. Workspace generation (64 lowercase hex).
4. Owner/principal digest (64 lowercase hex).
5. Human command approval ID (32 lowercase hex).
6. Exact command approval digest (64 lowercase hex).
7. Durable operation ID (32 lowercase hex).
8. Prepared snapshot ID (32 lowercase hex).
9. Administrator profile ID.
10. Exact profile version (64 lowercase hex).
11. Captured input-manifest digest (64 lowercase hex).
12. Expiry in decimal Unix seconds.

The proof is lowercase-hex HMAC-SHA256 over these bytes. The request digest is
SHA256 over the same bytes. Proof is not stored in the receipt ledger. A new
execution must have a valid fresh lease of at most 300 seconds, no later than
snapshot expiry. Its runtime is bounded by both the profile timeout and lease.
Known receipt lookup/reconciliation may validate the original signature after
expiry; it grants no new execution.

## Durable host ledger and execution

`openCommandJournal` requires a distinct private, service-owned mode-0700 state
directory on local ext4/XFS/Btrfs, outside workspaces. It holds an exclusive
process lock and an owner-only single-link `commands.jsonl` on the same mount.
Each append has a timestamp, checksum and previous-record checksum. Maximum size
is 32 MiB and 2,048 records; new claims reserve headroom for a bounded terminal
receipt. No automatic deletion/reset/compaction erases consumed identifiers.

`ExecuteRecorded` verifies the request/snapshot binding, acquires canonical
cross-process command admission, then appends and fsyncs a claim before project
code. Its systemd scope is `nexus-command-<operation_id>.scope`. The shared lock
covers the durable claim, sandbox execution, verified cleanup and receipt write.
The lock order is admission first, runner slot second. Reconciliation takes the
same admission lock and re-reads the receipt, preventing a race with a claimed
job that has not launched yet. The ordinary captured runner uses the same order.

Approval, operation and snapshot IDs are consumed together. An exact repeated
request returns its existing receipt and never grants another launch. A changed
binding or reused identifier conflicts. At most one unfinished claim is admitted
per journal. Append/sync ambiguity poisons the live handle; no further execution
can use it. Torn, corrupted or unsafe storage refuses reopening. This is checked
process/durability logic, not hardware power-loss validation. Hash chaining does
not defend against the trusted OS owner changing or rolling back the whole store.

## Outcomes and reconciliation

- `claimed`: consumed durably; no terminal outcome is known. Never replay it.
- `completed`: supervision ended and cleanup was verified. Inspect result exit
  code, cancellation/timeout/truncation flags and failure; this status alone does
  not mean tests passed. Exit -1 means no normal exit was observed.
- `interrupted`: explicit reconciliation found no remaining command scopes and
  recorded `exit_unknown`, without a result. It does not claim success or rerun.

Receipts include the captured snapshot/profile/input digest/generation and
bounded untrusted stdout/stderr. Internal error paths are reduced to fixed error
codes. Preserve independent authorization when exposing reads/output later.

Reconciliation never implicitly cancels a live job. Unknown remaining scopes
keep it unresolved. Caller cancellation currently follows the internal context
and existing process-tree cleanup; no externally addressable cancel API is
implemented yet. Unknown cleanup quarantines the runner and preserves the claim.

## Persistent captured-input store

`command_snapshots.go` now persists host/owner-bound preparation metadata, original
root device/inode and exact captured bytes. Its separate exclusive private
mode-0700 ext4/XFS/Btrfs directory holds at most eight canonical checksummed
records, each at most 2 MiB encoded and 1 MiB input. Byte arrays use base64 to keep
encoded sizes bounded. Record files are owner-only/single-linked/on the same
mount; unsafe records and unknown names refuse opening.

Save syncs an unpublished `.<snapshot-id>.pending` file, publishes atomically
under exclusive directory ownership and syncs the directory. Ambiguous writes
poison the live store. Reopen syncs validated publication. Cleanup deletes only
recognized private unpublished stages and validated expired captures. Unknown
files are preserved. The consumption/audit journal is separate and never erased
by cache expiry. Loads check host/owner and recreate exact captured inputs;
reloading is not new execution authority and cannot bypass journal consumption.

## Anonymous execution inputs

Capture/load/verification now keep bounded input bytes in process memory. Launch
creates unnamed `O_TMPFILE` inodes on canonical private user-runtime tmpfs,
reopens them read-only and closes the writable handles. Bubblewrap copies inputs
into a bounded 8 MiB namespace `/workspace` tmpfs, makes it read-only, and consumes/
closes transferred descriptors before project code. No global temporary input
name or materialization directory exists to orphan after service death. No
named-file fallback or global temporary-directory sweep is used. Persistent
published/staging cache records retain their separate managed lifecycle above.

Bootstrap has a 256-FD allowance for at most 128 inputs plus a capsule handle;
project code gets its original 64-FD limit. Aggregate memory/PID/CPU limits remain
verified before namespace creation. Profile version schema changed to
`nexus.command.profile.v2`; old unexecuted captures require re-preparation/review,
while existing receipt recovery never launches code and remains valid.

## Local evidence and remaining integration

`build/command-anonymous-full-tests.log` passes 70 top-level local race cases,
no skips, and vet. Actual fixtures test all 128 inputs/nested paths, immutable
workspace, project FD limit and closure of every transferred handle, capsule
source-FD offsets, anonymous inode/read-only properties and forced holder death.
The complete snapshot/receipt/cancellation/resource/isolation/patch/Git regression
suite also passes. Fault tests simulate process/file boundaries, not physical
power loss. No deployed Linux or iPhone acceptance is implied.

Required before public exposure: human-review HTTP/current execute-policy wiring,
host command service configuration/routes, authenticated owned cancellation/
output/audit APIs and native/model-tool integration. HMAC does
not substitute for a human decision. Do not reset consumed state or deploy source
without the complete authorization contract.

## Typed parent review storage

`agent-orchestrator/command_approvals.py` uses separate command approval/execution
SQLite tables in the private RunStore. Explicit kind/owner/submission/origin,
fixed invocation/resource limits and host/root/snapshot/profile/input/expiry bind
the proposal digest. The trusted proposal handler must obtain those fields from
the host's fixed profile/preparation. It must never copy a client/model-selected
executable/argument list into a privileged proposal.

Review decisions and approval-consumption/operation allocation are atomic. Exact
retries cannot change origin, contents or expiry; a host snapshot has one proposal.
Edit/command approvals cannot substitute. Dispatch state advances once; uncertain
or terminal claims cannot send again. Terminal receipts strictly bind the owned
operation, request, captured result, bounded output and real outcome flags.

The storage API is not human authentication or execute authorization. Human-review HTTP credentials/current execute-policy wiring, host command service
routes and native/model controls remain unfinished. The private dispatcher and
independent policy primitives are implemented as described below. Current local
evidence: full Python 144 cases/five opt-in skips plus eight latest focused review
cases; full Go race/vet 71 cases/no skips, including real manifest interoperability.
No public command route or deployed acceptance is established.

## Parent dispatch and current execution policy

`command_dispatch.py` requires distinct per-host `NEXUS_<HOST>_COMMAND_EXECUTOR_TOKEN`
credentials, clean HTTPS/loopback transport and current root generation/capability/
exact profile invocation. It consumes typed approval and saves the exact signed
request before one send. Unknown replies require receipt reconciliation; missing
saved requests are never regenerated after dispatch. Receipt validation also
matches the saved lease, not merely the approval's expiry. Wire expiry is an
integer even when SQLite stores dates as REAL. Pre-send cancellation does not
supply an externally owned live-cancel API.

Internal gateway operation `execute` requires `nexus.workspace.execute` plus
`NEXUS_WORKSPACE_EXECUTE_GRANTS_JSON`, default empty, alongside the existing
orchestrate/chat/read/read-root permissions. Writes cannot substitute. Controller
command keys are separate from read/review/PS5-control/edit-executor roles. This
source update does not register public command endpoints or modify live policy.

The missing-delivery case remains unresolved while its lease is fresh. Once
expired, explicit reconciliation under admission/no-scopes may consume that exact
signed request as interrupted/unknown-exit without execution. It never asserts
success/historical nonexecution or erases consumption. A late original execute
request receives the stored interruption rather than running again.

Local evidence: full Python 153 cases/five opt-in skips plus latest 9 dispatcher/
3 config cases; full host race/vet 74 cases/no skips; gateway race/vet. The real
Python HTTP/SQLite → Go isolated executor fixture intentionally loses a completed
reply and recovers after parent storage reopen with one execute request. Policy/
human decisions are fixtures; signing, transport, journal and sandbox execution
are real. No deployed/hardware acceptance is implied. Next: actual host/review/
gateway/native routes, explicit owned in-flight cancel/output/audit and agent
checkpoint integration. Manual controls must not bypass agent task cancellation.
