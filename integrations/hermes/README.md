<div align="center">

<img src="../../docs/design/nexus-icon.svg" width="64" alt="Nexus">

# Hermes engine for NexusAI

**Optional Nous Research Hermes agent loop, running networkless behind Nexus's own inference and review.**

![engine: optional](https://img.shields.io/badge/engine-optional-0B1430?style=flat-square&labelColor=070C18) ![runs in: Docker, no network](https://img.shields.io/badge/runs%20in-Docker,%20no%20network-0B1430?style=flat-square&labelColor=070C18&logo=docker&logoColor=9CBCFF) ![deployed: not yet](https://img.shields.io/badge/deployed-not%20yet-0B1430?style=flat-square&labelColor=070C18)

<sub>Part of <a href="../../README.md">Nexus</a> · private</sub>

</div>

---

Nexus remains the native client and security boundary. The existing authenticated
Cloudflare → gateway → orchestrator route admits an owned durable task. An explicit
`engine:"hermes"` request runs the pinned Nous Research Hermes agent on the Debian
orchestrator host; all inference still goes through Nexus's existing PS5 transport,
single inference slot, tokenizer checks and interruption/quarantine handling.

This source integration is opt-in. It has not been deployed to Debian or accepted
on an iPhone. An isolated real-Hermes fixture verifies the loop and scheduler
recovery with simulated PS5 responses, not real PS5 performance.

## What is implemented

- Real upstream `AIAgent.run_conversation`, pinned by `revision`; no vendored fork.
- Native Nexus/Hermes engine selection, preserved in the frozen pending submission
  and the owned run request. The same submission ID cannot change engines.
- Up to six sequential scoped workspace actions across proposal checkpoints.
  Reads/search and opt-in Git inspection reuse the existing workspace bridge.
- Optional proposals use the existing exact snapshot, human review, current policy,
  durable receipt and checkpoint/resume path. Hermes cannot approve itself or write
  to a workspace directly. Rejection resumes explicitly with no changes.
- Exact tokenizer preflight of the text actually submitted to PS5 inference, with
  the reserved response budget and a 90% context boundary. The bridge translates
  between Hermes tool messages and the existing strict PS5 JSON action format;
  native model-server tool calling is not assumed.

Hermes needs at least 64,000 **reported** context tokens. Nexus never enlarges the
reported capacity. Ordinary Nexus preflight compaction can run before entering the
Hermes loop; an oversized request during that loop currently fails safely instead
of invoking Hermes's independent compression provider. Learned long-term Hermes
memory, automatic skill creation, external tools, parallel delegation, cloud
fallbacks and general command execution are disabled. Existing Nexus transcript
history and bounded analytical subagents remain available. Those additional Hermes
features require separate integration with owner-scoped state and the same tool
and inference controls; they are not delivered by this adapter.

## Worker isolation

The runtime accepts only an immutable local image ID with the expected revision
and protocol labels. It launches a non-root container with no network, no host
mounts, a read-only image, all capabilities dropped, no privilege escalation,
1 GiB aggregate memory/no extra swap, 64 processes and one CPU. Scratch space is
a bounded 64 MiB tmpfs and is discarded. No service/user credentials, project
directory, Docker socket or user home enters the worker. Upstream tool execution
is replaced completely with the bounded Nexus pipe protocol. The parent validates
every action and supplies only scoped results. Unknown tools and malformed frames
fail closed. Worker diagnostics are not forwarded into application logs.

The orchestrator operator must trust the configured Docker daemon and executable;
the model has no access to either. Cancellation removes the actual container,
rather than assuming termination of the Docker client stops it. Inference
cancellation still requires the existing PS5 completion-marker guard; killing the
Hermes container alone does not establish PS5 idleness.
Admission first creates a named stopped container, then attaches to that exact
container. Failed/ambiguous cleanup disables further worker admissions; leftover
`nexus-hermes-*` containers also block admission after an orchestrator restart.
An operator must inspect and resolve those exact containers independently before
retrying. The adapter never blindly starts additional workers over unknown state.

## Local build and verification

Use the owner's ECC verification/security guidance before builds. On a trusted
development host with Docker and Git:

```sh
bash scripts/build-hermes-worker.sh
```

The script fetches the exact revision, exports only committed upstream contents,
builds with the pinned Python base image and upstream frozen dependency lock, and
prints the immutable image ID. It does not publish an image or change any service.
An existing checkout can be supplied as the first argument; `git archive` still
exports the pinned revision rather than working-tree contents.

```sh
NEXUS_HERMES_TEST_IMAGE="$(docker image inspect --format '{{.Id}}' nexus-hermes:local)" \
NEXUS_HERMES_TEST_DOCKER="$(command -v docker)" \
python3 -m unittest discover -s agent-orchestrator -p 'test_hermes*.py'
```

These opt-in tests run real Hermes in disposable networkless containers with
explicitly simulated inference/workspace responses. They cover a tool round,
proposal suspension/new-worker resume, real SQLite scheduler restart, owner and
submission identity, cancellation and actual container isolation probes.

## Fresh local verification — 4 November 2026

The existing immutable image
`sha256:08c62cae66d5ab55c53ac93ecdef0d7570c294d45f91f884f502cb05b185fd90`
was checked without network/host mounts against the current worker and pinned
upstream run_agent.py/uv.lock hashes. The 14 focused Hermes tests pass, including
all five formerly skipped container cases. The full Python suite then passes
**187 tests, zero skips** with that image enabled. Logs:
`build/nexusai-hermes-opt-in-20261104.log` and
`build/nexusai-ready-to-test-python-with-hermes-20261104.log`.
There were no leftover named test containers. These results use explicit simulated
PS5 responses; no live generation, Debian deployment, phone acceptance or new
image publication occurred.

## Deployment and rollback (operator steps; not executed)

After the complete coordinated gateway/orchestrator/native update has passed its
deployment gates, build/load the image on Debian and set privately in the existing
orchestrator service environment:

```text
NEXUS_HERMES_IMAGE=sha256:<the locally built immutable image ID>
NEXUS_HERMES_DOCKER=/usr/bin/docker
```

Use the actual trusted absolute Docker path. Keep all existing gateway, policy,
review, workspace and inference configuration. Do not expose the orchestrator,
Docker or an upstream Hermes API server publicly. The app selects Hermes using
its existing signed-in session; no new credential is entered on the phone.

Before restart, retain the previous source, environment, image ID and protected
run database backup. Drain active inference through the existing service and
confirm idleness; never clear quarantine merely because a connection disappeared.
Restart only under the owner's deployment authorization. Existing clients that
omit `engine` continue to request Nexus.

Rollback retains the protected run/approval/receipt database, stops new Hermes
admissions and restores the previous coordinated app/services/configuration. Never
silently rerun a saved Hermes task with the Nexus engine or another revision.
Recover known proposals/receipts under their original binding; unresolved outcomes
remain uncertain. Removing the optional image setting disables new Hermes runs
and does not grant another engine permission to replay them.

Upstream: https://github.com/NousResearch/hermes-agent (MIT). Preserve the upstream
license and dependency notices when distributing any runtime image. No image or
release was published by this implementation.
