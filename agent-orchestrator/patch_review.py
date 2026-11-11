"""Scoped proposal review plus explicit standalone application/reconciliation."""
from __future__ import annotations

import hashlib
import re

from approvals import ApprovalConflict, ApprovalStore, HEX_DIGEST, SUBMISSION_ID
from patch_dispatch import PatchDispatcher, PatchDispatchUnavailable
from patch_execution import ExecutionConflict

PATCH_ROUTE = re.compile(
    r"^/v1/nexus/workspaces/(debian|nixos)/([a-z][a-z0-9_-]{0,31})/patches"
    r"(?:/([0-9a-f]{32})(?:/(decision|apply|reconcile))?)?$"
)
MAX_PATCH_REQUEST = 512 * 1024


class ReviewError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message
        super().__init__(message)


class PatchReview:
    def __init__(self, controller, runs):
        self.controller = controller
        self.store = ApprovalStore(runs)
        self.dispatcher = PatchDispatcher(controller, self.store)
        self.executions = self.dispatcher.executions

    def dispatch(self, method: str, path: str, owner: str, payload: dict | None) -> tuple[int, dict]:
        match = PATCH_ROUTE.fullmatch(path)
        if match is None:
            raise ReviewError(404, "not_found")
        host, root, approval_id, decision = match.groups()
        scope = {"host": host, "workspace_id": root,
                 "execution_enabled": method == 'POST' and decision in ('apply', 'reconcile')}
        if method == "POST" and approval_id is None:
            item = self.propose(owner, host, root, payload)
            return 200, {**scope, "patch": self.with_execution(owner, item)}
        if method == "GET" and approval_id is None:
            if payload is not None:
                raise ReviewError(400, "request_body_not_permitted")
            items = self.store.list_scope(owner, host, root)
            for item in items:
                execution = self.executions.get(owner, item['id'], item['digest'])
                if execution is not None: item['execution_phase'] = execution['phase']
            return 200, {**scope, "patches": items}
        item = self.store.get(owner, approval_id)
        if item is None or (item["proposal"]["host"], item["proposal"]["workspace_id"]) != (host, root):
            raise ReviewError(404, "not_found")
        if method == "GET" and decision is None:
            if payload is not None:
                raise ReviewError(400, "request_body_not_permitted")
            return 200, {**scope, "patch": self.with_execution(owner, item)}
        if method == "POST" and decision == "decision":
            if (not isinstance(payload, dict) or set(payload) != {"digest", "decision"} or
                    not isinstance(payload["digest"], str) or not HEX_DIGEST.fullmatch(payload["digest"]) or
                    payload["decision"] not in ("approve", "reject")):
                raise ReviewError(400, "invalid_review_decision")
            target = "approved" if payload["decision"] == "approve" else "rejected"
            if not self.store.transition(owner, approval_id, payload["digest"], expected="pending", target=target):
                raise ReviewError(409, "proposal_changed_expired_or_already_reviewed")
            return 200, {**scope, "patch": self.with_execution(owner, self.store.get(owner, approval_id))}
        if method == 'POST' and decision in ('apply', 'reconcile'):
            if (not isinstance(payload, dict) or set(payload) != {'digest'} or
                    not isinstance(payload['digest'], str) or not HEX_DIGEST.fullmatch(payload['digest'])):
                raise ReviewError(400, 'invalid_execution_request')
            if payload['digest'] != item['digest']:
                raise ReviewError(409, 'proposal_digest_changed')
            if self.store.origin(owner, approval_id) != 'manual':
                raise ReviewError(409, 'proposal_is_not_a_standalone_manual_edit')
            try:
                # An uncached check covers reconciliation too: it may sync/clean
                # up a known operation, but can never dispatch another rename.
                if not self.controller.authorize_workspace_operation(owner, item['proposal'], 'apply'):
                    raise PermissionError('write access denied')
                if decision == 'apply':
                    self.dispatcher.apply(owner, approval_id, payload['digest'])
                else:
                    self.dispatcher.reconcile(owner, approval_id, payload['digest'])
            except PermissionError as exc:
                raise ReviewError(403, 'workspace_write_denied') from exc
            except ExecutionConflict as exc:
                raise ReviewError(409, 'execution_identity_or_state_conflict') from exc
            except PatchDispatchUnavailable as exc:
                raise ReviewError(503, 'execution_unavailable_reload_saved_receipt') from exc
            return 200, {**scope, 'patch': self.with_execution(owner, self.store.get(owner, approval_id))}
        raise ReviewError(405, "method_not_allowed")

    def with_execution(self, owner, item):
        result = dict(item)
        result['manual_execution_allowed'] = (self.store.origin(owner, item['id']) == 'manual' and
                                             item['proposal'].get('workspace_generation') is not None)
        execution = self.executions.get(owner, item['id'], item['digest'])
        if execution is not None:
            result['execution'] = {key: execution[key] for key in
                ('operation_id', 'phase', 'result_sha256', 'created_at', 'updated_at')}
        return result

    def propose(self, owner: str, host: str, root: str, payload: dict, *, origin: str = 'manual') -> dict:
        if origin not in ('manual', 'agent'):
            raise ValueError('invalid proposal origin')
        if (not isinstance(payload, dict) or set(payload) != {"path", "replacement", "submission_id"} or
                not self.controller.valid_workspace_path(payload["path"], allow_root=False) or
                not isinstance(payload["submission_id"], str) or not SUBMISSION_ID.fullmatch(payload["submission_id"]) or
                not isinstance(payload["replacement"], str) or "\0" in payload["replacement"] or
                len(payload["replacement"].encode("utf-8")) > 64 * 1024):
            raise ReviewError(400, "invalid_patch_proposal")
        previous = self.store.get_submission(owner, payload["submission_id"])
        if previous is not None:
            if self.store.origin(owner, previous['id']) not in ('legacy', origin):
                raise ApprovalConflict('proposal origin cannot change')
            saved = previous["proposal"]
            if (saved["host"], saved["workspace_id"], saved["path"], saved["replacement"]) != (
                    host, root, payload["path"], payload["replacement"]):
                raise ApprovalConflict("proposal submission conflicts with its saved contents")
            return previous
        context = self.controller.workspace_file_context(host, root, payload["path"])
        original = context["text"]
        proposal = {"host": host, "workspace_id": root, "path": payload["path"],
                    "original": original, "replacement": payload["replacement"],
                    "base_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest()}
        generation = context.get("workspace_generation")
        if generation is not None:
            if not isinstance(generation, str) or not HEX_DIGEST.fullmatch(generation):
                raise ReviewError(502, "invalid_workspace_generation")
            proposal["workspace_generation"] = generation
        return self.store.propose(owner, proposal, submission_id=payload["submission_id"], origin=origin)
