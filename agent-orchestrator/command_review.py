"""Owner-bound human review for fixed-profile captured commands.

No arbitrary executable, argument, input path or command text is accepted over
this interface. Host execution is distinct from human approval and defaults off.
"""
from __future__ import annotations

import re
import hashlib
import json

from approvals import ApprovalConflict, HEX_DIGEST, SUBMISSION_ID
from command_approvals import CommandApprovals, manifest_digest, validate_proposal
from command_dispatch import CommandDispatcher, CommandDispatchUnavailable
from patch_review import ReviewError
from run_jobs import WORKSPACE_ID
import time


COMMAND_ROUTE = re.compile(
    r'^/v1/nexus/workspaces/(debian|nixos)/([a-z][a-z0-9_-]{0,31})/commands'
    r'(?:/([0-9a-f]{32})(?:/(decision|execute|reconcile|cancel))?)?$'
)
COMMAND_PROFILE_ROUTE = re.compile(
    r'^/v1/nexus/workspaces/(debian|nixos)/([a-z][a-z0-9_-]{0,31})/commands/profiles$'
)
MAX_COMMAND_REVIEW_REQUEST = 4096


class CommandReview:
    def __init__(self, controller, runs):
        self.controller = controller
        self.store = CommandApprovals(runs)
        self.dispatcher = CommandDispatcher(controller, self.store)

    def with_execution(self, owner, item):
        record = dict(item)
        # An execution receipt is only taken from the separate authenticated
        # parent ledger, never inferred from a decision or client-provided text.
        record['execution_enabled'] = False
        execution = self.store.get_execution(owner, item['id'], item['digest'])
        if execution is not None:
            record['execution'] = execution
        return record

    def require_active_agent_checkpoint(self, owner, item):
        """Prevent executing an agent proposal after its parent is cancelled.

        The approval record alone is not authority to act on a former AI run.
        The saved model output must still be associated with exactly one
        checksum-verified, active, owner-bound waiting checkpoint. A crash
        after proposal creation but before association cannot bypass this.
        """
        if item['origin'] != 'agent':
            return
        with self.store.runs.lock:
            rows = self.store.runs.db.execute(
                'SELECT run_id,step,snapshot,checksum FROM approval_checkpoints '
                'WHERE approval_id=? AND owner=?', (item['id'], owner)).fetchall()
            if len(rows) != 1:
                raise ReviewError(409, 'agent_command_checkpoint_missing')
            run_id, step, encoded, checksum = rows[0]
            if hashlib.sha256(encoded.encode()).hexdigest() != checksum:
                raise ReviewError(409, 'agent_command_checkpoint_changed')
            try:
                saved = json.loads(encoded)
                action = saved['action']
                workspace = saved['workspace']
            except (TypeError, ValueError, KeyError) as exc:
                raise ReviewError(409, 'agent_command_checkpoint_invalid') from exc
            p = item['proposal']
            expected_submission = hashlib.sha256(f'nexus-command:{run_id}:{step}'.encode()).hexdigest()[:32]
            if (action != {'action': 'propose_command', 'profile_id': p['profile_id']} or
                    workspace.get('host') != p['host'] or
                    workspace.get('workspace_id') != p['workspace_id'] or
                    item['submission_id'] != expected_submission):
                raise ReviewError(409, 'agent_command_checkpoint_binding_changed')
            run = self.store.runs.get_owned(run_id, owner)
            if (run is None or run['status'] != 'waiting_for_approval' or run['cancel_requested']):
                raise ReviewError(409, 'agent_command_parent_no_longer_waiting')

    def dispatch(self, method: str, path: str, owner: str, payload: dict | None):
        profile_match = COMMAND_PROFILE_ROUTE.fullmatch(path)
        if profile_match is not None:
            if method != 'GET' or payload is not None:
                raise ReviewError(405, 'method_not_allowed')
            host, root = profile_match.groups()
            return 200, self.profiles(owner, host, root)
        match = COMMAND_ROUTE.fullmatch(path)
        if match is None:
            raise ReviewError(404, 'not_found')
        host, root, approval_id, action = match.groups()
        scope = {'host': host, 'workspace_id': root,
                 'execution_enabled': method == 'POST' and action in ('execute', 'reconcile', 'cancel')}

        # A read grant, patch-review grant or previously approved command does
        # not authorize command review or execution after permission revocation.
        if not self.controller.authorize_workspace_operation(owner,
                {'host': host, 'workspace_id': root}, 'execute'):
            raise ReviewError(403, 'workspace_execute_denied')

        if method == 'POST' and approval_id is None:
            if (not isinstance(payload, dict) or set(payload) != {'profile_id', 'submission_id'} or
                    not isinstance(payload['profile_id'], str) or
                    re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', payload['profile_id']) is None or
                    not isinstance(payload['submission_id'], str) or
                    SUBMISSION_ID.fullmatch(payload['submission_id']) is None):
                raise ReviewError(400, 'invalid_fixed_command_request')
            try:
                item = self.dispatcher.prepare_proposal(owner, host, root,
                    payload['profile_id'], payload['submission_id'])
            except PermissionError as exc:
                raise ReviewError(403, 'workspace_execute_denied') from exc
            except CommandDispatchUnavailable as exc:
                raise ReviewError(503, 'command_profile_or_snapshot_unavailable') from exc
            return 200, {**scope, 'command': self.with_execution(owner, item)}

        if method == 'GET' and approval_id is None:
            if payload is not None:
                raise ReviewError(400, 'request_body_not_permitted')
            return 200, {**scope, 'commands': self.store.list_scope(owner, host, root)}

        item = self.store.get(owner, approval_id)
        if (item is None or item['proposal']['host'] != host or
                item['proposal']['workspace_id'] != root):
            raise ReviewError(404, 'not_found')
        if method == 'GET' and action is None:
            if payload is not None:
                raise ReviewError(400, 'request_body_not_permitted')
            return 200, {**scope, 'command': self.with_execution(owner, item)}

        if method == 'POST' and action == 'decision':
            if (not isinstance(payload, dict) or set(payload) != {'digest', 'decision'} or
                    not isinstance(payload['digest'], str) or
                    HEX_DIGEST.fullmatch(payload['digest']) is None or
                    payload['decision'] not in ('approve', 'reject')):
                raise ReviewError(400, 'invalid_command_decision')
            # Both manual and AI-origin proposals require this same explicit
            # *human* decision. Agent task approval never starts execution.
            self.require_active_agent_checkpoint(owner, item)
            if not self.store.review(owner, approval_id, payload['digest'], payload['decision']):
                raise ReviewError(409, 'command_changed_expired_or_already_reviewed')
            return 200, {**scope, 'command': self.with_execution(owner, self.store.get(owner, approval_id))}

        if method == 'POST' and action in ('execute', 'reconcile', 'cancel'):
            if (not isinstance(payload, dict) or set(payload) != {'digest'} or
                    not isinstance(payload['digest'], str) or
                    HEX_DIGEST.fullmatch(payload['digest']) is None):
                raise ReviewError(400, 'invalid_command_execution_request')
            if payload['digest'] != item['digest']:
                raise ReviewError(409, 'command_review_digest_mismatch')
            # No model receives the distinct review bearer. A human must
            # separately trigger execute even after approving an agent idea.
            try:
                if action == 'cancel':
                    if item['status'] in ('pending', 'approved', 'rejected'):
                        self.store.withdraw(owner, approval_id, payload['digest'])
                    else:
                        self.dispatcher.cancel(owner, approval_id, payload['digest'])
                elif action == 'execute':
                    self.require_active_agent_checkpoint(owner, item)
                    # The parent can be cancelled while profile/generation
                    # checks are in flight. Recheck under the dispatcher's
                    # final SQLite admission lock: an old human approval must
                    # never bypass newer parent-task cancellation.
                    def parent_cancelled():
                        if item['origin'] != 'agent':
                            return False
                        try:
                            self.require_active_agent_checkpoint(owner, item)
                            return False
                        except ReviewError:
                            return True
                    self.dispatcher.execute(owner, approval_id, payload['digest'],
                                            cancelled=parent_cancelled if item['origin'] == 'agent' else None)
                else:
                    self.dispatcher.reconcile(owner, approval_id, payload['digest'])
            except PermissionError as exc:
                raise ReviewError(403, 'workspace_execute_denied') from exc
            except CommandDispatchUnavailable as exc:
                # Outcome may already be committed on host. Never auto-resend.
                raise ReviewError(503, 'command_outcome_requires_receipt_reconciliation') from exc
            except (InterruptedError, ApprovalConflict) as exc:
                raise ReviewError(409, 'command_state_conflict') from exc
            return 200, {**scope, 'command': self.with_execution(owner, self.store.get(owner, approval_id))}
        raise ReviewError(405, 'method_not_allowed')

    def profiles(self, owner: str, host: str, root: str) -> dict:
        """Expose only administrator-fixed profiles, never arbitrary commands.

        Called after a separate review token and owner principal were verified
        by the HTTP handler, with an uncached execute policy check. Both read
        bridge and execute credentials must be configured to make discovery
        usable. The host profile invocation is validated before serialization.
        """
        if not self.controller.authorize_workspace_operation(owner,
                {'host': host, 'workspace_id': root}, 'execute'):
            raise ReviewError(403, 'workspace_execute_denied')
        try:
            base, _ = self.dispatcher._configuration(host)
            roots = self.controller.list_workspace(host)
            matching = [item for item in roots['workspaces'] if item.get('id') == root]
            if (len(matching) != 1 or 'run_command' not in matching[0].get('capabilities', []) or
                    not isinstance(matching[0].get('generation'), str) or
                    HEX_DIGEST.fullmatch(matching[0]['generation']) is None):
                raise CommandDispatchUnavailable('command workspace is disabled')
            read_key = self.controller.workspaces[host][1]
            result = self.controller.http_json(base, '/workspaces/' + root +
                '/commands/profiles?host=' + host, read_key, timeout=5)
            if (not isinstance(result, dict) or set(result) != {'host', 'workspace_id', 'profiles'} or
                    result['host'] != host or result['workspace_id'] != root or
                    not isinstance(result['profiles'], list) or len(result['profiles']) > 32):
                raise CommandDispatchUnavailable('invalid fixed-profile inventory')
            ids = set()
            for item in result['profiles']:
                if (not isinstance(item, dict) or set(item) != {'id', 'version', 'invocation'} or
                        not isinstance(item['id'], str) or WORKSPACE_ID.fullmatch(item['id']) is None or
                        item['id'] in ids or not isinstance(item['version'], str) or
                        HEX_DIGEST.fullmatch(item['version']) is None):
                    raise CommandDispatchUnavailable('invalid fixed-profile identity')
                ids.add(item['id'])
                # Reuse the already trusted typed command-manifest validator.
                validate_proposal(owner, dict(kind='command', host=host, workspace_id=root,
                    workspace_generation=matching[0]['generation'], snapshot_id='0'*32,
                    profile_id=item['id'], profile_version=item['version'],
                    input_digest=manifest_digest([]), inputs=[], expires_at=int(time.time())+120,
                    invocation=item['invocation']))
            if not self.controller.authorize_workspace_operation(owner,
                    {'host': host, 'workspace_id': root}, 'execute'):
                raise ReviewError(403, 'workspace_execute_denied')
            return {'host': host, 'workspace_id': root, 'execution_enabled': False,
                    'workspace_generation': matching[0]['generation'], 'profiles': result['profiles']}
        except (ValueError, TypeError, KeyError, CommandDispatchUnavailable) as exc:
            raise ReviewError(503, 'fixed_command_profiles_unavailable') from exc
