"""Exact approved-command dispatch; timeout/restart never authorizes a resend."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import struct
import time
import uuid
from urllib.parse import urlsplit

from approvals import ApprovalConflict, SUBMISSION_ID
from command_approvals import canonical, validate_proposal, validate_receipt
from run_jobs import PRINCIPAL_ID, WORKSPACE_ID


class CommandDispatchUnavailable(Exception):
    pass


def command_binding(payload):
    result = b'nexus.workspace.command.v1\0'
    for name in ('host', 'workspace_id', 'workspace_generation', 'owner', 'approval_id', 'digest',
                 'operation_id', 'snapshot_id', 'profile_id', 'profile_version', 'input_digest', 'expires_at'):
        value = str(payload[name]).encode('utf-8')
        result += struct.pack('!I', len(value)) + value
    return result


def command_proof(payload, key):
    return hmac.new(key.encode('utf-8'), command_binding(payload), hashlib.sha256).hexdigest()


class CommandDispatcher:
    def __init__(self, controller, approvals):
        self.controller, self.approvals, self.runs = controller, approvals, approvals.runs
        with self.runs.lock:
            self.runs.db.execute('''CREATE TABLE IF NOT EXISTS command_dispatch_requests (
                approval_id TEXT PRIMARY KEY,owner TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,
                digest TEXT NOT NULL,body TEXT NOT NULL,checksum TEXT NOT NULL)''')

    def _configuration(self, host):
        keys = getattr(self.controller, 'command_executor_tokens', {})
        key = keys.get(host)
        if (not isinstance(key, str) or not 32 <= len(key) <= 256 or
                any(ord(c) <= 32 or ord(c) >= 127 for c in key) or
                len(set(keys.values())) != len(keys)):
            raise CommandDispatchUnavailable('distinct command executor credentials required')
        forbidden = [getattr(self.controller, name, '') for name in ('token', 'review_token', 'control_token')]
        forbidden += [value[1] for value in self.controller.workspaces.values()]
        forbidden += list(getattr(self.controller, 'workspace_executor_tokens', {}).values())
        bridge = self.controller.workspaces.get(host)
        if key in forbidden or bridge is None:
            raise CommandDispatchUnavailable('command credentials must be separate from other roles')
        base = bridge[0]
        try:
            url = urlsplit(base)
        except ValueError as exc:
            raise CommandDispatchUnavailable('invalid command executor ingress') from exc
        try:
            local = url.scheme == 'http' and ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            local = False
        if (not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment or
                (url.scheme != 'https' and not local)):
            raise CommandDispatchUnavailable('command executor requires clean HTTPS or loopback ingress')
        return base, key

    def _item(self, owner, approval_id, digest):
        item = self.approvals.get(owner, approval_id)
        if item is None or item['digest'] != digest:
            raise ApprovalConflict('exact owned command approval required')
        return item

    def _current_profile(self, proposal):
        response = self.controller.list_workspace(proposal['host'])
        if not isinstance(response,dict) or not isinstance(response.get('workspaces'),list) or len(response['workspaces'])>16:
            raise CommandDispatchUnavailable('invalid command workspace discovery')
        selected = [root for root in response['workspaces'] if isinstance(root,dict) and root.get('id') == proposal['workspace_id']]
        if (len(selected) != 1 or selected[0].get('generation') != proposal['workspace_generation'] or
                'run_command' not in selected[0].get('capabilities', [])):
            raise CommandDispatchUnavailable('command workspace capability or generation changed')
        base, read_key = self.controller.workspaces[proposal['host']]
        profiles = self.controller.http_json(base, '/workspaces/' + proposal['workspace_id'] +
                    '/commands/profiles?host=' + proposal['host'], read_key)
        if (not isinstance(profiles, dict) or profiles.get('host') != proposal['host'] or
                profiles.get('workspace_id') != proposal['workspace_id'] or
                not isinstance(profiles.get('profiles'), list) or len(profiles['profiles']) > 32):
            raise CommandDispatchUnavailable('invalid command profile discovery')
        matches = [profile for profile in profiles['profiles'] if isinstance(profile, dict) and profile.get('id') == proposal['profile_id']]
        if (len(matches) != 1 or matches[0].get('version') != proposal['profile_version'] or
                canonical(matches[0].get('invocation')) != canonical(proposal['invocation'])):
            raise CommandDispatchUnavailable('fixed command invocation or profile version changed')

    def _authorize(self, owner, proposal):
        if not self.controller.authorize_workspace_operation(owner, proposal, 'execute'):
            raise PermissionError('workspace command execution denied')

    def prepare_proposal(self, owner, host, workspace_id, profile_id, submission_id, *, origin='manual'):
        """Capture a trusted fixed-profile command as a *pending* human review.

        No client-supplied executable, arguments, file paths, input hashes or
        snapshot metadata may enter this operation. Human review and current
        execute grants remain mandatory before a separate execute() call.
        """
        if (not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner) or
                host not in ('nixos', 'debian') or
                not isinstance(workspace_id, str) or not WORKSPACE_ID.fullmatch(workspace_id) or
                not isinstance(profile_id, str) or not WORKSPACE_ID.fullmatch(profile_id) or
                not isinstance(submission_id, str) or not SUBMISSION_ID.fullmatch(submission_id)):
            raise ValueError('invalid fixed command review request')
        if origin not in ('manual', 'agent'):
            raise ValueError('invalid fixed command proposal origin')
        identity = {'host': host, 'workspace_id': workspace_id}
        self._authorize(owner, identity)
        existing = self.approvals.get_submission(owner, submission_id)
        if existing is not None:
            p = existing['proposal']
            if (existing['origin'] != origin or p['host'] != host or
                    p['workspace_id'] != workspace_id or p['profile_id'] != profile_id):
                raise ApprovalConflict('command submission identity cannot change')
            return existing

        base, _ = self._configuration(host)
        roots = self.controller.list_workspace(host)
        selected = [root for root in roots['workspaces'] if root['id'] == workspace_id]
        if (len(selected) != 1 or 'run_command' not in selected[0].get('capabilities', []) or
                not isinstance(selected[0].get('generation'), str)):
            raise CommandDispatchUnavailable('fixed command root not enabled')
        base, read_key = self.controller.workspaces[host]
        profiles = self.controller.http_json(base, '/workspaces/' + workspace_id +
            '/commands/profiles?host=' + host, read_key)
        if (not isinstance(profiles, dict) or profiles.get('host') != host or
                profiles.get('workspace_id') != workspace_id or
                not isinstance(profiles.get('profiles'), list) or len(profiles['profiles']) > 32):
            raise CommandDispatchUnavailable('invalid fixed command profile inventory')
        matching = [p for p in profiles['profiles'] if isinstance(p, dict) and p.get('id') == profile_id]
        if len(matching) != 1 or not isinstance(matching[0].get('version'), str):
            raise CommandDispatchUnavailable('requested fixed command profile is unavailable')

        # A saved snapshot ID is never supplied by the chat, a model tool or
        # the iOS client. The host atomically captures its allowlisted input.
        snapshot_id = uuid.uuid4().hex
        expires_at = int(time.time()) + 120
        response = self.controller.http_json(base, '/workspaces/' + workspace_id +
            '/commands/prepare', read_key, 'POST', {'host': host, 'workspace_id': workspace_id,
            'owner': owner, 'profile_id': profile_id, 'snapshot_id': snapshot_id,
            'expires_at': expires_at}, timeout=15)
        if (not isinstance(response, dict) or set(response) != {'host', 'owner', 'snapshot'} or
                response['host'] != host or response['owner'] != owner or
                not isinstance(response['snapshot'], dict)):
            raise CommandDispatchUnavailable('host command preparation was not authenticated')
        snapshot = response['snapshot']
        required = {'snapshot_id', 'workspace_id', 'workspace_generation', 'profile_id',
                    'profile_version', 'input_digest', 'inputs', 'expires_at', 'invocation'}
        if (set(snapshot) != required or snapshot['snapshot_id'] != snapshot_id or
                snapshot['workspace_id'] != workspace_id or snapshot['profile_id'] != profile_id or
                snapshot['workspace_generation'] != selected[0]['generation'] or
                snapshot['profile_version'] != matching[0]['version'] or
                snapshot['expires_at'] != expires_at or
                canonical(snapshot['invocation']) != canonical(matching[0].get('invocation'))):
            raise CommandDispatchUnavailable('host command snapshot differs from fixed policy')
        proposal = {'kind': 'command', 'host': host, **snapshot}
        try:
            validate_proposal(owner, proposal)
        except (ValueError, KeyError, TypeError) as exc:
            raise CommandDispatchUnavailable('host command snapshot failed validation') from exc
        # Fail on policy revocation between network capture and publication.
        self._authorize(owner, proposal)
        return self.approvals.propose(owner, proposal, submission_id, origin=origin)

    def _request(self, owner, item, execution, key, *, create):
        proposal = item['proposal']
        fields = {name: proposal[name] for name in ('host', 'workspace_id', 'workspace_generation',
                  'snapshot_id', 'profile_id', 'profile_version', 'input_digest')}
        fields.update(owner=owner, approval_id=item['id'], digest=item['digest'], operation_id=execution['operation_id'])
        with self.runs.lock:
            row = self.runs.db.execute('SELECT owner,operation_id,digest,body,checksum FROM command_dispatch_requests WHERE approval_id=?',
                                      (item['id'],)).fetchone()
            if row is not None:
                if (row[:3] != (owner, execution['operation_id'], item['digest']) or len(row[3].encode()) > 4096 or
                        hashlib.sha256(row[3].encode()).hexdigest() != row[4]):
                    raise ApprovalConflict('saved command dispatch integrity failure')
                payload = json.loads(row[3])
                if (not isinstance(payload, dict) or set(payload) != set(fields) | {'expires_at', 'proof'} or
                        any(payload[name] != value for name, value in fields.items()) or
                        type(payload['expires_at']) is not int or not 0 < payload['expires_at'] <= item['expires_at'] or
                        not isinstance(payload['proof'], str) or not hmac.compare_digest(payload['proof'], command_proof(payload, key)) or
                        canonical(payload) != row[3]):
                    raise ApprovalConflict('saved command request binding mismatch')
                return payload
            if not create or execution['phase'] != 'prepared':
                raise ApprovalConflict('original command dispatch request missing; do not regenerate')
            lease = math.ceil(proposal['invocation']['limits']['timeout_ms'] / 1000) + 5
            payload = {**fields, 'expires_at': min(int(item['expires_at']), int(time.time()) + lease)}
            payload['proof'] = command_proof(payload, key)
            encoded = canonical(payload)
            self.runs.db.execute('INSERT INTO command_dispatch_requests VALUES(?,?,?,?,?,?)',
                (item['id'], owner, execution['operation_id'], item['digest'], encoded, hashlib.sha256(encoded.encode()).hexdigest()))
            return payload

    def _receipt(self, owner, item, execution, payload, receipt):
        expected = {name: value for name, value in payload.items() if name != 'proof'}
        if not isinstance(receipt, dict) or receipt.get('request') != expected:
            raise CommandDispatchUnavailable('command receipt does not match original request')
        if receipt.get('status') == 'claimed':
            if set(receipt) != {'request', 'status'}:
                raise CommandDispatchUnavailable('invalid pending command receipt')
            return self.approvals.mark_uncertain(owner, item['id'], item['digest'], execution['operation_id'])
        validate_receipt(owner, item, execution['operation_id'], receipt)
        return self.approvals.finish(owner, item['id'], item['digest'], execution['operation_id'], receipt)

    def execute(self, owner, approval_id, digest, *, cancelled=None):
        if cancelled is not None and cancelled():
            raise InterruptedError('command cancelled before dispatch')
        item = self._item(owner, approval_id, digest)
        base, key = self._configuration(item['proposal']['host'])
        self._authorize(owner, item['proposal'])
        old = self.approvals.get_execution(owner, approval_id, digest)
        if old is not None and old['phase'] in ('completed', 'interrupted'):
            return old
        if old is not None and old['phase'] != 'prepared':
            return self.reconcile(owner, approval_id, digest)
        self._current_profile(item['proposal'])
        if cancelled is not None and cancelled():
            raise InterruptedError('command cancelled before approval consumption')
        self._authorize(owner, item['proposal'])
        execution = self.approvals.claim(owner, approval_id, digest)
        payload = self._request(owner, item, execution, key, create=True)
        if payload['expires_at'] <= time.time():
            raise CommandDispatchUnavailable('command lease expired before dispatch')
        self._authorize(owner, item['proposal'])
        with self.runs.lock:
            if cancelled is not None and cancelled():
                raise InterruptedError('command cancelled before dispatch boundary')
            started = self.approvals.start_dispatch(owner, approval_id, digest, execution['operation_id'])
        if not started:
            return self.reconcile(owner, approval_id, digest)
        timeout = math.ceil(item['proposal']['invocation']['limits']['timeout_ms'] / 1000) + 5
        try:
            receipt = self.controller.http_json(base, '/workspaces/' + item['proposal']['workspace_id'] + '/commands/execute',
                key, 'POST', payload, timeout=timeout)
            return self._receipt(owner, item, execution, payload, receipt)
        except Exception as exc:
            # Even a malformed reply may follow actual execution. Never resend.
            current = self.approvals.get_execution(owner, approval_id, digest)
            if current['phase'] == 'dispatching':
                self.approvals.mark_uncertain(owner, approval_id, digest, execution['operation_id'])
            raise CommandDispatchUnavailable('command outcome requires original receipt reconciliation') from exc

    def reconcile(self, owner, approval_id, digest):
        item = self._item(owner, approval_id, digest)
        base, key = self._configuration(item['proposal']['host'])
        self._authorize(owner, item['proposal'])
        execution = self.approvals.get_execution(owner, approval_id, digest)
        if execution is None:
            raise ApprovalConflict('no recorded command execution')
        if execution['phase'] in ('completed', 'interrupted', 'prepared'):
            return execution
        payload = self._request(owner, item, execution, key, create=False)
        try:
            receipt = self.controller.http_json(base, '/workspaces/' + item['proposal']['workspace_id'] + '/commands/receipts/' +
                execution['operation_id'] + '/reconcile', key, 'POST', payload, timeout=5)
            return self._receipt(owner, item, execution, payload, receipt)
        except Exception as exc:
            raise CommandDispatchUnavailable('original command receipt not yet verified') from exc

    def cancel(self, owner, approval_id, digest):
        """Durably request cancellation of one original signed operation.

        Never starts an operation, builds a new signature or treats an HTTP
        acknowledgement as proof that project code stopped. The host execution
        thread retains sole authority to write its terminal receipt.
        """
        item = self._item(owner, approval_id, digest)
        base, key = self._configuration(item['proposal']['host'])
        self._authorize(owner, item['proposal'])
        execution = self.approvals.get_execution(owner, approval_id, digest)
        if execution is None or execution['phase'] == 'prepared':
            raise ApprovalConflict('command has not been dispatched; withdraw the review instead')
        if execution['phase'] in ('completed', 'interrupted'):
            return execution
        payload = self._request(owner, item, execution, key, create=False)
        self._authorize(owner, item['proposal'])
        # The intent persists through parent restart, upstream timeout and
        # client disconnect. Retrying the exact cancellation is safe.
        self.approvals.request_cancel(owner, approval_id, digest)
        try:
            result = self.controller.http_json(base, '/workspaces/' + item['proposal']['workspace_id'] +
                '/commands/receipts/' + execution['operation_id'] + '/cancel',
                key, 'POST', payload, timeout=5)
            if (not isinstance(result, dict) or set(result) !=
                {'host', 'workspace_id', 'operation_id', 'cancel_requested', 'receipt_status'} or
                result['host'] != item['proposal']['host'] or
                result['workspace_id'] != item['proposal']['workspace_id'] or
                result['operation_id'] != execution['operation_id'] or
                type(result['cancel_requested']) is not bool or
                result['receipt_status'] not in ('claimed', 'completed', 'interrupted') or
                (result['receipt_status'] == 'claimed' and not result['cancel_requested']) or
                (result['receipt_status'] != 'claimed' and result['cancel_requested'])):
                raise ValueError('invalid signed host cancellation acknowledgement')
            current = self.approvals.get_execution(owner, approval_id, digest)
            if current['phase'] == 'dispatching':
                current = self.approvals.mark_uncertain(owner, approval_id, digest, execution['operation_id'])
            # A confirmed terminal status still requires a separate exact
            # receipt read. An acknowledged cancel is never a success result.
            return current
        except Exception as exc:
            current = self.approvals.get_execution(owner, approval_id, digest)
            if current['phase'] == 'dispatching':
                self.approvals.mark_uncertain(owner, approval_id, digest, execution['operation_id'])
            raise CommandDispatchUnavailable('original command cancellation unknown; reconcile original receipt') from exc
