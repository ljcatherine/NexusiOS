"""Private approved-patch dispatch with durable exact requests and no blind retries."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import struct
import time
from urllib.parse import urlsplit

from approvals import HEX_DIGEST
from patch_execution import ExecutionConflict, PatchExecutionStore


class PatchDispatchUnavailable(Exception):
    """An execution cannot be safely started or reconciled with current evidence."""


def patch_binding(payload):
    fields = ('host', 'workspace_id', 'owner', 'approval_id', 'digest', 'operation_id',
              'path', 'base_sha256', 'replacement', 'replacement_sha256', 'expires_at', 'workspace_generation')
    result = b'nexus.workspace.patch.v2\0'
    for field in fields:
        data = str(payload[field]).encode('utf-8')
        result += struct.pack('!I', len(data)) + data
    return result


def patch_proof(payload, key):
    return hmac.new(key.encode('utf-8'), patch_binding(payload), hashlib.sha256).hexdigest()


class PatchDispatcher:
    def __init__(self, controller, approvals):
        self.controller, self.approvals = controller, approvals
        self.executions = PatchExecutionStore(approvals)
        self.runs = approvals.runs
        with self.runs.lock:
            self.runs.db.execute('''CREATE TABLE IF NOT EXISTS patch_dispatch_requests (
                approval_id TEXT PRIMARY KEY, owner TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
                digest TEXT NOT NULL, body TEXT NOT NULL, checksum TEXT NOT NULL)''')

    def _configuration(self, host):
        token = getattr(self.controller, 'workspace_executor_tokens', {}).get(host)
        if not isinstance(token, str) or not 32 <= len(token) <= 256 or any(ord(c) <= 32 or ord(c) >= 127 for c in token):
            raise PatchDispatchUnavailable('workspace executor is not configured')
        configured = [value for value in getattr(self.controller, 'workspace_executor_tokens', {}).values() if value]
        if len(set(configured)) != len(configured):
            raise PatchDispatchUnavailable('host executor credentials must be distinct')
        read_bridge = self.controller.workspaces.get(host)
        if read_bridge is None:
            raise PatchDispatchUnavailable('workspace bridge is not configured')
        base = read_bridge[0]
        url = urlsplit(base)
        # Never send execution authority across cleartext LAN ingress. Loopback
        # may be carried by the existing authenticated SSH reverse tunnel.
        if url.scheme != 'https':
            try:
                local = url.scheme == 'http' and ipaddress.ip_address(url.hostname).is_loopback
            except ValueError:
                local = False
            if not local:
                raise PatchDispatchUnavailable('executor requires HTTPS or a loopback tunnel')
        forbidden = [self.controller.token, self.controller.review_token, self.controller.control_token,
                     *(value[1] for value in self.controller.workspaces.values())]
        if token in forbidden:
            raise PatchDispatchUnavailable('executor credential must be separate')
        return base, token

    def _approval(self, owner, approval_id, digest):
        item = self.approvals.get(owner, approval_id)
        if item is None or item['digest'] != digest:
            raise ExecutionConflict('exact owned approval is required')
        proposal = item['proposal']
        generation = proposal.get('workspace_generation')
        if not isinstance(generation, str) or not HEX_DIGEST.fullmatch(generation):
            raise PatchDispatchUnavailable('legacy proposals cannot execute')
        return item

    def _current_root(self, proposal):
        roots = self.controller.list_workspace(proposal['host'])['workspaces']
        selected = next((root for root in roots if root['id'] == proposal['workspace_id']), None)
        if (selected is None or selected.get('read_only') is not False or
                'apply_patch' not in selected.get('capabilities', []) or
                selected.get('generation') != proposal['workspace_generation']):
            raise PatchDispatchUnavailable('managed workspace identity changed or is unavailable')

    def _saved_request(self, owner, item, claim, key):
        proposal = item['proposal']
        fields = dict(host=proposal['host'], workspace_id=proposal['workspace_id'], owner=owner,
            approval_id=item['id'], digest=item['digest'], operation_id=claim['operation_id'],
            path=proposal['path'], base_sha256=proposal['base_sha256'], replacement=proposal['replacement'],
            replacement_sha256=claim['replacement_sha256'], workspace_generation=proposal['workspace_generation'])
        with self.runs.lock:
            row = self.runs.db.execute('SELECT owner,operation_id,digest,body,checksum FROM patch_dispatch_requests '
                                      'WHERE approval_id=?', (item['id'],)).fetchone()
            if row is not None:
                if (len(row[3].encode()) > 512 * 1024 or row[:3] != (owner, claim['operation_id'], item['digest']) or
                        hashlib.sha256(row[3].encode()).hexdigest() != row[4]):
                    raise ExecutionConflict('saved dispatch identity or checksum mismatch')
                payload = json.loads(row[3])
                if (set(payload) != set(fields) | {'expires_at', 'proof'} or
                        any(payload[name] != value for name, value in fields.items()) or
                        type(payload['expires_at']) is not int or not 0 < payload['expires_at'] <= int(item['expires_at']) or
                        not isinstance(payload['proof'], str) or not hmac.compare_digest(payload['proof'], patch_proof(payload, key))):
                    raise ExecutionConflict('saved dispatch binding mismatch')
                return payload
            payload = {**fields, 'expires_at': min(int(item['expires_at']), int(time.time()) + 30)}
            payload['proof'] = patch_proof(payload, key)
            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
            self.runs.db.execute('INSERT INTO patch_dispatch_requests VALUES(?,?,?,?,?,?)',
                (item['id'], owner, claim['operation_id'], item['digest'], encoded, hashlib.sha256(encoded.encode()).hexdigest()))
            return payload

    def _receipt(self, owner, item, claim, receipt):
        proposal = item['proposal']
        expected = dict(host=proposal['host'], workspace_id=proposal['workspace_id'], approval_id=item['id'],
                        digest=item['digest'], operation_id=claim['operation_id'])
        if (not isinstance(receipt, dict) or any(receipt.get(k) != v for k, v in expected.items()) or
                set(receipt) - (set(expected) | {'status', 'sha256'}) or
                receipt.get('status') not in ('applied', 'conflict', 'failed', 'uncertain')):
            raise PatchDispatchUnavailable('invalid executor receipt')
        status, result = receipt['status'], receipt.get('sha256')
        if status == 'applied':
            if result != claim['replacement_sha256']:
                raise PatchDispatchUnavailable('executor receipt hash mismatch')
        elif result is not None:
            raise PatchDispatchUnavailable('unexpected executor result hash')
        return self.executions.finish(owner, item['id'], item['digest'], claim['operation_id'], status, result)

    def apply(self, owner, approval_id, digest, *, cancelled=None):
        if cancelled is not None and cancelled():
            raise InterruptedError('patch dispatch cancelled before starting')
        item = self._approval(owner, approval_id, digest)
        proposal = item['proposal']
        base, key = self._configuration(proposal['host'])
        self._current_root(proposal)
        if not self.controller.authorize_workspace_operation(owner, proposal, 'apply'):
            raise PermissionError('workspace write permission denied')
        if cancelled is not None and cancelled():
            raise InterruptedError('patch dispatch cancelled before claim')
        claim = self.executions.claim(owner, approval_id, digest)
        if claim['phase'] in ('applied', 'conflict', 'failed'):
            return claim
        payload = self._saved_request(owner, item, claim, key)
        if claim['phase'] != 'prepared':
            return self.reconcile(owner, approval_id, digest)
        if payload['expires_at'] <= time.time():
            raise PatchDispatchUnavailable('prepared execution lease expired before dispatch')
        # This is deliberately uncached and immediately precedes the once-only
        # dispatch claim. The host rechecks lease/root before its commit permit.
        if not self.controller.authorize_workspace_operation(owner, proposal, 'apply'):
            raise PermissionError('workspace write permission denied')
        with self.runs.lock:
            if cancelled is not None and cancelled():
                raise InterruptedError('patch dispatch cancelled before mutation boundary')
            started = self.executions.start_dispatch(owner, approval_id, digest, claim['operation_id'])
        if not started:
            return self.reconcile(owner, approval_id, digest)
        try:
            receipt = self.controller.http_json(base, '/workspaces/' + proposal['workspace_id'] + '/patches/apply',
                key, 'POST', payload, timeout=16)
            return self._receipt(owner, item, claim, receipt)
        except Exception as exc:
            self.executions.finish(owner, approval_id, digest, claim['operation_id'], 'uncertain')
            # Do not retry the mutation or expose URLs/response bodies/tokens.
            raise PatchDispatchUnavailable('execution outcome requires receipt reconciliation') from exc

    def reconcile(self, owner, approval_id, digest):
        item = self._approval(owner, approval_id, digest)
        proposal = item['proposal']
        base, key = self._configuration(proposal['host'])
        self._current_root(proposal)
        claim = self.executions.get(owner, approval_id, digest)
        if claim is None:
            raise ExecutionConflict('no saved execution exists')
        if claim['phase'] in ('applied', 'conflict', 'failed'):
            return claim
        if claim['phase'] == 'prepared':
            return claim
        payload = self._saved_request(owner, item, claim, key)
        try:
            receipt = self.controller.http_json(base, '/workspaces/' + proposal['workspace_id'] + '/patches/receipts/' +
                claim['operation_id'] + '/reconcile', key, 'POST', payload, timeout=16)
            return self._receipt(owner, item, claim, receipt)
        except Exception as exc:
            raise PatchDispatchUnavailable('execution receipt is not yet verified') from exc
