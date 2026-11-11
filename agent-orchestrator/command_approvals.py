"""Typed durable command review/consumption; no transport or project execution.

Only trusted review/dispatch handlers may call review/claim. These methods do
not independently prove a human identity or current execute permissions.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from contextlib import contextmanager

from approvals import ApprovalConflict, HEX_DIGEST, SUBMISSION_ID
from run_jobs import PRINCIPAL_ID, WORKSPACE_ID

MAX_COMMAND_APPROVALS = 1024


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def manifest_digest(inputs):
    """Go encoding/json commandInput field order, including HTML/line escapes."""
    ordered = [dict(path=item['path'], size_bytes=item['size_bytes'], sha256=item['sha256']) for item in inputs]
    encoded = json.dumps(ordered, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    for value, escape in (('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'), ('\u2028', '\\u2028'), ('\u2029', '\\u2029')):
        encoded = encoded.replace(value, escape)
    return hashlib.sha256(b'nexus.command.inputs.v1\0' + encoded.encode('utf-8')).hexdigest()


def valid_id(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def safe_path(value):
    return (isinstance(value, str) and 0 < len(value.encode('utf-8')) <= 512 and
            not value.startswith('/') and not any(c in value for c in '\\\x00\r\n') and
            len(value.split('/')) <= 12 and all(part and not part.startswith('.') and
                len(part.encode('utf-8')) <= 255 for part in value.split('/')))


def validate_proposal(owner, proposal):
    fields = {'kind', 'host', 'workspace_id', 'workspace_generation', 'snapshot_id', 'profile_id',
              'profile_version', 'input_digest', 'inputs', 'expires_at', 'invocation'}
    if (not valid_id(owner, PRINCIPAL_ID) or not isinstance(proposal, dict) or set(proposal) != fields or
            proposal['kind'] != 'command' or proposal['host'] not in ('debian', 'nixos') or
            not valid_id(proposal['workspace_id'], WORKSPACE_ID) or
            not valid_id(proposal['workspace_generation'], HEX_DIGEST) or
            not valid_id(proposal['snapshot_id'], SUBMISSION_ID) or
            not valid_id(proposal['profile_id'], WORKSPACE_ID) or
            not valid_id(proposal['profile_version'], HEX_DIGEST) or
            not valid_id(proposal['input_digest'], HEX_DIGEST) or
            type(proposal['expires_at']) is not int or proposal['expires_at'] <= 0):
        raise ValueError('invalid typed command proposal')
    inputs = proposal['inputs']
    if not isinstance(inputs, list) or len(inputs) > 128:
        raise ValueError('invalid command manifest')
    total, previous = 0, ''
    for item in inputs:
        if (not isinstance(item, dict) or set(item) != {'path', 'size_bytes', 'sha256'} or
                not safe_path(item['path']) or item['path'] <= previous or
                type(item['size_bytes']) is not int or not 0 <= item['size_bytes'] <= 65536 or
                not valid_id(item['sha256'], HEX_DIGEST)):
            raise ValueError('invalid command manifest entry')
        previous = item['path']
        total += item['size_bytes']
    if total > 1048576 or manifest_digest(inputs) != proposal['input_digest']:
        raise ValueError('command manifest digest mismatch')
    invocation = proposal['invocation']
    if not isinstance(invocation, dict) or set(invocation) != {'executable', 'arguments', 'limits'}:
        raise ValueError('invalid fixed command invocation')
    program, arguments, limits = invocation['executable'], invocation['arguments'], invocation['limits']
    if (not isinstance(program, str) or not program.startswith('/') or len(program.encode()) > 4096 or
            any(c in program for c in '\x00\r\n') or any(part in ('', '.', '..') for part in program[1:].split('/')) or
            not isinstance(arguments, list) or len(arguments) > 64 or
            any(not isinstance(arg, str) or '\x00' in arg for arg in arguments) or
            sum(len(arg.encode('utf-8')) for arg in arguments) > 8192):
        raise ValueError('invalid fixed command invocation')
    bounds = {'timeout_ms': (1, 30000), 'memory_bytes': (16 << 20, 512 << 20),
              'address_space_bytes': (16 << 20, 16 << 30), 'processes': (1, 32),
              'cpu_seconds': (1, 10), 'scratch_bytes': (4096, 16 << 20), 'output_bytes': (1, 65536)}
    if (not isinstance(limits, dict) or set(limits) != set(bounds) or
            any(type(limits[key]) is not int or not low <= limits[key] <= high for key, (low, high) in bounds.items()) or
            limits['memory_bytes'] % 4096 or limits['address_space_bytes'] < limits['memory_bytes']):
        raise ValueError('invalid command limits')
    return canonical(proposal)


class CommandApprovals:
    """A separate table namespace prevents edit approvals becoming commands."""
    def __init__(self, runs):
        self.runs = runs
        with runs.lock:
            runs.db.execute('''CREATE TABLE IF NOT EXISTS command_approvals (
                id TEXT PRIMARY KEY,owner TEXT NOT NULL,digest TEXT NOT NULL,proposal TEXT NOT NULL,
                host TEXT NOT NULL,snapshot_id TEXT NOT NULL,submission_id TEXT NOT NULL,
                origin TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,status TEXT NOT NULL,
                updated REAL NOT NULL,UNIQUE(owner,submission_id),UNIQUE(host,snapshot_id))''')
            runs.db.execute('''CREATE TABLE IF NOT EXISTS command_executions (
                approval_id TEXT PRIMARY KEY,owner TEXT NOT NULL,digest TEXT NOT NULL,
                operation_id TEXT NOT NULL UNIQUE,phase TEXT NOT NULL,receipt TEXT,
                receipt_sha256 TEXT,created REAL NOT NULL,updated REAL NOT NULL)''')
            # A durable owner-bound cancellation intent is recorded *before*
            # contacting the host. Retry may send the same cancellation but
            # must never allocate another execution or dispatch new code.
            runs.db.execute('''CREATE TABLE IF NOT EXISTS command_cancellations (
                approval_id TEXT PRIMARY KEY,owner TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,
                requested REAL NOT NULL)''')

    @contextmanager
    def transaction(self):
        with self.runs.lock:
            self.runs.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self.runs.db.execute('COMMIT')
            except BaseException:
                self.runs.db.execute('ROLLBACK')
                raise

    def get(self, owner, approval_id):
        if not valid_id(owner, PRINCIPAL_ID):
            raise ValueError('invalid command owner')
        if not valid_id(approval_id, SUBMISSION_ID):
            return None
        with self.runs.lock:
            row = self.runs.db.execute('SELECT digest,proposal,host,snapshot_id,submission_id,origin,created,expires,status,updated '
                'FROM command_approvals WHERE id=? AND owner=?', (approval_id, owner)).fetchone()
        if row is None:
            return None
        proposal = json.loads(row[1])
        if (validate_proposal(owner, proposal) != row[1] or hashlib.sha256(row[1].encode()).hexdigest() != row[0] or
                row[2] != proposal['host'] or row[3] != proposal['snapshot_id'] or
                not valid_id(row[4], SUBMISSION_ID) or row[5] not in ('manual', 'agent') or
                row[7] != proposal['expires_at'] or row[8] not in ('pending', 'approved', 'rejected', 'executing')):
            raise ApprovalConflict('stored command approval integrity failure')
        return dict(id=approval_id, digest=row[0], proposal=proposal, submission_id=row[4], origin=row[5],
                    created_at=row[6], expires_at=row[7], status=row[8], updated_at=row[9])

    def get_submission(self, owner, submission_id):
        if not valid_id(owner, PRINCIPAL_ID) or not valid_id(submission_id, SUBMISSION_ID):
            raise ValueError('invalid command submission identity')
        with self.runs.lock:
            row = self.runs.db.execute('SELECT id FROM command_approvals WHERE owner=? AND submission_id=?',
                                      (owner, submission_id)).fetchone()
            return self.get(owner, row[0]) if row else None

    def list_scope(self, owner, host, workspace_id):
        if not valid_id(owner, PRINCIPAL_ID) or host not in ('debian', 'nixos') or not valid_id(workspace_id, WORKSPACE_ID):
            raise ValueError('invalid command review scope')
        with self.runs.lock:
            ids = self.runs.db.execute('SELECT id FROM command_approvals WHERE owner=? AND host=? ORDER BY created DESC LIMIT ?',
                                      (owner, host, MAX_COMMAND_APPROVALS)).fetchall()
            result = []
            for (approval_id,) in ids:
                item = self.get(owner, approval_id)
                proposal = item['proposal']
                if proposal['workspace_id'] != workspace_id:
                    continue
                metadata = {key: item[key] for key in ('id', 'digest', 'origin', 'created_at', 'expires_at', 'status')}
                metadata.update({key: proposal[key] for key in ('profile_id', 'snapshot_id', 'input_digest')})
                execution = self.get_execution(owner, approval_id, item['digest'])
                if execution is not None:
                    metadata['execution_phase'] = execution['phase']
                result.append(metadata)
                if len(result) == 100:
                    break
            return result

    def propose(self, owner, proposal, submission_id, *, origin='manual'):
        encoded = validate_proposal(owner, proposal)
        if not valid_id(submission_id, SUBMISSION_ID) or origin not in ('manual', 'agent'):
            raise ValueError('invalid command submission identity')
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with self.transaction():
            old = self.runs.db.execute('SELECT id FROM command_approvals WHERE owner=? AND submission_id=?',
                                      (owner, submission_id)).fetchone()
            if old:
                item = self.get(owner, old[0])
                if item['digest'] != digest or item['origin'] != origin:
                    raise ApprovalConflict('command submission cannot change contents or origin')
                return item
            now = time.time()
            if not now < proposal['expires_at'] <= now + 300:
                raise ValueError('command snapshot must be current and expire within five minutes')
            if self.runs.db.execute('SELECT COUNT(*) FROM command_approvals').fetchone()[0] >= MAX_COMMAND_APPROVALS:
                raise OverflowError('command history capacity reached')
            if self.runs.db.execute('SELECT id FROM command_approvals WHERE host=? AND snapshot_id=?',
                                   (proposal['host'], proposal['snapshot_id'])).fetchone():
                raise ApprovalConflict('command snapshot is already proposed')
            approval_id = uuid.uuid4().hex
            self.runs.db.execute('INSERT INTO command_approvals VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                (approval_id, owner, digest, encoded, proposal['host'], proposal['snapshot_id'], submission_id,
                 origin, now, proposal['expires_at'], 'pending', now))
        return self.get(owner, approval_id)

    def review(self, owner, approval_id, digest, decision):
        if decision not in ('approve', 'reject'):
            raise ValueError('invalid command review decision')
        with self.transaction():
            item = self.get(owner, approval_id)
            if item is None or item['digest'] != digest or item['status'] != 'pending' or item['expires_at'] <= time.time():
                return False
            self.runs.db.execute('UPDATE command_approvals SET status=?,updated=? WHERE id=?',
                ('approved' if decision == 'approve' else 'rejected', time.time(), approval_id))
            return True

    def get_execution(self, owner, approval_id, digest):
        with self.runs.lock:
            item = self.get(owner, approval_id)
            if item is None or item['digest'] != digest:
                return None
            row = self.runs.db.execute('SELECT digest,operation_id,phase,receipt,receipt_sha256,created,updated '
                'FROM command_executions WHERE approval_id=? AND owner=?', (approval_id, owner)).fetchone()
        if row is None:
            return None
        if (row[0] != digest or not valid_id(row[1], SUBMISSION_ID) or item['status'] != 'executing' or
                row[2] not in ('prepared', 'dispatching', 'uncertain', 'completed', 'interrupted') or
                (row[3] is None) != (row[4] is None) or
                (row[3] is not None and hashlib.sha256(row[3].encode()).hexdigest() != row[4])):
            raise ApprovalConflict('stored command execution integrity failure')
        receipt = json.loads(row[3]) if row[3] is not None else None
        if (row[2] in ('completed', 'interrupted')) != (row[3] is not None):
            raise ApprovalConflict('command terminal receipt missing or premature')
        if row[3] is not None:
            try:
                validate_receipt(owner, item, row[1], receipt)
                if canonical(receipt) != row[3] or receipt['status'] != row[2]:
                    raise ValueError('noncanonical receipt')
            except (ValueError, TypeError, UnicodeError) as exc:
                raise ApprovalConflict('stored command receipt integrity failure') from exc
        return dict(approval_id=approval_id, digest=digest, operation_id=row[1], phase=row[2], receipt=receipt,
                    created_at=row[5], updated_at=row[6],
                    cancel_requested=self.cancel_requested(owner, approval_id, row[1]))

    def cancel_requested(self, owner, approval_id, operation_id):
        with self.runs.lock:
            row = self.runs.db.execute('SELECT owner,operation_id FROM command_cancellations WHERE approval_id=?',
                                       (approval_id,)).fetchone()
            if row is None:
                return False
            if row != (owner, operation_id):
                raise ApprovalConflict('stored command cancel identity mismatch')
            return True

    def request_cancel(self, owner, approval_id, digest):
        with self.transaction():
            execution = self.get_execution(owner, approval_id, digest)
            if execution is None or execution['phase'] not in ('dispatching', 'uncertain'):
                raise ApprovalConflict('only a dispatched command may request host cancellation')
            self.runs.db.execute('INSERT OR IGNORE INTO command_cancellations VALUES(?,?,?,?)',
                (approval_id, owner, execution['operation_id'], time.time()))
            # Verify existing rows, including a corrupt/rebound operation ID.
            if not self.cancel_requested(owner, approval_id, execution['operation_id']):
                raise ApprovalConflict('command cancellation could not be recorded')
            return self.get_execution(owner, approval_id, digest)

    def withdraw(self, owner, approval_id, digest):
        """Cancel an unexecuted explicitly reviewed proposal (manual or agent).

        Rejection is terminal and cannot be upgraded or sent later. All state
        checks occur inside one SQLite write transaction.
        """
        with self.transaction():
            item = self.get(owner, approval_id)
            if item is None or item['digest'] != digest or item['origin'] not in ('manual', 'agent'):
                raise ApprovalConflict('command withdrawal requires exact approved review')
            if item['status'] == 'rejected':
                return item
            if item['status'] not in ('pending', 'approved') or self.get_execution(owner, approval_id, digest) is not None:
                raise ApprovalConflict('command execution already consumed or review terminal')
            self.runs.db.execute('UPDATE command_approvals SET status=?,updated=? WHERE id=?',
                ('rejected', time.time(), approval_id))
            return self.get(owner, approval_id)

    def claim(self, owner, approval_id, digest):
        """Caller must verify a human decision/current execute grants first."""
        with self.transaction():
            existing = self.get_execution(owner, approval_id, digest)
            if existing is not None:
                return existing
            item = self.get(owner, approval_id)
            if item is None or item['digest'] != digest or item['status'] != 'approved' or item['expires_at'] <= time.time():
                raise ApprovalConflict('current exact command approval required')
            now = time.time()
            self.runs.db.execute('UPDATE command_approvals SET status=?,updated=? WHERE id=?', ('executing', now, approval_id))
            self.runs.db.execute('INSERT INTO command_executions VALUES(?,?,?,?,?,?,?,?,?)',
                (approval_id, owner, digest, uuid.uuid4().hex, 'prepared', None, None, now, now))
            return self.get_execution(owner, approval_id, digest)

    def start_dispatch(self, owner, approval_id, digest, operation_id):
        with self.transaction():
            execution = self.get_execution(owner, approval_id, digest)
            item = self.get(owner, approval_id)
            if execution is None or execution['operation_id'] != operation_id:
                raise ApprovalConflict('command operation identity changed')
            if item['expires_at'] <= time.time() or execution['phase'] != 'prepared':
                return False
            self.runs.db.execute('UPDATE command_executions SET phase=?,updated=? WHERE approval_id=?',
                                 ('dispatching', time.time(), approval_id))
            return True

    def mark_uncertain(self, owner, approval_id, digest, operation_id):
        with self.transaction():
            execution = self.get_execution(owner, approval_id, digest)
            if execution is None or execution['operation_id'] != operation_id or execution['phase'] not in ('dispatching', 'uncertain'):
                raise ApprovalConflict('command has not been dispatched or is already terminal')
            self.runs.db.execute('UPDATE command_executions SET phase=?,updated=? WHERE approval_id=?',
                                 ('uncertain', time.time(), approval_id))
            return self.get_execution(owner, approval_id, digest)

    def finish(self, owner, approval_id, digest, operation_id, receipt):
        with self.transaction():
            execution = self.get_execution(owner, approval_id, digest)
            item = self.get(owner, approval_id)
            if execution is None or execution['operation_id'] != operation_id:
                raise ApprovalConflict('command operation identity changed')
            validate_receipt(owner, item, operation_id, receipt)
            encoded = canonical(receipt)
            if execution['phase'] in ('completed', 'interrupted'):
                if execution['receipt'] != receipt:
                    raise ApprovalConflict('terminal command outcome cannot change')
                return execution
            if execution['phase'] not in ('dispatching', 'uncertain'):
                raise ApprovalConflict('command was not dispatched')
            self.runs.db.execute('UPDATE command_executions SET phase=?,receipt=?,receipt_sha256=?,updated=? WHERE approval_id=?',
                (receipt['status'], encoded, hashlib.sha256(encoded.encode()).hexdigest(), time.time(), approval_id))
            return self.get_execution(owner, approval_id, digest)


def validate_receipt(owner, item, operation_id, receipt):
    """Strict host receipt shape/binding. Dispatcher must also match saved lease."""
    proposal = item['proposal']
    expected = {key: proposal[key] for key in ('host', 'workspace_id', 'workspace_generation', 'snapshot_id',
                                             'profile_id', 'profile_version', 'input_digest')}
    expected.update(owner=owner, approval_id=item['id'], digest=item['digest'], operation_id=operation_id)
    if (not isinstance(receipt, dict) or set(receipt) - {'request', 'status', 'result', 'failure'} or
            not isinstance(receipt.get('request'), dict) or set(receipt['request']) != set(expected) | {'expires_at'} or
            any(receipt['request'][key] != value for key, value in expected.items()) or
            type(receipt['request']['expires_at']) is not int or
            not 0 < receipt['request']['expires_at'] <= item['expires_at']):
        raise ValueError('command receipt binding mismatch')
    if receipt.get('status') == 'interrupted':
        if 'result' in receipt or receipt.get('failure') != 'exit_unknown':
            raise ValueError('interrupted command cannot report an exit result')
        return
    if receipt.get('status') != 'completed' or not isinstance(receipt.get('result'), dict):
        raise ValueError('invalid command receipt status')
    result = receipt['result']
    result_binding = {key: proposal[key] for key in ('profile_id', 'profile_version', 'input_digest', 'workspace_generation', 'snapshot_id')}
    if (set(result) != set(result_binding) | {'stdout', 'stderr', 'exit_code', 'truncated', 'timed_out', 'cancelled'} or
            any(result[key] != value for key, value in result_binding.items()) or
            type(result['exit_code']) is not int or not -1 <= result['exit_code'] <= 255 or
            any(type(result[key]) is not bool for key in ('truncated', 'timed_out', 'cancelled')) or
            any(not isinstance(result[key], str) for key in ('stdout', 'stderr')) or
            len(result['stdout'].encode('utf-8')) + len(result['stderr'].encode('utf-8')) > 65536 or
            receipt.get('failure', '') not in ('', 'execution_failed') or
            (not receipt.get('failure') and any(result[key] for key in ('truncated', 'timed_out', 'cancelled')))):
        raise ValueError('invalid command execution result')
