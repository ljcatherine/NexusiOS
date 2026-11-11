"""Durable single-use patch execution claims; does not perform filesystem writes.

A claim must be persisted before dispatch. Once dispatched, a missing reply is
ambiguous: callers must reconcile against a bridge receipt, never dispatch again
merely because an HTTP client timed out or this process restarted.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid

from approvals import HEX_DIGEST, SUBMISSION_ID
from run_jobs import PRINCIPAL_ID


class ExecutionConflict(Exception):
    """The approval/operation identity or durable execution phase does not match."""


class PatchExecutionStore:
    def __init__(self, approvals):
        self.approvals = approvals
        self.runs = approvals.runs
        with self.runs.lock:
            self.runs.db.execute("""CREATE TABLE IF NOT EXISTS patch_executions (
                approval_id TEXT PRIMARY KEY, owner TEXT NOT NULL,
                digest TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
                replacement_sha256 TEXT NOT NULL, phase TEXT NOT NULL,
                result_sha256 TEXT, created REAL NOT NULL, updated REAL NOT NULL
            )""")

    @staticmethod
    def _identity(owner, approval_id, digest):
        if (not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner) or
                not isinstance(approval_id, str) or not SUBMISSION_ID.fullmatch(approval_id) or
                not isinstance(digest, str) or not HEX_DIGEST.fullmatch(digest)):
            raise ValueError("invalid patch execution identity")

    def get(self, owner, approval_id, digest):
        self._identity(owner, approval_id, digest)
        with self.runs.lock:
            approval = self.approvals.get(owner, approval_id)
            if approval is None or not hmac.compare_digest(approval['digest'], digest):
                return None
            row = self.runs.db.execute(
                "SELECT digest,operation_id,replacement_sha256,phase,result_sha256,created,updated "
                "FROM patch_executions WHERE approval_id=? AND owner=?", (approval_id, owner)).fetchone()
            if row is None:
                return None
            expected = hashlib.sha256(approval['proposal']['replacement'].encode('utf-8')).hexdigest()
            if (not hmac.compare_digest(row[0], digest) or row[2] != expected or
                    not SUBMISSION_ID.fullmatch(row[1]) or
                    row[3] not in ('prepared', 'dispatching', 'applied', 'conflict', 'failed', 'uncertain') or
                    (row[4] is not None and not HEX_DIGEST.fullmatch(row[4])) or
                    (row[3] == 'applied' and row[4] != expected) or approval['status'] != 'executing'):
                raise ExecutionConflict("stored execution record integrity check failed")
            return {'approval_id': approval_id, 'operation_id': row[1], 'digest': digest,
                    'replacement_sha256': row[2], 'phase': row[3], 'result_sha256': row[4],
                    'created_at': row[5], 'updated_at': row[6]}

    def claim(self, owner, approval_id, digest):
        """Consume one approved snapshot and allocate its immutable operation ID.

        The caller must check current write permissions before calling this API.
        Existing claims retain their identity after expiry/restart. Only a new,
        currently approved and unexpired record can create a claim.
        """
        self._identity(owner, approval_id, digest)
        with self.runs.lock:
            self.runs.db.execute('BEGIN IMMEDIATE')
            try:
                existing = self.get(owner, approval_id, digest)
                if existing is not None:
                    self.runs.db.execute('COMMIT')
                    return existing
                approval = self.approvals.get(owner, approval_id)
                now = time.time()
                if (approval is None or not hmac.compare_digest(approval['digest'], digest) or
                        approval['status'] != 'approved' or approval['expires_at'] <= now):
                    raise ExecutionConflict('a current exact approved snapshot is required')
                operation = uuid.uuid4().hex
                expected = hashlib.sha256(approval['proposal']['replacement'].encode('utf-8')).hexdigest()
                cursor = self.runs.db.execute(
                    "UPDATE approvals SET status='executing',updated=? WHERE id=? AND owner=? "
                    "AND digest=? AND status='approved' AND expires>?", (now, approval_id, owner, digest, now))
                if cursor.rowcount != 1:
                    raise ExecutionConflict('approval was already consumed')
                self.runs.db.execute('INSERT INTO patch_executions VALUES(?,?,?,?,?,?,?,?,?)',
                    (approval_id, owner, digest, operation, expected, 'prepared', None, now, now))
                item = self.get(owner, approval_id, digest)
                self.runs.db.execute('COMMIT')
                return item
            except BaseException:
                self.runs.db.execute('ROLLBACK')
                raise

    def start_dispatch(self, owner, approval_id, digest, operation_id):
        """Only one caller may cross the side-effect boundary, including retries."""
        with self.runs.lock:
            item = self.get(owner, approval_id, digest)
            if item is None or item['operation_id'] != operation_id:
                raise ExecutionConflict('patch operation identity does not match')
            approval = self.approvals.get(owner, approval_id)
            if approval['expires_at'] <= time.time():
                return False
            changed = self.runs.db.execute(
                "UPDATE patch_executions SET phase='dispatching',updated=? WHERE approval_id=? "
                "AND owner=? AND digest=? AND operation_id=? AND phase='prepared'",
                (time.time(), approval_id, owner, digest, operation_id)).rowcount
            return changed == 1

    def finish(self, owner, approval_id, digest, operation_id, phase, result_sha256=None):
        """Record a validated bridge receipt. Unknown outcomes never imply success.

        An uncertain operation can only become final through receipt reconciliation;
        it cannot be dispatched again. This method never grants permission to retry.
        """
        if phase not in ('applied', 'conflict', 'failed', 'uncertain'):
            raise ValueError('unsupported patch execution outcome')
        if result_sha256 is not None and (not isinstance(result_sha256, str) or not HEX_DIGEST.fullmatch(result_sha256)):
            raise ValueError('invalid patch execution hash')
        with self.runs.lock:
            item = self.get(owner, approval_id, digest)
            if item is None or item['operation_id'] != operation_id:
                raise ExecutionConflict('patch operation identity does not match')
            if phase == 'applied' and result_sha256 != item['replacement_sha256']:
                raise ExecutionConflict('applied receipt does not match the approved replacement')
            if phase == 'uncertain' and result_sha256 is not None:
                raise ValueError('uncertain execution cannot report a file hash')
            if item['phase'] == phase and item['result_sha256'] == result_sha256:
                return item
            allowed = ('dispatching', 'uncertain') if phase != 'uncertain' else ('dispatching',)
            if item['phase'] not in allowed:
                raise ExecutionConflict('execution outcome is already final or was not dispatched')
            self.runs.db.execute(
                'UPDATE patch_executions SET phase=?,result_sha256=?,updated=? WHERE approval_id=? AND owner=?',
                (phase, result_sha256, time.time(), approval_id, owner))
            return self.get(owner, approval_id, digest)
