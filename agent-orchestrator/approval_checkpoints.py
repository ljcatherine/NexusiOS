"""Durable model safe boundaries. No filesystem dispatch or implicit application."""
from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor


class WaitingForApproval(Exception):
    """Unwind inference capacity after the continuation has been persisted."""


class ApprovalCheckpoints:
    def __init__(self, runs, controller):
        from patch_review import PatchReview
        from patch_execution import PatchExecutionStore
        from command_review import CommandReview
        self.runs, self.controller = runs, controller
        self.review = PatchReview(controller, runs)
        self.executions = PatchExecutionStore(self.review.store)
        self.command_review = CommandReview(controller, runs)
        self.command_dispatcher = self.command_review.dispatcher
        from patch_dispatch import PatchDispatcher
        self.dispatcher = PatchDispatcher(controller, self.review.store)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="nexus-patch-dispatch")
        self.futures, self.retry_at = {}, {}
        self.command_retry_at = {}
        self.closed = False
        with runs.lock:
            runs.db.execute('''CREATE TABLE IF NOT EXISTS approval_checkpoints (
                run_id TEXT NOT NULL, step INTEGER NOT NULL, owner TEXT NOT NULL,
                snapshot TEXT NOT NULL, checksum TEXT NOT NULL,
                approval_id TEXT, digest TEXT, outcome TEXT,
                PRIMARY KEY(run_id,step))''')

    def latest(self, run_id, owner):
        with self.runs.lock:
            if self.runs.get_owned(run_id, owner) is None:
                return None
            row = self.runs.db.execute(
                'SELECT step,snapshot,checksum,approval_id,digest,outcome FROM approval_checkpoints '
                'WHERE run_id=? AND owner=? ORDER BY step DESC LIMIT 1', (run_id, owner)).fetchone()
            if row is None:
                return None
            if hashlib.sha256(row[1].encode()).hexdigest() != row[2]:
                raise ValueError('checkpoint integrity failure')
            state = json.loads(row[1])
            request = json.loads(self.runs.execution_request(run_id)[1])
            if state['workspace'] != request['workspace'] or request.get('allow_proposals') is not True:
                raise ValueError('checkpoint workspace mismatch')
            return dict(step=row[0], state=state, approval_id=row[3], digest=row[4],
                        outcome=json.loads(row[5]) if row[5] else None)

    def suspend(self, run_id, owner, state):
        """Persist exact model output before creating even the approval record."""
        step = state['step']
        encoded = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        checksum = hashlib.sha256(encoded.encode()).hexdigest()
        with self.runs.lock:
            record = self.runs.get_owned(run_id, owner)
            if record is None or record['cancel_requested'] or record['status'] in ('cancelled', 'failed', 'completed'):
                raise InterruptedError('cancelled')
            prior = self.runs.db.execute('SELECT checksum FROM approval_checkpoints WHERE run_id=? AND step=?',
                                         (run_id, step)).fetchone()
            if prior and prior[0] != checksum:
                raise ValueError('immutable checkpoint conflict')
            self.runs.db.execute('INSERT OR IGNORE INTO approval_checkpoints VALUES(?,?,?,?,?,?,?,?)',
                                (run_id, step, owner, encoded, checksum, None, None, None))
        self.publish(run_id, owner)
        raise WaitingForApproval()

    def publish(self, run_id, owner):
        cp = self.latest(run_id, owner)
        state = cp['state']
        workspace = state['workspace']
        action = state['action']
        command = action['action'] == 'propose_command'
        # Deliberately uncached, including recovery of a saved proposal.
        if not self.controller.authorize_workspace_operation(owner, workspace, 'execute' if command else 'propose'):
            raise PermissionError('proposal authorization denied')
        submission_id = hashlib.sha256(f'nexus-{"command" if command else "proposal"}:{run_id}:{cp["step"]}'.encode()).hexdigest()[:32]
        if command:
            item = self.command_dispatcher.prepare_proposal(owner, workspace['host'],
                workspace['workspace_id'], action['profile_id'], submission_id, origin='agent')
        else:
            item = self.review.propose(owner, workspace['host'], workspace['workspace_id'],
                                       dict(path=action['path'], replacement=action['replacement'], submission_id=submission_id),
                                       origin='agent')
        with self.runs.lock:
            self.runs.db.execute('BEGIN IMMEDIATE')
            try:
                record = self.runs.get_owned(run_id, owner)
                self.runs.db.execute('UPDATE approval_checkpoints SET approval_id=?,digest=? '
                                    'WHERE run_id=? AND step=? AND owner=?',
                                    (item['id'], item['digest'], run_id, cp['step'], owner))
                if record and not record['cancel_requested'] and record['status'] not in ('completed', 'failed', 'cancelled'):
                    self.runs.update(run_id, status='waiting_for_approval', phase=(
                        'waiting for approved command execution' if command else 'waiting for patch review'))
                self.runs.db.execute('COMMIT')
            except BaseException:
                self.runs.db.execute('ROLLBACK')
                raise

    def reconcile(self, run_id, owner):
        cp = self.latest(run_id, owner)
        if cp is None:
            return None
        if cp['approval_id'] is None:
            self.publish(run_id, owner)
            cp = self.latest(run_id, owner)
        if cp['state']['action']['action'] == 'propose_command':
            return self._reconcile_command(run_id, owner, cp)
        item = self.review.store.get(owner, cp['approval_id'])
        workspace = cp['state']['workspace']
        if (item is None or item['digest'] != cp['digest'] or
                (item['proposal']['host'], item['proposal']['workspace_id']) !=
                (workspace['host'], workspace['workspace_id'])):
            raise ValueError('checkpoint approval mismatch')
        action = cp['state']['action']
        if item['proposal']['path'] != action['path'] or item['proposal']['replacement'] != action['replacement']:
            raise ValueError('checkpoint proposal contents mismatch')
        receipt = self.executions.get(owner, item['id'], item['digest'])
        if (item['status'] in ('approved', 'executing') and
                item['proposal'].get('workspace_generation') and
                getattr(self.controller, 'workspace_executor_tokens', {}).get(workspace['host']) and
                (receipt is None or receipt['phase'] in ('prepared', 'dispatching', 'uncertain'))):
            self.drive_execution(run_id, owner, item)
            receipt = self.executions.get(owner, item['id'], item['digest'])
        # Resolve expiry and dispatch state under the same DB lock used by
        # start_dispatch. A stale prepared read must never turn a concurrently
        # dispatched operation into an expired/no-changes tool result.
        with self.runs.lock:
            item = self.review.store.get(owner, cp['approval_id'])
            receipt = self.executions.get(owner, item['id'], item['digest'])
            outcome = None
            if receipt and receipt['phase'] == 'applied':
                outcome = dict(status='applied', digest=item['digest'], result_sha256=receipt['result_sha256'])
            elif item['status'] == 'rejected':
                outcome = dict(status='rejected', changes_applied=False)
            elif item['expires_at'] <= time.time() and (not receipt or receipt['phase'] == 'prepared'):
                outcome = dict(status='expired', changes_applied=False)
            elif receipt and receipt['phase'] in ('conflict', 'failed'):
                outcome = dict(status=receipt['phase'], changes_applied=False)
            if cp['outcome'] is not None and cp['outcome'] != outcome:
                raise ValueError('saved tool outcome no longer matches its receipt')
            if outcome is None:
                return None
            self.runs.db.execute('UPDATE approval_checkpoints SET outcome=? WHERE run_id=? AND step=? AND owner=?',
                                (json.dumps(outcome), run_id, cp['step'], owner))
            cp['outcome'] = outcome
            return cp

    def _reconcile_command(self, run_id, owner, cp):
        """Resolve a saved model command request *without ever dispatching it*.

        An approved command is not an executed command. Only the separately
        authorized human review HTTP endpoint can send /commands/execute.
        This poller can make an original, idempotent receipt read after a
        dropped connection; it must never produce a new execution lease.
        """
        from command_dispatch import CommandDispatchUnavailable

        action = cp['state']['action']
        workspace = cp['state']['workspace']
        item = self.command_review.store.get(owner, cp['approval_id'])
        submission_id = hashlib.sha256(f'nexus-command:{run_id}:{cp["step"]}'.encode()).hexdigest()[:32]
        if (item is None or item['digest'] != cp['digest'] or item['origin'] != 'agent' or
                item['submission_id'] != submission_id or
                item['proposal']['host'] != workspace['host'] or
                item['proposal']['workspace_id'] != workspace['workspace_id'] or
                item['proposal']['profile_id'] != action['profile_id']):
            raise ValueError('saved agent command approval is not bound to checkpoint')
        execution = self.command_review.store.get_execution(owner, item['id'], item['digest'])
        if (execution is not None and execution['phase'] in ('dispatching', 'uncertain') and
                time.monotonic() >= self.command_retry_at.get(run_id, 0)):
            self.command_retry_at[run_id] = time.monotonic() + 5
            try:
                self.command_dispatcher.reconcile(owner, item['id'], item['digest'])
            except (CommandDispatchUnavailable, PermissionError):
                # Current permission and host status are checked again on the
                # next bounded poll. Never reinterpret unavailable as success.
                pass

        # Re-read inside the same lock used by the owner's execution claim:
        # expiry cannot race a freshly dispatched signed operation.
        with self.runs.lock:
            item = self.command_review.store.get(owner, cp['approval_id'])
            execution = self.command_review.store.get_execution(owner, item['id'], item['digest'])
            outcome = None
            if item['status'] == 'rejected':
                outcome = {'status': 'rejected', 'command_executed': False}
            elif execution is not None and execution['phase'] in ('completed', 'interrupted'):
                if execution['phase'] == 'interrupted':
                    outcome = {'status': 'unknown_exit', 'execution_dispatched': True,
                               'receipt_verified': True, 'output_available': False}
                else:
                    receipt = execution['receipt']
                    result = receipt['result']
                    failed = bool(receipt.get('failure')) or result['exit_code'] != 0
                    outcome = {'status': 'failed' if failed else 'completed',
                               'execution_dispatched': True, 'receipt_verified': True,
                               'exit_code': result['exit_code'],
                               'timed_out': result['timed_out'],
                               'cancelled': result['cancelled'],
                               'truncated': result['truncated'],
                               'stdout': result['stdout'][:4096],
                               'stderr': result['stderr'][:2048],
                               'output_truncated_for_model': len(result['stdout']) > 4096 or len(result['stderr']) > 2048}
            elif (item['expires_at'] <= time.time() and
                  (execution is None or execution['phase'] == 'prepared')):
                outcome = {'status': 'expired', 'command_executed': False}
            if cp['outcome'] is not None and cp['outcome'] != outcome:
                raise ValueError('saved command outcome no longer matches signed receipt')
            if outcome is None:
                return None
            self.runs.db.execute('UPDATE approval_checkpoints SET outcome=? WHERE run_id=? AND step=? AND owner=?',
                                 (json.dumps(outcome), run_id, cp['step'], owner))
            cp['outcome'] = outcome
            return cp

    def drive_execution(self, run_id, owner, item):
        if self.closed:
            return
        future = self.futures.get(run_id)
        if future is not None:
            if not future.done():
                return
            try:
                future.result()
            except PermissionError:
                self.runs.update(run_id, phase='waiting for workspace write permission')
            except Exception:
                self.runs.update(run_id, phase='waiting for verified patch receipt')
            self.futures.pop(run_id, None)
            self.retry_at[run_id] = time.monotonic() + 5
            return
        if time.monotonic() < self.retry_at.get(run_id, 0):
            return
        record = self.runs.get_owned(run_id, owner)
        if record is None or record['cancel_requested'] or record['status'] in ('completed', 'failed', 'cancelled'):
            return
        def cancelled():
            current = self.runs.get_owned(run_id, owner)
            return current is None or current['cancel_requested'] or current['status'] in ('completed', 'failed', 'cancelled')
        self.futures[run_id] = self.pool.submit(self.dispatcher.apply, owner, item['id'], item['digest'], cancelled=cancelled)

    def close(self):
        if not self.closed:
            self.closed = True
            # Keep the run DB/lock alive until already dispatched operations
            # finish recording their receipt. HTTP requests have bounded timeouts.
            self.pool.shutdown(wait=True, cancel_futures=True)

    def poll(self):
        if self.closed:
            return []
        with self.runs.lock:
            rows = self.runs.db.execute("SELECT id,owner FROM runs WHERE status='waiting_for_approval'").fetchall()
        active = {run_id for run_id, _ in rows}
        for run_id in list(self.futures):
            if run_id not in active and self.futures[run_id].done(): self.futures.pop(run_id, None)
        self.retry_at = {key: value for key, value in self.retry_at.items() if key in active}
        self.command_retry_at = {key: value for key, value in self.command_retry_at.items() if key in active}
        ready = []
        for run_id, owner in rows:
            try:
                if self.reconcile(run_id, owner) is not None:
                    if self.runs.transition_active(run_id, 'queued', 'verified human review outcome'):
                        ready.append(run_id)
            except Exception:
                self.runs.update(run_id, status='failed', phase='review checkpoint unavailable',
                                 error='The saved review checkpoint could not be verified.')
        return ready
