import copy
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from approvals import ApprovalConflict
from command_approvals import CommandApprovals
from command_dispatch import CommandDispatcher, CommandDispatchUnavailable, command_proof
from run_jobs import RunStore
from test_command_approvals import proposal
from test_server import FakeController, OWNER_ID

KEY = 'command-executor-fixture-' + 'k' * 24


class CommandDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); os.chmod(self.temp.name, 0o700)
        self.runs = RunStore(self.temp.name)
        self.approvals = CommandApprovals(self.runs)
        self.value = proposal(); self.value['host'] = 'debian'
        self.item = self.approvals.propose(OWNER_ID, self.value, '1' * 32)
        self.approvals.review(OWNER_ID, self.item['id'], self.item['digest'], 'approve')
        self.ctrl = FakeController()
        self.ctrl.command_executor_tokens = {'debian': KEY}
        self.ctrl.workspace_executor_tokens = {'debian': 'patch-only-' + 'p' * 32}
        self.ctrl.review_token = 'review-only-' + 'r' * 32
        self.ctrl.list_workspace = lambda _: dict(workspaces=[dict(id='code', read_only=True,
            generation=self.value['workspace_generation'], capabilities=['run_command'])])
        self.allowed, self.drop = True, False
        self.checks, self.sent, self.receipt = [], [], None
        def authorize(owner, value, operation):
            self.assertEqual(owner, OWNER_ID); self.assertEqual(operation, 'execute')
            self.checks.append(operation)
            return self.allowed
        self.ctrl.authorize_workspace_operation = authorize
        def transport(base, path, key='', method='GET', payload=None, **kwargs):
            if method == 'GET':
                return dict(host='debian', workspace_id='code', profiles=[dict(id=self.value['profile_id'],
                    version=self.value['profile_version'], invocation=copy.deepcopy(self.value['invocation']))])
            self.assertEqual(key, KEY); self.assertEqual(payload['proof'], command_proof(payload, key))
            self.sent.append((path, copy.deepcopy(payload)))
            if path.endswith('/execute'):
                request = {k: v for k, v in payload.items() if k != 'proof'}
                result = {k: payload[k] for k in ('profile_id', 'snapshot_id', 'profile_version', 'input_digest', 'workspace_generation')}
                result.update(stdout='fixture result', stderr='', exit_code=0, timed_out=False, truncated=False, cancelled=False)
                self.receipt = dict(request=request, status='completed', result=result)
                if self.drop: raise OSError('private URL and internal transport detail')
            return copy.deepcopy(self.receipt)
        self.ctrl.http_json = transport
        self.dispatch = CommandDispatcher(self.ctrl, self.approvals)

    def tearDown(self): self.runs.close(); self.temp.cleanup()
    def execute(self, **kwargs): return self.dispatch.execute(OWNER_ID, self.item['id'], self.item['digest'], **kwargs)

    def prepare_transport(self, tamper=None):
        previous = self.ctrl.http_json
        self.prepared = []
        def transport(base, path, key='', method='GET', payload=None, **kwargs):
            if path.endswith('/commands/prepare'):
                self.assertEqual(key, self.ctrl.workspaces['debian'][1])
                self.assertEqual(method, 'POST')
                self.assertEqual(set(payload), {'host', 'workspace_id', 'owner', 'profile_id', 'snapshot_id', 'expires_at'})
                self.prepared.append(copy.deepcopy(payload))
                snapshot = {name: copy.deepcopy(value) for name, value in self.value.items()
                            if name not in ('kind', 'host')}
                snapshot['snapshot_id'] = payload['snapshot_id']
                snapshot['expires_at'] = payload['expires_at']
                if tamper is not None:
                    tamper(snapshot)
                return {'host': 'debian', 'owner': OWNER_ID, 'snapshot': snapshot}
            return previous(base, path, key, method, payload, **kwargs)
        self.ctrl.http_json = transport

    def test_prepare_proposal_is_real_fixed_host_capture_pending_review_and_idempotent(self):
        self.prepare_transport()
        item = self.dispatch.prepare_proposal(OWNER_ID, 'debian', 'code', 'tests', 'f' * 32)
        self.assertEqual(item['status'], 'pending')
        self.assertEqual(item['origin'], 'manual')
        self.assertEqual(item['proposal']['invocation'], self.value['invocation'])
        self.assertEqual(item['proposal']['snapshot_id'], self.prepared[0]['snapshot_id'])
        self.assertEqual(self.dispatch.prepare_proposal(OWNER_ID, 'debian', 'code', 'tests', 'f' * 32), item)
        self.assertEqual(len(self.prepared), 1)
        with self.assertRaises(ApprovalConflict):
            self.dispatch.prepare_proposal(OWNER_ID, 'debian', 'code', 'different', 'f' * 32)
        self.assertEqual(self.sent, [])
        self.assertIsNone(self.approvals.get_execution(OWNER_ID, item['id'], item['digest']))

    def test_prepare_refuses_unknown_profile_capability_and_revoked_grant(self):
        self.prepare_transport()
        with self.assertRaises(CommandDispatchUnavailable):
            self.dispatch.prepare_proposal(OWNER_ID, 'debian', 'code', 'not-advertised', 'a' * 32)
        self.assertEqual(self.prepared, [])
        self.ctrl.list_workspace = lambda _: dict(workspaces=[dict(id='code', read_only=True,
            generation=self.value['workspace_generation'], capabilities=['list', 'read_file'])])
        with self.assertRaises(CommandDispatchUnavailable):
            self.dispatch.prepare_proposal(OWNER_ID, 'debian', 'code', 'tests', 'a' * 32)
        self.assertEqual(self.prepared, [])
        self.allowed = False
        with self.assertRaises(PermissionError):
            self.dispatch.prepare_proposal(OWNER_ID, 'debian', 'code', 'tests', 'a' * 32)
        self.assertEqual(self.prepared, [])

    def test_prepare_rejects_tampered_snapshot_and_policy_revocation_after_capture(self):
        for mutate in (lambda s: s.update(workspace_generation='0' * 64),
                       lambda s: s['invocation']['arguments'].append('--evil'),
                       lambda s: s.update(input_digest='0' * 64),
                       lambda s: s.update(snapshot_id='0' * 32)):
            self.prepare_transport(mutate)
            with self.assertRaises(CommandDispatchUnavailable):
                self.dispatch.prepare_proposal(OWNER_ID, 'debian', 'code', 'tests', 'a' * 32)
            self.assertIsNone(self.approvals.get_submission(OWNER_ID, 'a' * 32))
        self.prepare_transport()
        called = 0
        def revoke(*args):
            nonlocal called
            called += 1
            return called == 1
        self.ctrl.authorize_workspace_operation = revoke
        with self.assertRaises(PermissionError):
            self.dispatch.prepare_proposal(OWNER_ID, 'debian', 'code', 'tests', 'a' * 32)
        self.assertEqual(len(self.prepared), 1)
        self.assertIsNone(self.approvals.get_submission(OWNER_ID, 'a' * 32))

    def test_prepare_rejects_invalid_identity_before_contacting_host(self):
        self.prepare_transport()
        for args in ((OWNER_ID, 'untrusted', 'code', 'tests', 'a'*32),
                     (OWNER_ID, 'debian', '../code', 'tests', 'a'*32),
                     (OWNER_ID, 'debian', 'code', '../shell', 'a'*32),
                     (OWNER_ID, 'debian', 'code', 'tests', 'not-a-uuid'),
                     ('unknown-owner', 'debian', 'code', 'tests', 'a'*32)):
            with self.assertRaises(ValueError):
                self.dispatch.prepare_proposal(*args)
        self.assertEqual(self.prepared, [])

    def test_exact_receipt_and_repeated_execute_send_once(self):
        result = self.execute()
        self.assertEqual(result['phase'], 'completed')
        self.assertEqual(self.execute(), result)
        self.assertEqual(len(self.sent), 1)
        self.assertGreaterEqual(len(self.checks), 3)

    def test_lost_reply_reconciles_original_signed_body_after_reopen_and_expiry(self):
        self.drop = True
        with self.assertRaises(CommandDispatchUnavailable) as raised: self.execute()
        self.assertNotIn('private URL', str(raised.exception))
        saved = copy.deepcopy(self.sent[0][1])
        self.runs.close(); self.runs = RunStore(self.temp.name)
        self.approvals = CommandApprovals(self.runs); self.dispatch = CommandDispatcher(self.ctrl, self.approvals)
        with patch('command_dispatch.time.time', return_value=time.time() + 600):
            result = self.dispatch.reconcile(OWNER_ID, self.item['id'], self.item['digest'])
        self.assertEqual(result['phase'], 'completed')
        self.assertEqual(self.sent[-1][1], saved)
        self.assertEqual(sum(path.endswith('/execute') for path, _ in self.sent), 1)

    def test_cancellation_persists_intent_and_never_resends_execution(self):
        self.drop = True
        with self.assertRaises(CommandDispatchUnavailable): self.execute()
        executed = copy.deepcopy(self.sent[0][1])
        sent = self.ctrl.http_json
        def cancelled(base, path, key='', method='GET', payload=None, **kwargs):
            if path.endswith('/cancel'):
                self.assertEqual(payload, executed)
                self.assertEqual(key, KEY)
                self.sent.append((path, copy.deepcopy(payload)))
                return {'host':'debian', 'workspace_id':'code', 'operation_id':executed['operation_id'],
                        'cancel_requested':True, 'receipt_status':'claimed'}
            return sent(base, path, key, method, payload, **kwargs)
        self.ctrl.http_json = cancelled
        cancelled_record = self.dispatch.cancel(OWNER_ID, self.item['id'], self.item['digest'])
        self.assertEqual(cancelled_record['phase'], 'uncertain')
        self.assertTrue(cancelled_record['cancel_requested'])
        self.runs.close(); self.runs = RunStore(self.temp.name)
        self.approvals = CommandApprovals(self.runs); self.dispatch = CommandDispatcher(self.ctrl, self.approvals)
        self.assertTrue(self.dispatch.cancel(OWNER_ID, self.item['id'], self.item['digest'])['cancel_requested'])
        self.assertEqual(sum(path.endswith('/execute') for path, _ in self.sent), 1)
        self.assertEqual(sum(path.endswith('/cancel') for path, _ in self.sent), 2)
        self.allowed = False
        with self.assertRaises(PermissionError): self.dispatch.cancel(OWNER_ID, self.item['id'], self.item['digest'])
        self.assertEqual(sum(path.endswith('/cancel') for path, _ in self.sent), 2)

    def test_invalid_host_cancel_ack_stays_uncertain_never_claims_success(self):
        self.drop = True
        with self.assertRaises(CommandDispatchUnavailable): self.execute()
        sent = self.ctrl.http_json
        def invalid(base, path, key='', method='GET', payload=None, **kwargs):
            if path.endswith('/cancel'):
                return {'host':'wrong', 'workspace_id':'code', 'operation_id':payload['operation_id'],
                        'cancel_requested':True, 'receipt_status':'claimed'}
            return sent(base, path, key, method, payload, **kwargs)
        self.ctrl.http_json = invalid
        with self.assertRaises(CommandDispatchUnavailable):
            self.dispatch.cancel(OWNER_ID, self.item['id'], self.item['digest'])
        record = self.approvals.get_execution(OWNER_ID, self.item['id'], self.item['digest'])
        self.assertEqual(record['phase'], 'uncertain')
        self.assertTrue(record['cancel_requested'])
        self.assertEqual(sum(path.endswith('/execute') for path, _ in self.sent), 1)

    def test_write_or_read_credentials_cannot_authorize_commands(self):
        for key in (self.ctrl.token, self.ctrl.review_token, self.ctrl.workspace_executor_tokens['debian']):
            self.ctrl.command_executor_tokens['debian'] = key
            with self.assertRaises(CommandDispatchUnavailable): self.execute()
        self.ctrl.command_executor_tokens = {'debian': KEY, 'nixos': KEY}
        with self.assertRaises(CommandDispatchUnavailable): self.execute()
        self.assertEqual(self.sent, [])
        self.assertIsNone(self.approvals.get_execution(OWNER_ID, self.item['id'], self.item['digest']))

    def test_policy_and_profile_fail_before_consumption(self):
        self.allowed = False
        with self.assertRaises(PermissionError): self.execute()
        self.allowed = True
        original = self.value['invocation']['arguments'][:]
        self.value['invocation']['arguments'].append('changed host profile')
        with self.assertRaises(CommandDispatchUnavailable): self.execute()
        self.value['invocation']['arguments'] = original
        self.ctrl.list_workspace = lambda _: dict(workspaces=[dict(id='code',generation='0' * 64,capabilities=['run_command'])])
        with self.assertRaises(CommandDispatchUnavailable): self.execute()
        self.assertIsNone(self.approvals.get_execution(OWNER_ID, self.item['id'], self.item['digest']))
        self.assertEqual(self.sent, [])

    def test_revocation_or_cancellation_at_send_boundary_prevents_transport(self):
        def authorized(owner, value, operation):
            self.checks.append(operation); return len(self.checks) < 3
        self.ctrl.authorize_workspace_operation = authorized
        with self.assertRaises(PermissionError): self.execute()
        self.assertEqual(self.sent, [])
        self.assertEqual(self.approvals.get_execution(OWNER_ID, self.item['id'], self.item['digest'])['phase'], 'prepared')
        self.ctrl.authorize_workspace_operation = lambda *args: True
        calls = 0
        def cancelled():
            nonlocal calls
            calls += 1; return calls >= 3
        with self.assertRaises(InterruptedError): self.execute(cancelled=cancelled)
        self.assertEqual(self.sent, [])

    def test_forged_lease_or_output_never_becomes_success_and_never_resends(self):
        transport = self.ctrl.http_json
        def forged(*args, **kwargs):
            receipt = transport(*args, **kwargs)
            if isinstance(receipt, dict) and receipt.get('status') == 'completed': receipt['request']['expires_at'] += 1
            return receipt
        self.ctrl.http_json = forged
        with self.assertRaises(CommandDispatchUnavailable): self.execute()
        self.assertEqual(self.approvals.get_execution(OWNER_ID, self.item['id'], self.item['digest'])['phase'], 'uncertain')
        self.ctrl.http_json = transport
        self.assertEqual(self.execute()['phase'], 'completed')
        self.assertEqual(sum(path.endswith('/execute') for path, _ in self.sent), 1)

    def test_missing_saved_request_after_dispatch_cannot_be_regenerated(self):
        self.drop = True
        with self.assertRaises(CommandDispatchUnavailable): self.execute()
        self.runs.db.execute('DELETE FROM command_dispatch_requests')
        with self.assertRaises(ApprovalConflict): self.execute()
        self.assertEqual(len(self.sent), 1)

    def test_short_remaining_lease_is_serialized_as_integer_not_sqlite_real(self):
        value = copy.deepcopy(self.value)
        value['snapshot_id'] = '2' * 32
        value['expires_at'] = int(time.time()) + 2
        item = self.approvals.propose(OWNER_ID, value, '3' * 32)
        self.approvals.review(OWNER_ID, item['id'], item['digest'], 'approve')
        with patch('command_dispatch.time.time', return_value=value['expires_at'] - 0.5):
            result = self.dispatch.execute(OWNER_ID, item['id'], item['digest'])
        self.assertEqual(result['phase'], 'completed')
        self.assertIs(type(self.sent[-1][1]['expires_at']), int)
        self.assertEqual(self.sent[-1][1]['expires_at'], value['expires_at'])

    def test_cleartext_or_wrong_owner_fails_before_claim(self):
        self.ctrl.workspaces['debian'] = ('http://192.168.1.1:8896/v1', self.ctrl.workspaces['debian'][1])
        with self.assertRaises(CommandDispatchUnavailable): self.execute()
        with self.assertRaises(ApprovalConflict): self.dispatch.execute('f' * 64, self.item['id'], self.item['digest'])
        self.assertEqual(self.sent, [])
