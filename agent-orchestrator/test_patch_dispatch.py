import hashlib
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from approvals import ApprovalStore
from patch_dispatch import ExecutionConflict, PatchDispatcher, PatchDispatchUnavailable, patch_proof
from run_jobs import RunStore
from test_server import FakeController, OWNER_ID

EXECUTOR = 'x' * 40
GENERATION = 'c' * 64


class PatchDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.runs = RunStore(self.temp.name)
        self.approvals = ApprovalStore(self.runs)
        self.controller = FakeController()
        self.controller.review_token = 'r' * 40
        self.controller.workspace_executor_tokens = {'debian': EXECUTOR}
        self.controller.list_workspace = lambda host: {'host': host, 'workspaces': [
            {'id': 'code', 'name': 'Managed', 'read_only': False, 'generation': GENERATION, 'capabilities': ['apply_patch']}]}
        self.allowed = True
        self.controller.authorize_workspace_operation = lambda *args: self.allowed
        self.payloads, self.receipt = [], None
        self.drop_reply = False
        def transport(base, path, key, method, payload, **kwargs):
            self.assertEqual(key, EXECUTOR)
            self.assertEqual(method, 'POST')
            self.assertEqual(payload['proof'], patch_proof(payload, key))
            self.payloads.append((path, payload.copy()))
            if path.endswith('/apply'):
                self.receipt = {name: payload[name] for name in
                    ('host', 'workspace_id', 'approval_id', 'digest', 'operation_id')}
                self.receipt.update(status='applied', sha256=payload['replacement_sha256'])
                if self.drop_reply:
                    raise OSError('private transport detail')
            return self.receipt
        self.controller.http_json = transport
        self.dispatcher = PatchDispatcher(self.controller, self.approvals)
        self.item = self.approvals.propose(OWNER_ID, dict(host='debian', workspace_id='code', path='main.py',
            original='old', replacement='new', base_sha256=hashlib.sha256(b'old').hexdigest(), workspace_generation=GENERATION))
        self.approvals.transition(OWNER_ID, self.item['id'], self.item['digest'], expected='pending', target='approved')

    def tearDown(self):
        self.runs.close()
        self.temp.cleanup()

    def apply(self):
        return self.dispatcher.apply(OWNER_ID, self.item['id'], self.item['digest'])

    def test_exact_applied_receipt_and_retry_never_dispatch_twice(self):
        result = self.apply()
        self.assertEqual(result['phase'], 'applied')
        self.assertEqual(self.apply(), result)
        self.assertEqual(len(self.payloads), 1)
        self.assertEqual(self.payloads[0][1]['workspace_generation'], GENERATION)

    def test_lost_reply_reconciles_original_binding_after_restart_without_mutation_retry(self):
        self.drop_reply = True
        with self.assertRaises(PatchDispatchUnavailable) as raised:
            self.apply()
        self.assertNotIn('private transport detail', str(raised.exception))
        original = self.payloads[0][1]
        self.runs.close()
        self.runs = RunStore(self.temp.name)
        self.approvals = ApprovalStore(self.runs)
        self.dispatcher = PatchDispatcher(self.controller, self.approvals)
        # Reconciliation accepts the original lease after expiry; it cannot rename anew.
        with patch('patch_dispatch.time.time', return_value=time.time() + 60):
            result = self.dispatcher.reconcile(OWNER_ID, self.item['id'], self.item['digest'])
        self.assertEqual(result['phase'], 'applied')
        self.assertEqual(len([path for path, _ in self.payloads if path.endswith('/apply')]), 1)
        self.assertEqual(self.payloads[-1][1], original)

    def test_policy_generation_and_credentials_fail_before_consumption(self):
        self.allowed = False
        with self.assertRaises(PermissionError): self.apply()
        self.allowed = True
        self.controller.workspace_executor_tokens['debian'] = self.controller.token
        with self.assertRaises(PatchDispatchUnavailable): self.apply()
        self.controller.workspace_executor_tokens['debian'] = EXECUTOR
        self.controller.workspace_executor_tokens['nixos'] = EXECUTOR
        with self.assertRaises(PatchDispatchUnavailable): self.apply()
        self.controller.workspace_executor_tokens.pop('nixos')
        self.controller.list_workspace = lambda _: {'workspaces': [{'id': 'code', 'read_only': False,
            'generation': 'f' * 64, 'capabilities': ['apply_patch']}]}
        with self.assertRaises(PatchDispatchUnavailable): self.apply()
        self.assertIsNone(self.dispatcher.executions.get(OWNER_ID, self.item['id'], self.item['digest']))
        self.assertEqual(self.payloads, [])

    def test_cleartext_lan_executor_is_refused(self):
        self.controller.workspaces['debian'] = ('http://192.168.1.1:8896/v1', 'z' * 40)
        with self.assertRaises(PatchDispatchUnavailable): self.apply()
        self.assertEqual(self.payloads, [])

    def test_legacy_proposal_and_wrong_owner_cannot_execute(self):
        old = dict(self.item['proposal']); old.pop('workspace_generation')
        legacy = self.approvals.propose(OWNER_ID, old)
        self.approvals.transition(OWNER_ID, legacy['id'], legacy['digest'], expected='pending', target='approved')
        with self.assertRaises(PatchDispatchUnavailable):
            self.dispatcher.apply(OWNER_ID, legacy['id'], legacy['digest'])
        with self.assertRaises(ExecutionConflict):
            self.dispatcher.apply('b' * 64, self.item['id'], self.item['digest'])

    def test_forged_receipt_hash_never_records_success(self):
        self.controller.http_json = lambda *args, **kwargs: {'status': 'applied', 'sha256': 'a' * 64}
        with self.assertRaises(PatchDispatchUnavailable): self.apply()
        result = self.dispatcher.executions.get(OWNER_ID, self.item['id'], self.item['digest'])
        self.assertEqual(result['phase'], 'uncertain')

    def test_cancel_before_dispatch_never_sends_mutation(self):
        with self.assertRaises(InterruptedError):
            self.dispatcher.apply(OWNER_ID, self.item['id'], self.item['digest'], cancelled=lambda: True)
        self.assertEqual(self.payloads, [])
        self.assertIsNone(self.dispatcher.executions.get(OWNER_ID, self.item['id'], self.item['digest']))


if __name__ == '__main__': unittest.main()
