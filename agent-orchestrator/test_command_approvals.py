import copy
import hashlib
import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from approvals import ApprovalConflict, ApprovalStore
from command_approvals import CommandApprovals, manifest_digest
from run_jobs import RunStore

OWNER, OTHER = 'a' * 64, 'b' * 64


def proposal():
    inputs = [dict(path='src/main.py', size_bytes=4, sha256=hashlib.sha256(b'pass').hexdigest())]
    return dict(kind='command', host='nixos', workspace_id='code', workspace_generation='c' * 64,
                snapshot_id='d' * 32, profile_id='tests', profile_version='e' * 64,
                input_digest=manifest_digest(inputs), inputs=inputs, expires_at=int(time.time()) + 290,
                invocation=dict(executable='/usr/bin/python3', arguments=['-m', 'unittest'], limits=dict(
                    timeout_ms=30000, memory_bytes=128 << 20, address_space_bytes=8 << 30,
                    processes=16, cpu_seconds=10, scratch_bytes=1 << 20, output_bytes=65536)))


class CommandApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.runs = RunStore(self.temp.name)
        self.store = CommandApprovals(self.runs)
        self.proposal = proposal()
        self.item = self.store.propose(OWNER, self.proposal, 'f' * 32)

    def tearDown(self):
        self.runs.close()
        self.temp.cleanup()

    def approve(self):
        self.assertTrue(self.store.review(OWNER, self.item['id'], self.item['digest'], 'approve'))

    def receipt(self, execution, status='completed'):
        request = {key: self.proposal[key] for key in ('host', 'workspace_id', 'workspace_generation',
                   'snapshot_id', 'profile_id', 'profile_version', 'input_digest', 'expires_at')}
        request.update(owner=OWNER, approval_id=self.item['id'], digest=self.item['digest'], operation_id=execution['operation_id'])
        if status == 'interrupted':
            return dict(request=request, status=status, failure='exit_unknown')
        result = {key: self.proposal[key] for key in ('snapshot_id', 'profile_id', 'profile_version', 'input_digest', 'workspace_generation')}
        result.update(stdout='ok', stderr='', exit_code=0, truncated=False, timed_out=False, cancelled=False)
        return dict(request=request, status=status, result=result)

    def test_stable_submission_owner_origin_and_snapshot_binding(self):
        self.assertEqual(self.store.propose(OWNER, self.proposal, 'f' * 32), self.item)
        self.assertIsNone(self.store.get(OTHER, self.item['id']))
        for change in ('contents', 'origin', 'snapshot'):
            with self.subTest(change=change), self.assertRaises(ApprovalConflict):
                value = copy.deepcopy(self.proposal)
                if change == 'contents': value['invocation']['arguments'] = ['changed']
                self.store.propose(OWNER, value, '1' * 32 if change == 'snapshot' else 'f' * 32,
                                   origin='agent' if change == 'origin' else 'manual')
        self.proposal['invocation']['arguments'].append('mutation')
        self.assertEqual(self.store.get(OWNER, self.item['id'])['proposal']['invocation']['arguments'], ['-m', 'unittest'])

    def test_submission_lookup_and_review_list_are_owner_and_scope_bound(self):
        self.assertEqual(self.store.get_submission(OWNER, 'f' * 32), self.item)
        self.assertIsNone(self.store.get_submission(OTHER, 'f' * 32))
        self.assertEqual(self.store.list_scope(OTHER, 'nixos', 'code'), [])
        self.assertEqual(self.store.list_scope(OWNER, 'debian', 'code'), [])
        self.assertEqual(self.store.list_scope(OWNER, 'nixos', 'other'), [])
        listing = self.store.list_scope(OWNER, 'nixos', 'code')
        self.assertEqual([item['id'] for item in listing], [self.item['id']])
        self.assertNotIn('proposal', listing[0])
        self.approve()
        execution = self.store.claim(OWNER, self.item['id'], self.item['digest'])
        self.assertEqual(self.store.list_scope(OWNER, 'nixos', 'code')[0]['execution_phase'], 'prepared')
        self.assertEqual(execution['phase'], 'prepared')

    def test_edit_and_command_approvals_cannot_substitute_for_each_other(self):
        edits = ApprovalStore(self.runs)
        self.assertIsNone(edits.get(OWNER, self.item['id']))
        edit = edits.propose(OWNER, dict(host='nixos', workspace_id='code', path='main.py', original='old',
                            replacement='new', base_sha256=hashlib.sha256(b'old').hexdigest()))
        self.assertIsNone(self.store.get(OWNER, edit['id']))
        self.assertFalse(self.store.review(OWNER, edit['id'], edit['digest'], 'approve'))
        with self.assertRaises(ValueError):
            self.store.propose(OWNER, edit['proposal'], '2' * 32)

    def test_single_human_decision_and_once_only_dispatch_are_atomic(self):
        self.assertFalse(self.store.review(OTHER, self.item['id'], self.item['digest'], 'approve'))
        self.assertFalse(self.store.review(OWNER, self.item['id'], '0' * 64, 'approve'))
        def review(_): return self.store.review(OWNER, self.item['id'], self.item['digest'], 'approve')
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(review, range(16))), 1)
        def claim(_):
            execution = self.store.claim(OWNER, self.item['id'], self.item['digest'])
            return self.store.start_dispatch(OWNER, self.item['id'], self.item['digest'], execution['operation_id'])
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(claim, range(16))), 1)
        execution = self.store.get_execution(OWNER, self.item['id'], self.item['digest'])
        self.assertEqual(execution['phase'], 'dispatching')
        self.store.mark_uncertain(OWNER, self.item['id'], self.item['digest'], execution['operation_id'])
        self.assertFalse(self.store.start_dispatch(OWNER, self.item['id'], self.item['digest'], execution['operation_id']))

    def test_expired_rejected_and_unreviewed_cannot_execute(self):
        with self.assertRaises(ApprovalConflict): self.store.claim(OWNER, self.item['id'], self.item['digest'])
        with patch('command_approvals.time.time', return_value=self.item['expires_at'] + 1):
            self.assertFalse(self.store.review(OWNER, self.item['id'], self.item['digest'], 'approve'))
            self.assertEqual(self.store.propose(OWNER, self.proposal, 'f' * 32), self.item)
        self.assertTrue(self.store.review(OWNER, self.item['id'], self.item['digest'], 'reject'))
        with self.assertRaises(ApprovalConflict): self.store.claim(OWNER, self.item['id'], self.item['digest'])

    def test_withdraw_is_owned_irreversible_and_safe_after_human_approval(self):
        self.assertEqual(self.store.withdraw(OWNER, self.item['id'], self.item['digest'])['status'], 'rejected')
        self.assertEqual(self.store.withdraw(OWNER, self.item['id'], self.item['digest'])['status'], 'rejected')
        self.assertFalse(self.store.review(OWNER, self.item['id'], self.item['digest'], 'approve'))
        with self.assertRaises(ApprovalConflict): self.store.claim(OWNER, self.item['id'], self.item['digest'])
        with self.assertRaises(ApprovalConflict): self.store.withdraw(OTHER, self.item['id'], self.item['digest'])
        with self.assertRaises(ApprovalConflict): self.store.withdraw(OWNER, self.item['id'], '0'*64)
        changed = proposal(); changed['snapshot_id'] = '1'*32
        approved = self.store.propose(OWNER, changed, '1'*32)
        self.assertTrue(self.store.review(OWNER, approved['id'], approved['digest'], 'approve'))
        self.assertEqual(self.store.withdraw(OWNER, approved['id'], approved['digest'])['status'], 'rejected')
        with self.assertRaises(ApprovalConflict): self.store.claim(OWNER, approved['id'], approved['digest'])

    def test_cancel_intent_is_durable_bounded_to_dispatched_original(self):
        self.approve()
        execution = self.store.claim(OWNER, self.item['id'], self.item['digest'])
        with self.assertRaises(ApprovalConflict): self.store.request_cancel(OWNER, self.item['id'], self.item['digest'])
        self.assertTrue(self.store.start_dispatch(OWNER, self.item['id'], self.item['digest'], execution['operation_id']))
        requested = self.store.request_cancel(OWNER, self.item['id'], self.item['digest'])
        self.assertTrue(requested['cancel_requested'])
        self.assertEqual(self.store.request_cancel(OWNER, self.item['id'], self.item['digest']), requested)
        self.assertIsNone(self.store.get_execution(OTHER, self.item['id'], self.item['digest']))
        with self.assertRaises(ApprovalConflict): self.store.request_cancel(OTHER, self.item['id'], self.item['digest'])
        self.runs.close(); self.runs = RunStore(self.temp.name); self.store = CommandApprovals(self.runs)
        self.assertEqual(self.store.get_execution(OWNER, self.item['id'], self.item['digest']), requested)
        self.store.mark_uncertain(OWNER, self.item['id'], self.item['digest'], execution['operation_id'])
        with self.assertRaises(ApprovalConflict): self.store.withdraw(OWNER, self.item['id'], self.item['digest'])
        self.store.finish(OWNER, self.item['id'], self.item['digest'], execution['operation_id'], self.receipt(execution))
        with self.assertRaises(ApprovalConflict): self.store.request_cancel(OWNER, self.item['id'], self.item['digest'])

    def test_restart_preserves_claim_and_terminal_receipt_without_dispatch(self):
        self.approve()
        execution = self.store.claim(OWNER, self.item['id'], self.item['digest'])
        self.assertTrue(self.store.start_dispatch(OWNER, self.item['id'], self.item['digest'], execution['operation_id']))
        self.store.mark_uncertain(OWNER, self.item['id'], self.item['digest'], execution['operation_id'])
        self.runs.close(); self.runs = RunStore(self.temp.name); self.store = CommandApprovals(self.runs)
        restored = self.store.claim(OWNER, self.item['id'], self.item['digest'])
        self.assertEqual(restored['operation_id'], execution['operation_id'])
        self.assertEqual(restored['phase'], 'uncertain')
        receipt = self.receipt(restored)
        finished = self.store.finish(OWNER, self.item['id'], self.item['digest'], restored['operation_id'], receipt)
        self.assertEqual(finished['phase'], 'completed')
        receipt['result']['stdout'] = 'changed by caller'
        self.assertEqual(self.store.get_execution(OWNER, self.item['id'], self.item['digest'])['receipt']['result']['stdout'], 'ok')
        self.runs.close(); self.runs = RunStore(self.temp.name); self.store = CommandApprovals(self.runs)
        self.assertEqual(self.store.get_execution(OWNER, self.item['id'], self.item['digest']), finished)
        self.assertFalse(self.store.start_dispatch(OWNER, self.item['id'], self.item['digest'], restored['operation_id']))

    def test_forged_receipt_cannot_claim_success_or_change_terminal_result(self):
        self.approve(); execution = self.store.claim(OWNER, self.item['id'], self.item['digest'])
        self.store.start_dispatch(OWNER, self.item['id'], self.item['digest'], execution['operation_id'])
        for mutation in ('owner', 'snapshot', 'exit', 'output', 'cancel', 'proof'):
            value = self.receipt(execution)
            if mutation == 'owner': value['request']['owner'] = OTHER
            if mutation == 'snapshot': value['result']['snapshot_id'] = '0' * 32
            if mutation == 'exit': value['result']['exit_code'] = True
            if mutation == 'output': value['result']['stdout'] = 'x' * 65537
            if mutation == 'cancel': value['result']['cancelled'] = True
            if mutation == 'proof': value['request']['proof'] = 'credential-like-extra'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.store.finish(OWNER, self.item['id'], self.item['digest'], execution['operation_id'], value)
        unknown = self.receipt(execution, 'interrupted')
        self.assertEqual(self.store.finish(OWNER, self.item['id'], self.item['digest'], execution['operation_id'], unknown)['phase'], 'interrupted')
        with self.assertRaises(ApprovalConflict):
            self.store.finish(OWNER, self.item['id'], self.item['digest'], execution['operation_id'], self.receipt(execution))

    def test_invalid_proposals_and_database_corruption_fail_closed(self):
        for mutation in ('kind', 'path', 'manifest', 'limits', 'executable', 'extra', 'expiry'):
            value = copy.deepcopy(self.proposal); value['snapshot_id'] = '1' * 32
            if mutation == 'kind': value['kind'] = 'patch'
            if mutation == 'path': value['inputs'][0]['path'] = '../escape'; value['input_digest'] = manifest_digest(value['inputs'])
            if mutation == 'manifest': value['input_digest'] = '0' * 64
            if mutation == 'limits': value['invocation']['limits']['processes'] = True
            if mutation == 'executable': value['invocation']['executable'] = '/bin/../sh'
            if mutation == 'extra': value['shell'] = 'arbitrary'
            if mutation == 'expiry': value['expires_at'] = int(time.time()) + 301
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.store.propose(OWNER, value, '2' * 32)
        self.runs.db.execute('UPDATE command_approvals SET proposal=? WHERE id=?', ('{}', self.item['id']))
        with self.assertRaises((ValueError, ApprovalConflict)): self.store.get(OWNER, self.item['id'])


if __name__ == '__main__': unittest.main()
