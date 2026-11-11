import hashlib
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from approvals import ApprovalStore
from patch_execution import ExecutionConflict, PatchExecutionStore
from run_jobs import RunStore

OWNER = 'a' * 64
OTHER = 'b' * 64


class PatchExecutionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        os.chmod(self.directory.name, 0o700)
        self.open()
        proposal = {'host': 'nixos', 'workspace_id': 'code', 'path': 'src/main.py',
                    'original': 'old', 'replacement': 'new',
                    'base_sha256': hashlib.sha256(b'old').hexdigest()}
        self.item = self.approvals.propose(OWNER, proposal)

    def open(self):
        self.runs = RunStore(self.directory.name)
        self.approvals = ApprovalStore(self.runs)
        self.executions = PatchExecutionStore(self.approvals)

    def tearDown(self):
        self.runs.close()
        self.directory.cleanup()

    def claim(self):
        return self.executions.claim(OWNER, self.item['id'], self.item['digest'])

    def approve(self):
        self.assertTrue(self.approvals.transition(OWNER, self.item['id'], self.item['digest'],
            expected='pending', target='approved'))

    def dispatch(self, claim):
        return self.executions.start_dispatch(OWNER, self.item['id'], self.item['digest'], claim['operation_id'])

    def finish(self, claim, phase, result=None):
        return self.executions.finish(OWNER, self.item['id'], self.item['digest'], claim['operation_id'], phase, result)

    def test_exact_approved_owner_is_required(self):
        with self.assertRaises(ExecutionConflict): self.claim()
        self.approve()
        for owner, digest in [(OTHER, self.item['digest']), (OWNER, 'c' * 64)]:
            with self.assertRaises(ExecutionConflict):
                self.executions.claim(owner, self.item['id'], digest)
        claim = self.claim()
        self.assertEqual(claim['phase'], 'prepared')
        self.assertEqual(self.approvals.get(OWNER, self.item['id'])['status'], 'executing')
        self.assertIsNone(self.executions.get(OTHER, self.item['id'], self.item['digest']))

    def test_concurrent_claim_and_dispatch_cross_boundary_once(self):
        self.approve()
        with ThreadPoolExecutor(max_workers=8) as workers:
            claims = list(workers.map(lambda _: self.claim(), range(16)))
        self.assertEqual(len({c['operation_id'] for c in claims}), 1)
        with ThreadPoolExecutor(max_workers=8) as workers:
            self.assertEqual(sum(workers.map(lambda _: self.dispatch(claims[0]), range(16))), 1)
        self.assertFalse(self.dispatch(self.claim()))

    def test_restart_never_replays_ambiguous_dispatch(self):
        self.approve()
        claim = self.claim()
        self.assertTrue(self.dispatch(claim))
        self.runs.close()
        self.open()
        restored = self.claim()
        self.assertEqual(restored['operation_id'], claim['operation_id'])
        self.assertEqual(restored['phase'], 'dispatching')
        self.assertFalse(self.dispatch(restored))
        uncertain = self.finish(restored, 'uncertain')
        self.assertEqual(uncertain['phase'], 'uncertain')
        self.assertFalse(self.dispatch(restored))
        with self.assertRaises(ExecutionConflict):
            self.finish(restored, 'applied', hashlib.sha256(b'different').hexdigest())
        applied = self.finish(restored, 'applied', claim['replacement_sha256'])
        self.assertEqual(applied['phase'], 'applied')
        self.assertEqual(self.finish(restored, 'applied', claim['replacement_sha256']), applied)
        with self.assertRaises(ExecutionConflict): self.finish(restored, 'conflict')

    def test_expired_or_rejected_approval_cannot_claim(self):
        self.approve()
        self.runs.db.execute('UPDATE approvals SET expires=0 WHERE id=?', (self.item['id'],))
        with self.assertRaises(ExecutionConflict): self.claim()
        self.runs.db.execute("UPDATE approvals SET status='rejected',expires=9999999999 WHERE id=?", (self.item['id'],))
        with self.assertRaises(ExecutionConflict): self.claim()

    def test_prepared_claim_survives_expiry_but_finish_requires_dispatch(self):
        self.approve()
        claim = self.claim()
        self.runs.db.execute('UPDATE approvals SET expires=0 WHERE id=?', (self.item['id'],))
        self.assertEqual(self.claim()['operation_id'], claim['operation_id'])
        self.assertFalse(self.dispatch(claim))
        # Current write authorization must additionally be rechecked by the dispatcher.
        with self.assertRaises(ExecutionConflict): self.finish(claim, 'applied', claim['replacement_sha256'])

    def test_corrupt_execution_and_proposal_fail_closed(self):
        self.approve()
        claim = self.claim()
        self.runs.db.execute("UPDATE patch_executions SET replacement_sha256=?", ('c' * 64,))
        with self.assertRaises(ExecutionConflict): self.dispatch(claim)
        self.runs.db.execute('UPDATE patch_executions SET replacement_sha256=?', (claim['replacement_sha256'],))
        self.runs.db.execute("UPDATE approvals SET proposal='{}' WHERE id=?", (self.item['id'],))
        with self.assertRaises(ValueError): self.dispatch(claim)


if __name__ == '__main__':
    unittest.main()
