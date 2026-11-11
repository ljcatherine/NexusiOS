import os
import hashlib
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from approvals import ApprovalConflict, ApprovalStore
from run_jobs import RunStore
from patch_execution import ExecutionConflict, PatchExecutionStore

OWNER = 'a' * 64
OTHER = 'b' * 64


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        os.chmod(self.directory.name, 0o700)
        self.runs = RunStore(self.directory.name)
        self.store = ApprovalStore(self.runs)
        self.executions = PatchExecutionStore(self.store)
        self.proposal = {'host': 'nixos', 'workspace_id': 'project', 'path': 'src/main.py',
                         'original': 'print("old")\n',
                         'base_sha256': hashlib.sha256(b'print("old")\n').hexdigest(), 'replacement': 'print("new")\n'}

    def claim(self, item):
        try:
            record = self.executions.claim(OWNER, item['id'], item['digest'])
        except (ExecutionConflict, ValueError):
            return False
        return self.executions.start_dispatch(OWNER, item['id'], item['digest'], record['operation_id'])

    def test_provenance_is_atomic_immutable_and_preserved_on_legacy_retry(self):
        submission = 'c' * 32
        def propose(origin):
            try:
                return self.store.propose(OWNER, self.proposal, submission_id=submission, origin=origin)
            except ApprovalConflict:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(propose, ('manual', 'agent')))
        item = next(value for value in results if value is not None)
        self.assertEqual(sum(value is not None for value in results), 1)
        origin = self.store.origin(OWNER, item['id'])
        self.assertIn(origin, ('manual', 'agent'))
        self.assertEqual(self.store.propose(OWNER, self.proposal, submission_id=submission, origin=origin), item)
        with self.assertRaises(ApprovalConflict):
            self.store.origin(OTHER, item['id'])
        # An old record must never gain manual execution authority on retry.
        self.runs.db.execute('DELETE FROM approval_origins WHERE approval_id=?', (item['id'],))
        self.assertEqual(self.store.propose(OWNER, self.proposal, submission_id=submission, origin='manual'), item)
        self.assertEqual(self.store.origin(OWNER, item['id']), 'legacy')

    def tearDown(self):
        self.runs.close()
        self.directory.cleanup()

    def test_approval_is_owner_and_exact_content_bound_and_single_use(self):
        item = self.store.propose(OWNER, self.proposal)
        self.assertIsNone(self.store.get(OTHER, item['id']))
        self.assertFalse(self.store.transition(OTHER, item['id'], item['digest'], expected='pending', target='approved'))
        self.assertFalse(self.store.transition(OWNER, item['id'], 'd' * 64, expected='pending', target='approved'))
        self.assertTrue(self.store.transition(OWNER, item['id'], item['digest'], expected='pending', target='approved'))
        self.assertFalse(self.store.transition(OWNER, item['id'], item['digest'], expected='pending', target='approved'))
        with self.assertRaises(ValueError):
            self.store.transition(OWNER, item['id'], item['digest'], expected='approved', target='executing')
        def claim(_):
            return self.claim(item)
        with ThreadPoolExecutor(max_workers=8) as executor:
            self.assertEqual(sum(executor.map(claim, range(16))), 1)
        self.assertEqual(self.store.get(OWNER, item['id'])['status'], 'executing')

    def test_expired_or_rejected_proposals_cannot_be_claimed(self):
        item = self.store.propose(OWNER, self.proposal, ttl=1)
        self.runs.db.execute('UPDATE approvals SET expires=? WHERE id=?', (time.time() - 1, item['id']))
        self.assertFalse(self.store.transition(OWNER, item['id'], item['digest'], expected='pending', target='approved'))
        other = self.store.propose(OWNER, self.proposal)
        self.assertTrue(self.store.transition(OWNER, other['id'], other['digest'], expected='pending', target='rejected'))
        self.assertFalse(self.claim(other))

    def test_invalid_paths_and_oversized_content_are_rejected(self):
        for path in ('../secrets', '/etc/passwd', 'a/.hidden', 'a//b', 'a\\b', ''):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.store.propose(OWNER, {**self.proposal, 'path': path})
        with self.assertRaises(ValueError):
            self.store.propose(OWNER, {**self.proposal, 'replacement': 'x' * (64 * 1024 + 1)})
        with self.assertRaises(ValueError):
            self.store.propose(OWNER, {**self.proposal, 'base_sha256': 'not-a-hash'})

    def test_proposal_is_immutable_and_corruption_fails_closed(self):
        item = self.store.propose(OWNER, self.proposal)
        self.proposal['replacement'] = 'changed after submission'
        self.assertEqual(self.store.get(OWNER, item['id'])['proposal']['replacement'], 'print("new")\n')

        self.runs.db.execute('UPDATE approvals SET proposal=? WHERE id=?',
                             ('{"replacement":"tampered"}', item['id']))
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.store.get(OWNER, item['id'])
        self.assertFalse(self.store.transition(OWNER, item['id'], item['digest'],
                                               expected='pending', target='approved'))

    def test_executing_claim_persists_across_restart_without_replay(self):
        item = self.store.propose(OWNER, self.proposal)
        self.assertTrue(self.store.transition(OWNER, item['id'], item['digest'], expected='pending', target='approved'))
        self.assertTrue(self.claim(item))
        self.runs.close()
        self.runs = RunStore(self.directory.name)
        self.store = ApprovalStore(self.runs)
        self.executions = PatchExecutionStore(self.store)
        self.assertEqual(self.store.get(OWNER, item['id'])['status'], 'executing')
        self.assertFalse(self.claim(item))

    def test_submission_retries_are_atomic_persistent_and_content_bound(self):
        submission_id = 'd' * 32
        with ThreadPoolExecutor(max_workers=8) as executor:
            items = list(executor.map(lambda _: self.store.propose(OWNER, self.proposal, submission_id=submission_id), range(16)))
        self.assertEqual(len({item['id'] for item in items}), 1)
        self.assertEqual(len(self.store.list_scope(OWNER, 'nixos', 'project')), 1)
        self.assertEqual(self.store.list_scope(OTHER, 'nixos', 'project'), [])
        with self.assertRaises(ApprovalConflict):
            self.store.propose(OWNER, {**self.proposal, 'replacement': 'different'}, submission_id=submission_id)
        self.runs.close()
        self.runs = RunStore(self.directory.name)
        self.store = ApprovalStore(self.runs)
        self.executions = PatchExecutionStore(self.store)
        self.assertEqual(self.store.get_submission(OWNER, submission_id)['id'], items[0]['id'])
        self.assertEqual(self.store.propose(OWNER, self.proposal, submission_id=submission_id)['id'], items[0]['id'])

    def test_snapshot_hash_must_match_original(self):
        with self.assertRaises(ValueError):
            self.store.propose(OWNER, {**self.proposal, 'original': 'different baseline'})


if __name__ == '__main__':
    unittest.main()
