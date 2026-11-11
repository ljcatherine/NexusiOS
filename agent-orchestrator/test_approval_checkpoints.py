"""Proposal checkpoints tested through the scheduler and real SQLite journal."""
import hashlib
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from approval_checkpoints import ApprovalCheckpoints
from run_jobs import RunJobs, RunStore
from test_server import FakeController, OWNER_ID, TOKEN, api

WORKSPACE = dict(host='debian', workspace_id='code', path='')
ACTION = dict(action='propose_patch', path='src/main.py', replacement='print(42)')


class ProposalController(FakeController):
    def __init__(self):
        super().__init__()
        self.review_token = 'r' * 40
        self.policy_calls = []
        self.proposal_allowed = True
        self.model_calls = 0
        self.context_calls = 0
        self.completion_outputs = [json.dumps(ACTION), json.dumps(dict(action='answer', response='Review resolved.'))]

    def authorize_workspace_operation(self, owner, workspace, operation):
        self.policy_calls.append((owner, workspace, operation))
        return self.proposal_allowed

    def workspace_file_context(self, host, root, path):
        self.context_calls += 1
        return dict(host=host, workspace_id=root, path=path, text='print(1)', size_bytes=8)

    def stream_completion(self, payload, cancelled):
        self.model_calls += 1
        return super().stream_completion(payload, cancelled)


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.controller = ProposalController()
        self.jobs = RunJobs(self.controller, self.temp.name)

    def tearDown(self):
        self.jobs.close()
        self.temp.cleanup()

    def wait(self, run_id, status):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            item = self.jobs.store.get_owned(run_id, OWNER_ID)
            if item['status'] == status:
                return item
            time.sleep(.01)
        self.fail(f'Expected {status}; got {item}')

    def submit(self, **extra):
        return self.jobs.submit(dict(prompt='Propose the edit', workspace=WORKSPACE,
                                     allow_proposals=True, **extra), owner=OWNER_ID)

    def waiting(self):
        run = self.submit()
        return self.wait(run['id'], 'waiting_for_approval')

    def decide(self, run, target):
        approval = self.jobs.checkpoints.review.store.get(OWNER_ID, run['approval_id'])
        self.assertTrue(self.jobs.checkpoints.review.store.transition(
            OWNER_ID, approval['id'], approval['digest'], expected='pending', target=target))
        return approval

    def test_wait_releases_capacity_exposes_only_approval_metadata_and_never_applies(self):
        run = self.waiting()
        self.assertEqual(run['approval_kind'], 'patch')
        self.assertTrue(self.controller.capacity.acquire(timeout=1))
        self.controller.capacity.release()
        self.assertEqual(self.jobs.active(), 0)
        self.assertEqual(self.controller.model_calls, 1)
        self.assertIsNone(run['result'])
        self.assertNotIn('replacement', json.dumps(run))
        self.assertEqual(self.controller.policy_calls, [(OWNER_ID, WORKSPACE, 'propose')])
        self.assertIsNone(self.jobs.store.get_owned(run['id'], 'b' * 64))
        self.assertIsNone(self.jobs.checkpoints.latest(run['id'], 'b' * 64))

    def test_approval_alone_does_not_resume_but_exact_applied_receipt_does(self):
        run = self.waiting()
        approval = self.decide(run, 'approved')
        self.assertIsNone(self.jobs.checkpoints.reconcile(run['id'], OWNER_ID))
        self.assertEqual(self.controller.model_calls, 1)
        executions = self.jobs.checkpoints.executions
        claim = executions.claim(OWNER_ID, approval['id'], approval['digest'])
        self.assertTrue(executions.start_dispatch(OWNER_ID, approval['id'], approval['digest'], claim['operation_id']))
        with self.assertRaises(Exception):
            executions.finish(OWNER_ID, approval['id'], approval['digest'], claim['operation_id'], 'applied', '0' * 64)
        executions.finish(OWNER_ID, approval['id'], approval['digest'], claim['operation_id'],
                          'applied', hashlib.sha256(ACTION['replacement'].encode()).hexdigest())
        done = self.wait(run['id'], 'completed')
        self.assertEqual(done['result']['workspace_tools'][0]['status'], 'applied')
        self.assertEqual(self.controller.model_calls, 2)

    def test_rejection_continues_with_explicit_no_changes_result(self):
        run = self.waiting()
        self.decide(run, 'rejected')
        done = self.wait(run['id'], 'completed')
        event = done['result']['workspace_tools'][0]
        self.assertEqual(event['status'], 'rejected')
        self.assertFalse(event['changes_applied'])
        self.assertIn('"changes_applied": false', self.controller.last_completion_payload['messages'][-1]['content'])

    def test_expired_proposal_resumes_without_claiming_applied(self):
        run = self.waiting()
        self.jobs.store.db.execute('UPDATE approvals SET expires=0 WHERE id=?', (run['approval_id'],))
        done = self.wait(run['id'], 'completed')
        self.assertEqual(done['result']['workspace_tools'][0]['status'], 'expired')
        self.assertFalse(done['result']['workspace_tools'][0]['changes_applied'])

    def test_cancel_waiting_survives_restart_even_if_approved(self):
        run = self.waiting()
        self.assertIsNone(self.jobs.cancel(run['id'], owner='b' * 64))
        cancelled = self.jobs.cancel(run['id'], owner=OWNER_ID)
        self.assertEqual(cancelled['status'], 'cancelled')
        self.decide(run, 'approved')
        self.jobs.close()
        self.jobs = RunJobs(self.controller, self.temp.name)
        self.assertEqual(self.jobs.store.get(run['id'])['status'], 'cancelled')
        self.assertEqual(self.controller.model_calls, 1)

    def test_restart_reuses_proposal_then_rejection_without_replaying_subagents(self):
        self.controller.completion_outputs.insert(0, 'subagent facts')
        run = self.submit(subagents=1)
        run = self.wait(run['id'], 'waiting_for_approval')
        cp = self.jobs.checkpoints.latest(run['id'], OWNER_ID)
        calls = self.controller.model_calls
        self.jobs.close()
        self.jobs = RunJobs(self.controller, self.temp.name)
        restored = self.jobs.store.get_owned(run['id'], OWNER_ID)
        self.assertEqual(restored['approval_id'], run['approval_id'])
        self.assertEqual(self.controller.model_calls, calls)
        self.decide(run, 'rejected')
        done = self.wait(run['id'], 'completed')
        self.assertEqual(self.controller.model_calls, calls + 1)
        self.assertEqual(done['result']['subagents'], cp['state']['agents'])
        self.assertEqual(self.jobs.store.db.execute('SELECT COUNT(*) FROM approvals').fetchone()[0], 1)

    def test_ambiguous_execution_remains_waiting_even_after_expiry(self):
        run = self.waiting()
        approval = self.decide(run, 'approved')
        executions = self.jobs.checkpoints.executions
        claim = executions.claim(OWNER_ID, approval['id'], approval['digest'])
        executions.start_dispatch(OWNER_ID, approval['id'], approval['digest'], claim['operation_id'])
        executions.finish(OWNER_ID, approval['id'], approval['digest'], claim['operation_id'], 'uncertain')
        self.jobs.store.db.execute('UPDATE approvals SET expires=0 WHERE id=?', (approval['id'],))
        self.assertIsNone(self.jobs.checkpoints.reconcile(run['id'], OWNER_ID))
        self.assertEqual(self.jobs.store.get(run['id'])['status'], 'waiting_for_approval')
        self.assertEqual(self.controller.model_calls, 1)

    def test_waiting_run_revoked_before_resume_does_not_publish_result(self):
        run = self.waiting()
        self.controller.authorize_run = lambda *_: False
        self.decide(run, 'rejected')
        failed = self.wait(run['id'], 'failed')
        self.assertEqual(failed['phase'], 'authorization revoked')
        self.assertIsNone(failed['result'])
        self.assertEqual(self.controller.model_calls, 1)

    def test_uncached_proposal_denial_creates_no_approval_or_retry(self):
        self.controller.proposal_allowed = False
        run = self.submit()
        self.wait(run['id'], 'failed')
        self.assertEqual(self.controller.model_calls, 1)
        self.assertEqual(len(self.controller.policy_calls), 1)
        self.assertEqual(self.jobs.store.db.execute('SELECT COUNT(*) FROM approvals').fetchone()[0], 0)

    def test_second_proposal_has_distinct_stable_step_and_rechecks_policy(self):
        second = dict(ACTION, replacement='print(43)')
        self.controller.completion_outputs = [json.dumps(ACTION), json.dumps(second), json.dumps(dict(action='answer', response='No changes.'))]
        run = self.waiting()
        first_id = run['approval_id']
        self.decide(run, 'rejected')
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            run = self.jobs.store.get_owned(run['id'], OWNER_ID)
            if run['status'] == 'waiting_for_approval' and run['approval_id'] and run['approval_id'] != first_id:
                break
            time.sleep(.01)
        self.assertNotEqual(run['approval_id'], first_id)
        self.assertEqual(len(self.controller.policy_calls), 2)
        self.decide(run, 'rejected')
        done = self.wait(run['id'], 'completed')
        self.assertEqual(len(done['result']['workspace_tools']), 2)

    def test_corrupt_checkpoint_fails_closed_without_model_call(self):
        run = self.waiting()
        self.jobs.store.db.execute("UPDATE approval_checkpoints SET snapshot='{}' WHERE run_id=?", (run['id'],))
        self.wait(run['id'], 'failed')
        self.assertEqual(self.controller.model_calls, 1)

    def test_no_whole_run_retry_for_proposal_enabled_upstream_failure(self):
        with patch.object(self.controller, 'context', side_effect=api.AgentError(503, 'unavailable')):
            run = self.submit()
            self.wait(run['id'], 'failed')
        self.assertEqual(self.controller.model_calls, 0)

    def test_waiting_patch_dispatch_does_not_block_an_unrelated_inference_run(self):
        original = self.controller.workspace_file_context
        self.controller.workspace_file_context = lambda *args: {**original(*args), 'workspace_generation': 'c' * 64}
        self.controller.workspace_executor_tokens = {'debian': 'e' * 40}
        started, release = threading.Event(), threading.Event()
        def blocked_apply(*args, **kwargs):
            started.set()
            release.wait(timeout=4)
        self.jobs.checkpoints.dispatcher.apply = blocked_apply
        parent = self.waiting()
        self.decide(parent, 'approved')
        try:
            self.assertTrue(started.wait(timeout=2))
            other = self.jobs.submit(dict(prompt='Independent read-only inference'), owner=OWNER_ID)
            self.wait(other['id'], 'completed')
            self.assertEqual(self.jobs.store.get(parent['id'])['status'], 'waiting_for_approval')
        finally:
            release.set()

    def test_expiry_cannot_report_no_changes_from_a_stale_prepared_read(self):
        run = self.waiting()
        item = self.decide(run, 'approved')
        self.jobs.stopping.set()
        self.jobs.worker.join(timeout=2)
        self.assertFalse(self.jobs.worker.is_alive())
        executions = self.jobs.checkpoints.executions
        claim = executions.claim(OWNER_ID, item['id'], item['digest'])
        original_get = executions.get
        calls = 0
        later_clock = patch('approval_checkpoints.time.time', return_value=item['expires_at'] + 1)
        clock_started = False
        def stale_read(*args):
            nonlocal calls, clock_started
            current = original_get(*args)
            calls += 1
            if calls == 1:
                self.assertTrue(executions.start_dispatch(OWNER_ID, item['id'], item['digest'], claim['operation_id']))
                later_clock.start()
                clock_started = True
            return current
        try:
            with patch.object(executions, 'get', side_effect=stale_read):
                self.assertIsNone(self.jobs.checkpoints.reconcile(run['id'], OWNER_ID))
            self.assertIsNone(self.jobs.checkpoints.latest(run['id'], OWNER_ID)['outcome'])
            self.assertEqual(original_get(OWNER_ID, item['id'], item['digest'])['phase'], 'dispatching')
        finally:
            if clock_started: later_clock.stop()


class CheckpointContractTests(unittest.TestCase):
    def test_flag_and_strict_tool_validation(self):
        controller = ProposalController()
        for value in (None, 0, 1, 'true', [], {}):
            with self.subTest(value=value), self.assertRaises(api.AgentError):
                controller.validate_run(dict(prompt='test', workspace=WORKSPACE, allow_proposals=value))
        for request in (dict(prompt='test', allow_proposals=True),
                        dict(prompt='test', workspace=WORKSPACE, allow_proposals=True, compact_only=True)):
            with self.assertRaises(api.AgentError):
                controller.validate_run(request)
        for action in (dict(ACTION, path='../escape'), dict(ACTION, host='nixos'),
                       dict(ACTION, replacement='é' * 32769), dict(ACTION, replacement='\0')):
            self.assertEqual(controller.parse_workspace_action(json.dumps(action)), dict(action='invalid'))
        self.assertEqual(controller.parse_workspace_action(json.dumps(dict(ACTION, replacement='é' * 32768)))['action'], 'propose_patch')

    def test_disabled_review_refuses_proposal_runs_before_queueing(self):
        controller = ProposalController()
        controller.review_token = ''
        with tempfile.TemporaryDirectory() as directory:
            jobs = RunJobs(controller, directory)
            try:
                with self.assertRaises(api.AgentError) as raised:
                    jobs.submit(dict(prompt='Propose an edit', workspace=WORKSPACE,
                                     allow_proposals=True), owner=OWNER_ID)
                self.assertEqual(raised.exception.status, 503)
                self.assertEqual(controller.model_calls, 0)
                self.assertEqual(jobs.store.list(owner=OWNER_ID), [])
            finally:
                jobs.close()


    def test_prepared_checkpoint_crash_recovers_exact_submission_without_new_model_output(self):
        controller = ProposalController()
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root)
            run = store.create(dict(prompt='test', workspace=WORKSPACE, allow_proposals=True), [], owner=OWNER_ID)
            store.update(run['id'], status='running')
            checkpoints = ApprovalCheckpoints(store, controller)
            state = dict(step=0, workspace=WORKSPACE, action=ACTION, messages=[], proposal=json.dumps(ACTION))
            with patch.object(checkpoints, 'publish', side_effect=OSError('simulated crash')):
                with self.assertRaises(OSError):
                    checkpoints.suspend(run['id'], OWNER_ID, state)
            store.close()
            store = RunStore(root)
            try:
                checkpoints = ApprovalCheckpoints(store, controller)
                self.assertEqual(store.get(run['id'])['status'], 'waiting_for_approval')
                self.assertIsNone(checkpoints.reconcile(run['id'], OWNER_ID))
                first = checkpoints.latest(run['id'], OWNER_ID)
                checkpoints.publish(run['id'], OWNER_ID)
                self.assertEqual(checkpoints.latest(run['id'], OWNER_ID)['approval_id'], first['approval_id'])
                self.assertEqual(controller.model_calls, 0)
                with self.assertRaises(ValueError):
                    checkpoints.suspend(run['id'], OWNER_ID, dict(state, action=dict(ACTION, replacement='changed')))
            finally:
                store.close()

    def test_crash_after_approval_creation_recovers_same_identity_and_original(self):
        controller = ProposalController()
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root)
            run = store.create(dict(prompt='test', workspace=WORKSPACE, allow_proposals=True), [], owner=OWNER_ID)
            store.update(run['id'], status='running')
            checkpoints = ApprovalCheckpoints(store, controller)
            state = dict(step=0, workspace=WORKSPACE, action=ACTION, messages=[], proposal=json.dumps(ACTION))
            with patch.object(store, 'update', side_effect=OSError('crash at association')):
                with self.assertRaises(OSError):
                    checkpoints.suspend(run['id'], OWNER_ID, state)
            approval_id = store.db.execute('SELECT id FROM approvals').fetchone()[0]
            reads = controller.context_calls
            store.close()
            store = RunStore(root)
            try:
                checkpoints = ApprovalCheckpoints(store, controller)
                self.assertIsNone(checkpoints.reconcile(run['id'], OWNER_ID))
                self.assertEqual(checkpoints.latest(run['id'], OWNER_ID)['approval_id'], approval_id)
                self.assertEqual(controller.context_calls, reads)
                self.assertEqual(controller.model_calls, 0)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM approvals').fetchone()[0], 1)
            finally:
                store.close()

    def test_interrupted_proposal_run_without_checkpoint_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root)
            run = store.create(dict(prompt='test', workspace=WORKSPACE, allow_proposals=True), [], owner=OWNER_ID)
            store.update(run['id'], status='running')
            store.close()
            store = RunStore(root)
            try:
                self.assertEqual(store.get(run['id'])['status'], 'failed')
                self.assertEqual(store.queued_ids(), [])
            finally:
                store.close()

    def test_native_http_status_preserves_owner_and_approval_id(self):
        controller = ProposalController()
        server = api.Service(('127.0.0.1', 0), controller)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            run = server.jobs.submit(dict(prompt='test', workspace=WORKSPACE, allow_proposals=True), owner=OWNER_ID)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and server.jobs.store.get(run['id'])['status'] != 'waiting_for_approval':
                time.sleep(.01)
            for owner, expected in ((OWNER_ID, 200), ('b' * 64, 404)):
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port)
                conn.request('GET', '/v1/nexus/agent-runs/' + run['id'], headers={
                    'Authorization': 'Bearer ' + TOKEN, 'X-Nexus-Principal': owner})
                response = conn.getresponse()
                body = json.loads(response.read())
                self.assertEqual(response.status, expected)
                if expected == 200:
                    self.assertEqual(body['status'], 'waiting_for_approval')
                    self.assertRegex(body['approval_id'], r'^[0-9a-f]{32}$')
                    self.assertEqual(body['approval_kind'], 'patch')
                conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
