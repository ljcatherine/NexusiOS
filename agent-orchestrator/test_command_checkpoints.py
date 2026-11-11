"""Durable AI-requested fixed-profile command checkpoints across real RunJobs.

These fixtures never run shell: the model can only submit a fixed profile ID;
the host execution transport is simulated and counts every send. The separate
Go sandbox HTTP suite covers real host command execution and cancellation.
"""
import copy
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest

from command_dispatch import command_proof
from patch_review import ReviewError
from run_jobs import RunJobs
from test_approval_checkpoints import ProposalController, WORKSPACE
from test_command_approvals import proposal
from test_server import OWNER_ID


COMMAND = {'action': 'propose_command', 'profile_id': 'tests'}


class FixedCommandController(ProposalController):
    def __init__(self):
        super().__init__()
        self.command_executor_tokens = {'debian': 'host-executor-' + 'e' * 40}
        self.fixed = proposal()
        self.fixed['host'] = 'debian'
        self.completion_outputs = [json.dumps(COMMAND), json.dumps({'action': 'answer', 'response': 'Verified outcome recorded.'})]
        self.prepares = []
        self.sends = []
        self.host_receipt = None
        self.drop_reply = False
        self.allowed_actions = {'execute': True, 'propose': True}

    def authorize_workspace_operation(self, owner, workspace, operation):
        self.policy_calls.append((owner, workspace, operation))
        return owner == OWNER_ID and self.allowed_actions.get(operation, False)

    def list_workspace(self, host):
        assert host == 'debian'
        return {'host': host, 'workspaces': [{
            'id': 'code', 'name': 'Source', 'read_only': True,
            'generation': self.fixed['workspace_generation'],
            'capabilities': ['list', 'read_file', 'run_command']}]}

    def http_json(self, base, path, token='', method='GET', payload=None, **kwargs):
        if path.endswith('/commands/profiles?host=debian'):
            return {'host': 'debian', 'workspace_id': 'code', 'profiles': [{
                'id': 'tests', 'version': self.fixed['profile_version'],
                'invocation': copy.deepcopy(self.fixed['invocation'])}]}
        if path.endswith('/commands/prepare'):
            self.prepares.append(copy.deepcopy(payload))
            assert token == self.workspaces['debian'][1]
            captured = {key: copy.deepcopy(value) for key, value in self.fixed.items()
                        if key not in ('kind', 'host')}
            captured['snapshot_id'] = payload['snapshot_id']
            captured['expires_at'] = payload['expires_at']
            return {'host': 'debian', 'owner': payload['owner'], 'snapshot': captured}
        if path.endswith('/commands/execute'):
            assert token == self.command_executor_tokens['debian']
            assert payload['proof'] == command_proof(payload, token)
            self.sends.append(copy.deepcopy(payload))
            request = {key: value for key, value in payload.items() if key != 'proof'}
            result = {key: payload[key] for key in ('profile_id', 'profile_version',
                'input_digest', 'workspace_generation', 'snapshot_id')}
            result.update(stdout='checked file', stderr='', exit_code=0,
                          cancelled=False, timed_out=False, truncated=False)
            self.host_receipt = {'request': request, 'status': 'completed', 'result': result}
            if self.drop_reply:
                raise OSError('simulated lost reply after host committed receipt')
            return copy.deepcopy(self.host_receipt)
        if '/commands/receipts/' in path and path.endswith('/reconcile'):
            assert token == self.command_executor_tokens['debian']
            assert payload['proof'] == command_proof(payload, token)
            if self.host_receipt is None:
                raise OSError('not claimed on host')
            return copy.deepcopy(self.host_receipt)
        return super().http_json(base, path, token, method, payload, **kwargs)


class CommandCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.controller = FixedCommandController()
        self.prepares = self.controller.prepares
        self.sends = self.controller.sends
        self.jobs = RunJobs(self.controller, self.temp.name)

    def tearDown(self):
        self.jobs.close()
        self.temp.cleanup()

    def wait(self, run_id, status, timeout=4):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            item = self.jobs.store.get_owned(run_id, OWNER_ID)
            if item is not None and item['status'] == status:
                return item
            time.sleep(.01)
        self.fail(f'run never reached {status}: {item}')

    def waiting(self):
        run = self.jobs.submit({'prompt': 'Run the safe fixed tests', 'workspace': WORKSPACE,
                                'allow_proposals': True}, owner=OWNER_ID)
        return self.wait(run['id'], 'waiting_for_approval')

    def route(self, run):
        return '/v1/nexus/workspaces/debian/code/commands/' + run['approval_id']

    def saved_item(self, run):
        return self.jobs.checkpoints.command_review.store.get(OWNER_ID, run['approval_id'])

    def decision(self, run, decision='approve'):
        item = self.saved_item(run)
        return self.jobs.checkpoints.command_review.dispatch('POST', self.route(run) + '/decision',
            OWNER_ID, {'digest': item['digest'], 'decision': decision})

    def execute(self, run):
        item = self.saved_item(run)
        return self.jobs.checkpoints.command_review.dispatch('POST', self.route(run) + '/execute',
            OWNER_ID, {'digest': item['digest']})

    def test_model_can_only_request_fixed_profile_and_waits_for_two_human_actions(self):
        run = self.waiting()
        approval = self.saved_item(run)
        self.assertEqual(approval['origin'], 'agent')
        self.assertEqual(approval['proposal']['profile_id'], 'tests')
        self.assertEqual(len(self.prepares), 1)
        self.assertEqual(self.sends, [])
        self.assertEqual(self.controller.model_calls, 1)
        self.assertTrue(self.controller.capacity.acquire(timeout=1))
        self.controller.capacity.release()
        self.assertEqual(self.decision(run)[1]['command']['status'], 'approved')
        time.sleep(.15)
        self.assertEqual(self.sends, [], 'human approval must not execute the command')
        self.assertEqual(self.jobs.store.get_owned(run['id'], OWNER_ID)['status'], 'waiting_for_approval')
        self.assertEqual(self.execute(run)[0], 200)
        done = self.wait(run['id'], 'completed')
        self.assertEqual(len(self.sends), 1)
        self.assertEqual(done['result']['workspace_tools'][0]['tool'], 'propose_command')
        self.assertEqual(done['result']['workspace_tools'][0]['status'], 'completed')
        self.assertTrue(done['result']['workspace_tools'][0]['receipt_verified'])
        self.assertEqual(done['result']['workspace_tools'][0]['stdout'], 'checked file')
        self.assertEqual(self.controller.model_calls, 2)

    def test_rejection_resumes_without_execution_and_no_second_model_proposal(self):
        run = self.waiting()
        self.assertEqual(run['approval_kind'], 'command')
        self.assertEqual(run['approval_id'], self.saved_item(run)['id'])
        self.decision(run, 'reject')
        finished = self.wait(run['id'], 'completed')
        self.assertEqual(self.sends, [])
        self.assertEqual(finished['result']['workspace_tools'][0]['status'], 'rejected')
        self.assertFalse(finished['result']['workspace_tools'][0]['command_executed'])
        self.assertEqual(len(self.prepares), 1)
        self.assertEqual(self.controller.model_calls, 2)

    def test_saved_command_checkpoint_cannot_be_relabelled_as_patch(self):
        run = self.waiting()
        cp = self.jobs.checkpoints.latest(run['id'], OWNER_ID)
        altered = copy.deepcopy(cp['state'])
        altered['action'] = {'action': 'propose_patch', 'path': 'src/main.py', 'replacement': 'bad'}
        raw = json.dumps(altered, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        self.jobs.store.db.execute('UPDATE approval_checkpoints SET snapshot=?, checksum=? '
            'WHERE run_id=? AND step=?', (raw, hashlib.sha256(raw.encode()).hexdigest(), run['id'], cp['step']))
        hidden = self.jobs.store.get_owned(run['id'], OWNER_ID)
        self.assertIsNone(hidden['approval_kind'])
        self.assertIsNone(hidden['approval_id'])
        self.assertIsNone(self.jobs.store.get_owned(run['id'], 'b' * 64))

    def test_parent_cancel_disables_review_and_execution_even_if_approved(self):
        run = self.waiting()
        self.assertEqual(self.jobs.cancel(run['id'], owner=OWNER_ID)['status'], 'cancelled')
        with self.assertRaises(ReviewError) as decision:
            self.decision(run)
        self.assertEqual(decision.exception.status, 409)
        self.assertEqual(self.sends, [])

        self.controller.completion_outputs = [json.dumps(COMMAND), json.dumps({'action': 'answer', 'response': 'done'})]
        second = self.waiting()
        self.decision(second)
        self.assertEqual(self.jobs.cancel(second['id'], owner=OWNER_ID)['status'], 'cancelled')
        with self.assertRaises(ReviewError) as execution:
            self.execute(second)
        self.assertEqual(execution.exception.status, 409)
        self.assertEqual(self.sends, [])

    def test_parent_cancellation_during_profile_validation_blocks_late_dispatch(self):
        run = self.waiting()
        self.decision(run)
        checkpoint = self.jobs.checkpoints
        started, release = threading.Event(), threading.Event()
        normal = checkpoint.command_dispatcher._current_profile
        def block_profile(proposal):
            started.set()
            if not release.wait(timeout=3):
                raise TimeoutError('profile fixture never released')
            return normal(proposal)
        checkpoint.command_dispatcher._current_profile = block_profile
        failures = []
        def attempt():
            try:
                self.execute(run)
            except Exception as exc:
                failures.append(exc)
        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        try:
            self.assertTrue(started.wait(timeout=2), 'execution never reached live profile check')
            self.assertEqual(self.jobs.cancel(run['id'], owner=OWNER_ID)['status'], 'cancelled')
        finally:
            release.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ReviewError)
        self.assertEqual(failures[0].status, 409)
        self.assertEqual(self.sends, [])
        self.assertIsNone(checkpoint.command_review.store.get_execution(
            OWNER_ID, run['approval_id'], self.saved_item(run)['digest']))

    def test_restart_keeps_original_agent_review_and_no_model_or_command_replay(self):
        run = self.waiting()
        cp = self.jobs.checkpoints.latest(run['id'], OWNER_ID)
        self.jobs.close()
        self.jobs = RunJobs(self.controller, self.temp.name)
        restored = self.jobs.store.get_owned(run['id'], OWNER_ID)
        self.assertEqual(restored['approval_id'], run['approval_id'])
        self.assertEqual(self.jobs.checkpoints.latest(run['id'], OWNER_ID)['digest'], cp['digest'])
        self.assertEqual(self.controller.model_calls, 1)
        self.assertIsNone(self.jobs.checkpoints.reconcile(run['id'], OWNER_ID))
        self.assertEqual(len(self.prepares), 1)
        self.decision(run)
        self.assertEqual(self.sends, [])
        self.execute(run)
        done = self.wait(run['id'], 'completed')
        self.assertEqual(done['result']['workspace_tools'][0]['status'], 'completed')
        self.assertEqual(len(self.prepares), 1)
        self.assertEqual(len(self.sends), 1)

    def test_lost_host_reply_is_reconciled_from_original_signed_receipt(self):
        run = self.waiting()
        self.decision(run)
        self.controller.drop_reply = True
        with self.assertRaises(ReviewError) as lost:
            self.execute(run)
        self.assertEqual(lost.exception.status, 503)
        self.assertEqual(len(self.sends), 1)
        done = self.wait(run['id'], 'completed')
        self.assertEqual(done['result']['workspace_tools'][0]['status'], 'completed')
        self.assertEqual(len(self.sends), 1)
        self.assertEqual(self.controller.model_calls, 2)

    def test_stale_administrator_profile_after_capture_cannot_execute(self):
        run = self.waiting()
        self.decision(run)
        self.controller.fixed['profile_version'] = 'f' * 64
        with self.assertRaises(ReviewError) as stale:
            self.execute(run)
        self.assertEqual(stale.exception.status, 503)
        self.assertEqual(self.sends, [])
        self.assertIsNone(self.jobs.checkpoints.command_review.store.get_execution(
            OWNER_ID, run['approval_id'], self.saved_item(run)['digest']))

    def test_verified_unknown_exit_is_never_reported_as_success_or_reexecuted(self):
        run = self.waiting()
        self.decision(run)
        checkpoint = self.jobs.checkpoints
        item = self.saved_item(run)
        approval = checkpoint.command_review.store
        execution = approval.claim(OWNER_ID, item['id'], item['digest'])
        payload = checkpoint.command_dispatcher._request(OWNER_ID, item, execution,
            self.controller.command_executor_tokens['debian'], create=True)
        self.assertTrue(approval.start_dispatch(OWNER_ID, item['id'], item['digest'], execution['operation_id']))
        verified = {key: value for key, value in payload.items() if key != 'proof'}
        receipt = {'request': verified, 'status': 'interrupted', 'failure': 'exit_unknown'}
        approval.finish(OWNER_ID, item['id'], item['digest'], execution['operation_id'], receipt)
        done = self.wait(run['id'], 'completed')
        event = done['result']['workspace_tools'][0]
        self.assertEqual(event['status'], 'unknown_exit')
        self.assertTrue(event['execution_dispatched'])
        self.assertTrue(event['receipt_verified'])
        self.assertNotIn('stdout', event)
        self.assertEqual(self.sends, [])

    def test_parent_cancel_after_approval_claim_prevents_dispatch_before_host_send(self):
        run = self.waiting()
        self.decision(run)
        checkpoint = self.jobs.checkpoints
        started, release = threading.Event(), threading.Event()
        original_request = checkpoint.command_dispatcher._request
        def block_after_claim(*args, **kwargs):
            result = original_request(*args, **kwargs)
            if kwargs.get('create'):
                started.set()
                if not release.wait(timeout=3):
                    raise TimeoutError('test did not release dispatch fixture')
            return result
        checkpoint.command_dispatcher._request = block_after_claim
        failures = []
        worker = threading.Thread(target=lambda: self._attempt_execute(run, failures), daemon=True)
        worker.start()
        try:
            self.assertTrue(started.wait(timeout=2))
            self.assertEqual(self.jobs.cancel(run['id'], owner=OWNER_ID)['status'], 'cancelled')
        finally:
            release.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ReviewError)
        self.assertEqual(failures[0].status, 409)
        self.assertEqual(self.sends, [])
        recorded = checkpoint.command_review.store.get_execution(
            OWNER_ID, run['approval_id'], self.saved_item(run)['digest'])
        self.assertEqual(recorded['phase'], 'prepared')

    def _attempt_execute(self, run, failures):
        try:
            self.execute(run)
        except Exception as exc:
            failures.append(exc)

    def test_disabled_or_revoked_execute_grant_never_prepares_command(self):
        self.controller.allowed_actions['execute'] = False
        run = self.jobs.submit({'prompt': 'Propose tests', 'workspace': WORKSPACE,
                                'allow_proposals': True}, owner=OWNER_ID)
        failed = self.wait(run['id'], 'failed')
        self.assertEqual(failed['phase'], 'failed')
        self.assertEqual(self.prepares, [])
        self.assertEqual(self.sends, [])

    def test_tampered_checkpoint_fails_closed_without_execution(self):
        run = self.waiting()
        self.jobs.store.db.execute('UPDATE approval_checkpoints SET snapshot=? WHERE run_id=?',
                                   ('{}', run['id']))
        with self.assertRaises(ReviewError) as decision:
            self.decision(run)
        self.assertEqual(decision.exception.status, 409)
        self.wait(run['id'], 'failed')
        self.assertEqual(self.sends, [])

    def test_model_generated_arbitrary_arguments_never_capture_or_execute(self):
        self.controller.completion_outputs = [json.dumps({'action': 'propose_command',
            'profile_id': 'tests', 'arguments': ['--unsafe']}),
            json.dumps({'action': 'answer', 'response': 'No command was run'})]
        run = self.jobs.submit({'prompt': 'Unsafe proposal', 'workspace': WORKSPACE,
                                'allow_proposals': True}, owner=OWNER_ID)
        finished = self.wait(run['id'], 'completed')
        self.assertEqual(self.prepares, [])
        self.assertEqual(self.sends, [])
        self.assertEqual(finished['result']['workspace_tools'], [])


if __name__ == '__main__':
    unittest.main()
