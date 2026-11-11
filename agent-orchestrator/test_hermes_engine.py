import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from hermes_engine import DockerWorker, HermesEngine, HermesUnavailable, REVISION, flatten_messages
from test_server import FakeController, api

MESSAGES = [{'role': 'system', 'content': 'Nexus fixture'}, {'role': 'user', 'content': 'Inspect main.py'}]
WORKSPACE = {'host': 'debian', 'workspace_id': 'code', 'path': ''}


class LoopFixture:
    """Protocol fixture, not a substitute for the separate real-Hermes test."""
    def converse(self, request, handle, cancelled):
        self.request = request
        history = [{'role': 'system', 'content': request['system']}, *request['history']]
        result = handle({'kind': 'inference', 'messages': history})
        message = result['choices'][0]['message']
        if message.get('tool_calls'):
            history.append(message)
            call = message['tool_calls'][0]
            text = handle({'kind': 'tool', 'name': call['function']['name'],
                'arguments': json.loads(call['function']['arguments']), 'history': history})
            history.append({'role': 'tool', 'tool_call_id': call['id'], 'content': text})
            result = handle({'kind': 'inference', 'messages': history})
        return result['choices'][0]['message']['content']


class HermesTests(unittest.TestCase):
    def setUp(self):
        self.controller = FakeController()
        self.controller.context_limit_override = None
        self.controller.reported_context = 65536
        self.worker = LoopFixture()
        self.engine = HermesEngine(self.worker)

    def run_engine(self, **kwargs):
        state = dict(combined=[], prompt='Inspect', agents=[], workspace_context_bytes=0,
            model='ps5', output_budget=4096, context_window=65536, workspace=WORKSPACE, engine='hermes')
        return self.engine.run(self.controller, MESSAGES, 'ps5', 65536, 4096, WORKSPACE,
            lambda _: None, lambda: False, state, kwargs.pop('proposal_checkpoint', None), **kwargs)

    def test_actual_controller_selects_hermes_and_all_inference_uses_ps5_transport(self):
        self.controller.hermes_engine = self.engine
        self.controller.completion_outputs = ['{"action":"read_file","path":"src/main.py"}',
                                               '{"action":"answer","response":"Inspected the file"}']
        result = self.controller.run({'prompt': 'Inspect', 'workspace': WORKSPACE, 'engine': 'hermes'})
        self.assertEqual(result['response'], 'Inspected the file')
        self.assertEqual(result['workspace_tools'][0]['tool'], 'read_file')
        self.assertEqual(self.controller.last_completion_payload['model'], self.controller.model)
        self.assertEqual(self.controller.last_completion_payload['messages'], self.controller.last_tokenizer_payload['messages'])
        names = {tool['function']['name'] for tool in self.worker.request['tools']}
        self.assertEqual(names, {'search', 'read_file'})

    def test_unavailable_engine_and_small_context_do_not_start_worker_or_inference(self):
        with self.assertRaises(api.AgentError):
            self.controller.validate_run({'prompt': 'x', 'engine': 'hermes'})
        self.controller.hermes_engine = self.engine
        for bad in ('unknown', None, ['hermes']):
            with self.assertRaises(api.AgentError): self.controller.validate_run({'prompt': 'x', 'engine': bad})
        with self.assertRaises(HermesUnavailable):
            self.engine.run(self.controller, MESSAGES, 'ps5', 32768, 4096, WORKSPACE,
                lambda _: None, lambda: False, {}, None)
        self.assertFalse(hasattr(self.worker, 'request'))

    def test_controller_checks_hermes_context_before_subagent_or_summary_inference(self):
        self.controller.hermes_engine = self.engine
        self.controller.reported_context = 32768
        with self.assertRaises(api.AgentError) as raised:
            self.controller.run({'prompt': 'Inspect', 'workspace': WORKSPACE,
                                 'engine': 'hermes', 'subagents': 3})
        self.assertEqual(raised.exception.status, 413)
        self.assertIsNone(self.controller.last_completion_payload)
        self.assertFalse(hasattr(self.worker, 'request'))

    def test_unapproved_shell_and_proposals_never_reach_tools(self):
        for output in ('{"action":"shell","command":"id"}',
                       '{"action":"propose_patch","path":"main.py","replacement":"x"}'):
            self.controller.completion_outputs = [output]
            with self.assertRaises(HermesUnavailable): self.run_engine()
        self.assertEqual(self.controller.task_payloads, [])

    def test_proposal_saves_exact_hermes_continuation_before_suspending(self):
        class Suspended(Exception): pass
        captured = []
        def checkpoint(state):
            captured.append(state)
            raise Suspended()
        self.controller.completion_outputs = ['{"action":"propose_patch","path":"src/main.py","replacement":"new"}']
        with self.assertRaises(Suspended): self.run_engine(proposal_checkpoint=checkpoint)
        state = captured[0]
        self.assertEqual(state['engine'], 'hermes')
        self.assertEqual(state['hermes_revision'], REVISION)
        self.assertEqual(state['action']['replacement'], 'new')
        self.assertEqual(state['hermes_history'][-1]['tool_calls'][0]['id'], state['hermes_call_id'])
        self.assertEqual(self.controller.task_payloads, [])
        state['hermes_revision'] = 'changed'
        with self.assertRaises(HermesUnavailable):
            self.run_engine(resume={'state': state, 'step': 0, 'outcome': {'status': 'rejected'}})

    def test_context_and_history_validation_precede_inference(self):
        self.controller.tokenizer = lambda _: 65000
        with self.assertRaises(HermesUnavailable): self.run_engine()
        self.assertIsNone(self.controller.last_completion_payload)
        for bad in ([{'role': 'system', 'content': {'not': 'text'}}],
                    [{'role': 'assistant', 'tool_calls': [{'function': {'name': 'shell', 'arguments': '{}'}}]}]):
            with self.assertRaises(HermesUnavailable): flatten_messages(bad, {'read_file'})

    def test_docker_image_must_be_immutable_and_executable_explicit(self):
        for executable, image in (('/does-not-exist/docker', 'sha256:' + 'a' * 64),
                                  ('docker', 'sha256:' + 'a' * 64), ('/bin/true', 'nexus-hermes:local')):
            with self.assertRaises(HermesUnavailable): DockerWorker(executable, image)

    def test_leftover_worker_blocks_new_admission_even_after_adapter_restart(self):
        worker = DockerWorker(sys.executable, 'sha256:' + 'a' * 64)
        labels = json.dumps({'org.nexus.hermes.revision': REVISION, 'org.nexus.hermes.protocol': '1'}).encode()
        with patch('hermes_engine.subprocess.run', side_effect=[
                subprocess.CompletedProcess([], 0, labels),
                subprocess.CompletedProcess([], 0, b'nexus-hermes-leftover\n')]), \
                patch('hermes_engine.subprocess.Popen') as launch:
            with self.assertRaises(HermesUnavailable): worker.converse({}, lambda _: None, lambda: False)
            launch.assert_not_called()

    def test_failed_cleanup_quarantines_further_admissions(self):
        worker = DockerWorker(sys.executable, 'sha256:' + 'a' * 64)
        with patch('hermes_engine.subprocess.run', return_value=subprocess.CompletedProcess([], 1)):
            worker._remove('nexus-hermes-fixture')
        with patch('hermes_engine.subprocess.run') as run:
            with self.assertRaises(HermesUnavailable): worker.converse({}, lambda _: None, lambda: False)
            run.assert_not_called()

    @unittest.skipUnless(os.environ.get('NEXUS_HERMES_TEST_IMAGE'), 'requires locally built pinned Hermes image')
    def test_real_pinned_hermes_loop_in_networkless_container(self):
        self.engine.worker = DockerWorker(os.environ['NEXUS_HERMES_TEST_DOCKER'], os.environ['NEXUS_HERMES_TEST_IMAGE'])
        self.controller.completion_outputs = ['{"action":"read_file","path":"src/main.py"}',
                                               '{"action":"answer","response":"Verified Hermes loop"}']
        result = self.run_engine()
        self.assertEqual(result[0], 'Verified Hermes loop')
        self.assertEqual(result[3][0]['tool'], 'read_file')

    @unittest.skipUnless(os.environ.get('NEXUS_HERMES_TEST_IMAGE'), 'requires locally built pinned Hermes image')
    def test_real_hermes_proposal_resumes_in_a_new_worker_after_review(self):
        class Suspended(Exception): pass
        captured = []
        def checkpoint(state):
            captured.append(state)
            raise Suspended()
        self.engine.worker = DockerWorker(os.environ['NEXUS_HERMES_TEST_DOCKER'], os.environ['NEXUS_HERMES_TEST_IMAGE'])
        self.controller.completion_outputs = ['{"action":"propose_patch","path":"src/main.py","replacement":"new"}']
        with self.assertRaises(Suspended): self.run_engine(proposal_checkpoint=checkpoint)
        self.controller.completion_outputs = ['{"action":"answer","response":"Review rejected; no changes"}']
        result = self.run_engine(proposal_checkpoint=checkpoint, resume={'state': captured[0], 'step': 0,
            'outcome': {'status': 'rejected', 'changes_applied': False}})
        self.assertEqual(result[0], 'Review rejected; no changes')
        self.assertEqual(result[3][0]['status'], 'rejected')
        self.assertEqual(len(captured), 1)
        self.assertEqual(self.controller.task_payloads, [])

    @unittest.skipUnless(os.environ.get('NEXUS_HERMES_TEST_IMAGE'), 'requires locally built pinned Hermes image')
    def test_cancelled_container_is_removed_without_starting_inference(self):
        worker = DockerWorker(os.environ['NEXUS_HERMES_TEST_DOCKER'], os.environ['NEXUS_HERMES_TEST_IMAGE'])
        polls = []
        def cancelled():
            polls.append(True)
            return len(polls) >= 3
        with self.assertRaises(InterruptedError):
            worker.converse({}, lambda frame: self.fail('cancelled worker requested inference'), cancelled)
        self.assertFalse(worker.quarantined)


if __name__ == '__main__':
    unittest.main()
