"""Opt-in actual Hermes containers; PS5 responses are explicit local fixtures."""
import json
import os
import subprocess
import tempfile
import time
import unittest

from hermes_engine import DockerWorker, HermesEngine
from run_jobs import RunJobs, SubmissionConflict
from test_approval_checkpoints import ProposalController, WORKSPACE
from test_server import OWNER_ID


@unittest.skipUnless(os.environ.get('NEXUS_HERMES_TEST_IMAGE'), 'requires pinned local Hermes image')
class HermesDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.docker = os.environ['NEXUS_HERMES_TEST_DOCKER']
        self.image = os.environ['NEXUS_HERMES_TEST_IMAGE']
        self.controller = ProposalController()
        self.controller.reported_context = 65536
        self.controller.context_limit_override = None
        self.controller.hermes_engine = HermesEngine(DockerWorker(self.docker, self.image))
        self.jobs = RunJobs(self.controller, self.temp.name)

    def tearDown(self):
        self.jobs.close()
        self.temp.cleanup()

    def wait(self, run_id, status):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            item = self.jobs.store.get_owned(run_id, OWNER_ID)
            if item['status'] == status:
                return item
            if item['status'] in ('failed', 'cancelled'):
                self.fail(f'Unexpected terminal task: {item["phase"]}')
            time.sleep(.05)
        self.fail(f'Expected {status}, got {item["status"]}')

    def test_hermes_checkpoint_survives_scheduler_restart_without_replaying_proposal(self):
        payload = dict(prompt='Propose a change', workspace=WORKSPACE, engine='hermes',
                       allow_proposals=True, submission_id='e' * 32)
        run = self.jobs.submit(payload, owner=OWNER_ID)
        waiting = self.wait(run['id'], 'waiting_for_approval')
        self.assertIsNone(self.jobs.store.get_owned(run['id'], 'b' * 64))
        with self.assertRaises(SubmissionConflict):
            self.jobs.submit({**payload, 'engine': 'nexus'}, owner=OWNER_ID)
        self.jobs.close()
        self.jobs = RunJobs(self.controller, self.temp.name)
        approval = self.jobs.checkpoints.review.store.get(OWNER_ID, waiting['approval_id'])
        self.assertTrue(self.jobs.checkpoints.review.store.transition(OWNER_ID,
            approval['id'], approval['digest'], expected='pending', target='rejected'))
        done = self.wait(run['id'], 'completed')
        self.assertEqual(done['result']['response'], 'Review resolved.')
        self.assertEqual(done['result']['workspace_tools'][0]['status'], 'rejected')
        self.assertFalse(done['result']['workspace_tools'][0]['changes_applied'])
        self.assertEqual(self.controller.model_calls, 2)
        self.assertEqual(self.jobs.store.db.execute('SELECT COUNT(*) FROM approvals').fetchone()[0], 1)

    def test_actual_container_has_no_egress_project_mounts_or_root_write_access(self):
        self.controller.completion_outputs = ['{"action":"answer","response":"Isolation verified"}']
        inference = self.controller.stream_completion
        probed = []
        def probe(payload, cancelled):
            ids = subprocess.check_output([self.docker, 'ps', '--filter', 'ancestor=' + self.image,
                '--filter', 'name=nexus-hermes-', '--format', '{{.ID}}'], text=True).split()
            self.assertEqual(len(ids), 1)
            info = json.loads(subprocess.check_output([self.docker, 'inspect', ids[0]]))[0]
            host = info['HostConfig']
            self.assertEqual(host['NetworkMode'], 'none')
            self.assertTrue(host['ReadonlyRootfs'])
            self.assertEqual(host['Memory'], 1024 ** 3)
            self.assertEqual(host['MemorySwap'], 1024 ** 3)
            self.assertEqual(host['PidsLimit'], 64)
            self.assertEqual(host['CapDrop'], ['ALL'])
            self.assertIn('no-new-privileges', host['SecurityOpt'])
            self.assertFalse(info['Mounts'])
            code = ('import os,socket,json\n'
                's=socket.socket();s.settimeout(.2)\n'
                'try: s.connect(("1.1.1.1",443)); network=True\n'
                'except OSError: network=False\n'
                'try: open("/nexus-write-probe","w"); writable=True\n'
                'except OSError: writable=False\n'
                'print(json.dumps(dict(uid=os.getuid(),network=network,writable=writable)))')
            result = json.loads(subprocess.check_output([self.docker, 'exec', ids[0],
                '/opt/venv/bin/python', '-c', code]))
            self.assertEqual(result, {'uid': 65534, 'network': False, 'writable': False})
            probed.append(True)
            return inference(payload, cancelled)
        self.controller.stream_completion = probe
        run = self.jobs.submit(dict(prompt='Inspect', workspace=WORKSPACE, engine='hermes'), owner=OWNER_ID)
        self.assertEqual(self.wait(run['id'], 'completed')['result']['response'], 'Isolation verified')
        self.assertEqual(probed, [True])


if __name__ == '__main__':
    unittest.main()
