"""Real Python approval/dispatch -> static Go bridge -> confined helper fixture."""
import hashlib
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.request import urlopen

from approvals import ApprovalStore
from patch_dispatch import PatchDispatcher
from patch_review import PatchReview, ReviewError
from run_jobs import RunStore
from test_server import api, OWNER_ID

BWRAP = '/nix/store/3hqwbwxij9lxhyrf2amsm2xg24xszmmx-bubblewrap-0.12.0/bin/bwrap'
LIMIT = '/run/current-system/sw/bin/prlimit'


class PatchDispatchIntegrationTests(unittest.TestCase):
    def test_real_generation_approval_signature_write_and_replay(self):
        if not shutil.which('go') or not os.path.isfile(BWRAP) or not os.path.exists(LIMIT):
            self.skipTest('Go and the trusted Linux sandbox tools are required')
        import json
        with tempfile.TemporaryDirectory(prefix='nexus-dispatch-fixture-') as tmp:
            base = pathlib.Path(tmp)
            root, receipts = base / 'workspace', base / 'receipts'
            root.mkdir(mode=0o700); receipts.mkdir(mode=0o700)
            target = root / 'main.py'
            target.write_text('old\n'); target.chmod(0o600)
            executable = base / 'workspace-agent'
            source = pathlib.Path(__file__).resolve().parents[1] / 'workspace-agent'
            build_env = {**os.environ, 'CGO_ENABLED': '0'}
            subprocess.run(['go', 'build', '-o', str(executable), '.'], cwd=source,
                           env=build_env, check=True, capture_output=True, timeout=60)
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0)); port = reserved.getsockname()[1]
            read_key, execute_key = 'read-fixture-' + 'r' * 40, 'execute-fixture-' + 'e' * 40
            environment = {'PATH': os.environ.get('PATH', ''),
                'NEXUS_WORKSPACE_HOST': 'debian', 'NEXUS_WORKSPACE_LISTEN': f'127.0.0.1:{port}',
                'NEXUS_WORKSPACE_TOKEN': read_key, 'NEXUS_WORKSPACE_EXECUTOR_TOKEN': execute_key,
                'NEXUS_WORKSPACE_PATCH_STATE_DIR': str(receipts), 'NEXUS_WORKSPACE_BWRAP_EXECUTABLE': BWRAP,
                'NEXUS_WORKSPACE_PRLIMIT_EXECUTABLE': LIMIT,
                'NEXUS_WORKSPACE_ROOTS_JSON': json.dumps([dict(id='code', name='Managed fixture', path=str(root),
                                                              managed_write=True, exclusive_writer=True)])}
            process = subprocess.Popen([str(executable)], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        self.fail('temporary workspace bridge exited before readiness')
                    try:
                        with urlopen(f'http://127.0.0.1:{port}/healthz', timeout=.2) as response:
                            if response.status == 200: break
                    except OSError:
                        if time.monotonic() > deadline: self.fail('temporary workspace bridge did not become ready')
                        time.sleep(.02)
                controller = api.Controller({'NEXUS_ORCHESTRATOR_TOKEN': 'o' * 40,
                    'NEXUS_APPROVAL_REVIEW_TOKEN': 'v' * 40,
                    'NEXUS_PS5_CHAT_URL': 'http://127.0.0.1:8081/v1', 'NEXUS_PS5_MODEL_ID': 'fixture',
                    'NEXUS_DEBIAN_WORKSPACE_URL': f'http://127.0.0.1:{port}/v1',
                    'NEXUS_DEBIAN_WORKSPACE_TOKEN': read_key})
                controller.workspace_executor_tokens = {'debian': execute_key}
                controller.authorize_workspace_operation = lambda *args: True
                runs = RunStore(base / 'runs')
                try:
                    review = PatchReview(controller, runs)
                    item = review.propose(OWNER_ID, 'debian', 'code', dict(path='main.py', replacement='new\n', submission_id='f' * 32))
                    self.assertEqual(len(item['proposal']['workspace_generation']), 64)
                    self.assertEqual(target.read_text(), 'old\n')
                    self.assertTrue(review.store.transition(OWNER_ID, item['id'], item['digest'], expected='pending', target='approved'))
                    route = '/v1/nexus/workspaces/debian/code/patches/' + item['id']
                    code, envelope = review.dispatch('POST', route + '/apply', OWNER_ID, {'digest': item['digest']})
                    self.assertEqual(code, 200)
                    self.assertTrue(envelope['execution_enabled'])
                    result = envelope['patch']['execution']
                    self.assertEqual(result['phase'], 'applied')
                    self.assertEqual(result['result_sha256'], hashlib.sha256(b'new\n').hexdigest())
                    self.assertEqual(target.read_text(), 'new\n')
                    inode = target.stat().st_ino
                    self.assertEqual(review.dispatch('POST', route + '/apply', OWNER_ID,
                        {'digest': item['digest']})[1]['patch']['execution'], result)
                    self.assertEqual(target.stat().st_ino, inode)

                    # Lose the HTTP reply after a real confined replacement.
                    # Restart the Python journal and recover only the saved receipt.
                    next_item = review.propose(OWNER_ID, 'debian', 'code',
                        dict(path='main.py', replacement='recovered\n', submission_id='a' * 32))
                    self.assertTrue(review.store.transition(OWNER_ID, next_item['id'], next_item['digest'],
                        expected='pending', target='approved'))
                    request_json = controller.http_json
                    def lose_reply(*args, **kwargs):
                        response = request_json(*args, **kwargs)
                        if args[1].endswith('/patches/apply'): raise OSError('fixture lost reply')
                        return response
                    controller.http_json = lose_reply
                    next_route = '/v1/nexus/workspaces/debian/code/patches/' + next_item['id']
                    with self.assertRaises(ReviewError) as lost:
                        review.dispatch('POST', next_route + '/apply', OWNER_ID, {'digest': next_item['digest']})
                    self.assertEqual(lost.exception.status, 503)
                    self.assertEqual(target.read_text(), 'recovered\n')
                    installed = target.stat().st_ino
                    controller.http_json = request_json
                    runs.close()
                    runs = RunStore(base / 'runs')
                    review = PatchReview(controller, runs)
                    self.assertEqual(review.store.origin(OWNER_ID, next_item['id']), 'manual')
                    code, recovered = review.dispatch('POST', next_route + '/reconcile', OWNER_ID,
                        {'digest': next_item['digest']})
                    self.assertEqual(code, 200)
                    self.assertEqual(recovered['patch']['execution']['phase'], 'applied')
                    self.assertEqual(target.stat().st_ino, installed)
                    self.assertEqual(target.read_text(), 'recovered\n')

                    conflict = review.propose(OWNER_ID, 'debian', 'code',
                        dict(path='main.py', replacement='must not install\n', submission_id='b' * 32))
                    self.assertTrue(review.store.transition(OWNER_ID, conflict['id'], conflict['digest'],
                        expected='pending', target='approved'))
                    target.write_text('concurrent edit\n')
                    _, refused = review.dispatch('POST', '/v1/nexus/workspaces/debian/code/patches/' +
                        conflict['id'] + '/apply', OWNER_ID, {'digest': conflict['digest']})
                    self.assertEqual(refused['patch']['execution']['phase'], 'conflict')
                    self.assertEqual(target.read_text(), 'concurrent edit\n')
                    # Exercise the actual durable scheduler and its background
                    # dispatcher, replacing only policy and model generation.
                    target.write_text('old\n')
                    from run_jobs import RunJobs
                    controller.authorize_run = lambda *args: True
                    controller.active_model = lambda: 'fixture'
                    controller.model_context_window = lambda: 4096
                    controller.input_tokens = lambda *args, **kwargs: 64
                    controller.context = lambda *args: ''
                    outputs = [json.dumps(dict(action='propose_patch', path='main.py', replacement='agent edit\n')),
                               json.dumps(dict(action='answer', response='The approved edit was applied.'))]
                    controller.llm = lambda *args, **kwargs: outputs.pop(0)
                    jobs = RunJobs(controller, base / 'agent-runs')
                    try:
                        run = jobs.submit(dict(prompt='Propose and apply an edit',
                            workspace=dict(host='debian', workspace_id='code', path=''), allow_proposals=True), owner=OWNER_ID)
                        def wait_status(status):
                            deadline = time.monotonic() + 6
                            while time.monotonic() < deadline:
                                current = jobs.store.get_owned(run['id'], OWNER_ID)
                                if current['status'] == status: return current
                                time.sleep(.02)
                            self.fail('scheduler did not reach ' + status + ': ' + current['status'])
                        paused = wait_status('waiting_for_approval')
                        approval = jobs.checkpoints.review.store.get(OWNER_ID, paused['approval_id'])
                        self.assertEqual(target.read_text(), 'old\n')
                        self.assertTrue(jobs.checkpoints.review.store.transition(OWNER_ID, approval['id'], approval['digest'],
                            expected='pending', target='approved'))
                        done = wait_status('completed')
                        self.assertEqual(target.read_text(), 'agent edit\n')
                        self.assertEqual(done['result']['workspace_tools'][0]['status'], 'applied')
                        self.assertEqual(outputs, [])
                    finally:
                        jobs.close()
                finally:
                    runs.close()
            finally:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
                process.stderr.close()


if __name__ == '__main__': unittest.main()
