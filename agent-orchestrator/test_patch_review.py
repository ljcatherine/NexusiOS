import hashlib
import http.client
import json
import threading
import unittest

from test_server import FakeController, OWNER_ID, TOKEN, api

REVIEW_TOKEN = 'r' * 40
SCOPE = '/v1/nexus/workspaces/debian/code/patches'


class PatchReviewHTTPTests(unittest.TestCase):
    def setUp(self):
        self.controller = FakeController()
        self.controller.review_token = REVIEW_TOKEN
        self.server = api.Service(('127.0.0.1', 0), self.controller)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path=SCOPE, payload=None, token=TOKEN, owner=OWNER_ID):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
        if owner is not None:
            headers['X-Nexus-Principal'] = owner
        body = json.dumps(payload) if payload is not None else None
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        status, value = response.status, json.loads(response.read())
        connection.close()
        return status, value

    def proposal(self):
        payload = {'path': 'src/main.py', 'replacement': 'print(7)', 'submission_id': 'c' * 32}
        status, response = self.request('POST', payload=payload)
        self.assertEqual(status, 200, response)
        self.assertFalse(response['execution_enabled'])
        return payload, response['patch']

    def managed(self):
        self.controller.workspace_file_context = lambda host, root, path: dict(host=host, workspace_id=root,
            path=path, text='print(123)', size_bytes=10, workspace_generation='c' * 64)
        self.controller.workspace_executor_tokens = {'debian': 'x' * 40}
        self.controller.workspaces['debian'] = ('http://127.0.0.1:8896/v1', 'b' * 40)
        self.controller.list_workspace = lambda _: {'workspaces': [{'id': 'code', 'read_only': False,
            'generation': 'c' * 64, 'capabilities': ['apply_patch']}]}
        self.write_allowed, self.writes, self.saved_receipt = True, [], None
        self.controller.authorize_workspace_operation = lambda *args: self.write_allowed
        def transport(base, path, key, method, payload, **kwargs):
            from patch_dispatch import patch_proof
            self.assertEqual(key, 'x' * 40)
            self.assertEqual(payload['proof'], patch_proof(payload, key))
            self.writes.append((path, dict(payload)))
            if path.endswith('/apply'):
                self.saved_receipt = {name: payload[name] for name in
                    ('host', 'workspace_id', 'approval_id', 'digest', 'operation_id')}
                self.saved_receipt.update(status='applied', sha256=payload['replacement_sha256'])
                if getattr(self, 'drop_reply', False): raise OSError('private upstream response')
            return self.saved_receipt
        self.controller.http_json = transport

    def approve(self, item):
        response = self.request('POST', SCOPE + '/' + item['id'] + '/decision',
            {'digest': item['digest'], 'decision': 'approve'}, token=REVIEW_TOKEN)
        self.assertEqual(response[0], 200, response)

    def test_manual_apply_is_review_authenticated_owner_digest_and_write_bound(self):
        self.managed()
        _, item = self.proposal()
        self.assertTrue(item['manual_execution_allowed'])
        path, payload = SCOPE + '/' + item['id'] + '/apply', {'digest': item['digest']}
        self.assertEqual(self.request('POST', path, payload)[0], 401)
        self.assertEqual(self.request('POST', path, payload, token=REVIEW_TOKEN)[0], 409)
        self.approve(item)
        self.assertEqual(self.request('POST', path, payload, token=REVIEW_TOKEN, owner='b' * 64)[0], 404)
        self.assertEqual(self.request('POST', path, {'digest': 'f' * 64}, token=REVIEW_TOKEN)[0], 409)
        self.assertEqual(self.request('POST', path, {**payload, 'command': 'sh'}, token=REVIEW_TOKEN)[0], 400)
        self.write_allowed = False
        self.assertEqual(self.request('POST', path, payload, token=REVIEW_TOKEN)[0], 403)
        self.assertEqual(self.writes, [])
        self.write_allowed = True
        code, result = self.request('POST', path, payload, token=REVIEW_TOKEN)
        self.assertEqual(code, 200, result)
        self.assertTrue(result['execution_enabled'])
        self.assertEqual(result['patch']['execution']['phase'], 'applied')
        self.assertEqual(self.request('POST', path, payload, token=REVIEW_TOKEN), (code, result))
        self.assertEqual(len(self.writes), 1)

    def test_manual_lost_reply_uses_original_receipt_without_replaying_write(self):
        self.managed()
        _, item = self.proposal()
        self.approve(item)
        path, payload = SCOPE + '/' + item['id'], {'digest': item['digest']}
        self.drop_reply = True
        self.assertEqual(self.request('POST', path + '/apply', payload, token=REVIEW_TOKEN)[0], 503)
        _, record = self.request('GET', path, token=REVIEW_TOKEN)
        self.assertFalse(record['execution_enabled'])
        self.assertEqual(record['patch']['execution']['phase'], 'uncertain')
        self.write_allowed = False
        self.assertEqual(self.request('POST', path + '/reconcile', payload, token=REVIEW_TOKEN)[0], 403)
        self.write_allowed = True
        code, result = self.request('POST', path + '/reconcile', payload, token=REVIEW_TOKEN)
        self.assertEqual(code, 200, result)
        self.assertEqual(result['patch']['execution']['phase'], 'applied')
        self.assertEqual(self.writes[0][1], self.writes[1][1])
        self.assertEqual(sum(path.endswith('/apply') for path, _ in self.writes), 1)

    def test_agent_and_legacy_proposals_cannot_use_manual_execution(self):
        self.managed()
        review = self.server.patch_reviews
        payload = {'path': 'src/main.py', 'replacement': 'new', 'submission_id': 'f' * 32}
        agent = review.propose(OWNER_ID, 'debian', 'code', payload, origin='agent')
        self.approve(agent)
        self.assertEqual(self.request('POST', payload=payload)[0], 409)
        _, detail = self.request('GET', SCOPE + '/' + agent['id'], token=REVIEW_TOKEN)
        self.assertFalse(detail['patch']['manual_execution_allowed'])
        for action in ('apply', 'reconcile'):
            self.assertEqual(self.request('POST', SCOPE + '/' + agent['id'] + '/' + action,
                {'digest': agent['digest']}, token=REVIEW_TOKEN)[0], 409)
        legacy = review.store.propose(OWNER_ID, agent['proposal'])
        self.approve(legacy)
        self.assertEqual(self.request('POST', SCOPE + '/' + legacy['id'] + '/apply',
            {'digest': legacy['digest']}, token=REVIEW_TOKEN)[0], 409)
        self.assertEqual(self.writes, [])

    def test_worker_credential_cannot_review_and_review_credential_cannot_propose(self):
        payload, item = self.proposal()
        for path in (SCOPE, SCOPE + '/' + item['id']):
            self.assertEqual(self.request('GET', path, token=TOKEN)[0], 401)
        decision_path = SCOPE + '/' + item['id'] + '/decision'
        self.assertEqual(self.request('POST', decision_path, {'digest': item['digest'], 'decision': 'approve'})[0], 401)
        self.assertEqual(self.request('POST', payload=payload, token=REVIEW_TOKEN)[0], 401)
        status, response = self.request('POST', decision_path,
            {'digest': item['digest'], 'decision': 'approve'}, token=REVIEW_TOKEN)
        self.assertEqual(status, 200, response)
        self.assertEqual(response['patch']['status'], 'approved')
        self.assertFalse(response['execution_enabled'])
        self.assertEqual(self.request('POST', decision_path,
            {'digest': item['digest'], 'decision': 'approve'}, token=REVIEW_TOKEN)[0], 409)
        self.assertEqual(self.request('POST', decision_path,
            {'digest': item['digest'], 'decision': 'executing'}, token=REVIEW_TOKEN)[0], 400)

    def test_generation_is_captured_and_retry_keeps_the_original_root(self):
        original = self.controller.workspace_file_context
        self.controller.workspace_file_context = lambda *args: {**original(*args), 'workspace_generation': 'c' * 64}
        _, item = self.proposal()
        self.assertEqual(item['proposal']['workspace_generation'], 'c' * 64)
        expected = hashlib.sha256(json.dumps(item['proposal'], ensure_ascii=False, sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(item['digest'], expected)
        self.controller.workspace_file_context = lambda *args: {**original(*args), 'workspace_generation': 'f' * 64}
        _, retry = self.proposal()
        self.assertEqual(retry, item)

    def test_review_is_owner_workspace_and_digest_bound(self):
        _, item = self.proposal()
        path = SCOPE + '/' + item['id']
        self.assertEqual(self.request('GET', path, token=REVIEW_TOKEN, owner='b' * 64)[0], 404)
        self.assertEqual(self.request('GET', path.replace('/code/', '/other/'), token=REVIEW_TOKEN)[0], 404)
        self.assertEqual(self.request('POST', path + '/decision',
            {'digest': 'd' * 64, 'decision': 'approve'}, token=REVIEW_TOKEN)[0], 409)
        self.assertEqual(self.request('GET', token=REVIEW_TOKEN, owner=None)[0], 403)
        status, response = self.request('GET', token=REVIEW_TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual([patch['id'] for patch in response['patches']], [item['id']])
        self.assertNotIn('original', json.dumps(response))
        self.assertNotIn('replacement', json.dumps(response))

    def test_snapshot_and_submission_retry_survive_source_change(self):
        payload, item = self.proposal()
        self.assertEqual(item['proposal']['original'], 'print(123)')
        self.assertEqual(item['proposal']['base_sha256'], hashlib.sha256(b'print(123)').hexdigest())
        self.controller.workspace_file_context = lambda *_: self.fail('retry must not re-read changed source')
        status, response = self.request('POST', payload=payload)
        self.assertEqual(status, 200)
        self.assertEqual(response['patch']['id'], item['id'])
        self.assertEqual(self.request('POST', payload={**payload, 'replacement': 'different'})[0], 409)
        status, snapshot = self.request('GET', SCOPE + '/' + item['id'], token=REVIEW_TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(snapshot['patch']['proposal']['original'], 'print(123)')

    def test_expired_and_rejected_proposals_do_not_become_approved(self):
        _, item = self.proposal()
        decision_path = SCOPE + '/' + item['id'] + '/decision'
        self.server.jobs.store.db.execute('UPDATE approvals SET expires=0 WHERE id=?', (item['id'],))
        self.assertEqual(self.request('POST', decision_path,
            {'digest': item['digest'], 'decision': 'approve'}, token=REVIEW_TOKEN)[0], 409)
        status, response = self.request('POST', payload={'path': 'src/main.py', 'replacement': 'print(8)', 'submission_id': 'e' * 32})
        self.assertEqual(status, 200)
        item = response['patch']
        path = SCOPE + '/' + item['id'] + '/decision'
        self.assertEqual(self.request('POST', path, {'digest': item['digest'], 'decision': 'reject'}, token=REVIEW_TOKEN)[0], 200)
        self.assertEqual(self.request('POST', path, {'digest': item['digest'], 'decision': 'approve'}, token=REVIEW_TOKEN)[0], 409)

    def test_proposals_reject_traversal_unknown_fields_and_unbounded_contents(self):
        for payload in (
            {'path': '../secret.py', 'replacement': 'x', 'submission_id': 'c' * 32},
            {'path': 'src/main.py', 'replacement': 'x', 'submission_id': 'c' * 32, 'command': 'sh'},
            {'path': 'src/main.py', 'replacement': 'x' * (64 * 1024 + 1), 'submission_id': 'c' * 32},
        ):
            self.assertEqual(self.request('POST', payload=payload)[0], 400)
        self.assertEqual(self.request('GET', SCOPE + '?arbitrary=1', token=REVIEW_TOKEN)[0], 400)

    def test_review_credential_configuration_rejects_worker_or_bridge_reuse(self):
        base = {'NEXUS_ORCHESTRATOR_TOKEN': TOKEN, 'NEXUS_PS5_CHAT_URL': 'http://127.0.0.1:8081/v1',
                'NEXUS_PS5_MODEL_ID': 'auto'}
        for env in (
            {**base, 'NEXUS_APPROVAL_REVIEW_TOKEN': TOKEN},
            {**base, 'NEXUS_APPROVAL_REVIEW_TOKEN': 'too-short'},
            {**base, 'NEXUS_APPROVAL_REVIEW_TOKEN': REVIEW_TOKEN,
             'NEXUS_DEBIAN_WORKSPACE_URL': 'http://127.0.0.1:8896/v1', 'NEXUS_DEBIAN_WORKSPACE_TOKEN': REVIEW_TOKEN},
            {**base, 'NEXUS_APPROVAL_REVIEW_TOKEN': REVIEW_TOKEN,
             'NEXUS_PS5_CONTROL_URL': 'http://127.0.0.1:8082/v1', 'NEXUS_PS5_CONTROL_TOKEN': REVIEW_TOKEN},
        ):
            with self.assertRaises(ValueError):
                api.Controller(env)
        self.assertEqual(api.Controller({**base, 'NEXUS_APPROVAL_REVIEW_TOKEN': REVIEW_TOKEN}).review_token, REVIEW_TOKEN)


if __name__ == '__main__':
    unittest.main()
