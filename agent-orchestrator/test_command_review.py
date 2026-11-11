"""Authenticated command-review HTTP acceptance: fixed profiles only."""
import copy
import http.client
import json
import threading
import unittest

from test_server import FakeController, OWNER_ID, TOKEN, api
from test_command_approvals import proposal
from command_approvals import manifest_digest


REVIEW_TOKEN = 'v' * 40
EXECUTOR_TOKEN = 'c' * 48
SCOPE = '/v1/nexus/workspaces/debian/code/commands'


class CommandReviewHTTPTests(unittest.TestCase):
    def setUp(self):
        self.controller = FakeController()
        self.controller.review_token = REVIEW_TOKEN
        self.controller.command_executor_tokens = {'debian': EXECUTOR_TOKEN}
        self.controller.workspaces['debian'] = ('http://127.0.0.1:8896/v1', 'w' * 40)
        self.allowed = True
        self.controller.authorize_workspace_operation = lambda *args: self.allowed
        self.source = proposal()
        self.source['host'] = 'debian'
        self.source['snapshot_id'] = 'd' * 32
        self.controller.list_workspace = lambda _: {'workspaces': [{
            'id': 'code', 'read_only': True, 'generation': self.source['workspace_generation'],
            'capabilities': ['list', 'read_file', 'run_command']}]}
        self.calls = []
        def transport(base, path, token='', method='GET', payload=None, **kwargs):
            self.calls.append((path, method, token))
            if path.endswith('/commands/profiles?host=debian'):
                return {'host': 'debian', 'workspace_id': 'code', 'profiles': [{
                    'id': 'tests', 'version': self.source['profile_version'],
                    'invocation': copy.deepcopy(self.source['invocation'])}]}
            if path.endswith('/commands/prepare'):
                result = {k: copy.deepcopy(v) for k, v in self.source.items() if k not in ('kind', 'host')}
                result['snapshot_id'] = payload['snapshot_id']
                result['expires_at'] = payload['expires_at']
                return {'host': 'debian', 'owner': OWNER_ID, 'snapshot': result}
            if path.endswith('/cancel'):
                from command_dispatch import command_proof
                self.assertEqual(token, EXECUTOR_TOKEN)
                self.assertEqual(payload['proof'], command_proof(payload, token))
                return {'host': 'debian', 'workspace_id': 'code', 'operation_id': payload['operation_id'],
                        'cancel_requested': True, 'receipt_status': 'claimed'}
            raise AssertionError('unexpected command transport')
        self.controller.http_json = transport
        self.server = api.Service(('127.0.0.1', 0), self.controller)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path=SCOPE, payload=None, token=REVIEW_TOKEN, owner=OWNER_ID):
        con = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
        if owner is not None:
            headers['X-Nexus-Principal'] = owner
        body = json.dumps(payload) if payload is not None else None
        con.request(method, path, body=body, headers=headers)
        reply = con.getresponse()
        status, result = reply.status, json.loads(reply.read())
        con.close()
        return status, result

    def create(self):
        status, value = self.request('POST', payload={'profile_id': 'tests', 'submission_id': 'f' * 32})
        self.assertEqual(status, 200, value)
        return value['command']

    def test_fixed_profile_review_decision_and_no_implicit_execution(self):
        item = self.create()
        self.assertEqual(item['status'], 'pending')
        self.assertFalse(item['execution_enabled'])
        self.assertEqual(item['origin'], 'manual')
        self.assertEqual(self.request('POST', payload={'profile_id': 'tests', 'submission_id': 'f' * 32})[1]['command'], item)
        self.assertEqual(sum('/prepare' in path for path, _, _ in self.calls), 1)
        self.assertEqual(self.request('GET')[1]['commands'][0]['id'], item['id'])
        path = SCOPE + '/' + item['id']
        self.assertEqual(self.request('GET', path)[1]['command']['id'], item['id'])
        self.assertEqual(self.request('POST', path + '/execute', {'digest': item['digest']})[0], 409)
        code, result = self.request('POST', path + '/decision', {'digest': item['digest'], 'decision': 'approve'})
        self.assertEqual(code, 200, result)
        self.assertEqual(result['command']['status'], 'approved')
        self.assertEqual(self.request('POST', path + '/decision', {'digest': item['digest'], 'decision': 'approve'})[0], 409)
        self.assertIsNone(self.server.command_reviews.store.get_execution(OWNER_ID, item['id'], item['digest']))

    def test_roles_scope_owner_and_revocation(self):
        self.assertEqual(self.request('POST', payload={'profile_id': 'tests', 'submission_id': 'f'*32}, token=TOKEN)[0], 401)
        self.assertEqual(self.request('GET', token=TOKEN)[0], 401)
        self.assertEqual(self.request('GET', owner=None)[0], 403)
        self.assertEqual(self.request('GET', owner='invalid-owner')[0], 403)
        self.assertEqual(self.request('POST', payload={'profile_id': 'tests', 'submission_id': 'f'*32}, owner=None)[0], 403)
        item = self.create()
        path = SCOPE + '/' + item['id']
        self.assertEqual(self.request('GET', path, owner='b'*64)[0], 404)
        self.assertEqual(self.request('GET', path.replace('/code/', '/other/'))[0], 404)
        self.allowed = False
        for method, endpoint, payload in [('GET', SCOPE, None), ('POST', SCOPE, {'profile_id':'tests','submission_id':'f'*32}),
                                          ('POST', path+'/decision', {'digest':item['digest'],'decision':'approve'}),
                                          ('POST', path+'/execute', {'digest':item['digest']}),
                                          ('POST', path+'/reconcile', {'digest':item['digest']})]:
            self.assertEqual(self.request(method, endpoint, payload)[0], 403)

    def test_no_arbitrary_command_and_malformed_requests(self):
        for payload in ({'profile_id':'tests','submission_id':'f'*32,'command':'rm'},
                        {'profile_id':'../tests','submission_id':'f'*32},
                        {'profile_id':'tests','submission_id':'f'*32,'arguments':['--unsafe']},
                        {'profile_id':'missing','submission_id':'f'*32}):
            code = self.request('POST', payload=payload)[0]
            self.assertIn(code, (400, 503))
        self.assertEqual(self.request('GET', SCOPE+'?host=debian')[0], 400)
        self.assertEqual(self.request('GET', SCOPE, payload={'x':1})[0], 400)
        # A malformed privileged route does not acquire review-token authority.
        self.assertEqual(self.request('POST', SCOPE+'/bad/decision', {'digest':'a'*64})[0], 401)
        self.assertEqual(self.request('POST', SCOPE, {'profile_id':'tests','submission_id':'f'*32}, owner='b'*64)[0], 503)

    def test_profiles_are_exact_administrator_inventory_owner_scoped_and_read_only(self):
        endpoint = SCOPE + '/profiles'
        status, result = self.request('GET', endpoint)
        self.assertEqual(status, 200, result)
        self.assertFalse(result['execution_enabled'])
        self.assertEqual(result['workspace_generation'], self.source['workspace_generation'])
        self.assertEqual(result['profiles'][0]['id'], 'tests')
        self.assertEqual(result['profiles'][0]['invocation'], self.source['invocation'])
        self.assertEqual(self.request('GET', endpoint, token=TOKEN)[0], 401)
        self.assertEqual(self.request('GET', endpoint, owner=None)[0], 403)
        self.assertEqual(self.request('POST', endpoint, {'profile_id':'tests'})[0], 405)
        self.assertEqual(self.request('GET', endpoint+'?host=debian')[0], 400)
        self.assertEqual(self.request('GET', endpoint, owner='b'*64)[0], 200)
        self.allowed = False
        self.assertEqual(self.request('GET', endpoint)[0], 403)
        self.allowed = True
        before = self.controller.http_json
        def malformed(base, path, token='', method='GET', payload=None, **kwargs):
            value = before(base, path, token, method, payload, **kwargs)
            if path.endswith('/profiles?host=debian'):
                value['profiles'][0]['invocation']['arguments'].append('\0danger')
            return value
        self.controller.http_json = malformed
        self.assertEqual(self.request('GET', endpoint)[0], 503)

    def test_owner_can_withdraw_pending_or_approved_command_without_host_dispatch(self):
        first = self.create()
        path = SCOPE + '/' + first['id'] + '/cancel'
        body = {'digest': first['digest']}
        code, result = self.request('POST', path, body)
        self.assertEqual(code, 200, result)
        self.assertTrue(result['execution_enabled'])
        self.assertEqual(result['command']['status'], 'rejected')
        self.assertEqual(self.request('POST', path, body)[1]['command']['status'], 'rejected')
        self.assertEqual(self.request('POST', path.replace('/code/', '/other/'), body)[0], 404)
        self.assertEqual(self.request('POST', path, {'digest': '0'*64})[0], 409)
        self.assertEqual(self.request('POST', path, {**body, 'command': 'rm'})[0], 400)
        self.assertEqual(self.request('POST', SCOPE, {'profile_id':'tests', 'submission_id':'e'*32})[0], 200)
        item = self.request('GET')[1]['commands'][0]
        approved_path = SCOPE + '/' + item['id']
        self.assertEqual(self.request('POST', approved_path+'/decision',
            {'digest':item['digest'], 'decision':'approve'})[0], 200)
        code, result = self.request('POST', approved_path+'/cancel', {'digest':item['digest']})
        self.assertEqual(code, 200, result)
        self.assertEqual(result['command']['status'], 'rejected')
        self.assertEqual(self.request('POST', approved_path+'/execute', {'digest':item['digest']})[0], 409)
        self.assertFalse(any(path.endswith(('/execute','/cancel')) for path,_,_ in self.calls))

    def test_cancel_inflight_requires_owner_and_original_stored_operation_after_restart(self):
        item = self.create()
        path = SCOPE + '/' + item['id']
        self.assertEqual(self.request('POST', path+'/decision',
            {'digest':item['digest'], 'decision':'approve'})[0], 200)
        reviews = self.server.command_reviews
        execution = reviews.store.claim(OWNER_ID, item['id'], item['digest'])
        self.assertTrue(reviews.store.start_dispatch(OWNER_ID, item['id'], item['digest'], execution['operation_id']))
        reviews.dispatcher._request(OWNER_ID, reviews.store.get(OWNER_ID, item['id']), execution, EXECUTOR_TOKEN, create=True)
        body = {'digest':item['digest']}
        self.assertEqual(self.request('POST', path+'/cancel', body, owner='b'*64)[0], 404)
        self.assertEqual(self.request('POST', path+'/cancel', body, token=TOKEN)[0], 401)
        status, response = self.request('POST', path+'/cancel', body)
        self.assertEqual(status, 200, response)
        self.assertEqual(response['command']['status'], 'executing')
        self.assertEqual(response['command']['execution']['phase'], 'uncertain')
        self.assertTrue(response['command']['execution']['cancel_requested'])
        self.assertEqual(self.request('POST', path+'/cancel', body)[1]['command'], response['command'])
        self.assertEqual(sum(path.endswith('/cancel') for path,_,_ in self.calls), 2)
        self.allowed = False
        self.assertEqual(self.request('POST', path+'/cancel', body)[0], 403)
        self.assertEqual(sum(path.endswith('/cancel') for path,_,_ in self.calls), 2)


if __name__ == '__main__':
    unittest.main()
