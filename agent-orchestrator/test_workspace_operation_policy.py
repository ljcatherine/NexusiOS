import io
import json
import unittest
from urllib.error import HTTPError, URLError

from test_server import FakeController, OWNER_ID, api


class WorkspaceOperationPolicyTests(unittest.TestCase):
    def test_uncached_operation_policy_checks_exact_identity_and_permission(self):
        controller = FakeController()
        captured = []
        class Reply:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *args): pass
        class Opener:
            allowed = True
            def open(self, request, timeout):
                captured.append((request.full_url, json.loads(request.data), timeout))
                if not self.allowed:
                    raise HTTPError(request.full_url, 403, 'denied', {}, io.BytesIO())
                return Reply()
        opener = Opener()
        controller.opener = opener
        workspace = {'host': 'debian', 'workspace_id': 'code', 'path': ''}
        self.assertTrue(controller.authorize_workspace_operation(OWNER_ID, workspace, 'apply'))
        opener.allowed = False
        self.assertFalse(controller.authorize_workspace_operation(OWNER_ID, workspace, 'apply'))
        self.assertEqual(len(captured), 2)
        url, body, timeout = captured[0]
        self.assertTrue(url.endswith('/internal/nexus/authorize-workspace-operation'))
        self.assertEqual(body, {'principal': OWNER_ID, 'workspace': {'host': 'debian', 'id': 'code'}, 'operation': 'apply'})
        self.assertEqual(timeout, 2)
        opener.allowed = True
        self.assertTrue(controller.authorize_workspace_operation(OWNER_ID, workspace, 'execute'))
        self.assertEqual(captured[-1][1]['operation'], 'execute')
        self.assertEqual(len(captured), 3)

    def test_unknown_identity_operation_or_unavailable_policy_fails_closed(self):
        controller = FakeController()
        workspace = {'host': 'debian', 'workspace_id': 'code'}
        for owner, root, operation in [('owner', workspace, 'apply'), (OWNER_ID, {}, 'apply'),
                                      (OWNER_ID, workspace, 'shell'), (OWNER_ID, None, 'propose')]:
            with self.assertRaises(api.AgentError):
                controller.authorize_workspace_operation(owner, root, operation)
        class Opener:
            def open(self, *args, **kwargs): raise URLError('private detail')
        controller.opener = Opener()
        with self.assertRaises(api.AgentError) as raised:
            controller.authorize_workspace_operation(OWNER_ID, workspace, 'propose')
        self.assertEqual(raised.exception.status, 503)
        self.assertNotIn('private detail', raised.exception.message)


if __name__ == '__main__': unittest.main()
