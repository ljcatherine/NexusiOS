import unittest

from test_server import api


class CommandConfigurationTests(unittest.TestCase):
    def env(self):
        return {'NEXUS_ORCHESTRATOR_TOKEN': 'o' * 40, 'NEXUS_PS5_CHAT_URL': 'http://127.0.0.1:8081/v1',
                'NEXUS_PS5_MODEL_ID': 'fixture', 'NEXUS_NIXOS_WORKSPACE_URL': 'http://127.0.0.1:8896/v1',
                'NEXUS_NIXOS_WORKSPACE_TOKEN': 'r' * 40, 'NEXUS_APPROVAL_REVIEW_TOKEN': 'v' * 40,
                'NEXUS_NIXOS_WORKSPACE_EXECUTOR_TOKEN': 'p' * 40}

    def test_command_keys_are_opt_in_and_distinct_from_every_existing_role(self):
        self.assertEqual(api.Controller(self.env()).command_executor_tokens, {})
        for key in ('o' * 40, 'r' * 40, 'v' * 40, 'p' * 40):
            value = self.env(); value['NEXUS_NIXOS_COMMAND_EXECUTOR_TOKEN'] = key
            with self.subTest(key_role=key[0]), self.assertRaises(ValueError): api.Controller(value)
        value = self.env(); value['NEXUS_NIXOS_COMMAND_EXECUTOR_TOKEN'] = 'c' * 40
        self.assertEqual(api.Controller(value).command_executor_tokens, {'nixos': 'c' * 40})
        value.update(NEXUS_DEBIAN_WORKSPACE_URL='http://127.0.0.1:8897/v1', NEXUS_DEBIAN_WORKSPACE_TOKEN='d' * 40,
                     NEXUS_DEBIAN_COMMAND_EXECUTOR_TOKEN='c' * 40)
        with self.assertRaises(ValueError): api.Controller(value)

    def test_command_ingress_requires_private_loopback_or_https(self):
        value = self.env(); value['NEXUS_NIXOS_COMMAND_EXECUTOR_TOKEN'] = 'c' * 40
        value.pop('NEXUS_NIXOS_WORKSPACE_EXECUTOR_TOKEN')
        value['NEXUS_NIXOS_WORKSPACE_URL'] = 'http://192.168.1.2:8896/v1'
        with self.assertRaises(ValueError): api.Controller(value)

    def test_command_discovery_requires_generation_and_does_not_enable_writes(self):
        controller = api.Controller(self.env())
        root = dict(id='code', name='Command fixture', read_only=True, capabilities=['run_command'])
        controller.http_json = lambda *args, **kwargs: dict(host='nixos', workspaces=[root])
        with self.assertRaises(api.AgentError): controller.list_workspace('nixos')
        root['generation'] = 'a' * 64
        selected = controller.list_workspace('nixos')['workspaces'][0]
        self.assertTrue(selected['read_only'])
        self.assertEqual(selected['capabilities'], ['run_command'])
        self.assertNotIn('apply_patch', selected['capabilities'])
