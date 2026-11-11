import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('service_provenance', Path(__file__).with_name('nexusai-service-provenance.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def encoded(text):
    value = len(text)
    prefix = bytearray()
    while value >= 128:
        prefix.append((value & 127) | 128); value >>= 7
    return bytes(prefix) + bytes([value]) + text


class ServiceProvenanceTests(unittest.TestCase):
    def test_only_whitelisted_build_metadata_is_emitted(self):
        revision = b'a' * 40
        settings = b'\xff' * 16 + b'path\tprivate/path\nbuild\tvcs.revision=' + revision + b'\nbuild\tvcs.modified=true\nbuild\t-ldflags=SECRET_FIXTURE_NEVER_EMIT\n' + b'\xff' * 16
        header = probe.MAGIC + bytes([8, 2]) + bytes(16)
        data = b'ELF fixture' + header + encoded(b'go1.24.4') + encoded(settings)
        self.assertEqual(probe.go_metadata(data), dict(go_version='go1.24.4', vcs_revision='a' * 40, vcs_modified='true'))
        self.assertNotIn('SECRET_FIXTURE', json.dumps(probe.go_metadata(data)))
        self.assertNotIn('private/path', json.dumps(probe.go_metadata(data)))

    def test_missing_legacy_oversized_and_torn_metadata_are_unreported(self):
        header = probe.MAGIC + bytes([8, 2]) + bytes(16)
        for data in (b'not a Go file', probe.MAGIC, header + b'\xff' * 10,
                     header + encoded(b'go1.24.4') + b'\x80\x80\x80\x01'):
            with self.subTest(data_length=len(data)):
                self.assertEqual(probe.go_metadata(data), {})
        legacy = probe.MAGIC + bytes([8, 0]) + bytes(16)
        self.assertEqual(probe.go_metadata(legacy), {})

    def test_known_entrypoint_is_selected_without_returning_other_arguments(self):
        commandline = b'/usr/bin/python3\0/fixture/nexus-agent-orchestrator.py\0--credential\0SECRET_FIXTURE\0'
        selected = probe.entrypoint_from_args(commandline)
        self.assertEqual(selected, Path('/fixture/nexus-agent-orchestrator.py'))
        self.assertNotIn('SECRET_FIXTURE', str(selected))
        self.assertEqual(probe.entrypoint_from_args(b'python3\0/fixture/nexus-agent-orchestrator\0'), Path('/fixture/nexus-agent-orchestrator'))
        self.assertEqual(probe.entrypoint_from_args(b'python3.11\0-u\0/other/renamed.py\0--token-file\0/private/server.py\0'),
                         Path('/other/renamed.py'))
        with self.assertRaises(ValueError): probe.entrypoint_from_args(b'x' * 32769)

    def test_python_script_parser_refuses_ambiguous_modes_and_later_operands(self):
        for args in (b'python3\0-c\0inline code\0server.py\0', b'python3\0-m\0server\0server.py\0',
                     b'python3\0-X\0dev\0server.py\0', b'python3\0-\0server.py\0',
                     b'python3\0unknown_entry\0--token-file\0server.py\0', b'wrapper\0server.py\0',
                     b'python3\0', b''):
            with self.subTest(args=args):
                with self.assertRaises(StopIteration): probe.entrypoint_from_args(args)

    def test_digest_reader_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture'
            path.write_bytes(b'fixture bytes')
            with self.assertRaises(ValueError): probe.digest_file(path, 3)
            self.assertEqual(len(probe.digest_file(path, 100)), 64)

    def test_special_and_symlink_source_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError): probe.digest_file(fifo, 100)
            link = Path(directory) / 'link'
            link.symlink_to(fifo)
            with self.assertRaises(OSError): probe.digest_file(link, 100)

    def test_restarted_service_does_not_mix_process_evidence(self):
        with patch.object(probe, 'unit_property', side_effect=['active', '123', '124']), \
             patch.object(Path, 'open', side_effect=PermissionError):
            result = probe.inspect_service('nexus-workspace-agent.service')
        self.assertEqual(result, {'unit': 'nexus-workspace-agent.service',
                                  'runtime_provenance': 'process_changed_during_probe'})


if __name__ == '__main__': unittest.main()
