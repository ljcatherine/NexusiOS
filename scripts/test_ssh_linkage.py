import struct
import unittest
from validate_ssh_linkage import POSIX_CONNECTOR_MARKER, REQUIRED, validate


def executable(symbols, *, undefined=False):
    names = b'\0'
    entries = b''
    for name in symbols:
        entries += struct.pack('<IBBHQ', len(names), 1 if undefined else 0x0F, 1, 0, 0x100000000)
        names += name.encode() + b'\0'
    header = struct.pack('<8I', 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    command = struct.pack('<6I', 2, 24, 56, len(symbols), 56 + len(entries), len(names))
    return header + command + entries + names


class SSHLinkageTests(unittest.TestCase):
    def test_rejects_missing_bool_conformance_even_with_generic_class(self):
        with self.assertRaisesRegex(ValueError, 'Missing SSH runtime metadata'):
            validate(executable({'_$s7Atomics13ManagedAtomicCMn', POSIX_CONNECTOR_MARKER.decode()}))

    def test_requires_definitions_not_undefined_symbol_references(self):
        with self.assertRaisesRegex(ValueError, 'Missing SSH runtime metadata'):
            validate(executable(REQUIRED | {POSIX_CONNECTOR_MARKER.decode()}, undefined=True))

    def test_accepts_all_required_defined_records(self):
        validate(executable(REQUIRED | {POSIX_CONNECTOR_MARKER.decode()}))

    def test_rejects_retired_network_framework_connector(self):
        with self.assertRaisesRegex(ValueError, 'retired Network.framework'):
            validate(executable(REQUIRED | {POSIX_CONNECTOR_MARKER.decode(), 'NIOTSConnectionBootstrap'}))

    def test_rejects_missing_posix_connector(self):
        with self.assertRaisesRegex(ValueError, 'expected NIO POSIX SSH connector'):
            validate(executable(REQUIRED))

    def test_rejects_truncated_table_and_invalid_name_offset(self):
        binary = executable(REQUIRED)
        with self.assertRaises(ValueError):
            validate(binary[:-5])
        damaged = bytearray(binary)
        struct.pack_into('<I', damaged, 56, 0xFFFFFFFF)
        with self.assertRaises(ValueError):
            validate(bytes(damaged))
