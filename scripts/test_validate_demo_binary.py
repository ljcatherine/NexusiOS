import unittest
from validate_demo_binary import DEMO_MARKER, validate

VALID_DEMO = (DEMO_MARKER + b" nixos.example.invalid debian.example.invalid "
    b"No SSH connection or command execution occurs in this preview.")


class DemoBinaryPrivacyTests(unittest.TestCase):
    def test_accepts_shared_screen_demo_with_reserved_example_domains(self):
        validate(VALID_DEMO)

    def test_rejects_legacy_standalone_demo_without_production_screens(self):
        with self.assertRaisesRegex(ValueError, "Shared production-screen demo markers"):
            validate(DEMO_MARKER + b" fake-only preview")

    def test_rejects_private_ipv4_addresses(self):
        for endpoint in (b"10.10.0.2", b"192.168.1.70", b"172.20.10.1"):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, "RFC1918"):
                validate(VALID_DEMO + b" " + endpoint)

    def test_rejects_tailscale_magicdns_names(self):
        with self.assertRaisesRegex(ValueError, "Tailscale"):
            validate(VALID_DEMO + b" https://private-panel.tailnet.ts.net/")

    def test_rejects_binary_without_demo_entry_point(self):
        with self.assertRaisesRegex(ValueError, "Demo entry point marker"):
            validate(b"Nexus production binary")
