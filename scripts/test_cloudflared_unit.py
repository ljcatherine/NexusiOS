import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNIT = (ROOT / "gateway" / "nexus-cloudflared.service").read_text()
GATEWAY_UNIT = (ROOT / "gateway" / "nexus-gateway.service").read_text()


class CloudflaredUnitTests(unittest.TestCase):
    def test_tunnel_reads_secret_from_file_not_process_arguments(self):
        exec_start = next(line for line in UNIT.splitlines() if line.startswith("ExecStart="))
        self.assertIn("--token-file /etc/nexus-cloudflared/tunnel-token", exec_start)
        self.assertNotIn("--token ", exec_start)
        self.assertNotIn("TUNNEL_TOKEN=", UNIT)

    def test_tunnel_runs_unprivileged_after_gateway_unit(self):
        self.assertIn("User=cloudflared", UNIT)
        self.assertIn("Group=cloudflared", UNIT)
        self.assertIn("Requires=nexus-gateway.service", UNIT)
        self.assertIn("After=network-online.target nexus-gateway.service", UNIT)
        self.assertIn("User=nexus-gateway", GATEWAY_UNIT)

    def test_workers_vpc_tunnel_requires_quic(self):
        exec_start = next(line for line in UNIT.splitlines() if line.startswith("ExecStart="))
        self.assertIn("tunnel --protocol quic", exec_start)

    def test_tunnel_unit_keeps_systemd_hardening(self):
        for setting in (
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectControlGroups=true",
            "RestrictSUIDSGID=true",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
        ):
            with self.subTest(setting=setting):
                self.assertIn(setting, UNIT)


if __name__ == "__main__":
    unittest.main()
