"""Offline tests for the fail-closed PS5 security preflight."""

import importlib.util
import contextlib
import io
import pathlib
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


SOURCE = pathlib.Path(__file__).with_name("nexusai-ps5-security-preflight.py")
spec = importlib.util.spec_from_file_location("nexusai_ps5_preflight", SOURCE)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PS5PreflightTests(unittest.TestCase):
    def test_real_http_rejects_redirect_without_forwarding_credential(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/must-not-follow")
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status = preflight.http_status("127.0.0.1", server.server_port, "/status", bearer="a" * 64)
            self.assertEqual(status, 302)
            self.assertEqual(seen, ["/status"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_private_env_rejects_wide_permissions_symlinks_and_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "private.env"
            line = 'NEXUS_PS5_CONTROL_TOKEN="' + "a" * 64 + '"\n'
            path.write_text(line)
            path.chmod(0o600)
            self.assertEqual(preflight.private_controller_token(path), "a" * 64)
            link = path.with_name("link.env")
            link.symlink_to(path)
            with self.assertRaises(OSError):
                preflight.private_controller_token(link)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                preflight.private_controller_token(path)
            path.chmod(0o600)
            path.write_text(line * 2)
            with self.assertRaises(ValueError):
                preflight.private_controller_token(path)

    def test_auth_acceptance_requires_all_negative_and_positive_checks(self):
        token = "a" * 64
        for statuses in ((401, 401, 200, 200), (200, 401, 200, 200),
                         (401, 200, 200, 200), (401, 401, None, None),
                         (401, 401, 200, 503)):
            with self.subTest(statuses=statuses):
                calls = []
                responses = iter(statuses)

                def probe(host, port, path, **kwargs):
                    calls.append((host, port, path, kwargs.get("bearer")))
                    return next(responses)

                result = preflight.assess_controller_auth("127.0.0.1", token, probe)
                self.assertEqual(result["controller_auth_checks_pass"], statuses == (401, 401, 200, 200))
                self.assertFalse(result["model_switch_tested"])
                self.assertNotEqual(calls[1][3], token)
                self.assertEqual(calls[2][3], token)
                self.assertNotIn(token, str(result))

    def test_exposed_privileged_port_blocks_even_if_controller_rejects_unauthenticated(self):
        attempted = []

        def tcp(_host, port):
            attempted.append(port)
            return port == 9021

        result = preflight.assess(
            "192.168.1.50", tcp_probe=tcp,
            http_probe=lambda *_args: 401,
        )
        self.assertEqual(attempted, [2121, 9021])
        self.assertEqual(result["model_control_gate"], "BLOCKED_PRIVILEGED_LAN_PORTS")
        self.assertEqual(result["controller_8082_http_status_without_credential"], 401)

    def test_owner_acceptance_allows_known_privileged_lan_ports_without_claiming_wan_safety(self):
        result = preflight.assess(
            "192.168.1.50", accept_trusted_lan=True,
            tcp_probe=lambda _host, port: port in (2121, 9021),
            http_probe=lambda _host, port, _path: 401 if port == 8082 else 200,
        )
        self.assertEqual(result["model_control_gate"], "OWNER_ACCEPTED_TRUSTED_LAN_RISK")
        self.assertTrue(result["owner_accepts_trusted_lan_risk"])
        self.assertIn("WAN exposure", result["probe_scope"])
        self.assertIn("router", result["next_requirement"])

    def test_unreachable_ports_never_certify_isolation(self):
        result = preflight.assess(
            "192.168.1.50", tcp_probe=lambda *_args: False,
            http_probe=lambda *_args: None,
        )
        self.assertEqual(result["model_control_gate"], "UNVERIFIED")
        self.assertIn("WAN safety", result["next_requirement"])

    def test_anonymous_controller_200_does_not_override_privileged_port_gate(self):
        result = preflight.assess(
            "192.168.1.50", accept_trusted_lan=True, tcp_probe=lambda *_args: True,
            http_probe=lambda *_args: 200,
        )
        self.assertEqual(result["model_control_gate"], "BLOCKED_UNAUTHENTICATED_CONTROLLER")
        self.assertEqual(result["controller_8082_http_status_without_credential"], 200)

    def test_cli_rejects_public_hostname_and_public_ipv4(self):
        for address in ("example.com", "8.8.8.8", "192.0.2.1", "127.0.0.1@evil.invalid"):
            with self.subTest(address=address), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as exit_code:
                preflight.main(["--ps5-host", address])
            self.assertEqual(exit_code.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
