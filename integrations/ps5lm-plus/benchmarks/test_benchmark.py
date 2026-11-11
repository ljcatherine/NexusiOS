"""Local, mocked HTTP contract tests. Never contacts a PS5."""

from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import benchmark


class FakeServer(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def send_json(self, obj, status=200):
        content = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        self.server.get_paths.append(self.path)
        if self.path == "/health":
            self.send_json({"status": "ok"})
        elif self.path == "/v1/models":
            self.send_json({"data": [{"id": "/data/PS5LM/models/test-model.gguf"}]})
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.org/")
            self.end_headers()
        elif self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Length", str(benchmark.MAX_BODY_BYTES + 1))
            self.end_headers()
        else:
            self.send_json({"error": "not found"}, status=404)

    def do_POST(self):
        self.server.post_paths.append(self.path)
        self.server.last_request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path != "/v1/chat/completions":
            self.send_json({"error": "not found"}, status=404)
            return
        self.send_json({
            "choices": [{"message": {"content": "mock: secret response that must never be saved"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 19, "completion_tokens": 40, "total_tokens": 59},
            "timings": {"prompt_n": 19, "prompt_ms": 100,
                        "predicted_n": 40, "predicted_ms": 500,
                        "predicted_per_second": 80.0},
        })


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeServer)
        self.server.get_paths = []
        self.server.post_paths = []
        self.server.last_request = None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_probe_get_only(self):
        capture = io.StringIO()
        with redirect_stdout(capture):
            self.assertEqual(benchmark.main(["--base-url", self.base]), 0)
        self.assertEqual(self.server.get_paths, ["/health", "/v1/models"])
        self.assertEqual(self.server.post_paths, [])
        output = json.loads(capture.getvalue())
        self.assertEqual(output["mode"], "probe_only")
        self.assertEqual(output["models"][0]["model_filename"], "test-model.gguf")
        self.assertNotIn("/data/PS5LM", capture.getvalue())

    def test_measured_live_request_and_private_report(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "result.json"
            capture = io.StringIO()
            with redirect_stdout(capture):
                self.assertEqual(benchmark.main(["--base-url", self.base,
                                                 "--run-live", "--count", "2",
                                                 "--output", str(destination)]), 0)
            self.assertEqual(self.server.post_paths, ["/v1/chat/completions"] * 2)
            payload = self.server.last_request
            self.assertEqual(payload["model"], "/data/PS5LM/models/test-model.gguf")
            self.assertEqual(payload["max_tokens"], 48)
            self.assertFalse(payload["stream"])
            self.assertFalse(payload["chat_template_kwargs"]["enable_thinking"])
            report = json.loads(destination.read_text())
            self.assertEqual(len(report["results"]), 2)
            self.assertEqual(report["results"][0]["prompt_tokens"], 19)
            self.assertEqual(report["results"][0]["eval_tokens"], 40)
            self.assertEqual(report["results"][0]["server_generation_tokens_per_second"], 80.0)
            self.assertGreater(report["results"][0]["wall_seconds"], 0)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("secret response", capture.getvalue())
            self.assertNotIn("secret response", destination.read_text())
            self.assertNotIn("/data/PS5LM", destination.read_text())

    def test_missing_usage_and_timings_is_unknown_not_estimated(self):
        measurement = benchmark.parse_measurement({"choices": [{"finish_reason": "stop"}]}, 1.2)
        self.assertIsNone(measurement["prompt_tokens"])
        self.assertIsNone(measurement["eval_tokens"])
        self.assertIsNone(measurement["server_generation_tokens_per_second"])
        self.assertIsNone(measurement["wall_eval_tokens_per_second"])

    def test_timing_calculation_and_invalid_values(self):
        measurement = benchmark.parse_measurement({
            "choices": [{}], "usage": {"prompt_tokens": -1, "completion_tokens": True},
            "timings": {"predicted_n": 32, "predicted_ms": 200, "prompt_ms": float("nan")}
        }, 1.0)
        self.assertEqual(measurement["server_generation_tokens_per_second"], 160)
        self.assertIsNone(measurement["prompt_tokens"])
        self.assertIsNone(measurement["eval_tokens"])
        self.assertIsNone(measurement["server_prompt_ms"])

    def test_no_redirects_or_oversize_responses(self):
        client = benchmark.HTTPClient(self.base, 2)
        with self.assertRaisesRegex(benchmark.BenchmarkError, "HTTP 302"):
            client.request("/redirect")
        with self.assertRaisesRegex(benchmark.BenchmarkError, "size limit"):
            client.request("/large")

    def test_reject_public_targets_and_unsafe_limits(self):
        for url in ("https://example.com", "http://8.8.8.8:8081", "http://user:password@127.0.0.1",
                    "http://127.0.0.1/?token=123", "file:///etc/passwd"):
            with self.subTest(url=url), self.assertRaises(benchmark.BenchmarkError):
                benchmark.check_base_url(url)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(benchmark.main(["--base-url", self.base,
                                             "--run-live", "--count", "4"]), 1)
        self.assertEqual(self.server.get_paths, [])
        self.assertEqual(self.server.post_paths, [])

    def test_existing_output_file_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "already.json"
            destination.write_text("original")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(benchmark.main(["--base-url", self.base, "--run-live",
                                                 "--output", str(destination)]), 1)
            self.assertEqual(destination.read_text(), "original")
            self.assertEqual(self.server.get_paths, [])
            self.assertEqual(self.server.post_paths, [])


if __name__ == "__main__":
    unittest.main()
