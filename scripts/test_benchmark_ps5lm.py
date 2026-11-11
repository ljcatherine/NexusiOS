import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import unittest

MODULE_PATH = Path(__file__).with_name("benchmark-ps5lm.py")
SPEC = importlib.util.spec_from_file_location("benchmark_ps5lm", MODULE_PATH)
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class _FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass

    def do_GET(self):
        if self.path != "/v1/models":
            self.send_error(404)
            return
        body = json.dumps({"data": [{"id": "fixture-model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert request["stream"] is True
        assert request["stream_options"]["include_usage"] is True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        events = [
            {"choices": [{"delta": {"role": "assistant"}}]},
            {"choices": [{"delta": {"content": "fixture answer"}}]},
            {"choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 3}},
        ]
        for event in events:
            self.wfile.write(b"data: " + json.dumps(event).encode() + b"\n\n")
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


class BenchmarkPS5LMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_private_http_base_url_is_normalized(self):
        self.assertEqual(benchmark.validate_base_url("http://192.168.1.50:8081"),
                         "http://192.168.1.50:8081/v1")
        self.assertEqual(benchmark.validate_base_url("http://100.64.20.1:8081/v1"),
                         "http://100.64.20.1:8081/v1")

    def test_rejects_public_cleartext_and_credential_urls(self):
        for value in ("http://example.com/v1", "http://8.8.8.8/v1",
                      "http://user:secret@192.168.1.4/v1", "https://example.com/v1?token=x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                benchmark.validate_base_url(value)

    def test_stream_metrics_use_provider_reported_usage(self):
        model_ids = benchmark.fetch_model_ids(self.base_url, "", timeout=2)
        self.assertEqual(model_ids, ["fixture-model"])
        result = benchmark.measure_once(self.base_url, "", "fixture-model", "synthetic prompt", 64, 2)
        self.assertGreaterEqual(result["time_to_first_text_ms"], 0)
        self.assertEqual(result["prompt_tokens_reported_by_server"], 12)
        self.assertEqual(result["completion_tokens_reported_by_server"], 3)
        self.assertIsNotNone(result["completion_tokens_per_second"])
        self.assertEqual(result["answer_and_reasoning_utf8_bytes"], len(b"fixture answer"))


if __name__ == "__main__":
    unittest.main()
