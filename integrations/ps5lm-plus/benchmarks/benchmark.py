#!/usr/bin/env python3
"""Bounded, opt-in PS5LM Plus chat completion benchmark (Python stdlib only).

Read-only health and model discovery are the default. An inference POST requires
--run-live. Neither mode can change the active model or server configuration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


MAX_BODY_BYTES = 256 * 1024
PROMPT = "List the integers from 1 through 24, in order, separated by spaces. Output only the integers."


class BenchmarkError(Exception):
    """Expected HTTP, validation, or measurement failure."""


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_base_url(value: str) -> str:
    """Accept explicit loopback/private IP URLs; reject accidental public endpoints."""
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise BenchmarkError("--base-url must be a private HTTP(S) origin without credentials, path, query or fragment")
    try:
        host = parsed.hostname
        address = ipaddress.ip_address(host)
        if not (address.is_private or address.is_loopback):
            raise ValueError("not private")
    except ValueError as exc:
        if parsed.hostname != "localhost":
            raise BenchmarkError("--base-url must use a private IP or localhost") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise BenchmarkError("Invalid origin port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise BenchmarkError("Invalid origin port")
    return value.rstrip("/")


class HTTPClient:
    def __init__(self, base_url: str, timeout: float):
        self.base_url = check_base_url(base_url)
        self.timeout = timeout
        # Bypass host-level proxy environment variables for private endpoints.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects)

    def request(self, path: str, payload: dict | None = None) -> dict:
        headers = {"Accept": "application/json"}
        token = os.environ.get("PS5LM_BENCH_BEARER_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=True).encode("ascii")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                if response.status != 200:
                    raise BenchmarkError(f"{path}: HTTP {response.status}")
                length = response.headers.get("Content-Length")
                if length and int(length) > MAX_BODY_BYTES:
                    raise BenchmarkError(f"{path}: response exceeds size limit")
                raw = response.read(MAX_BODY_BYTES + 1)
                if len(raw) > MAX_BODY_BYTES:
                    raise BenchmarkError(f"{path}: response exceeds size limit")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise BenchmarkError(f"{path}: expected JSON object")
                return result
        except urllib.error.HTTPError as exc:
            # Never print response bodies, which may contain prompts or secrets.
            raise BenchmarkError(f"{path}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BenchmarkError(f"{path}: connection failed ({type(exc).__name__})") from exc
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise BenchmarkError(f"{path}: malformed JSON or response length") from exc


def get_inventory(client: HTTPClient) -> list[dict]:
    health = client.request("/health")
    if health.get("status") != "ok":
        raise BenchmarkError("/health: model server is not ready")
    inventory = client.request("/v1/models").get("data")
    if not isinstance(inventory, list):
        raise BenchmarkError("/v1/models: missing model list")
    for model in inventory:
        if not isinstance(model, dict) or not isinstance(model.get("id"), str) or not model["id"]:
            raise BenchmarkError("/v1/models: invalid model identity")
    return inventory


def model_metadata(model_id: str) -> dict:
    return {
        "model_filename": model_id.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
        "model_id_sha256": hashlib.sha256(model_id.encode("utf-8")).hexdigest(),
    }


def positive_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and number > 0 else None


def nonnegative_integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def parse_measurement(reply: dict, wall_seconds: float) -> dict:
    choices = reply.get("choices")
    if not isinstance(choices, list) or not choices:
        raise BenchmarkError("/v1/chat/completions: response has no choices")
    usage = reply.get("usage") if isinstance(reply.get("usage"), dict) else {}
    timings = reply.get("timings") if isinstance(reply.get("timings"), dict) else {}
    prompt_tokens = nonnegative_integer(usage.get("prompt_tokens"))
    eval_tokens = nonnegative_integer(usage.get("completion_tokens"))
    prompt_n = nonnegative_integer(timings.get("prompt_n"))
    predicted_n = nonnegative_integer(timings.get("predicted_n"))
    prompt_ms = positive_number(timings.get("prompt_ms"))
    predicted_ms = positive_number(timings.get("predicted_ms"))
    provider_tps = positive_number(timings.get("predicted_per_second"))
    if provider_tps is None and predicted_n is not None and predicted_ms is not None:
        provider_tps = predicted_n * 1000 / predicted_ms
    return {
        "wall_seconds": round(wall_seconds, 4),
        "prompt_tokens": prompt_tokens,
        "eval_tokens": eval_tokens,
        "wall_eval_tokens_per_second": round(eval_tokens / wall_seconds, 3)
        if eval_tokens is not None and wall_seconds > 0 else None,
        "server_prompt_n": prompt_n,
        "server_prompt_ms": round(prompt_ms, 3) if prompt_ms is not None else None,
        "server_predicted_n": predicted_n,
        "server_predicted_ms": round(predicted_ms, 3) if predicted_ms is not None else None,
        "server_generation_tokens_per_second": round(provider_tps, 3)
        if provider_tps is not None else None,
        "finish_reason": choices[0].get("finish_reason") if isinstance(choices[0], dict) else None,
    }


def run_benchmark(client: HTTPClient, model_id: str, count: int, max_tokens: int) -> dict:
    measurements = []
    for _ in range(count):
        payload = {
            "model": model_id,
            "messages": [{"role": "user", "content": PROMPT}],
            "temperature": 0,
            "max_tokens": max_tokens,
            "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        start = time.perf_counter()
        reply = client.request("/v1/chat/completions", payload)
        wall_seconds = time.perf_counter() - start
        measurements.append(parse_measurement(reply, wall_seconds))

    measured_tps = [item["server_generation_tokens_per_second"] for item in measurements
                    if item["server_generation_tokens_per_second"] is not None]
    return {
        "kind": "live_chat_completion_benchmark",
        "recorded_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "model": model_metadata(model_id),
        "request_limit": {"max_tokens": max_tokens, "requests": count,
                          "per_request_timeout_seconds": client.timeout},
        "prompt_kind": "fixed_24_integer_sequence_no_thinking",
        "results": measurements,
        "mean_server_generation_tokens_per_second": round(sum(measured_tps) / len(measured_tps), 3)
        if measured_tps else None,
        "measurement_note": "Server generation TPS excludes prompt processing when provided; "
                            "wall TPS includes end-to-end HTTP and prompt processing. "
                            "Null means the API did not report enough data.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Explicit private model server origin")
    parser.add_argument("--timeout", type=float, default=20.0, help="Seconds per request (1..60)")
    parser.add_argument("--run-live", action="store_true", help="Explicitly allow inference POST requests")
    parser.add_argument("--count", type=int, default=1, help="Number of prompts (1..3)")
    parser.add_argument("--max-tokens", type=int, default=48, help="Output token cap per prompt (8..128)")
    parser.add_argument("--model-index", type=int, help="Zero-based index from /v1/models for multi-model servers")
    parser.add_argument("--output", type=Path, help="Write sanitized JSON report without response text or secrets")
    args = parser.parse_args(argv)

    try:
        if not math.isfinite(args.timeout) or not 1 <= args.timeout <= 60:
            raise BenchmarkError("--timeout must be from 1 to 60 seconds")
        if not 1 <= args.count <= 3 or not 8 <= args.max_tokens <= 128:
            raise BenchmarkError("--count must be 1..3 and --max-tokens must be 8..128")
        if args.output is not None and not args.run_live:
            raise BenchmarkError("--output requires --run-live")
        if args.output is not None and args.output.exists():
            raise BenchmarkError("--output already exists; refusing to overwrite")
        client = HTTPClient(args.base_url, args.timeout)
        inventory = get_inventory(client)
        print(json.dumps({"mode": "probe_only", "health": "ok", "model_count": len(inventory),
                          "models": [{"index": i, **model_metadata(m["id"])}
                                     for i, m in enumerate(inventory)]}, indent=2))
        if not args.run_live:
            return 0
        if not inventory:
            raise BenchmarkError("No loaded model available")
        if args.model_index is None:
            if len(inventory) != 1:
                raise BenchmarkError("Multiple models: explicitly select --model-index from probe output")
            index = 0
        else:
            index = args.model_index
        if index < 0 or index >= len(inventory):
            raise BenchmarkError("--model-index is out of range")
        report = run_benchmark(client, inventory[index]["id"], args.count, args.max_tokens)
        print(json.dumps(report, indent=2))
        if args.output is not None:
            # Exclusive creation plus user-only mode even with a permissive umask.
            fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as destination:
                json.dump(report, destination, indent=2)
                destination.write("\n")
        return 0
    except BenchmarkError as exc:
        print(f"benchmark: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
