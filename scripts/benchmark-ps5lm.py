#!/usr/bin/env python3
"""Measure OpenAI-compatible streaming latency without retaining prompts or output."""

import argparse
import ipaddress
import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_LINE_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 2 * 1_048_576


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


_OPENER = build_opener(_NoRedirect())


def validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Base URL must be an HTTP(S) origin with a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Base URL cannot contain credentials, a query, or a fragment.")
    if parsed.path not in ("", "/", "/v1"):
        raise ValueError("Base URL path must be empty, '/', or '/v1'.")
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            raise ValueError("Cleartext HTTP is allowed only for private IP addresses; use HTTPS for DNS names.") from exc
        if not (address.is_private or address.is_loopback or address.is_link_local or address in ipaddress.ip_network("100.64.0.0/10")):
            raise ValueError("Cleartext HTTP is allowed only for private, loopback, link-local, or Tailscale IPs.")
    return value.rstrip("/") + ("" if parsed.path.rstrip("/").endswith("/v1") else "/v1")


def _request(url: str, api_key: str, *, data: bytes | None = None, timeout: float) -> Request:
    headers = {"Accept": "application/json" if data is None else "text/event-stream",
               "Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return Request(url, data=data, headers=headers, method="GET" if data is None else "POST")


def fetch_model_ids(base_url: str, api_key: str, timeout: float) -> list[str]:
    try:
        with _OPENER.open(_request(base_url + "/models", api_key, timeout=timeout), timeout=timeout) as response:
            payload = response.read(1_048_577)
    except (HTTPError, URLError, TimeoutError) as exc:
        status = getattr(exc, "code", None)
        suffix = f"HTTP {status}" if status else type(exc).__name__
        raise RuntimeError(f"Model discovery failed ({suffix}); response details were withheld.") from None
    if len(payload) > 1_048_576:
        raise RuntimeError("Model list exceeded the 1 MiB safety limit.")
    try:
        models = json.loads(payload).get("data")
        if not isinstance(models, list):
            raise ValueError
        identifiers = [item["id"] for item in models if isinstance(item, dict) and isinstance(item.get("id"), str)]
    except (ValueError, TypeError, KeyError):
        raise RuntimeError("Model discovery returned an unexpected response format.") from None
    return identifiers


def measure_once(base_url: str, api_key: str, model: str, prompt: str, max_tokens: int,
                 timeout: float) -> dict:
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "stream": True,
        "stream_options": {"include_usage": True},
    }, separators=(",", ":")).encode()
    start = time.perf_counter()
    first_event = None
    total_bytes = 0
    completion_text_bytes = 0
    usage = None
    done = False
    try:
        with _OPENER.open(_request(base_url + "/chat/completions", api_key, data=body, timeout=timeout), timeout=timeout) as response:
            while True:
                line = response.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_LINE_BYTES:
                    raise RuntimeError("Provider stream line exceeded the 1 MiB safety limit.")
                total_bytes += len(line)
                if total_bytes > MAX_RESPONSE_BYTES:
                    raise RuntimeError("Provider stream exceeded the 2 MiB safety limit.")
                if not line.startswith(b"data:"):
                    continue
                data = line[5:].strip()
                if not data:
                    continue
                if data == b"[DONE]":
                    done = True
                    break
                try:
                    event = json.loads(data)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise RuntimeError("Provider stream contained malformed event data.") from None
                if isinstance(event.get("usage"), dict):
                    usage = event["usage"]
                choices = event.get("choices")
                if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                    delta = choices[0].get("delta")
                    if isinstance(delta, dict):
                        for key in ("content", "reasoning_content"):
                            value = delta.get(key)
                            if isinstance(value, str):
                                completion_text_bytes += len(value.encode("utf-8"))
                                if value and first_event is None:
                                    first_event = time.perf_counter()
    except (HTTPError, URLError, TimeoutError) as exc:
        status = getattr(exc, "code", None)
        suffix = f"HTTP {status}" if status else type(exc).__name__
        raise RuntimeError(f"Streaming request failed ({suffix}); response details were withheld.") from None
    if not done:
        raise RuntimeError("Provider closed the stream without the OpenAI-compatible [DONE] marker.")
    end = time.perf_counter()
    prompt_tokens = usage.get("prompt_tokens") if usage else None
    completion_tokens = usage.get("completion_tokens") if usage else None
    first_latency = None if first_event is None else first_event - start
    generation_seconds = None if first_event is None else end - first_event
    return {
        "time_to_first_text_ms": None if first_latency is None else round(first_latency * 1_000, 1),
        "request_to_done_seconds": round(end - start, 3),
        "prompt_tokens_reported_by_server": prompt_tokens,
        "completion_tokens_reported_by_server": completion_tokens,
        "prompt_tokens_per_second_estimate": _rate(prompt_tokens, first_latency),
        "completion_tokens_per_second": _rate(completion_tokens, generation_seconds),
        "answer_and_reasoning_utf8_bytes": completion_text_bytes,
        "token_rates_note": "Rates use provider-reported usage; no tokenizer estimates are presented." if usage else
            "Provider did not return streaming usage; token rates are unavailable.",
    }


def _rate(tokens, seconds):
    if not isinstance(tokens, int) or not isinstance(seconds, (float, int)) or seconds <= 0:
        return None
    return round(tokens / seconds, 2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("NEXUS_PS5LM_URL"),
                        help="PS5LM Plus OpenAI-compatible base URL (or set NEXUS_PS5LM_URL).")
    parser.add_argument("--model", default=os.environ.get("NEXUS_PS5LM_MODEL"),
                        help="Exact model ID returned by /v1/models (or set NEXUS_PS5LM_MODEL).")
    parser.add_argument("--runs", type=int, default=3, help="Measured streaming runs, 1–5 (default: 3).")
    parser.add_argument("--max-tokens", type=int, default=128, help="Output ceiling per run, 32–512 (default: 128).")
    parser.add_argument("--timeout", type=float, default=300, help="Per-request timeout in seconds, 2–1800 (default: 300).")
    args = parser.parse_args()
    if not args.base_url or not args.model:
        parser.error("provide --base-url and --model, or set NEXUS_PS5LM_URL and NEXUS_PS5LM_MODEL")
    if not 1 <= args.runs <= 5 or not 32 <= args.max_tokens <= 512 or not 2 <= args.timeout <= 1_800:
        parser.error("runs must be 1–5, max-tokens 32–512, and timeout 2–1800 seconds")
    try:
        base_url = validate_base_url(args.base_url)
        api_key = os.environ.get("NEXUS_PS5LM_API_KEY", "")
        models = fetch_model_ids(base_url, api_key, args.timeout)
        if args.model not in models:
            raise RuntimeError("Requested model ID was not present in the provider's current model list.")
        prompt = "Reply with a numbered list from 1 to 20, using one short word on each line."
        results = [measure_once(base_url, api_key, args.model, prompt, args.max_tokens, args.timeout)
                   for _ in range(args.runs)]
        print(json.dumps({
            "provider": "OpenAI-compatible PS5LM Plus endpoint",
            "model": args.model,
            "runs": results,
            "prompt_and_generated_text_saved": False,
            "stream_options_include_usage": True,
        }, indent=2))
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"PS5LM benchmark failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
