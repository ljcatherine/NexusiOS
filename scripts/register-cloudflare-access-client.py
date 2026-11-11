#!/usr/bin/env python3
"""Register Nexus as a public PKCE client for a Cloudflare Access app."""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def https_url(value: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("URL must be HTTPS and contain no credentials, query, or fragment")
    return parsed


def request_json(url: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    try:
        opener = urllib.request.build_opener(RejectRedirects)
        with opener.open(request, timeout=15) as response:
            if response.status < 200 or response.status >= 300:
                raise ValueError(f"Cloudflare returned HTTP {response.status}")
            if int(response.headers.get("Content-Length", "0")) > 256_000:
                raise ValueError("Cloudflare response exceeded the 256 KiB limit")
            body = response.read(256_001)
            if len(body) > 256_000:
                raise ValueError("Cloudflare response exceeded the 256 KiB limit")
            result = json.loads(body)
            if not isinstance(result, dict):
                raise ValueError("Cloudflare returned an invalid JSON object")
            return result
    except urllib.error.HTTPError as error:
        raise ValueError(f"Cloudflare returned HTTP {error.code}") from None
    except urllib.error.URLError:
        raise ValueError("Could not securely reach Cloudflare; check the URL and network") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("issuer_url", help="Cloudflare Access team issuer, for example https://team.cloudflareaccess.com")
    parser.add_argument("--resource-url", required=True, help="protected Worker origin, for example https://worker.example.workers.dev")
    parser.add_argument("--redirect-uri", help="HTTPS Worker callback URI; defaults to RESOURCE/oauth2redirect")
    args = parser.parse_args()

    issuer = https_url(args.issuer_url)
    if not (issuer.hostname or "").endswith(".cloudflareaccess.com") or issuer.path not in ("", "/"):
        raise ValueError("Issuer must be the Cloudflare Access team host")
    resource = https_url(args.resource_url)
    if resource.path not in ("", "/"):
        raise ValueError("Resource URL must be the protected Worker origin without a path")

    issuer_origin = urllib.parse.urlunsplit((issuer.scheme, issuer.netloc, "", "", ""))
    resource_origin = urllib.parse.urlunsplit((resource.scheme, resource.netloc, "", "", ""))
    redirect_uri = args.redirect_uri or resource_origin + "/oauth2redirect"
    redirect = https_url(redirect_uri)
    if redirect.hostname != resource.hostname or redirect.path != "/oauth2redirect" or redirect.port is not None:
        raise ValueError("Redirect URI must be the HTTPS /oauth2redirect path on the protected Worker origin")

    metadata = request_json(resource_origin + "/.well-known/oauth-authorization-server")
    if metadata.get("issuer") != issuer_origin:
        raise ValueError("Protected Worker OAuth metadata issuer does not match the configured team issuer")
    registration = metadata.get("registration_endpoint")
    if not isinstance(registration, str):
        raise ValueError("Managed OAuth metadata has no dynamic registration endpoint")
    registration_url = https_url(registration)
    if registration_url.hostname != issuer.hostname:
        raise ValueError("Registration endpoint is not on the configured Cloudflare Access team host")
    if metadata.get("code_challenge_methods_supported") is not None and "S256" not in metadata["code_challenge_methods_supported"]:
        raise ValueError("Cloudflare metadata does not advertise PKCE S256")

    result = request_json(registration, {
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "resource": resource_origin,
    })
    client_id = result.get("client_id")
    if not isinstance(client_id, str) or not client_id or len(client_id) > 512:
        raise ValueError("Cloudflare registration response did not include a valid client_id")
    print(client_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, json.JSONDecodeError) as error:
        print(f"Cloudflare OAuth client registration failed: {error}", file=sys.stderr)
        raise SystemExit(1)
