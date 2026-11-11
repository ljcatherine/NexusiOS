#!/usr/bin/env python3
"""Read-only PS5 management preflight with an explicit trusted-LAN risk option.

This tool cannot verify that PS5 ports are absent from WAN port-forwarding,
nor can it certify console isolation. Its accepted-risk status is a statement
of operator policy, NOT proof that the environment is secure or the controller
is ready to start.
"""

import argparse
import ipaddress
import json
import os
import re
import shlex
import socket
import stat
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


ALLOWED_LAN = tuple(ipaddress.ip_network(subnet) for subnet in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
))


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, _request, _fp, _code, _message, _headers, _new_url):
        return None


def tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_status(host: str, port: int, path: str, timeout: float = 2.0, *, bearer=None):
    headers = {"Authorization": "Bearer " + bearer} if bearer else {}
    request = Request(f"http://{host}:{port}{path}", method="GET", headers=headers)
    try:
        with build_opener(ProxyHandler({}), RejectRedirects()).open(request, timeout=timeout) as response:
            return response.status
    except HTTPError as error:
        return error.code  # 401 is evidence of a protected listener, not a valid token.
    except (URLError, OSError, ValueError):
        return None


def private_controller_token(path):
    """Read only the requested owner-private env; never print its contents."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("credential file must be owner-owned, regular and mode 0600")
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError("credential file too large")
    values = []
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("NEXUS_PS5_CONTROL_TOKEN="):
            words = shlex.split(line.split("=", 1)[1], comments=True)
            if len(words) != 1:
                raise ValueError("invalid controller credential")
            values.append(words[0])
    if len(values) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", values[0]):
        raise ValueError("missing, duplicate or invalid controller credential")
    return values[0]


def assess_controller_auth(host, token, probe=http_status):
    """GET-only checks; status codes are not model-switch or metadata acceptance."""
    path = "/v1/nexus/status"
    missing = probe(host, 8082, path)
    # Guaranteed different from the configured credential, while valid in format.
    invalid = ("b" if token[0] == "a" else "a") + token[1:]
    rejected = probe(host, 8082, path, bearer=invalid)
    valid = probe(host, 8082, path, bearer=token)
    models = probe(host, 8082, "/v1/nexus/models", bearer=token)
    return {
        "missing_auth_status": missing,
        "invalid_auth_status": rejected,
        "valid_auth_status": valid,
        "authenticated_inventory_status": models,
        "controller_auth_checks_pass": (missing, rejected, valid, models) == (401, 401, 200, 200),
        "model_switch_tested": False,
    }


def assess(host: str, *, accept_trusted_lan=False, tcp_probe=tcp_reachable,
           http_probe=http_status) -> dict:
    """Do not infer WAN policy, isolation or controller readiness from probes."""
    ftp = tcp_probe(host, 2121)
    loader = tcp_probe(host, 9021)
    inference = http_probe(host, 8081, "/health")
    controller = http_probe(host, 8082, "/v1/nexus/status")
    controller_unauthenticated = controller == 200
    privileged_ports_visible = ftp or loader
    if controller_unauthenticated:
        gate = "BLOCKED_UNAUTHENTICATED_CONTROLLER"
    elif privileged_ports_visible and not accept_trusted_lan:
        gate = "BLOCKED_PRIVILEGED_LAN_PORTS"
    elif privileged_ports_visible and accept_trusted_lan:
        gate = "OWNER_ACCEPTED_TRUSTED_LAN_RISK"
    else:
        gate = "UNVERIFIED"
    return {
        "ps5_host": host,
        "probe_scope": "development-host only; WAN exposure and LAN isolation not verified",
        "ftp_2121_reachable": ftp,
        "elf_loader_9021_reachable": loader,
        "inference_health_http_status": inference,
        "controller_8082_http_status_without_credential": controller,
        "owner_accepts_trusted_lan_risk": bool(accept_trusted_lan),
        "model_control_gate": gate,
        "next_requirement": (
            "Refuse an unauthenticated controller. Keep FTP/loader and controller "
            "off the public internet; verify this separately at the router. "
            "Before model switching, verify the dedicated bearer token, "
            "missing/invalid-auth 401, authenticated 200, Debian path, title "
            "backup and rollback. Trusted-LAN acceptance does not prove WAN safety."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ps5-host", required=True, help="PS5 private IPv4 address; no credentials")
    parser.add_argument("--accept-trusted-lan", action="store_true",
                        help="Record owner's acceptance of LAN-only privileged ports; does not verify WAN isolation")
    parser.add_argument("--controller-credential-env",
                        help="Optional owner-only 0600 env file on Debian; token is never an argument or output")
    args = parser.parse_args(argv)
    try:
        address = ipaddress.ip_address(args.ps5_host)
    except ValueError:
        parser.error("PS5 host must be a private numeric IPv4 address")
    if address.version != 4 or not any(address in network for network in ALLOWED_LAN):
        parser.error("PS5 host must be a private numeric IPv4 address")
    token = None
    if args.controller_credential_env:
        if not args.accept_trusted_lan:
            parser.error("credential probes require explicit --accept-trusted-lan")
        try:
            token = private_controller_token(args.controller_credential_env)
        except (OSError, ValueError):
            # Exception strings can include paths or malformed secret input.
            parser.error("cannot read a valid owner-private controller credential file")
    result = assess(str(address), accept_trusted_lan=args.accept_trusted_lan)
    if token is not None:
        result["controller_auth"] = assess_controller_auth(str(address), token)
    print(json.dumps(result, indent=2, sort_keys=True))
    # Exit 0 means only the operator's explicit trusted-LAN exception was
    # recorded. It NEVER certifies WAN isolation or controller authorization.
    if result["model_control_gate"].startswith("BLOCKED"):
        return 2
    if token is not None and not result["controller_auth"]["controller_auth_checks_pass"]:
        return 1
    return 0 if result["model_control_gate"] == "OWNER_ACCEPTED_TRUSTED_LAN_RISK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
