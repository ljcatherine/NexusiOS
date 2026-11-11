"""Require the iOS Simulator demo to be free of private endpoints and demo marker data."""
from pathlib import Path
import re
import sys

PRIVATE_IPV4 = re.compile(
    rb"(?<![0-9])(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|"
    rb"192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}|"
    rb"172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3})(?![0-9])"
)
TAILSCALE_DNS = re.compile(rb"(?i)(?:[a-z0-9-]+\.)+ts\.net")
DEMO_MARKER = "DEMO · simulated data only".encode()
SHARED_SCREEN_MARKERS = (
    b"nixos.example.invalid",
    b"debian.example.invalid",
    b"No SSH connection or command execution occurs in this preview.",
)


def validate(binary: bytes) -> None:
    if DEMO_MARKER not in binary:
        raise ValueError("Demo entry point marker is absent; refusing to package the app as a simulator preview.")
    missing = [marker.decode() for marker in SHARED_SCREEN_MARKERS if marker not in binary]
    if missing:
        raise ValueError("Shared production-screen demo markers are missing: " + ", ".join(missing))
    if PRIVATE_IPV4.search(binary):
        raise ValueError("Simulator demo contains an RFC1918 IPv4 address; remove production network configuration.")
    if TAILSCALE_DNS.search(binary):
        raise ValueError("Simulator demo contains a Tailscale DNS name; remove production network configuration.")


if __name__ == "__main__":
    try:
        validate(Path(sys.argv[1]).read_bytes())
        print("Verified demo marker and absence of private IPv4/Tailscale endpoints.")
    except (OSError, ValueError, IndexError) as error:
        raise SystemExit(f"Simulator demo privacy validation failed: {error}")
