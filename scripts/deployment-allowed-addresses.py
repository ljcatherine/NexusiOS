"""Print the private IPv4 host of the deployment's default AI endpoint, if any.

The IPA validator rejects private IPv4 literals unless they are listed in
NEXUS_ALLOWED_PRIVATE_ADDRESSES. A deployment that deliberately prefills a
private endpoint (NexusDefaultAIEndpoint in local/deployment.plist) allows
exactly that address and nothing else.
"""
import ipaddress
import plistlib
import sys
from pathlib import Path
from urllib.parse import urlsplit


def allowed(path: Path) -> str:
    if not path.is_file():
        return ""
    with path.open("rb") as source:
        endpoint = plistlib.load(source).get("NexusDefaultAIEndpoint", "")
    host = urlsplit(endpoint).hostname or ""
    try:
        return host if ipaddress.IPv4Address(host).is_private else ""
    except ValueError:
        return ""


if __name__ == "__main__":
    print(allowed(Path(sys.argv[1])))
