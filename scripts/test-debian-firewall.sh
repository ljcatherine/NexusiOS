#!/usr/bin/env bash
# Tests nexus-hardening.nft with real TCP connections between two throwaway
# network namespaces. Nothing on the host changes.
#
#   nix-shell -p nftables iproute2 python3 --run scripts/test-debian-firewall.sh
set -euo pipefail

RULES="$(cd "$(dirname "$0")" && pwd)/debian/nexus-hardening.nft"

if [[ "${NEXUS_FIREWALL_TEST_INNER:-}" != 1 ]]; then
    exec env NEXUS_FIREWALL_TEST_INNER=1 unshare -rn bash "$0"
fi

WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

# This namespace plays Debian; the peer namespace plays each outside address.
ip link set lo up
ip link add wlo1 type veth peer name peer0
ip addr add 192.168.1.60/22 dev wlo1
ip addr add 203.0.113.1/24 dev wlo1
ip -6 addr add 2001:db8:1::1/64 dev wlo1 nodad
ip -6 addr add fdab:1170:ddb2:1::1/64 dev wlo1 nodad
ip link set wlo1 up
ip link add tailscale0 type veth peer name peer1
ip addr add 100.64.10.1/24 dev tailscale0
ip link set tailscale0 up
nft -f "$RULES"

python3 -I - > /dev/null 2>&1 <<'PY' &
import select, socket
listeners = []
for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    for port in (21, 22, 1716, 25565, 25575, 40010):
        s = socket.socket(family)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((host, port))
        s.listen(16)
        listeners.append(s)
while True:
    for s in select.select(listeners, [], [])[0]:
        s.accept()[0].close()
PY
sleep 0.5

cat > "$WORK/peer.sh" <<'PEER'
set -euo pipefail
while [[ ! -e "$1/moved" ]]; do sleep 0.05; done
ip link set lo up
ip link set peer0 up
ip link set peer1 up
python3 -I - <<'PY'
import socket, subprocess, sys

def connect(source, target, port, family=socket.AF_INET):
    s = socket.socket(family)
    s.settimeout(1)
    try:
        s.bind((source, 0))
        s.connect((target, port))
        return "open"
    except OSError:
        return "blocked"
    finally:
        s.close()

def use(device, address):
    subprocess.run(["ip", "addr", "flush", "dev", device], check=True)
    subprocess.run(["ip", "addr", "add", address, "dev", device, "nodad"] if ":" in address
                   else ["ip", "addr", "add", address, "dev", device], check=True)

failures = 0
def check(name, result, expected):
    global failures
    print(f"{'ok  ' if result == expected else 'FAIL'} {name}: {result}")
    failures += result != expected

use("peer0", "192.168.1.70/22")
for port, name in ((22, "SSH"), (21, "FTP"), (40010, "FTP passive"), (1716, "KDE Connect"), (25565, "Minecraft")):
    check(f"LAN {name}", connect("192.168.1.70", "192.168.1.60", port), "open")
check("LAN RCON", connect("192.168.1.70", "192.168.1.60", 25575), "blocked")

use("peer0", "203.0.113.9/24")
check("internet IPv4 Minecraft", connect("203.0.113.9", "203.0.113.1", 25565), "open")
for port, name in ((22, "SSH"), (21, "FTP"), (25575, "RCON"), (1716, "KDE Connect")):
    check(f"internet IPv4 {name}", connect("203.0.113.9", "203.0.113.1", port), "blocked")

use("peer0", "2001:db8:1::9/64")
for port, name in ((22, "SSH"), (25575, "RCON"), (25565, "Minecraft")):
    check(f"internet IPv6 {name}", connect("2001:db8:1::9", "2001:db8:1::1", port, socket.AF_INET6), "blocked")

use("peer0", "fdab:1170:ddb2:1::9/64")
check("LAN IPv6 SSH", connect("fdab:1170:ddb2:1::9", "fdab:1170:ddb2:1::1", 22, socket.AF_INET6), "open")

use("peer1", "100.64.10.2/24")
check("Tailscale SSH", connect("100.64.10.2", "100.64.10.1", 22), "open")
check("Tailscale RCON", connect("100.64.10.2", "100.64.10.1", 25575), "blocked")

sys.exit(1 if failures else 0)
PY
PEER

unshare -n bash "$WORK/peer.sh" "$WORK" &
PEER_PID=$!
sleep 0.3
ip link set peer0 netns "$PEER_PID"
ip link set peer1 netns "$PEER_PID"
touch "$WORK/moved"
wait "$PEER_PID"

python3 -I -c '
import socket
s = socket.create_connection(("127.0.0.1", 25575), timeout=1)
print("ok   loopback RCON: open")
'
echo "All firewall checks passed."
