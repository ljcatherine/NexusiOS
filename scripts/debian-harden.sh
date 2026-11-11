#!/usr/bin/env bash
# Applies the Debian firewall and key-only SSH, with an automatic rollback.
#
#   sudo ./debian-harden.sh apply      Apply, and undo in 5 minutes unless confirmed
#   sudo ./debian-harden.sh confirm    Keep the changes and make them permanent
#   sudo ./debian-harden.sh rollback   Undo everything
set -euo pipefail

SSH_OWNER="${SSH_OWNER:?set SSH_OWNER to the account that keeps key-only SSH access}"
ROLLBACK_MINUTES=5
RULES=/etc/nexus-hardening.nft
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-nexus-hardening.conf
INSTALLED=/usr/local/sbin/nexus-debian-harden
NFTABLES_CONF=/etc/nftables.conf
ROLLBACK_UNIT=nexus-hardening-rollback
INCLUDE_LINE="include \"$RULES\""

die() { echo "Stopped: $*" >&2; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || die "run this with sudo."; }

remove_include() {
    [[ -f $NFTABLES_CONF ]] || return 0
    local kept
    kept=$(mktemp)
    grep -vxF "$INCLUDE_LINE" "$NFTABLES_CONF" > "$kept" || true
    cat "$kept" > "$NFTABLES_CONF"
    rm -f "$kept"
}

apply() {
    require_root
    local source_rules
    source_rules="$(dirname "$(readlink -f "$0")")/nexus-hardening.nft"
    [[ -f $source_rules ]] || die "nexus-hardening.nft must sit beside this script."

    local keys="/home/$SSH_OWNER/.ssh/authorized_keys"
    [[ -s $keys ]] && grep -qE '(^|[ ,])ssh-ed25519 ' "$keys" ||
        die "$keys has no Ed25519 key, so key-only SSH could lock you out."
    ip link show tailscale0 >/dev/null 2>&1 || die "Tailscale is down, so keep it as your way back in."
    command -v nft >/dev/null || die "nft is not installed."
    if systemctl is-active --quiet "$ROLLBACK_UNIT.timer"; then
        die "a rollback is already pending. Run confirm or rollback first."
    fi

    nft -c -f "$source_rules" || die "the firewall rules failed validation. Nothing changed."

    # Scheduled first, so any later failure still undoes itself.
    install -m 0755 "$(readlink -f "$0")" "$INSTALLED"
    systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active="${ROLLBACK_MINUTES}min" "$INSTALLED" rollback

    install -m 0644 "$source_rules" "$RULES"
    printf '# Installed by nexus-debian-harden.\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
        > "$SSHD_DROPIN"
    chmod 0644 "$SSHD_DROPIN"
    if ! sshd -t; then
        "$INSTALLED" rollback
        die "sshd rejected the new settings. Everything was undone."
    fi

    nft -f "$RULES"
    systemctl reload ssh

    echo
    echo "Applied. It undoes itself in $ROLLBACK_MINUTES minutes unless you confirm."
    echo "Keep this session open. In a NEW session, check that you can still log in."
    echo "Then run: sudo $INSTALLED confirm"
}

confirm() {
    require_root
    systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
    [[ -f $RULES ]] || die "nothing to confirm."
    grep -qxF "$INCLUDE_LINE" "$NFTABLES_CONF" || echo "$INCLUDE_LINE" >> "$NFTABLES_CONF"
    nft -c -f "$NFTABLES_CONF" || {
        remove_include
        die "the boot ruleset failed validation. The live firewall stays, but will not survive a reboot."
    }
    echo "Confirmed. The firewall and key-only SSH will survive a reboot."
}

rollback() {
    require_root
    # Runs unattended, so every step continues even if an earlier one fails.
    systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
    nft delete table inet nexus_hardening 2>/dev/null || true
    rm -f "$RULES" "$SSHD_DROPIN"
    remove_include || true
    systemctl reload ssh || true
    echo "Rolled back: no Nexus firewall table, and SSH is back to its previous settings."
}

case "${1:-}" in
    apply) apply ;;
    confirm) confirm ;;
    rollback) rollback ;;
    *) echo "Usage: sudo $0 apply|confirm|rollback" >&2; exit 2 ;;
esac
