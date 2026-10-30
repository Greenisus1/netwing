#!/bin/sh
# netwing installer - run on your Home Pi as root.
# Installs the app + dependencies WITHOUT starting any service and
# WITHOUT changing your network: applying anything needs a separate
# explicit `netwing --apply`, which runs a read-only preflight first.
set -e
if [ "$(id -u)" != "0" ]; then
    echo "run as root: sudo sh install.sh"; exit 1
fi
cd "$(dirname "$0")"

echo "netwing: installing the app files (no network changes)..."
cp netwing.py /usr/local/bin/netwing
chmod +x /usr/local/bin/netwing

echo "netwing: read-only preflight report (informational)..."
netwing --preflight || true

echo "netwing: installing packages (hostapd dnsmasq nftables)..."
echo "         service auto-start is suppressed; your running services"
echo "         are recorded and restored."
# Debian runs package postinst scripts which can auto-start services.
# policy-rc.d returning 101 is the standard way to forbid that; we add
# it only if none exists and remove our own copy afterwards.
POLICY=/usr/sbin/policy-rc.d
WROTE_POLICY=0
if [ ! -e "$POLICY" ]; then
    printf '#!/bin/sh\nexit 101\n' > "$POLICY"
    chmod 755 "$POLICY"
    WROTE_POLICY=1
fi
HOSTAPD_WAS=$(systemctl is-active hostapd 2>/dev/null || true)
DNSMASQ_WAS=$(systemctl is-active dnsmasq 2>/dev/null || true)
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq hostapd dnsmasq nftables
if [ "$WROTE_POLICY" = "1" ]; then
    rm -f "$POLICY"
fi
# belt and braces: if a service still started and was NOT running
# before, return it to its prior state (netwing starts its own
# configured instances at --apply time, never the distro ones)
if [ "$HOSTAPD_WAS" != "active" ] && [ "$(systemctl is-active hostapd 2>/dev/null || true)" = "active" ]; then
    systemctl stop hostapd || true
fi
if [ "$DNSMASQ_WAS" != "active" ] && [ "$(systemctl is-active dnsmasq 2>/dev/null || true)" = "active" ]; then
    systemctl stop dnsmasq || true
fi

echo ""
echo "Done. Nothing has been applied to your network."
echo "Next, when YOU are ready (ethernet cable plugged in):"
echo "  sudo netwing --apply"
echo "It inspects your setup, shows the plan, and asks before changing"
echo "anything - and rolls back by itself unless you keep it."
