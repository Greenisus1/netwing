#!/usr/bin/env python3
"""netwing - turn a Home Pi into your own router with network-wide ad blocking
and manual device approval.

Ethernet uplink (base version). The Pi broadcasts its own Wi-Fi network;
every device you approve gets filtered internet (ads/trackers/malware domains
sinkholed). New devices get NO internet until you approve them.

Safety model:
  * netwing --preflight is read-only and runs before anything changes.
  * apply requires a typed YES and a preflight pass.
  * a timed auto-rollback reverts everything unless you confirm "keep".
  * netwing --revert restores every file it touched and removes its rules.
  * the home router is never contacted or changed.

MIT License, copyright Greenisus1. Built with AI assistance from my design.
"""
import curses
import datetime
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
APP_NAME = "netwing"

# Real paths (all remapped under fake root when NETWING_FAKE_ROOT is set,
# which is how the test suite and the demo mode run without root/network).
ETC = "/etc/netwing"
CONF_PATH = ETC + "/netwing.json"
APPROVALS_PATH = ETC + "/approvals.json"
BLOCKLIST_PATH = ETC + "/blocklist.conf"
HOSTAPD_PATH = ETC + "/hostapd.conf"
DNSMASQ_PATH = ETC + "/dnsmasq.conf"
NFT_PATH = ETC + "/netwing.nft"
SYSCTL_PATH = "/etc/sysctl.d/90-netwing.conf"
DHCP_HOOK_PATH = "/usr/local/bin/netwing-dhcp-hook"
PORTAL_PORT = 8081
BACKUPS = ETC + "/backups"
CONFIRM_STAMP = ETC + "/keep-confirmed"
DNS_LOG = "/var/log/netwing-dns.log"
UNITS_DIR = "/etc/systemd/system"

DEFAULTS = {
    "ssid": "netwing",
    "password": "",               # asked in the wizard; WPA2, 8+ chars
    "subnet": "10.77.77.0/24",    # uncommon range, avoids typical LANs
    "ap_if": "wlan0",
    "uplink_if": "eth0",
    "dns_upstreams": ["1.1.1.1", "9.9.9.9"],
    # "new_devices": approve a device once, remembered by MAC.
    # "every_connect": every DHCP lease needs a fresh approval.
    # Chosen by the operator in the setup wizard; never assumed.
    "approval_mode": None,
    "blocklists": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    ],
    "applied_at": None,
    "stop_services": [],          # services apply() paused (revert restarts)
}

LEASE_DEL_EVENTS = {"del", "expire", "old-expire"}


class Sys:
    """All system reads/writes go through here so tests and demo mode can
    run the real code paths against fixture data with no root and no Pi."""

    def __init__(self):
        fake = os.environ.get("NETWING_FAKE_ROOT")
        self.fake_root = fake if fake else None
        self.ran = []             # commands "executed" (recorded in fake mode)

    def remap(self, path):
        if self.fake_root:
            return os.path.join(self.fake_root, path.lstrip("/"))
        return path

    def read(self, path):
        try:
            with open(self.remap(path), "r", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""

    def write(self, path, content, mode=0o644):
        path = self.remap(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, mode)

    def run(self, cmd, capture=True, check=False):
        """Run a command. In fake mode: record; answer from a stub file
        (<fakeroot>/cmdstub/<sanitized cmd>: rc line + stdout) if present."""
        if self.fake_root:
            self.ran.append(list(cmd))
            key = re.sub(r"[^A-Za-z0-9._-]+", "_", "-".join(cmd))
            stub = os.path.join(self.fake_root, "cmdstub", key)
            if os.path.exists(stub):
                with open(stub) as fh:
                    lines = fh.read().split("\n", 1)
                rc = int(lines[0])
                out = lines[1] if len(lines) > 1 else ""
                return rc, out, ""
            return 0, "", ""
        try:
            proc = subprocess.run(cmd, capture_output=capture, text=True,
                                  timeout=30)
            if check and proc.returncode != 0:
                raise RuntimeError("command failed: %s\n%s" %
                                   (" ".join(cmd), proc.stderr))
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except (OSError, subprocess.TimeoutExpired) as exc:
            if check:
                raise
            return 1, "", str(exc)

    def exists(self, path):
        return os.path.exists(self.remap(path))


SYS = Sys()


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def norm_mac(mac):
    mac = (mac or "").strip().lower()
    return mac if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) else None


# ---------------------------------------------------------------- config ---

def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(SYS.remap(CONF_PATH)) as fh:
            cfg.update(json.load(fh))
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    SYS.write(CONF_PATH, json.dumps(cfg, indent=2) + "\n")


# ------------------------------------------------------------- approvals ---

def load_approvals():
    try:
        with open(SYS.remap(APPROVALS_PATH)) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    for key in ("approved", "denied", "pending"):
        data.setdefault(key, {})
    return data


def save_approvals(data):
    SYS.write(APPROVALS_PATH, json.dumps(data, indent=2) + "\n")


def note_lease(event, mac, ip="", hostname="", mode="new_devices"):
    """A dnsmasq lease event arrived. Returns the device's new state:
    'approved', 'pending', 'denied', or 'ignored'."""
    mac = norm_mac(mac)
    if not mac:
        return "ignored"
    data = load_approvals()
    event = (event or "").lower()
    if event in LEASE_DEL_EVENTS:
        if mode == "every_connect" and mac in data["approved"]:
            # approval was for this connection only
            data["pending"][mac] = data["approved"].pop(mac)
            save_approvals(data)
            nft_sync_approvals(data)
            return "pending"
        return "ignored"
    if mac in data["denied"]:
        return "denied"
    if mode == "every_connect":
        # every reconnect needs a fresh manual approval
        if mac in data["approved"]:
            data["pending"][mac] = data["approved"].pop(mac)
        data["pending"].setdefault(mac, {})
        data["pending"][mac].update(
            {"ip": ip, "hostname": hostname, "last_seen": now_iso()})
        save_approvals(data)
        nft_sync_approvals(data)
        return "pending"
    # new_devices mode: first sighting goes to pending, approvals stick
    if mac in data["approved"]:
        data["approved"][mac].update({"ip": ip, "last_seen": now_iso()})
        save_approvals(data)
        return "approved"
    data["pending"].setdefault(mac, {})
    data["pending"][mac].update({
        "ip": ip, "hostname": hostname,
        "first_seen": data["pending"][mac].get("first_seen") or now_iso(),
        "last_seen": now_iso()})
    save_approvals(data)
    return "pending"


def approve_device(mac, name=""):
    mac = norm_mac(mac)
    if not mac:
        return False
    data = load_approvals()
    entry = data["pending"].pop(mac, data["denied"].pop(mac, {}))
    entry.update({"approved_at": now_iso()})
    if name:
        entry["name"] = name
    data["approved"][mac] = entry
    save_approvals(data)
    nft_sync_approvals(data)
    return True


def deny_device(mac):
    mac = norm_mac(mac)
    if not mac:
        return False
    data = load_approvals()
    entry = data["pending"].pop(mac, data["approved"].pop(mac, {}))
    entry["denied_at"] = now_iso()
    data["denied"][mac] = entry
    save_approvals(data)
    nft_sync_approvals(data)
    return True


def remove_device(mac):
    mac = norm_mac(mac)
    if not mac:
        return False
    data = load_approvals()
    gone = False
    for key in ("approved", "denied", "pending"):
        gone = data[key].pop(mac, None) is not None or gone
    save_approvals(data)
    nft_sync_approvals(data)
    return gone


def nft_sync_approvals(data):
    """Make the live nftables approved-set match the store. No-op until
    the table exists (i.e. until apply has run)."""
    if SYS.fake_root:
        SYS.ran.append(["nft", "sync-approved",
                        ",".join(sorted(data["approved"]))])
        return
    rc, out, _ = SYS.run(["nft", "list", "table", "inet", "netwing"])
    if rc != 0:
        return
    SYS.run(["nft", "flush", "set", "inet", "netwing", "approved"])
    for mac in sorted(data["approved"]):
        SYS.run(["nft", "add", "element", "inet", "netwing", "approved",
                 "{ %s }" % mac])
    # drop stale conntrack flows for the AP subnet so a revoked device
    # loses connectivity immediately, not just on its next new flow
    if shutil.which("conntrack"):
        cfg = load_config()
        SYS.run(["conntrack", "-D", "-s", str(
            ipaddress.ip_network(cfg["subnet"]))])


# ------------------------------------------------------------ blocklists ---

LOCAL_NAMES = {"localhost", "localhost.localdomain", "broadcasthost",
               "local", "0.0.0.0"}


def parse_hosts_file(text):
    """Parse a hosts-format blocklist into clean domain names.
    Returns (domains, skipped) counts for the UI."""
    domains = set()
    skipped = 0
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            skipped += 1
            continue
        if parts[0] not in ("0.0.0.0", "127.0.0.1", "::1", "::"):
            skipped += 1
            continue
        for name in parts[1:]:
            name = name.strip().lower().rstrip(".")
            if (not name or name in LOCAL_NAMES
                    or not re.fullmatch(r"[a-z0-9._-]+", name)
                    or "." not in name):
                skipped += 1
                continue
            domains.add(name)
    return sorted(domains), skipped


def render_blocklist(domains):
    lines = ["# netwing blocklist - %d domains, generated %s"
             % (len(domains), now_iso())]
    lines += ["address=/%s/0.0.0.0" % d for d in domains]
    return "\n".join(lines) + "\n"


def update_blocklists(cfg=None):
    """Fetch the configured blocklists and rewrite the dnsmasq block file.
    Returns (domain_count, errors). Network access happens here ONLY,
    and only when the operator runs it on the Pi."""
    cfg = cfg or load_config()
    all_domains, skipped_total, errors = set(), 0, []
    for url in cfg.get("blocklists", []):
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                text = resp.read().decode("utf-8", "replace")
            domains, skipped = parse_hosts_file(text)
            all_domains.update(domains)
            skipped_total += skipped
        except Exception as exc:            # network is the Pi's problem
            errors.append("%s: %s" % (url, exc))
    if all_domains:
        SYS.write(BLOCKLIST_PATH, render_blocklist(sorted(all_domains)))
    return len(all_domains), errors


# -------------------------------------------------------- config renders ---

def ap_ip(cfg):
    # the Pi itself is the first usable address on the AP subnet
    return str(list(ipaddress.ip_network(cfg["subnet"]).hosts())[0])


def dhcp_range(cfg):
    net = ipaddress.ip_network(cfg["subnet"])
    hosts = list(net.hosts())
    start = hosts[min(99, len(hosts) - 2)]
    end = hosts[-1]
    return str(start), str(end)


def render_hostapd(cfg):
    return """# netwing access point config - generated %s
interface=%s
driver=nl80211
ssid=%s
country_code=US
hw_mode=g
channel=6
wmm_enabled=1
auth_algs=1
wpa=2
wpa_passphrase=%s
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
""" % (now_iso(), cfg["ap_if"], cfg["ssid"], cfg["password"])


def render_dnsmasq(cfg):
    start, end = dhcp_range(cfg)
    ip = ap_ip(cfg)
    upstreams = "\n".join("server=%s" % u
                          for u in cfg.get("dns_upstreams", []))
    return """# netwing dns+dhcp on the AP interface only - generated %s
interface=%s
bind-interfaces
except-interface=lo
no-resolv
domain-needed
bogus-priv
%s
dhcp-range=%s,%s,12h
dhcp-option=3,%s
dhcp-option=6,%s
dhcp-script=%s
log-dhcp
log-queries=extra
log-facility=%s
conf-file=%s
""" % (now_iso(), cfg["ap_if"], upstreams, start, end, ip, ip,
       DHCP_HOOK_PATH, DNS_LOG, BLOCKLIST_PATH)


def render_nft(cfg):
    ap, uplink = cfg["ap_if"], cfg["uplink_if"]
    return """#!/usr/sbin/nft -f
# netwing rules - self-contained table; delete with: nft delete table inet netwing
table inet netwing {
    set approved {
        type ether_addr
    }
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        # unapproved devices: plain-HTTP probes land on the captive portal
        iifname "%s" meta nfproto ipv4 ether saddr != @approved tcp dport 80 redirect to :%d
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        # default-deny FIRST, for IPv4 and IPv6 alike: an unapproved
        # device never reaches the uplink, even on flows that were
        # already open when its approval was revoked
        iifname "%s" oifname "%s" ether saddr != @approved drop
        ct state established,related accept
        iifname "%s" oifname "%s" ether saddr @approved accept
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        meta nfproto ipv4 oifname "%s" masquerade
    }
}
""" % (ap, PORTAL_PORT, ap, uplink, ap, uplink, uplink)


def render_sysctl():
    return "# netwing: routing between the AP and the uplink\nnet.ipv4.ip_forward=1\n"


def render_dhcp_hook():
    return """#!/bin/sh
# netwing lease hook - called by dnsmasq as: hook add|old|del MAC IP HOSTNAME
exec /usr/local/bin/netwing --lease-event "$1" "$2" "$3" "$4" \
    >> /var/log/netwing-hook.log 2>&1
"""


def render_unit(name, after, exec_start, exec_start_pre=None, oneshot=False):
    pre = ""
    if exec_start_pre:
        pre = "".join("ExecStartPre=%s\n" % c for c in exec_start_pre)
    svc_type = "oneshot\nRemainAfterExit=yes" if oneshot else "simple"
    return """[Unit]
Description=netwing %s
After=%s

[Service]
Type=%s
%sExecStart=%s

[Install]
WantedBy=multi-user.target
""" % (name, after, svc_type, pre, exec_start)


def render_units(cfg):
    ip = ap_ip(cfg)
    ap = cfg["ap_if"]
    units = {
        "netwing-net.service": render_unit(
            "network (AP address, forwarding, firewall)", "network.target",
            "/usr/local/bin/netwing --net-up", oneshot=True),
        "netwing-hostapd.service": render_unit(
            "access point", "netwing-net.service",
            "/usr/sbin/hostapd %s" % HOSTAPD_PATH),
        "netwing-dnsmasq.service": render_unit(
            "dns+dhcp", "netwing-net.service",
            "/usr/sbin/dnsmasq -k -C %s" % DNSMASQ_PATH),
        "netwing-portal.service": render_unit(
            "captive portal", "netwing-net.service",
            "/usr/local/bin/netwing --portal"),
    }
    return units


# ------------------------------------------------------------- preflight ---

WATCHED_SERVICES = ["hostapd", "dnsmasq", "NetworkManager", "dhcpcd",
                    "wpa_supplicant", "guestwing"]


def collect_interfaces():
    """{name: {up, mac, ipv4, carrier}} from ip -j addr."""
    rc, out, _ = SYS.run(["ip", "-j", "addr", "show"])
    ifaces = {}
    try:
        for link in json.loads(out):
            name = link.get("ifname", "")
            ipv4 = [a["local"] for a in link.get("addr_info", [])
                    if a.get("family") == "inet"]
            ifaces[name] = {
                "up": "UP" in link.get("flags", []),
                "mac": link.get("address", ""),
                "ipv4": ipv4,
                "carrier": SYS.read(
                    "/sys/class/net/%s/carrier" % name).strip() == "1",
            }
    except ValueError:
        try:
            names = os.listdir(SYS.remap("/sys/class/net"))
        except OSError:
            names = []
        for name in names:
            ifaces[name] = {"up": False, "mac": "", "ipv4": [],
                            "carrier": False}
    return ifaces


def default_route_dev():
    rc, out, _ = SYS.run(["ip", "-j", "route", "show", "default"])
    try:
        routes = json.loads(out)
        if routes:
            return routes[0].get("dev", "")
    except ValueError:
        pass
    return ""


def parse_proc_net_tcp(text):
    """Established TCP connections: list of (local_ip, local_port,
    rem_ip, rem_port)."""
    conns = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 4 or f[3] != "01":       # 01 = ESTABLISHED
            continue
        lip_hex, lp_hex = f[1].rsplit(":", 1)
        rip_hex, rp_hex = f[2].rsplit(":", 1)
        conns.append((lip_hex, int(lp_hex, 16), rip_hex, int(rp_hex, 16)))
    return conns


def _hex_to_ipv4(h):
    raw = bytes.fromhex(h)
    return ".".join(str(b) for b in raw[::-1])


def ssh_client_ips():
    """Remote IPs of established sessions on local TCP port 22."""
    ips = []
    for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        for lip, lp, rip, rp in parse_proc_net_tcp(SYS.read(path)):
            if lp == 22 and not v6:
                ips.append(_hex_to_ipv4(rip))
    return ips


def route_dev_for(ip):
    rc, out, _ = SYS.run(["ip", "route", "get", ip])
    m = re.search(r"\bdev\s+(\S+)", out)
    return m.group(1) if m else ""


def active_services():
    states = {}
    for name in WATCHED_SERVICES + ["netwing-hostapd", "netwing-dnsmasq"]:
        rc, out, _ = SYS.run(["systemctl", "is-active", name])
        states[name] = (out.strip() or "unknown") if rc == 0 or out else "unknown"
    return states


def missing_binaries():
    need = {"hostapd": "hostapd", "dnsmasq": "dnsmasq", "nft": "nftables"}
    missing = []
    for binary, pkg in need.items():
        if SYS.fake_root:
            continue
        if shutil.which(binary) is None:
            missing.append((binary, pkg))
    return missing


def run_preflight(cfg=None):
    """Read-only inspection. Returns {ok, blocks, warnings, facts}.
    A block means apply refuses; a warning needs an explicit typed override."""
    cfg = cfg or load_config()
    blocks, warnings, facts = [], [], {}
    ifaces = collect_interfaces()
    facts["interfaces"] = ifaces
    ap, uplink = cfg["ap_if"], cfg["uplink_if"]

    if ap not in ifaces:
        blocks.append("AP interface %s does not exist on this machine" % ap)
    if uplink not in ifaces:
        blocks.append("uplink interface %s does not exist" % uplink)
    else:
        up = ifaces[uplink]
        facts["uplink_ipv4"] = up["ipv4"]
        if not up["carrier"] and not up["ipv4"]:
            blocks.append("uplink %s has no cable/link - the base version "
                          "needs ethernet plugged in" % uplink)
        elif not up["ipv4"]:
            blocks.append("uplink %s has link but no IPv4 address yet"
                          % uplink)

    route_dev = default_route_dev()
    facts["default_route_dev"] = route_dev
    if route_dev == ap:
        blocks.append("your internet currently comes IN through %s (Wi-Fi). "
                      "The base version turns %s into an access point, which "
                      "would cut that. Plug in ethernet first." % (ap, ap))

    ssh = []
    for ip in ssh_client_ips():
        dev = route_dev_for(ip)
        ssh.append({"ip": ip, "dev": dev})
        if dev == ap:
            blocks.append("SSH session from %s arrives via %s - applying "
                          "would cut this session" % (ip, ap))
    facts["ssh_sessions"] = ssh

    svc = active_services()
    facts["services"] = svc
    if svc.get("guestwing") == "active":
        blocks.append("guestwing is running and owns the Wi-Fi radio - stop "
                      "it yourself first (netwing never touches it)")
    if svc.get("hostapd") == "active":
        warnings.append("a non-netwing hostapd is already active")
    if svc.get("dnsmasq") == "active":
        warnings.append("a non-netwing dnsmasq is already active")
    if svc.get("NetworkManager") == "active":
        warnings.append("NetworkManager may fight for control of %s" % ap)

    missing = missing_binaries()
    if missing:
        warnings.append("missing packages: %s (run: sudo apt install %s)"
                        % (", ".join(b for b, _ in missing),
                           " ".join(sorted({p for _, p in missing}))))
    facts["missing"] = [b for b, _ in missing]
    facts["ok"] = not blocks
    return {"ok": not blocks, "blocks": blocks, "warnings": warnings,
            "facts": facts}


# ---------------------------------------------------------- apply/revert ---

def backup_existing():
    """Back up every pre-existing file netwing will replace. Returns the
    backup dir. Only app-owned paths are ever touched."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = "%s/%s" % (BACKUPS, stamp)
    for path in (SYSCTL_PATH,):
        if SYS.exists(path):
            target = "%s%s" % (dest, path)
            SYS.write(target, SYS.read(path))
    prev_forward = SYS.read("/proc/sys/net/ipv4/ip_forward").strip() or "0"
    SYS.write("%s/ip_forward.was" % dest, prev_forward + "\n")
    return dest


def apply(cfg, stop_services=("wpa_supplicant",)):
    """Write app-owned config, start app-owned services. The timed
    auto-rollback is armed BEFORE anything live changes, so a crash or
    disconnect mid-apply still reverts. Returns the backup dir. Callers
    must have shown the plan and collected a typed YES already."""
    backup_dir = backup_existing()
    cfg["applied_at"] = now_iso()
    cfg["stop_services"] = []
    save_config(cfg)
    # armed first: systemd-run is a system-level transient timer, so it
    # survives this SSH session ending
    rc, _, err = SYS.run(["systemd-run", "--unit=netwing-rollback",
                          "--on-active=300",
                          "/usr/local/bin/netwing", "--auto-rollback"])
    if rc != 0:
        cfg["applied_at"] = None
        save_config(cfg)
        raise RuntimeError("could not arm the auto-rollback timer "
                           "(%s) - aborting with no live changes" % err)
    stopped = []
    for svc in stop_services:
        rc, out, _ = SYS.run(["systemctl", "is-active", svc])
        if out.strip() == "active":
            SYS.run(["systemctl", "stop", svc])
            stopped.append(svc)
    cfg["stop_services"] = stopped
    save_config(cfg)

    SYS.write(HOSTAPD_PATH, render_hostapd(cfg))
    SYS.write(DNSMASQ_PATH, render_dnsmasq(cfg))
    SYS.write(NFT_PATH, render_nft(cfg))
    SYS.write(SYSCTL_PATH, render_sysctl())
    SYS.write(DHCP_HOOK_PATH, render_dhcp_hook(), mode=0o755)
    if not SYS.exists(BLOCKLIST_PATH):
        SYS.write(BLOCKLIST_PATH, "# netwing blocklist (empty until updated)\n")
    for name, content in render_units(cfg).items():
        SYS.write(os.path.join(UNITS_DIR, name), content)
    save_config(cfg)

    SYS.run(["systemctl", "daemon-reload"])
    for unit in render_units(cfg):
        SYS.run(["systemctl", "enable", "--now", unit])
    return backup_dir


def net_up(cfg):
    """Brought up by netwing-net.service at boot/apply."""
    ip = ap_ip(cfg)
    prefix = ipaddress.ip_network(cfg["subnet"]).prefixlen
    ap = cfg["ap_if"]
    SYS.run(["ip", "link", "set", ap, "up"])
    SYS.run(["ip", "addr", "replace", "%s/%d" % (ip, prefix), "dev", ap])
    SYS.run(["nft", "-f", NFT_PATH])
    SYS.write("/proc/sys/net/ipv4/ip_forward", "1")


def confirm_keep():
    SYS.run(["systemctl", "stop", "netwing-rollback.timer"])
    SYS.write(CONFIRM_STAMP, now_iso() + "\n")


def auto_rollback():
    cfg = load_config()
    try:
        stamp = os.path.getmtime(SYS.remap(CONFIRM_STAMP))
        applied = datetime.datetime.fromisoformat(cfg["applied_at"] or
                                                  "1970-01-01T00:00:00")
        if stamp >= applied.timestamp():
            return False                     # operator confirmed; keep
    except OSError:
        pass
    revert(cfg, purge=False)
    return True


def revert(cfg=None, purge=False):
    """Remove only netwing-owned state; restore what apply() changed."""
    cfg = cfg or load_config()
    SYS.run(["systemctl", "stop", "netwing-rollback.timer"])
    for unit in render_units(cfg):
        SYS.run(["systemctl", "disable", "--now", unit])
        path = os.path.join(UNITS_DIR, unit)
        if SYS.exists(path):
            os.remove(SYS.remap(path))
    SYS.run(["nft", "delete", "table", "inet", "netwing"])
    ip = ap_ip(cfg)
    prefix = ipaddress.ip_network(cfg["subnet"]).prefixlen
    SYS.run(["ip", "addr", "del", "%s/%d" % (ip, prefix),
             "dev", cfg["ap_if"]])
    prev = "0"
    if cfg.get("applied_at"):
        backups = sorted(os.listdir(SYS.remap(BACKUPS))
                         if SYS.exists(BACKUPS) else [])
        if backups:
            was = SYS.read("%s/%s/ip_forward.was" % (BACKUPS, backups[-1]))
            prev = was.strip() or "0"
    SYS.write("/proc/sys/net/ipv4/ip_forward", prev)
    if SYS.exists(SYSCTL_PATH):
        os.remove(SYS.remap(SYSCTL_PATH))
    for svc in cfg.get("stop_services", []):
        SYS.run(["systemctl", "start", svc])
    SYS.run(["systemctl", "daemon-reload"])
    cfg["applied_at"] = None
    save_config(cfg)
    if purge and SYS.exists(ETC):
        shutil.rmtree(SYS.remap(ETC))


# ---------------------------------------------------------- captive portal ---

def arp_table():
    """client ip -> mac from /proc/net/arp."""
    table = {}
    for line in SYS.read("/proc/net/arp").splitlines()[1:]:
        f = line.split()
        if len(f) >= 4:
            table[f[0]] = f[3].lower()
    return table


PORTAL_PAGE = """<!doctype html><meta name=viewport content="width=device-width">
<title>netwing</title>
<body style="background:#0b1020;color:#e8ecf8;font-family:system-ui;
display:flex;min-height:100vh;align-items:center;justify-content:center">
<div style="max-width:26rem;text-align:center">
<h1 style="color:#7dd3fc">netwing</h1>
<p style="font-size:1.2rem">%(state)s</p>
<p>This device: <code>%(mac)s</code><br>%(host)s %(ip)s</p>
<p style="opacity:.7">Ads and trackers are blocked on this network.
Ask the network owner to approve this device.</p>
</div>"""


def render_portal_page(client_ip):
    mac = arp_table().get(client_ip, "unknown device")
    data = load_approvals()
    if mac in data["approved"]:
        state = "This device is approved. You are online."
    elif mac in data["denied"]:
        state = "This device was denied internet access."
    else:
        state = "Waiting for the network owner to approve this device..."
    host = ""
    try:
        host = socket.getfqdn(client_ip)
    except OSError:
        pass
    return PORTAL_PAGE % {"state": state, "mac": mac,
                          "host": host if host != client_ip else "",
                          "ip": client_ip}


class PortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = render_portal_page(self.client_address[0]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def run_portal():
    server = ThreadingHTTPServer(("0.0.0.0", PORTAL_PORT), PortalHandler)
    server.serve_forever()


# ---------------------------------------------------------------- status ---

def service_active(name):
    rc, out, _ = SYS.run(["systemctl", "is-active", name])
    return out.strip() == "active"


def blocked_count():
    """Blocked DNS answers so far, from the dnsmasq log."""
    count = 0
    for line in SYS.read(DNS_LOG).splitlines():
        if " is 0.0.0.0" in line or " config " in line and "0.0.0.0" in line:
            count += 1
    return count


def dhcp_leases():
    leases = {}
    for line in SYS.read("/var/lib/misc/dnsmasq.leases").splitlines():
        f = line.split()
        if len(f) >= 4:
            leases[f[1].lower()] = {"ip": f[2], "hostname": f[3]}
    return leases


def collect_status(cfg):
    return {
        "applied": bool(cfg.get("applied_at")),
        "ap": service_active("netwing-hostapd"),
        "dns": service_active("netwing-dnsmasq"),
        "portal": service_active("netwing-portal"),
        "blocked": blocked_count(),
        "leases": dhcp_leases(),
        "approvals": load_approvals(),
    }


# -------------------------------------------------------------------- UI ---

TABS = ["Status", "Devices", "Blocklists", "YouTube", "Settings"]

YOUTUBE_TEXT = [
    "YouTube ads: the honest version",
    "",
    "DNS blocking (netwing, Pi-hole, AdGuard Home - all of them) CANNOT",
    "remove YouTube video ads. YouTube serves ads from the same domains",
    "as the videos (googlevideo.com), so a DNS blocker can only block",
    "both or neither. YouTube also now stitches some ads into the video",
    "stream itself (server-side insertion).",
    "",
    "What netwing DOES block on YouTube: nothing in the video itself.",
    "What it blocks everywhere else: ad/tracker/malware domains for every",
    "approved device on this network.",
    "",
    "What actually removes YouTube ads (per device, your choice):",
    "  - a browser with uBlock Origin, on computers",
    "  - SmartTube-type apps on Android/Google TV",
    "  - YouTube Premium (the only option that works everywhere)",
]


def draw_tab_bar(win, current, width):
    x = 1
    for i, name in enumerate(TABS):
        label = " %s " % name
        attr = curses.A_REVERSE if i == current else curses.A_NORMAL
        try:
            win.addstr(1, x, label, attr)
        except curses.error:
            pass
        x += len(label) + 1


def ui_status(win, cfg, st, y0=3):
    lines = [
        "SSID: %s   network: %s   uplink: %s" % (
            cfg["ssid"], cfg["subnet"], cfg["uplink_if"]),
        "Router active: %s   AP: %s   DNS: %s   portal: %s" % (
            "yes" if st["applied"] else "no",
            "up" if st["ap"] else "down",
            "up" if st["dns"] else "down",
            "up" if st["portal"] else "down"),
        "Blocked ad/tracker lookups: %d" % st["blocked"],
        "Devices online: %d   approved: %d   waiting: %d   denied: %d" % (
            len(st["leases"]), len(st["approvals"]["approved"]),
            len(st["approvals"]["pending"]), len(st["approvals"]["denied"])),
        "",
        "Approval rule: %s" % (
            {"new_devices": "approve each NEW device once (remembered)",
             "every_connect": "approve EVERY connection"}.get(
                cfg.get("approval_mode"), "not set yet - run setup")),
    ]
    for i, line in enumerate(lines):
        try:
            win.addstr(y0 + i, 2, line)
        except curses.error:
            pass


def ui_devices(win, st, sel):
    data = st["approvals"]
    rows = []
    for mac, e in data["pending"].items():
        rows.append(("WAITING", mac, e.get("hostname") or "?",
                     e.get("ip", "")))
    for mac, e in data["approved"].items():
        rows.append(("approved", mac, e.get("name") or e.get("hostname")
                     or "?", e.get("ip", "")))
    for mac, e in data["denied"].items():
        rows.append(("DENIED", mac, e.get("hostname") or "?",
                     e.get("ip", "")))
    try:
        win.addstr(3, 2, "a=approve  d=deny  x=remove", curses.A_BOLD)
    except curses.error:
        pass
    for i, (state, mac, name, ip) in enumerate(rows):
        attr = curses.A_REVERSE if i == sel else curses.A_NORMAL
        try:
            win.addstr(5 + i, 2, "%-8s %-19s %-20s %s"
                       % (state, mac, name[:20], ip), attr)
        except curses.error:
            pass
    if not rows:
        try:
            win.addstr(5, 2, "no devices seen yet")
        except curses.error:
            pass
    return rows


def ui_blocklists(win, cfg):
    count = 0
    if SYS.exists(BLOCKLIST_PATH):
        count = max(0, len(SYS.read(BLOCKLIST_PATH).splitlines()) - 1)
    lines = ["Blocklists in use:"]
    lines += ["  " + u for u in cfg.get("blocklists", [])]
    lines += ["", "Domains blocked: %d" % count, "",
              "press u to download the latest lists"]
    for i, line in enumerate(lines):
        try:
            win.addstr(3 + i, 2, line)
        except curses.error:
            pass


def ui_youtube(win):
    for i, line in enumerate(YOUTUBE_TEXT):
        try:
            win.addstr(3 + i, 2, line,
                       curses.A_BOLD if i == 0 else curses.A_NORMAL)
        except curses.error:
            pass


def ui_settings(win, cfg):
    lines = [
        "s = change Wi-Fi name / password",
        "k = confirm KEEP after apply (cancels auto-rollback)",
        "R = revert EVERYTHING netwing changed (type REVERT)",
        "",
        "netwing only ever changes its own files, services and firewall",
        "table. Your home router is never contacted or changed. Revert",
        "restores what apply() backed up and removes the rest.",
    ]
    for i, line in enumerate(lines):
        try:
            win.addstr(3 + i, 2, line)
        except curses.error:
            pass


def run_ui(stdscr):
    curses.curs_set(0)
    stdscr.timeout(1500)
    tab, sel = 0, 0
    while True:
        cfg = load_config()
        st = collect_status(cfg)
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        try:
            stdscr.addstr(0, 1, " netwing %s - your Pi, your router "
                          % VERSION, curses.A_BOLD)
        except curses.error:
            pass
        draw_tab_bar(stdscr, tab, w)
        if tab == 0:
            ui_status(stdscr, cfg, st)
        elif tab == 1:
            rows = ui_devices(stdscr, st, sel)
        elif tab == 2:
            ui_blocklists(stdscr, cfg)
        elif tab == 3:
            ui_youtube(stdscr)
        else:
            ui_settings(stdscr, cfg)
        try:
            stdscr.addstr(h - 1, 1, " 1-5 tabs   q quit ", curses.A_DIM)
        except curses.error:
            pass
        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord("q"), 27):
            return
        if key in (curses.KEY_LEFT,):
            tab = (tab - 1) % len(TABS)
        elif key in (curses.KEY_RIGHT,):
            tab = (tab + 1) % len(TABS)
        elif ord("1") <= key <= ord("5"):
            tab = key - ord("1")
            sel = 0
        elif tab == 1 and rows:
            if key == curses.KEY_UP:
                sel = max(0, sel - 1)
            elif key == curses.KEY_DOWN:
                sel = min(len(rows) - 1, sel + 1)
            elif key in (ord("a"), ord("d"), ord("x")):
                mac = rows[sel][1]
                if key == ord("a"):
                    approve_device(mac)
                elif key == ord("d"):
                    deny_device(mac)
                else:
                    remove_device(mac)
                sel = 0
        elif tab == 2 and key == ord("u"):
            update_blocklists(cfg)
            if st["dns"]:
                SYS.run(["systemctl", "restart", "netwing-dnsmasq"])
        elif tab == 4:
            if key == ord("k"):
                confirm_keep()
            elif key == ord("s"):
                curses.endwin()
                wizard_network(cfg)
            elif key == ord("R"):
                curses.endwin()
                confirm_revert_cli()


# ------------------------------------------------------------ wizard/CLI ---

def ask(prompt, secret=False):
    if secret:
        import getpass
        return getpass.getpass(prompt)
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def wizard_network(cfg):
    print("netwing Wi-Fi setup")
    ssid = ask("Wi-Fi name (SSID) [%s]: " % cfg["ssid"]) or cfg["ssid"]
    while True:
        pw = ask("Wi-Fi password (8+ characters): ", secret=True)
        if len(pw) >= 8:
            break
        print("too short - WPA2 needs at least 8 characters")
    cfg["ssid"], cfg["password"] = ssid, pw
    save_config(cfg)
    print("saved. Re-run netwing to apply with the new name/password.")


def wizard_approval_mode(cfg):
    """The operator must pick explicitly - there is no default."""
    print("\nHow should internet approval work?")
    print("  1 = a NEW device asks once; approved devices stay approved")
    print("  2 = EVERY connection asks; approved lasts until disconnect")
    while cfg.get("approval_mode") not in ("new_devices", "every_connect"):
        choice = ask("choose 1 or 2: ")
        if choice == "1":
            cfg["approval_mode"] = "new_devices"
        elif choice == "2":
            cfg["approval_mode"] = "every_connect"
        else:
            print("please type 1 or 2")
    save_config(cfg)


def show_plan(cfg, pre):
    print("\nnetwing plan")
    print("  - turn %s into Wi-Fi access point '%s'" % (cfg["ap_if"],
                                                   cfg["ssid"]))
    print("  - hand out addresses on %s, route them out %s (NAT)"
          % (cfg["subnet"], cfg["uplink_if"]))
    print("  - filter DNS for ads/trackers/malware (%d list(s))"
          % len(cfg.get("blocklists", [])))
    print("  - hold unapproved devices at a captive portal (no internet)")
    print("  - approval rule: %s" % cfg.get("approval_mode"))
    print("  - write its own services: %s"
          % ", ".join(sorted(render_units(cfg))))
    if pre["facts"].get("missing"):
        print("  - MISSING packages first: %s" % ", ".join(
            pre["facts"]["missing"]))
    print("\nRISK: changing the Wi-Fi radio and firewall CAN cut this SSH")
    print("session and this Pi's internet. Preflight and a 5-minute")
    print("auto-rollback reduce that risk; they do not remove it.")
    print("netwing never touches your home router or your existing files.")


def confirm_apply_cli(cfg):
    if not cfg.get("ssid") or not cfg.get("password"):
        wizard_network(cfg)
    wizard_approval_mode(cfg)
    pre = run_preflight(cfg)
    show_plan(cfg, pre)
    for block in pre["blocks"]:
        print("BLOCKED: " + block)
    for warn in pre["warnings"]:
        print("warning: " + warn)
    if not pre["ok"]:
        print("\nPreflight found the problems above. Fix them and re-run.")
        return 1
    if ask("\nType YES to apply: ") != "YES":
        print("aborted - nothing changed")
        return 1
    try:
        backup = apply(cfg)
    except RuntimeError as exc:
        print("\nABORTED: %s" % exc)
        return 1
    print("\napplied. backups in %s" % backup)
    print("Auto-rollback in 5 minutes unless you confirm: run the UI and")
    print("press k on the Settings tab, or: netwing --keep")
    return 0


def confirm_revert_cli():
    cfg = load_config()
    if ask("Type REVERT to undo everything netwing changed: ") == "REVERT":
        revert(cfg)
        print("reverted.")
    else:
        print("aborted - nothing changed")


USAGE = """netwing %s - your Pi as a router with ad blocking + manual approval

  netwing                 fullscreen control panel
  netwing --preflight     read-only safety inspection (no changes)
  netwing --apply         guided setup + apply (asks, types YES, rolls back
                          automatically unless you confirm with --keep)
  netwing --keep          cancel the auto-rollback after --apply
  netwing --revert        undo everything netwing changed
  netwing --status        one-line status
  netwing --pending       list devices waiting for approval
  netwing --approve MAC   approve a device
  netwing --deny MAC      deny a device
  netwing --update-lists  download the latest ad/tracker blocklists
""" % VERSION


def main(argv):
    args = argv[1:]
    if not args:
        curses.wrapper(run_ui)
        return 0
    cmd = args[0]
    if cmd == "--preflight":
        pre = run_preflight()
        print(json.dumps(pre, indent=2, default=str))
        return 0 if pre["ok"] else 1
    if cmd == "--apply":
        return confirm_apply_cli(load_config())
    if cmd == "--keep":
        confirm_keep()
        print("kept - auto-rollback cancelled")
        return 0
    if cmd == "--auto-rollback":
        return 0 if auto_rollback() else 0
    if cmd == "--revert":
        confirm_revert_cli()
        return 0
    if cmd == "--status":
        st = collect_status(load_config())
        print(json.dumps({k: v for k, v in st.items()
                          if k != "approvals"}, indent=2, default=str))
        return 0
    if cmd == "--pending":
        for mac, e in load_approvals()["pending"].items():
            print("%-19s %-20s %s" % (mac, e.get("hostname", "?"),
                                      e.get("ip", "")))
        return 0
    if cmd in ("--approve", "--deny") and len(args) > 1:
        ok = approve_device(args[1]) if cmd == "--approve" \
            else deny_device(args[1])
        print(("approved " if cmd == "--approve" else "denied ")
              + args[1] if ok else "bad MAC address")
        return 0 if ok else 1
    if cmd == "--update-lists":
        count, errors = update_blocklists()
        print("%d domains blocked. %s" % (count, " ".join(errors)))
        return 0 if not errors else 1
    if cmd == "--lease-event":
        cfg = load_config()
        mode = cfg.get("approval_mode") or "new_devices"
        state = note_lease(args[1] if len(args) > 1 else "",
                           args[2] if len(args) > 2 else "",
                           args[3] if len(args) > 3 else "",
                           args[4] if len(args) > 4 else "", mode)
        print(state)
        return 0
    if cmd == "--portal":
        run_portal()
        return 0
    if cmd == "--net-up":
        net_up(load_config())
        return 0
    if cmd in ("-h", "--help"):
        print(USAGE)
        return 0
    print(USAGE)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
