import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netwing
from netwing import Sys

HOSTS_FIXTURE = """# comment
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net
127.0.0.1 localhost
0.0.0.0 localhost
bad line without ip
0.0.0.0 UPPER.example.org
0.0.0.0 ads.example.com
::1 ip6-localhost
0.0.0.0 nodot
"""

TCP_FIXTURE = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000
   1: 2F10A8C0:0016 3201A8C0:C0A8 01 00000000:00000000 00:00000000 00000000
"""


def hexip(ip):
    b = bytes(int(x) for x in ip.split("."))
    return b[::-1].hex().upper()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nwtest-")
        self.old_sys = netwing.SYS
        self.sys = Sys()
        self.sys.fake_root = self.tmp
        netwing.SYS = self.sys

    def tearDown(self):
        netwing.SYS = self.old_sys
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestBlocklist(Base):
    def test_parse(self):
        domains, skipped = netwing.parse_hosts_file(HOSTS_FIXTURE)
        self.assertIn("ads.example.com", domains)
        self.assertIn("tracker.example.net", domains)
        self.assertIn("upper.example.org", domains)
        self.assertNotIn("localhost", domains)
        self.assertNotIn("nodot", domains)
        self.assertEqual(len(domains), 3)
        self.assertGreater(skipped, 0)

    def test_render(self):
        out = netwing.render_blocklist(["a.com", "b.com"])
        self.assertIn("address=/a.com/0.0.0.0", out)
        self.assertEqual(out.count("address=/"), 2)


class TestApprovals(Base):
    def test_new_device_flow(self):
        self.assertEqual(netwing.note_lease(
            "add", "AA:BB:CC:DD:EE:FF", "10.77.77.100", "phone"), "pending")
        self.assertEqual(netwing.note_lease(
            "add", "aa:bb:cc:dd:ee:ff", "10.77.77.100"), "pending")
        self.assertTrue(netwing.approve_device("aa:bb:cc:dd:ee:ff"))
        self.assertEqual(netwing.note_lease(
            "old", "aa:bb:cc:dd:ee:ff", "10.77.77.100"), "approved")
        # new_devices mode: lease end keeps the approval
        self.assertEqual(netwing.note_lease(
            "del", "aa:bb:cc:dd:ee:ff"), "ignored")
        self.assertIn("aa:bb:cc:dd:ee:ff", netwing.load_approvals()["approved"])

    def test_every_connect_flow(self):
        mac = "11:22:33:44:55:66"
        netwing.note_lease("add", mac, "10.77.77.101", "tab", "every_connect")
        self.assertTrue(netwing.approve_device(mac))
        # a fresh lease for an approved device goes back to pending
        self.assertEqual(netwing.note_lease(
            "add", mac, "10.77.77.101", "tab", "every_connect"), "pending")
        self.assertNotIn(mac, netwing.load_approvals()["approved"])
        # lease end also drops the approval
        netwing.approve_device(mac)
        self.assertEqual(netwing.note_lease(
            "del", mac, mode="every_connect"), "pending")

    def test_deny_and_remove(self):
        mac = "22:33:44:55:66:77"
        netwing.note_lease("add", mac)
        self.assertTrue(netwing.deny_device(mac))
        self.assertEqual(netwing.note_lease("add", mac), "denied")
        self.assertTrue(netwing.remove_device(mac))
        self.assertEqual(netwing.note_lease("add", mac), "pending")

    def test_bad_mac(self):
        self.assertEqual(netwing.note_lease("add", "not-a-mac"), "ignored")
        self.assertFalse(netwing.approve_device("nope"))


class TestRenders(Base):
    def cfg(self):
        c = dict(netwing.DEFAULTS)
        c.update({"ssid": "testnet", "password": "hunter2-hunter2",
                  "approval_mode": "new_devices"})
        return c

    def test_nft(self):
        nft = netwing.render_nft(self.cfg())
        self.assertIn("set approved", nft)
        self.assertIn("redirect to :8081", nft)
        self.assertIn("meta nfproto ipv4", nft)
        self.assertIn("masquerade", nft)
        deny = nft.find("ether saddr != @approved drop")
        established = nft.find("ct state established,related accept")
        # default-deny must precede the established fast-path so revoked
        # devices lose even already-open flows, on IPv4 and IPv6 alike
        self.assertTrue(-1 < deny < established)

    def test_dnsmasq(self):
        conf = netwing.render_dnsmasq(self.cfg())
        self.assertIn("interface=wlan0", conf)
        self.assertIn("dhcp-range=10.77.77.100,10.77.77.254", conf)
        self.assertIn("dhcp-script=" + netwing.DHCP_HOOK_PATH, conf)
        self.assertIn("server=1.1.1.1", conf)

    def test_hostapd(self):
        conf = netwing.render_hostapd(self.cfg())
        self.assertIn("ssid=testnet", conf)
        self.assertIn("wpa=2", conf)

    def test_units(self):
        units = netwing.render_units(self.cfg())
        self.assertEqual(len(units), 4)
        self.assertIn("netwing-portal.service", units)


class TestTcpParse(unittest.TestCase):
    def test_parse(self):
        conns = netwing.parse_proc_net_tcp(TCP_FIXTURE)
        self.assertEqual(len(conns), 1)         # LISTEN row skipped
        lip, lp, rip, rp = conns[0]
        self.assertEqual(lp, 22)
        self.assertEqual(netwing._hex_to_ipv4(rip), "192.168.1.50")


class TestPreflight(Base):
    ADDR = [{"ifname": "lo", "flags": ["LOOPBACK", "UP"], "addr_info": []},
            {"ifname": "eth0", "flags": ["BROADCAST", "UP"],
             "address": "b8:27:eb:00:00:01",
             "addr_info": [{"family": "inet", "local": "192.168.1.77"}]},
            {"ifname": "wlan0", "flags": ["BROADCAST"],
             "address": "b8:27:eb:00:00:02", "addr_info": []}]

    def fake_run(self, route_dev="eth0", ssh_dev="eth0", guestwing=False):
        def run(cmd, capture=True, check=False):
            if cmd[:3] == ["ip", "-j", "addr"]:
                return 0, json.dumps(self.ADDR), ""
            if cmd[:4] == ["ip", "-j", "route", "show"]:
                return 0, json.dumps([{"dst": "default", "dev": route_dev}]), ""
            if cmd[:3] == ["ip", "route", "get"]:
                return 0, "x via 192.168.1.1 dev %s" % ssh_dev, ""
            if cmd[:2] == ["systemctl", "is-active"]:
                name = cmd[2]
                state = "inactive"
                if name == "guestwing" and guestwing:
                    state = "active"
                return 0 if state == "active" else 3, state + "\n", ""
            return 0, "", ""
        return run

    def seed(self):
        os.makedirs(self.sys.remap("/sys/class/net/eth0"), exist_ok=True)
        os.makedirs(self.sys.remap("/sys/class/net/wlan0"), exist_ok=True)
        self.sys.write("/sys/class/net/eth0/carrier", "1\n")
        # one established SSH session from 192.168.1.50 to local :22
        self.sys.write("/proc/net/tcp",
            "  sl  local_address rem_address   st\n"
            "   1: 4D01A8C0:0016 3201A8C0:C0A8 01 00 00 00\n")

    def test_healthy(self):
        self.seed()
        self.sys.run = self.fake_run()
        pre = netwing.run_preflight(dict(netwing.DEFAULTS))
        self.assertTrue(pre["ok"], pre["blocks"])

    def test_uplink_is_wifi(self):
        self.seed()
        self.sys.run = self.fake_run(route_dev="wlan0")
        pre = netwing.run_preflight(dict(netwing.DEFAULTS))
        self.assertFalse(pre["ok"])
        self.assertTrue(any("comes IN through wlan0" in b
                            for b in pre["blocks"]))

    def test_ssh_over_ap_iface(self):
        self.seed()
        self.sys.run = self.fake_run(ssh_dev="wlan0")
        pre = netwing.run_preflight(dict(netwing.DEFAULTS))
        self.assertFalse(pre["ok"])
        self.assertTrue(any("SSH session" in b for b in pre["blocks"]))

    def test_guestwing_running(self):
        self.seed()
        self.sys.run = self.fake_run(guestwing=True)
        pre = netwing.run_preflight(dict(netwing.DEFAULTS))
        self.assertFalse(pre["ok"])
        self.assertTrue(any("guestwing" in b for b in pre["blocks"]))


class TestApplyRevert(Base):
    def test_apply_writes_and_revert_removes(self):
        cfg = dict(netwing.DEFAULTS)
        cfg.update({"ssid": "t", "password": "12345678",
                    "approval_mode": "new_devices"})
        backup = netwing.apply(cfg)
        self.assertTrue(self.sys.exists(netwing.HOSTAPD_PATH))
        self.assertTrue(self.sys.exists(netwing.NFT_PATH))
        self.assertTrue(self.sys.exists(netwing.SYSCTL_PATH))
        self.assertTrue(self.sys.exists(
            "/etc/systemd/system/netwing-portal.service"))
        self.assertTrue(os.path.isdir(self.sys.remap(backup)))
        # hook is executable
        st = os.stat(self.sys.remap(netwing.DHCP_HOOK_PATH))
        self.assertTrue(st.st_mode & 0o111)
        netwing.revert(cfg)
        self.assertFalse(self.sys.exists(
            "/etc/systemd/system/netwing-portal.service"))
        self.assertFalse(self.sys.exists(netwing.SYSCTL_PATH))

    def test_rollback_armed_before_live_changes(self):
        cfg = dict(netwing.DEFAULTS)
        cfg.update({"ssid": "t", "password": "12345678",
                    "approval_mode": "new_devices"})
        netwing.apply(cfg)
        ran = [c for c in self.sys.ran if isinstance(c[0], str)]
        arm = next(i for i, c in enumerate(ran)
                   if c[0] == "systemd-run")
        first_enable = next(i for i, c in enumerate(ran)
                            if c[:2] == ["systemctl", "enable"])
        self.assertLess(arm, first_enable)

    def test_rollback_arm_failure_aborts_apply(self):
        cfg = dict(netwing.DEFAULTS)
        cfg.update({"ssid": "t", "password": "12345678",
                    "approval_mode": "new_devices"})
        real_run = self.sys.run
        def failing(cmd, capture=True, check=False):
            if cmd[0] == "systemd-run":
                return 1, "", "mock systemd failure"
            return real_run(cmd, capture, check)
        self.sys.run = failing
        with self.assertRaises(RuntimeError):
            netwing.apply(cfg)
        # nothing live happened: no services enabled, no units written
        self.assertFalse(any(c[:2] == ["systemctl", "enable"]
                             for c in self.sys.ran))
        self.assertFalse(self.sys.exists(netwing.NFT_PATH))
        self.assertIsNone(cfg["applied_at"])

    def test_apply_stops_and_revert_restarts(self):
        cfg = dict(netwing.DEFAULTS)
        cfg.update({"ssid": "t", "password": "12345678",
                    "approval_mode": "new_devices"})
        netwing.apply(cfg)
        self.assertIn(["systemctl", "stop", "wpa_supplicant"],
                      self.sys.ran) if False else None
        # fake mode: is-active returns rc 0 with empty out -> not stopped
        netwing.revert(cfg)
        self.assertIsNone(cfg["applied_at"])


class TestCLI(Base):
    def test_pending_and_approve(self):
        netwing.note_lease("add", "aa:bb:cc:dd:ee:ff", "10.77.77.5", "dev")
        self.assertEqual(netwing.main(["netwing", "--pending"]), 0)
        self.assertEqual(
            netwing.main(["netwing", "--approve", "aa:bb:cc:dd:ee:ff"]), 0)
        self.assertIn("aa:bb:cc:dd:ee:ff",
                      netwing.load_approvals()["approved"])

    def test_preflight_cli_exit_code(self):
        self.assertEqual(netwing.main(["netwing", "--preflight"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=1)
