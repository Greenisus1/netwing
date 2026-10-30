# netwing

Your Pi as your own router: it broadcasts its own Wi-Fi network, blocks
ads, trackers and malware domains for every device on it, and no device
gets internet until **you** approve it.

Built with AI assistance from my design.

## What it does

- **Router:** plugs into your home router over ethernet and broadcasts
  its own WPA2 Wi-Fi network. Your home router is never contacted or
  changed - it just sees one wired client.
- **Network-wide ad blocking:** DNS sinkhole (Pi-hole class) using
  community blocklists. Every approved device on the netwing network is
  covered - phones, TVs, consoles - with nothing to install on them.
- **Manual approval:** a device that joins gets no internet until you
  approve it. Unapproved devices land on a captive page that says it is
  waiting for you. You pick the rule at setup: approve each *new* device
  once (remembered), or approve *every* connection.
- **Fullscreen control panel:** live blocked-counter, device list with
  one-key approve/deny, blocklist updates, settings.

## What it does NOT do (honest notes)

- **YouTube video ads cannot be blocked by DNS** - not by netwing, not
  by Pi-hole, not by anything working at the DNS layer. YouTube serves
  ads from the same domains as the videos themselves, so a DNS blocker
  can only block both or neither. netwing says so in the app instead of
  pretending.
- The Wi-Fi repeater ("clone an existing network") mode is planned, not
  in this version. This version needs an ethernet cable to the router.

## Install (on your Home Pi)

```sh
git clone https://github.com/Greenisus1/netwing
cd netwing
sudo sh install.sh
```

Then plug an ethernet cable from the Pi into your home router and:

```sh
sudo netwing --apply
```

`--apply` first runs a **read-only preflight**: it checks your
interfaces, where your internet comes from, and which interface your
SSH session is using. If applying would cut your connection, it
refuses and says what to change first. If it is safe, it shows the
exact plan and asks you to type YES. After applying, a **5-minute
auto-rollback** undoes everything unless you confirm you want to keep
it (`sudo netwing --keep`, or press `k` on the Settings tab).

Heads-up: even with preflight, changing the Wi-Fi radio and firewall
can drop your SSH session or the Pi's internet. Do the first apply
with a keyboard/screen attached or from a connection you can afford
to lose for a few minutes - the rollback brings things back either
way.

## Daily use

```sh
netwing                # fullscreen control panel
netwing --pending      # devices waiting for approval
netwing --approve MAC  # approve a device
netwing --deny MAC     # deny a device
netwing --status       # one-line status
netwing --revert       # undo everything netwing changed
```

## Safety

netwing only ever touches its own files (`/etc/netwing`, four
`netwing-*` systemd services, one sysctl drop-in, one nftables table).
Everything it replaces is backed up first, `--revert` restores it, and
the timed rollback runs automatically after every apply. It never
reboots the Pi and never changes your home router.

## License

MIT - copyright Greenisus1
