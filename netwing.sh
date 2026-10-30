#!/bin/sh
# netwing bootstrap - downloads and INSTALLS netwing only.
# No network changes happen here. Applying is a separate explicit
# step (sudo netwing --apply) that inspects your setup first and asks.
# Pinned route: pass the release tag (for example v1.1.0) so this
# script and everything it downloads come from that exact published
# version - never a moving branch or a stale CDN copy.
set -e
REF=${1:-main}
BASE=https://raw.githubusercontent.com/Greenisus1/netwing/$REF
cd /tmp
wget -q "$BASE/netwing.py" -O netwing.py
wget -q "$BASE/install.sh" -O netwing-install.sh
sh netwing-install.sh
