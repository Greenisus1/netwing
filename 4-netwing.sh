#!/bin/sh
# netwing bootstrap - downloads and INSTALLS netwing only.
# No network changes happen here. Applying is a separate explicit
# step (sudo netwing --apply) that inspects your setup first and asks.
set -e
BASE=https://raw.githubusercontent.com/Greenisus1/netwing/main
cd /tmp
wget -q "$BASE/netwing.py" -O netwing.py
wget -q "$BASE/install.sh" -O netwing-install.sh
sh netwing-install.sh
