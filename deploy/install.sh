#!/bin/sh
# Build sliver-web-gui, install it, and register the systemd unit.
#
# Run from the repo root as root:  sudo ./deploy/install.sh
#
# The unit is pulled up automatically whenever sliver.service starts (it is
# WantedBy=sliver.service), so there is no separate `systemctl start` here —
# restart sliver.service, or start this unit directly, once installed.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"

echo "==> building"
go build -o sliver-web-gui .

echo "==> installing binary to /usr/local/bin"
install -m755 sliver-web-gui /usr/local/bin/sliver-web-gui

echo "==> installing systemd unit"
install -m644 deploy/sliver-web-gui.service /etc/systemd/system/sliver-web-gui.service

# Never clobber an existing config — it may hold a password and a chosen port.
if [ -f /etc/default/sliver-web-gui ]; then
	echo "==> keeping existing /etc/default/sliver-web-gui"
else
	echo "==> installing default config to /etc/default/sliver-web-gui"
	install -m600 deploy/sliver-web-gui.env.example /etc/default/sliver-web-gui
fi

systemctl daemon-reload
systemctl enable sliver-web-gui.service

addr=$(sed -n 's/^WEBGUI_ADDR=//p' /etc/default/sliver-web-gui | tail -1)
: "${addr:=127.0.0.1:4443}"

cat <<EOF

Installed. Before first start, check the paths in
/etc/systemd/system/sliver-web-gui.service — it expects sliver-server at
/root/sliver-server and the operator listener on 127.0.0.1:31337.

To change the listen port, edit WEBGUI_ADDR in /etc/default/sliver-web-gui.
Binding a non-localhost address also requires -password in WEBGUI_OPTS.

Then:  systemctl start sliver-web-gui
Open:  http://$addr
EOF
