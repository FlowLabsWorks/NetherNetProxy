#!/bin/sh
# Install NetherNetProxy as a systemd service. Run as root:
#
#   sudo deploy/install.sh /path/to/nethernet-proxy-binary
#
# Creates the unprivileged user "nethernet-proxy", installs the binary to
# /opt/nethernet-proxy, a config to /etc/nethernet-proxy (only if none exists yet) and the
# systemd unit, then enables and (re)starts the service. Re-running updates the binary and keeps
# the previous one as nethernet-proxy.previous.
set -eu

BIN="${1:?usage: install.sh /path/to/nethernet-proxy-binary}"
[ "$(id -u)" -eq 0 ] || { echo "install.sh: run as root" >&2; exit 1; }
[ -f "$BIN" ] || { echo "install.sh: $BIN not found" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/nethernet-proxy
CONF=/etc/nethernet-proxy
UNIT=nethernet-proxy.service

id nethernet-proxy >/dev/null 2>&1 ||
  useradd --system --no-create-home --shell /usr/sbin/nologin nethernet-proxy

install -d -m 0755 "$APP" "$CONF"
if [ -f "$APP/nethernet-proxy" ]; then
  cp -p "$APP/nethernet-proxy" "$APP/nethernet-proxy.previous"
fi
install -m 0755 "$BIN" "$APP/nethernet-proxy"

if [ ! -f "$CONF/config.json" ]; then
  install -m 0644 "$HERE/../config.example.json" "$CONF/config.json"
  echo "Installed an example config - edit $CONF/config.json, then: systemctl restart nethernet-proxy"
fi

install -m 0644 "$HERE/$UNIT" "/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemctl enable "$UNIT"
systemctl restart "$UNIT"
echo "Installed $("$APP/nethernet-proxy" -version)."
systemctl --no-pager --lines=0 status "$UNIT" || true
