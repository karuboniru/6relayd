#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Exercise the same three capabilities as the DynamicUser systemd service.
unshare --map-current-user --keep-caps -n \
  setpriv --inh-caps=-all,+net_admin,+net_raw,+net_bind_service \
          --ambient-caps=-all,+net_admin,+net_raw,+net_bind_service \
  python3 tests/recovery.py "$(pwd)/build/bin/6relayd"
