#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
${CC:-cc} -D_GNU_SOURCE -Wall -Wextra -I src/6relayd \
  tests/netlink.c src/6relayd/netlink.c -o "$test_dir/netlink-test"
unshare -Urn sh -eu -c '
  ip link set lo up
  ip link add test0 type dummy
  ip link set test0 up
  ip -6 addr add fe80::1/64 dev test0 nodad
  ip -6 route add 2001:db8:3::1/128 dev test0 proto 77
  "$1"
' sh "$test_dir/netlink-test"
unshare -Urn python3 tests/daemon-netlink.py "$(pwd)/build/bin/6relayd"
