#!/bin/sh
# tests/double/start.sh — start the test ACME server and print its
# address, for example http://127.0.0.1:41253.  The server ends itself
# after ten minutes.
dir=$(dirname "$0")
out=$(mktemp)
python3 -I "$dir/acme_double.py" >"$out" 2>/dev/null </dev/null &
for _ in $(seq 1 50); do
    port=$(head -n 1 "$out")
    [ -n "$port" ] && break
    sleep 0.1
done
rm -f "$out"
[ -n "$port" ] || exit 1
echo "http://127.0.0.1:$port"
