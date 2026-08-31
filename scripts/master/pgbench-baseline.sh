#!/usr/bin/env bash
# Repeatable read-only pgbench. Deliberately CPU/syscall-bound (dataset fits in
# shared_buffers) because that is what CPU mitigations actually affect.
# Identical parameters must be used before and after the reboot.
set -e
D=/scratch/bench
LABEL="$1"
sudo rm -rf $D; sudo mkdir -p $D; sudo chown postgres:postgres $D
sudo -u postgres initdb -D $D --locale=en_US.UTF-8 --encoding=UTF8 >/dev/null 2>&1
sudo -u postgres pg_ctl -D $D -l $D/log -o "-c port=5597 -c unix_socket_directories=$D \
  -c shared_buffers=8GB -c huge_pages=off -c io_method=io_uring \
  -c max_connections=200 -c fsync=off -c synchronous_commit=off" start >/dev/null 2>&1
sleep 4
sudo -u postgres pgbench -h $D -p 5597 -i -s 100 -q postgres >/dev/null 2>&1
echo "--- $LABEL ---"
for i in 1 2 3; do
  sudo -u postgres pgbench -h $D -p 5597 -S -M prepared -c 32 -j 32 -T 20 postgres 2>/dev/null \
    | awk '/^tps/{printf "  run '"$i"': %s tps\n", $3}'
done
sudo -u postgres pg_ctl -D $D stop >/dev/null 2>&1
sudo rm -rf $D
