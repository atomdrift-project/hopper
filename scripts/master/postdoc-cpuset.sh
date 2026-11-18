#!/bin/sh
# Hopper supervises this command. Exec keeps the worker in the process group
# Hopper uses to stop it, and the CPU set also applies to Postdoc's children.
set -eu

if [ -n "${HOPPER_POSTDOC_CPUS:-}" ]; then
	exec /bin/cpuset -l "$HOPPER_POSTDOC_CPUS" /usr/local/bin/postdoc "$@"
fi
exec /usr/local/bin/postdoc "$@"
