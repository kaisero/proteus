#!/bin/sh
# Runs `proteus fetch --all` now and then every FETCH_INTERVAL seconds
# (default 3600). The inventory must set `export_inventory: true`, so each run
# writes store/.proteus/inventory.yaml for the server.
#
# The password comes from the secret file PASSWORD_FILE (default
# /run/secrets/panos-password) into the variable the inventory's password_env
# names (PASSWORD_ENV, default PANOS_PASSWORD), before each run.
set -u

interval="${FETCH_INTERVAL:-3600}"
password_file="${PASSWORD_FILE:-/run/secrets/panos-password}"
password_env="${PASSWORD_ENV:-PANOS_PASSWORD}"

while :; do
	# Read on each run: a changed password applies without a restart.
	if [ -e "$password_file" ]; then
		if password="$(cat "$password_file")"; then
			export "$password_env=$password"
		else
			echo "fetch-loop: cannot read $password_file: give it to UID 10001, mode 0400" >&2
		fi
	fi
	# Exit 3 means some devices failed or the export failed; the next run
	# tries again. The run log in PROTEUS_LOG_DIR says why.
	proteus fetch --all "$@"
	echo "fetch-loop: proteus fetch exited $?; next run in ${interval}s" >&2
	sleep "$interval"
done
