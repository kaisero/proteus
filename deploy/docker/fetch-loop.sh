#!/bin/sh
# Runs `proteus fetch --all` now and then every FETCH_INTERVAL seconds
# (default 3600). The inventory must set `export_inventory: true`, so each run
# writes store/.proteus/inventory.yaml for the server.
#
# The password comes from the secret file PASSWORD_FILE (default
# /run/secrets/panos-password) into the variable the inventory's password_env
# names (PASSWORD_ENV, default PANOS_PASSWORD), before each run.
#
# The script is the container's PID 1, and PID 1 gets no default action for
# a signal. So it traps TERM and INT itself: it sends TERM to the running
# `proteus fetch` or `sleep`, waits for it, and exits 143 (130 for INT).
set -u

interval="${FETCH_INTERVAL:-3600}"
password_file="${PASSWORD_FILE:-/run/secrets/panos-password}"
password_env="${PASSWORD_ENV:-PANOS_PASSWORD}"

# A positive whole number of seconds: anything else would make sleep fail and
# the loop fetch without a pause.
case "$interval" in
'' | *[!0-9]*) interval_ok=false ;;
*) [ "$interval" -gt 0 ] && interval_ok=true || interval_ok=false ;;
esac
if [ "$interval_ok" = false ]; then
	echo "fetch-loop: FETCH_INTERVAL must be a positive number of seconds, not '$interval'" >&2
	exit 2
fi

# child is the process in the background that the loop waits for, if any.
child=
stop() {
	trap '' TERM INT
	if [ -n "$child" ]; then
		kill -TERM "$child" 2>/dev/null
		wait "$child" 2>/dev/null
	fi
	exit "$1"
}
trap 'stop 143' TERM
trap 'stop 130' INT

while :; do
	# Read on each run: a changed password applies without a restart.
	if [ -e "$password_file" ]; then
		if password="$(cat "$password_file")"; then
			export "$password_env=$password"
		else
			echo "fetch-loop: cannot read $password_file: give it to UID 10001, mode 0400" >&2
		fi
	else
		echo "fetch-loop: no password file $password_file; $password_env stays as it is" >&2
	fi
	# Exit 3 means some devices failed or the export failed; the next run
	# tries again. The run log in PROTEUS_LOG_DIR says why.
	# Both run in the background: a trapped signal ends `wait` at once, while
	# a command in the foreground would delay the trap until it returns.
	proteus fetch --all "$@" &
	child=$!
	wait "$child"
	status=$?
	child=
	echo "fetch-loop: proteus fetch exited $status; next run in ${interval}s" >&2
	sleep "$interval" &
	child=$!
	wait "$child"
	child=
done
