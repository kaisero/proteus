#!/usr/bin/env bash
# Capture a zone snapshot from a firewall.
#
# The library performs no network access, so capturing is the caller's job. This
# script is the reference implementation of that job: two op-command calls, saved
# verbatim into the envelope the library reads.
#
# Usage: PANOS_HOST=... PANOS_API_KEY=... scripts/capture-zones.sh [out.json]
set -euo pipefail

out=${1:-zone-snapshot.json}
: "${PANOS_HOST:?set PANOS_HOST}"
: "${PANOS_API_KEY:?set PANOS_API_KEY}"

op() {
  curl -sk --max-time 60 -G "https://$PANOS_HOST/api/" \
    --data-urlencode "type=op" \
    --data-urlencode "cmd=$1" \
    --data-urlencode "key=$PANOS_API_KEY"
}

# afi=both so a device with IPv6 routes reports them; the argument is declared by the
# operational schema, so it is safe to pass on any release that has the command.
interfaces=$(op '<show><interface>all</interface></show>')
fib=$(op '<show><advanced-routing><fib><afi>both</afi></afi></fib></advanced-routing></show>')

# A firewall not in Advanced Routing Mode rejects that command; the legacy one shares
# the same handler on the device and therefore the same output shape.
if ! grep -q '<fibs>' <<<"$fib"; then
  fib=$(op '<show><routing><fib/></routing></show>')
fi

for doc in "$interfaces" "$fib"; do
  grep -q 'status="success"' <<<"$doc" || { echo "a command failed:" >&2; echo "$doc" >&2; exit 1; }
done

serial=$(op '<show><system><info/></system></show>' \
  | sed -n 's:.*<serial>\(.*\)</serial>.*:\1:p' | head -1)

python3 - "$out" "$PANOS_HOST" "$serial" <<'PY' "$interfaces" "$fib"
import json, sys, datetime
out, host, serial, interfaces, fib = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
json.dump({
    "taken_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    "source": host,
    "serial": serial,
    "interfaces_xml": interfaces,
    "fib_xml": fib,
}, open(out, "w"), indent=2)
print(f"wrote {out}")
PY
