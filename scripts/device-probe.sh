#!/usr/bin/env bash
# Compare the library's first address match against a firewall's own verdict.
#
# The library reports which rules a value can reach. A device evaluates zones,
# applications and services too, so the two can legitimately disagree — the
# library over-matches, which is the safe direction for a candidate set. This
# script exists to show where they disagree and why, not to require agreement.
#
# Usage: PANOS_HOST=... PANOS_API_KEY=... scripts/device-probe.sh <config.xml> <scope> [explore-binary]
set -uo pipefail

cfg=${1:?config file}
scope=${2:?scope, e.g. vsys:vsys1}
explore=${3:-bin/panos-explore}

: "${PANOS_HOST:?set PANOS_HOST}"
: "${PANOS_API_KEY:?set PANOS_API_KEY}"

# Each probe is source destination from-zone to-zone application port, then the
# rule it is aimed at. Zones and ports are taken from that rule, because
# test security-policy-match needs real zone names and rejects "any".
#
# The library ignores zones, applications and services by design, so a probe whose
# target rule is only reachable past an earlier any-source rule is expected to
# disagree. Those probes are kept, not removed: they measure the cost of ignoring
# zones on a real configuration.
probes=(
  "198.18.0.5      10.10.0.5      client     prisma    ssl          5007 identity-redistribution"
  "198.18.100.115  198.18.1.1     client     transport ssl          443  certbot-to-homefw"
  "198.18.0.5      198.18.0.6     int-link-b transport web-browsing 80   ztnac-to-lab"
  "198.18.0.5      198.18.1.50    prisma     client    ssl          443  prisma-to-home"
  "198.18.10.100   198.18.100.250 server     client    ssl          8006 dc-to-pve"
  "198.18.0.5      198.18.10.100  client     server    ldap         389  shared-service-ad"
  "100.64.0.5      198.18.0.6     prisma     client    web-browsing 80   prisma-to-lab"
)

device_match() {
  local src=$1 dst=$2 fz=$3 tz=$4 app=$5 port=$6
  curl -sk --max-time 40 -G "https://$PANOS_HOST/api/" \
    --data-urlencode "type=op" --data-urlencode "key=$PANOS_API_KEY" \
    --data-urlencode "cmd=<test><security-policy-match><source>$src</source><destination>$dst</destination><from>$fz</from><to>$tz</to><application>$app</application><protocol>6</protocol><destination-port>$port</destination-port></security-policy-match></test>" \
  | python3 -c '
import sys, xml.etree.ElementTree as ET
try:
    t = ET.fromstring(sys.stdin.read())
except Exception:
    print("parse-error"); raise SystemExit
e = t.find(".//rules/entry")
if e is not None:
    print(e.get("name") or (e.text or "").strip() or "unnamed")
else:
    print((t.findtext(".//result") or "no-match").strip().splitlines()[0][:40] or "no-match")'
}

agreed=0
total=0
printf '%-15s %-15s %-9s %-23s %-23s %s\n' SOURCE DESTINATION FROM-ZONE DEVICE LIBRARY AGREE
for p in "${probes[@]}"; do
  read -r src dst fz tz app port target <<<"$p"
  dev=$(device_match "$src" "$dst" "$fz" "$tz" "$app" "$port")
  lib=$("$explore" simulate "$cfg" "$scope" "$src" "$dst" "$fz" "$tz" 2>/dev/null \
        | sed -n 's/^first match: \([^ ]*\).*/\1/p')
  lib=${lib:-no-match}
  total=$((total + 1))
  if [ "$dev" = "$lib" ]; then
    agree=yes
    agreed=$((agreed + 1))
  else
    agree="NO (aimed at $target)"
  fi
  printf '%-15s %-15s %-9s %-23s %-23s %s\n' "$src" "$dst" "$fz" "$dev" "$lib" "$agree"
done
echo
echo "$agreed of $total agree. The library is given the same zones as the device and"
echo "evaluates them; a remaining disagreement means the device declined on application"
echo "or service, which the library does not evaluate."
