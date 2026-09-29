#!/usr/bin/env bash
# Compare the library's first address match against a firewall's own verdict.
#
# The library reports which rules a value can reach. A device evaluates zones,
# applications and services too, so the two can legitimately disagree — the
# library over-matches, which is the safe direction for a candidate set. This
# script exists to show where they disagree and why, not to require agreement.
#
# Usage: PANOS_HOST=... PANOS_API_KEY=... scripts/device-probe.sh <config.xml> <vsys> [proteus]
#        PANOS_HOST=... PANOS_API_KEY=... scripts/device-probe.sh --routing <device> <router> <destination>...
#        PANOS_HOST=... PANOS_API_KEY=... scripts/device-probe.sh --nat <device> <router> <src,dst,port[,from-zone]>...
#
# <vsys> is vsys1 or vsys:vsys1.
#
# --routing compares simulate routing's first lookup on <device> (a device of the
# inventory, fetched) with the device's own: its fib-lookup when the XML API offers
# it, else the longest prefix match of its live forwarding table, computed here.
# Measured 2026-09-29: the Advanced Routing fib-lookup is "Unsupported command"
# through the XML API on 11.2 and 12.2; the legacy test routing fib-lookup answers
# on 11.2 for the router named default (fw01) and refuses other logical routers and
# every router on 12.2 (fw02). The two agree when the egress interface is the same
# and the library's next hop is one of the device's (ECMP picks by hash).
set -uo pipefail

routing_probe() {
  local dev=${1:?device} router=${2:?router}
  shift 2
  local analyst=${PROTEUS_BIN:-bin/proteus} agreed=0 total=0
  local live
  live=$(curl -sk --max-time 40 -G "https://$PANOS_HOST/api/" \
    --data-urlencode "type=op" --data-urlencode "key=$PANOS_API_KEY" \
    --data-urlencode "cmd=<show><advanced-routing><fib><afi>ipv4</afi></fib></advanced-routing></show>")
  printf '%-16s %-40s %-40s %s\n' DESTINATION DEVICE LIBRARY AGREE
  for dst in "$@"; do
    local ref lib
    ref=$( { curl -sk --max-time 40 -G "https://$PANOS_HOST/api/" \
      --data-urlencode "type=op" --data-urlencode "key=$PANOS_API_KEY" \
      --data-urlencode "cmd=<test><advanced-routing><fib-lookup><ip>$dst</ip><logical-router>$router</logical-router></fib-lookup></advanced-routing></test>"
      echo "<!--next-->"
      curl -sk --max-time 40 -G "https://$PANOS_HOST/api/" \
      --data-urlencode "type=op" --data-urlencode "key=$PANOS_API_KEY" \
      --data-urlencode "cmd=<test><routing><fib-lookup><ip>$dst</ip><virtual-router>$router</virtual-router></fib-lookup></routing></test>"
      } | LIVE="$live" python3 -c '
import ipaddress, os, sys, xml.etree.ElementTree as ET
dst, router = ipaddress.ip_address(sys.argv[1]), sys.argv[2]
for part in sys.stdin.read().split("<!--next-->"):
    try:
        t = ET.fromstring(part.strip())
    except ET.ParseError:
        continue
    if t.get("status") == "success" and t.find(".//interface") is not None:
        # verified on fw01 (11.2): <nh>ip|recv</nh>, <interface>, <ip> the next hop
        # when there is one; a connected or own address has none.
        print("fib-lookup:%s:%s" % (t.findtext(".//interface"), t.findtext("result/ip") or "0.0.0.0"))
        raise SystemExit
best = None
for fib in ET.fromstring(os.environ["LIVE"]).iter("fibs"):
    for vr in fib.findall("entry"):
        if (vr.findtext("vr") or "") != router:
            continue
        for e in vr.find("entries").findall("entry"):
            net = ipaddress.ip_network(e.findtext("dst"), strict=False)
            if dst in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, [])
            if best and net == best[0]:
                best[1].append((e.findtext("interface"), e.findtext("nexthop")))
if best is None:
    print("lpm:no-route")
else:
    print("lpm:%s:%s" % (best[1][0][0], ",".join(sorted(nh for _, nh in best[1]))))' "$dst" "$router")
    lib=$("$analyst" simulate routing "$dst" --device "$dev" --router "$router" --output json 2>/dev/null \
      | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)["results"]
except Exception:
    print("error"); raise SystemExit
h = r["hops"][0] if r.get("hops") else None
if not h or not h.get("lookups"):
    print("no-route"); raise SystemExit
print("%s:%s" % (h["out"]["interface"], ",".join(sorted(n["NextHop"] for n in h["lookups"][0]["route"]["next_hops"]))))')
    total=$((total + 1))
    local want=${ref#*:}
    local agree="NO"
    if [ "${want%%:*}" = "${lib%%:*}" ]; then
      for nh in $(tr , ' ' <<<"${lib#*:}"); do
        case ",${want#*:}," in *",$nh,"*) agree=yes ;; esac
      done
      [ "$want" = "no-route" ] && [ "$lib" = "no-route" ] && agree=yes
    fi
    [ "$agree" = yes ] && agreed=$((agreed + 1))
    printf '%-16s %-40s %-40s %s\n' "$dst" "$ref" "$lib" "$agree"
  done
  echo
  echo "$agreed of $total agree."
}

# --nat compares simulate nat's rule with the device's test nat-policy-match. The
# engine's JSON gives the zones and the egress interface the device is asked with
# (its from zone, and the pre-NAT lookup's zone and interface), so the probe checks
# them too. A flow is src,dst,port[,from-zone]. The engine runs with --no-dns: an
# FQDN resolved here says nothing of what the device resolved. The XML API answers
# the rule name only (spec §18 F13); an implicit bi-directional rule carries its
# origin's name on both sides.
nat_probe() {
  local dev=${1:?device} router=${2:?router}
  shift 2
  local analyst=${PROTEUS_BIN:-bin/proteus} agreed=0 total=0
  printf '%-44s %-24s %-24s %s\n' FLOW DEVICE LIBRARY AGREE
  for f in "$@"; do
    IFS=, read -r src dst port zone <<<"$f"
    if [ "$src" = "-" ]; then
      # The device answers no rule for a flow without a source (fw01, 2026-09-29).
      echo "skipped $f: test nat-policy-match needs a source"
      continue
    fi
    local extra=()
    [ -n "${zone:-}" ] && extra=(--from-zone "$zone")
    local json lib from to ifc
    json=$("$analyst" simulate nat "$src" "$dst" --device "$dev" --router "$router" --port "$port" ${extra[@]+"${extra[@]}"} --no-dns --output json 2>/dev/null)
    read -r lib from to ifc < <(python3 -c '
import json, sys
try:
    env = json.load(sys.stdin)
    r = env["results"]
except Exception:
    print("error - - -"); raise SystemExit
rule = (r.get("rule") or {}).get("Name") or "none"
# A translation to an address nothing resolves is what the device reports as no rule (spec §18 F17, D8).
if any("resolves to no address" in u.get("reason", "") for u in env.get("unresolved") or []):
    rule = "none"
pre = r["pre_nat"]["out"]
print(rule, r["in"].get("zone") or "-", pre.get("zone") or "-", pre.get("interface") or "-")' <<<"$json")
    local cmd="<test><nat-policy-match>"
    [ "$src" != "-" ] && cmd+="<source>$src</source>"
    cmd+="<destination>$dst</destination><destination-port>$port</destination-port><protocol>6</protocol>"
    [ "$from" != "-" ] && cmd+="<from>$from</from>"
    [ "$to" != "-" ] && cmd+="<to>$to</to>"
    [ "$ifc" != "-" ] && cmd+="<to-interface>$ifc</to-interface>"
    cmd+="</nat-policy-match></test>"
    local ref
    ref=$(curl -sk --max-time 40 -G "https://$PANOS_HOST/api/" \
      --data-urlencode "type=op" --data-urlencode "key=$PANOS_API_KEY" --data-urlencode "cmd=$cmd" \
      | python3 -c '
import sys, xml.etree.ElementTree as ET
t = ET.fromstring(sys.stdin.read())
e = t.find(".//rules/entry")
print((e.text or "").strip() if e is not None else "none")')
    total=$((total + 1))
    local agree=NO
    [ "$ref" = "$lib" ] && agree=yes && agreed=$((agreed + 1))
    printf '%-44s %-24s %-24s %s\n' "$src -> $dst:$port ($from->$to $ifc)" "$ref" "$lib" "$agree"
  done
  echo
  echo "$agreed of $total agree."
}

if [ "${1:-}" = "--nat" ]; then
  : "${PANOS_HOST:?set PANOS_HOST}"
  : "${PANOS_API_KEY:?set PANOS_API_KEY}"
  shift
  nat_probe "$@"
  exit 0
fi

if [ "${1:-}" = "--routing" ]; then
  : "${PANOS_HOST:?set PANOS_HOST}"
  : "${PANOS_API_KEY:?set PANOS_API_KEY}"
  shift
  routing_probe "$@"
  exit 0
fi

cfg=${1:?config file}
vsys=${2:?vsys, e.g. vsys1}
vsys=${vsys#vsys:}
analyst=${3:-bin/proteus}

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
  lib=$("$analyst" simulate policy "$src" "$dst" --file "$cfg" --vsys "$vsys" \
        --from-zone "$fz" --to-zone "$tz" --port "$port" --application "$app" 2>/dev/null \
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
echo "$agreed of $total agree. The library is given the same zones and ports as the"
echo "device and evaluates them; a remaining disagreement means the device declined on"
echo "application, which the library does not evaluate."
