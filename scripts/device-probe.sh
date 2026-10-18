#!/usr/bin/env bash
# Compare the library's first address match against a firewall's own verdict.
#
# The library reports which rules a value can reach. A device evaluates zones,
# applications and services too, so the two can legitimately disagree — the
# library over-matches, which is the safe direction for a candidate set. This
# script exists to show where they disagree and why, not to require agreement.
#
# Usage: PANOS_HOST=... PANOS_KEY_HEADER=<file> scripts/device-probe.sh <config.xml> <vsys> [proteus]
#        PANOS_HOST=... PANOS_KEY_HEADER=<file> scripts/device-probe.sh --routing <device> <router> <destination>...
#        PANOS_HOST=... PANOS_KEY_HEADER=<file> scripts/device-probe.sh --nat <device> <router> <src,dst,port[,from-zone]>...
#        PANOS_HOST_<NAME>=... PANOS_KEY_HEADER_<NAME>=<file> scripts/device-probe.sh --path <flows-file>
#
# A key header file holds one line, "X-PAN-KEY: <key>". Each call is a POST that
# sends the key in that header, so the key never goes in a URL.
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
#
# --path compares each hop of simulate policy's path answer with the hop's device;
# its comment block below holds the measured facts it relies on.
set -uo pipefail

# need_key_header <file>: stop the probe when the key header file cannot be
# read, before the call that needs it, so no request goes out without its key.
# The message names the path, never the key.
need_key_header() {
  if [ ! -f "$1" ] || [ ! -r "$1" ]; then
    echo "device-probe: cannot read the key header file $1" >&2
    exit 2
  fi
}

routing_probe() {
  local dev=${1:?device} router=${2:?router}
  shift 2
  local analyst=${PROTEUS_BIN:-bin/proteus} agreed=0 total=0
  local live
  live=$(curl -sk --max-time 40 -H @"$PANOS_KEY_HEADER" "https://$PANOS_HOST/api/" \
    --data-urlencode "type=op" \
    --data-urlencode "cmd=<show><advanced-routing><fib><afi>ipv4</afi></fib></advanced-routing></show>")
  printf '%-16s %-40s %-40s %s\n' DESTINATION DEVICE LIBRARY AGREE
  for dst in "$@"; do
    local ref lib
    ref=$( { curl -sk --max-time 40 -H @"$PANOS_KEY_HEADER" "https://$PANOS_HOST/api/" \
      --data-urlencode "type=op" \
      --data-urlencode "cmd=<test><advanced-routing><fib-lookup><ip>$dst</ip><logical-router>$router</logical-router></fib-lookup></advanced-routing></test>"
      echo "<!--next-->"
      curl -sk --max-time 40 -H @"$PANOS_KEY_HEADER" "https://$PANOS_HOST/api/" \
      --data-urlencode "type=op" \
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
    ref=$(curl -sk --max-time 40 -H @"$PANOS_KEY_HEADER" "https://$PANOS_HOST/api/" \
      --data-urlencode "type=op" --data-urlencode "cmd=$cmd" \
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

# --path runs simulate policy in path mode for each flow of <flows-file> and asks
# each hop's device the same question with test security-policy-match. A flows
# file has one flow per line, "<src> <dst> <protocol> <port>"; "#" starts a comment.
# Each hop's device is reached through PANOS_HOST_<NAME> and PANOS_KEY_HEADER_<NAME>,
# NAME being the device name upper-cased with every non-alphanumeric as "_"; a hop
# whose variables are missing is reported "not probed". Only hops proteus decides
# (security check pass or stop) are compared; undecided and not-evaluated hops are
# counted, not probed. The test is sent without <application>: the device then
# ignores the application but applies application-default ports, so its answer is
# not ground truth for rules with an application (measured on fw02, 2026-10-08).
# Measured on fw02, 2026-10-08: the device does not name its default rules; a flow
# no rule matches gives an empty result. Agree means the same rule name, or an empty
# device result where proteus decided by a default rule (spec §10.2). A hop dropped
# by routing is listed with the --routing command that checks it. The test carries
# no vsys, so a hop on a vsys other than vsys1 is skipped.
xml_escape() {
  local s=$1
  s=${s//&/'&amp;'}
  s=${s//</'&lt;'}
  s=${s//>/'&gt;'}
  printf '%s' "$s"
}

device_env() {
  # device_env <device>: the suffix of its PANOS_HOST_/PANOS_KEY_HEADER_ variables.
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g'
}

path_probe() {
  local flows=${1:?flows file}
  [ -r "$flows" ] || { echo "cannot read $flows" >&2; return 2; }
  local analyst=${PROTEUS_BIN:-bin/proteus}
  local decided=0 agreed=0 disagreed=0 undecided=0 unprobed=0 drops=0
  local fmt='%-36s %-4s %-12s %-30s %-40s %s\n'
  # shellcheck disable=SC2059 # fmt is the table layout
  printf "$fmt" FLOW HOP DEVICE PROTEUS DEVICE-ANSWER RESULT
  local line src dst proto port rest
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    read -r src dst proto port rest <<<"$line"
    [ -z "${src:-}" ] && continue
    if [ -z "${port:-}" ] || [ -n "${rest:-}" ]; then
      echo "skipped line \"$line\": want <src> <dst> <protocol> <port>" >&2
      continue
    fi
    local flow="$src>$dst $proto/$port" hops
    hops=$("$analyst" simulate policy "$src" "$dst" --protocol "$proto" --port "$port" --output json 2>/dev/null \
      | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)["results"][0]
except Exception:
    print("error"); raise SystemExit
at = r.get("at") or {}
num = {"tcp": "6", "udp": "17", "icmp": "1", "sctp": "132"}
for h in r.get("hops") or []:
    sec = (h.get("checks") or {}).get("security") or {}
    f = h.get("flow") or {}
    kind = sec.get("verdict") or "not-evaluated"
    # Only a route lookup that fails drops the flow; a path that leaves the estate
    # or ends unresolved still ran its checks on the last hop.
    if r.get("outcome") == "dropped" and at.get("hop") == h["index"]:
        kind = "routing-drop"
    proto = str(f.get("protocol") or "")
    print("\t".join(str(x) if x not in (None, "") else "-" for x in (
        kind, h["index"], h.get("device"), h.get("vsys"), sec.get("rule"), sec.get("default"),
        ((f.get("source") or {}).get("addrs") or [None])[0],
        ((f.get("destination") or {}).get("addrs") or [None])[0],
        f.get("from_zone"), f.get("to_zone"), num.get(proto, proto), f.get("port"),
        (h.get("in") or {}).get("router"),
        ",".join(d.get("rule") or "" for d in sec.get("doubts") or []))))')
    if [ "$hops" = error ] || [ -z "$hops" ]; then
      # shellcheck disable=SC2059
      printf "$fmt" "$flow" - - "no JSON answer" - SKIP
      continue
    fi
    local kind idx dev vsys rule dflt hsrc hdst fz tz pnum hport router doubted
    while IFS=$'\t' read -r kind idx dev vsys rule dflt hsrc hdst fz tz pnum hport router doubted; do
      local mine="$rule $kind" theirs=- result=SKIP
      case $kind in
        undecided)
          undecided=$((undecided + 1)); mine="undecided" ;;
        not-evaluated)
          mine="not evaluated" ;;
        routing-drop)
          drops=$((drops + 1)); mine="routing drop"
          theirs="see --routing $dev $router $hdst" ;;
        pass|stop)
          decided=$((decided + 1))
          local name host header
          name=$(device_env "$dev")
          host=PANOS_HOST_$name header=PANOS_KEY_HEADER_$name
          if [ -z "${!host:-}" ] || [ -z "${!header:-}" ]; then
            unprobed=$((unprobed + 1)); theirs="not probed"
          elif [ "$vsys" != vsys1 ]; then
            unprobed=$((unprobed + 1)); theirs="not probed ($vsys)"
          elif [ "$fz" = - ] || [ "$tz" = - ] || [ "$hsrc" = - ] || [ "$hdst" = - ]; then
            unprobed=$((unprobed + 1)); theirs="not probed (no zones)"
          else
            need_key_header "${!header}"
            local cmd="<test><security-policy-match>"
            cmd+="<source>$(xml_escape "$hsrc")</source><destination>$(xml_escape "$hdst")</destination>"
            cmd+="<from>$(xml_escape "$fz")</from><to>$(xml_escape "$tz")</to>"
            cmd+="<protocol>$pnum</protocol>"
            [ "$hport" != - ] && cmd+="<destination-port>$hport</destination-port>"
            cmd+="</security-policy-match></test>"
            theirs=$(curl -sk --max-time 40 -H @"${!header}" "https://${!host}/api/" \
              --data-urlencode "type=op" --data-urlencode "cmd=$cmd" \
              | python3 -c '
import sys, xml.etree.ElementTree as ET
try:
    t = ET.fromstring(sys.stdin.read())
except Exception:
    print("error: no XML"); raise SystemExit
if t.get("status") != "success":
    print("error: " + " ".join((t.findtext(".//msg") or t.findtext(".//line") or "refused").split())[:40])
    raise SystemExit
e = t.find(".//rules/entry")
print("(default)" if e is None else (e.get("name") or (e.text or "").strip() or "unnamed"))')
            case $theirs in
              error:*) unprobed=$((unprobed + 1)) ;;
              *)
                if [ "$theirs" = "$rule" ] || { [ "$theirs" = "(default)" ] && [ "$dflt" != - ]; }; then
                  result=AGREE; agreed=$((agreed + 1))
                elif [[ ",$doubted," == *",$theirs,"* ]]; then
                  # Without <application> the device skips the application but keeps
                  # application-default ports (measured on fw02, 2026-10-08), so it can
                  # stop at a rule proteus holds in doubt. proteus decided the hop only
                  # because every such rule has the deciding action (spec E20).
                  result=AGREE-ACTION; agreed=$((agreed + 1))
                else
                  result=DISAGREE; disagreed=$((disagreed + 1))
                fi ;;
            esac
          fi ;;
      esac
      # shellcheck disable=SC2059
      printf "$fmt" "$flow" "$idx" "$dev" "$mine" "$theirs" "$result"
    done <<<"$hops"
  done <"$flows"
  echo
  echo "$decided decided hops: $agreed agree, $disagreed disagree, $unprobed not probed."
  echo "$undecided undecided hops; $drops routing drops (check with --routing)."
}

if [ "${1:-}" = "--path" ]; then
  shift
  path_probe "$@"
  exit $?
fi

if [ "${1:-}" = "--nat" ]; then
  : "${PANOS_HOST:?set PANOS_HOST}"
  : "${PANOS_KEY_HEADER:?set PANOS_KEY_HEADER}"
  need_key_header "$PANOS_KEY_HEADER"
  shift
  nat_probe "$@"
  exit 0
fi

if [ "${1:-}" = "--routing" ]; then
  : "${PANOS_HOST:?set PANOS_HOST}"
  : "${PANOS_KEY_HEADER:?set PANOS_KEY_HEADER}"
  need_key_header "$PANOS_KEY_HEADER"
  shift
  routing_probe "$@"
  exit 0
fi

cfg=${1:?config file}
vsys=${2:?vsys, e.g. vsys1}
vsys=${vsys#vsys:}
analyst=${3:-bin/proteus}

: "${PANOS_HOST:?set PANOS_HOST}"
: "${PANOS_KEY_HEADER:?set PANOS_KEY_HEADER}"
need_key_header "$PANOS_KEY_HEADER"

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

# library_rule reads the text answer of simulate policy on its standard input
# and prints the rule to compare with the device's (internal/query FileAnswer):
#   "first match: <rule> (<action>)"                    -> <rule>
#   "first match: <rule> (<action>), default rule (...)" -> no-match, because
#       the device names no default rule (measured on fw02, 2026-10-08)
#   "no enabled rule matches"                           -> no-match
#   "first certain match: ..." or "undecided: ..."      -> undecided: an earlier
#       rule is held in doubt, so the library names no first match
# Any other answer, such as an error, prints error.
library_rule() {
  awk '
    /^first match: .*, default rule \(/ { ans = "no-match"; next }
    /^first match: / { r = substr($0, 14); sub(/ \([^()]*\)$/, "", r); ans = r; next }
    /^no enabled rule matches$/ { ans = "no-match"; next }
    /^(first certain match|undecided): / { ans = "undecided"; next }
    END { print (ans == "" ? "error" : ans) }'
}

device_match() {
  local src=$1 dst=$2 fz=$3 tz=$4 app=$5 port=$6
  curl -sk --max-time 40 -H @"$PANOS_KEY_HEADER" "https://$PANOS_HOST/api/" \
    --data-urlencode "type=op" \
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
        | library_rule)
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
