# Quickstart

This guide answers one question per section. Each section gives the purpose, a
command you can run, and the real output. Some sections also give the Go
equivalent.

Every command below runs against a committed fixture in `testdata/config/`. The
output is the output those commands produce. No device is involved.

Each command first prints a `loaded ...` line with the file, the version and the
platform. The output blocks below drop that line, except in section 1.

## Build

```bash
make tools-bin
```

That builds `bin/panos-explore` and `bin/panos-demo`. Every command below uses
the fixtures in `testdata/config/`, so you need no device and no network.

## See everything at once

`panos-demo` runs every feature against one file and narrates what it does. Add
`-v` and it also explains why each answer is what it is.

```bash
./bin/panos-demo testdata/config/firewall-urlcat.xml
./bin/panos-demo -v testdata/config/panorama-lab.xml
```

The tour has twelve sections: loading, what the schema says, the scopes, the
policy targets, the effective policy, visible objects and shadowing, groups,
building the index, a reverse lookup, where a name is used, which rule wins, and
what the answers do not cover.

## The fixtures

| Fixture | What it exercises |
| --- | --- |
| `firewall-urlcat.xml` | custom URL categories, services, an FQDN, an address range |
| `firewall-urlprofile.xml` | a URL category reached through security profiles |
| `firewall-users.xml` | local users, local groups, a dynamic user group |
| `firewall-zones.xml` | zones, interfaces, static routes, a virtual router with BGP |
| `firewall-apps.xml` | a custom application, a group, a filter, a container |
| `panorama-lab.xml` | two hierarchies, one serial in two vsys, dynamic groups |
| `panorama-merge.xml` | three levels, every rule layer populated |
| `panorama-nested-groups.xml` | three levels of group nesting |
| `panorama-shadow.xml` | a child device group shadowing a parent's object |
| `unsupported-version.xml` | a version this build has no digest for |

---

## 1. Load a configuration

This tells you what the file is before you ask anything about it.

```bash
./bin/panos-explore info testdata/config/panorama-lab.xml
```

```
loaded testdata/config/panorama-lab.xml in 60.525ms: PAN-OS 11.2.0 (11.2.7), panorama

device-group tree
    corp
      host_1_directory
      corp-graz
    vsys01
      at-ktn
      at-ooe

firewalls (3), keyed by serial and vsys
  007900000000004 / vsys2    -> at-ooe               stack s_vsys01     0 effective rules
  007900000000004 / vsys3    -> at-ktn               stack s_vsys01     0 effective rules
  007900000000003 / vsys1    -> host_1_directory     stack s_corp       1 effective rules
```

The version and the platform come from the file. The tree comes from `parent-dg`
under `/config/readonly`, which is the only place PAN-OS records it. One serial
appears twice, because the key is serial **and** vsys.

```go
cfg, rep, err := config.Load("testdata/config/panorama-lab.xml")
if err != nil {
    return err                       // an unsupported version fails here
}
fmt.Println(cfg.Version(), cfg.DetailVersion(), cfg.Platform())
fmt.Println("untyped elements:", len(rep.Untyped))
```

The first `Load` in a process decodes the schema digest, which costs about 55 ms.
Every `Load` after that costs about 0.12 ms. Both figures have a benchmark in
`config/bench_test.go`.

Only PAN-OS 11.2 digests ship. Another version fails with a clear message:

```
$ ./bin/panos-explore info testdata/config/unsupported-version.xml
panos-explore: config: no schema for PAN-OS 9.1.0 firewall; this build supports 11.2.0
```

## 2. Find what a firewall actually gets

Panorama cannot report a merged policy. This computes it.

```bash
./bin/panos-explore target testdata/config/panorama-lab.xml 007900000000003 vsys1
```

```
007900000000003 / vsys1
  device group   host_1_directory
  template stack s_corp
  inherits from  shared -> dg:corp -> dg:host_1_directory

effective security policy, in evaluation order (1 rules)
   1. [dg-post     dg:host_1_directory] Corp DC Access           allow  src=[corp-location] dst=[corp-dc] app=[active-directory]

visible address objects (2)
  corp-dc-vienna             10.124.0.1           dg:host_1_directory tags=[corp-dc]
  corp-location-vienna       10.124.0.0/16        dg:host_1_directory tags=[corp-location]
```

To see the layer order, use the merge fixture. Pre-rules run from root to leaf.
Post-rules run from leaf to root.

```bash
./bin/panos-explore groups testdata/config/panorama-merge.xml
```

```
  leaf (9 rules)
     1. [shared-pre  shared          ] shared-pre-1             src=[any] dst=[]
     2. [dg-pre      dg:top          ] top-pre                  src=[] dst=[]
     3. [dg-pre      dg:middle       ] middle-pre               src=[] dst=[]
     4. [dg-pre      dg:leaf         ] leaf-pre-1               src=[] dst=[]
     5. [dg-pre      dg:leaf         ] leaf-pre-2               src=[] dst=[]
     6. [dg-post     dg:leaf         ] leaf-post                src=[] dst=[]
     7. [dg-post     dg:middle       ] middle-post              src=[] dst=[]
     8. [dg-post     dg:top          ] top-post                 src=[] dst=[]
     9. [shared-post shared          ] shared-post-1            src=[any] dst=[]
```

```go
t, err := resolve.TargetFor(cfg, "007900000000003", "vsys1")
fmt.Println(t.DeviceGroup(), t.TemplateStack(), t.Chain())

rules, err := t.Rules(resolve.Security)
for _, r := range rules {
    fmt.Printf("%d. %s %s %s %s\n", r.Position, r.Name, r.Action, r.Layer, r.Scope)
}
```

`target` also reports shadowing. A child device group's object of the same name
hides the parent's:

```bash
./bin/panos-explore target testdata/config/panorama-shadow.xml 001122334455 vsys1
```

```
visible address objects (2)
  web-server                 10.9.9.1             dg:leaf          tags=[]  (shadows the definition in dg:top)
  only-in-top                10.0.0.9             dg:top           tags=[]
```

## 3. Find an object by value

Use this when you hold an address and want the objects covering it, the groups
holding them, and the rules naming either.

```bash
./bin/panos-explore lookup testdata/config/panorama-nested-groups.xml dg:dg1 10.1.1.1
```

```
looking up "10.1.1.1" in dg:dg1

1. objects whose value covers 10.1.1.1
     h-1                        10.1.1.1/32        dg:dg1

2. groups holding them, transitively
     h-1                        in [g-inner g-middle g-outer]

3. rules naming any of them, or naming a literal that covers the address
      1. allow-outer              as source      [dg-pre]
```

The fixture nests `h-1` in `g-inner`, in `g-middle`, in `g-outer`. The rule names
`g-outer` only. All three steps compose, so an address finds a rule three groups
away. There is no depth limit. A cycle in the group definitions is tolerated.

A prefix works too. It finds overlapping objects rather than covering ones.

## 4. Find an object by a fragment of its value

Use this when a value is longer than the name holding it. PAN-OS caps a custom
URL category name at 31 characters and one of its members at 255.

```bash
./bin/panos-explore search testdata/config/firewall-urlcat.xml vsys:vsys1 azureapps
```

```
1 object(s) whose value contains "azureapps" in vsys:vsys1
  custom-azuresite-group     custom-url-category  vsys:vsys1 superlong.example.azureapps.microsoft.com

this is a search, not a match: use reaches to ask what a rule would do
```

The URL is 41 characters. It cannot appear in the name of the category holding
it, so searching the values is the only way to find it.

**Search and matching are different. Do not confuse them.** Search is a
case-insensitive substring test over object values. Matching is token-based and
never a substring test. Section 5.2 shows the difference.

```go
for _, h := range idx.SearchValues("azureapps") {
    fmt.Printf("%s (%s) in %s: %s\n", h.Name, h.Kind, h.Scope, h.Via)
}
```

---

## 5. Ask which rules a value reaches

`reaches` takes a rule field and a value. The fields are `source`,
`destination`, `category`, `application`, `service`, `from`, `to`, `source-user`
and `tag`.

The value spaces a field gets come from the schema. A security rule's `source`
accepts an address, an address group, a region, an external list and an IP block
list. That is five value spaces, not one.

### 5.1 An address

```bash
./bin/panos-explore reaches testdata/config/panorama-lab.xml dg:host_1_directory \
    source 10.124.0.1
```

```
which rules could source match 10.124.0.1, in dg:host_1_directory

10.124.0.1 matched via
  corp-dc-vienna           address        10.124.0.1/32
  corp-location-vienna     address        10.124.0.0/16
  corp-dc                  group holding one of those
  corp-location            group holding one of those

rules in evaluation order (1)
    1. Corp DC Access             allow  [dg-post     dg:host_1_directory]
```

The address resolver reads a prefix, a range and an FQDN. `Via` names the value
that matched, so the reasoning is checkable.

### 5.2 A URL

```bash
./bin/panos-explore reaches testdata/config/firewall-urlcat.xml vsys:vsys1 \
    category sub.wildcard-example.com
```

```
sub.wildcard-example.com matched via
  custom-azuresite-group   custom-url-category *.wildcard-example.com

rules in evaluation order (2)
    1. any-category-early         allow  [local       vsys:vsys1]
    4. URL-Example                allow  [local       vsys:vsys1]

some of those match only because their category is "any"
```

Now ask about a host that only *contains* the pattern:

```bash
./bin/panos-explore reaches testdata/config/firewall-urlcat.xml vsys:vsys1 \
    category wildcard-example.com.evil.net
```

```
rules in evaluation order (1)
    1. any-category-early         allow  [local       vsys:vsys1]

some of those match only because their category is "any"
```

The category does not match. A host is read from the right, so extra tokens on
the end are a different domain.

**URL syntax rules, verified against a real firewall's validator:**

| Pattern | Verdict |
| --- | --- |
| `*.example.com` | accept |
| `^.example.com` | accept |
| `^^.example.com` | accept — carets may repeat |
| `example.com/*` | accept |
| `mail*.example.com` | reject — a `*` must own its whole token |
| `**.example.com` | reject |
| `*.*.example.com` | reject — at most one `*` per pattern, even when not adjacent |

**URL matching rules, documentation-derived and not device-verified.** `test url`
reports PAN-DB categories only and never names a custom category, so no op
command can check these:

- The host splits on `.` and the path splits on `/`.
- The host matches in full. The path matches as a prefix, so `example.com/a`
  covers `example.com/a/b`.
- `*` matches one or more tokens. `^` matches exactly one.
- There is no implicit subdomain wildcard. `example.com` does not cover
  `www.example.com`.

### 5.3 A service

```bash
./bin/panos-explore reaches testdata/config/firewall-urlcat.xml vsys:vsys1 \
    service tcp/8006
```

```
tcp/8006 matched via
  svc-pve                  service        tcp/8006
  svc-range                service        tcp/8000-8100
  svc-grp                  group holding one of those

rules in evaluation order (1)
    2. svc-rule                   allow  [local       vsys:vsys1]
```

Port ranges match as ranges. A bare `443` matches whichever protocol carries it.
The hit reports the range that matched.

### 5.4 A user

```bash
./bin/panos-explore reaches testdata/config/firewall-users.xml vsys:vsys1 \
    source-user alice
```

```
INCOMPLETE: this answer is missing matches.
  quarantined-users (dynamic-user-group): a dynamic user group is filled in at runtime by User-ID, so who is in it is not in the configuration and a user cannot be matched against it
  alice (user-group): no user directory was supplied, so only the local user database was searched. A rule naming a directory group this user belongs to is missing from the result

alice matched via
  alice                    user           alice
  local-admins             user-group     alice

rules in evaluation order (1)
    1. admins-allowed             allow  [local       vsys:vsys1]
```

Without a directory the library searches the local user database only, and it
says so. Section 9 supplies one.

### 5.5 A zone

Give a zone name, and the answer is a direct reading:

```bash
./bin/panos-explore reaches testdata/config/firewall-zones.xml vsys:vsys1 from inside
```

```
rules in evaluation order (1)
    1. from-inside                allow  [local       vsys:vsys1]
```

Give an address, and the library infers the zone. It reads interface addresses and
static routes as a small routing table. The longest prefix wins.

```bash
./bin/panos-explore reaches testdata/config/firewall-zones.xml vsys:vsys1 from 10.1.0.5
```

```
INCOMPLETE: this answer is missing matches.
  empty-zone (zone): this zone has no interface assigned, so no address can be placed in it
  ethernet1/9 (zone): interface ethernet1/9 is in no zone, so 10.9.0.0/24 cannot be placed in one
  tunnel.99 (zone): interface tunnel.99 is in no zone, so 0.0.0.0/0 cannot be placed in one
  default/bgp (zone): this virtual router learns routes at runtime, and a route learned that way is not in the configuration, so an address reachable only by it cannot be placed in a zone

10.1.0.5 matched via
  inside                   zone           ethernet1/1 10.1.0.1/24

rules in evaluation order (1)
    1. from-inside                allow  [local       vsys:vsys1]
```

The inference reports every limit. An address no route covers places nowhere:

```bash
./bin/panos-explore reaches testdata/config/firewall-zones.xml vsys:vsys1 from 8.8.8.8
```

```
  8.8.8.8 (zone): no interface address and no static route in this configuration covers this address, so the zone it would arrive on is unknown

no rule could match it
```

On Panorama the network configuration lives in a template, so a device group scope
has no zones at all.

### 5.6 An application

```bash
./bin/panos-explore reaches testdata/config/firewall-apps.xml vsys:vsys1 \
    application custom-erp
```

```
INCOMPLETE: this answer is missing matches.
  high-risk-filter (application-filter): an application filter selects predefined applications by category, risk and behaviour, and that metadata is in the content database a firewall downloads rather than in the configuration, so which applications it holds cannot be determined here
  ms-office-bundle (application-container): an application container groups predefined applications, and its members are in the content database rather than the configuration

custom-erp matched via
  custom-erp               application    custom-erp
  erp-bundle               group holding one of those

rules in evaluation order (1)
    1. erp-allow                  allow  [local       vsys:vsys1]
```

A custom application and an application group resolve. A predefined name such as
`ssl` works as a name. An application filter and an application container are
reported rather than guessed, because their members live in the content database.

A tag needs no value space, because a tag is a name.

---

### 5.5.1 Place an address from the device, not the configuration

A configuration says what a firewall was told. Its forwarding table says what it is
doing, and the two differ routinely. Capture a snapshot:

```bash
PANOS_HOST=fw01 PANOS_API_KEY=... scripts/capture-zones.sh zone-snapshot.json
```

Then point `PANOS_ZONES` at it:

```bash
PANOS_ZONES=zone-snapshot.json ./bin/panos-explore reaches cfg.xml vsys:vsys1 from 198.18.0.5
```

```
using zone snapshot from fw01.example.net, serial 007900000000002, taken 2026-09-27T17:05:00Z; routers [default lte]
198.18.0.5 matched via
  transport                zone           ethernet1/1 via default 0.0.0.0/0
```

The answer names the interface, the router and the route that decided it. Without the
snapshot this address places nowhere: the configuration's default route points at a
tunnel that is in no zone, and the device has since replaced that route.

An address can be covered by more than one logical router. All of them are reported
and none is chosen, because which applies depends on the interface the packet arrived
on — which is what the question was.

A snapshot is authoritative: where it places nothing, the configuration is not
consulted instead. The format is in `docs/zone-snapshot-format.md`.

## 6. Follow a URL category through security profiles

PAN-OS deployments normally apply URL policy through profiles, not through the
`category` field. On a lab firewall every rule has `category any`.

```bash
./bin/panos-explore uses testdata/config/firewall-urlprofile.xml vsys:vsys1 demo-category
```

```
2 profile path(s) reaching "demo-category" in vsys:vsys1
  rule via-group                pos 1    group default        profile default-url-filter     alert     demo-category          by name
  rule via-named-profile        pos 2    group -              profile default-url-filter     alert     demo-category          by name

these are not matches. A rule matches on addresses, zones, application and
service; its profile then inspects the request. What the profile does with a
match is not derivable from the configuration, so no verdict is given here.
```

A URL works as well as a category name:

```bash
./bin/panos-explore uses testdata/config/firewall-urlprofile.xml vsys:vsys1 \
    'example.com/this/is/a/very/long/url/i/need/to/match'
```

```
2 profile path(s) reaching "example.com/this/is/a/very/long/url/i/need/to/match" in vsys:vsys1
  rule via-group                pos 1    group default        profile default-url-filter     alert     demo-category          example.com/this/is/a/very/long/url/i/need/to/match
  rule via-named-profile        pos 2    group -              profile default-url-filter     alert     demo-category          example.com/this/is/a/very/long/url/i/need/to/match
```

The path runs rule, profile setting, profile group or named profile,
url-filtering profile, action list, category. `List` names the action list:
`block`, `alert`, `allow`, `continue` or `override`. No allow-or-block verdict is
given, because that depends on the response and the session.

```go
for _, u := range idx.ProfileUses("demo-category") {
    fmt.Printf("%s pos %d group %q profile %q list %s -> %s (%s)\n",
        u.Rule, u.Position, u.Group, u.Profile, u.List, u.Category, u.Via)
}
```

## 7. Simulate a match, with zones

`simulate` intersects the two address sides and reports the first match. Without
zones it does not evaluate zones, and the answer is often wrong rather than
slightly wrong.

```bash
./bin/panos-explore simulate testdata/config/firewall-zones.xml vsys:vsys1 \
    10.1.0.5 10.2.0.5
```

```
no zones given, so zones are not evaluated; pass from-zone and to-zone to
narrow the answer the way the device does

candidates in evaluation order (2)
   1. from-inside              allow  [local       vsys:vsys1]
   2. from-loop                allow  [local       vsys:vsys1]

first match: from-inside (allow)
note: addresses only. Application, service and zones were not evaluated,
      so this is a candidate set and the device may pick a different rule.
```

Now give the zones:

```bash
./bin/panos-explore simulate testdata/config/firewall-zones.xml vsys:vsys1 \
    10.1.0.5 10.2.0.5 inside dmz
```

```
zones: from inside, to dmz

candidates in evaluation order (1)
   1. from-inside              allow  [local       vsys:vsys1]

first match: from-inside (allow)
note: addresses and zones were evaluated; application and service were not,
      so the device may still decline a rule this reports.
```

A firewall's own `test security-policy-match` takes zones as arguments too.
Measured against it on a lab firewall, with probes built from each rule's own
zones and ports: `simulate` agreed on 3 of 7 without zones, and on 7 of 7 with
them. Give the zones whenever you have them.

The library never decides the verdict. The caller composes it:

```go
src := idx.CandidatesFor(index.Source, srcAddr)
dst := idx.CandidatesFor(index.Destination, dstAddr)

cand := roaring.And(src, dst)
cand.AndNot(idx.Disabled())
if !cand.IsEmpty() {
    first := idx.Rules()[cand.Minimum()]     // PAN-OS takes the first match
    fmt.Println(first.Name, first.Action)
}
```

## 8. Read a report and act on `Unresolved`

Every lookup returns a `Report`:

| Field | What it holds |
| --- | --- |
| `Value` | the value asked about |
| `Hits` | each object that matched, with `Via` — the value that matched it |
| `Groups` | the groups that carried a hit to a rule |
| `ViaAny` | true when some rules join only because the field is `any` |
| `Unresolved` | what the library could not evaluate, and why |

**A non-empty `Unresolved` means the answer is incomplete. Tell your own users
so.** The library never hides incompleteness, and a caller must not either.

```go
rules, rep := idx.Candidates(index.SourceUser, "alice")
fmt.Println(rules.GetCardinality(), "rules reached")

for _, h := range rep.Hits {
    fmt.Printf("matched %s (%s) via %s\n", h.Name, h.Kind, h.Via)
}
for _, u := range rep.Unresolved {
    fmt.Printf("INCOMPLETE: %s\n", u)      // Value, Kind and Reason
}
if rep.ViaAny {
    fmt.Println("some rules match only because the field is \"any\"")
}
```

The library reports these as unresolved:

- a `Category Match` URL category
- a URL external list
- a dynamic address group's or dynamic user group's runtime members
- an application filter or an application container
- a zone with no interface assigned
- an interface in no zone
- a virtual router running BGP or OSPF
- an address no interface address and no static route covers
- a user query with no directory supplied
- a stale user snapshot

A value nothing recognised is also unresolved. A value that was recognised and
matched nothing is a **complete** answer: a URL in no category really does reach
only the `any` rules.

## 9. Supply a user snapshot

A configuration does not hold user-to-group membership. User-ID learns it from a
directory, and it changes far faster than a configuration. So the snapshot
attaches to a view, never to the cached index.

The library defines this JSON format and reads it. The library never fetches.
`taken_at` is required.

```json
{
  "taken_at": "2026-09-27T12:00:00Z",
  "source": "User-ID on a lab firewall",
  "groups": {
    "alice": ["local-admins", "engineering"],
    "ACME\\carol": ["engineering"]
  }
}
```

Point `PANOS_USERS` at it:

```bash
PANOS_USERS=testdata/users-snapshot.json ./bin/panos-explore reaches \
    testdata/config/firewall-users.xml vsys:vsys1 source-user alice
```

```
using user snapshot testdata/users-snapshot.json, taken 2026-09-27T12:00:00Z
INCOMPLETE: this answer is missing matches.
  quarantined-users (dynamic-user-group): a dynamic user group is filled in at runtime by User-ID, so who is in it is not in the configuration and a user cannot be matched against it

alice matched via
  alice                    user           alice
  local-admins             user-group     alice
  engineering              user-group     alice

rules in evaluation order (2)
    1. admins-allowed             allow  [local       vsys:vsys1]
    2. engineering-allowed        allow  [local       vsys:vsys1]
```

`engineering` is a directory group. It is not in the file. The snapshot added it,
and with it the second rule. A domain-qualified name works too, case
insensitively:

```bash
PANOS_USERS=testdata/users-snapshot.json ./bin/panos-explore reaches \
    testdata/config/firewall-users.xml vsys:vsys1 source-user 'ACME\carol'
```

```
ACME\carol matched via
  engineering              user-group     ACME\carol

rules in evaluation order (1)
    2. engineering-allowed        allow  [local       vsys:vsys1]
```

In Go:

```go
f, err := os.Open("testdata/users-snapshot.json")
defer f.Close()

snap, err := index.LoadUserSnapshot(f)      // taken_at is required
if reason, stale := snap.Stale(); stale {
    fmt.Println("warn:", reason)            // report this to your users
}

view := idx.With(index.Providers{Users: snap})
rules, rep := view.Candidates(index.SourceUser, "alice")
```

A snapshot older than 24 hours is reported as stale on every lookup that used it.
Set `max_age` to change the limit. A `Providers` value also takes a `Zones`
locator, for a live routing table.

## 10. Scope decides the answer

One shared dynamic address group. Three device groups. Three different answers.

```bash
for dg in host_1_directory corp-graz at-ktn; do
  ./bin/panos-explore group testdata/config/panorama-lab.xml dg:$dg corp-location
done
```

```
corp-location in dg:host_1_directory
  dynamic, filter 'corp-location'
  members matched by tag: [corp-location-vienna]
  note: Members registered at runtime through User-ID or VM monitoring are not in a configuration file and are not included.

corp-location in dg:corp-graz
  dynamic, filter 'corp-location'
  members matched by tag: [corp-location-graz]
  note: Members registered at runtime through User-ID or VM monitoring are not in a configuration file and are not included.

corp-location in dg:at-ktn
  dynamic, filter 'corp-location'
  members matched by tag: []
  note: Members registered at runtime through User-ID or VM monitoring are not in a configuration file and are not included.
```

The group, the filter and the schema are identical in all three. Only the visible
scope differs. Resolve it once globally and every answer about a rule using it is
wrong rather than incomplete.

Tag filters parse properly. `and`, `or`, `not` and parentheses all work, and `and`
binds tighter than `or`. A filter this build cannot read contributes no members
and is reported.

`group` reads address groups only.

## 11. Find every reference to a name

```bash
./bin/panos-explore whereused testdata/config/panorama-nested-groups.xml dg:dg1 g-outer
```

```
1 reference(s) to "g-outer" in dg:dg1
  dg:dg1           source       /config/devices/localhost.localdomain/device-group/dg1/pre-rulebase/security/rules/allow-outer
                                could be: [region address address-group external-list ip-block-list-v2]

it is a group holding [h-1 h-2 g-inner g-middle]
```

The path names the **instance**, not the schema location, so two device groups
holding an object of the same name stay distinguishable.

`could be` lists the object kinds the schema permits in that field. 919 of 2,420
reference fields allow more than one, and the widest allows 31. The schema cannot
tell you which kind a given target actually is.

## 12. Run the tests

```bash
make gate       # tidy, lint, unit tests
make ci         # adds the race detector, coverage floors, a drift gate, a vulnerability scan
go test -bench . -benchmem ./index/ ./config/
```

Against a real device, which CI never does:

```bash
PANOS_LIVE_CONFIG=/tmp/pano-live.xml go test -tags live -v ./resolve/
```

Read these tests first. Each one pins a mistake that was actually made.

| Test | What it prevents |
| --- | --- |
| `config.TestWalkContinuesPastANestedConfigElement` | a template embeds a whole config; stopping at the first `</config>` yielded 1 reference instead of 18 |
| `index.TestNestedChainFromValueToRule` | the value, object, group, group, rule chain |
| `resolve.TestMergedRuleOrder` | pre-rules top-down, post-rules bottom-up |
| `resolve.TestDynamicGroupDiffersInASibling` | the same group resolving differently per device group |
| `digest.TestRealSchemaFormCensus` | 9,647 real object references out of 13,120 declarations |
| `codegen.TestRootNameIsReserved` | the schema contains an inline sequence named `config` |
