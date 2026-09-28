# Quickstart

This guide answers one question per section. Each section gives the purpose, a
command you can run, and the real output. Some sections also give the Go
equivalent.

Every command below runs against a committed fixture in `testdata/config/`. The
output is the output those commands produce. No device is involved.

Each command first prints a `loaded ...` line with the file and the version. The output blocks below drop that line, except in section 1.

## Build

```bash
make tools-bin
```

That builds `bin/panos-explore`, `bin/panos-demo` and `bin/panos-analyst`. Section 0
fetches from a real firewall. Every command from section 1 on uses the fixtures in
`testdata/config/`, so you need no device and no network.

## See everything at once

`panos-demo` runs every feature against one file and narrates what it does. Add
`-v` and it also explains why each answer is what it is.

```bash
./bin/panos-demo testdata/config/firewall-urlcat.xml
./bin/panos-demo -v testdata/config/firewall-multivsys.xml
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
| `firewall-multivsys.xml` | three vsys, one shared dynamic group resolving differently in each |
| `firewall-lab.xml` | pushed shared pre- and post-rules around a vsys's own rules |
| `firewall-nested-groups.xml` | three levels of group nesting |
| `firewall-shadow.xml` | a vsys object shadowing a shared one |
| `unsupported-version.xml` | a version older than every digest, read with the lowest |
| `firewall-version-12.2.xml` | a version newer than every digest, read with the nearest |
| `panorama-rejected.xml` | a Panorama configuration, which is refused |

---

## 0. Fetch a firewall

Everything below also works on a snapshot fetched from a device.

```bash
./bin/panos-analyst init                  # writes ~/.config/panos-analyst/config.yaml, mode 0600
$EDITOR ~/.config/panos-analyst/config.yaml
export PANOS_PASSWORD=...                 # the variable the inventory names
./bin/panos-analyst fetch fw01
./bin/panos-explore info @fw01
```

`fetch` logs in with the inventory's username and password, and stores the running
configuration, `show system info`, `show interface all` and the forwarding table as
one snapshot under `~/.local/share/panos-analyst/fw01/`. `@fw01` is the latest
snapshot with a configuration, `@fw01@<id>` an earlier one, and zone answers then
come from the stored forwarding table.

The inventory template turns TLS certificate verification off, because lab
firewalls present self-signed certificates, and every fetch says so. Set
`insecure_tls: false` once your devices present certificates this machine trusts.

## 1. Load a configuration

This tells you what the file is before you ask anything about it.

```bash
./bin/panos-explore info testdata/config/firewall-multivsys.xml
```

```
loaded testdata/config/firewall-multivsys.xml in 36.12ms: PAN-OS 11.2.0 (11.2.5)

vsys (3), keyed by device and vsys
  localhost.localdomain / vsys1    1 rules
  localhost.localdomain / vsys2    0 rules
  localhost.localdomain / vsys3    0 rules
```

The version comes from the file. Each vsys is its own policy scope, so the key is
device **and** vsys.

```go
cfg, rep, err := config.Load("testdata/config/firewall-multivsys.xml")
if err != nil {
    return err                       // an unsupported version fails here
}
fmt.Println(cfg.Version(), cfg.DetailVersion())
fmt.Println("untyped elements:", len(rep.Untyped))
```

The first `Load` in a process decodes the schema digest, which costs about 55 ms.
Every `Load` after that costs about 0.12 ms. Both figures have a benchmark in
`config/bench_test.go`.

Only PAN-OS 11.2 digests ship. Another version loads with the nearest digest, and
says so:

```
$ ./bin/panos-explore info testdata/config/firewall-version-12.2.xml
loaded testdata/config/firewall-version-12.2.xml in 56.493ms: PAN-OS 12.2.0 (12.2.1)
  warning: the configuration is PAN-OS 12.2.0 but was read with the 11.2.0 schema, the nearest this build carries; a field added or moved between them yields no reference, so this answer can miss rules
```

A Panorama configuration is refused. Read each firewall's own export instead.

## 2. Find what a firewall actually evaluates

```bash
./bin/panos-explore target testdata/config/firewall-multivsys.xml localhost.localdomain vsys1
```

```
localhost.localdomain / vsys1
  inherits from  shared -> vsys:vsys1

effective security policy, in evaluation order (1 rules)
   1. [local       vsys:vsys1      ] Corp DC Access           allow  src=[corp-location] dst=[corp-dc] app=[active-directory]

visible address objects (2)
  corp-dc-vienna             10.124.0.1           vsys:vsys1       tags=[corp-dc]
  corp-location-vienna       10.124.0.0/16        vsys:vsys1       tags=[corp-location]
```

To see the layer order, use the lab fixture. Pushed shared pre-rules come first,
then the vsys's own rules, then pushed shared post-rules.

```bash
./bin/panos-explore groups testdata/config/firewall-lab.xml
```

```
  vsys1 (5 rules)
     1. [shared-pre  shared          ] pushed-pre               src=[any] dst=[]
     2. [local       vsys:vsys1      ] identity-redistribution  src=[any] dst=[10.10.0.0/24]
     3. [local       vsys:vsys1      ] dc-to-home               src=[g-servers] dst=[net-home]
     4. [local       vsys:vsys1      ] tagged-out               src=[g-tagged] dst=[any]
     5. [shared-post shared          ] pushed-post              src=[any] dst=[]
```

```go
t, err := resolve.TargetFor(cfg, "localhost.localdomain", "vsys1")
fmt.Println(t.Scope(), t.Chain())

rules, err := t.Rules(resolve.Security)
for _, r := range rules {
    fmt.Printf("%d. %s %s %s %s\n", r.Position, r.Name, r.Action, r.Layer, r.Scope)
}
```

`target` also reports shadowing. A vsys object of the same name hides the shared
one:

```bash
./bin/panos-explore target testdata/config/firewall-shadow.xml localhost.localdomain vsys1
```

```
visible address objects (2)
  web-server                 10.9.9.1             vsys:vsys1       tags=[]  (shadows the definition in shared)
  only-in-shared             10.0.0.9             shared           tags=[]
```

## 3. Find an object by value

Use this when you hold an address and want the objects covering it, the groups
holding them, and the rules naming either.

```bash
./bin/panos-explore lookup testdata/config/firewall-nested-groups.xml vsys:vsys1 10.1.1.1
```

```
looking up "10.1.1.1" in vsys:vsys1

1. objects whose value covers 10.1.1.1
     h-1                        10.1.1.1/32        vsys:vsys1

2. groups holding them, transitively
     h-1                        in [g-inner g-middle g-outer]

3. rules naming any of them, or naming a literal that covers the address
      1. allow-outer              as source      [local]
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
./bin/panos-explore reaches testdata/config/firewall-multivsys.xml vsys:vsys1 \
    source 10.124.0.1
```

```
which rules could source match 10.124.0.1, in vsys:vsys1

10.124.0.1 matched via
  corp-dc-vienna           address        10.124.0.1/32
  corp-location-vienna     address        10.124.0.0/16
  corp-dc                  group holding one of those
  corp-location            group holding one of those

rules in evaluation order (1)
    1. Corp DC Access             allow  [local       vsys:vsys1]
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
  10.1.0.5 (zone): this zone came from the configuration, not from the device. It is an inference from interface addresses and static routes, and a firewall's forwarding table routinely differs: supply a zone snapshot for what the device is actually doing

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

One shared dynamic address group. Three vsys. Three different answers.

```bash
for v in vsys1 vsys2 vsys3; do
  ./bin/panos-explore group testdata/config/firewall-multivsys.xml vsys:$v corp-location
done
```

```
corp-location in vsys:vsys1
  dynamic, filter 'corp-location'
  members matched by tag: [corp-location-vienna]
  note: Members registered at runtime through User-ID or VM monitoring are not in a configuration file and are not included.

corp-location in vsys:vsys2
  dynamic, filter 'corp-location'
  members matched by tag: [corp-location-graz]
  note: Members registered at runtime through User-ID or VM monitoring are not in a configuration file and are not included.

corp-location in vsys:vsys3
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
./bin/panos-explore whereused testdata/config/firewall-nested-groups.xml vsys:vsys1 g-outer
```

```
1 reference(s) to "g-outer" in vsys:vsys1
  vsys:vsys1 source /config/devices/localhost.localdomain/vsys/vsys1/rulebase/security/rules/allow-outer
                    could be: [region address address-group external-list ip-block-list-v2]

it is a group holding [h-1 h-2 g-inner g-middle]
```

The path names the **instance**, not the schema location, so two vsys holding
an object of the same name stay distinguishable.

`could be` lists the object kinds the schema permits in that field. 673 of 1,559
reference fields allow more than one, and the widest allows 153. The schema cannot
tell you which kind a given target actually is.

A field is a **path** wherever the reference really is nested, and a plain name
wherever it is not — `source` stays `source`. That is how a rule's security
profiles are found, which needs three or four levels and a named union in between:

```bash
./bin/panos-explore whereused testdata/config/firewall-refpaths.xml vsys:vsys1 baseline
```

```
1 reference(s) to "baseline" in vsys:vsys1
  vsys:vsys1 profile-setting/group /config/devices/localhost.localdomain/vsys/vsys1/rulebase/security/rules/by-group
                                   could be: [profile-group]
```

The columns are sized to the rows, so a path-shaped field does not truncate and a
short one does not push the instance path off to the right.

Values that are an element's text rather than a member are found the same way, so
`log-setting`, `schedule` and `group-tag` all resolve. Candidates are the kinds
declared for that leaf alone: `profile-setting/group` can only be a profile group,
where a merged field would have offered all eleven kinds `profile-setting` contains.

## 12. Run the tests

```bash
make gate       # tidy, lint, unit tests
make ci         # adds the race detector, coverage floors, a drift gate, a vulnerability scan
go test -bench . -benchmem ./index/ ./config/
```

Against a real device, which CI never does:

```bash
PANOS_LIVE_CONFIG=/tmp/fw-live.xml go test -tags live -v ./resolve/
```

Read these tests first. Each one pins a mistake that was actually made.

| Test | What it prevents |
| --- | --- |
| `config.TestWalkContinuesPastANestedConfigElement` | a configuration holds nested `<config>` elements; stopping at the first yielded 1 reference instead of 18 |
| `index.TestNestedChainFromValueToRule` | the value, object, group, group, rule chain |
| `resolve.TestFirewallRuleOrderIncludesTheLocalLayer` | shared pre-rules, then the vsys's own, then shared post-rules |
| `resolve.TestDynamicGroupDiffersInASibling` | the same group resolving differently per vsys |
| `digest.TestRealSchemaFormCensus` | 5,144 real object references out of 5,898 declarations |
| `codegen.TestRootNameIsReserved` | the schema contains an inline sequence named `config` |
