# Quickstart

This guide answers one question per section. Each section gives the purpose, a
command you can run, and the real output. Some sections also give the Go
equivalent.

From section 3 on, every command reads a committed fixture in `testdata/config/`
with `--file`. No device and no network are involved. Against fetched devices, the
same commands drop `--file` and answer for every device in the inventory.

## 1. Build

```bash
make tools-bin
```

That builds `bin/panos-analyst` and `bin/panos-demo`.

`panos-demo` runs every library feature against one file and narrates what it
does. Add `-v` and it also explains why each answer is what it is:

```bash
./bin/panos-demo -v testdata/config/firewall-multivsys.xml
```

## 2. Fetch a firewall

```bash
./bin/panos-analyst inventory init        # writes ~/.config/panos-analyst/config.yaml, mode 0600
$EDITOR ~/.config/panos-analyst/config.yaml
export PANOS_PASSWORD=...                 # the variable the inventory names
./bin/panos-analyst fetch --all
./bin/panos-analyst snapshot show
```

`fetch` logs in with the inventory's username and password, and stores the running
configuration, `show system info`, `show interface all` and the forwarding table as
one snapshot per device, up to eight devices at once. Every question below then
runs against each device's latest snapshot. `--device fw01` or
`--label site=vienna` narrows the selection, `--at 2026-09-23` reads older
snapshots, and `--fresh` fetches first.

The inventory template turns TLS certificate verification off, because lab
firewalls present self-signed certificates, and every fetch says so. Set
`insecure_tls: false` once your devices present certificates this machine trusts.

## The fixtures

| Fixture | What it exercises |
| --- | --- |
| `firewall-multivsys.xml` | three vsys, one shared dynamic group resolving differently in each |
| `firewall-lab.xml` | pushed shared pre- and post-rules around a vsys's own rules |
| `firewall-lab-changed.xml` | the lab configuration a week later: one value changed, one object gone, one rule added, one disabled |
| `firewall-nested-groups.xml` | three levels of group nesting |
| `firewall-literals.xml` | addresses written straight into rule fields |
| `firewall-urlcat.xml` | custom URL categories, services, an FQDN, an address range |
| `firewall-urlprofile.xml` | a URL category reached through security profiles |
| `firewall-users.xml` | local users, local groups, a dynamic user group |
| `firewall-zones.xml` | zones, interfaces, static routes, a virtual router with BGP |
| `firewall-version-12.2.xml` | a version newer than every digest, read with the nearest |
| `unsupported-version.xml` | a version older than every digest, read with the lowest |
| `panorama-rejected.xml` | a Panorama configuration, which is refused |

---

## 3. Look at a configuration

```
$ panos-analyst snapshot show --file testdata/config/firewall-multivsys.xml
file   testdata/config/firewall-multivsys.xml
  vsys1    PAN-OS 11.2.5, security rules: 1
  vsys2    PAN-OS 11.2.5, security rules: 0
  vsys3    PAN-OS 11.2.5, security rules: 0
```

Against the store, `snapshot show` also names each device's host, model, serial,
the snapshot's age, and every fetched document with its size or its error.

## 4. Search for an address

`search` answers "where does this appear". One term goes in; out come the objects
whose value holds it, the objects with that name, the groups holding either, the
references naming any of them, and the rules that write it straight into a field.

```
$ panos-analyst search 10.124.0.1 --file testdata/config/firewall-multivsys.xml
search 10.124.0.1 (covers)

file / vsys1   testdata/config/firewall-multivsys.xml
  object     address              corp-dc-vienna           10.124.0.1/32
  object     address              corp-location-vienna     10.124.0.0/16
  group      address-group        corp-dc                  holds corp-dc-vienna
  group      address-group        corp-location            holds corp-location-vienna
  reference  security rule        Corp DC Access           destination -> corp-dc
  reference  security rule        Corp DC Access           source -> corp-location
1 with results, 2 without, 0 holes
```

The groups are shared dynamic groups; the objects join them by tag. A rule whose
field is `any` reaches every address, but no object leads to it, so search leaves
it out. Which rule traffic would hit is `simulate`, section 11.

## 5. Scope decides the answer

The same shared group holds different members in each vsys, because only shared and
the vsys itself contribute:

```
$ panos-analyst search 10.125.0.1 --file testdata/config/firewall-multivsys.xml
search 10.125.0.1 (covers)

file / vsys2   testdata/config/firewall-multivsys.xml
  object     address              corp-dc-graz             10.125.0.1/32
  object     address              corp-location-graz       10.125.0.0/16
  group      address-group        corp-dc                  holds corp-dc-graz
  group      address-group        corp-location            holds corp-location-graz
1 with results, 2 without, 0 holes
```

Every result is keyed by device and vsys. Resolve the group once globally and
every answer about a rule using it is wrong rather than incomplete.

## 6. Groups, nested and direct

```
$ panos-analyst search 10.1.1.1 --file testdata/config/firewall-nested-groups.xml
search 10.1.1.1 (covers)

file / vsys1   testdata/config/firewall-nested-groups.xml
  object     address              h-1                      10.1.1.1/32
  group      address-group        g-inner                  holds h-1
  group      address-group        g-middle                 holds h-1
  group      address-group        g-outer                  holds h-1
  reference  address-group        g-inner                  static -> h-1
  reference  address-group        g-middle                 static -> g-inner
  reference  address-group        g-outer                  static -> g-middle
  reference  security rule        allow-outer              source -> g-outer
1 with results, 0 without, 0 holes
```

The rule names `g-outer` only; the address sits three groups down. `--direct`
answers "which group do I edit":

```
$ panos-analyst search 10.1.1.1 --direct --show objects,groups --file testdata/config/firewall-nested-groups.xml
search 10.1.1.1 (covers)

file / vsys1   testdata/config/firewall-nested-groups.xml
  object     address              h-1                      10.1.1.1/32
  group      address-group        g-inner                  holds h-1
1 with results, 0 without, 0 holes
```

## 7. Addresses written into a rule

```
$ panos-analyst search 198.18.1.1 --file testdata/config/firewall-literals.xml
search 198.18.1.1 (covers)

file / vsys1   testdata/config/firewall-literals.xml
  object     address              named-host               198.18.1.1/32
  reference  security rule        named-rule               source -> named-host
  literal    security rule        literal-host             source 198.18.1.1/32
  literal    security rule        literal-net              source 198.18.0.0/16
1 with results, 0 without, 0 holes
```

A configuration can name no object at all and write addresses straight into its
rules. The literal stage finds those.

## 8. How the term matches

The term's type sets the default: an address is **covered**, a prefix or a range
`a-b` **overlaps**, a port is **covered**, a URL matches by PAN-OS tokens, anything
else is **exact**. Three flags override it, one at a time.

`--within` keeps what lies inside the term:

```
$ panos-analyst search 10.124.0.0/24 --within --file testdata/config/firewall-multivsys.xml --vsys vsys1
search 10.124.0.0/24 (within)

file / vsys1   testdata/config/firewall-multivsys.xml
  object     address              corp-dc-vienna           10.124.0.1/32
  group      address-group        corp-dc                  holds corp-dc-vienna
  reference  security rule        Corp DC Access           destination -> corp-dc
1 with results, 0 without, 0 holes
```

`--exact` keeps only an equal value:

```
$ panos-analyst search 10.124.0.0/16 --exact --show objects --file testdata/config/firewall-multivsys.xml --vsys vsys1
search 10.124.0.0/16 (exact)

file / vsys1   testdata/config/firewall-multivsys.xml
  object     address              corp-location-vienna     10.124.0.0/16
1 with results, 0 without, 0 holes
```

`--contains` searches names and values as text. PAN-OS caps a custom URL category
name at 31 characters and a member at 255, so a long URL cannot appear in the name
of the category holding it:

```
$ panos-analyst search azureapps --contains --file testdata/config/firewall-urlcat.xml
search azureapps (contains)

file / vsys1   testdata/config/firewall-urlcat.xml
  object     custom-url-category  custom-azuresite-group   superlong.example.azureapps.microsoft.com
  reference  security rule        URL-Example              category -> custom-azuresite-group
1 with results, 0 without, 0 holes
```

**Text search and matching are different.** `--contains` is a substring test;
without it, a URL matches by PAN-OS tokens and never by substring.

## 9. Ports, URLs, users

A port finds every service whose range holds it:

```
$ panos-analyst search tcp/8006 --file testdata/config/firewall-urlcat.xml
search tcp/8006 (covers)

file / vsys1   testdata/config/firewall-urlcat.xml
  object     service              svc-pve                  tcp/8006
  object     service              svc-range                tcp/8000-8100
  group      service-group        svc-grp                  holds svc-pve
  group      service-group        svc-grp                  holds svc-range
  reference  security rule        svc-rule                 service -> svc-grp
  reference  service-group        svc-grp                  members -> svc-pve
  reference  service-group        svc-grp                  members -> svc-range
1 with results, 0 without, 0 holes
```

A URL category reaches rules through their security profiles, not only through
their `category` field:

```
$ panos-analyst search demo-category --file testdata/config/firewall-urlprofile.xml
search demo-category (matches)

file / vsys1   testdata/config/firewall-urlprofile.xml
  object     custom-url-category  demo-category            name
  reference  security rule        via-group                profile-setting -> default > default-url-filter alert demo-category
  reference  security rule        via-named-profile        profile-setting -> default-url-filter alert demo-category
  reference  url-filtering        default-url-filter       alert -> demo-category
1 with results, 0 without, 0 holes
```

A profile inspects traffic a rule already matched; the rule does not match
because of it.

Which directory groups a user belongs to is not in a configuration. Point
`PANOS_USERS` at a user snapshot and search follows them:

```
$ PANOS_USERS=testdata/users-snapshot.json panos-analyst search 'ACME\carol' --file testdata/config/firewall-users.xml
search ACME\carol (matches)

file / vsys1   testdata/config/firewall-users.xml
  object     user-group           engineering              ACME\carol
  reference  security rule        engineering-allowed      source-user -> engineering
1 with results, 0 without, 0 holes
```

The snapshot format is `{"taken_at":"…","groups":{"alice":["engineering"]}}`.
Against the store, a stored forwarding table also answers zone questions.

## 10. Narrow a search

- `--kind address,service` keeps objects and groups of these kinds.
- `--field source,destination` keeps references and literals from these fields.
- `--show objects,groups,refs,literals` keeps these stages.
- `--direct` keeps groups one level up.
- `--device`, `--label k=v`, `--vsys` narrow the targets.

## 11. Simulate a flow

`simulate secpolicy` answers "which rule would this traffic hit". It runs named
stages that narrow the candidate rules, and each stage says how certain it is:
**exact**, **overmatch** (may hold more than the device would match), **inferred**
(from data the device may not be using) or **undermatch** (may be missing matches).
The run's fidelity is the weakest stage's.

Source and destination are an address or an FQDN. `--port`, `--url` and the zones
narrow the flow:

```
$ panos-analyst simulate secpolicy 10.1.0.5 10.2.0.5 --file testdata/config/firewall-zones.xml --from-zone inside --to-zone dmz --port 443
10.1.0.5 -> 10.2.0.5 tcp/443
file / vsys1   testdata/config/firewall-zones.xml
  zones      from inside, to dmz (given)
  relevance  unknown: no stored forwarding table
  fidelity   overmatch: kept rules whose service is application-default, predefined or absent: from-inside; not evaluated: application
    1. from-inside                allow  [local       vsys:vsys1]
first match: from-inside (allow)
```

`from-inside` names no service, so a port cannot rule it out: it stays, and the
fidelity says why. Application is never evaluated yet.

Without `--from-zone` and `--to-zone`, zones are derived: from the stored forwarding
table against a fetched device, else from the configuration's interfaces and
routes. `--why` shows every stage and how many candidates it left:

```
$ panos-analyst simulate secpolicy 10.1.0.5 10.2.0.5 --file testdata/config/firewall-zones.xml --why
10.1.0.5 -> 10.2.0.5 tcp
file / vsys1   testdata/config/firewall-zones.xml
  zones      from inside, to dmz (configuration)
  relevance  unknown: no stored forwarding table
  fidelity   inferred; not evaluated: service, application
  resolve-source       exact          2  10.1.0.5: 0 hits, 0 negated rules
  resolve-destination  exact          2  10.2.0.5: 0 hits, 0 negated rules
  derive-zones         inferred       1  from inside; to dmz (configuration)
  match-service        overmatch      1  no port given
  match-url            exact          1  no candidate names a URL category
  drop-disabled        exact          1  0 disabled
  order                exact          1  1 in order
  first-match          overmatch      1  from-inside (allow), position 1
    1. from-inside                allow  [local       vsys:vsys1]
first match: from-inside (allow)
```

A derived zone is **inferred** even from the device's own forwarding table: the
source zone is the zone of the interface a packet arrives on, which a table only
predicts. Against a fetched device, the answer also says whether the device is
**relevant**: whether a route more specific than the default covers either end.

A URL matches custom URL categories; a rule naming a PAN-DB category cannot be
judged from a configuration, so it stays:

```
$ panos-analyst simulate secpolicy 10.0.0.1 10.6.0.1 --file testdata/config/firewall-simulate.xml --url shop.example.com/cart
10.0.0.1 -> 10.6.0.1 tcp shop.example.com/cart
file / vsys1   testdata/config/firewall-simulate.xml
  zones      not evaluated
  relevance  unknown: no stored forwarding table
  fidelity   overmatch: kept rules naming a category the configuration does not define, such as a PAN-DB category: social; not evaluated: zones, service, application
    7. shop                       allow  [local       vsys:vsys1]
    8. social                     deny   [local       vsys:vsys1]
    9. anything                   allow  [local       vsys:vsys1]
first match: shop (allow)
```

A port matches services; `application-default` and predefined services such as
`service-https` stay for the same reason:

```
$ panos-analyst simulate secpolicy 10.0.0.1 10.5.0.1 --file testdata/config/firewall-simulate.xml --port 8443
10.0.0.1 -> 10.5.0.1 tcp/8443
file / vsys1   testdata/config/firewall-simulate.xml
  zones      not evaluated
  relevance  unknown: no stored forwarding table
  fidelity   overmatch: kept rules whose service is application-default, predefined or absent: app-default, predefined-https; not evaluated: zones, application
    4. custom-port                allow  [local       vsys:vsys1]
    5. app-default                allow  [local       vsys:vsys1]
    6. predefined-https           allow  [local       vsys:vsys1]
    9. anything                   allow  [local       vsys:vsys1]
first match: custom-port (allow)
```

An FQDN is resolved with this machine's DNS, and the name matches FQDN objects while
each address matches everything else. Those addresses may differ from what the
firewall resolves, so the stage is inferred. Without an address, only FQDN objects
match, and the answer says it may be missing rules:

```
$ panos-analyst simulate secpolicy 10.0.0.1 www.example.com --file testdata/config/firewall-simulate.xml --no-dns
10.0.0.1 -> www.example.com tcp
file / vsys1   testdata/config/firewall-simulate.xml
  dns        www.example.com -> []
  zones      not evaluated
  relevance  unknown: no stored forwarding table
  fidelity   undermatch: www.example.com resolved to no address, so only FQDN objects of that name were matched; an fqdn object matches this name, but the addresses it resolves to are not in the configuration, so rules reaching those addresses another way are not reported; not evaluated: zones, service, application
    2. to-web-by-name             allow  [local       vsys:vsys1]
    9. anything                   allow  [local       vsys:vsys1]
unresolved: file/vsys1: an fqdn object matches this name, but the addresses it resolves to are not in the configuration, so rules reaching those addresses another way are not reported
unresolved: file/vsys1: www.example.com resolved to no address, so only FQDN objects of that name were matched

first match: to-web-by-name (allow)
```

That exits 3. Negated source and destination are evaluated, and disabled rules
never win. A simulation runs on one device and vsys; estate simulation follows.

## 11a. Read the run log

Every command writes one log file under `~/.local/state/panos-analyst/log` (or
`log_dir`, `PANOS_LOG_DIR`, `--log-dir`). A run that ends with an error or exit 3
prints its path on stderr. `--log-level debug` records every API call, every
finding and, for a simulation, the rules each stage kept; `--verbose` echoes the log
to the terminal. Passwords and API keys never reach it.

```
$ panos-analyst simulate secpolicy 10.1.0.5 10.2.0.5 --file testdata/config/firewall-zones.xml --log-level debug
$ cut -d' ' -f2- ~/.local/state/panos-analyst/log/simulate_secpolicy-*.log | grep -E 'SNAP|derive-zones|first-match|exit'
[INFO] [SNAP] file testdata/config/firewall-zones.xml: PAN-OS 11.2.0 read with the 11.2.0 schema
[INFO] [STEP] secpolicy/derive-zones: inferred, 1 candidates, 8µs - from inside; to dmz (configuration)
[DEBUG] [STEP] secpolicy/derive-zones: 10.1.0.5: inside via ethernet1/1 10.1.0.1/24
[DEBUG] [STEP] secpolicy/derive-zones: 10.2.0.5: dmz via ethernet1/2.20 10.2.0.1/24
[DEBUG] [STEP] secpolicy/derive-zones: left: from-inside
[INFO] [STEP] secpolicy/first-match: overmatch; not evaluated: application, 1 candidates, 0s - from-inside (allow), position 1
[INFO] [RUN] exit 0 after 41ms
```

Each line is `<time> [<LEVEL>] [<TAG>] <message>` (the `cut` drops the time); `grep '\[STEP\]'` finds the
stages, `grep '\[API\]'` the device calls.

## 12. What changed

`snapshot diff` compares two snapshots of each selected device, per vsys and
shared, in the schema's terms. With a week-old and a current snapshot of the lab
firewall:

```
$ panos-analyst snapshot diff
fw01   2026-09-22T08-00-00Z -> 2026-09-28T08-00-00Z
  shared     no changes
  vsys:vsys1
    changed  address              net-home                 198.18.1.0/24 -> 198.18.2.0/24
    removed  address              net-labor                198.18.0.0/15
    changed  security rule        dc-to-home               allow application=ssl destination=net-home source=g-servers -> allow disabled application=ssl destination=net-home source=g-servers
    added    security rule        new-rule                 allow application=dns destination=any source=net-home
  vsys:vsys2 no changes
```

The default compares the snapshot before `latest` with `latest`; `--from` and
`--to` take a time or a date. A rule moving is not a change here.

## 13. Incomplete answers, JSON and exit codes

A configuration from a release this build has no schema for is read with the
nearest one, and every answer says it can miss rules:

```
$ panos-analyst search 198.18.10.100 --file testdata/config/firewall-version-12.2.xml --vsys vsys1 --show objects
search 198.18.10.100 (covers)

file / vsys1   testdata/config/firewall-version-12.2.xml
  object     address              dc01                     198.18.10.100/32
  object     address              net-labor                198.18.0.0/15
unresolved: file/vsys1: the configuration is PAN-OS 12.2.0 but was read with the 11.2.0 schema, the nearest this build carries; a field added or moved between them yields no reference, so this answer can miss rules

1 with results, 0 without, 0 holes
```

That exits 3. The exit codes are:

| Code | Meaning |
| --- | --- |
| 0 | answered completely, including "no results" |
| 1 | error |
| 2 | usage error |
| 3 | answered, with holes (a device or vsys not read) or unresolved entries |

`--output json` prints one envelope for scripts, with `holes`, `unresolved` and
`notes` at the top level so a script cannot miss them:

```
$ panos-analyst search 10.124.0.1 --file testdata/config/firewall-multivsys.xml --vsys vsys1 --show objects --output json
{
  "format": 1,
  "command": "search",
  "input": {
    "direct": false,
    "fields": null,
    "kinds": null,
    "mode": "covers",
    "selection": {
      "file": "testdata/config/firewall-multivsys.xml",
      "vsys": [
        "vsys1"
      ]
    },
    "show": [
      "objects"
    ],
    "term": "10.124.0.1"
  },
  "results": [
    {
      "device": "file",
      "vsys": "vsys1",
      "stage": "object",
      "kind": "address",
      "name": "corp-dc-vienna",
      "via": "10.124.0.1/32",
      "scope": "vsys:vsys1"
    },
    {
      "device": "file",
      "vsys": "vsys1",
      "stage": "object",
      "kind": "address",
      "name": "corp-location-vienna",
      "via": "10.124.0.0/16",
      "scope": "vsys:vsys1"
    }
  ],
  "holes": [],
  "unresolved": [],
  "notes": []
}
```

## 14. The same in Go

```go
cfg, rep, err := config.Load("testdata/config/firewall-multivsys.xml")
if rep.VersionGap != "" {
    log.Print(rep.VersionGap)            // the answer can miss rules
}
idx, err := index.For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
found, err := search.Run(cfg, idx, search.Query{Term: "10.124.0.1"})
for _, f := range found {
    fmt.Println(f.Stage, f.Kind, f.Name, f.Via)
}
```

## 15. Run the tests

```bash
make gate       # tidy, lint, unit tests
make ci         # adds the race detector, coverage floors, a drift gate, a vulnerability scan
go test -bench . -benchmem ./index/ ./config/
```

Against a real device, which CI never does:

```bash
PANOS_LIVE_CONFIG=/tmp/fw-live.xml go test -tags live -v ./resolve/
PANOS_HOST=... PANOS_API_KEY=... scripts/device-probe.sh /tmp/fw-live.xml vsys1
```

Read these tests first. Each one pins a mistake that was actually made.

| Test | What it prevents |
| --- | --- |
| `config.TestWalkContinuesPastANestedConfigElement` | a configuration holds nested `<config>` elements; stopping at the first yielded 1 reference instead of 18 |
| `index.TestNestedChainFromValueToRule` | the value, object, group, group, rule chain |
| `resolve.TestFirewallRuleOrderIncludesTheLocalLayer` | shared pre-rules, then the vsys's own, then shared post-rules |
| `resolve.TestDynamicGroupDiffersInASibling` | the same group resolving differently per vsys |
| `search.TestAnAddressFollowsEveryStage` | a tag and a group sharing a name; a tag field naming the tag does not name the group |
| `estate.TestVsysFilterHoldsForEveryVsys` | asking for the first vsys let every later one through |
| `digest.TestRealSchemaFormCensus` | 5,144 real object references out of 5,898 declarations |
| `codegen.TestRootNameIsReserved` | the schema contains an inline sequence named `config` |
