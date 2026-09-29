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

That builds `bin/proteus` and `bin/panos-demo`.

`panos-demo` runs every analysis feature against one file and narrates what it
does. Add `-v` and it also explains why each answer is what it is:

```bash
./bin/panos-demo -v testdata/config/firewall-multivsys.xml
```

## 2. Fetch a firewall

```bash
./bin/proteus inventory init        # writes ~/.config/proteus/config.yaml, mode 0600
$EDITOR ~/.config/proteus/config.yaml
export PANOS_PASSWORD=...                 # the variable the inventory names
./bin/proteus fetch --all
./bin/proteus snapshot show
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
$ proteus snapshot show --file testdata/config/firewall-multivsys.xml
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
$ proteus search 10.124.0.1 --file testdata/config/firewall-multivsys.xml
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
$ proteus search 10.125.0.1 --file testdata/config/firewall-multivsys.xml
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
$ proteus search 10.1.1.1 --file testdata/config/firewall-nested-groups.xml
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
$ proteus search 10.1.1.1 --direct --show objects,groups --file testdata/config/firewall-nested-groups.xml
search 10.1.1.1 (covers)

file / vsys1   testdata/config/firewall-nested-groups.xml
  object     address              h-1                      10.1.1.1/32
  group      address-group        g-inner                  holds h-1
1 with results, 0 without, 0 holes
```

## 7. Addresses written into a rule

```
$ proteus search 198.18.1.1 --file testdata/config/firewall-literals.xml
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
$ proteus search 10.124.0.0/24 --within --file testdata/config/firewall-multivsys.xml --vsys vsys1
search 10.124.0.0/24 (within)

file / vsys1   testdata/config/firewall-multivsys.xml
  object     address              corp-dc-vienna           10.124.0.1/32
  group      address-group        corp-dc                  holds corp-dc-vienna
  reference  security rule        Corp DC Access           destination -> corp-dc
1 with results, 0 without, 0 holes
```

`--exact` keeps only an equal value:

```
$ proteus search 10.124.0.0/16 --exact --show objects --file testdata/config/firewall-multivsys.xml --vsys vsys1
search 10.124.0.0/16 (exact)

file / vsys1   testdata/config/firewall-multivsys.xml
  object     address              corp-location-vienna     10.124.0.0/16
1 with results, 0 without, 0 holes
```

`--contains` searches names and values as text. PAN-OS caps a custom URL category
name at 31 characters and a member at 255, so a long URL cannot appear in the name
of the category holding it:

```
$ proteus search azureapps --contains --file testdata/config/firewall-urlcat.xml
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
$ proteus search tcp/8006 --file testdata/config/firewall-urlcat.xml
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
$ proteus search demo-category --file testdata/config/firewall-urlprofile.xml
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
`PROTEUS_USERS` at a user snapshot and search follows them:

```
$ PROTEUS_USERS=testdata/users-snapshot.json proteus search 'ACME\carol' --file testdata/config/firewall-users.xml
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

## 10a. Look up a rule or an object

`search` says where a name appears. `lookup` shows the whole element behind it. A
rule prints the way the rule editor lays it out. `--expand` puts each name's value
in parentheses and opens groups as a tree, three levels deep. `NOT` marks a negated
side. A literal address stays bare. A value the configuration does not define shows
`(predefined)`. A list stops at five items; `--full` shows all of them.

```
$ proteus lookup branch-to-dc --file testdata/config/firewall-lookup.xml --expand
file / vsys1   testdata/config/firewall-lookup.xml
security rule  branch-to-dc                 position 2 of 2, local, enabled
  uuid         0b3f5e2a-9d41-4c1e-8f7a-2b6c9d1ec21e
  tags         branch
  description  Branch offices to the shared data-center services

  source       zones      branch-vpn, sdwan
               addresses  branch-networks (group, 4 members)
                            net-vienna (10.20.0.0/16)
                            net-graz (10.21.0.0/16)
                            net-linz (10.22.0.0/16)
                            west-branches (group, 1 member)
                              net-salzburg (10.23.0.0/16)
                          tagged-laptops (dynamic, filter 'laptop' and 'managed')
                          10.99.0.0/24
               users      acme\branch-staff
  destination  zones      datacenter
               addresses  NOT dc-mgmt (group, 2 members)
                                dc-mgmt-net (10.1.250.0/24)
                                oob-net (10.1.251.0/24)
  application  ssl, web-browsing, ms-rdp, ssh, dns, … (+2 more)
  service      svc-web (group, 2 members)
                 service-https (predefined)
                 svc-rdp (tcp/3389)
  url category corp-allowed (custom, 2 entries), business-and-economy (predefined)
  profile      group      strict-inspect
                            as-strict (spyware)
                            url-strict (url-filtering)
                            av-strict (virus)
  action       allow
  log          at session start and end, forwarded to log-to-panorama
  schedule     business-hours

1 with it, 0 without, 0 holes
```

An object card gives its value, its members and the groups holding it. It ends
with the `search` command that shows where the object is used:

```
$ proteus lookup net-vienna --file testdata/config/firewall-lookup.xml
file / vsys1   testdata/config/firewall-lookup.xml
address        net-vienna                   vsys:vsys1
  tags         branch
  description  Vienna office

  value        10.20.0.0/16
  held by      branch-networks
  where it is used: proteus search net-vienna --file testdata/config/firewall-lookup.xml

1 with it, 0 without, 0 holes
```

The kind comes from the name. `dc-mgmt` is a tag and an address group in this
file, so `lookup dc-mgmt` exits 2 and names both; `--kind address-group` picks one.
A name found nowhere exits 1. `--output json` carries the whole card, never cut.

## 11. Simulate a flow

`simulate policy` answers "which rule would this traffic hit". It runs named
stages that narrow the candidate rules, and each stage says how certain it is:
**exact**, **overmatch** (may hold more than the device would match), **inferred**
(from data the device may not be using) or **undermatch** (may be missing matches).
The run's fidelity is the weakest stage's.

Source and destination are an address or an FQDN. `--port`, `--url` and the zones
narrow the flow:

```
$ proteus simulate policy 10.1.0.5 10.2.0.5 --file testdata/config/firewall-zones.xml --from-zone inside --to-zone dmz --port 443
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
$ proteus simulate policy 10.1.0.5 10.2.0.5 --file testdata/config/firewall-zones.xml --why
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
$ proteus simulate policy 10.0.0.1 10.6.0.1 --file testdata/config/firewall-simulate.xml --url shop.example.com/cart
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
$ proteus simulate policy 10.0.0.1 10.5.0.1 --file testdata/config/firewall-simulate.xml --port 8443
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
$ proteus simulate policy 10.0.0.1 www.example.com --file testdata/config/firewall-simulate.xml --no-dns
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

Every command writes one log file under `~/.local/state/proteus/log` (or
`log_dir`, `PROTEUS_LOG_DIR`, `--log-dir`). A run that ends with an error or exit 3
prints its path on stderr. `--log-level debug` records every API call, every
finding and, for a simulation, the rules each stage kept; `--verbose` echoes the log
to the terminal. Passwords and API keys never reach it.

```
$ proteus simulate policy 10.1.0.5 10.2.0.5 --file testdata/config/firewall-zones.xml --log-level debug
$ cut -d' ' -f2- ~/.local/state/proteus/log/simulate_policy-*.log | grep -E 'SNAP|derive-zones|first-match|exit'
[INFO] [SNAP] file testdata/config/firewall-zones.xml: PAN-OS 11.2.0 read with the 11.2.0 schema
[INFO] [STEP] policy/derive-zones: inferred, 1 candidates, 8µs - from inside; to dmz (configuration)
[DEBUG] [STEP] policy/derive-zones: 10.1.0.5: inside via ethernet1/1 10.1.0.1/24
[DEBUG] [STEP] policy/derive-zones: 10.2.0.5: dmz via ethernet1/2.20 10.2.0.1/24
[DEBUG] [STEP] policy/derive-zones: left: from-inside
[INFO] [STEP] policy/first-match: overmatch; not evaluated: application, 1 candidates, 0s - from-inside (allow), position 1
[INFO] [RUN] exit 0 after 41ms
```

Each line is `<time> [<LEVEL>] [<TAG>] <message>` (the `cut` drops the time); `grep '\[STEP\]'` finds the
stages, `grep '\[API\]'` the device calls.

## 11b. Trace a path across firewalls

`simulate routing` follows a packet through the fetched firewalls: the firewall the
source is connected to, then each firewall owning the next hop, until the packet is
delivered or leaves the inventory. Each box leads with the zone pair, which is
where a security rule goes. The lab below is fw01 and fw02, joined by
198.19.0.0/24, from their stored interface state and forwarding tables:

```
$ proteus simulate routing 198.18.10.5 8.8.8.8
simulate routing 198.18.10.5 -> 8.8.8.8            fidelity: undermatch

  198.18.10.5
     │ 198.18.10.0/24
  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   server -> transport                         │
  │  in      ethernet1/2   198.18.10.1/24                │
  │  out     ethernet1/1   198.19.0.254/24               │
  │  route   0.0.0.0/0 via 198.19.0.1   static           │
  └──┬───────────────────────────────────────────────────┘
     │ 198.19.0.0/24   198.19.0.254 -> 198.19.0.1
  ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   labor -> wan                                │
  │  in      vlan.32       198.19.0.1/24                 │
  │  out     ethernet1/1   192.168.0.138/24              │
  │  route   0.0.0.0/0 via 192.168.0.1   static          │
  └──┬───────────────────────────────────────────────────┘
     │ 192.168.0.0/24
  192.168.0.1   leaves the estate (not in the inventory)

firewalls on the path: fw01 (server -> transport), fw02 (labor -> wan)
may be incomplete: the path leaves the estate at 192.168.0.1
```

`may be incomplete` names what the answer cannot see: here, the network behind
192.168.0.1, which no inventory firewall owns. The other direction is complete:

```
$ proteus simulate routing 198.18.1.10 198.18.10.100
simulate routing 198.18.1.10 -> 198.18.10.100            fidelity: exact

  198.18.1.10
     │ 198.18.1.0/24
  ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 2m ────────┐
  │  zones   home -> labor                               │
  │  in      vlan.1        198.18.1.1/24                 │
  │  out     vlan.32       198.19.0.1/24                 │
  │  route   198.18.0.0/15 via 198.19.0.254   static     │
  └──┬───────────────────────────────────────────────────┘
     │ 198.19.0.0/24   198.19.0.1 -> 198.19.0.254
  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 2m ────────┐
  │  zones   transport -> server                         │
  │  in      ethernet1/1   198.19.0.254/24               │
  │  out     ethernet1/2   198.18.10.1/24                │
  │  route   198.18.10.0/24  connected                   │
  └──┬───────────────────────────────────────────────────┘
     │ 198.18.10.0/24
  198.18.10.100   delivered

firewalls on the path: fw02 (home -> labor), fw01 (transport -> server)
```

- A source connected on two firewalls is a choice only you can make:
  `proteus: 198.18.100.50 could enter at several firewalls; name one with --device: fw01 ethernet1/5, fw02 vlan.100`
- `simulate routing <destination> --device fw01` starts on one firewall;
  `--router` picks its logical router when it has several.
- `--rib` lists the routing table's other routes to the destination at each
  firewall, and marks the one in use `(active)`.
- A PBF or NAT rule that could take the packet is named in its box (`pbf`, `nat`),
  and the path still follows the forwarding table. ECMP follows the lowest next
  hop and names the others (`ecmp`).
- `--output json` gives each hop's `flow`: device, vsys, zones, source and
  destination, the input `simulate policy` takes.

## 11c. Simulate NAT

`simulate nat` answers on one firewall which NAT rule a packet hits, what the
packet looks like after it, and what security policy then matches: the addresses
and port before NAT, the zones after it. The examples below use fw01's NAT test
rules (`testdata/config/firewall-nat.xml`), each checked against fw01's own
`test nat-policy-match`. A port forward:

```
$ proteus simulate nat 198.19.0.1 198.18.250.10 --device fw01 --port 8443
simulate nat 198.19.0.1 -> 198.18.250.10 tcp/8443 on fw01            fidelity: exact

  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   transport -> server                         │
  │  in      ethernet1/1   198.19.0.254/24               │
  │  out     ethernet1/2   198.18.10.1/24                │
  │  route   0.0.0.0/0 via 198.19.0.1   (pre-NAT)        │
  │  route   198.18.10.0/24  connected   (post-NAT)      │
  │  rule    t-dnat-port, matched transport -> transport │
  │  dest    198.18.250.10:8443 -> 198.18.10.100:443     │
  └──────────────────────────────────────────────────────┘

  before   198.19.0.1 -> 198.18.250.10:8443  tcp
  after    198.19.0.1 -> 198.18.10.100:443  tcp

security policy matches: 198.19.0.1 -> 198.18.250.10, port 8443, zones transport -> server
```

The NAT rule matched on the zone of the **pre-NAT** route (transport), and the
translated destination is routed into server, which is the zone the security rule
needs. A source pool:

```
$ proteus simulate nat 198.18.11.5 198.18.250.200 --device fw01 --port 443
simulate nat 198.18.11.5 -> 198.18.250.200 tcp/443 on fw01            fidelity: exact

  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 2m ───────────────────────────────────┐
  │  zones   client -> transport                                                    │
  │  in      ethernet1/3   198.18.11.1/24                                           │
  │  out     ethernet1/1   198.19.0.254/24                                          │
  │  route   0.0.0.0/0 via 198.19.0.1                                               │
  │  rule    t-dip-pool, matched client -> transport                                │
  │  source  198.18.11.5 -> 198.18.250.64/29, port unchanged; fallback 198.19.0.254 │
  └─────────────────────────────────────────────────────────────────────────────────┘

  before   198.18.11.5 -> 198.18.250.200:443  tcp
  after    198.18.250.64 -> 198.18.250.200:443  tcp

security policy matches: 198.18.11.5 -> 198.18.250.200, port 443, zones client -> transport
```

- `--why` lists every rule above the match and the field that excluded it
  (`not t-no-nat   from zone client ≠ transport`), then every stage.
- A rule the answer cannot decide is a `doubt` row with the reason, for example a
  rule naming a service when no `--port` is given.
- The ingress is where the source is connected, else where its return route leaves
  (inferred); `--from-zone` or `--from-interface` sets it.
- `simulate policy` uses the post-NAT zone: for the port forward above it finds
  `zones  from transport, to server (forwarding table, after NAT rule t-dnat-port)`
  and `first match: t-allow-8443`, the rule fw01 applied to real traffic.
- `simulate routing` applies NAT on every firewall of a path, and later firewalls
  see the translated packet.

## 12. What changed

`snapshot diff` compares two snapshots of each selected device, per vsys and
shared, in the schema's terms. With a week-old and a current snapshot of the lab
firewall:

```
$ proteus snapshot diff
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
$ proteus search 198.18.10.100 --file testdata/config/firewall-version-12.2.xml --vsys vsys1 --show objects
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
$ proteus search 10.124.0.1 --file testdata/config/firewall-multivsys.xml --vsys vsys1 --show objects --output json
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
go test -bench . -benchmem ./internal/index/ ./internal/config/
```

Against a real device, which CI never does:

```bash
PROTEUS_LIVE_CONFIG=/tmp/fw-live.xml go test -tags live -v ./internal/resolve/
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
