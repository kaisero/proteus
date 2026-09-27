# Quickstart

Try the library without writing Go. Every command below was run against the lab
Panorama at 198.18.100.10 and the committed fixtures, and the output shown is the
real output.

## Build

```bash
cd ~/git/go-panos-schema
make build-local                      # the generator
go build -o bin/panos-explore ./cmd/panos-explore
go build -o bin/panos-demo    ./cmd/panos-demo
```

## The fastest way to see everything

`panos-demo` runs every feature against one file and narrates what it does. With
`-v` it also explains why each answer is what it is.

```bash
./bin/panos-demo -v testdata/config/firewall-lab.xml
./bin/panos-demo -v /tmp/pano-live.xml
./bin/panos-demo -v -probe 198.18.1.77 /tmp/pano-live.xml
```

Twelve sections: loading, what the schema says, the scopes, the policy targets,
the effective policy, visible objects and shadowing, static and dynamic groups,
building the index, a reverse lookup, where a name is used, which rule wins, and
what the answers do not cover. It picks a probe address from the configuration
itself, including from a rule literal when there are no objects.

The rest of this guide takes the same ground one command at a time.

## Get a configuration

Either export one from a device:

```bash
KEY=$(grep PANOS_API_KEY ~/git/panos-mcp-server/.env.panorama | cut -d= -f2-)
curl -sk "https://198.18.100.10/api/?type=export&category=configuration&key=$KEY" \
  -o /tmp/pano-live.xml
```

Or use a committed fixture. Both shapes load: the bare `<config>` from an export,
and the `<response><result>` wrapper the XML API returns.

| Fixture | What it exercises |
| --- | --- |
| `testdata/config/panorama-lab.xml` | two hierarchies, one serial in two vsys, dynamic groups |
| `testdata/config/panorama-merge.xml` | three levels, every rule layer populated |
| `testdata/config/panorama-nested-groups.xml` | three levels of group nesting |
| `testdata/config/panorama-shadow.xml` | a child device group shadowing a parent's object |
| `testdata/config/firewall-lab.xml` | a firewall rather than Panorama |

---

## 1. What is this configuration

```bash
./bin/panos-explore info /tmp/pano-live.xml
```

```
loaded /tmp/pano-live.xml in 68.27ms: PAN-OS 11.2.0 (11.2.7), panorama

device-group tree
    Default
    vsys01
      at-ktn

firewalls (1), keyed by serial and vsys
  007900000000004 / vsys3    -> at-ktn    stack s_vsys01   2 effective rules
```

The version and platform come from the file itself. The tree comes from
`parent-dg` under `/config/readonly`, which is the only place PAN-OS records it.

The first load in a process takes about 65 ms because it decodes the schema;
every load after that takes **0.12 ms**.

## 2. What policy does each device group get

```bash
./bin/panos-explore groups /tmp/pano-live.xml
```

```
  Default (4 rules)
     1. [shared-pre  shared      ] Shared-Pre-Rule    src=[198.18.1.1/32] dst=[198.18.2.1/32]
     2. [dg-pre      dg:Default  ] Default-Pre-Rule   src=[198.18.1.1/32] dst=[198.18.2.1/32]
     3. [dg-pre      dg:Default  ] Default-URL-Rule   src=[198.18.1.0/24] dst=[any]
     4. [shared-post shared      ] Shared-Post-Rule   src=[198.18.1.1/32] dst=[198.18.2.1/32]

  at-ktn (2 rules)
     1. [shared-pre  shared      ] Shared-Pre-Rule    src=[198.18.1.1/32] dst=[198.18.2.1/32]
     2. [shared-post shared      ] Shared-Post-Rule   src=[198.18.1.1/32] dst=[198.18.2.1/32]
```

Two things to notice. The shared layers wrap the device group's own rules, in the
order the firewall evaluates them. And `Default`'s two rules do **not** appear in
`at-ktn`, because `Default` is a sibling root, not an ancestor.

To see pre-rules and post-rules run in opposite directions across three levels,
use the merge fixture:

```bash
./bin/panos-explore groups testdata/config/panorama-merge.xml
```

`leaf` gives `shared-pre → top-pre → middle-pre → leaf-pre → leaf-post →
middle-post → top-post → shared-post`.

## 3. What does one firewall get

```bash
./bin/panos-explore target /tmp/pano-live.xml 007900000000004 vsys3
```

```
007900000000004 / vsys3
  device group   at-ktn
  template stack s_vsys01
  inherits from  shared -> dg:vsys01 -> dg:at-ktn
```

The key is **serial and vsys**, never serial alone. Try this on the lab fixture,
where one firewall has two vsys in two different device groups:

```bash
./bin/panos-explore target testdata/config/panorama-lab.xml 007900000000004 vsys3   # at-ktn
./bin/panos-explore target testdata/config/panorama-lab.xml 007900000000004 vsys2   # at-ooe
```

Object shadowing shows up here too:

```bash
./bin/panos-explore target testdata/config/panorama-shadow.xml 001122334455 vsys1
```

```
visible address objects (2)
  web-server    10.9.9.1    dg:leaf   (shadows the definition in dg:top)
  only-in-top   10.0.0.9    dg:top
```

## 4. Reverse lookup: from a value to the rules

This is the nested question, and it works to any depth.

```bash
./bin/panos-explore lookup testdata/config/panorama-nested-groups.xml dg:dg1 10.1.1.1
```

```
1. objects whose value covers 10.1.1.1
     h-1                        10.1.1.1/32        dg:dg1

2. groups holding them, transitively
     h-1                        in [g-inner g-middle g-outer]

3. rules naming any of them
      1. allow-outer              as source      [dg-pre]
```

The fixture nests `h-1 → g-inner → g-middle → g-outer`, and the rule names only
`g-outer`. All three steps compose, so an address finds a rule three groups away.
There is no depth limit, and a cycle in the group definitions is tolerated rather
than hanging.

It also works from a prefix, which finds overlapping objects rather than covering
ones:

```bash
./bin/panos-explore lookup testdata/config/panorama-nested-groups.xml dg:dg1 10.1.0.0/16
```

## 5. Where is this name used

```bash
./bin/panos-explore whereused /tmp/pano-live.xml dg:Default '198.18.1.1/32'
```

```
  shared      source   /config/shared/post-rulebase/security/rules/Shared-Post-Rule
                       could be: [region address address-group external-list ip-block-list-v2]
  dg:Default  source   /config/devices/localhost.localdomain/device-group/Default/pre-rulebase/…
```

Two details worth knowing. The path names the **instance**, not the schema
location, so two device groups holding an object of the same name stay
distinguishable. And `could be` lists the object kinds the schema permits for that
field, because 919 of 2,420 reference fields allow more than one and the worst
allows 31 — the schema cannot tell you which one a given target actually is.

On the lab fixture, try a group and an object:

```bash
./bin/panos-explore whereused testdata/config/panorama-lab.xml dg:host_1_directory corp-location
./bin/panos-explore whereused testdata/config/panorama-nested-groups.xml dg:dg1 g-outer
```

## 6. Which rule wins

```bash
./bin/panos-explore simulate /tmp/pano-live.xml dg:Default '198.18.1.1/32' '198.18.2.1/32'
```

```
candidates in evaluation order (3)
   1. Shared-Pre-Rule    allow  [shared-pre  shared]
   2. Default-Pre-Rule   allow  [dg-pre      dg:Default]
   4. Shared-Post-Rule   deny   [shared-post shared]

first match: Shared-Pre-Rule (allow)
```

Rule position is the bit index in a compressed bitmap, and PAN-OS takes the first
match, so the answer is the lowest set bit. Disabled rules are masked out.

## 7. Scope decides the answer

The point the whole design turns on. One shared dynamic address group, three device
groups, three different answers:

```bash
for dg in host_1_directory corp-graz at-ktn; do
  ./bin/panos-explore group testdata/config/panorama-lab.xml dg:$dg corp-location
done
```

```
corp-location in dg:host_1_directory
  dynamic, filter 'corp-location'
  members matched by tag: [corp-location-vienna]

corp-location in dg:corp-graz
  members matched by tag: [corp-location-graz]

corp-location in dg:at-ktn
  members matched by tag: []
```

The group, the filter and the schema are identical in all three. Only the visible
scope differs. Resolve it once globally and every answer about a rule using it is
wrong rather than merely incomplete.

The same holds for plain objects. Each device group sees its own and its
ancestors', never a sibling's:

```bash
./bin/panos-explore lookup testdata/config/panorama-lab.xml dg:host_1_directory 10.124.0.1
./bin/panos-explore lookup testdata/config/panorama-lab.xml dg:corp-graz       10.125.0.1
```

Asking in the wrong scope returns nothing, which is the honest answer.

---

## What does not work yet

Two gaps this guide originally documented are now closed, and each has tests:

- **An address reaches a rule that names a literal CIDR.** Your lab needs this: its
  rules hold literal addresses and no named objects.

  ```bash
  ./bin/panos-explore lookup /tmp/pano-live.xml dg:Default 198.18.1.1
  #   3. rules naming any of them, or naming a literal that covers the address
  #        1. Shared-Pre-Rule    as source  [shared-pre]
  #        2. Default-Pre-Rule   as source  [dg-pre]
  #        3. Default-URL-Rule   as source  [dg-pre]
  #        4. Shared-Post-Rule   as source  [shared-post]

  ./bin/panos-explore lookup /tmp/pano-live.xml dg:Default 198.18.1.77
  #        3. Default-URL-Rule   as source  [dg-pre]     <- only the /24 covers it
  ```

- **A dynamic group extends the chain.** An address now finds the object, the
  dynamic group holding that object by tag, and the rule naming the group.

  ```bash
  ./bin/panos-explore lookup testdata/config/panorama-lab.xml dg:host_1_directory 10.124.0.1
  #   2. groups holding them, transitively
  #        corp-location-vienna   in [corp-location]
  #   3. rules ...
  #        1. Corp DC Access      as source      [dg-post]
  ```

  Filters are parsed properly, not just single tags: `and`, `or`, `not` and
  parentheses, with `and` binding tighter than `or`. A filter this build cannot
  read contributes no members and is reported rather than guessed at — `lookup`
  prints a note, and `index.UnparsedFilters()` lists them.

Also not covered, with every affected answer saying so:

- **Application and service** are not evaluated in `simulate`. It matches
  addresses only, so treat the result as candidates rather than a verdict.
- **Rules using `any`** are excluded, because `any` is a keyword rather than an
  object. A real simulator has to add them back deliberately.
- **Template variables.** 2,482 of the schema's reference declarations point at
  them, and resolving one needs the template-stack chain.
- **Group members registered at runtime** by User-ID or VM monitoring. They are
  not in a configuration file at all.
- **NAT** rules are read but translated-address fields are not resolved.

## Checked against the firewall itself

The device is the authority on which rule wins. `test security-policy-match` asks
it directly, so the library's answer can be compared with the real one.

```bash
KEY=$(grep PANOS_API_KEY ~/git/panos-mcp-server/.env | cut -d= -f2-)
curl -sk "https://fw01.example.net/api/?type=op&key=$KEY" --data-urlencode \
  "cmd=<test><security-policy-match><source>198.18.0.5</source><destination>198.18.1.5</destination><protocol>6</protocol><destination-port>443</destination-port><application>ssl</application></security-policy-match></test>"

./bin/panos-explore simulate /tmp/fw-live.xml vsys:vsys1 198.18.0.5 198.18.1.5
```

Seven cases against `fw01.example.net`, a PA-VM on 11.2.5 with nine local rules:

| source → destination | firewall says | library says | agree |
| --- | --- | --- | --- |
| 198.18.0.5 → 198.18.1.5 | ztnac-to-lab | ztnac-to-lab | yes |
| 198.18.100.115 → 198.18.1.1 | certbot-to-homefw | certbot-to-homefw | yes |
| 198.18.10.100 → 198.18.100.250 | ztnac-to-lab | ztnac-to-lab | yes |
| 100.64.0.5 → 198.18.1.5 | ztnac-to-lab | ztnac-to-lab | yes |
| 203.0.113.9 → 198.18.1.5 | ztnac-to-lab | ztnac-to-lab | yes |
| 198.18.0.5 → 10.10.0.5 | identity-redistribution | identity-redistribution | yes |
| 198.18.10.100 → 198.18.10.100 | **no match** | ztnac-to-lab | no |

Six of seven agree exactly. The seventh is the documented limit rather than a
defect: source and destination are the same host, so the device declines on
**zone** grounds, and zones are not evaluated here. The library over-matches,
which is the safe direction for a candidate set, but it is a candidate set.

### Where the line sits

Rule matching is not in the library. The library answers one question per side of
a match — *which rules could this value reach* — and the caller decides what that
means:

```go
src := idx.CandidatesFor(index.Source, srcAddr)       // or CandidatesForName
dst := idx.CandidatesFor(index.Destination, dstAddr)

cand := roaring.And(src, dst)
cand.AndNot(idx.Disabled())
first := idx.Rules()[cand.Minimum()]                  // your verdict, not the library's
```

`CandidatesFor` unions the four paths by which a rule field can reach an address:
an object covering it, a group holding that object, a literal in the field, and a
field of `any`. Those four are index knowledge. Whether the winner is really the
winner — application, service, zones — is the simulator's business.

This comparison also found a real defect. Address-only matching originally
excluded rules whose field is `any`, on the grounds that `any` is a keyword rather
than an object. That is right for the reference graph and wrong for a first-match
answer: `ztnac-to-lab` is rule 3 with `source any`, so excluding it returned rule 8
instead. An any-rule is usually earlier in a rulebase than a specific one, so the
omission did not merely lose candidates, it named the wrong winner.

## Running the tests yourself

```bash
make gate       # tidy, lint, unit tests
make ci         # adds race detector, coverage floors, drift gate, vulnerability scan
go test -bench . -benchmem ./index/ ./config/
```

Against a real device, which CI never does:

```bash
PANOS_LIVE_CONFIG=/tmp/pano-live.xml go test -tags live -v ./resolve/
```

The interesting tests to read, because each pins a mistake that was actually made:

| Test | What it prevents |
| --- | --- |
| `config.TestWalkContinuesPastANestedConfigElement` | a template embeds a whole config; stopping at the first `</config>` yielded 1 reference instead of 18 |
| `index.TestNestedChainFromValueToRule` | the value → object → group → group → rule chain |
| `resolve.TestMergedRuleOrder` | pre-rules top-down, post-rules bottom-up |
| `resolve.TestDynamicGroupDiffersInASibling` | the same group resolving differently per device group |
| `digest.TestRealSchemaFormCensus` | 8,234 real references out of 13,120 declarations |
| `codegen.TestRootNameIsReserved` | the schema contains an inline sequence named `config` |
