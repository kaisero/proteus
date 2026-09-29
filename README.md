# panos-analyst

`panos-analyst` is a read-only Go library. It loads a PAN-OS firewall
configuration file and answers questions about it. It never writes a
configuration. `panos-analyst fetch` reads devices with show commands and a
configuration export, and the analysis never contacts a device.

The library exists for tools and AI agents. They ask two kinds of question.
*Does an object with this value exist?* And *which rules can this value reach?*
The library answers both, per scope, and reports what it could not evaluate.

The object model is generated from the schema PAN-OS itself ships.

## What it does

- **Fetches what it analyses** — `panos-analyst fetch` logs in to each firewall in
  an inventory and stores its configuration and operational state as a timestamped
  snapshot. Every question then runs against the devices' latest snapshots.
- **Reads what a firewall actually evaluates** — the library keys each policy by
  device **and** vsys, and orders the rule layers the way the firewall evaluates
  them: pushed shared pre-rules, the vsys's own rules, pushed shared post-rules.
- **Answers from a value, not only from a name** — give it an address, a prefix,
  a URL, a port, a user, a zone or an application name. It returns the rules that
  value can reach, in evaluation order.
- **Matches each rule field by the value spaces the schema allows there** — a
  security rule's `source` accepts an address, an address group, a region, an
  external list and an IP block list. That is five value spaces, not one. The
  wiring comes from the schema, not from hand-written code.
- **Resolves per scope** — a scope is `shared` or a vsys, and a vsys inherits
  shared. One shared dynamic address group resolves to different members in each
  vsys. A global answer is wrong, not merely incomplete.
- **Reports incompleteness** — every lookup returns a report. A non-empty
  `Unresolved` list means the answer is missing matches, and the report says why.
- **Takes facts a configuration does not hold** — a user-to-group mapping comes
  from User-ID, not from a file. The library defines a snapshot format and reads
  it. The caller fetches the data.
- **Builds each index once** — an index is immutable and cached per file and
  scope. Concurrent readers need no lock.

## A first look

```text
$ ./bin/panos-analyst search superlong.example.azureapps.microsoft.com \
      --file testdata/config/firewall-urlcat.xml
search superlong.example.azureapps.microsoft.com (matches)

file / vsys1   testdata/config/firewall-urlcat.xml
  object     custom-url-category  custom-azuresite-group   superlong.example.azureapps.microsoft.com
  reference  security rule        URL-Example              category -> custom-azuresite-group
1 with results, 0 without, 0 holes
```

See two things here. The answer names the object that matched and the value that
matched it, so a reader can check the reasoning. And it follows the object to the
rule that names it. Without `--file`, the same command answers for every device in
the inventory, one block per device and vsys.

Which rules a value can reach, including the rules whose field is `any`, is a lookup
in Go:

```go
cfg, _, err := config.Load("testdata/config/firewall-urlcat.xml")
sc, err := config.ParseScope("vsys:vsys1")
idx, err := index.For(cfg, sc)

rules, rep := idx.Candidates(index.Category, "superlong.example.azureapps.microsoft.com")
fmt.Println(rules.GetCardinality(), "rules")
for _, h := range rep.Hits {
    fmt.Printf("%s (%s) via %s\n", h.Name, h.Kind, h.Via)
}
```

[QUICKSTART.md](QUICKSTART.md) takes one question at a time.

## How it works

Three packages. The dependency order is one-way: `config` <- `resolve` <-
`index`.

1. **`config`** loads the file. It parses the XML into an element tree and holds
   the schema digest for the version the file declares. `config.Load(path)`
   returns the configuration and a report of anything it could not type.
2. **`resolve`** holds PAN-OS semantics: one policy target per vsys, scoped
   object visibility with shadowing, rule order, group membership and tag filters, URL pattern parsing, and zones,
   interfaces and routes.
3. **`index`** holds the lookup structures. `index.For(cfg, scope)` returns an
   immutable, cached `*Index`.

### Four paths reach a value

A rule field reaches a value by four paths. A caller that forgets one gets a
wrong answer, not an incomplete one.

1. The field names an object whose value matches.
2. The field names a group holding such an object, at any depth. Static
   membership and a tag filter both count.
3. The field holds a matching value directly, with no object involved.
4. The field is `any`, which matches everything.

`Candidates` unions all four. The fourth path is the one that bites. Checked
against a live firewall: for 198.18.0.5 to 198.18.1.5 the device reports rule 3,
whose source is `any`. Matching on objects alone reports rule 8.

### Reachability, not a verdict

The library says which rules a value **can** reach. It does not say which rule
wins. Intersecting the two sides of a match, dropping disabled rules and deciding
what the first match means belongs to the caller.

```go
src := idx.CandidatesFor(index.Source, srcAddr)
dst := idx.CandidatesFor(index.Destination, dstAddr)

cand := roaring.And(src, dst)
cand.AndNot(idx.Disabled())
first := idx.Rules()[cand.Minimum()]   // the caller's verdict, not the library's
```

[ARCHITECTURE.md](ARCHITECTURE.md) explains where this line sits and why.

### Search is not matching

`SearchValues` performs a case-insensitive substring search over object values.
Matching is token-based and never a substring test. The pattern
`wildcard-example.com` does **not** cover the URL
`wildcard-example.com.evil.net`, because a host is read from the right.

Search exists because a value can be longer than the name holding it. PAN-OS caps
a custom URL category name at 31 characters and one of its members at 255. So
searching `azureapps` finds a category holding a 41-character URL that appears in
no name. Other kinds are wider: an address or service name may be 63 characters
and a tag 127.

### Profile paths are not matches

`ProfileUses` follows the path from a rule to a URL category: profile setting,
profile group or named profile, url-filtering profile, then the action list
holding the category. It reports which list — `block`, `alert`, `allow`,
`continue` or `override`. It gives no allow-or-block verdict, because that
depends on the response and the session.

This matters because PAN-OS deployments normally apply URL policy this way. On a
lab firewall every rule has `category any`, and all URL policy runs through
profiles. QUICKSTART.md section 6 shows the output.

## Why generated, not hand-written

Every PAN-OS appliance ships its own configuration schema. Generating the model
from it gives **2,289** object types against pango's **117**. It also removes a
class of defect that a hand-maintained specification cannot avoid.

A concrete example. pango types a device group's `vsys` assignment as a member
list, but Panorama writes an entry list. pango returns an empty value and
preserves nothing, so a round trip deletes the assignment. The schema states the
shape without ambiguity, so a generator cannot get it wrong.

The schema also carries the reference graph. The firewall schema declares 5,898
`memberof` targets, and 5,144 of them are real object references saying which
objects a field may point at. `internal/digest.TestRealSchemaFormCensus` pins the
census. The schema also carries name length limits, defaults, enum values and
help strings.

## Getting Started

### Prerequisites

- Go, at the version in [`go.mod`](go.mod). The code is pure Go.
- A PAN-OS 11.2 configuration file, or one of the fixtures in `testdata/config/`.

### Build

```bash
make tools-bin                 # bin/panos-analyst and bin/panos-demo
make build-local               # the generator, bin/panos-schemagen
```

`make build` cross-compiles the generator for linux/amd64. It builds neither
explorer command. Use `make tools-bin` for those.

The schema digests are committed in two places. `schemadigest/` holds the
originals, and `config/schemadigest/` holds the copy that `go:embed` reads,
because an embed directive cannot reach outside its own package. `make
config/schemadigest` refreshes the copy after you regenerate a digest, and
`make digest-check` fails the build if the two differ.

### Use the library

The repository has no remote yet. Add it with a `replace` directive:

```
require github.com/okaiser/panos-analyst v0.0.0
replace github.com/okaiser/panos-analyst => ../go-panos-schema
```

## Commands

One binary, `panos-analyst`. Questions are verbs; housekeeping is grouped by noun.

| Command and arguments | What it does |
| --- | --- |
| `fetch <device>… \| --label k=v \| --all` | Log in, fetch config, system info, interfaces, FIB, RIB and HA state, store a snapshot; up to eight devices at once; a passive HA member is read from its active peer |
| `inventory init` | Write an inventory template, mode 0600, with TLS verification off and how to turn it on |
| `snapshot list <device>` | A device's snapshots, newest first; `*` marks latest |
| `snapshot show` | Per device and vsys: snapshot, age, version, rule count, fetched documents |
| `snapshot diff [--from] [--to]` | Objects and rules added, removed or changed between two snapshots |
| `search <term>` | Every place a value or name appears: objects by value and by name, groups, references, literals |
| `lookup <name>` | The whole rule or object behind a name: a rule as the rule editor shows it, an object with its value, members and groups; `--expand` adds values and group trees, `--full` shows every list item |
| `simulate secpolicy <src> <dst>` | The rule one flow would hit on one device: source and destination by address or FQDN, `--port`, `--url`, zones given or derived; every stage says how certain it is, and `--why` shows them |
| `simulate routing <src> <dst>` | The firewalls a packet crosses, one box per firewall with its zones, interfaces and route; `<dst> --device <name>` starts on one device, `--rib` adds the routing table's other routes, and the answer names ECMP, PBF, NAT and a path leaving the inventory |

Every question takes the same selectors: `--device`, `--label k=v`, `--vsys`,
`--at <time>` for older snapshots, `--fresh` to fetch first, or `--file <config.xml>`
to read one file with no inventory. `search` takes `--exact`, `--within` or
`--contains`, and `--kind`, `--field`, `--show` and `--direct` to narrow it. `lookup` takes `--kind` when one name has several kinds.
`simulate routing` takes only `--device`, `--router` and `--at`: a path may cross any
firewall of the inventory.

`--output json` prints one versioned envelope. Exit codes: 0 complete, 1 error,
2 usage, 3 answered with holes or unresolved entries.

Settings come from, in rising precedence, the defaults, the inventory's
`defaults:`, `PANOS_*` variables and flags: the inventory (`PANOS_CONFIG`,
`--config`), the store (`store:`, `PANOS_STORE`, `--store`), the snapshot age limit
(`max_snapshot_age:`, `PANOS_MAX_SNAPSHOT_AGE`, `--max-age`) and the output
(`output:`, `PANOS_OUTPUT`, `--output`). `PANOS_USERS` points at a user snapshot.

Every run writes a log you can read back when an answer needs explaining:
`log_level:` (`PANOS_LOG_LEVEL`, `--log-level`: error, warn, info, debug),
`log_dir:` (`PANOS_LOG_DIR`, `--log-dir`, default `~/.local/state/panos-analyst/log`)
and `log_keep:`. `--verbose` echoes it to the terminal. Passwords and API keys never
reach it.

`panos-demo <config.xml> [-v]` runs every library feature against one file in
twelve sections and narrates what it does.

## Known limits

The library reports each of these rather than hiding it.

- **Only PAN-OS 11.2 digests ship.** Another version loads with the nearest digest,
  and every answer carries a warning naming both versions.
- **Panorama configurations are refused.** Read each firewall's own export instead.
- **NAT translated addresses are not modelled.** The library reads the rulebase.
- **Predefined content is unknown.** Regions, predefined applications and PAN-DB
  categories live in the content database a firewall downloads.
- **External dynamic list contents are fetched at runtime**, so the file does not
  hold them.
- **`simulate` does not evaluate application or service.** It evaluates zones when
  you give them.
- **Zones are an input, not an output, for simulation.** The device's own
  `test security-policy-match` takes zones as arguments. Measured against it on a
  lab firewall, with probes built from each rule's own zones and ports:
  `simulate` agreed on 3 of 7 without zones, and on 7 of 7 with them. The library
  can also infer a zone from an address, and it reports every limit of that
  inference.
- **`simulate routing` follows the forwarding table, IPv4 only.** It names, but
  does not follow, policy-based forwarding and NAT; with ECMP it follows the lowest
  next hop and names the others. A path ends where it leaves the inventory,
  including into a tunnel. Firewalls in virtual wire or Layer 2 are not seen on a
  path; the answer names them.
- **URL matching rules are documentation-derived.** A firewall's validator
  verifies the syntax rules. It cannot verify the matching rules, because
  `test url` reports PAN-DB categories only and never names a custom category.
- **A large configuration costs memory.** The parsed element tree peaks near ten
  times the file size.

## Project structure

```
go-panos-schema/
├── cmd/
│   ├── panos-analyst/     # fetch, snapshots, search, lookup, simulate: the CLI
│   ├── panos-demo/        # a narrated tour of every feature
│   └── panos-schemagen/   # digest a vendor schema, generate the Go model
├── config/                # Load, version detection, element tree, scopes
│   └── v11_2/firewall/    # generated model, per PAN-OS minor
├── resolve/               # PAN-OS semantics: targets per vsys, rule order,
│                          #   objects, groups, tag filters, URL patterns, zones
├── index/                 # lookup structures, value-space resolvers, reports
├── inventory/             # devices, credentials and TLS choice, from YAML
├── fetch/                 # read-only XML API client and the document list
├── store/                 # timestamped on-disk snapshots, latest, retention
├── estate/                # selectors and a time to targets; the simulation registry
├── simulate/              # the staged simulation framework and its fidelity
│   ├── securitypolicy/    # the first simulation: which rule a flow would hit
│   └── routing/           # which firewalls a packet crosses, hop by hop
├── runlog/                # the run log: levels, redaction, rotation
├── search/                # every place a value or name appears, in one scope
├── card/                  # the whole rule or object behind a name, for lookup
├── drift/                 # what changed between two configurations of a scope
├── schema/                # public: query the schema itself (design not settled)
├── internal/schema/       # parse the PAN-OS schema grammar
├── internal/digest/       # the committed digest format
├── internal/codegen/      # emit Go from a digest
├── internal/archtest/     # the import-direction check (R12)
├── internal/fakepanos/    # a fake PAN-OS XML API for tests
├── schemadigest/          # committed firewall digests, roughly 0.2 MB each
├── testdata/config/       # configuration fixtures, one per behaviour
├── ARCHITECTURE.md        # the reasoning, and where the library's line sits
├── AGENTS.md              # the mandatory rules
└── Makefile               # build and checks
```

## Development

```bash
make tools     # install pinned dev tools
make hooks     # enable the pre-commit gate
make gate      # tidy + lint + tests (what the hook runs)
make ci        # everything CI runs
make generate  # regenerate the model from the committed digests
make help      # list every target
```

### Getting the schema

The schema is not published and the device API does not serve it. Copy it off an
appliance, then build a digest and regenerate the model:

```bash
make schema-pull HOST=labadmin@your-panos-vm   # into schemas/
make schema-digest PANOS_VERSION=11.2.0        # into schemadigest/
make generate
```

`schema-pull` fetches `schema.xml`, `cms-schema.xml` and `opschema.xml` from
`/opt/pancfg/mgmt/factory/`. These are vendor files and are not committed. Read
ARCHITECTURE.md first.

## Rules

[AGENTS.md](AGENTS.md) holds the rules that govern this repository. They are
mandatory, and each one names the check that enforces it.

## Licence

MIT. See [LICENSE](LICENSE).
