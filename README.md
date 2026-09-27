# go-panos-schema

`go-panos-schema` is a read-only Go library. It loads a PAN-OS or Panorama
configuration file and answers questions about it. It never writes a
configuration and it never contacts a device.

The library exists for tools and AI agents. They ask two kinds of question.
*Does an object with this value exist?* And *which rules can this value reach?*
The library answers both, per scope, and reports what it could not evaluate.

The object model is generated from the schema PAN-OS itself ships.

## What it does

- **Reads what a firewall actually gets** — the library builds the device group
  hierarchy from `parent-dg`, keys each firewall by serial **and** vsys, and
  merges the rule layers in the order the firewall evaluates them. Panorama
  cannot report a merged policy. The library computes it.
- **Answers from a value, not only from a name** — give it an address, a prefix,
  a URL, a port, a user, a zone or an application name. It returns the rules that
  value can reach, in evaluation order.
- **Matches each rule field by the value spaces the schema allows there** — a
  security rule's `source` accepts an address, an address group, a region, an
  external list and an IP block list. That is five value spaces, not one. The
  wiring comes from the schema, not from hand-written code.
- **Resolves per scope** — a scope is `shared`, a vsys, or a device group with its
  ancestor chain. One shared dynamic address group resolves to different members
  in each device group. A global answer is wrong, not merely incomplete.
- **Reports incompleteness** — every lookup returns a report. A non-empty
  `Unresolved` list means the answer is missing matches, and the report says why.
- **Takes facts a configuration does not hold** — a user-to-group mapping comes
  from User-ID, not from a file. The library defines a snapshot format and reads
  it. The caller fetches the data.
- **Builds each index once** — an index is immutable and cached per file and
  scope. Concurrent readers need no lock.

## A first look

```text
$ ./bin/panos-explore reaches testdata/config/firewall-urlcat.xml vsys:vsys1 \
      category superlong.example.azureapps.microsoft.com
loaded testdata/config/firewall-urlcat.xml in 29.501ms: PAN-OS 11.2.0 (11.2.5), firewall

which rules could category match superlong.example.azureapps.microsoft.com, in vsys:vsys1

superlong.example.azureapps.microsoft.com matched via
  custom-azuresite-group   custom-url-category superlong.example.azureapps.microsoft.com

rules in evaluation order (2)
    1. any-category-early         allow  [local       vsys:vsys1]
    4. URL-Example                allow  [local       vsys:vsys1]

some of those match only because their category is "any"
```

See three things here. The answer names the rules in evaluation order. It names
the object that matched and the value that matched it, so a reader can check the
reasoning. And it says which rules join only because the field is `any`.

The same question in Go:

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
2. **`resolve`** holds PAN-OS semantics: the device group hierarchy, which
   firewall gets which policy, scoped object visibility with shadowing, merged
   rule order, group membership and tag filters, URL pattern parsing, and zones,
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

The schema also carries the reference graph. The Panorama schema declares 13,120
`memberof` targets, and 9,647 of them are real object references saying which
objects a field may point at. `internal/digest.TestRealSchemaFormCensus` pins the
census. The schema also carries name length limits, defaults, enum values and
help strings.

## Getting Started

### Prerequisites

- Go, at the version in [`go.mod`](go.mod). The code is pure Go.
- A PAN-OS 11.2 configuration file, or one of the fixtures in `testdata/config/`.

### Build

```bash
make tools-bin                 # bin/panos-explore and bin/panos-demo
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
require github.com/okaiser/go-panos-schema v0.0.0
replace github.com/okaiser/go-panos-schema => ../go-panos-schema
```

## Commands

`panos-explore` answers every question the library answers, without any Go.

| Command and arguments | What it answers |
| --- | --- |
| `info <config.xml>` | Which version and platform this file is, the device group tree, and each firewall's rule count |
| `groups <config.xml>` | The effective policy of every device group, in evaluation order |
| `target <config.xml> <serial> <vsys>` | Which device group, template stack and scope chain one firewall gets |
| `lookup <config.xml> <scope> <value>` | From an address or prefix: the objects covering it, the groups holding them, the rules naming either |
| `reaches <config.xml> <scope> <field> <value>` | Which rules one field could match one value, in any value space |
| `search <config.xml> <scope> <substring>` | Which objects hold a fragment of a value |
| `uses <config.xml> <scope> <category\|url>` | Which rules apply a security profile that mentions a URL category |
| `whereused <config.xml> <scope> <name>` | Every reference to a name, with the object kinds the schema permits there |
| `simulate <config.xml> <scope> <source> <destination> [from-zone to-zone]` | The candidate rules for one address pair, and the first match |
| `group <config.xml> <scope> <name>` | What an address group resolves to in one scope |

A scope is `shared`, `vsys:<name>` or `dg:<name>`. A field is `source`,
`destination`, `category`, `application`, `service`, `from`, `to`, `source-user`
or `tag`. `PANOS_USERS` points at a user snapshot.

`panos-demo <config.xml> [-v]` runs every feature against one file in twelve
sections and narrates what it does.

## Known limits

The library reports each of these rather than hiding it.

- **Only PAN-OS 11.2 digests ship.** `config.Load` refuses a 12.2 configuration.
- **Template variables are not resolved.** 1,069 schema targets point at them.
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
- **URL matching rules are documentation-derived.** A firewall's validator
  verifies the syntax rules. It cannot verify the matching rules, because
  `test url` reports PAN-DB categories only and never names a custom category.
- **A large configuration costs memory.** The parsed element tree peaks near ten
  times the file size.

## Project structure

```
go-panos-schema/
├── cmd/
│   ├── panos-explore/     # the CLI used throughout these docs
│   ├── panos-demo/        # a narrated tour of every feature
│   └── panos-schemagen/   # digest a vendor schema, generate the Go model
├── config/                # Load, version detection, element tree, scopes
│   ├── v11_2/firewall/    # generated model, per PAN-OS minor and platform
│   └── v11_2/panorama/
├── resolve/               # PAN-OS semantics: hierarchy, targets, merge order,
│                          #   objects, groups, tag filters, URL patterns, zones
├── index/                 # lookup structures, value-space resolvers, reports
├── schema/                # public: query the schema itself (design not settled)
├── internal/schema/       # parse the PAN-OS schema grammar
├── internal/digest/       # the committed digest format
├── internal/codegen/      # emit Go from a digest
├── schemadigest/          # committed digests, roughly 0.4 MB each
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
