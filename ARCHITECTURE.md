# Architecture

This file holds the reasoning. AGENTS.md holds the rules.

## What this project is

proteus is a read-only command-line tool that answers questions about PAN-OS
firewalls, with its knowledge of every configuration field taken from PAN-OS's own
schema.

It is an application, not a library. Every package lives under `internal/`, so
none of them is an API that must stay stable for outside code; a later MCP server
belongs in this module and can import them. The read-only core (`config`,
`resolve`, `index`) does not talk to devices and it does not write. Above it,
`fetch` reads devices with show commands and a configuration export, `store` keeps what it read as timestamped snapshots,
and `inventory` says which devices there are. R12 keeps the core free of I/O.

## Why read the schema

PAN-OS ships an authoritative configuration schema on every appliance:

| File | Size | Describes |
| --- | --- | --- |
| `/opt/pancfg/mgmt/factory/schema.xml` | ~4.8 MB | Firewall configuration |
| `/opt/pancfg/mgmt/factory/opschema.xml` | ~2.1 MB | Operational commands |

It is not published, and the device API does not serve it: `show config schema`
returns error 17. It must be copied off an appliance (`make schema-pull`).

The grammar is richer than an XSD. It carries defaults, name length limits, enum
values, validator names, help strings, and — importantly — `memberof`
declarations that state which other objects a field may reference.

The alternative is a hand-maintained SDK, and correctness is the argument
against it. A hand-maintained specification can type an entry list as a member list. pango
did exactly that for a vsys assignment: the device writes
`<entry name="vsys3"/>`, pango read an empty value and kept nothing, so a round
trip deleted the assignment. The schema states the shape unambiguously, and the
grammar makes the two forms structurally distinct. A reader taking the shape from that grammar cannot choose wrong, because
the choice is its input. R1 and R4 exist to keep it that way.

A Go model was once generated from the schema. Nothing read it: the core walks the
element tree through the digest (see "No version seam" below), so the model, its
generator and its drift gate were removed. What remains is the digest and
`internal/tools/schemadigest`, which makes one for a new PAN-OS version.

## Why read-only

proteus analyses and answers. Writing is a different problem with different
risks, and pango's API client already solves it. Keeping writes out removes a
whole category of failure from a tool whose value is that its answers can be
trusted. R2 enforces it.

## Each firewall is read directly

proteus reads each firewall's own configuration, not Panorama's. A managed
firewall's running configuration already carries the policy Panorama pushed to
it, so the device-group hierarchy that computed that policy does not need to be
modelled here. What remains is the order a firewall evaluates its layers in:
shared pre-rules, the vsys's own rules, shared post-rules, then the defaults.
Source: PAN-OS documentation, "Device Group Policies".

That claim is not yet verified on a Panorama-managed firewall, and the 11.2.0
firewall schema declares no pre-rulebase at all. See
`docs/specs/2026-09-27-panos-analyst-scope.md` §5.3.

Scope still decides what a name means. A shared dynamic address group resolves to
different members in each vsys, because only shared and the vsys contribute.
Resolve globally and sibling vsys bleed into each other. R5 exists for this.

## Layout

```
cmd/proteus/                main only: signal context, version, calls internal/cli
internal/cli/               the commands, their rendering and settings
internal/config/            Load, version detection, element tree, scopes
internal/config/schemadigest/  committed firewall digests, ~0.2 MB each, embedded
internal/resolve/           PAN-OS semantics (targets, rule order, scoped visibility)
internal/index/             scope-keyed indexes (refs, closure, CIDR, rules)
internal/inventory/         devices, credentials and TLS choice, from YAML
internal/fetch/             read-only XML API client and the document list
internal/store/             timestamped on-disk snapshots, latest, retention
internal/estate/            selectors and a time to targets; the simulation registry
internal/simulate/…         the staged simulation framework and its kinds
internal/search/            where a value or name appears
internal/card/              the whole rule or object behind a name
internal/drift/             what changed between two configurations
internal/runlog/            one log file per run
internal/schema/            parse the PAN-OS schema grammar
internal/digest/            the committed schema digest format
internal/archtest/          the import-direction check (R12)
internal/fakepanos/         a fake PAN-OS XML API for tests
internal/tools/schemadigest/  dev tool: a vendor schema into a digest
testdata/                   trimmed schema fragments, config and op-data fixtures
schemas/                    vendor schema files, pulled from an appliance, not committed
```

`cmd/` holds only wiring. A command's logic lives in `internal/cli`, where tests
reach it and a second front end could share it.

Dependency order is one-way: `config` <- `resolve` <- `index`. Nothing imports a
versioned package except the caller. R12 checks it with a test rather than a
sentence, and the test fails when a rule names a package that no longer exists,
so a move cannot switch a rule off.

The schema digests have one home, `internal/config/schemadigest/`: `go:embed`
cannot reach outside its package, so the schemadigest tool writes them there
rather than keeping a second copy in step.

## Decisions

Settled in `docs/specs/2026-09-26-go-panos-schema-design.md`, which holds the
detail and the measurements.

- **Versions.** One digest per PAN-OS minor, embedded in the binary. A
  configuration from a release without one loads with the nearest digest and a
  warning.
- **Schema input.** A compact digest is committed; the vendor XML is not.
- **Unknown data.** Preserved verbatim and reported. A newer config still loads.
- **Indexes live here, verdicts do not.** References, transitive group closure,
  CIDR containment and rule-position bitmaps, all keyed by scope. The simulator and
  search build on top.

  The line runs between *reachability* and *decision*. The index answers "which
  rules could this value reach", because that is index knowledge and there are four
  separate paths to get it wrong: the object covering an address, a group holding
  that object, a literal in the rule field, and a field of `any`. `CandidatesFor`
  unions all four for one side of a match. Intersecting the sides, dropping
  disabled rules, and deciding what a first match means — including whether
  application, service and zone agree — is the consumer's.

  That split was arrived at the hard way. The composition was first written twice,
  in two commands, and the `any` path was missing from both. A live firewall caught
  it: for 198.18.0.5 to 198.18.1.5 the device reports rule 3, whose source is
  `any`, while matching on objects alone reported rule 8. One wrong winner, fixed
  in two places. Now there is one place.
- **No version seam.** `resolve` and `index` read the configuration as a parsed
  element tree, guided by the schema digest, rather than through generated
  structs. The digest records its own PAN-OS version, so no version-agnostic
  interface and no generated adapter are needed. A prototype established this; an
  earlier draft had both.
- **Everything immutable is computed once.** The schema digest is decoded once per
  process and the reference tables built alongside it; a configuration is parsed
  once by `Load`; an index is built once per scope. Recomputing these per query
  cost 18.7 ms to build one index on a 41 KB file, against 0.023 ms now.

## Still open

1. **Schema redistribution.** Whether the derived digest may be published is
   unresolved. Until it is, this repository stays private.
2. **Large configurations.** The parsed element tree peaks near ten times the file
   size, so a 200 MB export implies roughly 2 GB. Streaming per vsys is the
   mitigation and is not yet designed.
3. **Runtime data.** Registered-IP group members and App-ID dependencies are not
   in a configuration file at all.
4. **NAT semantics.** The NAT rulebase is read, but translated-address fields are
   not resolved.
