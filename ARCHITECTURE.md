# Architecture

This file holds the reasoning. AGENTS.md holds the rules.

## What this library is

A read-only Go interface to a PAN-OS or Panorama configuration file, with the
object model generated from PAN-OS's own schema.

It is a library. Other tools consume it — an analysis platform, an MCP server, a
policy simulator. It does not talk to devices and it does not write.

## Why generate from the schema

PAN-OS ships an authoritative configuration schema on every appliance:

| File | Size | Describes |
| --- | --- | --- |
| `/opt/pancfg/mgmt/factory/schema.xml` | ~4.8 MB | Firewall configuration |
| `/opt/pancfg/mgmt/factory/cms-schema.xml` | ~10 MB | Panorama configuration |
| `/opt/pancfg/mgmt/factory/opschema.xml` | ~2.1 MB | Operational commands |

It is not published, and the device API does not serve it: `show config schema`
returns error 17. It must be copied off an appliance (`make schema-pull`).

The grammar is richer than an XSD. It carries defaults, name length limits, enum
values, validator names, help strings, and — importantly — `memberof`
declarations that state which other objects a field may reference.

The alternative is a hand-maintained SDK. Measured against PAN-OS 11.2:

| Approach | Object types |
| --- | --- |
| Generated from `cms-schema.xml` | 2,289 |
| pango (hand-maintained specs) | 117 |

Coverage is the smaller argument. Correctness is the larger one. pango types a
device group's `vsys` assignment as a member list; Panorama writes an entry
list. pango returns an empty value and does not preserve the original, so the
data is lost. The schema states the shape unambiguously, and the grammar makes
the two forms structurally distinct — 2,291 entry lists against 1,911 member
lists. A generator reading that grammar cannot choose wrong, because the choice
is its input. R1 and R4 exist to keep it that way.

## Why read-only

The consumers of this library analyse and answer. Writing is a different problem
with different risks, and pango's API client already solves it. Keeping writes
out removes a whole category of failure from a library whose value is that its
answers can be trusted. R2 enforces it.

## Panorama is the primary target

Observed on Panorama 11.2.7-h1:

- **The device group hierarchy is not where the device groups are.** `parent-dg`
  lives only under `/config/readonly/devices/entry/device-group/entry`. It
  survives both `action=show` and `export`, so a config file is sufficient. The
  schema declares `readonly` as an empty node, so this is hand-modelled (R8).
- **The device key is (serial, vsys), never serial.** One firewall had vsys2 and
  vsys3 in two different device groups. Keying by serial merges two distinct
  effective policies into one wrong answer.
- **Panorama cannot tell you the merged policy.** `show config merged` and
  `show config pushed-shared-policy` are both rejected on Panorama. Computing
  the effective policy is this library's job.
- **Rule order reverses between pre and post.** Shared pre-rules, then device
  group pre-rules from root to leaf, then the firewall's local rules, then device
  group post-rules from leaf to root, then shared post-rules, then the defaults.
  Source: PAN-OS documentation, "Device Group Policies".
- **Scope decides what a name means.** A shared dynamic address group resolves
  to different members in each device group, because only the visible scope
  contributes. Resolve globally and sibling device groups bleed into each other.
  R5 exists for this.

## Layout

```
cmd/panos-schemagen/   generator CLI: digest -> Go model
internal/schema/       parse the PAN-OS schema grammar
internal/digest/       the committed schema digest format
internal/codegen/      emit Go from the digest
schema/                public: query the schema itself (types, limits, references)
config/                public: Load, version detection, the Model interface
config/v11_2/…         public: generated model per PAN-OS minor and platform
resolve/               public: Panorama semantics (hierarchy, targets, merge order)
index/                 public: scope-keyed indexes (refs, closure, CIDR, rules)
schemadigest/          committed digests, ~0.4 MB each
testdata/              trimmed schema fragments and config fixtures
schemas/               vendor schema files, pulled from an appliance, not committed
```

Dependency order is one-way: `config` <- `resolve` <- `index`. Nothing imports a
versioned package except the caller.

`schema/` is public because the schema is useful on its own: it answers "what may
this field reference", "how long may this name be", and "what does this field
mean" — without a config file in hand.

## Decisions

Settled in `docs/specs/2026-09-26-go-panos-schema-design.md`, which holds the
detail and the measurements.

- **Naming.** One Go type per distinct structural shape. That collapses 2,291
  entry types to 506, because the template subtree embeds a whole firewall
  config. Names come from the shallowest path where a shape occurs.
- **API surface.** All generated structs are public.
- **Versions.** One generated model per PAN-OS minor and platform, in its own
  package. Adding 11.3 cannot break an 11.2 consumer.
- **Schema input.** A compact digest is committed; the vendor XML is not. CI
  regenerates from the digest, so drift is gated without an appliance.
- **Unknown data.** Preserved verbatim and reported. A newer config still loads.
- **Indexes live here, verdicts do not.** References, transitive group closure,
  CIDR containment and rule-position bitmaps, all keyed by scope. Consumers build
  the policy simulator and where-used calls on top.

  The line runs between *reachability* and *decision*. The library answers "which
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
  element tree, guided by the schema digest, rather than through the generated
  structs. The digest records its own PAN-OS version, so no version-agnostic
  interface and no generated adapter are needed. A prototype established this; an
  earlier draft had both.
- **Shapes are deduplicated on both sides.** Entry arrays and inline sequences
  alike, which takes the Panorama package from 4,438 type declarations to 2,891.
- **Everything immutable is computed once.** The schema digest is decoded once per
  process and the reference tables built alongside it; a configuration is parsed
  once by `Load`; an index is built once per scope. Recomputing these per query
  cost 18.7 ms to build one index on a 41 KB file, against 0.023 ms now.

## Still open

1. **Schema redistribution.** Whether the derived digest may be published is
   unresolved. Until it is, this repository stays private.
2. **Large configurations.** The parsed element tree peaks near ten times the file
   size, so a 200 MB Panorama export implies roughly 2 GB. Streaming per device
   group is the mitigation and is not yet designed.
3. **Runtime data.** Registered-IP group members, App-ID dependencies and
   template-variable resolution are not in a configuration file at all. 1,069 of
   the schema's reference declarations point at template variables.
4. **NAT semantics.** The NAT rulebase is read, but translated-address fields are
   not resolved.
