# schema-codegen

Validated against 86fd84f on 2026-09-27 · Purpose: how the PAN-OS schema becomes a digest and a generated Go model, and what stops either drifting.

## Purpose & responsibilities

PAN-OS ships its own schema on the appliance: `/opt/pancfg/mgmt/factory/schema.xml`
on a firewall and `cms-schema.xml` on Panorama. `panos-schemagen` still reads
both, but only the firewall digest ships (Panorama support was removed in M1). It
turns one into a
compact digest, and the digest into Go structs for every configuration object.

Nothing in this project hand-writes a field mapping that the schema already
describes. That is rule R1.

## How it works

### Two subcommands

- **`panos-schemagen digest -in schema.xml -out internal/config/schemadigest/`** — parse the
  proprietary grammar and write a trimmed, gzipped JSON digest carrying its PAN-OS
  version and platform.
- **`panos-schemagen generate -digest internal/config/schemadigest -out internal/config`** — emit
  `internal/config/v11_2/firewall/model.go`.

### The grammar

Not XSD. The elements are `sequence`, `array`, `element`, `choice`, `union`,
`validate`, `attr-req`, `memberof` and `enum`. `validate` and `string` are
transparent wrappers and are never skipped: 11,721 of 11,725 `memberof` elements
sit inside a `validate`.

### Shape deduplication

A naive emit produces about 7,200 types. Most are structurally identical.
`internal/schema/shape.go` fingerprints each shape and `GroupByShape` collapses
them; the rest become Go type aliases. Measured on `cms-schema.xml`: 2,291 entry
arrays collapse to 506 shapes and 6,720 inline sequences to 1,737, so the package
declares about 2,243 types.

### Naming

`internal/codegen/naming.go` resolves collisions deterministically, caps a name at
50 characters, and reserves `Config`, `MemberList` and `RawNode`. The schema
contains an inline sequence named `config`, which collides with the root type; there
is a regression test and a fixture for it.

### Reference classification

`internal/schema/refs.go` decides what a `memberof` target names. Only an object or
predefined target is an index edge. The census over the 11.2 firewall schema, pinned
by `internal/digest/census_test.go`:

| Form | Count |
|---|---|
| object | 3,811 |
| predefined | 1,333 |
| template variable | 0 |
| rule field | 276 |
| expression | 429 |
| unrecognised | 49 |
| **total** | **5,898** |

Two earlier classifiers undercounted, and both are recorded in that test so the
mistake cannot recur. The first treated any parenthesis as a computed expression and
misfiled conditional references. The second treated every `#myentry(` anchor
as a template variable; most are scope-relative object references, and discarding
them cost 1,455 objects in this schema and every zone target of a security rule.

### Where the digests live

`internal/config/schemadigest/` is the only copy. `go:embed` reads it there,
because an embed directive cannot reach outside its own package, and the generator
reads and writes it there. **It is committed.** With it gitignored, a pristine
checkout did not compile.

## Build / run pointers

- `make generate` — regenerate the model from the committed digests.
- `make generate-check` — fail if the committed model differs from a fresh
  generation. Scoped to `internal/config/v*/`, so hand-written code in `internal/config/` is not
  compared.
- `make context` / `make context-check` — refresh or verify the API blocks in these
  agent docs.
- `go test ./internal/...` — schema, digest and codegen.

## Public API

None. Every package here is internal — `internal/schema`, `internal/digest`,
`internal/codegen` — and the surface is the `panos-schemagen` command.

## Gotchas / invariants

- **The schema files themselves are not committed.** `/schemas/` is gitignored
  because redistribution is unresolved. The digests are committed instead.
- **A drift gate must diff only generated paths.** An earlier version regenerated
  over the tree before diffing, so it could not detect drift at all; a later one
  compared all of `internal/config/`, including hand-written files.
- **Only 11.2 digests ship.** Adding 12.2 is a `panos-schemagen digest` run against
  that appliance's `schema.xml`, not a code change.

## See also

- `cmd/panos-schemagen/`, `internal/schema/`, `internal/digest/`, `internal/codegen/`
- `internal/digest/census_test.go` — the pinned reference census
- [config-loading](config-loading.md) — how the digest is consumed
