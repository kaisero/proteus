# schema-digest

Validated against 6cd7766 on 2026-09-29 · Purpose: how the PAN-OS schema becomes the digest proteus embeds, and what the digest records.

## Purpose & responsibilities

PAN-OS ships its own schema on every firewall at
`/opt/pancfg/mgmt/factory/schema.xml`. The developer tool
`internal/tools/schemadigest` parses it into a compact, gzipped digest that
proteus embeds and reads at run time.

Nothing in this project hand-writes a field mapping that the schema already
describes. That is rule R1.

## How it works

### One tool, one job

- **`make schema-digest PANOS_VERSION=x.y.z`** runs
  `go run ./internal/tools/schemadigest -schema schemas -out internal/config/schemadigest -version x.y.z`.
  It parses the proprietary grammar and writes a trimmed, gzipped JSON digest
  carrying its PAN-OS version and platform. It refuses a parse that found no
  `memberof` target, the failure mode that once cost a proof-of-concept cycle,
  and one that marked no element `encrypt="yes"`.

### Secrets

The schema marks a key, password or secret `encrypt="yes"` (150 live elements in
the 11.2 firewall schema). The parser keeps it as `Node.Encrypted`, and the digest
carries it (`enc`). Digest format 2 added it; `digest.Read` refuses format 1, which
would read as a schema without secrets. `phash`, a password hash, is not marked;
it is a hand-modelled secret (R8). `schema.IsSecret` answers both. No secret is a
reference (`config.TestNoSecretIsAReference`), so the walk, the index and search
never see one; snapshot diff shows `(secret)` in its place.

A Go model was once generated from the digest as well. Nothing read it, because
`internal/config`, `resolve` and `index` walk the element tree through the digest,
so it was removed with its generator and drift gate on 2026-09-29.

### The grammar

Not XSD. The elements are `sequence`, `array`, `element`, `choice`, `union`,
`validate`, `attr-req`, `memberof` and `enum`. `validate` and `string` are
transparent wrappers and are never skipped: 11,721 of 11,725 `memberof` elements
sit inside a `validate`.

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
because an embed directive cannot reach outside its own package, and the
schemadigest tool writes it there. **It is committed.** With it gitignored, a
pristine checkout did not compile.

## Build / run pointers

- `make schema-pull HOST=user@host` — copy the vendor schema files into `schemas/`.
- `make schema-digest PANOS_VERSION=x.y.z` — write a digest for that version.
- `make context` / `make context-check` — refresh or verify the API blocks in these
  agent docs.
- `go test ./internal/schema ./internal/digest ./internal/tools/...`

## Public API

None. `internal/schema` and `internal/digest` are internal, and the surface is
`make schema-digest`.

## Gotchas / invariants

- **The schema files themselves are not committed.** `/schemas/` is gitignored
  because redistribution is unresolved. The digests are committed instead.
- **Only 11.2 digests ship.** Adding 12.2 is a `make schema-digest` run against
  that appliance's `schema.xml`, not a code change.

## See also

- `internal/tools/schemadigest/`, `internal/schema/`, `internal/digest/`
- `internal/digest/census_test.go` — the pinned reference census
- [config-loading](config-loading.md) — how the digest is consumed
