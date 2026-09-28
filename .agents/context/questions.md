# questions

Validated against c173b67 on 2026-09-29 · Purpose: how a question becomes targets, findings and changes — the packages under `panos-analyst search` and `snapshot diff`.

## Purpose & responsibilities

Three packages sit between the read-only core and the command. `estate` turns a
selection and a time into targets: one (device, vsys, configuration) each, plus a
hole for anything that could not be read. `search` answers one term against one
scope's index as findings. `drift` compares two configurations of one scope. Spec
`docs/specs/2026-09-27-panos-analyst-scope.md` §15, C4 to C9.

## How it works

### estate

`Open(store, devices, vsys, When)` reads each device's `latest` snapshot, or with
`When.At` the newest at or before that time (`store.AtOrBefore`), loads its
configuration once, and returns one `Target` per vsys, filtered by `vsys`. A
missing snapshot, an unreadable configuration or an absent vsys is a `Hole`. A
snapshot older than `When.MaxAge` and a version gap become `Target.Notes`.
`OpenFile` does the same for one file with no store.

### search

`Run(cfg, idx, Query)` runs five stages in order: objects by value (address terms
through `Containing`/`Overlapping`, any other term through every field's resolvers
with the query's `Providers`), objects by name (every kind `resolve.ObjectKinds`
lists), groups (`GroupsOf`, or `DirectGroupsOf` with `Direct`), references
(`Refs` and `ProfileUses`), literals (`RulesWithAddr`/`RulesWithPrefix`). Modes
`Exact`, `Within`, `Contains` change stage one; `Kinds`, `Fields`, `Show` filter.

### drift

`Compare(before, after, scope)` renders every object of `ObjectKinds` defined in
the scope itself, and every security and NAT rule, to one line each, and reports
what was added, removed or changed. Position is not compared.

## Build / run pointers

- `go test ./estate ./search ./drift`
- `./bin/panos-analyst search <term> --file <cfg>`, `./bin/panos-analyst snapshot diff`

## Public API

<!-- GENERATED:api ./estate -->
```go
type Hole struct{ ... }
type Target struct{ ... }
type When struct{ ... }

func Open(st *store.Store, devices, vsys []string, w When) ([]Target, []Hole)
func OpenFile(path string, vsys []string) ([]Target, []Hole, error)
func ParseAt(s string) (time.Time, error)
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./search -->
```go
type Finding struct{ ... }
type Mode int
type Query struct{ ... }
type Stage string

func Run(cfg *config.Config, idx *index.Index, q Query) ([]Finding, error)
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./drift -->
```go
type Change struct{ ... }
type Op string

func Compare(before, after *config.Config, sc config.Scope) ([]Change, error)
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **A reference counts only for the kinds its field can name.** A tag and an
  address group can share a name; a tag field naming the tag does not name the
  group (`search.TestAnAddressFollowsEveryStage`).
- **Any-rules are never findings.** They answer a simulation question.
- **Kinds come from the schema** (R1): `resolve.ObjectKinds` reads `FieldKinds` and
  `KindContainer`, never a list in the code.
- **R12:** `search` and `drift` import none of `fetch`, `store`, `estate`.

## See also

- [commands](commands.md) — the command surface over these packages
- [fetch-and-store](fetch-and-store.md) — where the snapshots come from
