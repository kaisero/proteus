# questions

Validated against 2f14f3f on 2026-09-29 · Purpose: how a question becomes targets, findings, cards and changes — the packages under `proteus search`, `lookup` and `snapshot diff`.

## Purpose & responsibilities

Four packages sit between the read-only core and the command. `estate` turns a
selection and a time into targets: one (device, vsys, configuration) each, plus a
hole for anything that could not be read. `search` answers one term against one
scope's index as findings. `card` builds the whole element behind one name.
`drift` compares two configurations of one scope. Spec
`docs/specs/2026-09-27-panos-analyst-scope.md` §15, C4 to C9, and §16, K1 to K12.

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

### card

`Find(cfg, idx, name, kind)` returns one `Card` per element of that name visible in
the scope: a security rule (`idx.Rules()`) or an object of any kind
`resolve.ObjectKinds` lists. `Rule` lays a rule out in the rule editor's sections;
`Object` gives a value, members, profiles and the groups holding it
(`DirectGroupsOf`). Every `Item` carries its value and children to full depth; a
name no object defines is `Literal` (an address or prefix) or `Predefined` (in
source, destination, service, category). The command cuts trees at three levels
and lists at five items; JSON carries the whole card.

### drift

`Compare(before, after, scope)` renders every object of `ObjectKinds` defined in
the scope itself, and every security and NAT rule, to one line each, and reports
what was added, removed or changed. Position is not compared.

## Build / run pointers

- `go test ./internal/estate ./internal/search ./internal/card ./internal/drift`
- `./bin/proteus search <term> --file <cfg>`, `./bin/proteus lookup <name> --file <cfg> --expand`, `./bin/proteus snapshot diff`

## Public API

<!-- GENERATED:api ./internal/estate -->
```go
type Hole struct{ ... }
type Network struct{ ... }
type Target struct{ ... }
type When struct{ ... }

func (n *Network) Device(name string) (simulate.DeviceData, error)
func (n *Network) Devices() []string
func Kinds() []string
func NewNetwork(st *store.Store, devices []string, w When) *Network
func Open(st *store.Store, devices, vsys []string, w When) ([]Target, []Hole)
func OpenFile(path string, vsys []string, log *runlog.Logger) ([]Target, []Hole, error)
func ParseAt(s string) (time.Time, error)
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./internal/search -->
```go
type Finding struct{ ... }
type Mode int
type Query struct{ ... }
type Stage string

func Run(cfg *config.Config, idx *index.Index, q Query) ([]Finding, error)
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./internal/card -->
```go
type Card struct{ ... }
type Item struct{ ... }
type Row struct{ ... }
type Section struct{ ... }

func Find(cfg *config.Config, idx *index.Index, name, kind string) ([]Card, error)
func Kinds(cfg *config.Config) []string
func Object(cfg *config.Config, idx *index.Index, o resolve.Object) Card
func Rule(cfg *config.Config, idx *index.Index, r resolve.Rule, rules int) Card
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./internal/drift -->
```go
type Change struct{ ... }
type Op string

func Compare(before, after *config.Config, sc config.Scope) []Change
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **A reference counts only for the kinds its field can name.** A tag and an
  address group can share a name; a tag field naming the tag does not name the
  group (`search.TestAnAddressFollowsEveryStage`).
- **Any-rules are never findings.** They answer a simulation question.
- **Kinds come from the schema** (R1): `resolve.ObjectKinds` reads `FieldKinds` and
  `KindContainer`, never a list in the code.
- **A card never loops.** A group cycle is cut and its item's value is `cycle`
  (`card.TestACycleIsCut`).
- **One name can have several kinds.** `Find` returns a card per kind; the command
  exits 2 and asks for `--kind` (`card.TestFindInfersTheKind`).
- **"Predefined" means only "not in the configuration".** No table of PAN-OS
  predefined values exists (spec §14 open item 6).
- **R12:** `search`, `card` and `drift` import none of `fetch`, `store`, `estate`.

## See also

- [commands](commands.md) — the command surface over these packages
- [fetch-and-store](fetch-and-store.md) — where the snapshots come from
