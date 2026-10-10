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
lists), groups (`GroupsHolding` per kind a name was found as, one level up with
`Direct`), references
(`Refs` and `ProfileUses`), literals (`RulesWithAddr`/`RulesWithPrefix`). Modes
`Exact`, `Within`, `Contains` change stage one; `Kinds`, `Fields`, `Show` filter.

### card

`Find(cfg, idx, name, kind)` returns one `Card` per element of that name visible in
the scope: a security rule (`idx.Rules()`) or an object of any kind
`resolve.ObjectKinds` lists. `Rule` lays a rule out in the rule editor's sections;
`Object` gives a value, members, profiles and the groups of its kind holding it
(`GroupsHolding` with direct). Every `Item` carries its value and children to full depth; a
name no object defines is `Literal` (an address or prefix) or `Predefined` (in
source, destination, service, category). The command cuts trees at three levels
and lists at five items; JSON carries the whole card.

### drift

`Compare(before, after, scope)` walks the scope's element (shared, or one vsys)
with the schema digest and takes every entry of every entry list it meets as one
entry to compare: objects of every kind, profiles, zones and schedules included,
and the rules of every rulebase. It stops at an entry list; nested entries belong
to their entry's form. The shared `pre-rulebase` and `post-rulebase` are read with
a vsys rulebase's node (hand-modelled, R8). An element the digest does not
describe is compared whole, as one entry named by its path. Each entry becomes a
canonical form: setting paths with text and attributes in document order; a
member list (from the digest, R4) is one value with its members sorted; a secret
is compared but never shown; `uuid`,
`admin`, `time` and `dirtyId` are ignored (`ignoredAttrs`). A changed entry
carries `Fields` (`path`, `old`, `new`); an added or removed one a short line in
`New` or `Old`: the object's value and tags as `resolve` reads them, or a rule's
action and member lists. Position is not compared. Predefined services are never
read.

## Build / run pointers

- `go test ./internal/estate ./internal/search ./internal/card ./internal/drift`
- `./bin/proteus search <term> --file <cfg>`, `./bin/proteus lookup <name> --file <cfg> --expand`, `./bin/proteus snapshot diff`

## Public API

<!-- GENERATED:api ./internal/estate -->
```go
type ConfigSource interface{ ... }
type DiskConfigs struct{}
type DiskOps struct{}
type Hole struct{ ... }
type Indexes interface{ ... }
type Loaded struct{ ... }
type Network struct{ ... }
type OpSource interface{ ... }
type OpTables struct{ ... }
type Target struct{ ... }
type When struct{ ... }

func (DiskConfigs) Config(sn store.Snapshot) (Loaded, error)
func (DiskOps) HA(sn store.Snapshot) (resolve.HAState, error)
func (DiskOps) Tables(sn store.Snapshot) (OpTables, error)
func (h Hole) Why() reason.Reason
func (n *Network) Device(name string) (simulate.DeviceData, error)
func (n *Network) Devices() []string
func (n *Network) Read() []string
func GapOf(err error) reason.Code
func Kinds() []string
func NewHole(device, vsys string, r reason.Reason) Hole
func NewNetwork(st *store.Store, devices []string, w When) *Network
func Open(st *store.Store, devices, vsys []string, w When) ([]Target, []Hole)
func OpenFile(path string, vsys []string, log *runlog.Logger) ([]Target, []Hole, error)
func OpenSnapshot(st *store.Store, device, id string, vsys []string, w When) ([]Target, []Hole)
func ParseAt(s string) (time.Time, error)
func StaleNote(id string, age, limit time.Duration) string
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./internal/search -->
```go
type Finding struct{ ... }
type Mode int
type Query struct{ ... }
type Stage string

func Run(cfg *config.Config, idx *index.Index, q Query) ([]Finding, []index.Unresolved, error)
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
type FieldChange struct{ ... }
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
- **A secret never shows.** A setting `schema.IsSecret` marks (the schema's
  `encrypt="yes"`, or the hand-modelled `phash`) is compared, but its values read
  `(secret)` (`drift.Hidden`) and `FieldChange.Secret` is set; the text line is
  `<path>: changed (secret, not shown)`. A short line passes `redact` as a second
  guard (`drift.TestCompareHidesSecrets`).
- **R12:** `search`, `card` and `drift` import none of `fetch`, `store`, `estate`.

## See also

- [commands](commands.md) — the command surface over these packages
- [fetch-and-store](fetch-and-store.md) — where the snapshots come from
