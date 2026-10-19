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
snapshot older than `When.MaxAge` becomes a `Target.Notes` entry.
`OpenFile` does the same for one file with no store.

App-ID data (spec 2026-10-16): each target carries `Apps`, a lazy loader, and
`AppsPath`. For a snapshot it reads `Snapshot.ContentPath()` (nil without
`app_version`) through `When.Apps`, an `AppSource` (`DiskApps` by default, the MCP
cache in the server, a per-question memo in `query`); a `Loaded.Apps` from the
config source wins. `OpenFile` reads `AppsFile`, `apps.xml.gz` in the directory of
the configuration. A question that needs no application data never calls `Apps`.

User-ID data (spec 2026-10-17 §4.2, §7): each target carries `Identity`, a lazy
loader, and `IdentityPath`. For a snapshot it reads `Snapshot.IdentityPath()` (""
without the file) through `When.Identity`, an `IdentitySource` (`DiskIdentity` by
default, the MCP cache in the server, `identityMemo` per question in `query`); a
`Loaded.Identity` from the config source wins. `OpenFile` reads `IdentityFile`,
`identity.json.gz` in the directory of the configuration. `query.identityFor`
turns a load into data and notes (PD11). See [identity](identity.md).

### search

`Run(cfg, idx, Query)` runs five stages in order: objects by value (address terms
through `Containing`/`Overlapping`, any other term through every field's resolvers
with the query's `Providers`), objects by name (every kind `resolve.ObjectKinds`
lists), groups (`GroupsHolding` per kind a name was found as, one level up with
`Direct`), references
(`Refs` and `ProfileUses`), literals (`RulesWithAddr`/`RulesWithPrefix`). Modes
`Exact`, `Within`, `Contains` change stage one; `Kinds`, `Fields`, `Show` filter.
With App-ID data in `Query.Providers.Apps` (spec 2026-10-16 §5.1), an
application term also finds, through the resolver, the filters that select it
(the finding's `Via` names the selecting fields, `category=media, risk=4`) and the
containers that hold it; an application group finding shows the path through
nested groups (`Index.GroupPath`, `outer > inner > ssl`, D12); and `implicitUse`
adds the allow rules that reach it only through the implicit use of another
application (`Via` `implicit use by <app>`), leaving out any-rules and rules an
explicit finding already holds. `query.Search` makes the term canonical first
(D17): `Refs` and the interner match case exactly.

With User-ID data in `Query.Providers.Users` (spec 2026-10-17 §6.1, PD13), a user
term reaches, through the user value space, the `source-user` members of the rules
that the user satisfies; the object findings carry `Via` `<source>, <n> members`
for a group ("1 member" for one). `query.Search` replaces the term with its
primary name first (`userTerm`, through `Resolve`, PD18). The stage `identity`
(after `object`) adds a mapping for one address, and for a user term the user
(`identity-user`), its groups (`identity-group`) and its mapped addresses
(`mapping`), each only when no object finding names it (`shownByObjects`; with
`--show` without `objects`, every one). `groupForms` lets a group term reach a rule
that names the group by its short name or its DN in another case: search shows
where a group is named, while `simulate` keeps same-text matching. `Contains`
mode runs no identity stage. When to load the data: [identity](identity.md#loading-pd10-42).

### card

`Find(cfg, idx, apps, name, kind)` returns one `Card` per element of that name visible in
the scope: a security rule (`idx.Rules()`) or an object of any kind
`resolve.ObjectKinds` lists. With App-ID data (`apps`, may be nil) it also finds
a predefined application (`App`: category, subcategory, technology, risk, flags,
tags, default, obsolete, container, parent, use, implicit use, tunnel,
description; parent and tunnel as written, F15) and a container with its
functions; an application filter is a `FilterCard` (criteria, the count and the
applications it selects, `KindFilter`). The text cuts a filter's applications at
20 (`maxFilterApps`), `--full` lifts it; the summary drops the card (C5). `Rule` lays a rule out in the rule editor's sections;
`Object` gives a value, members, profiles and the groups of its kind holding it
(`GroupsHolding` with direct). A group's members come from the builder's object
cache, read once per kind; a dynamic group shows its filter as written. Every `Item` carries its value and children to full depth; a
name no object defines is `Literal` (an address or prefix) or `Predefined` (in
source, destination, service, category). The command cuts trees at three levels
and lists at five items; JSON carries the whole card.

`FindIdentity(ids, name, kind)` (PD14) builds the cards of the User-ID data:
`identity-user` (primary, alternate names, email, groups with their source,
mapped addresses with type and timeout, tags) by `Resolve`, and `identity-group`
(source, member count, members) by name in any case or short name, a DUG too. The
text cuts a group's members at 20 (`maxGroupMembers`), `--full` lifts it.
`query.Lookup` calls it for an identity kind, or with no kind when the first look
finds nothing (`needsIdentity`).

### drift

`Compare(before, after, scope)` walks the scope's element (shared, or one vsys)
with the schema digest and takes every entry of every entry list it meets as one
entry to compare: objects of every kind, profiles, zones and schedules included,
and the rules of every rulebase. It stops at an entry list; nested entries belong
to their entry's form. A vsys `user-group`, an array of arrays named `entry`
with a name, is read as an entry list too (`namedEntries`). Every other element
or array below the scope, and an empty element set by its presence (an
alternative of a choice, or a node with nothing to hold: `setByPresence`), is a
setting: one entry of kind `setting`, named by its path below the scope, whose
form paths start at its own name (`drift.TestCompareReadsScopeSettings`). A
container the walk descends into keeps its own attributes as a setting. The shared `pre-rulebase` and
`post-rulebase` are read with a vsys rulebase's node (hand-modelled, R8); their
rules' kind names the rulebase, such as `pre-rulebase security rule`
(`ruleKind`), and a vsys's own rule reads `security rule`. An element the digest does not
describe is compared whole, its own text too, as one entry named by its path. Each entry becomes a
canonical form: setting paths with text and attributes in document order; a
member list (from the digest, R4) is one value with its members sorted; a
nested entry list adds an order field (`<path> order`, names in document order;
only the names both sides hold count); a secret or an undescribed value is
compared but never shown; `uuid`,
`admin`, `time` and `dirtyId` are ignored (`ignoredAttrs`). A changed entry
carries `Fields` (`path`, `old`, `new`, `secret`, `undescribed`); an added or
removed one a short line in
`New` or `Old`: the object's value and tags as `resolve` reads them, or a rule's
action and described member lists. `resolve` does not read the schema, so an
object whose form holds a secret or an undescribed value has no short line.
Position is not compared. Predefined services are never
read. `query.Diff` adds `note.app-version-changed` when the two snapshots'
`app_version` differ; it never compares applications (spec 2026-10-16 §5.3).
It adds `note.config-source-changed` when their `config_source` differs (a
snapshot without the key counts as `export`, spec 2026-10-17 §2.4). With User-ID
data in both snapshots, `identityDiff` adds one result with the scope `identity`
(PD15): `identity.Diff` as `drift.Change` values of kinds `identity user` (groups
gained or lost, one `group` field each) and `identity source` (came, went, or a
group count change). It never compares mappings (D9). One side without data gives
no result and `note.identity-not-compared`; a part missing on either side is not
compared, and the same note names it.

## Build / run pointers

- `go test ./internal/estate ./internal/search ./internal/card ./internal/drift`
- `./bin/proteus search <term> --file <cfg>`, `./bin/proteus lookup <name> --file <cfg> --expand`, `./bin/proteus snapshot diff`

## Public API

<!-- GENERATED:api ./internal/estate -->
```go
type AppSource interface{ ... }
type ConfigSource interface{ ... }
type DiskApps struct{}
type DiskConfigs struct{}
type DiskIdentity struct{}
type DiskOps struct{}
type Hole struct{ ... }
type IdentitySource interface{ ... }
type Indexes interface{ ... }
type Loaded struct{ ... }
type Network struct{ ... }
type OpSource interface{ ... }
type OpTables struct{ ... }
type Target struct{ ... }
type When struct{ ... }

func (DiskApps) Apps(path string) (*appid.Data, error)
func (DiskConfigs) Config(sn store.Snapshot) (Loaded, error)
func (DiskIdentity) Identity(path string) (*identity.Data, error)
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
func SkipNote(sn store.Snapshot) (reason.Reason, bool)
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

func App(a appid.App, sc config.Scope) Card
func FilterCard(cfg *config.Config, idx *index.Index, apps *appid.Data, o resolve.Object) Card
func Find(cfg *config.Config, idx *index.Index, apps *appid.Data, name, kind string) ([]Card, error)
func FindIdentity(ids *identity.Data, name, kind string) []Card
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
  `encrypt="yes"`, or a hand-modelled one: `phash` and the credentials the schema
  keeps in clear text, such as an SNMP v2c community) is compared, but its values read
  `(secret)` (`drift.Hidden`) and `FieldChange.Secret` is set; the text line is
  `<path>: changed (secret, not shown)` (`drift.TestCompareHidesSecrets`). A
  rule's short line reads only described member lists; an object's short line
  is dropped when its form holds a hidden value
  (`drift.TestCompareObjectLineHoldsNoHiddenValue`).
- **An undescribed value never shows.** An element the digest does not describe
  (a whole one under the scope, or an unknown child of a known entry), an
  attribute it does not declare (only `name`, `id` and `status` are declared) and
  a member list whose members carry attributes are compared by raw value, but
  `FieldChange.Undescribed` is set and `old`/`new` stay empty; the text line is
  `<path>: changed (not described by the schema; values not shown)`. The lab's
  12.2.3 configuration is read with the one 11.2 digest, so this is common
  (`drift.TestCompareHidesAnUndescribedChild`).
- **R12:** `search`, `card` and `drift` import none of `fetch`, `store`, `estate`.

## See also

- [commands](commands.md) — the command surface over these packages
- [fetch-and-store](fetch-and-store.md) — where the snapshots come from
