# panorama-semantics

Validated against 86fd84f on 2026-09-27 · Purpose: which policy a firewall actually gets, and which objects it can see.

## Purpose & responsibilities

`resolve` turns a parsed file into PAN-OS meaning. Panorama cannot report a merged
policy for a firewall; this package computes it. It also decides which objects a
scope can see, which definition wins when two scopes define the same name, and what
a group resolves to in one device group specifically.

## How it works

### Hierarchy and targets

`NewHierarchy` reads `parent-dg` to build the device-group tree. `Roots`,
`ParentOf`, `Children` and `Chain` navigate it. `Chain(dg)` returns shared first,
then root to leaf.

`readParentDg` matches exactly `/config/readonly/devices/entry/device-group/entry`.
A looser match also hits the read-only mirror of the same tree and overwrites real
data with nil.

A `Target` is a firewall, keyed by **serial and vsys**, not by serial alone. Two
vsys on one chassis can sit in different device groups. `Targets(cfg)` branches on
platform: a Panorama file yields device-group targets, a firewall file yields one
per vsys.

### Merged rule order

`(*Target).Rules(rb)` returns the effective policy in evaluation order:

1. shared pre-rules
2. device-group pre-rules, root to leaf
3. the firewall's own rules — the plain `rulebase`, empty on Panorama
4. device-group post-rules, leaf to root
5. shared post-rules

`Position` is 1-based in that merged order, and it is the bit index the rule
bitmaps use. So the lowest set bit is the first match.

### Scoped visibility and shadowing

`ObjectsInScope(cfg, scope, kind)` walks the chain root to leaf, so a descendant
definition replaces an ancestor's of the same name and records what it replaced in
`ShadowedFrom`. `ObjectsAt` takes an explicit container path, for the kinds whose
name is ambiguous in the schema.

`objectValue` reduces an object to the one value that identifies it, and PAN-OS
spells that differently per kind: `ip-netmask`, `ip-range`, `fqdn`, `ip-wildcard`,
`static` for an address group, `members` for a service group, `user` for a local
user group, `list` for a URL category, and `protocol/<proto>/port` for a service.
Missing one leaves the object valueless and it drops out of every value lookup.

### Groups

A static group lists members. A dynamic group carries a tag filter, and its members
are the visible objects whose tags satisfy it — which is why group resolution is
scope-bound. The same shared group resolves to different members in different
device groups.

`ParseTagFilter` is a real recursive-descent parser: `and`, `or`, `not`,
parentheses, and `and` binds tighter. A filter it cannot read contributes no
members and is recorded, never guessed at.

### Profiles and zones

`URLFilteringProfilesInScope` and `ProfileGroupsInScope` read entries that carry
several member lists, which `Object` cannot represent. `ZonesInScope`,
`InterfaceAddresses`, `StaticRoutes` and `DynamicRoutingProtocols` supply the
zone value space.

`InterfaceAddresses` reads every nesting shape: an ethernet address behind
`layer3`, a subinterface behind `layer3/units`, a loopback directly under `units`.
It stops at the next `entry` down, because that is a subinterface with a name and
possibly a zone of its own.

## Build / run pointers

- `go test ./resolve/` — the whole package.
- `./bin/panos-explore target <cfg> <serial> <vsys>` — what one firewall gets.
- `./bin/panos-explore groups <cfg>` — the device-group tree.
- `./bin/panos-explore group <cfg> <scope> <name>` — one group in one scope.

## Public API

<!-- GENERATED:api ./resolve -->
```go
type FIBRoute struct{ ... }
type Hierarchy struct{ ... }
type InterfaceAddress struct{ ... }
type InterfaceState struct{ ... }
type Layer int
type Members struct{ ... }
type Object struct{ ... }
type ProfileGroup struct{ ... }
type Rule struct{ ... }
type Rulebase int
type StaticRoute struct{ ... }
type TagFilter struct{ ... }
type Target struct{ ... }
type URLFilteringProfile struct{ ... }
type URLPattern struct{ ... }
type Zone struct{ ... }

func (f *TagFilter) Match(tags []string) bool
func (f *TagFilter) String() string
func (f *TagFilter) Tags() []string
func (h *Hierarchy) Chain(dg string) []config.Scope
func (h *Hierarchy) Children(dg string) []string
func (h *Hierarchy) ParentOf(dg string) (string, bool)
func (h *Hierarchy) Roots() []string
func (l Layer) String() string
func (p URLPattern) Match(url string) bool
func (p URLPattern) Raw() string
func (r Rulebase) String() string
func (t *Target) Chain() []config.Scope
func (t *Target) DeviceGroup() string
func (t *Target) Objects(kind string) ([]Object, error)
func (t *Target) ResolveGroup(name string) (Members, error)
func (t *Target) Rules(rb Rulebase) ([]Rule, error)
func (t *Target) Scope() config.Scope
func (t *Target) Serial() string
func (t *Target) TemplateStack() string
func (t *Target) Vsys() string
func DynamicRoutingProtocols(cfg *config.Config) []string
func GroupInScope(cfg *config.Config, sc config.Scope, name string) (Members, error)
func InterfaceAddresses(cfg *config.Config) ([]InterfaceAddress, error)
func NewHierarchy(cfg *config.Config) (*Hierarchy, error)
func ObjectsAt(cfg *config.Config, sc config.Scope, kind string, within []string) ([]Object, error)
func ObjectsInScope(cfg *config.Config, sc config.Scope, kind string) ([]Object, error)
func ParseTagFilter(raw string) (*TagFilter, error)
func ParseURLPattern(member string) (URLPattern, error)
func ProfileGroupsInScope(cfg *config.Config, sc config.Scope) ([]ProfileGroup, error)
func ReadFIBRoutes(b []byte) ([]FIBRoute, error)
func ReadInterfaceStates(b []byte) ([]InterfaceState, error)
func RulesForDeviceGroup(cfg *config.Config, dg string, rb Rulebase) ([]Rule, error)
func StaticRoutes(cfg *config.Config) ([]StaticRoute, error)
func TargetFor(cfg *config.Config, serial, vsys string) (*Target, error)
func Targets(cfg *config.Config) ([]*Target, error)
func URLFilteringProfilesInScope(cfg *config.Config, sc config.Scope) ([]URLFilteringProfile, error)
func Vsyses(cfg *config.Config) ([]string, error)
func ZonesInScope(cfg *config.Config, sc config.Scope) ([]Zone, error)
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **A scope is not optional.** A global index merges sibling device groups and
  returns answers that are wrong rather than incomplete. See R5 and R10.
- **A template carries no policy objects.** Templates hold network and device
  configuration. Zones live there, which is why a device-group scope has none.
- **`group` reads address groups only.** Service and application groups take part
  in the index closure but `GroupInScope` does not read them.
- **Runtime group members are absent by design.** Addresses registered through
  User-ID or VM monitoring are not in a file, and every group answer says so.

## See also

- `resolve/target.go`, `resolve/hierarchy.go`, `resolve/rules.go`
- `resolve/objects.go`, `resolve/groups.go`, `resolve/filter.go`
- `resolve/zones.go`, `resolve/profiles.go`
- [config-loading](config-loading.md) — the tree and schema questions this builds on
- [value-spaces](value-spaces.md) — what `index` does with these objects
