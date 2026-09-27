# config-loading

Validated against 86fd84f on 2026-09-27 · Purpose: how a configuration file becomes a queryable tree, and what the schema can be asked.

## Purpose & responsibilities

`config` owns the file and the schema. It parses the XML into an element tree,
attaches the schema digest for that PAN-OS version, and answers the questions only
the schema can answer: which object kinds a field may name, where a kind sits under
a scope, and every reference edge the file contains.

It knows nothing about device groups, rules or lookups. Those are `resolve` and
`index`.

## How it works

### Load

`Load(path)` returns `(*Config, Report, error)`. It reads the version attributes
from the root element, picks the platform (firewall or Panorama) from the presence
of Panorama-only containers, and loads the matching digest.

Two details are load-bearing and both have regression tests:

- **Paths anchor at `<config>`.** A file arrives bare from
  `type=export&category=configuration` or wrapped in `<response><result>` from
  `type=config&action=show`. Both load.
- **A nested `<config>` is an ordinary child.** A Panorama file holds several,
  because a template embeds a whole firewall configuration. Parsing stops only when
  the outermost one closes. Stopping at the first nested close found 1 reference
  edge where the correct walk finds 18.

Only 11.2 digests ship. A 12.2 file is refused with a clear error rather than
parsed against the wrong schema.

### The element tree

`Element` is a small nil-safe node: `Attr`, `Child`, `ChildrenNamed`, `Members`,
`Find`, `SchemaPath`, `InstancePath`, `TextOr`. Every accessor tolerates a nil
receiver, so a walk reads as a path rather than as a chain of existence checks.

`InstancePath` names entries, because two device groups can each hold an object of
the same name.

### The digest, and why it is embedded twice

The schema is large. `internal/digest` stores a trimmed, gzipped form, and
`config/embed.go` embeds it with `go:embed schemadigest`.

An embed directive cannot reach outside its own package, so the digests live in two
committed places: `schemadigest/` holds the originals and `config/schemadigest/`
holds the copy that is embedded. `make config/schemadigest` refreshes the copy and
`make digest-check` fails the build if they diverge. When the copy was gitignored,
a pristine checkout did not compile at all, and neither did a consumer running
`go get`.

Both the decoded digest and the reference table are cached process-wide per schema.
Before that caching, `Load` cost 41.8 ms and `Walk` 15.2 ms; after, 0.12 ms and
0.011 ms.

### Schema questions

- **`FieldKinds(suffix)`** — for every entry array whose schema path ends with the
  suffix, which object kinds each reference field may name. It comes from the schema
  and not from the file, because a field left at `any` produces no walk event.
- **`KindContainer(kind)` / `KindContainers(kind)`** — where a kind sits under a
  scope. Most kinds are direct children; a custom URL category and every security
  profile live under `profiles/`.
- **`WalkPaths(fn)`** — every reference value in the file, scoped, each located by
  its path below the entry that holds it (`profile-setting/group`, `log-setting`),
  with the candidate kinds the schema allows for that leaf alone. This is the walk
  to use.
- **`Walk(fn)`** — the older walk, kept for callers that have not moved. It sees
  only `entry/<field>/member`, which is 397 of the firewall schema's 1,991
  reference leaves, and reports a field's candidates merged across everything
  below it.

### Ambiguous kind names

`KindContainer` returns the shallowest match, **which is a guess**. Several kind
names appear at more than one place under a scope:

| Kind | Containers |
|---|---|
| `user` | `user`, `local-user-database/user` |
| `service` | `service`, `route/service` |
| `spyware` | `profiles/spyware`, `threats/spyware` |
| `application` | `application`, `alg-override/application`, and two more |
| `rules` | twelve, one per rulebase |

For `user` the guess is wrong: the local user database is the deeper path. A caller
that might hit an ambiguous kind uses `KindContainers` and chooses, then reads with
`resolve.ObjectsAt`.

## Build / run pointers

- `go test ./config/` — loading, the tree, the walk, the schema questions.
- `./bin/panos-explore info <cfg>` — version, platform, load time.
- `make digest-check` — the two digest copies agree.

## Public API

<!-- GENERATED:api ./config -->
```go
type Config struct{ ... }
type Element struct{ ... }
type Event struct{ ... }
type EventKind int
type Platform int
type Report struct{ ... }
type Scope struct{ ... }
type ScopeSort int
type Untyped struct{ ... }

func (c *Config) DetailVersion() string
func (c *Config) Digest() *schema.Node
func (c *Config) FieldKinds(suffix string) map[string][]string
func (c *Config) KindContainer(kind string) []string
func (c *Config) KindContainers(kind string) [][]string
func (c *Config) Path() string
func (c *Config) Platform() Platform
func (c *Config) Root() *Element
func (c *Config) Version() string
func (c *Config) Walk(fn func(Event) bool) error
func (c *Config) WalkPaths(fn func(Event) bool) error
func (e *Element) Attr(name string) string
func (e *Element) Child(name string) *Element
func (e *Element) ChildrenNamed(name string) []*Element
func (e *Element) Find(path ...string) []*Element
func (e *Element) InstancePath() string
func (e *Element) Members() []string
func (e *Element) SchemaPath() string
func (e *Element) TextOr(fallback string) string
func (p Platform) String() string
func (r Report) HasUnknown() bool
func (r Report) String() string
func (s Scope) String() string
func Load(path string) (*Config, Report, error)
func ParseScope(s string) (Scope, error)
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **A reference edge carries candidate kinds, never one resolved kind.** Of 2,961
  reference fields, 1,034 declare more than one and the worst declares 153. The
  schema alone cannot say which kind a target is. `TestReferenceFieldCensus` pins
  these; they moved once when scope-relative targets started parsing, and two code
  comments went stale unnoticed.
- **Keywords are never edges.** `any`, `application-default` and `none` appear in
  reference fields and name no object. The list is explicit, because a field can
  accept `any` without declaring it as an enum value.
- **A `memberof` declaration is not always a reference.** Classify on the `#`
  prefix. Two earlier classifiers undercounted: one treated any parenthesis as a
  computed expression and misfiled 1,561 conditional references; the other treated
  every `#myentry(` anchor as a template variable and discarded 1,413 scope-relative
  object references, every zone target among them.
- **A named choice or union owns a path segment; an anonymous one does not.**
  `Fields()` flattens both, which is right for the grammar and wrong for the file:
  `profile-setting` is a named union and a real element, so flattening it leaves a
  path that matches nothing. `PathFields` flattens only the anonymous ones. The
  firewall schema has 358 named and 325 anonymous.
- **Stop at a nested entry array by kind, never by element name.** An element named
  `entry` is not always an entry list: `prefix-list` holds
  `<prefix><entry><network/></entry></prefix>`, where `entry` has no name attribute
  and is a plain sequence. Attributing on the name puts the edge on the wrong object.
- **A reference value is always an element's text.** A member list needs no special
  case — its path ends at `member` and the descent visits each `<member>` sibling in
  turn. Reading `Members()` instead silently drops every scalar reference.
- **The element tree peaks near ten times the file size.** A 200 MB export implies
  roughly 2 GB. Streaming per device group is not yet designed.

## See also

- `config/load.go`, `config/tree.go`, `config/walk.go`
- `internal/schema/refs.go` — target classification and the census
- [schema-codegen](schema-codegen.md) — where the digest comes from
- [panorama-semantics](panorama-semantics.md) — what `resolve` builds on this
