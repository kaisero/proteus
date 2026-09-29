# proteus

> Read a PAN-OS firewall configuration file and answer questions about it. This
> is the read-first map for coding agents working in-repo: the system model and
> where each subsystem is documented. Load only the deep-dive you need.

## System technical design

proteus is read-only. It loads a configuration file, resolves PAN-OS
semantics over it, and builds lookup structures that answer two questions fast:
*does an object with this value exist*, and *which rules can this value reach*.
It never writes a configuration, and the core never opens a network connection.
Above the core, `inventory`, `fetch` and `store` read devices into on-disk
snapshots; see [fetch-and-store](fetch-and-store.md).

Three packages, dependency order strictly one-way — `config` <- `resolve` <- `index`:

- **`config`** — the file. `Load(path)` parses the XML into an element tree and
  attaches the schema digest for that PAN-OS version. It answers schema questions:
  which object kinds a field may name (`FieldKinds`), where a kind sits under a
  scope (`KindContainer`), and every reference edge in the file (`WalkPaths`).
- **`resolve`** — PAN-OS semantics. Targets per vsys, rule order, scoped object
  visibility with shadowing, group membership including tag filters, URL pattern
  parsing, zones and routes.
- **`index`** — speed and answers. `For(cfg, scope)` builds an immutable, cached
  index: a prefix trie, group-closure bitmaps, rule-field bitmaps and a reference
  table. It exposes the lookups and the report that comes with them.
  The reference edges are read once per configuration and cached as an edge list
  (`edgesOf`); a scope's index holds positions into it, never its own copies, and
  still sees only its own scope and shared. The list is a materialisation of the
  file, not an index — it answers no question and is keyed by nothing — so R10
  still holds, and `TestNoGlobalIndex` is what proves it.

Control flow for the main question, "which rules can this value reach":

`index.For(cfg, scope)` builds once per `(file, scope)` and caches. A query goes
to `View.Candidates(field, value)`, which asks each **resolver** wired to that
field to turn the value into object names. The schema decides that wiring:
`config.FieldKinds("rulebase/security/rules")` says which object kinds a field
accepts, and a kind maps to the resolver that can answer for it. Matched names
expand through the group closure, become interned ids, and index into the
rule-field bitmaps. The rules whose field is `any` join them. The result is a
`roaring.Bitmap` of rule positions plus a `Report`.

Repo map:

- `internal/config/` — `load.go` (Load, Panorama refusal, digest cache), `tree.go` (element tree),
  `walk.go` (reference walk, `FieldKinds`, `KindContainers`), `embed.go`,
  `schemadigest/` (embedded digests).
- `internal/resolve/` — `target.go`, `rules.go`, `objects.go`, `groups.go`,
  `filter.go` (tag filters), `urlpattern.go`, `profiles.go`, `zones.go`.
- `internal/index/` — `index.go` (build + cache), `candidates.go` (the driver),
  `resolver*.go` (one file per value space), `closure.go`, `cidr.go`, `rules.go`,
  `refs.go`, `profileuse.go`, `snapshot.go`, `intern.go`.
- `internal/schema`, `internal/digest` — schema parsing and the digest format;
  `internal/tools/schemadigest` — the dev tool that writes a digest. `internal/archtest` — the R12 import check.
- `internal/estate/` — selectors and a time to targets and holes; `internal/search/` — five-stage findings for one term; `internal/card/` — the whole element behind one name, for `lookup`; `internal/drift/` — changes between two configurations.
- `internal/inventory/` — the YAML device list and credentials; `internal/fetch/` — the read-only XML
  API client and the `Document` list; `internal/store/` — timestamped snapshots, `latest`.
- `cmd/proteus` — `main` only; the commands (fetch, snapshots, search, lookup,
  simulate) live in `internal/cli`.
- `scripts/` — `coverage-gate.sh`, `device-probe.sh`, `context-api.py`.

Hard invariants:

- **An `Index` is immutable and shared.** It is cached per `(file, scope)` and
  handed to every caller. A query must never write to it — not even to intern a
  name. Use `Interner.Lookup`, never `Interner.ID`, on any query path.
- **The read-only core performs no I/O beyond reading the configuration file.** Facts a
  file does not hold arrive through `Providers`, which the caller fills.
- **An answer that is incomplete says so.** A non-empty `Report.Unresolved` means
  matches are missing, with the reason. Silence is a wrong answer.
- **Reachability is not a verdict.** The index says which rules a value can
  reach. Intersecting sides, dropping disabled rules and deciding what a first
  match means belong to the caller.

## Subsystem deep-dives

- [config-loading](config-loading.md): `Load`, the element tree, the embedded
  schema digest, and the schema questions `config` answers.
- [scope-semantics](scope-semantics.md): targets, rule order, scoped visibility,
  shadowing, group membership.
- [simulator](simulator.md): `simulate`, `internal/simulate/securitypolicy`, `internal/simulate/routing`, `internal/simulate/nat`, `internal/simulate/topology`, `internal/simulate/rulebase`, `runlog` — the staged simulator, fidelity, the routing path, NAT, and the run log.
- [questions](questions.md): `estate`, `search`, `card`, `drift` — how a question becomes targets, findings, cards and changes.
- [fetch-and-store](fetch-and-store.md): the inventory, the read-only fetcher, and
  the snapshot store.
- [value-spaces](value-spaces.md): the resolver seam, the four paths that reach a
  value, and each implemented value space.
- [reporting](reporting.md): `Report`, `Hit`, `Unresolved`, and the difference
  between recognised-and-unmatched and not-recognised.
- [providers](providers.md): facts a configuration does not hold, the `View`, and
  the user snapshot format.
- [schema-digest](schema-digest.md): the digest, where it comes from, and the
  reference census.
- [commands](commands.md): `proteus` and its subcommands.
- [testing-and-gates](testing-and-gates.md): `make ci`, the coverage ratchet, the
  fixtures, and the device probe.

## Cross-cutting

- [decisions](decisions.md): the design-decision log and the rationale, including
  the ones reversed after measurement.

## Rules

The binding rules live in [`AGENTS.md`](../../AGENTS.md) at the repo root — R1 to
R12, each with a check. This set explains mechanism and rationale, not rules.
`ARCHITECTURE.md` holds the reasoning behind the design as a whole.
