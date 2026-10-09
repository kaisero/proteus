# commands

Validated against 9e7d9b7 on 2026-10-08 · Purpose: the proteus command, what each subcommand is for, and which one to reach for.

## Purpose & responsibilities

`proteus` is the product and the one command surface: it fetches devices
into the store and answers questions of them. It is the only binary; the one
developer tool, `internal/tools/schemadigest`, runs through `make schema-digest`
(see [schema-digest](schema-digest.md)). Spec:
`docs/specs/2026-09-27-panos-analyst-scope.md` §15.

`make build-local` builds `bin/proteus`. `make build` cross-compiles it for
linux/amd64.

## proteus

```
fetch <device>... | --label k=v | --all     log in, fetch six documents, store a snapshot (--why: stages)
inventory init                              write an inventory template, mode 0600
snapshot list <device>                      snapshots, newest first; * marks latest
snapshot show                               per device and vsys: snapshot, age, version, rules
snapshot diff [--from] [--to]               objects and rules added, removed, changed
search <term>                               every place a value or name appears
lookup <name>                               the whole rule or object behind a name
simulate policy <src> <dst>                 does the estate allow the flow along its path (--file: one configuration)
simulate routing <src> <dst>                the firewalls a packet crosses, hop by hop
simulate nat <src> <dst> --device <fw>      the NAT rule and the translated packet
```

- **Two question verbs.** `search` answers "where does this appear" in five stages:
  objects by value, objects by name, groups, references, literals. Rules whose field
  is `any` are not in it; `simulate` answers "what would this traffic hit".
- **Selectors** on `search`, `lookup` and `snapshot`: `--device`, `--label k=v`
  (AND), `--vsys`, `--at <time>`, `--fresh`, `--file <config.xml>`. No selector means
  every device. The `simulate` commands take their own subsets (below).
- **Search modes:** the term's type sets the match (address covers, prefix overlaps,
  port covers, URL by tokens, else exact); `--exact`, `--within`, `--contains`
  override. Filters: `--kind`, `--field`, `--show objects,groups,refs,literals`,
  `--direct`.
- **`lookup <name>`** prints a rule as the rule editor lays it out, or an object
  with its value, members and holding groups. The kind is inferred; a name several
  kinds share exits 2 until `--kind` picks one; found nowhere exits 0 with empty
  `results`. `--expand`
  shows values in parentheses and groups as trees (three levels); lists stop at five
  items unless `--full`. See [questions](questions.md).
- **`simulate <kind>`** has one subcommand per kind registered in
  `estate.Simulations`, each from its own builder in `kindCommands`
  (`TestEveryKindHasACommand`). See [simulator](simulator.md).
- **`simulate policy <src> <dst>`** (`cli/policypath.go`, `query/policy.go`) has two modes (spec
  2026-10-07 §3). **Path mode**, the default: routing's path from the start
  (`--device` names it, `--router` picks its router), the security check on every
  hop with the hop's flow and zones (`pathpolicy.Run`), one verdict `allowed`,
  `denied` or `undecided` with the hop that set it. Text: verdict line, routing
  boxes with a `policy` row (and `doubt` rows), `--why` per hop. Exit 3 when
  undecided. `--vsys`, `--label`, `--from-zone`, `--to-zone`, several `--device`,
  `--router` without `--device`, `--each` (fan-out, M5b) exit 2; `--fresh` and
  `--all-devices` are not registered. An FQDN traces its first IPv4 address; with
  `--no-dns` or no address, exit 2. The loader opens the snapshot each routing hop
  used (HA: the active member). **`--file`**: one configuration, `--vsys`, zones
  given (both) or derived, no NAT; `--device`, `--label`, `--at`, `--router` exit 2.
  Its text ends with `first match: <rule> (<action>)` or `first certain match:` and
  `undecided:`. Both modes share one JSON security block (`securityJSON`).
  `scripts/device-probe.sh <config> <vsys>` reads the `--file` text;
  `--path <flows-file>` compares each decided hop with the hop device's
  `test security-policy-match`.
- **`simulate nat <src> <dst> --device <fw>`** (own command via `kindCommands`):
  `--router`, `--port`, `--protocol`, `--from-zone` or `--from-interface`, `--why`,
  `--no-dns` (resolves no FQDN at all, also a translated destination's). A source
  of `-` is any. `--device` is required (exit 2 without it); exit 2 for a device
  not in the inventory, several routers, IPv6; a device without a snapshot is a
  hole (exit 3).
- **`simulate routing <src> <dst>`** (or `<dst> --device <name> [--router]`) has
  its own command (`kindCommands`): no selectors but `--device`, `--at`, `--rib`,
  `--why`. It reads every inventory device's stored interfaces and tables, draws a
  box per firewall and vsys, and exits 2 for a start it cannot choose (ties,
  default-only, several routers, IPv6); a start device without a snapshot is a hole
  (exit 3). `scripts/device-probe.sh --routing <device>
  <router> <dst>...` checks its first lookup against the device.
- **Output:** `--output text|json|yaml`. JSON and YAML are the same envelope:
  `format` (1), `command`, `input`, `results` (always an array), `holes`,
  `unresolved`, `notes`. Every note the text shows is in `notes` too.
- **Colour:** `--color auto|always|never` (also `PROTEUS_COLOR`, inventory `color:`),
  default `auto`. JSON and YAML are never coloured. `NO_COLOR`, `CLICOLOR_FORCE` and
  `TERM=dumb` act on `auto` only; `auto` colours a terminal and nothing else.
  Colour follows meaning (`palette`: bad, warn, ok, head, dim, accent), wraps one
  token or cell, never a line; columns go through `table`, which aligns by visible
  width.
- **Exit codes** (spec §4.1): 0 complete, possibly empty; 1 no answer; 2 the command
  line must change (unknown command, flag or topic, bad setting, a device not in the
  inventory, an empty selection); 3 holes or unresolved; 130 SIGINT; 143 SIGTERM.
  `fetch`: all stored 0, a failure with one device stored 3, none stored 1; it
  prints its answer in all three.
- **Errors on stderr:** text mode prints `proteus: <message>` and `log: <path>`. In
  JSON and YAML mode the last stderr line of a non-zero exit is one JSON object,
  `{"format":1,"exit":N,"error":…,"log":…}`, also for command-line errors.
- **A new command** builds an `answer` (`Command`, `Input`, `Results`,
  `Qualifiers`, `Text`) and ends its `RunE` with `a.emitRun(a.runX(...))`. It never
  writes to stdout itself; `emit` renders the format, logs the `answer:` line and
  sets the exit from the qualifiers. It also needs a row in `contractRows`
  (`contract_test.go`) and goldens.
- **`fetch --why`** prints each device's stages, `resolve`, `login`, `ha`,
  `documents`, `store`, with status (`ok`, `partial`, `skipped`, `failed`) and
  detail; JSON always carries them as `stages`. On a terminal a progress line per
  finished stage goes to stderr.
- **Settings**, rising precedence default < inventory `defaults:` < `PROTEUS_*` <
  flag: inventory path, store root, `max_snapshot_age`, output, color, and the run log's
  `log_level`, `log_dir`, `log_keep` (plus `--verbose`). `PROTEUS_USERS` names a user
  snapshot; a stored forwarding table supplies zones.
- **Run log:** one file per run under `log_dir`, `<time> [<LEVEL>] [<TAG>] <msg>`,
  tags `RUN`, `API`, `SNAP`, `FIND`, `STEP`; secrets redacted; the path is printed
  when a run exits non-zero. Help, completion and a bare group write no log and
  ignore a bad setting. The core never logs; `runlog` is used above it.

## Build / run pointers

- `make build-local` — `bin/proteus` for this machine.
- Fixtures live in `testdata/config/`; with `--file` no command needs a device.

## Public API

`cmd/proteus` is `main` only; the commands live in `internal/cli` behind
`cli.Run`.

**Query layer** (`internal/query`, spec 2026-10-09 §3.7). Each question is a
function from a typed input and an `Env` to a typed `Envelope[In, Res]`: the
command line and the MCP server call the same functions. `cli` keeps Cobra, the
flags, the text renderers, `emit` and the exit codes, and wraps each envelope in
a local type that implements `answer`. A full result keeps the native values the
renderers need in `json:"-"` fields, and the envelope keeps every target read
(`Targets`). Input rules live in each input's `Validate()`; a refused input is a
`*query.UsageError` with code `call.usage`, the command line's `Text`, and a
`ToolText` with the input's field names where `Text` names a flag. `cli` maps it
to exit 2. A choice only the user can make stays a `*simulate.ChoiceError`,
whose `Kind` says what is chosen (`device`, `router`, or empty for a question
with no choice).

<!-- GENERATED:api ./internal/query -->
```go
type Check struct{ ... }
type Checks []Check
type DiffInput struct{ ... }
type DiffResult struct{ ... }
type Env struct{ ... }
type Envelope[In, Res any] struct{ ... }
type Finding struct{ ... }
type FlowInput struct{ ... }
type LookupInput struct{ ... }
type LookupResult struct{ ... }
type NATInput struct{ ... }
type NATResult struct{ ... }
type Note struct{ ... }
type PathHop struct{ ... }
type PathResult struct{ ... }
type Point struct{ ... }
type PolicyFileInput struct{ ... }
type PolicyInput struct{ ... }
type RoutingInput struct{ ... }
type RoutingResult struct{ ... }
type Rule struct{ ... }
type SearchInput struct{ ... }
type Security struct{ ... }
type SecurityResult struct{ ... }
type Selection struct{ ... }
type Stage struct{ ... }
type Summary struct{ ... }
type Target struct{ ... }
type Unresolved struct{ ... }
type UsageError struct{ ... }

func (cs Checks) MarshalJSON() ([]byte, error)
func (e *UsageError) Error() string
func (e *UsageError) Unwrap() error
func (in DiffInput) Validate() *UsageError
func (in LookupInput) Validate() *UsageError
func (in NATInput) Validate() *UsageError
func (in PolicyFileInput) Validate() *UsageError
func (in PolicyInput) Validate() *UsageError
func (in RoutingInput) Validate() *UsageError
func (in SearchInput) Matching() string
func (in SearchInput) Validate() *UsageError
func Detail(f search.Finding) string
func Lookup(ctx context.Context, env Env, in LookupInput) (Envelope[LookupInput, LookupResult], error)
func NAT(ctx context.Context, env Env, in NATInput) (Envelope[NATInput, NATResult], error)
func NoteOf(device, vsys string, r reason.Reason) Note
func PointHop(r pathpolicy.Result) (routing.Hop, bool)
func Policy(ctx context.Context, env Env, in PolicyInput) (Envelope[PolicyInput, PathResult], error)
func PolicyFile(ctx context.Context, env Env, in PolicyFileInput) (Envelope[PolicyFileInput, SecurityResult], error)
func Routing(ctx context.Context, env Env, in RoutingInput) (Envelope[RoutingInput, RoutingResult], error)
func Search(ctx context.Context, env Env, in SearchInput) (Envelope[SearchInput, Finding], error)
func SimStages(stages []simulate.Stage) []Stage
func SnapshotDiff(ctx context.Context, env Env, in DiffInput) (Envelope[DiffInput, DiffResult], error)
func Summarize[In, R, S any](e Envelope[In, R], f func(R) S) Envelope[In, S]
func SystemCanonicalName(ctx context.Context, name string) (string, error)
func SystemResolve(ctx context.Context, name string) ([]netip.Addr, error)
func TargetOf(t estate.Target) Target
func TargetQualifiers(ts []estate.Target) ([]Unresolved, []Note)
func Targets(ctx context.Context, env Env, sel Selection) ([]estate.Target, []estate.Hole, error)
func UnresolvedOf(device, vsys string, r reason.Reason) Unresolved
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **Commands hold no matching logic.** They compose package calls: `estate` for
  targets, `search` for findings, `drift` for changes, `index` for candidates. The
  four paths live in `internal/index/candidates.go` and nowhere else.
- **An incomplete answer exits 3.** A hole or an unresolved entry is printed and
  sets the exit code; a script must be able to refuse to act on it.
- **A version gap is unresolved, a stale snapshot is a note.** The first can make
  an answer miss rules; the second only qualifies it. `simulate policy` is the
  exception (E25): the gap is a note and the check is `inferred`.

## See also

- `internal/cli/`, `cmd/proteus/main.go`
- `QUICKSTART.md` — the same commands, task by task, with output
- [fetch-and-store](fetch-and-store.md) — what `fetch` and the store do
- [reporting](reporting.md) — what `Unresolved` means
