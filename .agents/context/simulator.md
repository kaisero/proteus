# simulator

Validated against 54cfdf9 on 2026-09-29 · Purpose: how a simulation runs as stages, how certain its answer is, and how to trace one after the fact.

## Purpose & responsibilities

`simulate` is the framework of spec §11: a run of named stages over one flow, each
declaring its fidelity. It is a leaf (R12). `simulate/securitypolicy` answers which
rule one flow hits on one device; `simulate/routing` (spec §17) which firewalls a
packet crosses; `simulate/nat` (spec §18) the NAT rule and the translated packet on
one firewall. `simulate/nat` is also the NAT engine routing and securitypolicy
call; `simulate/topology` and `simulate/policy` are leaf packages they share. `estate.Simulations` is the registry; the command makes one
`simulate <kind>` subcommand per entry, from `kindCommands` when a kind needs its own
flags (routing). `runlog` records each stage.

## How it works

### Fidelity

Four levels, strongest first: **exact**, **overmatch**, **inferred**, **undermatch**.
`Weakest` takes the highest level and merges reasons and skipped dimensions. A run's
fidelity is `Overall(stages)`, computed, never asserted. `NotEvaluated(dims...)` is
overmatch naming what was skipped: skipping a matching dimension can only add
candidates. The zero value is undeclared, and the stepper fails a run on it.

### The stepper

`Execute(ctx, kind, state, steps, keepBitmaps, log)` runs `Step`s in order. Each
returns an `Outcome`: fidelity, detail, unresolved entries, the candidate set after it,
and debug lines. The stepper records a `Stage` (count, elapsed, bitmap when kept),
logs one `[STEP]` line at info and the debug lines at debug, wraps errors as
`kind/slug`, and stops on a cancelled context.

### securitypolicy

Eight stages, each ANDing into the running candidate set:

| Slug | Fidelity |
|---|---|
| `resolve-source`, `resolve-destination` | exact for an address; inferred for an FQDN resolved by this machine's DNS; undermatch for an FQDN with no address or any unresolved value |
| `derive-zones` | exact when given; inferred when derived (forwarding table or configuration); not evaluated when no zone was found |
| `match-service` | exact; overmatch naming rules kept for `application-default`, a predefined service or no service; not evaluated without `--port` |
| `match-url` | exact; overmatch naming rules kept for a category the configuration does not define; not evaluated without `--url` when a candidate names a category |
| `drop-disabled`, `order` | exact |
| `first-match` | not evaluated: application (and user when given) |

Negated rules are inverted in the resolve stages. A rule without a category matches
any URL. Relevance (S14) comes from the zone locator: a route more specific than a
default covering either endpoint.

### routing

Reads every device's interface state, FIB and RIB through `simulate.Network`
(`estate.NewNetwork` over the store; an HA pair is one node, paired by serial) and a
path device's configuration through `Env.Load`. `routing.Topology` is built once:
address owners, connected nets, a `bart` table per router, and `Place` (connected,
else the most specific non-default route, walking on while that route leads to
another node; ties and default-only are `ChoiceError`, exit 2).

| Slug | Fidelity |
|---|---|
| `place` | exact (connected, `--device`); inferred (routed); undermatch when a device cannot be read |
| `hop<N>/pbf` | exact; inferred when a PBF rule could take the packet or on a version gap; not evaluated without configuration |
| `hop<N>/lookup` | exact; undermatch on ECMP (lowest next hop followed) or an unknown `nh_type` |
| `hop<N>/zones` | exact |
| `hop<N>/nat` | exact; inferred when a NAT rule could translate, or after an earlier hop could |
| `hop<N>/next` | exact; undermatch when the path leaves the estate or by an interface; unresolved for two owners, over 16 hops |

### nat

`nat.Match(Input)` finds the first rule that surely matches the pre-NAT packet, the
doubts above it (N11) and the excluded rules with their field; `nat.Rules` places
each bi-directional rule's implicit destination rule directly after it (verified on
fw01). `nat.Translate` gives the source candidates (port "assigned at runtime" for
DIPP), the destination with its port, first-to-first for static ranges, and the
post-NAT lookup. The `nat` kind's stages: `place`, `pbf`, `lookup`, `match`,
`translate`, `post-lookup`. Routing's `nat` stage calls the engine and replaces the
hop's egress after a destination NAT; the policy simulation's `derive-zones` runs it per source
zone for the post-NAT destination zone.

`Run.Output` is `routing.Path`: `Hops` (one per device and vsys; a vsys crossing
splits through the external zones), `Outcome`, `End`, `Hidden` (off-path devices
with interfaces without a router).

## Build / run pointers

- `go test ./simulate/... ./runlog`
- `./bin/panos-analyst simulate policy <src> <dst> --file <cfg> --why`
- `./bin/panos-analyst simulate routing <src> <dst> --why` (needs fetched devices)
- `./bin/panos-analyst simulate nat <src> <dst> --device <fw> --port <p> --why`
- `scripts/device-probe.sh --nat <device> <router> <src,dst,port>...` against the device
- `--log-level debug`, then `grep '\[STEP\]'` in the run log: the rules each stage left.

## Public API

<!-- GENERATED:api ./simulate -->
```go
type ChoiceError struct{ ... }
type DeviceData struct{ ... }
type Endpoint struct{ ... }
type Env struct{ ... }
type Fidelity struct{ ... }
type Flow struct{ ... }
type Forward struct{ ... }
type Input struct{ ... }
type Match struct{ ... }
type Network interface{ ... }
type Outcome struct{ ... }
type Port struct{ ... }
type Run struct{ ... }
type Simulation interface{ ... }
type Stage struct{ ... }
type StageState struct{ ... }
type Step[S any] struct{ ... }
type Target struct{ ... }

func (e *ChoiceError) Error() string
func (e Endpoint) String() string
func (f Fidelity) Declared() bool
func (f Fidelity) Level() string
func (f Fidelity) MarshalJSON() ([]byte, error)
func (f Fidelity) Reasons() []string
func (f Fidelity) Skipped() []string
func (f Fidelity) String() string
func (m Match) First() resolve.FIBRoute
func (p Port) Link() netip.Prefix
func Addr(a netip.Addr) Endpoint
func Execute[S any](ctx context.Context, kind string, state *S, steps []Step[S], keepBitmaps bool, log *runlog.Logger) ([]Stage, error)
func NotEvaluated(dimensions ...string) Fidelity
func OverMatchBecause(reason string) Fidelity
func Overall(stages []Stage) Fidelity
func UnderMatch(reason string) Fidelity
func Weakest(fs ...Fidelity) Fidelity
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./simulate/securitypolicy -->
```go
type Relevance struct{ ... }
type Simulation struct{}
type Verdict struct{ ... }
type ZoneDerivation struct{ ... }

func (Simulation) Describe() string
func (Simulation) Kind() string
func (Simulation) Run(ctx context.Context, env *simulate.Env, in simulate.Input) (simulate.Run, error)
func (Simulation) Stages() []string
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./simulate/routing -->
```go
type Hop struct{ ... }
type Lookup struct{ ... }
type NotFollowed struct{ ... }
type Outcome string
type Path struct{ ... }
type Simulation struct{}

func (Simulation) Describe() string
func (Simulation) Kind() string
func (Simulation) Run(ctx context.Context, env *simulate.Env, in simulate.Input) (simulate.Run, error)
func (Simulation) Stages() []string
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./simulate/nat -->
```go
type Doubt struct{ ... }
type Excluded struct{ ... }
type Input struct{ ... }
type MatchResult struct{ ... }
type Result struct{ ... }
type Rule struct{ ... }
type Simulation struct{}
type Translation struct{ ... }

func (Simulation) Describe() string
func (Simulation) Kind() string
func (Simulation) Run(ctx context.Context, env *simulate.Env, in simulate.Input) (simulate.Run, error)
func (Simulation) Stages() []string
func FQDNs(in Input, r *Rule) []string
func Match(in Input) MatchResult
func Rules(t *resolve.Target) []Rule
func Translate(in Input, m MatchResult) Result
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./simulate/topology -->
```go
type Placed string
type Placement struct{ ... }
type Topology struct{ ... }

func (t *Topology) Connected(a netip.Addr) []simulate.Port
func (t *Topology) Forward(node, router string, a netip.Addr) simulate.Forward
func (t *Topology) Interface(node, name string) (simulate.Port, bool)
func (t *Topology) Lookup(node, router string, a netip.Addr) (simulate.Match, bool)
func (t *Topology) Nodes() []string
func (t *Topology) Owners(a netip.Addr) []simulate.Port
func (t *Topology) Peers(out simulate.Port, nh netip.Addr) []simulate.Port
func (t *Topology) Place(src netip.Addr) (Placement, error)
func (t *Topology) Routers(node string) []string
func (t *Topology) Start(node, router string, src netip.Addr) (simulate.Port, bool, error)
func NewTopology(devs []simulate.DeviceData) *Topology
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./simulate/policy -->
```go
type Vsys struct{ ... }

func (v Vsys) Holds(value string, a netip.Addr) bool
func (v Vsys) PBF(src, dst netip.Addr, in simulate.Port) (rule resolve.PBFRule, note string, ok bool)
func (v Vsys) Sides(rb resolve.Rulebase, src, dst netip.Addr, negated func(int) (bool, bool)) (*roaring.Bitmap, *roaring.Bitmap)
func FromFits(r resolve.PBFRule, in simulate.Port) bool
func Load(load func(device, vsys string) (simulate.Target, error), device, vsys string) (Vsys, bool)
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./runlog -->
```go
type Level int
type Logger struct{ ... }
type Options struct{ ... }
type Tag string

func (l *Logger) AddSecret(s string)
func (l *Logger) Close() error
func (l *Logger) Debugf(tag Tag, format string, args ...any)
func (l *Logger) Enabled(lv Level) bool
func (l *Logger) Errorf(tag Tag, format string, args ...any)
func (l *Logger) Infof(tag Tag, format string, args ...any)
func (l *Logger) Path() string
func (l *Logger) Warnf(tag Tag, format string, args ...any)
func (lv Level) String() string
func Discard() *Logger
func Open(o Options) (*Logger, error)
func ParseLevel(s string) (Level, error)
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **A derived zone is inferred, even from the forwarding table.** The source zone is
  the arrival interface's zone, which a table only predicts (PAN-OS "Packet Flow
  Sequence").
- **A default route does not place a source.** A source placed only by a default
  route leaves the source zone open (not evaluated). Measured on fw01 on 2026-09-29:
  derived zones agreed with the device for 3 of 7 probe flows (given zones: 7 of 7).
  The misses came from overlay routing the forwarding table does not show: traffic
  arriving on a tunnel zone whose source a specific route places elsewhere, and a
  destination the device sends by policy-based forwarding.
- **Keep what cannot be judged.** Dropping a rule the configuration cannot evaluate
  silently under-matches; keeping it over-matches and says so.
- **The core never logs.** `config`, `resolve`, `index` stay free of I/O (R12);
  `simulate` receives the log through `Env`.
- **`Run.Output` is `any`.** Each kind documents its type; securitypolicy's is
  `Verdict`, routing's `routing.Path`.
- **Routing applies NAT and detects PBF.** The stages run in packet-flow order
  (pbf, lookup, zones, nat); a destination NAT adds a post-NAT lookup to the hop
  (`routing.TestDestinationNAT`).
- **NAT matches the pre-NAT packet, security policy the post-NAT zones.** Both
  verified on fw01 with real traffic (spec §18 F5, F6); the fixtures
  `testdata/opdata/fw01-nat-policy-match.tsv` hold the device's answers and
  `nat.TestTheRuleFw01Named` replays them.
- **Unverified shapes fail conservative.** The lab has no HA pair, multi-vsys,
  discard or next-lr route: an unknown `nh_type` is unresolved, an HA state short of
  a confirmed pair is not followed (spec §17.2).

## See also

- [commands](commands.md), [questions](questions.md), [providers](providers.md)
- spec §11 and §17, plans `docs/plans/2026-09-29-panos-analyst-m4-simulator.md`,
  `docs/plans/2026-09-29-panos-analyst-routing.md`
