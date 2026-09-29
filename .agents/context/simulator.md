# simulator

Validated against 755542d on 2026-09-29 · Purpose: how a simulation runs as stages, how certain its answer is, and how to trace one after the fact.

## Purpose & responsibilities

`simulate` is the framework of spec §11: a run of named stages over one flow and one
device, each declaring its fidelity. It is a leaf (R12). `simulate/securitypolicy` is
the first simulation. `estate.Simulations` is the registry; the command makes one
`simulate <kind>` subcommand per entry. `runlog` records each stage.

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

## Build / run pointers

- `go test ./simulate/... ./runlog`
- `./bin/panos-analyst simulate secpolicy <src> <dst> --file <cfg> --why`
- `--log-level debug`, then `grep '\[STEP\]'` in the run log: the rules each stage left.

## Public API

<!-- GENERATED:api ./simulate -->
```go
type Endpoint struct{ ... }
type Env struct{ ... }
type Fidelity struct{ ... }
type Flow struct{ ... }
type Input struct{ ... }
type Outcome struct{ ... }
type Run struct{ ... }
type Simulation interface{ ... }
type Stage struct{ ... }
type StageState struct{ ... }
type Step[S any] struct{ ... }
type Target struct{ ... }

func (e Endpoint) String() string
func (f Fidelity) Declared() bool
func (f Fidelity) Level() string
func (f Fidelity) MarshalJSON() ([]byte, error)
func (f Fidelity) Reasons() []string
func (f Fidelity) Skipped() []string
func (f Fidelity) String() string
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
- **Keep what cannot be judged.** Dropping a rule the configuration cannot evaluate
  silently under-matches; keeping it over-matches and says so.
- **The core never logs.** `config`, `resolve`, `index` stay free of I/O (R12);
  `simulate` receives the log through `Env`.
- **`Run.Output` is `any`.** Each kind documents its type; securitypolicy's is
  `Verdict`.

## See also

- [commands](commands.md), [questions](questions.md), [providers](providers.md)
- spec §11, plan `docs/plans/2026-09-29-panos-analyst-m4-simulator.md`
