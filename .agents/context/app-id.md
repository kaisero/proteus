# app-id

Validated against 4236df4 on 2026-10-17 · Purpose: how the App-ID data of a device gets from the firewall into a content file, and how the simulator, search, lookup and the MCP server use it.

## Purpose & responsibilities

A configuration names applications, application groups, filters and containers,
but the predefined applications and their metadata live in the App-ID content the
firewall downloads. `internal/appid` owns that data as one file per content
version: the format in both directions, the parser, and the questions about one
application (filter selection, containers, implicit use, default ports). It is a
leaf: it imports only the standard library and `internal/reason` (AGENTS.md R12).
Spec `docs/specs/2026-10-16-app-id-design.md` (§, F, S, I, P, O numbers below),
plan `docs/plans/2026-10-16-app-id.md` (C and D numbers).

## How it works

### The data path

```
fetch: applications step ──trim──> Result.Apps.File
cli: store step ──WriteContent──> <store>/.content/<app-version>.v<trim>.xml.gz
                                  meta.json "app_version"
estate: Target.Apps (lazy) ──appid.Load──> *appid.Data
query: appsFor ──> index.Providers.Apps ──> securitypolicy, search, card
mcp: one LRU item per content version (contentBytes)
```

- **Fetch** (`internal/fetch/applications.go`): the step `applications` runs after
  `documents`. It reads `System.AppVersion`, asks the store's `HaveContent`
  (a hit touches the file), and on a miss runs the two show commands of F1
  through `opStream`, trimming each stream with `appid.Trim`. A refusal gives
  `note.fetch-applications-missing` (exit 0); a transport failure an outcome
  named `applications` (exit 3); containers that fail leave a file that records
  them as missing. See [fetch-and-store](fetch-and-store.md).
- **Store** (`internal/store/content.go`): `WriteContent` (temporary file, sync,
  rename; mode 0600 in a 0700 `.content/`), `PruneContent` once per run after every
  device (a file no `meta.json` names and older than one hour), `ContentPath`,
  `Snapshot.ContentPath`. The CLI sets `Meta.AppVersion` only after a hit or a
  successful write (D4); a failed write exits 3.
- **Estate and query**: `estate.Target.Apps` loads the snapshot's file, or with
  `--file` `apps.xml.gz` beside the configuration (`estate.AppsFile`,
  `note.app-data-file`). `query` loads it only when the question needs it (D11),
  once per file per question (`appMemo`); a missing or damaged file gives
  `note.app-data-missing` and the answer as without data.
- **Index** (`resolver_app.go`): with `Providers.Apps`, the application value
  space answers predefined applications, the filters that select one and the
  containers that hold one; each hit keeps its scope (custom and filter: the
  configured scope; content: `config.ScopePredefined`). Without it,
  `gap.application-filter` and `gap.application-container`.
- **Simulator** (`securitypolicy`): the stage `match-application` and the two
  passes of `firstMatch`; `application-default` in `match-service`. See
  [simulator](simulator.md).
- **Search, lookup, diff, MCP**: see [questions](questions.md) and
  `docs/guides/mcp.md`.

### The content file

`<store>/.content/<app-version>.v<trim>.xml.gz`, for example
`8000-1000.v1.xml.gz`. `appid.FileName` builds the name, `appid.ValidVersion`
(`^[0-9]+-[0-9]+$`) guards it, `appid.TrimVersion` is `<trim>`. One gzip XML
document:

```
<content version="8000-1000" trim="1" containers="missing"?>
  <application><entry name="…">…</entry>…</application>
  <application-container><entry name="…"><functions>…</functions></entry>…</application-container>
</content>
```

`Trim` keeps `@name` as the only attribute (no `@minver`, §3.3) and the children
of `keptFields` (§3.2): the filter fields, `tag`, `saas`, `default`, implicit,
use and tunnel lists, container and parent, `ident-by-dport`, `ident-by-sport`,
`obsolete`, `description`, and a container's `functions`. A change to
`keptFields` increments `TrimVersion`, so old files give a miss.
`TestEveryFilterFieldHasAKeptField` fails when the digest's filter node gains a
field without a kept field. The content answer is not a configuration, so R3 does
not cover it; R8 registers the two predefined nodes and the filter-field map.

`Parse` refuses a damaged file whole: a form it cannot read is an error, never a
partial answer (`docs/todo.md` item 59).

### What `Data` answers

- `App(name)`, `Container(name)`: any case (P14); the result names the content
  name, which is lower case (F14).
- `ImpliedBy(app)`: the content applications whose `implicit-use-applications`
  hold `app` (I1). Not the reverse (I3), and never a custom application (I9).
- `ContainersOf(app)`, `HasContainers()`: nil without containers (§2.2).
- `Suggest(name, n)`: for a container its functions, else the nearest names
  (P10).
- `Filter.Selects(App)`: OR within category, subcategory, technology and risk;
  AND for tags, `saas-risk` and `saas-certifications`; AND across fields (S1-S3,
  S11). Tags match verbatim with brackets; the caller adds the configured
  `application-tag` tags (S12). `exclude` names applications and containers (S4,
  S13). `no-tag` adds no restriction (S14). Obsolete applications count (S15).
  `no-certifications` selects only an application with a `saas` block
  (`SaaS.Block`; lab run on fw02). `Selection.Via` names the selecting fields.
- `Default.Match(proto, port)`: the forms of §4.4: ports and ranges, `/secure`
  extended ports (`PortSecure`), `dynamic` and `any` (P3, P11),
  `ident-by-ip-protocol` with a range (`IPProtocolHigh`, as content 9160-10295
  on fw02 holds it), ICMP types (`PortICMP`), no default (P6). `ident-by-dport`
  and `ident-by-sport` change nothing (P12). `PortOpen` when the flow leaves the
  protocol or port open. `Default.Protocols()` gives the run's protocol (D10).
- `CustomDefault(...)`: a custom application's `default` block from the
  configuration (P7). `resolve.Applications` builds the custom `App` values.

### Decisions

| # | Decision |
|---|---|
| D1 | `appid` owns the format both ways: `Trim`, `Encode`, `Parse`, `TrimVersion`. |
| D2 | `fetch` streams through the unexported `opStream`; `do` and `opStream` share `send`; the exported client methods stay `ExportConfig`, `Keygen`, `Op`. |
| D3 | `applicationsStep` never returns an error; a transport failure is an outcome and a `partial` step, the snapshot is stored, the run exits 3. |
| D4 | The CLI store step sets `Meta.AppVersion` after a hit or a write; a failed write adds the note and exits 3. |
| D5 | The data reaches the simulator in `index.Providers.Apps`; PBF's view has empty providers, so PBF keeps `doubt.application`. |
| D6 | `match-application` runs between `derive-zones` and `match-service`, which needs it for `application-default`. |
| D7 | `firstMatch` evaluates explicit (with kept) candidates, then implicit ones, each in rule order, then the default rules; the doubt logic is unchanged. |
| D8 | A rule kept for an unknown name is an explicit candidate in doubt and never decides; the check covers the group closure and filter `exclude` lists; without containers a container name is unknown; no rule is in both passes. |
| D9 | No code for an open question: the lab closed O2, O3, O4, O6; O5 keeps the order of D7; O1 is an accepted risk. |
| D10 | `Run` takes the protocol from the application's default per check; routing, NAT and PBF see the protocol as given. |
| D11 | `query` loads data for `--application`, a name-shaped search term, or a lookup that needs application kinds; once per file per question; the MCP cache keeps it per process. |
| D12 | `search` shows nested application groups with `Index.GroupPath`. |
| D13 | An unknown or container flow application is a `ChoiceError` of kind `ChoiceApplication` with empty `Options`: a usage error with `--file`, the hop's undecided in path mode. |
| D14 | `simulate policy` passes an empty protocol with `--application` and no `--protocol`; `simulate routing` and `nat` keep `tcp`. |
| D15 | Fixtures are plain XML in `testdata/appid/`; tests gzip them; no binary fixture. |
| D16 | `securitypolicy` tests write small configurations with `appConfig`; `testdata/config/firewall-appid.xml` serves the CLI goldens. |
| D17 | The flow application is canonical before the stages; `query.Search` makes an application term canonical too. |
| D18 | The lab tool runs file mode on a copy of a fresh snapshot, with the content file as `apps.xml.gz`. |
| D19 | A protocol without ports drops rules whose service names only custom services or service groups, with and without a flow application (P13). |

## Build / run pointers

- `go test ./internal/appid ./internal/simulate/securitypolicy ./internal/index ./internal/fetch ./internal/store`
- `./bin/proteus simulate policy <src> <dst> --application ssl --port 443 --file <dir>/config.xml --why`
  with the content file as `<dir>/apps.xml.gz`
- `./bin/proteus search <application> --file <cfg>`, `./bin/proteus lookup <application> --file <cfg>`
- `make app-lab DEVICE=fw02 APPLAB_KEY_HEADER=<file>`: the lab check, by hand
  (`docs/lab/app-id-lab.md`).

## Public API

<!-- GENERATED:api ./internal/appid -->
```go
type App struct{ ... }
type Container struct{ ... }
type Data struct{ ... }
type Default struct{ ... }
type Filter struct{ ... }
type PortMatch int
type PortRange struct{ ... }
type RefusedError struct{ ... }
type SaaS struct{ ... }
type Selection struct{ ... }

func (d *Data) App(name string) (App, bool)
func (d *Data) Apps() []App
func (d *Data) Container(name string) (Container, bool)
func (d *Data) ContainersOf(app string) []string
func (d *Data) HasContainers() bool
func (d *Data) ImpliedBy(app string) []string
func (d *Data) Suggest(name string, n int) []string
func (d *Data) Version() string
func (d Default) Match(proto string, port uint16) PortMatch
func (d Default) Protocols() []string
func (d Default) String() string
func (e *RefusedError) Error() string
func (f Filter) Selects(a App) Selection
func (m PortMatch) String() string
func CustomDefault(ports []string, ipProtocol string, icmp, icmp6 bool) (Default, error)
func Encode(w io.Writer, version string, apps, containers []byte) error
func FileName(version string) string
func FilterField(name string) (string, bool)
func Load(path string) (*Data, error)
func Parse(r io.Reader) (*Data, error)
func ProtocolNumber(p string) (int, bool)
func Trim(r io.Reader, w io.Writer) (int, error)
func ValidVersion(v string) bool
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **Case.** The flow's application matches in any case (P14), but a rule names
  applications exactly: a rule naming `SSL` names an unknown name. The interner and
  `Refs` match exactly too, so search and the simulator make the term canonical
  first (D17).
- **A custom application never implies.** Only content applications have
  `implicit-use-applications` (I9); the schema node of that name belongs to the
  internal content preview.
- **Name lists, not bitmaps.** `appid` answers for one application at a time and
  keeps no rule or group sets (C12); rule sets stay `*roaring.Bitmap` in `index`
  and `securitypolicy` (R11).
- **A hit does not look inside the file.** A file without containers serves until
  the trim version changes (C11, `docs/todo.md` item 65).
- **One content version, two releases.** The key has no release (§3.3, O1,
  `docs/todo.md` item 62).
- **The XML API marks an implicit match** with an `<Implicit>rule matched</Implicit>`
  element before the entry (fw02, PAN-OS 12.2.3); the lab tool reads it.
- **No F3 timing in the docs** (R7). The MCP content item, `contentBytes`, is
  checked by `BenchmarkCacheRetention`.

## See also

- [simulator](simulator.md), [fetch-and-store](fetch-and-store.md),
  [value-spaces](value-spaces.md), [questions](questions.md),
  [providers](providers.md), [testing-and-gates](testing-and-gates.md)
- `docs/lab/app-id-lab.md`, `docs/limits.md#applications`
