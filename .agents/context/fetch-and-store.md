# fetch-and-store

Validated against e37ee52 on 2026-09-30 · Purpose: how a device's configuration and operational state get from the firewall into a snapshot the core can read.

## Purpose & responsibilities

Three packages sit above the read-only core. `inventory` says which firewalls there
are and how to log in to each. `fetch` logs in and reads documents from a device's
XML API. `store` keeps each fetch as a timestamped snapshot on disk. The core never
imports any of them (R12); `internal/cli` wires them together, and
every `proteus` question reads the selected devices' snapshots.

## How it works

### Inventory

YAML at `$PROTEUS_CONFIG`, else `~/.config/proteus/config.yaml`. `Load` refuses
a file its group or others can read, because it holds credentials or names the
variables that do. Unknown keys are errors.

Each device has a `username` and a password source. Most specific wins: the
device's `password`, its `password_env`, then the same two under `defaults`. There
is no API key in the file: `fetch` exchanges the credentials for one per run and
never stores it.

`insecure_tls` defaults to `true` (spec S8, lab devices with self-signed
certificates). `proteus init` writes it explicitly with a comment on how to
opt in, and every fetch prints whether verification is on.

The `mcp:` section (`Inventory.MCP`, nil when absent) holds the server's settings;
`Parse` validates it (no negative numbers, readable durations, `listen` with a
port). With `defaults.export_inventory: true`, `fetch` calls `WriteExport` after
every run, a failed one too: `Export()` drops username, password and
password_env everywhere, and the file lands at `<store>/.proteus/inventory.yaml`
(0600, temp file and rename, directory synced). A write failure adds
`note.export-failed` and turns exit 0 into 3, never into 1. `ReadExport` (the server's
reader) refuses any credential and clears `store` and `log_dir`. `.proteus` is not
a valid device name, so it cannot collide with a device directory.

### Fetch

`Client` has three methods and no others: `Keygen`, `Op`, `ExportConfig`. `Op`
refuses any command not starting `<show>` before a request is sent. The password
travels in a POST body and the key in the `X-PAN-KEY` header, so neither is ever in
a URL. A transport error is retried once; a refusal (HTTP 4xx, or
`status="error"` with HTTP 200) is not.

A `Document` is a name and a fetch function. `Documents` lists them:
`config` (export), `system-info`, `interfaces`, `fib`, `rib`, `ha`, `predefined`.
**Adding a fetcher is adding one `Document` value and listing it.** A document with
`Optional` set is one a release may refuse: an API refusal, or an answer that fails
`Optional.Check`, adds the `Optional.Refused` note to `Result.Notes`, stores
nothing, records no outcome and leaves the step complete; a transport failure fails
it as any other. `predefined` is optional: it was checked on PAN-OS 12.2.3 only
(L4), its check needs a `<service>` element, and its note is
`note.fetch-predefined-missing`. `OpDocument(name, cmds...)`
tries each show command in order until the device accepts one; `fib` and `rib` use
this to fall back from the Advanced Routing command to the legacy one. On an
Advanced Routing device the legacy route command answers success with a deprecation
text, so the Advanced Routing command must come first (verified on fw02).

`Steps()` are a device's fetch as `internal/task` steps on a `State` (`NewState`):
`login`, `ha`, `documents`. The CLI runs them with `task.Run`, between its own
`resolve` and `store` steps, with the device's name as the task's kind, so every
error starts `<device>/<step>: `. A failed document is recorded in
`Result.Outcomes` and the rest continue (spec S10); the `documents` step is then
`partial`. Only a failed login fails the device. The `ha` step (spec §17 R18) reads
the HA state: a passive member of an active-passive pair is fetched from its active
peer (`ha_peer` or the reported management address, through
`ActiveOptions.PeerHost`) once the peer confirms the pair by serial; any doubt
fetches the device asked and adds `Result.Notes`. `Result.FetchedFrom` and
`Meta.FetchedFrom` name the peer that answered. The CLI fetches up to eight
devices at once and answers one result per device named, with its stages;
`fetch --why` prints them, and a device's TLS and HA notes go to the envelope's
`notes`. An HA state that cannot be read skips the `ha` step as "HA state
unreadable".

### Store

```
<root>/<device>/<timestamp>/<document>.xml
<root>/<device>/<timestamp>/meta.json
<root>/<device>/latest -> <timestamp>
```

The root is `$PROTEUS_STORE`, else `~/.local/share/proteus`. `Write` fills a
hidden directory and renames it into place, so a reader never sees half a snapshot.
It makes that directory with `os.Mkdir`, so a second writer of the same id fails at
once, and checks again for the id after the Mkdir. Only the creator removes the
directory, and only before its rename. Each file is synced before the rename; the
snapshot and device directories are synced after it and before `latest` moves, and
the device directory again after `latest`. A sync failure after the rename says
the snapshot is stored but not synced.
`latest` moves only when `config` arrived. Retention keeps the newest
`snapshot_keep` snapshots with `config.xml` and the newest `snapshot_keep` without
it (an unreadable `meta.json` counts as without), and never removes the one
`latest` names. It also removes `.<id>.partial` and `.latest-*` entries whose
modification time is more than an hour old: what a crashed write left.

`Resolve("fw01")` is the latest snapshot, `Resolve("fw01@<id>")` one in particular.
`Snapshot.Zones()` builds the index's `ZoneSnapshot` from the stored `interfaces`
and `fib`. `config.Load` on the stored `config.xml` reads `predefined.xml` beside
it; a snapshot stored before that document existed loads without it. `estate.NewNetwork` reads `interfaces`, `fib`, `rib` and `ha` of every
device for `simulate routing`, pairing HA members by serial into one node.

A lookup failure matches one kind with `errors.Is`: `ErrNoSnapshot` (nothing to
pick for the device, id or time), `ErrNoConfig` (the picked snapshot has no
configuration; `Snapshot.ConfigPath`), `ErrUnreadable` (a stored file is there but
cannot be read or parsed). `Latest` and `AtOrBefore` on a device whose snapshots
all lack a configuration match both `ErrNoSnapshot` and `ErrNoConfig`; test
`ErrNoConfig` first. The message text stays as it was. An absent zone document
matches `fs.ErrNotExist`, not `ErrUnreadable`. `Get` of a snapshot directory
without `meta.json` matches `ErrUnreadable` (damaged), not `ErrNoSnapshot` or
`fs.ErrNotExist`; `snapshot list` shows it as a `gap.load-failed` hole and lists
the rest. `AtOrBefore` passes over damaged snapshots and names them in
`Snapshot.Skipped`; `estate.SkipNote` turns that into `note.snapshot-skipped`
on the targets, the routing data and `snapshot diff`. `Latest` and `Get` never
fall back.

## Build / run pointers

- `go test ./internal/inventory ./internal/fetch ./internal/store ./internal/cli`
- `./bin/proteus init | fetch <device>… | fetch --all | snapshots <device>`
- `./bin/proteus search <term> --device fw01` — any question, from the latest snapshot.

## Public API

<!-- GENERATED:api ./internal/fetch -->
```go
type APIError struct{ ... }
type ActiveOptions struct{ ... }
type Client struct{ ... }
type Document struct{ ... }
type Optional struct{ ... }
type Outcome struct{ ... }
type Result struct{ ... }
type State struct{ ... }
type System struct{ ... }

func (c *Client) ExportConfig(ctx context.Context) ([]byte, error)
func (c *Client) Keygen(ctx context.Context, user, password string) error
func (c *Client) Op(ctx context.Context, cmd string) ([]byte, error)
func (e *APIError) Error() string
func (r Result) OK(name string) bool
func NewClient(t inventory.Target, log *runlog.Logger) *Client
func NewState(t inventory.Target, docs []Document, opts ActiveOptions, log *runlog.Logger) State
func OpDocument(name string, cmds ...string) Document
func ParseSystemInfo(b []byte) (System, error)
func Steps() []task.Step[State]
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./internal/store -->
```go
type DocumentMeta struct{ ... }
type Meta struct{ ... }
type Snapshot struct{ ... }
type Store struct{ ... }

func (s *Store) AtOrBefore(device string, t time.Time) (Snapshot, error)
func (s *Store) Get(device, id string) (Snapshot, error)
func (s *Store) Latest(device string) (Snapshot, error)
func (s *Store) List(device string) ([]string, error)
func (s *Store) Resolve(ref string) (Snapshot, error)
func (s *Store) WithClock(now func() time.Time) *Store
func (s *Store) Write(meta Meta, docs map[string][]byte, keep int) (Snapshot, error)
func (sn Snapshot) ConfigPath() (string, error)
func (sn Snapshot) Has(doc string) bool
func (sn Snapshot) Path(doc string) string
func (sn Snapshot) Zones() (*index.ZoneSnapshot, error)
func At(root string) *Store
func DefaultRoot(getenv func(string) string) (string, error)
func Open(root string) (*Store, error)
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **Only reads reach a device.** `TestOnlyReadCalls` pins the method set and the
  `<show>` guard. A new `Client` method needs an R2 review.
- **Document names are a contract.** `store` names `config`, `interfaces` and `fib`
  itself, because it cannot import `fetch` (R12). A test in `internal/cli`
  asserts they equal `fetch`'s names.
- **Tests never touch a device.** `internal/fakepanos` serves keygen, show commands
  and an export over TLS on 127.0.0.1, records every request, and can drop
  connections to exercise the retry.
- **Secrets stay out of output.** Errors never quote a password or a key; tests
  check both.

## See also

- `internal/inventory/`, `internal/fetch/`, `internal/store/`, `internal/cli/`, `internal/fakepanos/`
- [providers](providers.md) — what the index does with a zone snapshot
- [commands](commands.md) — the `proteus` surface
