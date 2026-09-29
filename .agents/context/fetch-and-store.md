# fetch-and-store

Validated against 7a7cefe on 2026-09-29 · Purpose: how a device's configuration and operational state get from the firewall into a snapshot the core can read.

## Purpose & responsibilities

Three packages sit above the read-only core. `inventory` says which firewalls there
are and how to log in to each. `fetch` logs in and reads documents from a device's
XML API. `store` keeps each fetch as a timestamped snapshot on disk. The core never
imports any of them (R12); `cmd/panos-analyst` wires them together, and
every `panos-analyst` question reads the selected devices' snapshots.

## How it works

### Inventory

YAML at `$PANOS_CONFIG`, else `~/.config/panos-analyst/config.yaml`. `Load` refuses
a file its group or others can read, because it holds credentials or names the
variables that do. Unknown keys are errors.

Each device has a `username` and a password source. Most specific wins: the
device's `password`, its `password_env`, then the same two under `defaults`. There
is no API key in the file: `fetch` exchanges the credentials for one per run and
never stores it.

`insecure_tls` defaults to `true` (spec S8, lab devices with self-signed
certificates). `panos-analyst init` writes it explicitly with a comment on how to
opt in, and every fetch prints whether verification is on.

### Fetch

`Client` has three methods and no others: `Keygen`, `Op`, `ExportConfig`. `Op`
refuses any command not starting `<show>` before a request is sent. The password
travels in a POST body and the key in the `X-PAN-KEY` header, so neither is ever in
a URL. A transport error is retried once; a refusal (HTTP 4xx, or
`status="error"` with HTTP 200) is not.

A `Document` is a name and a fetch function. `Documents` lists them:
`config` (export), `system-info`, `interfaces`, `fib`, `rib`, `ha`. **Adding a
fetcher is adding one `Document` value and listing it.** `OpDocument(name, cmds...)`
tries each show command in order until the device accepts one; `fib` and `rib` use
this to fall back from the Advanced Routing command to the legacy one. On an
Advanced Routing device the legacy route command answers success with a deprecation
text, so the Advanced Routing command must come first (verified on fw02).

`Run` logs in, then fetches every document. A failed document is recorded in
`Result.Outcomes` and the rest continue (spec S10). Only a failed login fails the
whole run. `RunActive` (spec §17 R18) reads the HA state first: a passive member of
an active-passive pair is fetched from its active peer (`ha_peer` or the reported
management address, through `ActiveOptions.PeerHost`) once the peer confirms the
pair by serial; any doubt fetches the device asked and adds `Result.Notes`.
`Result.FetchedFrom` and `Meta.FetchedFrom` name the peer that answered.

### Store

```
<root>/<device>/<timestamp>/<document>.xml
<root>/<device>/<timestamp>/meta.json
<root>/<device>/latest -> <timestamp>
```

The root is `$PANOS_STORE`, else `~/.local/share/panos-analyst`. `Write` fills a
hidden directory and renames it into place, so a reader never sees half a snapshot.
`latest` moves only when `config` arrived. Retention keeps the newest
`snapshot_keep` snapshots and never removes the one `latest` names.

`Resolve("fw01")` is the latest snapshot, `Resolve("fw01@<id>")` one in particular.
`Snapshot.Zones()` builds the index's `ZoneSnapshot` from the stored `interfaces`
and `fib`. `estate.NewNetwork` reads `interfaces`, `fib`, `rib` and `ha` of every
device for `simulate routing`, pairing HA members by serial into one node.

## Build / run pointers

- `go test ./inventory ./fetch ./store ./cmd/panos-analyst`
- `./bin/panos-analyst init | fetch <device>… | fetch --all | snapshots <device>`
- `./bin/panos-analyst search <term> --device fw01` — any question, from the latest snapshot.

## Public API

<!-- GENERATED:api ./fetch -->
```go
type APIError struct{ ... }
type ActiveOptions struct{ ... }
type Client struct{ ... }
type Document struct{ ... }
type Outcome struct{ ... }
type Result struct{ ... }
type System struct{ ... }

func (c *Client) ExportConfig(ctx context.Context) ([]byte, error)
func (c *Client) Keygen(ctx context.Context, user, password string) error
func (c *Client) Op(ctx context.Context, cmd string) ([]byte, error)
func (e *APIError) Error() string
func (r Result) OK(name string) bool
func NewClient(t inventory.Target, log *runlog.Logger) *Client
func OpDocument(name string, cmds ...string) Document
func ParseSystemInfo(b []byte) (System, error)
func Run(ctx context.Context, t inventory.Target, docs []Document, log *runlog.Logger) (Result, error)
func RunActive(ctx context.Context, t inventory.Target, docs []Document, opts ActiveOptions, log *runlog.Logger) (Result, error)
```
<!-- /GENERATED:api -->

<!-- GENERATED:api ./store -->
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
func (sn Snapshot) Has(doc string) bool
func (sn Snapshot) Path(doc string) string
func (sn Snapshot) Zones() (*index.ZoneSnapshot, error)
func DefaultRoot(getenv func(string) string) (string, error)
func Open(root string) (*Store, error)
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **Only reads reach a device.** `TestOnlyReadCalls` pins the method set and the
  `<show>` guard. A new `Client` method needs an R2 review.
- **Document names are a contract.** `store` names `config`, `interfaces` and `fib`
  itself, because it cannot import `fetch` (R12). A test in `cmd/panos-analyst`
  asserts they equal `fetch`'s names.
- **Tests never touch a device.** `internal/fakepanos` serves keygen, show commands
  and an export over TLS on 127.0.0.1, records every request, and can drop
  connections to exercise the retry.
- **Secrets stay out of output.** Errors never quote a password or a key; tests
  check both.

## See also

- `inventory/`, `fetch/`, `store/`, `cmd/panos-analyst/`, `internal/fakepanos/`
- [providers](providers.md) — what the index does with a zone snapshot
- [commands](commands.md) — the `panos-analyst` surface
