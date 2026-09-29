# commands

Validated against 54cfdf9 on 2026-09-29 · Purpose: the proteus command, what each subcommand is for, and which one to reach for.

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
fetch <device>... | --label k=v | --all     log in, fetch six documents, store a snapshot
inventory init                              write an inventory template, mode 0600
snapshot list <device>                      snapshots, newest first; * marks latest
snapshot show                               per device and vsys: snapshot, age, version, rules
snapshot diff [--from] [--to]               objects and rules added, removed, changed
search <term>                               every place a value or name appears
lookup <name>                               the whole rule or object behind a name
simulate policy <src> <dst>              the rules one flow could hit, and the first match
simulate routing <src> <dst>                the firewalls a packet crosses, hop by hop
simulate nat <src> <dst> --device <fw>      the NAT rule and the translated packet
```

- **Two question verbs.** `search` answers "where does this appear" in five stages:
  objects by value, objects by name, groups, references, literals. Rules whose field
  is `any` are not in it; `simulate` answers "what would this traffic hit".
- **Selectors** on every question: `--device`, `--label k=v` (AND), `--vsys`,
  `--at <time>`, `--fresh`, `--file <config.xml>`. No selector means every device.
- **Search modes:** the term's type sets the match (address covers, prefix overlaps,
  port covers, URL by tokens, else exact); `--exact`, `--within`, `--contains`
  override. Filters: `--kind`, `--field`, `--show objects,groups,refs,literals`,
  `--direct`.
- **`lookup <name>`** prints a rule as the rule editor lays it out, or an object
  with its value, members and holding groups. The kind is inferred; a name several
  kinds share exits 2 until `--kind` picks one; found nowhere exits 1. `--expand`
  shows values in parentheses and groups as trees (three levels); lists stop at five
  items unless `--full`. See [questions](questions.md).
- **`simulate <kind>`** has one subcommand per kind registered in
  `estate.Simulations`; `policy` is the first. It runs on one device and vsys
  (M5 fans out), takes an address or FQDN per side, `--port`, `--url`, zones given
  or derived, and prints each stage with `--why`. Its text ends with
  `first match: <rule> (<action>)`, which `scripts/device-probe.sh` reads. See
  [simulator](simulator.md).
- **`simulate nat <src> <dst> --device <fw>`** (own command via `kindCommands`):
  `--router`, `--port`, `--protocol`, `--from-zone` or `--from-interface`, `--why`,
  `--no-dns` (resolves no FQDN at all, also a translated destination's). A source
  of `-` is any. Exit 2 for a missing device, several routers, IPv6.
- **`simulate routing <src> <dst>`** (or `<dst> --device <name> [--router]`) has
  its own command (`kindCommands`): no selectors but `--device`, `--at`, `--rib`,
  `--why`. It reads every inventory device's stored interfaces and tables, draws a
  box per firewall and vsys, and exits 2 for a start it cannot choose (ties,
  default-only, several routers, IPv6). `scripts/device-probe.sh --routing <device>
  <router> <dst>...` checks its first lookup against the device.
- **Output and exit codes:** `--output text|json`; JSON is one envelope with
  `format`, `command`, `input`, `results`, `holes`, `unresolved`, `notes`. Exit 0
  complete, 1 error, 2 usage, 3 holes or unresolved.
- **Settings**, rising precedence default < inventory `defaults:` < `PROTEUS_*` <
  flag: inventory path, store root, `max_snapshot_age`, output, and the run log's
  `log_level`, `log_dir`, `log_keep` (plus `--verbose`). `PROTEUS_USERS` names a user
  snapshot; a stored forwarding table supplies zones.
- **Run log:** one file per run under `log_dir`, `<time> [<LEVEL>] [<TAG>] <msg>`,
  tags `RUN`, `API`, `SNAP`, `FIND`, `STEP`; secrets redacted; the path is printed
  when a run exits non-zero. The core never logs; `runlog` is used above it.

## Build / run pointers

- `make build-local` — `bin/proteus` for this machine.
- Fixtures live in `testdata/config/`; with `--file` no command needs a device.

## Public API

None. `cmd/proteus` is `main` only; the commands live in `internal/cli` behind
`cli.Run`.

## Gotchas / invariants

- **Commands hold no matching logic.** They compose package calls: `estate` for
  targets, `search` for findings, `drift` for changes, `index` for candidates. The
  four paths live in `internal/index/candidates.go` and nowhere else.
- **An incomplete answer exits 3.** A hole or an unresolved entry is printed and
  sets the exit code; a script must be able to refuse to act on it.
- **A version gap is unresolved, a stale snapshot is a note.** The first can make
  an answer miss rules; the second only qualifies it.

## See also

- `internal/cli/`, `cmd/proteus/main.go`
- `QUICKSTART.md` — the same commands, task by task, with output
- [fetch-and-store](fetch-and-store.md) — what `fetch` and the store do
- [reporting](reporting.md) — what `Unresolved` means
