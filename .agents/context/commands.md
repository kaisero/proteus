# commands

Validated against 2f14f3f on 2026-09-29 · Purpose: the three binaries, what each is for, and which one to reach for.

## Purpose & responsibilities

The library is the product; the commands are how a human or an agent exercises it
without writing Go. `panos-analyst` is the one command surface: it fetches devices
into the store and answers questions of them. `panos-demo` is a narrated tour used
to check behaviour against a real configuration. `panos-schemagen` is the
build-time generator. Spec: `docs/specs/2026-09-27-panos-analyst-scope.md` §15.

`make tools-bin` builds the first two. `make build` cross-compiles only the
generator.

## panos-analyst

```
fetch <device>... | --label k=v | --all     log in, fetch four documents, store a snapshot
inventory init                              write an inventory template, mode 0600
snapshot list <device>                      snapshots, newest first; * marks latest
snapshot show                               per device and vsys: snapshot, age, version, rules
snapshot diff [--from] [--to]               objects and rules added, removed, changed
search <term>                               every place a value or name appears
lookup <name>                               the whole rule or object behind a name
simulate secpolicy <src> <dst>              the rules one flow could hit, and the first match
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
  `estate.Simulations`; `secpolicy` is the first. It runs on one device and vsys
  (M5 fans out), takes an address or FQDN per side, `--port`, `--url`, zones given
  or derived, and prints each stage with `--why`. Its text ends with
  `first match: <rule> (<action>)`, which `scripts/device-probe.sh` reads. See
  [simulator](simulator.md).
- **Output and exit codes:** `--output text|json`; JSON is one envelope with
  `format`, `command`, `input`, `results`, `holes`, `unresolved`, `notes`. Exit 0
  complete, 1 error, 2 usage, 3 holes or unresolved.
- **Settings**, rising precedence default < inventory `defaults:` < `PANOS_*` <
  flag: inventory path, store root, `max_snapshot_age`, output, and the run log's
  `log_level`, `log_dir`, `log_keep` (plus `--verbose`). `PANOS_USERS` names a user
  snapshot; a stored forwarding table supplies zones.
- **Run log:** one file per run under `log_dir`, `<time> [<LEVEL>] [<TAG>] <msg>`,
  tags `RUN`, `API`, `SNAP`, `FIND`, `STEP`; secrets redacted; the path is printed
  when a run exits non-zero. The core never logs; `runlog` is used above it.

## panos-demo

`panos-demo <cfg>` walks twelve sections over one configuration: load, scopes,
targets, rules, objects, groups, lookups, matching, and the caveats. `-v` explains
each answer. `-probe <addr>` chooses the address the lookup sections use.

Use it to check a whole configuration at once, especially a real one.

## panos-schemagen

`digest` turns an appliance `schema.xml` into a committed digest. `generate` turns
digests into `config/v11_2/*/model.go`. See [schema-codegen](schema-codegen.md).

## Build / run pointers

- `make tools-bin` — `bin/panos-analyst`, `bin/panos-demo`.
- `make build-local` — `bin/panos-schemagen` for this machine.
- Fixtures live in `testdata/config/`; with `--file` no command needs a device.

## Public API

Not a library surface. The commands are `main` packages under `cmd/`.

## Gotchas / invariants

- **Commands hold no matching logic.** They compose library calls: `estate` for
  targets, `search` for findings, `drift` for changes, `index` for candidates. The
  four paths live in `index/candidates.go` and nowhere else.
- **An incomplete answer exits 3.** A hole or an unresolved entry is printed and
  sets the exit code; a script must be able to refuse to act on it.
- **A version gap is unresolved, a stale snapshot is a note.** The first can make
  an answer miss rules; the second only qualifies it.

## See also

- `cmd/panos-analyst/`, `cmd/panos-demo/main.go`
- `QUICKSTART.md` — the same commands, task by task, with output
- [fetch-and-store](fetch-and-store.md) — what `fetch` and the store do
- [reporting](reporting.md) — what `Unresolved` means
