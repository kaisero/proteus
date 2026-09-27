# commands

Validated against 86fd84f on 2026-09-27 · Purpose: the three binaries, what each is for, and which one to reach for.

## Purpose & responsibilities

The library is the product; the commands are how a human or an agent exercises it
without writing Go. `panos-explore` is the query surface, `panos-demo` is a
narrated tour used to check behaviour against a real configuration, and
`panos-schemagen` is the build-time generator.

`make tools-bin` builds the first two. `make build` cross-compiles only the
generator for linux/amd64.

## panos-explore

```
info      <cfg>                                      version, platform, load time
groups    <cfg>                                      the device-group tree
target    <cfg> <serial> <vsys>                      what one firewall actually gets
lookup    <cfg> <scope> <value>                      the four paths, narrated step by step
reaches   <cfg> <scope> <field> <value>              which rules one field could match
search    <cfg> <scope> <substring>                  objects by a fragment of their value
uses      <cfg> <scope> <category|url>               rule to category through profiles
whereused <cfg> <scope> <name>                       every reference to a name
simulate  <cfg> <scope> <src> <dst> [from to]        both sides, optionally zoned
group     <cfg> <scope> <name>                       one address group in one scope
```

A scope is `shared`, `vsys:<name>` or `dg:<name>`. A field is `source`,
`destination`, `category`, `application`, `service`, `from`, `to`, `source-user`
or `tag`. `PANOS_USERS` points at a user snapshot.

### Which one to use

- **`reaches`** is the general door. One field, one value, any kind of value.
- **`lookup`** shows the same thing step by step, which is what to run when an
  answer looks wrong.
- **`simulate`** intersects source and destination. **Pass the zones.** Without
  them it agrees with a device on 3 of 7 probes; with them, 7 of 7.
- **`uses`** answers the question `reaches` cannot: which rules apply a profile
  that mentions a category. It gives no allow-or-block verdict.
- **`search`** is substring and is not matching. The output says so.

### Conventions the commands follow

- The incompleteness warning prints **before** the result, because the result on
  its own looks complete.
- Every match prints what matched and the value that matched it.
- Each command names what it did not evaluate, and the wording differs with and
  without zones.

## panos-demo

`panos-demo <cfg>` walks twelve sections over one configuration: load, hierarchy,
targets, rules, objects, groups, lookups, matching, and the caveats. `-v` explains
each answer. `-probe <addr>` chooses the address the lookup sections use.

Use it to check a whole configuration at once, especially a real one.

## panos-schemagen

`digest` turns an appliance `schema.xml` into a committed digest. `generate` turns
digests into `config/v11_2/*/model.go`. See [schema-codegen](schema-codegen.md).

## Build / run pointers

- `make tools-bin` — `bin/panos-explore`, `bin/panos-demo`.
- `make build-local` — `bin/panos-schemagen` for this machine.
- Fixtures live in `testdata/config/`; no command needs a device.

## Public API

Not a library surface. The commands are `main` packages under `cmd/`.

## Gotchas / invariants

- **Commands hold no matching logic.** They compose library calls. The four paths
  live in `index/candidates.go` and nowhere else; duplicating them is how the
  `any` defect came to need fixing twice.
- **A command must surface `Report.Unresolved`.** A guard nothing prints is not a
  guard.
- **`lookup` deduplicates by object.** An ip-range decomposes into several
  prefixes and step one lists each, but group membership belongs to the object.

## See also

- `cmd/panos-explore/main.go`, `cmd/panos-demo/main.go`
- `QUICKSTART.md` — the same commands, task by task, with output
- [reporting](reporting.md) — what the warning block means
