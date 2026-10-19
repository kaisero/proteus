# identity

Validated against 4c57e88 on 2026-10-19 · Purpose: how the User-ID data of a device gets from the firewall into an identity file, and how the simulator, search, lookup, snapshot diff and the MCP server use it.

## Purpose & responsibilities

A configuration names users and groups in the `source-user` field of a rule, but
who is in a group and which user an address has come from User-ID at run time.
`internal/identity` owns that data as one file per snapshot: the format in both
directions, the parsers of the device answers, the source of a group by its form,
and the questions about one user or one group. It is a leaf: it imports only the
standard library and `internal/reason` (AGENTS.md R12). It keeps name lists, not
bitmaps: it answers for one user or group at a time, and rule sets stay
`*roaring.Bitmap` in `index` and `securitypolicy` (R11, SG11).
Spec `docs/specs/2026-10-17-user-id-design.md` (§, D, U, N, M, C, X, O numbers
below), plan `docs/plans/2026-10-18-user-id.md` (PD and SG numbers).

## How it works

### The data path

```
fetch: identity step ──Parse*, Assemble, Encode──> Result.Identity (gzip JSON)
cli: store step ──Store.Write(meta, docs, identityFile, keep)──>
     <store>/<device>/<id>/identity.json.gz   mode 0600
     meta.json "identity": true
estate: Target.IdentityPath, Target.Identity (lazy) ──identity.Load──> *identity.Data
query: identityFor ──> index.Providers.Users ──> user value space, securitypolicy,
       search (stage identity), card.FindIdentity, identityDiff
mcp: one LRU item per snapshot (identityBytes)
```

- **Fetch** (`internal/fetch/identity.go`): the step `identity` runs after
  `applications` (§3.1). It needs the system info (`multi-vsys: off`) and the
  merged configuration (the CIE and LDAP domains). It sends 8 commands and
  max(1, ⌈n/10,000⌉) pages of the mapping table, in sequence (D3, SG1). It never
  returns an error (PD4); the cases are in "When there is no file" below. The
  snapshot keeps no device answer, only the file (D4).
- **Store** (`internal/store/store.go`): `Write` takes the gzip bytes as its own
  argument, writes them as `identity.FileName` into the hidden directory before
  `meta.json`, and sets `Meta.Identity`. `Snapshot.IdentityPath` names the file,
  or "" without one. A pruned snapshot removes it. PD5 planned a variadic
  `...store.File`; the code took one `[]byte` argument, and an empty slice is no
  file.
- **Estate** (`internal/estate`): `openSnapshot` sets `IdentityPath` from the
  snapshot; `OpenFile` sets it to `identity.json.gz` beside a `--file`
  configuration. `IdentitySource` (`DiskIdentity`, or the MCP cache) loads it.
- **Query** (`internal/query/identity.go`): `identityMemo` loads each file once
  per question. `identityFor` gives the data and its notes (PD11, §7): no file, no
  note; a file that does not load, `gap.no-user-directory` with the cause and the
  answer as without data; a `--file` file, `note.identity-file`, and
  `gap.user-directory-stale` past `max_snapshot_age`. When to load is in "Loading"
  below.
- **Index** (`internal/index/resolver_user.go`): with `Providers.Users`, the user
  value space returns as hits the `source-user` members of the rules, as written,
  that a user satisfies (PD7, PD8). A member that the data cannot judge is an
  unresolved entry (`doubt.user-cie-group`, `doubt.user-data-missing`). Without
  the data, `gap.no-user-directory` and `gap.dynamic-user-group`, as before.
- **Simulator** (`securitypolicy`, stage `match-user`; `pathpolicy`, the after-NAT
  mark): see [simulator](simulator.md).
- **Search, lookup, diff, MCP**: see [questions](questions.md) and
  `docs/commands/mcp.md`.

### The file

`identity.json.gz`, gzip JSON, `"format": 1` (`identity.Format`). `format` rises
when a key changes its meaning or goes; an added key keeps it.
`TestFormatGuardsTheFields` pins the keys of each format.

| Key | Content | Answer |
|---|---|---|
| `taken_at` | the time of the fetch | — |
| `sources.ldap` | `name`, `domain`, `base`, `groups` per group-mapping profile | U6 statistics and `state all`; the domain from the configuration (`resolve.GroupMappings`) |
| `sources.cie` | `name`, `domain`, `groups`, `last` per CIE profile | U7; the domain from the configuration (`resolve.CloudIdentityEngines`, SG2) |
| `users` | `name` (primary), `alt`, `email`, `groups` (groups and DUGs) | U3 joined with U8 by primary name, in any case |
| `groups` | `name`, `source`, `members` | U5, the full and the dynamic list; the count from `users` |
| `dugs` | the DUG names | U5 `dynamic` |
| `tags` | `user`, `tags` | U9 |
| `mappings` | `ip`, `user`, `type`, `timeout` | U1, in pages |
| `parts_missing` | the missing parts, sorted | — |
| `mappings_partial` | `true` when the table was cut or moved; left out when false | — |

Every name stays as the device prints it; no parser changes case (§3.3).

### The parts

The part names are the names that `parts_missing` and
`note.identity-part-missing` use (`identity.Part*`):

| Part | Command | Calls |
|---|---|---|
| `sources.ldap` | U6 `group-mapping statistics` and `state all` | 2 |
| `sources.cie` | U7 `cloud-identity-engine status all` | 1 |
| `users.groups` | U3 `user-ids all` | 1 |
| `users.names` | U8 `user-attributes user all` | 1 |
| `groups` | U5 `group list` and `group list dynamic` | 2 |
| `tags` | U9 `registered-user all` | 1 |
| `mappings` | U1 `ip-user-mapping-mp all`, pages of 10,000 | max(1, ⌈n/10,000⌉) |

- A refused command (`APIError`) or an answer that does not read makes its part
  missing; the other parts stay. A `*PartError` names the part, the entry index or
  the line number, and a fixed reason, never a value (§3.5).
- A U3 user count that differs from `Total: N` makes `users.groups` missing (O3).
  U3 reads fixed columns (X1); `ParseUserIDsMatch` reads the one-user table of
  `user-ids match-user` for the lab tool and does not compare its `Total`.
- Paging (§3.2): from start-point 1 until `total` entries or a short page. A
  `total` that changes, or a read that ends with fewer distinct entries than
  min(total, cap), keeps the pages, drops duplicate addresses (the later entry
  wins), adds `note.identity-mappings-moved` and sets `mappings_partial` (ruling
  T7-I1). More than 512,000 entries keep the first 512,000, with
  `note.identity-mappings-cut`.

### When there is no file

| Condition | Result |
|---|---|
| inventory `identity: false` (`Target.Identity` false) | no call, no file, `note.identity-off`, step `skipped` |
| system info `multi-vsys: on` | no file, `note.identity-multi-vsys` (D10) |
| system info without the mode | no file, `note.identity-multi-vsys` with its own text (ruling T7-I2) |
| a transport error or a time-out | no file, an `Outcome` named `identity`, step `partial`, exit 3 (PD4) |

No step falls back to the identity data of an older snapshot.

### The source of a group

`identity.Classify` gives the source by the form of the name (§3.3, U10, U11), in
this order:

| Form | Source |
|---|---|
| a DN that ends with the base of an LDAP profile, in any case (the longest base wins) | `ldap:<profile>` |
| a DN while `sources.ldap` is missing | `ldap` (ruling D9) |
| a name in the `dynamic` list | `dug` |
| `<domain>\<group>` where `<domain>` is a CIE profile domain | `cie:<profile>` |
| `<domain>\<group>` while a CIE profile has no known domain, or `sources.cie` is missing | `cie` (SG2, ruling T4-Q2) |
| any other name | `xmlapi` |

A DN is a name of `<key>=<value>` parts that commas split; an escaped comma
stays in its part.

### The name rules

`(*Data).Resolve` is the one decision for `--user`, a search term and `lookup`
(PD18): a primary name, then an alternate name, then an email when
`identity.InputEmail` is true, each in any case; of two users with one name in
one tier, the first in the file counts. `InputEmail` is true (N7 not shown, PD21):
a simulation whose user came from an email is `inferred` with
`note.user-resolved`. `identity.RuleEmail` is false (SG4): an email in a rule
names no user. `TestEmailConstantsFollowTheFacts` pins both.

`(*Data).Member` reads a `source-user` member of a rule as the device does:

| Member | Kind | Fact |
|---|---|---|
| a primary name or an alternate name, in any case | `MemberUser` | N1, N2 |
| a DUG | `MemberDUG`; members from U3 only (D13, PD20) | M8, X2 |
| a group of `groups[]` by its name in any case, or by its short name `<domain>\<cn>` | `MemberGroup` | M7, M11, M12 |
| a group of a CIE source | `MemberCIE` | D1, U16 |
| a short name whose domain is unknown, or of two groups | `MemberInDoubt` (`doubt.user-data-missing`, names `sources.ldap`) | ruling T5 |
| anything else | `MemberUnknown`: matches only a user of the same text | M13, M17 |

- A mapped user is compared as stored, against primary names only: `example\alice`
  is no mapping of `example.com\alice` (M2, N4). `GroupsOf` takes a primary name
  only.
- A group name (a group, a DUG, a CIE group or a short name) given as `--user` is
  no user and never matches by its literal text (M12, Task 13 fix, confirmed in the
  lab run). A flow value of the same text as a `MemberInDoubt` member keeps that
  rule in doubt.
- `InGroup(user, group)` takes the name that `Member` gives: classify with
  `Member` first.
- `TagsOf` merges two registrations of one user in two cases; tags compare in
  exact case (M14). Tags feed `lookup` only (D13).
- `Mapping(ip)`: the later mapping of one address counts; a mapping whose user is
  `unknown` counts as no mapping (U2, PD17, in `securitypolicy`).

### Loading (PD10, §4.2)

| Question | Loads the file when |
|---|---|
| `simulate policy` | `--user` is given, or a rule of the vsys names a `source-user` other than `any` (`namesUser`; SG9) |
| `simulate routing`, `simulate nat` | never (`simEnv` passes no loader) |
| `search` | the term is one address, holds `\`, `@` or `=`, or equals a `source-user` member in any case (`searchNeedsIdentity`); else when the first search of a target finds nothing, and then it searches that target again |
| `lookup` | `--kind identity-user` or `identity-group`, or no kind when the first look finds nothing (`needsIdentity`) |
| `snapshot diff` | always, both snapshots |

`namesUser`, `searchNeedsIdentity` and `newUserResolver` filter the members in
three ways on purpose; the doc comment of `namesUser` says why.

## Decisions

| # | Decision |
|---|---|
| PD1 | `RunningConfig` reads `show config running`; `Document.Fallback` exports when the device refuses it or the answer holds no `response/result/config`, with `note.config-not-running`. `PushedTemplate` (`template`) is optional: `No template pushed to device` is no template and no note (C7); a refusal or an answer without a template gives `note.config-no-template`; a transport error fails the document, and `documents` is `partial`. |
| PD2 | `unwrapConfig` and `unwrapTemplate` slice the answers byte for byte; the step `template` runs `MergeTemplate(base, template, root)` with the digest's `tlo` mark (format 3) and puts the result in `Docs["config"]`. |
| PD3 | `identity` owns the format both ways, the parsers and the queries; `fetch` parses at fetch time. |
| PD4 | `identityStep` never returns an error; a transport failure is an outcome and a `partial` step, the snapshot is stored, the fetch exits 3. |
| PD5 | `Store.Write` writes the identity file and sets `Meta.Identity` (the code takes one `identityFile []byte`, not a variadic list). |
| PD6 | `index.Providers.Users` is `*identity.Data`; `UserDirectory`, `StaleReporter`, `UserSnapshot` and `LoadUserSnapshot` are gone. |
| PD7 | The user value space returns the rule members a user satisfies; CIE groups come back unresolved with `doubt.user-cie-group`. |
| PD8 | The value space takes a user as the device compares it: a primary name, or a mapped name as stored; the caller resolves first. |
| PD9 | `securitypolicy` handles `known-user`, `unknown`, `pre-logon`, the digest default of an absent `source-user`, the doubts and the fidelity. |
| PD10 | `query` loads the data only for a question that needs it (table above); once per file per question. |
| PD11 | A missing file behaves as before; a file that does not load gives `gap.no-user-directory` with the cause. |
| PD12 | `pathpolicy` marks a hop `inferred` with `note.user-after-nat` when an earlier hop translated the source and the hop judged a user; `match-user` is a decision stage. |
| PD13 | `search` has a stage `identity` for the user, its groups and its mapped addresses; rules come through the reference stage. |
| PD14 | `card.FindIdentity` builds the `identity-user` and `identity-group` cards; `card.Find` keeps its signature. |
| PD15 | `snapshot diff` adds one result per device with the scope `identity` when both snapshots hold data; changes of kinds `identity user` and `identity source`. |
| PD16 | The lab tools share `internal/tools/labkit`; `uidlab` reads the tracked placeholder lab files; the real values stay in the ignored `docs/lab/user-id-lab.vars`. |
| PD17 | `--user any`, `known-user` and `unknown` are usage errors; a mapping of user `unknown` is no mapping. |
| PD18 | `InputEmail` and `Resolve` serve `--user`, a search term and `lookup`; a rule member follows `RuleEmail`. |
| PD19 | Missing data never gives an exact answer: a member a missing part cannot judge is `doubt.user-data-missing`; a source without a mapping in a missing, cut or moved table is a user in doubt, `inferred`, with `note.identity-part-missing`. |
| PD20 | DUG membership comes from U3; no code evaluates a DUG filter; tags feed `lookup` only. |
| PD21 | N7 not shown: `InputEmail` true, an email gives `inferred`; `RuleEmail` false; a test pins each constant. |

## Build / run pointers

- `go test ./internal/identity ./internal/index ./internal/simulate/securitypolicy ./internal/fetch ./internal/query`
- `./bin/proteus simulate policy <src> <dst> --port 443 --user <name> --file <dir>/config.xml --why`
  with the identity file as `<dir>/identity.json.gz`; `testdata/identity/identity.json`
  is the fixture, plain JSON (gzip it for a try)
- `./bin/proteus search <user> --file <cfg>`, `./bin/proteus lookup <user|group> --file <cfg>`
- `make uid-lab DEVICE=fw01 UIDLAB_KEY_HEADER=<file>`: the lab check, by hand
  (`internal/tools/uidlab`, spec §10.3).

## Public API

<!-- GENERATED:api ./internal/identity -->
```go
type Attributes struct{ ... }
type CIESource struct{ ... }
type Change struct{ ... }
type Counts struct{ ... }
type Data struct{ ... }
type Domains struct{ ... }
type File struct{ ... }
type Group struct{ ... }
type GroupAnswer struct{ ... }
type LDAPSource struct{ ... }
type LDAPState struct{ ... }
type Mapping struct{ ... }
type MappingPage struct{ ... }
type Member struct{ ... }
type MemberKind int
type PartError struct{ ... }
type Parts struct{ ... }
type Sources struct{ ... }
type Tags struct{ ... }
type User struct{ ... }

func (d *Data) Complete(part string) bool
func (d *Data) Counts() Counts
func (d *Data) File() File
func (d *Data) Group(name string) (Group, bool)
func (d *Data) GroupsOf(user string) []string
func (d *Data) InGroup(user, group string) bool
func (d *Data) Known(name string) bool
func (d *Data) Mapping(ip netip.Addr) (Mapping, bool)
func (d *Data) MappingsOf(user string) []Mapping
func (d *Data) Member(name string) Member
func (d *Data) MemberCount(group string) int
func (d *Data) Members(group string) []string
func (d *Data) PartsMissing() []string
func (d *Data) Resolve(name string) (string, bool)
func (d *Data) TagsOf(user string) []string
func (d *Data) TakenAt() time.Time
func (d *Data) User(name string) (User, bool)
func (e *PartError) Error() string
func Assemble(p Parts, domains Domains, takenAt time.Time) File
func Classify(group string, ldap []LDAPSource, ldapMissing bool, dugs []string, cie []CIESource, cieMissing bool) string
func Diff(before, after *Data) []Change
func Encode(w io.Writer, f File) error
func Load(path string) (*Data, error)
func New(f File) *Data
func ParseCIEStatus(b []byte) ([]CIESource, error)
func ParseGroupList(b []byte) ([]string, error)
func ParseGroupMappingState(b []byte) (map[string]LDAPState, error)
func ParseGroupMappingStatistics(b []byte) ([]LDAPSource, error)
func ParseGroupName(b []byte) (GroupAnswer, error)
func ParseMappings(b []byte) (MappingPage, error)
func ParseRegisteredUsers(b []byte) ([]Tags, error)
func ParseUserAttributes(b []byte) ([]Attributes, error)
func ParseUserIDs(b []byte) (map[string][]string, error)
func ParseUserIDsMatch(b []byte) (map[string][]string, error)
func Read(r io.Reader) (*Data, error)
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **No value in a log, a note or an error.** The run log, the notes, the step
  detail and every error name parts, counts, times and line numbers, never a user,
  a group, a mapped address or a tag (§3.5).
- **Case.** Names compare in any case (N1, M11, X2), but the file keeps each name
  as the device prints it. Tags compare in exact case (M14).
- **The stored form of a mapping decides.** The device can store a login in the
  NetBIOS form `example\alice`, which matches no user rule and no group (M2, N4);
  the cause is open (N6, `docs/todo.md` item 75).
- **One vsys only.** The file has no vsys key, so a device of several vsys, or of
  an unknown mode, gets no file (D10, ruling T7-I2).
- **CIE never decides** until a CIE lab passes (D1, `docs/todo.md` item 68).
- **An XML API group message rewrites U8** until the next group-mapping refresh:
  the members lose their alternate names and email (U18). The lab flows name no
  member of the lab XML API group in a UPN or user check.
- **No device timing in the docs** (R7). The MCP identity item, `identityBytes`
  (fixed part, per mapping, per user and group, per membership), is checked by
  `BenchmarkCacheRetention`.

## See also

- [fetch-and-store](fetch-and-store.md), [simulator](simulator.md),
  [value-spaces](value-spaces.md), [questions](questions.md),
  [providers](providers.md), [testing-and-gates](testing-and-gates.md)
- `docs/commands/simulate-policy.md#users`, `docs/reference/limits.md#users`,
  `docs/reference/configuration.md#the-identity-file`
