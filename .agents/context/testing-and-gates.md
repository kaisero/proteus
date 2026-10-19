# testing-and-gates

Validated against 133ba4a on 2026-09-27 · Purpose: what must pass before a commit, and what each gate is protecting against.

## Purpose & responsibilities

`make ci` is the contract. A commit that does not pass it does not land. The
pre-commit hook runs it, which is why it has to stay fast enough to tolerate.

```
ci: tidy-check lint test-race test-cov bench-check context-check build vuln
```

## The gates

| Gate | Protects against |
|---|---|
| `tidy-check` | `go.mod` drifting from the imports |
| `lint` | golangci-lint v2, zero issues tolerated |
| `test-race` | the shared-index data race class |
| `test-cov` | coverage falling below the recorded floor |
| `bench-check` | a benchmark behind a documented figure (R7) that no longer compiles or runs; each runs once |
| `build` | proteus still cross-compiles for linux/amd64 |
| `vuln` | govulncheck |
| `context-check` | these agent docs drifting from the real API |

`go test ./internal/archtest -run TestImportDirection` is R12: the read-only core
imports no I/O, and the packages above it point one way. `TestTestHelpersStayInTests`
keeps the test helpers `internal/fakepanos`, `internal/simulate/pathlab` and
`internal/testconfig`, which import `testing`, out of every package's non-test code.
It runs in `test-race`. `internal/testconfig` writes the generated group-tree
configuration the index and card benchmarks share, gzips
`testdata/appid/content.xml` into a test's directory (`Content`), and generates a
content file for the MCP cache benchmark (`AppContent`), and a generated identity
file for the same benchmark (`IdentityFile`: users, groups per user, mappings). It
does not import `internal/appid` or `internal/identity`, so their tests can use it.

### The coverage ratchet

`coverage-floors.txt` records what each package achieves. `scripts/coverage-gate.sh`
fails if a package drops below its floor.

**A floor is raised, never lowered.** If new code drops coverage, the answer is
tests, not a lower number. This was got wrong once and the commit had to be amended.

Current floors: config 98.1, resolve 95.8, index 95.1, internal/schema 85.9,
internal/digest 71.8, internal/tools/schemadigest 59.2,
inventory 96.2, fetch 100.0, store 88.1, estate 100.0, search 97.3, drift 91.1,
runlog 93.0, simulate 100.0, internal/simulate/securitypolicy 97.5, internal/cli 93.4,
internal/appid 100.0, internal/tools/applab 93.6, internal/identity 100.0,
internal/tools/labkit 96.8, internal/tools/uidlab 96.0.
`coverage-floors.txt` is the authority; these figures only orient.

The fetcher's tests run against `internal/fakepanos`, a fake XML API over TLS on
127.0.0.1. No test touches a device.

### Fixtures

`testdata/config/` holds every input. No test touches a device.

| Fixture | What it exercises |
|---|---|
| `firewall-multivsys.xml` | three vsys; one shared dynamic group resolving differently in each; a nested `<config>` |
| `firewall-multivsys-wrapped.xml` | the `<response><result>` envelope |
| `firewall-siblings.xml` | one name, two vsys, two values: R10 |
| `firewall-shadow.xml`, `firewall-urlprofile-shadow.xml` | a vsys definition shadowing a shared one |
| `firewall-nested-groups.xml`, `firewall-cyclic-groups.xml` | closure depth and cycles |
| `firewall-shared-names.xml` | one name, several kinds: tag and address group, address group and service group |
| `firewall-device-refs.xml` | references from outside any vsys: a static route and an IKE gateway |
| `firewall-badfilter.xml` | a tag filter the parser refuses |
| `firewall-literals.xml` | addresses written directly into rule fields |
| `firewall-lab.xml`, `firewall-paths.xml` | shared pre/post around vsys rulebases, disabled rules |
| `firewall-anyrule.xml` | the any-field path |
| `firewall-urlcat.xml` | URL categories, services, FQDN, ip-range |
| `firewall-urlcat-edge.xml` | Category Match, unreadable members, malformed ports |
| `firewall-urlprofile.xml` | rule to category through a profile group and directly |
| `firewall-users.xml` | local users, groups, a dynamic user group |
| `firewall-identity.xml` | User-ID: one rule per `source-user` form (a user, a UPN, LDAP, XML API and dynamic user groups, a DN in another case, a short name, empty groups, a CIE group, an outside user, the keywords, no `source-user`, a local group); the goldens copy it beside a gzipped `testdata/identity/identity.json` as `identity.json.gz` |
| `firewall-lab-template.xml`, `firewall-lab-merged.xml` | a pushed template in the answer's shape for `firewall-lab.xml`, and the expected merge: each row of spec 2026-10-17 §2.2 and the two device cases of C11 |
| `firewall-lab-indented.xml` | `firewall-lab.xml` indented as `show config running` answers: it loads and compares as the compact file (C12) |
| `firewall-zones.xml`, `firewall-zones-shared.xml` | every interface shape, routes, limits |
| `firewall-apps.xml` | custom application, group, filter, container |
| `firewall-appid.xml` | App-ID: custom applications with and without a default and in mixed case, `application-tag`, filters, nested groups, a container and the rules of the CLI App-ID goldens; the goldens copy it beside a gzipped `testdata/appid/content.xml` as `apps.xml.gz` |
| `firewall-ipv6.xml` | v6 containment and range decomposition |
| `unsupported-version.xml` | a version older than every digest, read with the lowest |
| `firewall-version-12.2.xml` | a version newer than every digest, and the gap it reports |
| `panorama-rejected.xml` | a Panorama refusal |
| `path-fw01.xml`, `path-fw02.xml` | the two-firewall path fixture: zones as in the lab's operational data, no security rule; `internal/simulate/pathlab` serves them with default-rule variants to the path and CLI tests |

### App-ID fixtures

`testdata/appid/` holds plain XML with dummy values, content version `8000-1000`
(plan D15: no binary fixture): `answer-applications.xml` and
`answer-containers.xml` in the device answer's shapes (F1, F7-F17), and
`content.xml`, the trimmed file. A test gzips what it needs into a temporary
directory. `internal/fakepanos` answers the two show commands with dummy data
unless `Ops` names them. Each fixture case names the lab fact it proves (S, I, P
or F). `TestEveryFilterFieldHasAKeptField` reads the digest's
`application-filter` node and fails on a filter field without a kept field.

### The App-ID lab check

`make app-lab DEVICE=<name> APPLAB_KEY_HEADER=<file>` runs
`internal/tools/applab` by hand, never in CI: per flow of `docs/lab/app-id-flows.tsv`
it compares the device's `test security-policy-match` with
`proteus simulate policy --file` on a fresh snapshot (rule, action, implicit
marker). It sends only `<show>` and `<test><security-policy-match>`
(`TestOnlyShowAndPolicyMatch`, AGENTS.md R2). The tracked lab files hold
placeholders only; the real values live in the ignored
`docs/lab/app-id-lab.vars`. `docs/lab/app-id-lab.md` holds the procedure and the
results: on fw02 all 108 flows agreed.

### User-ID fixtures

`testdata/identity/` holds plain files with dummy values (`example.com`, `alice`,
`bob`, `carol`, `dave`, `other\ghost`, TEST-NET and `2001:db8::/32` addresses):
one `answer-*.xml` per device answer shape of spec 2026-10-17 X1 (U1, U3, U4, U5,
U6, U7, U8, U9, the long-name U3 layout, `user-ids match-user`, a mapping by
address with and without a match, two mapping pages, the dataplane table), and
`identity.json`, the format-1 file. A test gzips what it needs. Each fixture case
names its fact. `internal/fakepanos` answers the identity commands with dummy data
unless `Ops` names them; `DropCmd` and a per-command `Stall` exercise the
transport cases.

### The User-ID lab check

`make uid-lab DEVICE=<name> UIDLAB_KEY_HEADER=<file>` runs `internal/tools/uidlab`
by hand, never in CI (spec 2026-10-17 §10.3): on a fresh snapshot it compares
`simulate policy --file` with the device's `test security-policy-match` per policy
flow, `lookup` of a user and of a group with `user-attributes`, `user-ids
match-user` and `group name`, and `search` of an address with
`ip-user-mapping-mp ip`. A policy flow that differs is tried twice more (M18).
Both lab tools send through `internal/tools/labkit`, which allows only `<show>` and
`<test><security-policy-match>` (`TestOnlyShowAndPolicyMatch`, AGENTS.md R2).

Five User-ID lab files are tracked, with placeholders such as `${USER_A}`, dummy
names `uid-lab-*` and destinations in 192.0.2.0/24 only (spec D12):
`docs/lab/user-id-flows.tsv`, `user-id-lab-set.tsv`, `user-id-lab-delete.tsv`,
`user-id-lab-login.xml` and `user-id-lab-logout.xml`. The real values live in the
ignored `docs/lab/user-id-lab.vars`; `uidlab -render <file>` fills a file for the
shell only. CI reads the tracked files: `TestFlowListCoversTheFacts`,
`TestLabConfigIsIsolated`, `TestTheLabXMLAPIGroupMeetsNoUserCheck`,
`TestTheLogoutEndsWithShortLogins` and `TestLabFilesHoldNoLabData` (no address
outside the TEST-NETs and `2001:db8::/32`, no serial, no domain but
`example.com`). On fw01 all 56 cases passed (`docs/reference/limits.md#users`).

### The device probe

`scripts/device-probe.sh <cfg> <scope> [binary]` compares proteus's first match
against a firewall's own `test security-policy-match`. It needs `PANOS_HOST` and
`PANOS_KEY_HEADER`, a file with the one line `X-PAN-KEY: <key>`. Each call is a
POST with the key in that header, never in a URL.

Each probe carries the zones and ports of the rule it aims at, because the device
command **requires real zone names** and rejects `any`. Probes built without that
care measure nothing: an earlier ad-hoc set reported 6 of 7 agreement by accident,
where a set derived from the rules reported 3 of 7.

It is not a pass/fail gate. The simulator over-matches by design, which is the safe
direction for a candidate set. Use it to see **where** the two differ and why.

It is also the refactor gate: run it before and after, and diff the output. The
value-space refactor was accepted on a byte-identical result.

## Build / run pointers

- `make ci` — everything.
- `make test-race`, `make test-cov`, `make lint` — one at a time.
- `make context` — refresh the API blocks in these docs after an API change.
- `go test ./internal/index/ -run TestConcurrentUnknownNameLookupsAreSafe -race` — the race
  regression.

## Public API

None.

## Gotchas / invariants

- **A test that would also pass on the broken code is worthless.** Both regression
  tests for the interning defect were verified by temporarily restoring the old
  behaviour and watching them fail.
- **Check the premise before blaming the code.** Several apparent failures during
  development were wrong test inputs: 198.18.2.1 is inside another rule's
  198.18.0.0/16; 10.1.1.1 is not inside 10.1.0.0/24.
- **Delete a test that asserts a limitation once the limitation is gone.** Two such
  tests were rewritten to assert the new behaviour rather than worked around.
- **Do not lower a coverage floor.**

## See also

- `Makefile`, `scripts/coverage-gate.sh`, `scripts/device-probe.sh`
- `AGENTS.md` — the binding rules, each with its check
