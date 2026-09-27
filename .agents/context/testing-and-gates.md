# testing-and-gates

Validated against 133ba4a on 2026-09-27 · Purpose: what must pass before a commit, and what each gate is protecting against.

## Purpose & responsibilities

`make ci` is the contract. A commit that does not pass it does not land. The
pre-commit hook runs it, which is why it has to stay fast enough to tolerate.

```
ci: tidy-check lint test-race test-cov generate-check digest-check context-check build vuln
```

## The gates

| Gate | Protects against |
|---|---|
| `tidy-check` | `go.mod` drifting from the imports |
| `lint` | golangci-lint v2, zero issues tolerated |
| `test-race` | the shared-index data race class |
| `test-cov` | coverage falling below the recorded floor |
| `generate-check` | a hand-edited generated model |
| `digest-check` | the embedded digest copy drifting from the original |
| `build` | the generator still cross-compiles |
| `vuln` | govulncheck |
| `context-check` | these agent docs drifting from the real API |

`go test ./internal/archtest -run TestImportDirection` is R12: the read-only core
imports no I/O, and the packages above it point one way. It runs in `test-race`.

### The coverage ratchet

`coverage-floors.txt` records what each package achieves. `scripts/coverage-gate.sh`
fails if a package drops below its floor.

**A floor is raised, never lowered.** If new code drops coverage, the answer is
tests, not a lower number. This was got wrong once and the commit had to be amended.

Current floors: config 98.1, resolve 95.7, index 95.0, internal/schema 85.9,
internal/codegen 93.0, internal/digest 71.8, cmd/panos-schemagen 57.6.

### Fixtures

`testdata/config/` holds every input. No test touches a device.

| Fixture | What it exercises |
|---|---|
| `firewall-multivsys.xml` | three vsys; one shared dynamic group resolving differently in each; a nested `<config>` |
| `firewall-multivsys-wrapped.xml` | the `<response><result>` envelope |
| `firewall-siblings.xml` | one name, two vsys, two values: R10 |
| `firewall-shadow.xml`, `firewall-urlprofile-shadow.xml` | a vsys definition shadowing a shared one |
| `firewall-nested-groups.xml`, `firewall-cyclic-groups.xml` | closure depth and cycles |
| `firewall-badfilter.xml` | a tag filter the parser refuses |
| `firewall-literals.xml` | addresses written directly into rule fields |
| `firewall-lab.xml`, `firewall-paths.xml` | shared pre/post around vsys rulebases, disabled rules |
| `firewall-anyrule.xml` | the any-field path |
| `firewall-urlcat.xml` | URL categories, services, FQDN, ip-range |
| `firewall-urlcat-edge.xml` | Category Match, unreadable members, malformed ports |
| `firewall-urlprofile.xml` | rule to category through a profile group and directly |
| `firewall-users.xml` | local users, groups, a dynamic user group |
| `firewall-zones.xml`, `firewall-zones-shared.xml` | every interface shape, routes, limits |
| `firewall-apps.xml` | custom application, group, filter, container |
| `firewall-ipv6.xml` | v6 containment and range decomposition |
| `unsupported-version.xml` | a version refusal |
| `panorama-rejected.xml` | a Panorama refusal |

### The device probe

`scripts/device-probe.sh <cfg> <scope> [binary]` compares the library's first match
against a firewall's own `test security-policy-match`. It needs `PANOS_HOST` and
`PANOS_API_KEY`.

Each probe carries the zones and ports of the rule it aims at, because the device
command **requires real zone names** and rejects `any`. Probes built without that
care measure nothing: an earlier ad-hoc set reported 6 of 7 agreement by accident,
where a set derived from the rules reported 3 of 7.

It is not a pass/fail gate. The library over-matches by design, which is the safe
direction for a candidate set. Use it to see **where** the two differ and why.

It is also the refactor gate: run it before and after, and diff the output. The
value-space refactor was accepted on a byte-identical result.

## Build / run pointers

- `make ci` — everything.
- `make test-race`, `make test-cov`, `make lint` — one at a time.
- `make context` — refresh the API blocks in these docs after an API change.
- `go test ./index/ -run TestConcurrentUnknownNameLookupsAreSafe -race` — the race
  regression.

## Public API

Not a library surface.

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
