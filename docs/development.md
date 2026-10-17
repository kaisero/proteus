# Development

## Setup

```bash
make tools     # install the pinned golangci-lint, gofumpt and govulncheck
make hooks     # run `make gate` before every commit
```

## Everyday commands

| Command | What it does |
| --- | --- |
| `make build-local` | builds `bin/proteus` for this machine |
| `make build` | builds a static linux/amd64 `bin/proteus` |
| `make test` | runs the unit tests |
| `make gate` | tidy check, lint, unit tests; the pre-commit hook |
| `make ci` | everything CI runs: race detector, coverage floors, one run of every benchmark, context check, build, vulnerability scan |
| `make fmt` | formats the code |
| `make help` | lists every target |

Run `make ci` before you push. The pre-commit hook runs only `make gate`, which
does not check the coverage floors.

## Repository layout

```
cmd/proteus/                 main only
internal/                    every package; see Architecture
  config/schemadigest/       the committed, embedded schema digest
  tools/schemadigest/        developer tool: schema.xml -> digest
testdata/config/             configuration fixtures, one per behaviour
testdata/opdata/             operational-data fixtures (interfaces, FIB, RIB)
testdata/schema/             a trimmed firewall schema for parser tests
scripts/                     device probes, the coverage gate, the context refresh
docs/                        this site
```

## Tests

- Tests sit next to the code. Fixtures live in `testdata/`.
- `internal/fakepanos` is a fake PAN-OS XML API over TLS. The fetch tests use it,
  so no test contacts a real device.
- `coverage-floors.txt` records a coverage floor per package. `make test-cov`
  fails when a package drops below its floor. Raise a floor when you raise the
  coverage. Never lower one.

### Fixtures

| Fixture in `testdata/config/` | What it exercises |
| --- | --- |
| `firewall-multivsys.xml` | three vsys; one shared dynamic group resolves differently in each |
| `firewall-lab.xml` | pushed shared pre- and post-rules around a vsys's own rules |
| `firewall-lab-changed.xml` | the lab configuration a week later, for `snapshot diff` |
| `firewall-nested-groups.xml` | three levels of group nesting |
| `firewall-literals.xml` | addresses written into rule fields |
| `firewall-urlcat.xml` | custom URL categories, services, an FQDN, an address range |
| `firewall-urlprofile.xml` | a URL category reached through security profiles |
| `firewall-users.xml` | local users, local groups, a dynamic user group |
| `firewall-zones.xml` | zones, interfaces, static routes, a virtual router with BGP |
| `firewall-lookup.xml` | a rule and objects for `lookup` |
| `firewall-simulate.xml` | services, URL categories and FQDNs for `simulate policy` |
| `firewall-nat*.xml` | NAT rules and translations |
| `firewall-version-12.2.xml` | a version newer than every digest |
| `unsupported-version.xml` | a version older than every digest |
| `panorama-rejected.xml` | a Panorama configuration, which is refused |

### Tests that pin real mistakes

Read these first. Each one holds a mistake that was made once.

| Test | What it prevents |
| --- | --- |
| `config.TestWalkContinuesPastANestedConfigElement` | stopping at a nested `<config>` found 1 reference instead of 18 |
| `index.TestNestedChainFromValueToRule` | losing the value, object, group, group, rule chain |
| `resolve.TestFirewallRuleOrderIncludesTheLocalLayer` | a wrong rule layer order |
| `resolve.TestDynamicGroupDiffersInASibling` | resolving one group the same way in every vsys |
| `search.TestAnAddressFollowsEveryStage` | a tag and a group that share a name |
| `estate.TestVsysFilterHoldsForEveryVsys` | a vsys filter that let every later vsys through |
| `digest.TestRealSchemaFormCensus` | a reference classifier that undercounts |

### Tests against a real device

CI never contacts a device. Run these by hand:

```bash
PROTEUS_LIVE_CONFIG=/tmp/fw-live.xml go test -tags live -v ./internal/resolve/
PANOS_HOST=... PANOS_API_KEY=... scripts/device-probe.sh /tmp/fw-live.xml vsys1
```

`device-probe.sh` compares the first match of `proteus simulate policy` with the
firewall's own `test security-policy-match`.

## Update the schema digest

proteus embeds one digest and reads every PAN-OS version with it. Replace it with
the schema of a newer release when that release changes a field proteus reads.

1. Copy the schema off a firewall of that release. The files are vendor files.
   Do not commit them.

    ```bash
    make schema-pull HOST=admin@fw.example.net     # into schemas/
    ```

2. Build the digest. It replaces `internal/config/schemadigest/firewall.json.gz`:

    ```bash
    make schema-digest PANOS_VERSION=12.2.0
    ```

3. Run `make ci` and read the golden diff. Answers for older configurations must
   not lose a reference. Then commit the new digest.

## Add a fetched document

Add a `Document` to `internal/fetch/documents.go` and list it in `Documents`. The
run, the store and the snapshot metadata take it from there. Mark it `Optional`,
with the note a refusal adds, when a release may not know the command.

## Rules

`AGENTS.md` holds the mandatory rules. Each rule names the check that enforces
it. Read it before you change a package.

## Build these docs

The docs use [Zensical](https://zensical.org/). `zensical.toml` holds the
navigation and the pages that stay out of the site. The make targets run the pinned
version through `uvx`, so you need only [uv](https://docs.astral.sh/uv/):

```bash
make docs-serve     # http://127.0.0.1:8000, rebuilds on every change
make docs           # build site/ and fail on a broken link or anchor
```

A push to `main` publishes the site to GitHub Pages. A pull request builds it,
so a broken link fails the check before the merge.
