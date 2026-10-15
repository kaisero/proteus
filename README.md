# proteus

**Ask your PAN-OS firewalls questions, from a copy of their configuration.**

proteus reads each firewall's configuration and operational state, keeps a
timestamped copy on disk, and answers from that copy. It tells you where an
address is used, which rule a flow would hit, what NAT does to a packet, and which
firewalls a packet crosses. It never changes a firewall.

```
$ proteus simulate policy 10.1.0.5 10.2.0.5 --port 443 --file testdata/config/firewall-zones.xml
10.1.0.5 -> 10.2.0.5 tcp/443
file / vsys1   testdata/config/firewall-zones.xml
  zones      from inside, to dmz (configuration)
  relevance  unknown: no stored forwarding table
  fidelity   inferred: kept rules whose service is application-default, predefined or absent: from-inside; not evaluated: application
    1. from-inside                allow  [local       vsys:vsys1]
first match: from-inside (allow)
```

The answer names the rule, and it says how certain it is and why.

## Features

- **Search** every firewall for an address, prefix, port, URL, user or name. Find
  the objects, the groups (at any depth), the rules and the profiles that use it.
- **Look up** a rule or object in full, laid out like the firewall's rule editor.
- **Simulate** security policy, NAT and routing: which rule a flow hits, what the
  packet looks like after NAT, and the path across your firewalls.
- **Compare** snapshots: which objects and rules changed since last week.
- **Honest answers.** Every answer says how certain it is (`exact`, `overmatch`,
  `inferred`, `undermatch`) and names what it could not evaluate.
- **Read-only by design.** The API client refuses every command that is not a
  `<show>` command or a configuration export.
- **Schema first.** Field knowledge comes from the PAN-OS schema, not from
  hand-written code.
- **Scripting.** `--output json`, and exit codes that separate a complete answer
  from an incomplete one.

## Install

proteus is a single Go binary with no runtime dependency. You need Go at the
version in [`go.mod`](go.mod).

```bash
git clone <repository> proteus && cd proteus
make build-local                 # writes bin/proteus
```

Or install it into `$(go env GOPATH)/bin`:

```bash
go install ./cmd/proteus
```

## Quick start

Try it on a test configuration. No firewall is needed:

```bash
proteus search 10.124.0.1 --file testdata/config/firewall-multivsys.xml
```

Connect your firewalls:

```bash
proteus inventory init                 # writes ~/.config/proteus/config.yaml
$EDITOR ~/.config/proteus/config.yaml  # add your firewalls
export PANOS_PASSWORD='...'
proteus fetch --all                    # store a snapshot of each firewall
proteus search 10.20.0.0/16            # ask every firewall
```

[QUICKSTART.md](QUICKSTART.md) walks through these steps with real output.

> **Security note:** the inventory template turns TLS certificate verification
> off, because lab firewalls present self-signed certificates. Set
> `insecure_tls: false` for every firewall whose certificate this machine trusts.
> See [Configuration](docs/configuration.md#tls).

## Documentation

| Topic | Page |
| --- | --- |
| First steps | [Getting started](docs/getting-started.md) |
| The model behind the answers | [Concepts](docs/concepts.md) |
| Search and lookup | [Search](docs/guides/search.md), [Lookup](docs/guides/lookup.md) |
| Simulations | [Policy](docs/guides/simulate-policy.md), [NAT](docs/guides/simulate-nat.md), [Routing](docs/guides/simulate-routing.md) |
| Snapshots and change history | [Snapshots](docs/guides/snapshots.md) |
| JSON output and exit codes | [Scripting](docs/guides/scripting.md) |
| Questions for an agent over MCP | [MCP server](docs/guides/mcp.md) |
| Inventory, settings and paths | [Configuration](docs/configuration.md) |
| Every command and flag | [CLI reference](docs/cli-reference.md) |
| How it is built | [Architecture](docs/architecture.md) |
| What it does not do yet | [Limits](docs/limits.md) |
| Build, test and extend | [Development](docs/development.md) |

The pages also build as a site: `mkdocs serve` (see
[Development](docs/development.md#build-these-docs)).

## Status

proteus works against PAN-OS firewalls. It ships one schema digest, from PAN-OS
11.2, and reads every configuration version with it.
`simulate policy` does not evaluate application or user yet. See
[Limits](docs/limits.md).

## Contributing

Read [AGENTS.md](AGENTS.md) for the rules every change follows, and
[Development](docs/development.md) for the workflow. Run `make ci` before you
push.

## License

MIT. See [LICENSE](LICENSE).
