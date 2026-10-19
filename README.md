# proteus

[![CI](https://github.com/kaisero/proteus/actions/workflows/ci.yml/badge.svg)](https://github.com/kaisero/proteus/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Ask your PAN-OS firewalls questions. proteus answers from a stored copy of each
firewall's configuration, operational state and User-ID data, and never writes
to a device. The stored configuration is the running configuration merged with
the template that Panorama pushed, normally without uncommitted changes.

**[Full documentation →](https://kaisero.github.io/proteus/)**

## Features

Use proteus to

- Find every object, group, rule and profile that uses an address, prefix, port,
  URL, user, group or name, across all firewalls
- Show a rule, an object, a user or a group in full, laid out like the firewall's
  rule editor
- Check which security rule a flow hits, on one firewall or along its whole path,
  with its application and its user
- Trace what NAT does to a packet and which zones the security policy must match
- Trace the path of a packet across your firewalls
- Compare two snapshots of a firewall to see which objects and rules changed
- See how certain each answer is, and which parts proteus could not evaluate
- Script with `--output json` and exit codes, or serve the same answers to an
  agent over MCP

## Quick start

Build proteus. You need Go at the version in [`go.mod`](go.mod).

```bash
git clone https://github.com/kaisero/proteus.git && cd proteus
make build-local                 # writes bin/proteus
go install ./cmd/proteus         # or install into $(go env GOPATH)/bin
```

Ask a test configuration where an address is used. You need no firewall:

```text
$ proteus search 10.124.0.1 --file testdata/config/firewall-multivsys.xml
search 10.124.0.1 (covers)

file / vsys1   testdata/config/firewall-multivsys.xml
  object    address       corp-dc-vienna       10.124.0.1/32
  object    address       corp-location-vienna 10.124.0.0/16
  group     address-group corp-dc              holds corp-dc-vienna
  group     address-group corp-location        holds corp-location-vienna
  reference security rule Corp DC Access       destination -> corp-dc
  reference security rule Corp DC Access       source -> corp-location
1 with results, 2 without, 0 holes
```

Connect your firewalls and ask all of them:

```bash
proteus inventory init                 # writes ~/.config/proteus/config.yaml
$EDITOR ~/.config/proteus/config.yaml  # add your firewalls
export PANOS_PASSWORD='...'
proteus fetch --all                    # store a snapshot of each firewall
proteus search 10.20.0.0/16
```

## Development

Read [AGENTS.md](AGENTS.md) for the rules every change follows. Run `make ci`
before you push.

## License

MIT. See [LICENSE](LICENSE).
