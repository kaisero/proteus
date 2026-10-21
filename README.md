<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/images/readme-banner-dark.svg">
    <img alt="Proteus: ground truth for NetSec agents" src="docs/assets/images/readme-banner-light.svg">
  </picture>
</p>

[![CI](https://github.com/kaisero/proteus/actions/workflows/ci.yml/badge.svg)](https://github.com/kaisero/proteus/actions/workflows/ci.yml)
[![Docs](https://github.com/kaisero/proteus/actions/workflows/docs.yml/badge.svg)](https://kaisero.github.io/proteus/)
[![Release](https://img.shields.io/github/v/release/kaisero/proteus)](https://github.com/kaisero/proteus/releases/latest)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Analyse your Palo Alto Networks NetSec estate using CLI and MCP. Find configuration references and simulate
Traffic to find out how data flows through your network and what policy rules actually match. 

Proteus takes care of the heavy lifting to connect your LLM to PAN-OS so you can find out what’s actually working and why.
Empower your agents with near real-time data without hammering your devices directly with API Calls.

**[Full documentation →](https://kaisero.github.io/proteus/)**

## Features

Use Proteus to

- Find every object, group, rule and profile that uses an address, prefix, port,
  URL, user, group or name, across multiple firewalls
- Show a rule, an object, a user or a group in full, laid out like the firewall's
  rule editor
- Check which security rule a flow hits, on one firewall or along its whole path,
  with its application and its user
- Trace what NAT does to a packet and which zones the security policy must match
- Trace the path of a packet across your whole estate
- Compare two snapshots of a firewall to see which objects and rules changed
- See how certain each answer is, and which parts Proteus could not evaluate
- Script with `--output json` and exit codes, or serve the same answers to an
  agent over MCP

## Install

Download the archive for your platform from the
[latest release](https://github.com/kaisero/proteus/releases/latest). Each
archive holds one static binary for Linux, macOS or Windows, on amd64 or arm64.
`SHA256SUMS` lists the checksum of each archive.

```bash
tar -xzf proteus_<version>_darwin_arm64.tar.gz
sudo mv proteus_<version>_darwin_arm64/proteus /usr/local/bin/
proteus --version
```

To build from source instead, you need Go at the version in [`go.mod`](go.mod):

```bash
git clone https://github.com/kaisero/proteus.git && cd proteus
make build-local                 # writes bin/proteus
go install ./cmd/proteus         # or install into $(go env GOPATH)/bin
```

## Quick start

From a clone of the repository, ask a test configuration where an address is
used. You need no firewall:

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

## License

MIT. See [LICENSE](LICENSE).
