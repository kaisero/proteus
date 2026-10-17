# Getting started

This page takes about ten minutes. Part 1 needs no firewall. Part 2 connects
proteus to your firewalls.

## Requirements

- Go, at the version in `go.mod`. The code is pure Go and has no C dependency.
- For part 2: network access to the firewall management interface, and an
  account that can use the XML API.

## Build

```bash
git clone <repository> proteus && cd proteus
make build-local          # writes bin/proteus
./bin/proteus --version
```

`go install ./cmd/proteus` also works. It puts `proteus` in `$(go env GOPATH)/bin`.

## Part 1: ask questions of a file

The repository has test configurations in `testdata/config/`. `--file` reads one
of them. No inventory and no firewall are needed.

Find where an address appears:

```
$ proteus search 10.124.0.1 --file testdata/config/firewall-multivsys.xml
search 10.124.0.1 (covers)

file / vsys1   testdata/config/firewall-multivsys.xml
  object     address              corp-dc-vienna           10.124.0.1/32
  object     address              corp-location-vienna     10.124.0.0/16
  group      address-group        corp-dc                  holds corp-dc-vienna
  group      address-group        corp-location            holds corp-location-vienna
  reference  security rule        Corp DC Access           destination -> corp-dc
  reference  security rule        Corp DC Access           source -> corp-location
1 with results, 2 without, 0 holes
```

Show an object, with its value and the groups that hold it:

```
$ proteus lookup net-vienna --file testdata/config/firewall-lookup.xml
file / vsys1   testdata/config/firewall-lookup.xml
  file/vsys1: address net-vienna
address        net-vienna                   vsys:vsys1
  tags         branch
  description  Vienna office

  value        10.20.0.0/16
  held by      branch-networks

1 with it, 0 without, 0 holes
```

Find the rule a flow would hit:

```
$ proteus simulate policy 10.1.0.5 10.2.0.5 --port 443 \
    --from-zone inside --to-zone dmz --file testdata/config/firewall-zones.xml
10.1.0.5 -> 10.2.0.5 tcp/443
file / vsys1   testdata/config/firewall-zones.xml
  zones      from inside, to dmz (given)
  relevance  unknown: no stored forwarding table
  fidelity   overmatch: kept rules whose service is application-default, predefined or absent: from-inside; not evaluated: application
    1. from-inside                allow  [local       vsys:vsys1]
first match: from-inside (allow)
```

The `fidelity` line tells you how certain the answer is. Here it says
`overmatch`: the rule names no service, so a port cannot exclude it. See
[Concepts](concepts/fidelity.md).

## Part 2: connect your firewalls

### 1. Write an inventory

```bash
proteus inventory init            # writes ~/.config/proteus/config.yaml, mode 0600
$EDITOR ~/.config/proteus/config.yaml
```

Add one entry per firewall:

```yaml
version: 1
defaults:
  username: admin
  password_env: PANOS_PASSWORD      # the variable that holds the password
devices:
  - name: fw01
    host: fw01.example.net
    labels:
      site: vienna
```

!!! warning "TLS verification is off by default"
    The template turns off TLS certificate verification, because lab firewalls
    present self-signed certificates. Anyone on the network path can then read
    the password and send false data. Set `insecure_tls: false` when your
    firewalls present certificates that this machine trusts.

proteus refuses to read the inventory when other users can read it. Keep the
file at mode `0600`.

### 2. Fetch

```bash
export PANOS_PASSWORD='...'
proteus fetch --all
proteus snapshot show
```

`fetch` logs in, reads the configuration and operational state of each firewall,
and stores one snapshot per firewall. It fetches up to eight firewalls at the same
time. A failed firewall does not stop the others.

### 3. Ask

Without `--file`, every question reads the latest snapshot of every firewall in
the inventory:

```bash
proteus search 10.20.0.0/16
proteus simulate policy 10.20.1.5 10.1.250.10 --port 443
proteus simulate routing 10.20.1.5 8.8.8.8
```

Narrow the selection with `--device fw01`, `--label site=vienna` or
`--vsys vsys1`. Read older snapshots with `--at 2026-09-23`. Fetch before you ask
with `--fresh`.

## Next steps

- Learn the model behind the answers in [Concepts](concepts/index.md).
- Read the guide for the command you need, starting with
  [search](guides/search.md).
- Use proteus from scripts: see [Scripting](guides/scripting.md).
