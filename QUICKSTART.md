# Quickstart

This guide takes you from a fresh clone to your first answers in about ten
minutes. Steps 1 to 4 need no firewall. Step 5 connects your firewalls.

## 1. Build

```bash
make build-local        # writes bin/proteus
export PATH="$PWD/bin:$PATH"
proteus --version
```

## 2. Find where an address is used

The repository holds test configurations in `testdata/config/`. `--file` reads
one of them.

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

Read it top down: the objects that cover the address, the groups that hold them,
and the rule that names the groups. Each block is one vsys. The summary line counts
the vsys with results, the vsys without, and the holes (vsys that could not be
read).

## 3. Show a rule or an object

```
$ proteus lookup net-vienna --file testdata/config/firewall-lookup.xml
file / vsys1   testdata/config/firewall-lookup.xml
address        net-vienna                   vsys:vsys1
  tags         branch
  description  Vienna office

  value        10.20.0.0/16
  held by      branch-networks

1 with it, 0 without, 0 holes
```

Try `proteus lookup branch-to-dc --expand --file testdata/config/firewall-lookup.xml`
to see a whole security rule with its groups opened.

## 4. Find the rule a flow would hit

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

The `fidelity` line is the important one:

- `inferred`: proteus derived the zones from the configuration's interfaces and
  routes. The firewall uses the interface a packet arrives on, which the routes only
  predict.
- `kept rules whose service is ...`: the rule names no service, so the port cannot
  exclude it.
- `not evaluated: application`: the question gives no `--application`, so the
  rule's application is not checked.

Add `--why` to see every stage and how many rules it kept.

## 5. Connect your firewalls

Write an inventory and add your firewalls:

```bash
proteus inventory init                 # writes ~/.config/proteus/config.yaml, mode 0600
$EDITOR ~/.config/proteus/config.yaml
```

```yaml
version: 1
defaults:
  username: admin
  password_env: PANOS_PASSWORD
devices:
  - name: fw01
    host: fw01.example.net
    labels:
      site: vienna
```

> **Warning:** the template turns TLS certificate verification off, because lab
> firewalls present self-signed certificates. Anyone on the network path can then
> read the password. Set `insecure_tls: false` when your firewalls present
> certificates that this machine trusts.

Fetch a snapshot of each firewall, then check what was stored:

```bash
export PANOS_PASSWORD='...'
proteus fetch --all
proteus snapshot show
```

Now ask without `--file`. Every question reads the latest snapshot of every
firewall:

```bash
proteus search 10.20.0.0/16
proteus simulate policy 10.20.1.5 10.1.250.10 --port 443
proteus simulate routing 10.20.1.5 8.8.8.8
proteus snapshot diff                  # after a second fetch
```

Narrow a question with `--device fw01`, `--label site=vienna` or `--vsys vsys1`.
`simulate policy` is the exception: it follows the routed path from the source and
gives one verdict for the estate. `--device` names where the path starts; check one
configuration with `--file <config.xml> --vsys vsys1`.

## Where next

- [Concepts](docs/concepts.md): snapshots, scopes and how certain an answer is.
- The guides: [search](docs/guides/search.md), [lookup](docs/guides/lookup.md),
  [simulate policy](docs/guides/simulate-policy.md),
  [simulate NAT](docs/guides/simulate-nat.md),
  [simulate routing](docs/guides/simulate-routing.md),
  [snapshots](docs/guides/snapshots.md), [scripting](docs/guides/scripting.md).
- [CLI reference](docs/cli-reference.md): every command and flag.
