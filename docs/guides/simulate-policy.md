# Simulate policy: which rule would a flow hit?

`proteus simulate policy <source> <destination>` names the security rule a flow
would hit on each selected firewall and vsys. It also says how certain that answer
is.

## The stages

A simulation runs named stages. Each stage removes candidate rules and declares
its [fidelity](../concepts.md#how-certain-an-answer-is).

| Stage | What it does |
| --- | --- |
| `resolve-source` | keeps rules whose source reaches the source address or FQDN |
| `resolve-destination` | the same for the destination |
| `derive-zones` | keeps rules whose zones match, given or derived |
| `match-service` | keeps rules whose service holds `--port` |
| `match-url` | keeps rules whose URL category matches `--url` |
| `drop-disabled` | removes disabled rules |
| `order` | sorts the rest in evaluation order |
| `first-match` | picks the first rule |

The answer carries the weakest fidelity of all stages.

## A basic run

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

`from-inside` names no service, so a port cannot exclude it. The rule stays, and
the fidelity line says why.

## Zones

Without `--from-zone` and `--to-zone`, proteus derives the zones:

- against the store, from the firewall's stored forwarding table;
- with `--file`, from the configuration's interfaces and routes.

A derived zone is always `inferred`. The source zone is the zone of the interface
that a packet arrives on, and a routing table only predicts it. `--why` shows every
stage and how many candidates it left:

```
$ proteus simulate policy 10.1.0.5 10.2.0.5 --why --file testdata/config/firewall-zones.xml
10.1.0.5 -> 10.2.0.5 tcp
file / vsys1   testdata/config/firewall-zones.xml
  zones      from inside, to dmz (configuration)
  relevance  unknown: no stored forwarding table
  fidelity   inferred; not evaluated: service, application
  resolve-source       exact          2  10.1.0.5: 0 hits, 0 negated rules
  resolve-destination  exact          2  10.2.0.5: 0 hits, 0 negated rules
  derive-zones         inferred       1  from inside; to dmz (configuration)
  match-service        overmatch      1  no port given
  match-url            exact          1  no candidate names a URL category
  drop-disabled        exact          1  0 disabled
  order                exact          1  1 in order
  first-match          overmatch      1  from-inside (allow), position 1
    1. from-inside                allow  [local       vsys:vsys1]
first match: from-inside (allow)
```

When a destination NAT rule applies, the destination zone is the zone of the
translated address. That is the zone the firewall uses for the security rule. See
[Simulate NAT](simulate-nat.md).

## Ports and services

```
$ proteus simulate policy 10.0.0.1 10.5.0.1 --port 8443 --file testdata/config/firewall-simulate.xml
10.0.0.1 -> 10.5.0.1 tcp/8443
file / vsys1   testdata/config/firewall-simulate.xml
  zones      not evaluated
  relevance  unknown: no stored forwarding table
  fidelity   overmatch: kept rules whose service is application-default, predefined or absent: app-default, predefined-https; not evaluated: zones, application
    4. custom-port                allow  [local       vsys:vsys1]
    5. app-default                allow  [local       vsys:vsys1]
    6. predefined-https           allow  [local       vsys:vsys1]
    9. anything                   allow  [local       vsys:vsys1]
first match: custom-port (allow)
```

A rule with `application-default` or a predefined service such as `service-https`
stays in the list. The configuration does not hold their ports.

## URLs

`--url` matches custom URL categories. A rule that names a PAN-DB category stays in
the list, because the configuration does not say which URLs that category holds:

```
$ proteus simulate policy 10.0.0.1 10.6.0.1 --url shop.example.com/cart \
    --file testdata/config/firewall-simulate.xml
10.0.0.1 -> 10.6.0.1 tcp shop.example.com/cart
file / vsys1   testdata/config/firewall-simulate.xml
  zones      not evaluated
  relevance  unknown: no stored forwarding table
  fidelity   overmatch: kept rules naming a category the configuration does not define, such as a PAN-DB category: social; not evaluated: zones, service, application
    7. shop                       allow  [local       vsys:vsys1]
    8. social                     deny   [local       vsys:vsys1]
    9. anything                   allow  [local       vsys:vsys1]
first match: shop (allow)
```

## FQDNs

A source or destination can be an FQDN. proteus resolves it with this machine's
DNS. The name matches FQDN objects, and each address matches everything else. The
firewall can resolve other addresses, so this stage is `inferred`.

With `--no-dns`, only FQDN objects of that name match, and the answer says that it
can miss rules:

```
$ proteus simulate policy 10.0.0.1 www.example.com --no-dns \
    --file testdata/config/firewall-simulate.xml
10.0.0.1 -> www.example.com tcp
file / vsys1   testdata/config/firewall-simulate.xml
  dns        www.example.com -> []
  zones      not evaluated
  relevance  unknown: no stored forwarding table
  fidelity   undermatch: www.example.com resolved to no address, so only FQDN objects of that name were matched; an fqdn object matches this name, but the addresses it resolves to are not in the configuration, so rules reaching those addresses another way are not reported; not evaluated: zones, service, application
    2. to-web-by-name             allow  [local       vsys:vsys1]
    9. anything                   allow  [local       vsys:vsys1]
unresolved: file/vsys1: an fqdn object matches this name, but the addresses it resolves to are not in the configuration, so rules reaching those addresses another way are not reported
unresolved: file/vsys1: www.example.com resolved to no address, so only FQDN objects of that name were matched

first match: to-web-by-name (allow)
```

That run exits with code 3, because the answer has unresolved entries.

## What is not evaluated yet

- `--application` and `--user` are accepted but not evaluated. The answer says
  `not evaluated: application`.
- A simulation runs on each device and vsys on its own. It does not follow a flow
  from one firewall to the next; use [simulate routing](simulate-routing.md) for
  the path.
