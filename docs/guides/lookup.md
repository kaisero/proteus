# Lookup: what does a rule or object contain?

`proteus lookup <name>` shows the whole element behind a name. `search` tells you
where a name appears; `lookup` tells you what it is.

## A security rule

A rule prints the way the firewall's rule editor lays it out. `--expand` puts each
name's value in parentheses and opens groups as a tree, three levels deep.

```
$ proteus lookup branch-to-dc --expand --file testdata/config/firewall-lookup.xml
file / vsys1   testdata/config/firewall-lookup.xml
  file/vsys1: security-rule branch-to-dc
security rule  branch-to-dc                 position 2 of 2, local, enabled
  uuid         0b3f5e2a-9d41-4c1e-8f7a-2b6c9d1ec21e
  tags         branch
  description  Branch offices to the shared data-center services

  source       zones      branch-vpn, sdwan
               addresses  branch-networks (group, 4 members)
                            net-vienna (10.20.0.0/16)
                            net-graz (10.21.0.0/16)
                            net-linz (10.22.0.0/16)
                            west-branches (group, 1 member)
                              net-salzburg (10.23.0.0/16)
                          tagged-laptops (dynamic, filter 'laptop' and 'managed')
                          10.99.0.0/24
               users      acme\branch-staff
  destination  zones      datacenter
               addresses  NOT dc-mgmt (group, 2 members)
                                dc-mgmt-net (10.1.250.0/24)
                                oob-net (10.1.251.0/24)
  application  ssl, web-browsing, ms-rdp, ssh, dns, … (+2 more)
  service      svc-web (group, 2 members)
                 service-https (predefined)
                 svc-rdp (tcp/3389)
  url category corp-allowed (custom, 2 entries), business-and-economy (predefined)
  profile      group      strict-inspect
                            as-strict (spyware)
                            url-strict (url-filtering)
                            av-strict (virus)
  action       allow
  log          at session start and end, forwarded to log-to-panorama
  schedule     business-hours

1 with it, 0 without, 0 holes
```

How to read it:

- `NOT` marks a negated source or destination.
- A literal address has no parentheses.
- `(predefined)` marks a value the configuration does not define, such as
  `service-https`.
- A list stops at five items. `--full` shows every item.

## An object

An object shows its value, its members and the groups that hold it. To see where
the object is used, run `proteus search <name>`:

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

## When a name has several kinds

proteus infers the kind from the name. In `firewall-lookup.xml`, `dc-mgmt` is a
tag and an address group. `lookup dc-mgmt` then exits with code 2 and names both.
Pick one with `--kind address-group`.

A name that proteus finds nowhere exits with code 1.

`--output json` returns the whole element. It never cuts a list.
