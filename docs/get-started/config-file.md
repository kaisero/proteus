# Ask a config file

The repository holds test configurations in `testdata/config/`. `--file` reads one
of them, so you need no firewall and no inventory for these steps. Run them from
the repository root.

## Find where an address is used

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

Read the answer from the top: the objects that cover the address, the groups that
hold them, and the rule that names the groups. Each block is one vsys. The last
line counts the vsys with results, the vsys without results, and the
[holes](../concepts/fidelity.md#holes-unresolved-entries-and-notes).

## Show an object

```text
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

`lookup` shows the object with its value and the groups that hold it. Run
`proteus lookup branch-to-dc --expand --file testdata/config/firewall-lookup.xml`
to see a whole security rule with its groups opened.

## Find the rule a flow hits

```text
$ proteus simulate policy 10.1.0.5 10.2.0.5 --port 443 \
    --from-zone inside --to-zone dmz --file testdata/config/firewall-zones.xml
10.1.0.5 -> 10.2.0.5 tcp/443
file / vsys1   testdata/config/firewall-zones.xml
  zones      from inside, to dmz (given)
  relevance  unknown: no stored forwarding table
  fidelity   exact
  1. from-inside allow [local vsys:vsys1]
first match: from-inside (allow)
```

The `fidelity` line says how certain the answer is. `exact` means that the
firewall computes the same result. Leave out `--from-zone` and `--to-zone`, and
Proteus derives the zones from the configuration; see
[Fidelity](../concepts/fidelity.md).

Add `--why` to see every stage and how many rules it kept.

## Next

[Connect your firewalls](firewalls.md) to ask the same questions of your own
configurations.
