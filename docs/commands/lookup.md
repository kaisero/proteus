# lookup

What does a rule, an object or an application behind a name contain?

## Synopsis

```text
proteus lookup <name> [selection flags] [flags]
```

## Examples

### Show a security rule

```text
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

A rule prints the way the firewall's rule editor lays it out. `--expand` puts
each name's value in parentheses and opens groups as a tree, three levels deep.
Without `--expand`, the card lists only the names, such as
`branch-networks, tagged-laptops, 10.99.0.0/24`.

### Show an object

=== "text"

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

=== "json"

    ```json
    {
      "format": 2,
      "command": "lookup",
      "detail": "full",
      "input": {
        "expand": false,
        "full": false,
        "kind": "",
        "limit": 0,
        "name": "net-vienna",
        "selection": {
          "file": "testdata/config/firewall-lookup.xml"
        }
      },
      "results": [
        {
          "answer": "file/vsys1: address net-vienna",
          "device": "file",
          "vsys": "vsys1",
          "scope": "vsys:vsys1",
          "card": {
            "kind": "address",
            "name": "net-vienna",
            "tags": [
              "branch"
            ],
            "description": "Vienna office",
            "sections": [
              {
                "title": "value",
                "rows": [
                  {
                    "label": "",
                    "text": "10.20.0.0/16"
                  }
                ]
              },
              {
                "title": "held by",
                "rows": [
                  {
                    "label": "",
                    "items": [
                      {
                        "name": "branch-networks"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      ],
      "summary": {
        "answer": "1 with it, 0 without, 0 holes",
        "found": 1,
        "with": 1,
        "without": 0,
        "omitted": 0
      },
      "holes": [],
      "unresolved": [],
      "notes": []
    }
    ```

An object shows its value, its members and the groups that hold it. To see where
the object is used, run [`proteus search net-vienna`](search.md).

### Show an application

```text
$ proteus lookup app-remote --file demo/config.xml
file / vsys1   demo/config.xml
  note: application data of content 8000-1000 from demo/apps.xml.gz
  file/vsys1: application app-remote
application    app-remote                   predefined

  category     networking
  subcategory  remote-access
  technology   client-server
  risk         4
  default      tcp/80,443,8090
  uses         dns
  implicit uses ssl, web-browsing

1 with it, 0 without, 0 holes
```

With the device's App-ID data, lookup shows predefined applications and
containers. The data comes from the snapshot, or with `--file` from
`apps.xml.gz` beside the configuration (see
[Simulate policy](simulate-policy.md#where-the-app-id-data-comes-from)).

### Show an application filter

```text
$ proteus lookup f-media --file demo/config.xml
file / vsys1   demo/config.xml
  note: application data of content 8000-1000 from demo/apps.xml.gz
  file/vsys1: application-filter f-media
application filter  f-media                      vsys:vsys1

  criteria     category   media
  applications 3 applications
               app-media, app-old, shared-media
  held by      inner

1 with it, 0 without, 0 holes
```

A filter shows its criteria, the number of applications it selects, and the
groups that hold it. The count includes custom applications and the tags that
`application-tag` adds.

## Reading the output

Each block is one device and one vsys, with the answer line of the element
under its header. The summary line counts the vsys with the name, the vsys
without it, and the holes.

### Rule cards

| Marker | Meaning |
| --- | --- |
| `NOT` | a negated source or destination |
| no parentheses | a literal address, such as `10.99.0.0/24` |
| `(predefined)` | a value the configuration does not define, such as `service-https` |
| `(group, N members)` | a group, opened as a tree with `--expand` |
| `(members shown elsewhere on this card)` | a group that the card already opens at a place nearer the top |
| `(cycle)` | a group that holds itself through its members |
| `… (+N more)` | a list that stops at five items; `--full` shows every item |

A card opens each group once, at its place nearest the top of the card. Every
other place shows the group with that marker and without its members.

### Application cards

| Element | The card shows |
| --- | --- |
| application | category, subcategory, technology and risk; flags such as `evasive-behavior` or `ident-by-dport`; tags; default ports; whether it is obsolete; its container and parent; the applications it uses, implies and tunnels; its description |
| container | its functions |
| filter | its criteria, the count of applications it selects, the first 20 of them, and the groups that hold it |

The parent and the tunneled applications show as the data writes them. They can
name an application that the data does not hold.

Without App-ID data, lookup finds no predefined application and no container. A
filter shows its criteria, and its applications read
`unknown: no application data`. The note `note.app-data-missing` says so.

### Names that match no element or several kinds

A name that lookup finds nowhere is an empty answer. Lookup prints
`no element named "x" in the selection` and exits 0.

Lookup infers the kind from the name. In `firewall-lookup.xml`, `dc-mgmt` is a
tag and an address group, so lookup exits with code 2 and names both:

```text
$ proteus lookup dc-mgmt --file testdata/config/firewall-lookup.xml
proteus: "dc-mgmt" names more than one kind; pick one with --kind:
  address-group on file/vsys1
  tag on file/vsys1
```

Pick one with `--kind address-group`.

## Flags

Lookup takes the selection flags `--device`, `--label`, `--vsys`, `--at`,
`--fresh` and `--file` (see [Selection flags](../reference/global-flags.md#selection-flags)).

| Flag | Default | Description |
| --- | --- | --- |
| `--kind <kind>` | inferred from the name | the kind of element: `security-rule`, `application` or another object kind |
| `--expand` | off | shows each name's value and every group's members |
| `--full` | off | shows every item of a list, and every application of a filter |
| `--limit N` | every card | keeps the first N cards (see [Results](../reference/output.md#results)) |
| `--detail` | `full` | with `--output json` or `yaml`, see [Detail](../reference/output.md#detail) |

`--output json` and `--output yaml` return the whole element and never cut a
list. They hold every application of a filter.

`--limit N` helps when a name is on many devices. The summary line then ends
with `; 1 of 2 shown, narrow by device or vsys`, and `summary.omitted` in JSON
and YAML counts the cards left out.

## Limits

- Without App-ID data, lookup shows no predefined application, no container, and
  no application of a filter.
- Lookup does not check that `apps.xml.gz` beside a `--file` configuration has
  the device's content version.

See [Limits](../reference/limits.md#applications).

## See also

- [search](search.md)
- [simulate policy](simulate-policy.md)
- [App-ID data](../concepts/snapshots.md#app-id-data)
- [Scope](../concepts/scope.md)
- [Output and exit codes](../reference/output.md)
