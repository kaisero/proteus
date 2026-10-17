# Search: where does a value appear?

`proteus search <term>` finds every place a value or a name appears. It answers
"where is this used". It does not answer "which rule would this traffic hit"; use
[simulate policy](simulate-policy.md) for that.

## What search returns

One term goes in. Search returns up to four stages of findings, in this order:

| Stage | What it finds |
| --- | --- |
| `object` | objects whose value holds the term, and objects with that name |
| `group` | groups that hold one of those objects, at any depth |
| `reference` | rules, NAT rules, groups and profiles that name one of them |
| `literal` | rules that write the term directly into a field |

A rule whose field is `any` reaches every value, but no object leads to it.
Search leaves such rules out.

## Search for an address

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

The summary line counts the vsys with results, the vsys without results, and the
holes. Each block is one device and one vsys.

## Nested groups

```
$ proteus search 10.1.1.1 --file testdata/config/firewall-nested-groups.xml
search 10.1.1.1 (covers)

file / vsys1   testdata/config/firewall-nested-groups.xml
  object     address              h-1                      10.1.1.1/32
  group      address-group        g-inner                  holds h-1
  group      address-group        g-middle                 holds h-1
  group      address-group        g-outer                  holds h-1
  reference  address-group        g-inner                  static -> h-1
  reference  address-group        g-middle                 static -> g-inner
  reference  address-group        g-outer                  static -> g-middle
  reference  security rule        allow-outer              source -> g-outer
1 with results, 0 without, 0 holes
```

The rule names `g-outer` only. The address is three groups down. To find the
group you must edit, add `--direct`. It keeps groups one level up:

```
$ proteus search 10.1.1.1 --direct --show objects,groups \
    --file testdata/config/firewall-nested-groups.xml
search 10.1.1.1 (covers)

file / vsys1   testdata/config/firewall-nested-groups.xml
  object     address              h-1                      10.1.1.1/32
  group      address-group        g-inner                  holds h-1
1 with results, 0 without, 0 holes
```

## Addresses written into rules

Some configurations name no object and write addresses into rule fields. The
`literal` stage finds them:

```
$ proteus search 198.18.1.1 --file testdata/config/firewall-literals.xml
search 198.18.1.1 (covers)

file / vsys1   testdata/config/firewall-literals.xml
  object     address              named-host               198.18.1.1/32
  reference  security rule        named-rule               source -> named-host
  literal    security rule        literal-host             source 198.18.1.1/32
  literal    security rule        literal-net              source 198.18.0.0/16
1 with results, 0 without, 0 holes
```

## Change how the term matches

The term's type sets the default match (see
[Concepts](../concepts.md#value-spaces)). Three flags change it. You can use only
one of them at a time.

| Flag | Keeps |
| --- | --- |
| `--within` | values that lie wholly inside the term (addresses, prefixes, ranges) |
| `--exact` | values equal to the term |
| `--contains` | names and values that hold the term as text |

```
$ proteus search 10.124.0.0/24 --within --vsys vsys1 \
    --file testdata/config/firewall-multivsys.xml
search 10.124.0.0/24 (within)

file / vsys1   testdata/config/firewall-multivsys.xml
  object     address              corp-dc-vienna           10.124.0.1/32
  group      address-group        corp-dc                  holds corp-dc-vienna
  reference  security rule        Corp DC Access           destination -> corp-dc
1 with results, 0 without, 0 holes
```

`--within` and `--exact` compare an address's whole value, in an object or written
into a rule. The range `10.0.0.2-10.0.0.9` is not within `10.0.0.0/29`, because
two of its addresses lie outside it, and it is not exactly `10.0.0.4/30`.

`--contains` is a text search. It is not matching. Use it to find a long URL in a
custom URL category, because a category name cannot hold it:

```
$ proteus search azureapps --contains --file testdata/config/firewall-urlcat.xml
search azureapps (contains)

file / vsys1   testdata/config/firewall-urlcat.xml
  object     custom-url-category  custom-azuresite-group   superlong.example.azureapps.microsoft.com
  reference  security rule        URL-Example              category -> custom-azuresite-group
1 with results, 0 without, 0 holes
```

## Ports

A port finds every service whose range holds it:

```
$ proteus search tcp/8006 --file testdata/config/firewall-urlcat.xml
search tcp/8006 (covers)

file / vsys1   testdata/config/firewall-urlcat.xml
  object     service              svc-pve                  tcp/8006
  object     service              svc-range                tcp/8000-8100
  group      service-group        svc-grp                  holds svc-pve
  group      service-group        svc-grp                  holds svc-range
  reference  security rule        svc-rule                 service -> svc-grp
  reference  service-group        svc-grp                  members -> svc-pve
  reference  service-group        svc-grp                  members -> svc-range
1 with results, 0 without, 0 holes
```

## URL categories in security profiles

A URL category can reach a rule through its security profile, not only through the
rule's `category` field:

```
$ proteus search demo-category --file testdata/config/firewall-urlprofile.xml
search demo-category (matches)

file / vsys1   testdata/config/firewall-urlprofile.xml
  object     custom-url-category  demo-category            name
  reference  security rule        via-group                profile-setting -> default > default-url-filter alert demo-category
  reference  security rule        via-named-profile        profile-setting -> default-url-filter alert demo-category
  reference  url-filtering        default-url-filter       alert -> demo-category
1 with results, 0 without, 0 holes
```

A profile inspects traffic that a rule already matched. The rule does not match
because of the profile.

## Applications

With the device's App-ID data, a search for an application finds each place that
selects it. The data comes from the snapshot, or with `--file` from `apps.xml.gz`
beside the configuration (see
[Simulate policy](simulate-policy.md#where-the-app-id-data-comes-from)).

```
$ proteus search ssl --file demo/config.xml
search ssl (matches)

file / vsys1   demo/config.xml
  note: application data of content 8000-1000 from demo/apps.xml.gz
  object    application       ssl          predefined
  group     application-group inner        holds inner > ssl
  group     application-group outer        holds outer > inner > ssl
  reference application-group inner        members -> ssl
  reference application-group outer        members -> inner
  reference security rule     allow-outer  application -> outer
  reference security rule     allow-remote application -> implicit use by app-remote
1 with results, 0 without, 0 holes
```

| Finding | What it says |
| --- | --- |
| `object application` | the application; `predefined` marks an application of the App-ID data |
| `object application-filter` | a filter that selects it, with the fields that select it, such as `category=media, risk=4` |
| `object application-container` | the container that holds it |
| `group application-group` | a group that holds it, with the path through nested groups: `outer > inner > ssl` |
| `reference security rule` | a rule that names it, or a group, filter or container that holds it |
| `... implicit use by <app>` | an allow rule that allows it only through the implicit use of another application |

The term takes any case. The findings use the name as the data writes it. A
filter `exclude` that names it, or its container, shows as a reference.

Without App-ID data, search finds the custom applications of the configuration
only. The note `note.app-data-missing` says what it cannot find: filters,
containers and implicit use.

## Users

A configuration does not say which directory groups a user belongs to. Give
proteus a user snapshot through `PROTEUS_USERS`:

```
$ PROTEUS_USERS=testdata/users-snapshot.json \
    proteus search 'ACME\carol' --file testdata/config/firewall-users.xml
search ACME\carol (matches)

file / vsys1   testdata/config/firewall-users.xml
  object     user-group           engineering              ACME\carol
  reference  security rule        engineering-allowed      source-user -> engineering
1 with results, 0 without, 0 holes
```

The snapshot format is:

```json
{"taken_at": "2026-09-28T08:00:00Z", "groups": {"alice": ["engineering"]}}
```

## Narrow the result

| Flag | Effect |
| --- | --- |
| `--kind address,service` | keeps objects and groups of these kinds |
| `--field source,destination` | keeps references and literals from these fields |
| `--show objects,groups,refs,literals` | keeps these stages |
| `--direct` | keeps groups one level up |
| `--why` | adds each finding's answer line under its row |
| `--device`, `--label k=v`, `--vsys` | narrow the devices and vsys |
| `--limit N` | keeps the first N findings (see below) |

## Keep the first findings

A broad term can find thousands of places across an estate. `--limit N` keeps
the first N findings, in the usual order, over all devices and vsys together.
There is no default: without `--limit`, search returns every finding.

```
$ proteus search 10.124.0.1 --limit 2 --file testdata/config/firewall-multivsys.xml
search 10.124.0.1 (covers)

file / vsys1   testdata/config/firewall-multivsys.xml
  object address corp-dc-vienna       10.124.0.1/32
  object address corp-location-vienna 10.124.0.0/16
1 with results, 2 without, 0 holes; 2 of 6 shown, narrow by device, vsys or kind
```

The counts on the summary line are for the whole answer. The end of the line
says how many findings it shows and what narrows the search. In JSON and YAML,
`summary.found` counts every finding and `summary.omitted` counts the findings
that the limit left out. `omitted` is 0 when nothing is left out. Holes,
unresolved entries and notes are never cut. In text, the notes of a vsys whose
findings are all left out print below the findings, as
`note: fw02/vsys1: <text>`.

`--limit` takes 1 or more. `--limit 0` is a usage error (exit 2).
`proteus lookup` and `proteus snapshot diff` take `--limit` too.
