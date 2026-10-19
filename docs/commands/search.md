# search

Where does an address, prefix, port, URL, user or name appear in your configurations?

## Synopsis

```text
proteus search <term> [selection flags] [flags]
```

## Examples

### Search for an address

=== "text"

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

=== "json"

    ```json
    {
      "format": 2,
      "command": "search",
      "detail": "full",
      "input": {
        "direct": false,
        "fields": null,
        "kinds": null,
        "limit": 0,
        "mode": "covers",
        "selection": {
          "file": "testdata/config/firewall-multivsys.xml"
        },
        "show": null,
        "term": "10.124.0.1"
      },
      "results": [
        {
          "answer": "file/vsys1: address corp-dc-vienna",
          "device": "file",
          "vsys": "vsys1",
          "stage": "object",
          "kind": "address",
          "name": "corp-dc-vienna",
          "via": "10.124.0.1/32",
          "scope": "vsys:vsys1"
        },
        {
          "answer": "file/vsys1: address corp-location-vienna",
          "device": "file",
          "vsys": "vsys1",
          "stage": "object",
          "kind": "address",
          "name": "corp-location-vienna",
          "via": "10.124.0.0/16",
          "scope": "vsys:vsys1"
        },
        {
          "answer": "file/vsys1: address-group corp-dc",
          "device": "file",
          "vsys": "vsys1",
          "stage": "group",
          "kind": "address-group",
          "name": "corp-dc",
          "via": "holds corp-dc-vienna",
          "scope": "shared"
        },
        {
          "answer": "file/vsys1: address-group corp-location",
          "device": "file",
          "vsys": "vsys1",
          "stage": "group",
          "kind": "address-group",
          "name": "corp-location",
          "via": "holds corp-location-vienna",
          "scope": "shared"
        },
        {
          "answer": "file/vsys1: security rule Corp DC Access (destination)",
          "device": "file",
          "vsys": "vsys1",
          "stage": "reference",
          "kind": "security rule",
          "name": "Corp DC Access",
          "field": "destination",
          "via": "corp-dc",
          "path": "/config/devices/localhost.localdomain/vsys/vsys1/rulebase/security/rules/Corp DC Access",
          "scope": "vsys:vsys1"
        },
        {
          "answer": "file/vsys1: security rule Corp DC Access (source)",
          "device": "file",
          "vsys": "vsys1",
          "stage": "reference",
          "kind": "security rule",
          "name": "Corp DC Access",
          "field": "source",
          "via": "corp-location",
          "path": "/config/devices/localhost.localdomain/vsys/vsys1/rulebase/security/rules/Corp DC Access",
          "scope": "vsys:vsys1"
        }
      ],
      "summary": {
        "answer": "1 with results, 2 without, 0 holes",
        "found": 6,
        "with": 1,
        "without": 2,
        "omitted": 0
      },
      "holes": [],
      "unresolved": [],
      "notes": []
    }
    ```

The address lies in two objects: a host and the /16 network that covers it. Each
object reaches the rule `Corp DC Access` through a group. The other two vsys of
the file hold no finding.

### Find the group to edit

```text
$ proteus search 10.1.1.1 --file testdata/config/firewall-nested-groups.xml
search 10.1.1.1 (covers)

file / vsys1   testdata/config/firewall-nested-groups.xml
  object    address       h-1         10.1.1.1/32
  group     address-group g-inner     holds h-1
  group     address-group g-middle    holds h-1
  group     address-group g-outer     holds h-1
  reference address-group g-inner     static -> h-1
  reference address-group g-middle    static -> g-inner
  reference address-group g-outer     static -> g-middle
  reference security rule allow-outer source -> g-outer
1 with results, 0 without, 0 holes
```

The rule names only `g-outer`, and the address sits three groups down. Add
`--direct` to keep the groups one level up, and `--show` to drop the references:

```text
$ proteus search 10.1.1.1 --direct --show objects,groups \
    --file testdata/config/firewall-nested-groups.xml
search 10.1.1.1 (covers)

file / vsys1   testdata/config/firewall-nested-groups.xml
  object address       h-1     10.1.1.1/32
  group  address-group g-inner holds h-1
1 with results, 0 without, 0 holes
```

### Find addresses written into rules

```text
$ proteus search 198.18.1.1 --file testdata/config/firewall-literals.xml
search 198.18.1.1 (covers)

file / vsys1   testdata/config/firewall-literals.xml
  object    address       named-host   198.18.1.1/32
  reference security rule named-rule   source -> named-host
  literal   security rule literal-host source 198.18.1.1/32
  literal   security rule literal-net  source 198.18.0.0/16
1 with results, 0 without, 0 holes
```

Some configurations write addresses into rule fields and name no object. The
`literal` stage finds these rules, here a host and a /16 that covers the term.

### Search for an application

```text
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

With the device's App-ID data, search finds each place that selects the
application. The rule `allow-remote` allows `ssl` only through the implicit use
of `app-remote`. The data comes from the snapshot, or with `--file` from
`apps.xml.gz` beside the configuration (see
[Simulate policy](simulate-policy.md#where-the-app-id-data-comes-from)).

### Search for a user

```text
$ proteus search alice@example.com --file users/config.xml
search alice@example.com (matches)

file / vsys1   users/config.xml
  note: application data of content 8000-1000 from users/apps.xml.gz
  note: identity data taken 2026-10-19T02:00:00Z from users/identity.json.gz
  object    user          alice@example.com                          example.com\alice
  object    user          example.com\alice                          example.com\alice
  object    user-group    CN=Domain Users,CN=Users,DC=example,DC=com ldap:example.com, 3 members
  object    user-group    cn=domain users,cn=users,dc=example,dc=com ldap:example.com, 3 members
  object    user-group    cn=payroll,ou=groups,dc=example,dc=com     ldap:example.com, 1 member
  object    user-group    example.com\domain users                   ldap:example.com, 3 members
  identity  mapping       198.51.100.11                              user example.com\alice, XMLAPI, timeout 14400 s
  reference security rule u-dn-case                                  source-user -> CN=Domain Users,CN=Users,DC=example,DC=com
  reference security rule u-ldap-group                               source-user -> cn=domain users,cn=users,dc=example,dc=com
  reference security rule u-multi                                    source-user -> cn=payroll,ou=groups,dc=example,dc=com
  reference security rule u-short                                    source-user -> example.com\domain users
  reference security rule u-upn                                      source-user -> alice@example.com
  reference security rule u-user                                     source-user -> example.com\alice
1 with results, 0 without, 0 holes
```

The UPN `alice@example.com` is an alternate name of `example.com\alice`, so search
reads it as that user. The `object` rows are the `source-user` members of the
rules that the user satisfies, each with the user or with the source and member
count of the group. The rules name one directory group in three forms: the DN,
the DN in another case, and the short name. The `identity` row is the address
that the firewall maps to the user. The data comes from the snapshot, or with
`--file` from `identity.json.gz` beside the configuration (see
[Users](#users)).

## Reading the output

The first line repeats the term and the match in parentheses. Each block is one
device and one vsys. The summary line counts the vsys with results, the vsys
without results, and the holes.

### Stages

Each row starts with its stage. The stages print in this order:

| Stage | What it finds |
| --- | --- |
| `object` | objects whose value holds the term, and objects with that name; with User-ID data, the users and groups of the rules that a user term satisfies |
| `identity` | with User-ID data: the user and its groups that no `object` row shows, and the mapped addresses (see [Users](#users)) |
| `group` | groups that hold one of those objects, at any depth |
| `reference` | rules, NAT rules, groups and profiles that name one of them |
| `literal` | rules that write the term directly into a field |

A rule whose field is `any` reaches every value, but no object leads to it.
Search leaves such rules out (see
[Concepts](../concepts/index.md#from-a-value-to-a-rule)).

### Terms

The term's type sets the default match (see
[Concepts](../concepts/index.md#from-a-value-to-a-rule)).

| Term | Match in the first line | What search finds |
| --- | --- | --- |
| address, such as `10.124.0.1` | `covers` | objects and literals whose value holds the address |
| prefix or range, such as `10.124.0.0/24` | `overlaps` | objects and literals whose value overlaps it |
| port, such as `tcp/8006` or `8006` | `covers` | every service whose range holds the port, such as `tcp/8000-8100` |
| URL, such as `shop.example.com/cart` | `matches` | values that match by PAN-OS URL tokens |
| user, such as `example.com\alice`, a UPN or an email | `matches` | with User-ID data: the user's groups with their source, the rules that name the user or a group, and the mapped addresses; without it, the local user groups that hold the user |
| group, such as a group DN | `matches` | with User-ID data: the rules that name the group, with its source and member count |
| anything else | `matches` | objects with that exact name or value |
| any term with `--within`, `--exact` or `--contains` | `within`, `exact` or `contains` | see [Flags](#flags) |

An address with a mapping also gives an `identity` row with the mapped user.

### Users

A configuration does not say which directory groups a user belongs to. The
User-ID data of a snapshot does. `proteus fetch` stores it with each snapshot, and
`--file` reads `identity.json.gz` beside the configuration (see
[User-ID data](../concepts/snapshots.md#user-id-data)).

| Finding | What it says |
| --- | --- |
| `object user` | a `source-user` member that names the user, with the primary name |
| `object user-group`, `object dynamic-user-group` | a group of a rule that holds the user, with its source and member count, such as `ldap:example.com, 3 members` |
| `identity identity-user` | the user, when no `object` row shows it |
| `identity identity-group` | a group of the user that no `object` row shows |
| `identity mapping` | an address that the firewall maps to the user, with the type and the timeout; for an address term, the mapped user |
| `reference security rule` | a rule that names the user or one of its groups |

The term reads as `--user` of [simulate policy](simulate-policy.md#names) does: a
UPN, an alternate name and an email give the primary name, in any case. A rule
that names `any`, `known-user`, `unknown` or `pre-logon` is no finding.

A group term finds each rule that names the group: by its DN, by its DN in
another case, and by its short name `<domain>\<cn>`. For a user of the group,
[simulate policy](simulate-policy.md#how-a-rule-matches-a-user) matches the same
rules. The group name given as `--user` is no user and matches no rule (see
[Names](simulate-policy.md#names)): search shows where a name is used, and
simulate shows what the firewall matches.

search reads the User-ID data at once for an address, for a term with `\`, `@` or
`=`, and for a term that a rule names as `source-user`. For another term, it reads
the data only when the first search of a vsys finds nothing, and then searches
that vsys again. A `--file` configuration whose `identity.json.gz` Proteus cannot
read then adds `gap.no-user-directory` with the cause, also for a term that is no
user.

### URL categories in security profiles

A URL category can reach a rule through the rule's security profile, besides the
rule's `category` field. The reference then shows the profile path:

```text
  reference security rule       via-group          profile-setting -> default > default-url-filter alert demo-category
  reference security rule       via-named-profile  profile-setting -> default-url-filter alert demo-category
  reference url-filtering       default-url-filter alert -> demo-category
```

A profile inspects traffic that a rule already matched. The rule does not match
because of the profile.

### Applications

| Finding | What it says |
| --- | --- |
| `object application` | the application; `predefined` marks an application of the App-ID data |
| `object application-filter` | a filter that selects it, with the fields that select it, such as `category=media, risk=4` |
| `object application-container` | the container that holds it |
| `group application-group` | a group that holds it, with the path through nested groups: `outer > inner > ssl` |
| `reference security rule` | a rule that names it, or a group, filter or container that holds it |
| `... implicit use by <app>` | an allow rule that allows it only through the implicit use of another application |

The term takes any case, and the findings use the name as the data writes it. A
filter `exclude` that names the application, or its container, shows as a
reference.

Without App-ID data, search finds only the custom applications of the
configuration. The note `note.app-data-missing` then says what search cannot
find: filters, containers and implicit use.

## Flags

Search takes the selection flags `--device`, `--label`, `--vsys`, `--at`,
`--fresh` and `--file` (see [Selection flags](../reference/global-flags.md#selection-flags)).

| Flag | Default | Description |
| --- | --- | --- |
| `--within` | off | keeps values that lie wholly inside the term (addresses, prefixes, ranges) |
| `--exact` | off | keeps values equal to the term |
| `--contains` | off | keeps names and values that hold the term as text |
| `--kind <kinds>` | every kind | keeps objects and groups of these kinds, such as `address,service` |
| `--field <fields>` | every field | keeps references and literals from these fields, such as `source,destination` |
| `--show <stages>` | every stage | keeps these stages: `objects`, `identity`, `groups`, `refs`, `literals` |
| `--direct` | off | keeps only the groups one level up from an object |
| `--why` | off | adds each finding's answer line under its row |
| `--limit N` | every finding | keeps the first N findings (see [Results](../reference/output.md#results)) |
| `--detail` | `full` | with `--output json` or `yaml`, see [Detail](../reference/output.md#detail) |

You can use only one of `--within`, `--exact` and `--contains` at a time.

`--within` and `--exact` compare an address's whole value, in an object or
written into a rule. The range `10.0.0.2-10.0.0.9` is not within `10.0.0.0/29`,
because two of its addresses lie outside it. It is also not exactly
`10.0.0.4/30`.

`--contains` compares text and ignores the term's type. Use it to find a long URL
in a custom URL category, because a category name cannot hold the URL.

`--limit N` counts findings in the usual order, over all devices and vsys
together. It takes 1 or more, and `--limit 0` is a usage error with exit 2. The
counts on the summary line stay for the whole answer, and the line ends with
`2 of 6 shown, narrow by device, vsys or kind`. In JSON and YAML,
`summary.found` counts every finding and `summary.omitted` counts the findings
that the limit leaves out. The limit never cuts holes, unresolved entries or
notes. In text, the notes of a vsys whose findings the limit leaves out print
below the findings, as `note: fw02/vsys1: <text>`.

## Limits

- A search for a prefix or range, or with `--within` or `--exact`, lists each
  wildcard address object that can hold one of its addresses as unresolved, and
  exits with code 3.
- A reference outside any vsys, such as a static route, matches by name alone,
  with scope `config`.
- Without App-ID data, search finds no filter, container or implicit use of an
  application.
- Without User-ID data, search finds no directory group of a user and no mapped
  address.

See [Limits](../reference/limits.md#search).

## See also

- [lookup](lookup.md)
- [simulate policy](simulate-policy.md)
- [From a value to a rule](../concepts/index.md#from-a-value-to-a-rule)
- [App-ID data](../concepts/snapshots.md#app-id-data)
- [User-ID data](../concepts/snapshots.md#user-id-data)
- [Holes, unresolved entries and notes](../concepts/fidelity.md#holes-unresolved-entries-and-notes)
- [Output and exit codes](../reference/output.md)
