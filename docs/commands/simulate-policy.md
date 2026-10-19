# simulate policy

Does the estate allow a flow end to end, and which rule decides it on each firewall?

## Synopsis

```text
proteus simulate policy <source> <destination> [flags]
proteus simulate policy <source> <destination> --file <config.xml> [flags]
```

The first form is **path mode**, the default. It traces the path as
[simulate routing](simulate-routing.md) does and checks the security policy of
every firewall and vsys on that path. The second form checks one configuration
file, with no inventory and no path.

## Examples

### A path that a firewall denies

```text
$ proteus simulate policy 198.18.1.10 198.18.10.100 --port 443
denied at hop 2: fw01 / vsys1, rule block-servers (deny)

simulate policy 198.18.1.10 -> 198.18.10.100 tcp/443            fidelity: exact

  198.18.1.10
     │ 198.18.1.0/24
  ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   home -> labor                               │
  │  in      vlan.1        198.18.1.1/24                 │
  │  out     vlan.32       198.19.0.1/24                 │
  │  route   198.18.0.0/15 via 198.19.0.254   static     │
  │  policy  interzone-default (allow)                   │
  └──┬───────────────────────────────────────────────────┘
     │ 198.19.0.0/24   198.19.0.1 -> 198.19.0.254
  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   transport -> server                         │
  │  in      ethernet1/1   198.19.0.254/24               │
  │  out     ethernet1/2   198.18.10.1/24                │
  │  route   198.18.10.0/24  connected                   │
  │  policy  block-servers (deny)                        │
  └──┬───────────────────────────────────────────────────┘
     │ 198.18.10.0/24
  198.18.10.100   delivered

firewalls on the path: fw02 (home -> labor), fw01 (transport -> server)
```

The first line gives the verdict. Each box is one hop, and its `policy` row names
the rule that decides that hop. Path mode takes the zones from the path, so you
give no zones.

### A path that leaves the estate

```text
$ proteus simulate policy 198.18.1.10 198.18.10.100 --port 443
undecided at hop 1: fw02 / vsys1, 198.19.0.77 leaves the estate (not in the inventory)

simulate policy 198.18.1.10 -> 198.18.10.100 tcp/443            fidelity: undermatch

  198.18.1.10
     │ 198.18.1.0/24
  ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   home -> labor                               │
  │  in      vlan.1        198.18.1.1/24                 │
  │  out     vlan.32       198.19.0.1/24                 │
  │  route   198.18.0.0/15 via 198.19.0.77   static      │
  │  policy  interzone-default (allow)                   │
  └──┬───────────────────────────────────────────────────┘
     │ 198.19.0.0/24
  198.19.0.77   leaves the estate (not in the inventory)

firewalls on the path: fw02 (home -> labor)
may be incomplete: the path leaves the estate at 198.19.0.77
unresolved: fw02/vsys1: 198.19.0.77 leaves the estate (not in the inventory)
```

The next hop 198.19.0.77 is no firewall of the inventory, so proteus cannot check
the rest of the path. The run exits with code 3. See [Undecided](#undecided) for
every cause of an undecided hop.

### One configuration with given zones

=== "text"

    ```text
    $ proteus simulate policy 10.2.0.5 10.1.0.5 --port 443 \
        --from-zone dmz --to-zone inside --file testdata/config/firewall-zones.xml
    10.2.0.5 -> 10.1.0.5 tcp/443
    file / vsys1   testdata/config/firewall-zones.xml
      zones      from dmz, to inside (given)
      relevance  unknown: no stored forwarding table
      fidelity   exact
    first match: interzone-default (deny), default rule (built-in)
    ```

=== "json"

    ```json
    {
      "format": 2,
      "command": "simulate policy",
      "detail": "summary",
      "input": {
        "flow": {
          "source": {
            "addrs": [
              "10.2.0.5"
            ],
            "resolved": false
          },
          "destination": {
            "addrs": [
              "10.1.0.5"
            ],
            "resolved": false
          },
          "protocol": "tcp",
          "port": 443,
          "from_zone": "dmz",
          "to_zone": "inside"
        },
        "selection": {
          "file": "testdata/config/firewall-zones.xml"
        }
      },
      "results": [
        {
          "answer": "first match: interzone-default (deny), default rule (built-in)",
          "verdict": "stop",
          "reasons": [
            {
              "code": "verdict.default",
              "text": "default rule interzone-default (deny), built-in"
            }
          ],
          "rule": "interzone-default",
          "default_action": "deny",
          "fidelity": {
            "level": "exact"
          },
          "doubts": [],
          "zones": {
            "from": [
              "dmz"
            ],
            "to": [
              "inside"
            ],
            "source": "given"
          },
          "relevance": {
            "known": false,
            "relevant": false,
            "code": "gap.fib-missing",
            "text": "no stored forwarding table"
          },
          "target": {
            "device": "file",
            "vsys": "vsys1"
          }
        }
      ],
      "holes": [],
      "unresolved": [],
      "notes": []
    }
    ```

No rule matches the flow from `dmz` to `inside`, so the built-in
`interzone-default` rule denies it. The JSON tab shows the output of
`--output json --detail summary`. The [relevance](../concepts/fidelity.md#relevance)
is `unknown`, because a file holds no forwarding table.

### An application on one configuration

```text
$ proteus simulate policy 10.1.0.5 10.2.0.5 --application web-browsing --port 80 \
    --why --file demo/config.xml
10.1.0.5 -> 10.2.0.5 tcp/80
file / vsys1   demo/config.xml
  note: application data of content 8000-1000 from demo/apps.xml.gz
  note: the device can match the session again when App-ID identifies it later: an earlier application, such as ssl or web-browsing, can match another rule than web-browsing
  note: rule allow-remote matches web-browsing only through the implicit use of app-remote
  zones      from inside, to outside (configuration)
  relevance  unknown: no stored forwarding table
  fidelity   inferred
  resolve-source      exact    8 10.1.0.5: 0 hits, 0 negated rules
  resolve-destination exact    8 10.2.0.5: 0 hits, 0 negated rules
  derive-zones        inferred 8 from inside; to outside (configuration)
  match-application   exact    1 web-browsing: 0 explicit, 1 implicit, 0 kept in doubt (content 8000-1000)
  match-service       exact    1 tcp/80; protocol tcp, from the default of web-browsing (tcp/80; tcp/443/secure)
  match-url           exact    1 no candidate names a URL category
  drop-disabled       exact    1 0 disabled
  order               exact    1 1 in order
  first-match         exact    1 allow-remote (allow), position 8
  8. allow-remote allow [local vsys:vsys1]
first match: allow-remote (allow)
```

The App-ID data comes from `apps.xml.gz` beside the configuration. `allow-remote`
names `app-remote`, whose implicit use holds `web-browsing`. The run gives no
zones, so proteus derives them and the answer is `inferred`.

### A user on one configuration

```text
$ proteus simulate policy 198.51.100.11 192.0.2.10 --port 443 \
    --from-zone inside --to-zone outside --file users/config.xml
198.51.100.11 -> 192.0.2.10 tcp/443
file / vsys1   users/config.xml
  note: identity data taken 2026-10-19T02:00:00Z from users/identity.json.gz
  note: the user example.com\alice comes from the mapping of 198.51.100.11
  zones      from inside, to outside (given)
  user       example.com\alice (from the mapping of 198.51.100.11)
  relevance  unknown: no stored forwarding table
  fidelity   exact
  1. u-ldap-group allow [local vsys:vsys1]
first match: u-ldap-group (allow)
```

The User-ID data comes from `identity.json.gz` beside the configuration. The
source address has a mapping to `example.com\alice`, so the flow has that user,
as on the firewall. `u-ldap-group` names the directory group
`cn=domain users,cn=users,dc=example,dc=com`, which holds the user. A `--user`
flag would not change the answer: the mapping wins. See [Users](#users).

## Reading the output

### Path mode

The first line is the verdict:

| Line | Meaning |
| --- | --- |
| `allowed` | every hop passes and routing delivers the flow |
| `denied at hop N: <device> / <vsys>, rule <name> (<action>)` | a rule or a default rule stops the flow |
| `denied at hop N: no route to <address> on <device>` | routing drops the flow on that hop |
| `undecided at hop N: <device> / <vsys>, <reason>` | proteus cannot decide that hop |

The first hop that stops the flow, or that is undecided, sets the verdict.
proteus still checks every other hop, and a hop after the deny shows
`(after the deny)`. A deny after an undecided hop leaves the verdict `undecided`,
and a note names the later deny.

Each box holds the rows of [simulate routing](simulate-routing.md) and a `policy`
row with the hop's answer:

| Row | Meaning |
| --- | --- |
| `policy  <rule> (<action>)` | the rule that decides the hop |
| `policy  interzone-default (deny)` | no rule matches, and a default rule decides |
| `policy  undecided: <reason>` | the hop is undecided |
| `policy  not evaluated: <reason>` | the check did not run, for example after a routing drop |
| `user  <user> (<from>)` | the user of the hop's check and where it comes from, see [Users](#users) |
| `doubt  <reason>` | a doubt that comes from the path or the zones, see [Undecided](#undecided) |

Each hop's check uses the hop's flow. That flow has the addresses after any NAT
on an earlier hop, and the zones that routing gives on that hop.

The path starts where the source is connected, or where the most specific route to
the source leaves. When two firewalls connect the source, or only default routes
cover it, the command exits 2 and asks you to name the start with `--device <name>`.

Path mode needs one address per endpoint. proteus resolves an FQDN endpoint with
this machine's DNS and traces the first IPv4 address, and FQDN objects of that name
still match. With `--no-dns`, or when the name has no IPv4 address, the command
exits 2: "path mode needs an address for <name>; remove --no-dns or give an address".

Each device answers from its latest snapshot, or from its latest one at or before
`--at`. For an HA pair, proteus reads the snapshot of the active member.

`--why` adds the stages of routing, then one block per hop. The block holds the
security verdict, the candidate rules with their doubts, the default rule and the
[stage table](#stages):

```text
$ proteus simulate policy 198.18.1.10 198.18.10.100 --port 443 --why
denied at hop 1: fw02 / vsys1, rule interzone-default (deny)
...
hop 1: fw02 / vsys1, security stop: default rule interzone-default (deny), built-in
  - interzone-default deny [default built-in]
  resolve-source      exact 0 198.18.1.10: 2 hits, 0 negated rules
  resolve-destination exact 0 198.18.10.100: 1 hits, 0 negated rules
  derive-zones        exact 0 from home, to labor, as given
  match-application   exact 0 no application given
  match-service       exact 0 tcp/443
  match-url           exact 0 no candidate names a URL category
  drop-disabled       exact 0 0 disabled
  order               exact 0 0 in order
  first-match         exact 0 no enabled rule matches; default rule interzone-default (deny), built-in
```

`--output json` gives one result with these keys:

| Key | Content |
| --- | --- |
| `mode` | the mode of the run |
| `verdict` | `allowed`, `denied` or `undecided` |
| `at` | the hop, the check, the rule and the reason that set the verdict |
| `fidelity` | the [fidelity](../concepts/fidelity.md) of the answer |
| routing's fields | the path, as [simulate routing](simulate-routing.md) gives it |
| per hop: `doubts`, `after_deny`, `checks.security` | the hop's doubts, whether it comes after the deny, and its security check |

The `checks.security` block has the same keys as a `--file` result.

A destination that the firewall itself owns gets the same check as any other hop.
A note says that proteus does not check the firewall's own services, the interface
management profile.

### `--file` mode

The header shows the flow, then one block per vsys:

| Row | Meaning |
| --- | --- |
| `file / <vsys>   <path>` | the configuration and the vsys of the check |
| `note: <text>` | a note, for example the App-ID data file that the run reads |
| `zones` | the zones and where they come from: `given` or `configuration` |
| `user` | with User-ID data: the user of the flow and where it comes from, or `none`, see [Users](#users) |
| `relevance` | always `unknown: no stored forwarding table` for a file |
| `fidelity` | the [fidelity](../concepts/fidelity.md) of the answer, with the rules in doubt |
| `unresolved: <vsys>: <reason>` | the rule that keeps the answer undecided |

The last lines give the answer:

| Line | Meaning |
| --- | --- |
| `first match: <rule> (<action>)` | the rule that decides the flow |
| `first match: <rule> (<action>), default rule (<source>)` | no rule matches, and a [default rule](#default-rules-and-rule-type) decides |
| `first certain match: <rule> (<action>)` | the first rule that surely matches, in an undecided answer |
| `undecided: <rule> (<action>) at position N may match first: <reason>` | the earlier rule in doubt that keeps the answer undecided |

Without `--from-zone` and `--to-zone`, proteus derives the zones from the
interfaces and routes of the configuration. A derived zone is always `inferred`.
`--file` does not check NAT, so a derived zone is the zone before NAT.

!!! warning
    Derived zones can give a wrong answer. Against a lab firewall's own
    `test security-policy-match`, 3 of 7 probe flows agreed with derived zones
    and 7 of 7 with given zones. Give `--from-zone` and `--to-zone` when you
    know them.

With one derived zone on each side, the default rules decide a flow that no rule
matches. With several derived zones on a side, or none, such a flow is undecided:
"the default rule depends on the zones".

`--why` shows every stage, each candidate with its doubts, and the default rule:

```text
$ proteus simulate policy 198.19.0.254 10.2.0.5 --port 443 --why \
    --from-zone labor --to-zone dmz --file testdata/config/firewall-doubt.xml
198.19.0.254 -> 10.2.0.5 tcp/443
file / vsys1   testdata/config/firewall-doubt.xml
  zones      from labor, to dmz (given)
  relevance  unknown: no stored forwarding table
  fidelity   overmatch: earlier candidates in doubt share the action deny: labor-app; not evaluated: application
  resolve-source      exact     14 198.19.0.254: 1 hits, 0 negated rules
  resolve-destination exact     12 10.2.0.5: 0 hits, 0 negated rules
  derive-zones        exact     1  from labor, to dmz, as given
  match-application   exact     1  no application given
  match-service       exact     1  tcp/443
  match-url           exact     1  no candidate names a URL category
  drop-disabled       exact     1  0 disabled
  order               exact     1  1 in order
  first-match         overmatch 1  every candidate is in doubt; default rule interzone-default (deny), built-in
  14. labor-app         deny [local vsys:vsys1]
      doubt: application not evaluated (dropbox)
  -   interzone-default deny [default built-in]
first match: interzone-default (deny), default rule (built-in)
```

`labor-app` names an application, and the run has no `--application`, so the rule
is in doubt. It denies like the default rule, so the answer is still decided.

An undecided answer ends with the first rule that surely matches and the cause.
That run exits with code 3:

```text
$ proteus simulate policy 10.0.0.5 203.0.113.5 --port 443 \
    --from-zone dmz --to-zone wan --file testdata/config/firewall-doubt.xml
...
unresolved: file/vsys1: dmz-user (deny) at position 7 may match first: user not evaluated (corp\alice)

first certain match: dmz-plain (allow)
undecided: dmz-user (deny) at position 7 may match first: user not evaluated (corp\alice)
```

### Stages

A check runs named stages. Each stage removes candidate rules and declares its
[fidelity](../concepts/fidelity.md). A `--why` row shows the stage, its fidelity,
the candidates that remain, and the detail.

| Stage | What it does |
| --- | --- |
| `resolve-source` | keeps rules whose source reaches the source address or FQDN |
| `resolve-destination` | the same for the destination |
| `derive-zones` | keeps rules whose zones and rule-type match, given or derived |
| `match-application` | keeps rules whose application matches `--application`, explicit or through implicit use |
| `match-user` | with User-ID data: keeps rules whose `source-user` matches the user of the flow, see [Users](#users) |
| `match-service` | keeps rules whose service holds `--port`, or whose `application-default` holds it |
| `match-url` | keeps rules whose URL category matches `--url` |
| `drop-disabled` | removes disabled rules |
| `order` | sorts the rest in evaluation order and lists the doubts of each rule |
| `first-match` | decides at the first rule without doubt, else at a default rule |

### Undecided

proteus decides a hop at the first candidate rule that it can evaluate in full.
An earlier candidate that it cannot evaluate is **in doubt**, because the firewall
can match it first. When every such rule has the same action, the hop is decided
with the fidelity `overmatch`. When one of them has another action, the hop is
undecided.

| Cause | Examples |
| --- | --- |
| a candidate above the match names an application | an application or service `application-default` without `--application` or without App-ID data; an application that the App-ID data does not hold, see [Applications](#applications) |
| a candidate above the match names a service that proteus cannot read | a predefined service such as `service-https` that the snapshot does not hold, a service group that holds one, or no service |
| a candidate above the match names a value without data | a user or a group without User-ID data, a Cloud Identity Engine group, a group that a missing part of the User-ID data cannot judge, a HIP profile or a schedule |
| a candidate above the match names a URL category | without `--url`, or a category that the configuration does not define, such as a PAN-DB category |
| a candidate names a runtime source or destination | an external dynamic list, a region or a dynamic address group; these rules stay candidates, because their members are known only at runtime |
| a doubt on the path | ECMP (proteus does not follow the other next hops), a PBF rule that can redirect the flow, a NAT or PBF answer that can miss matches, or a start that only a default route places |
| the zones | the vsys of the hop is unknown, a zone is missing, a zone is the placeholder `external` of a vsys crossing, or the vsys does not define the zone |
| the default rules | the local and the pushed override of a default rule have different actions, and proteus does not know which one wins |
| the routing end | the path leaves the estate, loops, or ends unresolved |

When a PBF rule only may match, the hop also says why, for example a service and
no `--port`.

### Default rules and rule-type

A firewall evaluates its default rules after every other rule, and proteus does
the same. `intrazone-default` decides a flow with equal zones, and
`interzone-default` decides a flow with different zones. The built-in actions are
allow and deny, and an override in the configuration changes the action:

| Source | Where it comes from |
| --- | --- |
| `built-in` | no override |
| `local` | the default rule override of the vsys |
| `pushed` | an override that Panorama pushed |

When a local and a pushed override have the same action, the output shows `local`.
When their actions differ, the hop is undecided.

proteus applies the `rule-type` of each rule:

| Rule-type | Matches |
| --- | --- |
| `universal` | both zones are in the lists of the rule |
| `intrazone` | equal zones only |
| `interzone` | different zones only |

Path mode always knows both zones. With `--file`, rule-type and the default rules
apply when you give both zones, or when proteus derives one zone on each side. The
answer is then `inferred`. With several derived zones on a side, or none, an
`intrazone` or `interzone` rule stays in doubt (`zone.derived`). The answer is
undecided when that rule can change it.

### Applications

`--application <name>` gives the application of the flow: a predefined application
or a custom application of the configuration. proteus then matches it as the
firewall does, from the App-ID data of the device.

#### Where the App-ID data comes from

| Mode | Source |
| --- | --- |
| path mode | each hop reads the App-ID data of the content version of its snapshot; `proteus fetch` stores it, see [App-ID data](../concepts/snapshots.md#app-id-data) and [fetch](fetch.md); the hops of one path can have different content versions |
| `--file` | `apps.xml.gz` in the directory of the configuration; the note `note.app-data-file` names the file and its content version; nothing checks that the version is the device's; copy the file from `<store>/.content/<version>.v1.xml.gz` |
| no data | a snapshot without a content version, a missing file or a file that proteus cannot read gives the note `note.app-data-missing`; the answer is then the same as without `--application` |

#### How a rule matches

The name takes any case. A custom application of that name wins over a predefined
one. The answer writes the name as the data or the configuration writes it.

The `match-application` stage keeps three kinds of rule:

| Kind | A rule is one when |
| --- | --- |
| explicit | its application is the flow's, `any`, a group that holds it at any depth, a filter that selects it, or a container that holds it |
| implicit | it allows, and one of its predefined applications lists the flow's application in its implicit use |
| kept in doubt | it names an application or a container that neither the data nor the configuration holds (`doubt.application-unknown`) |

The first match comes in two passes. First come the explicit rules and the rules
kept in doubt, in rule order. Then come the implicit rules, in rule order. So an
explicit match wins over an implicit one, also when it comes later. The default
rules come last.

A deny rule never matches through implicit use, and a custom application never
implies another. An implicit match carries `note.app-implicit`, which names the
application that implies the flow's application.

A filter counts the tags that the configuration adds to an application with
`application-tag`. A filter `exclude` removes the named applications and every
function of a named container.

Every answer with an application carries `note.app-shift`. The firewall can match
the session again when App-ID identifies it later. proteus evaluates one
application per flow, as `test security-policy-match` does.

#### application-default

A rule with service `application-default` matches when the protocol and port of
the flow are in the default ports of the application. For an implicit match, the
ports are those of the rule's applications that imply the flow's application.

| Default | Matches |
| --- | --- |
| `tcp/80,443`, `udp/53`, ranges | that protocol and those ports |
| a secure extended port, such as `tcp/443/secure` | that port, with `note.app-secure-port` |
| `tcp/dynamic`, `tcp/any` | any port of that protocol |
| an IP protocol, such as 89, or a range of them | that protocol, any port |
| an ICMP or ICMPv6 type | protocol 1 or 58, with `note.app-icmp-type`: proteus does not check the type |
| no default | any protocol and port |

A rule with a custom service matches on the ports of the service. When such a port
is not a default port of the application, `note.app-non-default-port` says so.
Without `--port`, a rule with `application-default` stays in doubt
(`doubt.app-port-open`).

#### The protocol

Without `--protocol`, `--application` takes the protocol of the application's
default: `ssl` gives tcp, and `ospf` gives 89. An application with several default
protocols, or with no default, leaves the protocol open. A rule that depends on the
protocol then stays in doubt. The header line shows the protocol of the run.

`simulate routing` and `simulate nat` keep `tcp`. In path mode, routing and NAT see
the open protocol, so a NAT or PBF rule that names a service stays in doubt. Give
`--protocol` to decide it.

A protocol without ports, such as icmp or 89, never matches a custom service or a
service group. Such a flow drops those rules, with or without `--application`.

#### A name that is no application

The firewall refuses an unknown name and a container as the application of a flow.
With `--file`, proteus exits 2 and suggests up to five names. For a container, the
suggestions are its functions:

```text
$ proteus simulate policy 10.1.0.5 10.2.0.5 --application office-suite --file demo/config.xml
proteus: --application office-suite is an application container in content 8000-1000, not an application; name one of its functions: office-docs, office-mail
```

In path mode, such a name leaves that hop undecided. The reason names the device
and its content version, because another hop can have another content version.

### Users

`--user <name>` gives the user of the flow. With User-ID data, proteus matches the
`source-user` of each rule as the firewall does: the mapping of the source
address, the directory groups, the XML API groups and the dynamic user groups
decide the rule.

#### Where the User-ID data comes from

| Mode | Source |
| --- | --- |
| path mode | each hop reads the User-ID data of its own snapshot; `proteus fetch` stores it, see [User-ID data](../concepts/snapshots.md#user-id-data) and [fetch](fetch.md) |
| `--file` | `identity.json.gz` in the directory of the configuration; the note `note.identity-file` names the file and the time the data was taken; nothing checks that the file belongs to the configuration; a file older than `max_snapshot_age` adds `gap.user-directory-stale`; copy the file out of a snapshot, see [snapshot](snapshot.md#user-id-data) |
| no data | a snapshot or a directory without the file: a rule that names a user or a group stays in doubt (`doubt.not-evaluated.user`); a file that proteus cannot read adds `gap.no-user-directory` with the cause, and the answer is the same as without data |

proteus reads the data only when `--user` is given or a rule of the vsys names a
`source-user` other than `any`.

#### The user of a flow

The firewall takes the user from the mapping of the source address. proteus does
the same:

| `--user` | Mapping of the source | User of the flow | Note |
| --- | --- | --- | --- |
| given | none | `--user`, read as its primary name | `note.user-resolved` when proteus reads an alternate name or an email; `note.user-not-in-directory` when no user of the data has the name |
| none | present | the mapped user, as the firewall stores it | `note.user-from-mapping`; `note.user-not-in-directory` when the name is no primary name |
| given | present, another user | the mapped user: the mapping wins | `note.user-from-mapping` names both users |
| none | none | no user, see [No user](#no-user) | `note.user-unknown-inferred` when a candidate names a user |

The source address of the check is the first address of the flow: for an FQDN,
its first address. An IPv6 mapping is found by its address. A mapping of the user
`unknown` counts as no mapping.

#### Names

| Name | How proteus reads it |
| --- | --- |
| a primary name, such as `example.com\alice` | as it is, in any case |
| `--user` as a UPN or another alternate name, such as `alice@example.com` | as its primary name, with `note.user-resolved` |
| `--user` as an email | as its primary name; the answer is `inferred`, because no device was seen to resolve an email |
| `--user` that no user of the data has | as given, with `note.user-not-in-directory`; it matches `any`, `known-user` and a rule that names the same text only |
| `--user` as a group, such as `example.com\domain users` | as no user: it matches no rule by its text, as on the firewall |
| a mapped user | as the firewall stores it, against primary names only |
| a rule that names a UPN or an alternate name | as the primary name of that user |
| a rule that names an email | as written: an email in a rule matches no user |

A firewall can store a mapping in the NetBIOS form, such as `example\alice`.
That name is no primary name, so it matches `any`, `known-user` and a rule that
names `example\alice` only, as on the firewall.

`--user any`, `--user known-user` and `--user unknown` exit 2: these are rule
keywords, not users. Leave `--user` out for a flow without a user.
`--user pre-logon` is valid.

#### How a rule matches

The `match-user` stage keeps a rule when one member of its `source-user` matches
the user of the flow:

| Member | Matches |
| --- | --- |
| `any`, or no `source-user` | every flow |
| `known-user` | a flow with a user other than `pre-logon` |
| `unknown` | a flow without a user |
| `pre-logon` | `--user pre-logon` only |
| a user | the user of the flow |
| a directory or XML API group | a user that the group holds, as the firewall lists the members; the group name takes any case, and the short name `<domain>\<cn>` of a directory group names the group |
| a dynamic user group | a user that the firewall lists as a member; proteus does not evaluate the tag filter |
| a Cloud Identity Engine group | no flow: the rule stays a candidate, in doubt (`doubt.user-cie-group`) |
| a local user or a local user group | as the local user database of the configuration holds it |
| a group that the data does not hold | no flow |

When a part of the User-ID data is missing, the answer is never `exact`. A member
that the missing part cannot judge keeps its rule in doubt
(`doubt.user-data-missing`, which names the part):

| Missing part | Members in doubt |
| --- | --- |
| `users.groups` | each group and dynamic user group |
| `groups` | each member that is no user of the data |
| `users.names` | each member with `@` that is no primary name |
| `mappings` | none; a source without a mapping has a user in doubt, and the answer is `inferred` with `note.identity-part-missing` |

A mapping table that `fetch` cut or read while it changed counts as a missing
`mappings` part. A source with a mapping keeps its fidelity: the mapping decides.

#### No user

A flow without `--user` and without a mapping has no user. It matches `any`,
`unknown` and the rules without a `source-user`. When a candidate names a
`source-user` other than `any`, the answer is `inferred`, with
`note.user-unknown-inferred`. proteus follows the PAN-OS admin guide, where
`known-user` takes an identified user only. The firewall's own
`test security-policy-match` matches `known-user` without a user, and no traffic
test confirms `unknown`. `--user pre-logon` is no identified user either, and its
answer is `inferred` too.

When no candidate names a user, the user decides nothing, and the fidelity stays.

#### A hop after NAT

In path mode, each hop looks up the source address that its firewall sees: after
NAT on an earlier hop, the translated address. The hop reads the mappings of its
own firewall only. When an earlier hop translated the source and a candidate of
the hop names a user, the hop adds `note.user-after-nat`, and its fidelity is
`inferred`: no lab path with NAT and User-ID showed this. A hop without User-ID
data keeps the doubt of a check without data.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--port <port>` | none | destination port: `443` or `tcp/443` |
| `--protocol <proto>` | `tcp`, or with `--application` the default of the application | `tcp`, `udp`, `sctp`, `icmp` or a protocol number |
| `--source-port <n>` | none | source port |
| `--from-zone <zone>` | derived | with `--file`: the source zone; give both zones or neither |
| `--to-zone <zone>` | derived | with `--file`: the destination zone; give both zones or neither |
| `--url <url>` | none | URL, matched against custom URL categories |
| `--application <name>` | none | a predefined or custom application, matched with App-ID data, see [Applications](#applications) |
| `--user <user>` | none | source user: a primary name such as `example.com\alice`, a UPN or an email; a mapping of the source address wins, see [Users](#users) |
| `--no-dns` | off | do not resolve an FQDN endpoint |
| `--router <name>` | none | path mode with `--device`: start in this logical router |
| `--each` | off | check every selected firewall on its own; arrives in a later release |
| `--why` | off | show every stage: its fidelity, what it kept and why |

The command takes the [selection flags](../reference/global-flags.md#selection-flags)
`--device`, `--label`, `--vsys`, `--at` and `--file`. In path mode, `--device` names
the start firewall and `--at` picks the snapshot of each device. With `--file`,
`--vsys` picks the vsys. For JSON and YAML, see [`--detail`](../reference/output.md#detail)
and [results](../reference/output.md#results).

A zone that the vsys does not define exits 2, and the message lists the zones of
the vsys. When you select several vsys, a vsys without the zone is a hole. The
command then exits 2 only when no vsys defines the zone.

`--url` matches custom URL categories. A rule that names a PAN-DB category stays a
candidate, in doubt. With `--file`, an FQDN endpoint resolves with this machine's
DNS. The name matches FQDN objects, and the first address matches everything else.
A note names the other addresses.

These flags exit 2 in path mode, and the message names the flag:

| Flag | Use instead |
| --- | --- |
| `--vsys`, `--label`, `--from-zone`, `--to-zone` | the path gives the firewalls, the vsys and the zones; use `--file <path> --vsys <name>` for one configuration |
| `--device a --device b` | path mode starts on one device |
| `--router` without `--device` | add `--device` |
| `--each` | arrives in a later release |

With `--file`, `--device`, `--label`, `--at` and `--router` exit 2, because they
select from the store. The command does not take `--fresh`, because path mode reads
stored snapshots.

## Exit codes

| Code | When |
| --- | --- |
| 0 | `allowed` or `denied`, with a complete answer |
| 3 | `undecided`, an unresolved entry, or a hole, such as a device without a snapshot or a configuration that proteus cannot read |
| 2 | you must change the command line: no start, a start tie, or a flag that the mode refuses |

The other codes are in [Output and exit codes](../reference/output.md#exit-codes).

## Limits

- Without User-ID data, a rule that names a user or a group is in doubt.
- A rule that names a Cloud Identity Engine group is in doubt.
- A flow without a user, or with `--user pre-logon`, is `inferred` when a
  candidate names a user.
- A hop after NAT that judges a user is `inferred`.
- Without `--application`, or without App-ID data, a rule that names an
  application is in doubt.
- Policy-based forwarding does not evaluate the application or the user.
- proteus does not check the return path.
- `--file` does not check NAT.

See [Limits: simulate policy](../reference/limits.md#simulate-policy),
[Limits: applications](../reference/limits.md#applications) and
[Limits: users](../reference/limits.md#users).

## See also

- [simulate routing](simulate-routing.md)
- [simulate nat](simulate-nat.md)
- [lookup](lookup.md)
- [fetch](fetch.md)
- [Fidelity](../concepts/fidelity.md)
- [App-ID data](../concepts/snapshots.md#app-id-data)
- [User-ID data](../concepts/snapshots.md#user-id-data)
- [Rule layers](../concepts/scope.md#rule-layers)
- [Output and exit codes](../reference/output.md)
