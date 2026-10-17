# CLI reference

```
proteus <command> [arguments] [flags]
```

Questions are verbs (`search`, `lookup`, `simulate`). Housekeeping is grouped by
noun (`inventory`, `snapshot`). `fetch` stays at the top level because you use it
most.

[Global flags](reference/global-flags.md) lists the flags that every command takes.
[Output and exit codes](reference/output.md) describes the output.

## fetch

```
proteus fetch [device...] [--label key=value] [--all]
```

Logs in to each device, reads its configuration and operational state, and stores
them as a snapshot. It also stores the device's App-ID data, once per content
version. Name devices, select them with `--label`, or pass `--all`.
See [Snapshots](guides/snapshots.md#fetch).

| Flag | Meaning |
| --- | --- |
| `--why` | show every stage: what it decided and why |

Stages, in order: `resolve`, `login`, `ha`, `documents`, `store`.

## inventory init

```
proteus inventory init
```

Writes an inventory template with mode 0600. It never overwrites a file.

## snapshot list

```
proteus snapshot list <device>
```

Lists a device's snapshots, newest first. `*` marks `latest`.

## snapshot show

```
proteus snapshot show [selection flags]
```

Shows the snapshots a question would read: version, vsys, rule counts and
documents.

## snapshot diff

```
proteus snapshot diff [selection flags] [--from <time>] [--to <time>]
```

Compares objects and rules per vsys and shared. A note says when the App-ID
content version changed. The default compares the snapshot before `latest` with
`latest`.

| Flag | Meaning |
| --- | --- |
| `--from <time>` | compare from the newest snapshot at or before this time |
| `--to <time>` | compare to the newest snapshot at or before this time; default `latest` |

## search

```
proteus search <term> [selection flags] [flags]
```

Finds every place a value or name appears. For an application, it also finds the
filters, containers and implicit use that select it. See
[Search](guides/search.md).

| Flag | Meaning |
| --- | --- |
| `--exact` | the value equals the term |
| `--within` | the value lies inside the term (addresses, prefixes, ranges) |
| `--contains` | the value or name holds the term as text; not a match |
| `--kind <kinds>` | only objects and groups of these kinds |
| `--field <fields>` | only references and literals from these fields |
| `--show <stages>` | only these stages: `objects`, `groups`, `refs`, `literals` |
| `--direct` | groups one level up only |

`--exact`, `--within` and `--contains` exclude each other.

## lookup

```
proteus lookup <name> [selection flags] [flags]
```

Shows the whole rule, object or application behind a name. See
[Lookup](guides/lookup.md).

| Flag | Meaning |
| --- | --- |
| `--kind <kind>` | `security-rule`, `application` or another object kind, when several kinds share the name |
| `--expand` | show each name's value and every group's members |
| `--full` | show every item of a list, and every application of a filter |

## simulate policy

```
proteus simulate policy <source> <destination> [selection flags] [flags]
```

Names the security rule a flow would hit. See
[Simulate policy](guides/simulate-policy.md).

| Flag | Meaning |
| --- | --- |
| `--port <port>` | destination port: `443` or `tcp/443` |
| `--protocol <proto>` | `tcp`, `udp`, `sctp`, `icmp` or a number; default `tcp`, or with `--application` the application's default |
| `--source-port <n>` | source port |
| `--from-zone`, `--to-zone` | zones; derived when absent |
| `--url <url>` | URL, matched against URL categories |
| `--application <name>` | a predefined or custom application; matched with App-ID data |
| `--user` | accepted, not evaluated yet |
| `--no-dns` | do not resolve an FQDN endpoint |
| `--why` | show every stage: its fidelity, what it kept and why |

## simulate nat

```
proteus simulate nat <source> <destination> --device <name> [flags]
```

Names the NAT rule a packet hits on one firewall and shows the packet after
translation. See [Simulate NAT](guides/simulate-nat.md).

| Flag | Meaning |
| --- | --- |
| `--device <name>` | the firewall; required |
| `--at <time>` | the newest snapshot at or before this time |
| `--from-zone`, `--from-interface` | where the packet arrives |
| `--router <name>` | the logical router, when the firewall has several |
| `--port`, `--protocol`, `--source-port` | complete the packet |
| `--no-dns` | resolve no FQDN |
| `--why` | list the rules above the match and every stage |

## simulate routing

```
proteus simulate routing <source> <destination>
proteus simulate routing <destination> --device <name>
```

Traces the path a packet takes across the inventory's firewalls. See
[Simulate routing](guides/simulate-routing.md).

| Flag | Meaning |
| --- | --- |
| `--device <name>` | start on this device |
| `--router <name>` | start in this logical router of `--device` |
| `--at <time>` | each device's newest snapshot at or before this time |
| `--port <port>` | decides NAT and PBF rules that name a service |
| `--rib` | list the routing table's other routes at each firewall |
| `--no-dns` | do not resolve an FQDN endpoint |
| `--why` | show every stage |
