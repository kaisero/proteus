# Snapshots: fetch, list, show and compare

## Fetch

```bash
proteus fetch fw01 fw02          # these devices
proteus fetch --label site=vienna
proteus fetch --all              # every device in the inventory
```

`fetch` logs in with the inventory's username and password and asks the firewall
for an API key. It then reads the documents listed in
[Concepts](../concepts.md#snapshots-and-the-store) and stores them as one snapshot.

- It fetches up to eight firewalls at the same time.
- A failed document is recorded in `meta.json`. The rest of the snapshot is kept.
- The predefined services are optional. A firewall that refuses them gives a note,
  and the fetch is still complete. Rules that name them then stay in doubt.
- A failed firewall does not stop the others. `fetch` then exits with code 3.
- When a device is the passive member of an HA pair, `fetch` reads the active peer
  instead and says so. Set `ha_peer` in the inventory when the peer's reported
  address is not reachable from your machine.

`fetch` is read-only. It runs `<show>` commands and a configuration export,
nothing else. The client refuses any other command before it reaches the device.

## List

```
$ proteus snapshot list fw01
* 2026-09-29T06-29-08Z  PAN-OS 11.2.5   4 documents, 0 failed
```

The list is newest first. `*` marks `latest`. A snapshot whose `meta.json` is
missing or unreadable shows as a hole below the list, and the command exits 3.

## Show

`snapshot show` shows what a question would read: the device, the snapshot and its
age, the PAN-OS version, the vsys and their rule counts, and each document.

```
$ proteus snapshot show --file testdata/config/firewall-multivsys.xml
file   testdata/config/firewall-multivsys.xml
  vsys1    PAN-OS 11.2.5, security rules: 1
  vsys2    PAN-OS 11.2.5, security rules: 0
  vsys3    PAN-OS 11.2.5, security rules: 0
```

## Compare

`snapshot diff` compares two snapshots of each selected device, per vsys and
shared. It compares objects and rules in the schema's terms, not as XML text.

```
$ proteus snapshot diff
fw01   2026-09-22T08-00-00Z -> 2026-09-28T08-00-00Z
  shared     no changes
    fw01/shared: 0 added, 0 removed, 0 changed
  vsys:vsys1
    fw01/vsys:vsys1: 1 added, 1 removed, 3 changed
    changed address       net-home
      ip-netmask: 198.18.1.0/24 -> 198.18.2.0/24
    removed address       net-labor 198.18.0.0/15
    changed nat rule      dnat-web
      destination-translation/translated-address: srv-web -> 10.88.2.11
    changed security rule dc-to-home
      disabled: (unset) -> yes
      negate-destination: (unset) -> yes
    added   security rule new-rule  allow application=dns destination=any source=net-home
  vsys:vsys2 no changes
    fw01/vsys:vsys2: 0 added, 0 removed, 0 changed
1 with changes, 0 without, 0 holes
```

The last line counts the devices with changes, the devices compared without a
change, and the holes. A device without two snapshots to compare is a hole.

What it compares:

- Every entry the scope defines: objects of every kind (addresses, services,
  external lists, zones, schedules, profiles, profile groups, log settings and
  the rest), and the rules of every rulebase (security, NAT, PBF, decryption and
  the others). Shared compares shared only, with the rules pushed from Panorama;
  a vsys compares that vsys only.
- The whole entry: every setting, with its text and attributes. A list of members
  is a set, so a reorder is no change. A list of named entries inside an entry,
  such as a server profile's servers, keeps its order: a reorder shows as one
  line, `server order: ldap1, ldap2 -> ldap2, ldap1`. The attributes PAN-OS
  writes for its own bookkeeping (`uuid`, `admin`, `time`, `dirtyId`) are not
  compared.
- Not the device's predefined services: they are not configuration.

How it shows a change:

- A changed entry lists each setting that differs on its own line,
  `path: old -> new`. A setting present on one side only reads `(unset)` on the
  other. An element that is present but holds no value reads `(set)`.
- An added or removed entry shows a short line: an object's value, or a rule's
  action and lists.
- In JSON and YAML, a changed entry has `fields`, each with `path`, `old` and
  `new`; an absent side is empty. An added or removed entry has `new` or `old`.

By default it compares the snapshot before `latest` with `latest`. `--from` and
`--to` take a snapshot id, an RFC 3339 time or a date. A value that is none of
these is a usage error (exit 2) that names the flag. A rule that only moved is
not a change.

`--limit N` keeps the first N changes, in the order above, over all scopes and
devices together. The scope where the limit falls shows its first changes, and
its count line keeps the whole counts and adds how many it shows:
`fw01/vsys:vsys1: 1 added, 1 removed, 2 changed (1 of 4 changes shown)`. The
scopes after it are left out. There is no default. With changes left out, the
last line ends `; 1 of 4 shown, narrow by device`. In JSON and YAML,
`summary.found` counts every change and `summary.omitted` the changes left out;
`omitted` is 0 when nothing is left out. With `--detail summary`, each scope
counts all of its changes. Holes and notes are never cut: the note of a device
whose changes are all left out prints below, as `note: fw02: <text>`.
`--limit` takes 1 or more; `--limit 0` is a usage error (exit 2).

A secret never shows: a key, a password or a password hash, such as a
certificate's private key, a server profile's password or a local user's
password hash. A change in one reads `private-key: changed (secret, not shown)`,
and JSON and YAML give `(secret)` for its old and new values, with
`"secret": true`. Where a secret is set on one side only, that side reads
`(secret)` and the other is empty.

A value the schema does not describe never shows either: an element or an
attribute that the schema proteus reads the configuration with does not know, as a
newer release can add. It may hold a secret. Its change still shows, as
`<path>: changed (not described by the schema; values not shown)`; JSON and
YAML give empty `old` and `new` with `"undescribed": true`. An added or removed
entry's short line leaves such values out.

## Old snapshots

Every question takes `--at <time>`. It reads each device's newest snapshot at or
before that time. A date means the end of that day.

An answer from a snapshot older than `max_snapshot_age` (default 24h) carries a
note. Change the limit with `--max-age 7d`.
