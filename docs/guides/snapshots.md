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
- It stores the App-ID data of the firewall's content version: the predefined
  applications and containers. See [App-ID data](#app-id-data).
- When a device is the passive member of an HA pair, `fetch` reads the active peer
  instead and says so. Set `ha_peer` in the inventory when the peer's reported
  address is not reachable from your machine.

`fetch` is read-only. It runs `<show>` commands and a configuration export,
nothing else. The client refuses any other command before it reaches the device.

### App-ID data

The applications that a rule, a filter or a container selects come from the
firewall's App-ID content, not from its configuration. `fetch` reads the content
version in `show system info`. When the store holds no file of that version, it
asks the firewall for its predefined applications and containers, keeps the
fields that proteus needs, and writes one file:

```
<store>/.content/<content version>.v1.xml.gz
```

- One file serves every device and snapshot with that content version. The next
  fetch of the same version does not ask the firewall again.
- The first fetch of a new content version takes longer: the answer is large.
- `meta.json` records the version as `app_version`. The answers read the file of
  that version.
- The directory has mode 0700, and each file has mode 0600.
- Each run removes the files that no snapshot names and that are older than one
  hour.
- A firewall that refuses the data, or whose content version has an unknown form,
  gives the note `note.fetch-applications-missing`. The fetch is still complete.
  Rules that name an application then stay in doubt.
- When the call fails on the way, or the file cannot be written, the snapshot is
  still stored, and `fetch` exits with code 3.
- When the firewall returns the applications but not the containers, the file
  records that. A rule that names a container then stays in doubt. Delete the file
  to fetch it again.

To use the data with `--file`, copy the file beside the configuration as
`apps.xml.gz`.

## List

```
$ proteus snapshot list fw01
* 2026-09-29T06-29-08Z PAN-OS 11.2.5 7 documents, 0 failed
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
  a vsys compares that vsys only. A pushed rule's kind names its rulebase,
  `pre-rulebase security rule` or `post-rulebase security rule`; a vsys's own
  rule reads `security rule`.
- Every setting of the scope that is not such an entry, such as the interfaces
  a vsys imports, its captive portal or the trusted root CAs in shared. Each
  is one entry of kind `setting`, named by its path below the scope:
  `changed setting import/network/interface` with
  `interface: ethernet1/1 -> ethernet1/1, ethernet1/3` below it. An added or
  removed setting shows its value when it has one value that may show. A vsys
  user group is a list of named entries and compares as kind `user-group`.
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

When the App-ID content version differs between the two snapshots, a note says
so: `note.app-version-changed`, with the two versions. The diff does not compare
the applications.

By default it compares the snapshot before `latest` with `latest`. `--from` and
`--to` take a snapshot id, an RFC 3339 time or a date. A value that is none of
these is a usage error (exit 2) that names the flag. A rule that only moved is
not a change.

`--limit N` keeps the first N changes, in the order above, over all scopes and
devices together. The scope where the limit falls shows its first changes, and
its count line keeps the whole counts and adds how many it shows:
`fw01/vsys:vsys1: 1 added, 1 removed, 3 changed (1 of 5 changes shown)`. The
scopes after it are left out. There is no default. With changes left out, the
last line ends `; 1 of 5 shown, narrow by device`. In JSON and YAML,
`summary.found` counts every change and `summary.omitted` the changes left out;
`omitted` is 0 when nothing is left out. With `--detail summary`, each scope
counts all of its changes. Holes and notes are never cut: the note of a device
whose changes are all left out prints below, as `note: fw02: <text>`.
`--limit` takes 1 or more; `--limit 0` is a usage error (exit 2).

A secret never shows: a key, a password or a password hash, such as a
certificate's private key, a server profile's password or a local user's
password hash. Credentials the schema does not mark as encrypted count too:
an SNMP v2c trap community, a SCEP fixed challenge, the URL, payload, header
and parameter values of an HTTP server profile and the values of an MFA server
profile. A
change in one reads `private-key: changed (secret, not shown)`, and JSON and
YAML give `(secret)` for its old and new values, with `"secret": true`. Where a
secret is set on one side only, that side reads `(secret)` and the other is
empty.

A value the schema does not describe never shows either: an element or an
attribute that the schema proteus reads the configuration with does not know, as a
newer release can add. It may hold a secret. Its change still shows, as
`<path>: changed (not described by the schema; values not shown)`; JSON and
YAML give empty `old` and `new` with `"undescribed": true`. An added or removed
object that holds such a value, or a secret, shows no short line; a rule's short
line shows only the lists the schema describes.

## Old snapshots

Every question takes `--at <time>`. It reads each device's newest snapshot at or
before that time. A date means the end of that day.

A damaged snapshot, whose `meta.json` cannot be read, is passed over: the answer
reads the next older one and carries a note that names the skipped one. When no
older one can be read, the device is a hole that names the damaged ones. Without
`--at`, a damaged `latest` is a hole; proteus does not fall back to an older
snapshot.

An answer from a snapshot older than `max_snapshot_age` (default 24h) carries a
note. Change the limit with `--max-age 7d`.
