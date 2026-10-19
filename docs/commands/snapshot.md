# snapshot

Which snapshots do you have, what does a question read, and what changed between two of them?

## Synopsis

```text
proteus snapshot list <device>
proteus snapshot show [selection flags]
proteus snapshot diff [--device <name>] [--label key=value] [--vsys <name>] [--from <time>] [--to <time>] [--limit N]
```

## Examples

### List the snapshots of a device

```text
$ proteus snapshot list fw01
* 2026-09-28T08-00-00Z PAN-OS 11.2.5 1 documents, 0 failed
  2026-09-22T08-00-00Z PAN-OS 11.2.5 1 documents, 0 failed
```

The list starts with the newest snapshot. The `*` marks the snapshot that
`latest` names, which every question reads by default.

### Show what a question reads

```text
$ proteus snapshot show --device fw01
fw01   snapshot 2026-09-28T08-00-00Z (19d)
  note: snapshot 2026-09-28T08-00-00Z is 461h42m0s old, past the 24h0m0s limit
  fw01.example.net, PA-VM, serial 000000000001
  config 3252 bytes
  vsys1    PAN-OS 11.2.5, security rules: 6
  vsys2    PAN-OS 11.2.5, security rules: 3
```

`snapshot show` reports the device, the snapshot and its age, each document, and
the vsys with their rule counts. The note appears because the snapshot is older
than `max_snapshot_age`.

### Check a configuration file

```text
$ proteus snapshot show --file testdata/config/firewall-multivsys.xml
file   testdata/config/firewall-multivsys.xml
  vsys1    PAN-OS 11.2.5, security rules: 1
  vsys2    PAN-OS 11.2.5, security rules: 0
  vsys3    PAN-OS 11.2.5, security rules: 0
```

With `--file`, Proteus reads one configuration file and needs no store. Use it to
confirm that Proteus finds every vsys before you ask a question about the file.

### Compare the last two snapshots

=== "text"

    ```text
    $ proteus snapshot diff
    fw01   2026-09-22T08-00-00Z -> 2026-09-28T08-00-00Z
      shared     no changes
        fw01/shared: 0 added, 0 removed, 0 changed
      vsys:vsys1
        fw01/vsys:vsys1: 1 added, 1 removed, 2 changed
        changed address       net-home
          ip-netmask: 198.18.1.0/24 -> 198.18.2.0/24
        removed address       net-labor 198.18.0.0/15
        changed security rule dc-to-home
          disabled: (unset) -> yes
        added   security rule new-rule  allow application=dns destination=any source=net-home
      vsys:vsys2 no changes
        fw01/vsys:vsys2: 0 added, 0 removed, 0 changed
    1 with changes, 0 without, 0 holes
    ```

=== "json"

    ```json
    {
      "format": 2,
      "command": "snapshot diff",
      "detail": "summary",
      "input": {
        "from": "",
        "limit": 0,
        "selection": {},
        "to": ""
      },
      "results": [
        {
          "answer": "fw01/shared: 0 added, 0 removed, 0 changed",
          "device": "fw01",
          "from": "2026-09-22T08-00-00Z",
          "to": "2026-09-28T08-00-00Z",
          "scope": "shared",
          "added": 0,
          "removed": 0,
          "changed": 0
        },
        {
          "answer": "fw01/vsys:vsys1: 1 added, 1 removed, 2 changed",
          "device": "fw01",
          "from": "2026-09-22T08-00-00Z",
          "to": "2026-09-28T08-00-00Z",
          "scope": "vsys:vsys1",
          "added": 1,
          "removed": 1,
          "changed": 2
        },
        {
          "answer": "fw01/vsys:vsys2: 0 added, 0 removed, 0 changed",
          "device": "fw01",
          "from": "2026-09-22T08-00-00Z",
          "to": "2026-09-28T08-00-00Z",
          "scope": "vsys:vsys2",
          "added": 0,
          "removed": 0,
          "changed": 0
        }
      ],
      "summary": {
        "answer": "1 with changes, 0 without, 0 holes",
        "found": 4,
        "with": 1,
        "without": 0,
        "omitted": 0
      },
      "holes": [],
      "unresolved": [],
      "notes": []
    }
    ```

Without `--from` and `--to`, the diff compares the snapshot before `latest` with
`latest`. It compares each selected device per vsys and for shared, entry by
entry in the schema's terms. The JSON tab shows
`proteus snapshot diff --output json --detail summary`, which keeps the counts
and leaves out the changes.

## Reading the output

### snapshot list

| Part | Meaning |
| --- | --- |
| `*` | the snapshot that `latest` names |
| `2026-09-28T08-00-00Z` | the snapshot id: the UTC time of the fetch |
| `PAN-OS 11.2.5` | the PAN-OS version of the device at that time |
| `1 documents, 0 failed` | the documents the fetch stored, and the documents that failed |
| a hole below the list | a snapshot whose `meta.json` is missing or unreadable; the command exits 3 |

### snapshot show

| Line | Meaning |
| --- | --- |
| `fw01   snapshot <id> (<age>)` | the device, the snapshot a question reads, and its age |
| `file   <path>` | the configuration file that `--file` names |
| `note: …` | a note about the snapshot, such as its age past `max_snapshot_age` |
| `<host>, <model>, serial <serial>` | the device as the snapshot records it |
| `fetched from the active HA peer <host>` | the device was passive, and `fetch` read its active peer |
| `<document> <n> bytes` | a stored document and its size |
| `<document> FAILED <error>` | a document that the fetch could not read |
| `<vsys> PAN-OS <version>, security rules: <n>` | a vsys, its PAN-OS version and its security rule count |

### snapshot diff

| Line | Meaning |
| --- | --- |
| `fw01   <from> -> <to>` | the device and the two snapshots it compares |
| `shared`, `vsys:vsys1` | a scope; `no changes` follows when nothing changed |
| `fw01/vsys:vsys1: 1 added, 1 removed, 2 changed` | the counts of the scope |
| `changed <kind> <name>` | an entry that exists in both snapshots with a different content |
| `  <path>: <old> -> <new>` | one setting that differs in a changed entry |
| `added <kind> <name> <short line>` | an entry in the newer snapshot only |
| `removed <kind> <name> <short line>` | an entry in the older snapshot only |
| `identity` | the User-ID result of the device, when both snapshots hold User-ID data, see [User-ID data](#user-id-data) |
| `changed identity user <name>` | a user whose groups changed; a `group:` line names each group that the user gained or lost |
| `changed identity source <name>` | an identity source whose group count changed, such as `groups: 3 -> 4` |
| `added identity user <name>`, `removed identity source <name>` | a user or an identity source in one snapshot only |
| `1 with changes, 0 without, 0 holes` | the devices with changes, the devices without a change, and the holes |

A device without two snapshots to compare is a hole. The short line of an added
or removed entry shows an object's value, or a rule's action and lists.

These markers appear in a setting line:

| Marker | Meaning |
| --- | --- |
| `(unset)` | the setting is absent on this side |
| `(set)` | the element is present and holds no value |
| `changed (secret, not shown)` | a secret changed; the value stays hidden |
| `(secret)` | a secret that is set on this side only |
| `changed (not described by the schema; values not shown)` | a value that the schema does not describe changed |
| `server order: ldap1, ldap2 -> ldap2, ldap1` | a list of named entries inside an entry changed its order |

The diff compares these parts of each scope:

| Part | How it compares |
| --- | --- |
| objects of every kind | addresses, services, external lists, zones, schedules, profiles, profile groups, log settings and the rest |
| rules of every rulebase | security, NAT, PBF, decryption and the others |
| rules pushed from Panorama | in shared only; the kind names the rulebase, such as `pre-rulebase security rule` or `post-rulebase security rule` |
| a vsys's own rules | in that vsys only; the kind reads `security rule` |
| other settings of the scope | one entry of kind `setting`, named by its path below the scope, such as `import/network/interface` |
| a vsys user group | a list of named entries, of kind `user-group` |
| a list of members | a set, so a reorder is no change |
| a list of named entries inside an entry | in order, so a reorder shows as one line |

A changed entry lists every setting that differs, with its text and attributes.
An added or removed setting shows its value when it has one value that may show.
For example, `changed setting import/network/interface` has the line
`interface: ethernet1/1 -> ethernet1/1, ethernet1/3` below it.

The diff skips the attributes that PAN-OS writes for its own bookkeeping: `uuid`,
`admin`, `time` and `dirtyId`. A rule that only moved counts as no change.

When the App-ID content version differs between the two snapshots, the note
`note.app-version-changed` names both versions.

When the two snapshots come from different configuration sources, the note
`note.config-source-changed` names both sources. A snapshot that an older release
of proteus fetched holds the configuration export. Across the change to the
running configuration with the pushed template, the template values show as
added once, and the uncommitted changes that the export held show as removed.
The empty elements below `shared/content-preview` show as removed too. See
[Snapshots](../concepts/snapshots.md#what-a-snapshot-holds).

In JSON and YAML, the changes have these keys:

| Key | Content |
| --- | --- |
| `fields` | the settings of a changed entry, each with `path`, `old` and `new`; an absent side is empty |
| `new`, `old` | the value of an added or a removed entry |
| `"secret": true` | a secret; `old` and `new` read `(secret)` |
| `"undescribed": true` | a value the schema does not describe; `old` and `new` are empty |
| `summary.found` | every change |
| `summary.omitted` | the changes that `--limit` leaves out; 0 when none |

### Secrets and undescribed values

The diff never shows a secret. A secret is a key, a password or a password hash,
such as a certificate's private key, a server profile's password or a local
user's password hash.

Some credentials count as secrets although the schema does not mark them as
encrypted:

- an SNMP v2c trap community
- a SCEP fixed challenge
- the URL, payload, header and parameter values of an HTTP server profile
- the values of an MFA server profile

The diff also hides a value that the schema does not describe. A newer PAN-OS
release can add such an element or attribute, and it may hold a secret. An added
or removed object that holds a secret or such a value shows no short line. A
rule's short line shows only the lists that the schema describes.

### App-ID data

The applications that a rule, a filter or a container selects come from the
firewall's App-ID content. The configuration does not hold them. `fetch` reads the
content version from `show system info`. When the store holds no file of that
version, `fetch` asks the firewall for its predefined applications and
containers. It keeps the fields that Proteus needs and writes one file:

```text
<store>/.content/<content version>.v1.xml.gz
```

| Case | Result |
| --- | --- |
| a later fetch of the same content version | reuses the file and does not ask the firewall again |
| the first fetch of a new content version | takes longer, because the answer is large |
| a file that no snapshot names and that is older than one hour | each run removes it |
| the firewall refuses the data, or its content version has an unknown form | the note `note.fetch-applications-missing`; the fetch is still complete, and rules that name an application stay in doubt |
| the call fails on the way, or the file cannot be written | the snapshot is stored, and `fetch` exits 3 |
| the firewall returns the applications without the containers | the file records that, and a rule that names a container stays in doubt |

[Snapshots](../concepts/snapshots.md#app-id-data) describes how the store shares
the file and how `meta.json` names its version. To fetch a file again, delete it.

To use the data with `--file`, copy the file beside the configuration file and
name it `apps.xml.gz`.

### User-ID data

A configuration names users and groups, but it does not say who is in a group or
which user an address has. The firewall's User-ID data does. For each
single-vsys firewall, `fetch` reads the user-to-address mappings, the users with
their groups, alternate names and emails, the groups with their source, the
registered user tags, and the identity sources. It writes one file into the
snapshot:

```text
<store>/<device>/<snapshot id>/identity.json.gz
```

`meta.json` then holds `"identity": true`. A snapshot without the file behaves as
before the data: a rule that names a user or a group stays in doubt.
[fetch](fetch.md#user-id-data) lists the cases where `fetch` writes no file or a
file with a missing part.

`snapshot diff` compares the User-ID data of the two snapshots when both hold it.
The device then gets one more result with the scope `identity`:

```text
  identity
    fw01/identity: 0 added, 0 removed, 2 changed
    changed identity source ldap:example.com
      groups: 3 -> 4
    changed identity user   example.com\alice
      group: (unset) -> team-x
```

| Change | What it says |
| --- | --- |
| `identity user` | a user that came or went, with its groups, or a user that gained or lost a group |
| `identity source` | an identity source that came or went, or whose group count changed |

The diff does not compare the mappings: they change all the time. When one of
the two snapshots has no User-ID data, the device gets no `identity` result, and
`note.identity-not-compared` says so. Else every user would show as added. A part
that is missing in one of the two snapshots is not compared either, and the note
names the part.

To use the data with `--file`, copy the file beside the configuration file:

```bash
mkdir fw01
cp ~/.local/share/proteus/fw01/latest/config.xml fw01/
cp ~/.local/share/proteus/fw01/latest/identity.json.gz fw01/
proteus simulate policy 198.51.100.11 192.0.2.10 --port 443 --file fw01/config.xml
```

With `PROTEUS_STORE` set, the store is that directory. The note
`note.identity-file` names the file that a `--file` answer reads. Nothing checks
that the file belongs to the configuration.

### Old and damaged snapshots

Every question takes `--at <time>` and reads each device's newest snapshot at or
before that time. A date means the end of that day.

| Case | Result |
| --- | --- |
| a damaged snapshot at the asked time, whose `meta.json` cannot be read | the answer reads the next older one, with `note.snapshot-skipped` naming the skipped one |
| no older snapshot can be read | the device is a hole that names the damaged snapshots |
| a damaged `latest`, without `--at` | the device is a hole; Proteus does not fall back to an older snapshot |
| a snapshot older than `max_snapshot_age` (default 24h) | the answer carries `note.snapshot-stale`; change the limit with `--max-age 7d` |

## Flags

`snapshot list` takes one device name and no flags of its own.

`snapshot show` takes every [selection flag](../reference/global-flags.md#selection-flags):
`--device`, `--label`, `--vsys`, `--at`, `--fresh` and `--file`.

`snapshot diff` takes `--device`, `--label` and `--vsys`, and these flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--from <time>` | the snapshot before `--to` | compare from the newest snapshot at or before this time |
| `--to <time>` | `latest` | compare to the newest snapshot at or before this time |
| `--limit N` | all | keep only the first N changes; the summary counts the rest |
| `--detail` | `full` | with `--output json` or `yaml`: `summary` or `full` |

`--from` and `--to` take a snapshot id, an RFC 3339 time or a date. Any other
value is a usage error (exit 2) that names the flag.

`--limit` takes 1 or more, and `--limit 0` is a usage error (exit 2). It counts the
changes in output order over all scopes and devices together. The scope where the
limit falls shows its first changes, and its count line adds how many it shows:

```text
fw01/vsys:vsys1: 1 added, 1 removed, 2 changed (2 of 4 changes shown)
```

The scopes after it are left out, and the last line ends
`; 2 of 4 shown, narrow by device`. Holes and notes are never cut. When all
changes of a device are left out, its note prints below as `note: fw02: <text>`.
With `--detail summary`, each scope counts all of its changes.

## Limits

- `snapshot diff` does not compare the App-ID applications. A note only says
  that the content version changed.
- `snapshot diff` does not compare the predefined services, because they are not
  configuration.
- `snapshot diff` does not compare the User-ID mappings, and it compares the
  User-ID data only when both snapshots hold it.

See [Limits](../reference/limits.md).

## See also

- [fetch](fetch.md)
- [Snapshots and the store](../concepts/snapshots.md)
- [Global flags](../reference/global-flags.md)
- [Output and exit codes](../reference/output.md)
- [mcp](mcp.md)
