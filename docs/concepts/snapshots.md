# Snapshots and the store

`proteus fetch` writes one **snapshot** per device. A snapshot is a directory with
one XML file per document, the User-ID data and a `meta.json`.

## What a snapshot holds

| Document | Source | Used for |
| --- | --- | --- |
| `config.xml` | `show config running`, merged with the pushed template | every question |
| `template.xml` | `show config pushed-template`, as the device sent it | the template values that `config.xml` holds |
| `system-info.xml` | `show system info` | model, serial, PAN-OS version |
| `interfaces.xml` | `show interface all` | zones, interfaces, addresses |
| `fib.xml` | forwarding table | zones of an address, routing paths |
| `rib.xml` | routing table | `simulate routing --rib` |
| `ha.xml` | high-availability state | the active member of a pair |
| `predefined.xml` | the device's predefined services | the ports of `service-http` and `service-https` |
| `identity.json.gz` | the device's User-ID data | the users, groups and mappings of `simulate policy`, `search`, `lookup` and `snapshot diff` |

`config.xml` is the running configuration of the firewall merged with the
template that Panorama pushed to it. A value that the firewall holds itself wins
over the template value. `config.xml` holds no change that an admin did not
commit. A firewall without a template gives no `template.xml`, and `config.xml`
is then the running configuration. See [fetch](../commands/fetch.md#the-configuration).

`meta.json` names the source of `config.xml` as `config_source`:

| `config_source` | `config.xml` holds |
| --- | --- |
| `running+template` | the running configuration, merged with the pushed template |
| `running` | the running configuration; the device has no template, or did not send it |
| `export+template` | the configuration export, merged with the pushed template; the device refused `show config running` |
| `export` | the configuration export; also every snapshot without the key, from an older release |

The export can hold uncommitted changes. `snapshot diff` between two snapshots
of different sources adds `note.config-source-changed`.

## The store

The **store** is the directory that holds every snapshot:

```text
~/.local/share/proteus/
  fw01/
    2026-09-27T17-05-00Z/
      config.xml  template.xml  system-info.xml  interfaces.xml  fib.xml
      rib.xml  ha.xml  predefined.xml
      identity.json.gz
      meta.json
    latest -> 2026-09-27T17-05-00Z
  .content/
    8000-1000.v1.xml.gz
```

`fetch` writes each snapshot to a hidden directory and then renames it, so a
reader always sees a complete snapshot.

## App-ID data

The predefined applications and application containers of a device are its
**App-ID data**. They depend on the content version, so the store keeps them once
per version in `.content/`, and every snapshot with that version shares the file.
`meta.json` names the version as `app_version`.

`.content/` has mode 0700 and each file in it has mode 0600. See
[snapshot](../commands/snapshot.md#app-id-data) for how to inspect and import the
data.

## User-ID data

The users, groups and user-to-address mappings of a firewall are its **User-ID
data**. They change all the time, so each snapshot keeps its own copy in
`identity.json.gz`, mode 0600. `meta.json` then holds `"identity": true`. A
pruned snapshot removes the file with it.

| Part | What it holds |
| --- | --- |
| `sources` | the LDAP group-mapping profiles and the Cloud Identity Engine profiles |
| `users` | each user that the firewall knows, with alternate names, email and groups |
| `groups` | each group, with its source and member count |
| `tags` | the tags that User-ID registered for each user |
| `mappings` | each mapped address, with its user, type and timeout |

`fetch` reads the data only from a firewall with one vsys, and not when the
inventory sets `identity: false` on the device. A part that the firewall refused
is missing, and the file names it. See
[snapshot](../commands/snapshot.md#user-id-data) for how to compare the data and
copy it for `--file`.

## Which snapshot a question reads

| Flag | Snapshot |
| --- | --- |
| none | `latest` |
| `--at <time>` | the newest snapshot at or before that time |
| `--fresh` | a new snapshot, fetched first |

## Retention

The store keeps the newest 20 snapshots with a configuration and the newest 20
without one, per device. Set `snapshot_keep` in the
[configuration](../reference/configuration.md) to change the number.
