# inventory

`inventory init` writes an inventory template that you fill in with your firewalls.

## Synopsis

```text
proteus inventory init [--config <path>]
```

## Examples

### Write the template

```text
$ proteus inventory init --config config.yaml
wrote config.yaml (mode 0600)
set the hosts and credentials, then run: proteus fetch --all
```

Without `--config`, the template goes to `$PROTEUS_CONFIG` or
`~/.config/proteus/config.yaml`. Set the hosts, the username and the password
variable, then run `proteus fetch --all`.

### Refuse an existing file

```text
$ proteus inventory init --config config.yaml
proteus: config.yaml exists; name another file with --config, or move it
```

`inventory init` never overwrites a file. It exits 2, so you keep the inventory
you already have.

## Reading the output

The template holds one device, `fw01`, and every default with a comment:

| Key | Template value |
| --- | --- |
| `insecure_tls` | `true`; the comment explains the risk and how to opt in to verification |
| `timeout` | `60` seconds per API call |
| `snapshot_keep` | `20` |
| `username` | `admin` |
| `password_env` | `PANOS_PASSWORD` |
| `max_snapshot_age` | `24h` |
| `output` | `text` |
| `log_level` | `info` |
| `log_keep` | `20` |
| `log_dir`, `store`, `export_inventory` | commented out |
| `ha_peer` on `fw01` | commented out |
| `identity` on `fw01` | commented out; `identity: false` turns off the fetch of the device's User-ID data |

[Configuration](../reference/configuration.md#the-inventory) describes every key.

## Flags

`inventory init` has no flags of its own. It writes to the file that the global
flag `--config` names.

## See also

- [fetch](fetch.md)
- [Configuration](../reference/configuration.md)
- [TLS](../reference/configuration.md#tls)
- [Global flags](../reference/global-flags.md)
