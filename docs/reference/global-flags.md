# Global flags

```text
proteus <command> [arguments] [flags]
```

Questions are verbs: `search`, `lookup` and `simulate`. Housekeeping commands are
grouped by noun: `inventory` and `snapshot`. `fetch` stays at the top level,
because you run it most.

## Global flags

Every command takes these flags. [Configuration](configuration.md#settings)
lists the matching variables and inventory keys.

| Flag | Default | Description |
| --- | --- | --- |
| `--config <path>` | `~/.config/proteus/config.yaml` | inventory file |
| `--store <path>` | `~/.local/share/proteus` | snapshot store |
| `--output text\|json\|yaml` | `text` | output format; see [Output and exit codes](output.md) |
| `--color auto\|always\|never` | `auto` | color text output; `auto` colors only on a terminal |
| `--max-age <duration>` | `24h` | add a note to answers from older snapshots, for example `24h` or `7d` |
| `--log-level error\|warn\|info\|debug` | `info` | run log level |
| `--log-dir <path>` | `~/.local/state/proteus/log` | directory for run logs |
| `--verbose` | off | echo the run log to stderr |
| `-v`, `--version` | | print the version |

## Selection flags

Questions select devices, vsys and snapshots with these flags. Each command page
lists the flags that the command takes.

| Flag | Description |
| --- | --- |
| `--device <name>` | only these devices; repeatable, any of them |
| `--label key=value` | only devices with this label; repeatable, all must hold |
| `--vsys <name>` | only these vsys; repeatable; default every vsys |
| `--at <time>` | each device's newest snapshot at or before this time: a snapshot id, RFC 3339 or a date |
| `--fresh` | fetch the selected devices first |
| `--file <path>` | read one configuration file instead of the store |

You cannot combine `--file` with `--device`, `--label`, `--at` or `--fresh`.

## Shell completion

`proteus completion` prints a completion script for `bash`, `zsh`, `fish` or
`powershell`:

```bash
proteus completion bash > /etc/bash_completion.d/proteus
proteus completion zsh  > "${fpath[1]}/_proteus"
```
