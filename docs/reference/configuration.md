# Configuration

Proteus reads its settings from the inventory file, environment variables and
flags, and writes its data to fixed paths.

## The inventory

The inventory is a YAML file that lists your firewalls and the default settings.
`proteus inventory init` writes a template.

| Item | Value |
| --- | --- |
| Default path | `~/.config/proteus/config.yaml`, or `$XDG_CONFIG_HOME/proteus/config.yaml` |
| Other path | `--config <path>` or `PROTEUS_CONFIG` |
| Mode | `0600`. Proteus refuses to read the file when other users can read it. |

```yaml
version: 1

defaults:
  insecure_tls: true             # see "TLS" below
  timeout: 60                    # seconds per API call
  snapshot_keep: 20              # snapshots kept per device, with and without a configuration
  username: admin                # the login used to get an API key
  password_env: PANOS_PASSWORD   # the variable that holds the password
  max_snapshot_age: 24h          # answers from older snapshots carry a note
  output: text                   # text, json or yaml
  log_level: info                # error, warn, info or debug
  log_keep: 20                   # run logs kept
  # log_dir: ~/.local/state/proteus/log
  # store: ~/.local/share/proteus
  # export_inventory: true       # see "The inventory export" below

devices:
  - name: fw01
    host: fw01.example.net
    labels:
      site: vienna
    # ha_peer: fw01-b.example.net
    # identity: false            # do not fetch the User-ID data of this device
```

`snapshot_keep` counts two groups separately. A fetch keeps the newest N snapshots
that hold a configuration and the newest N that hold none, such as failed exports.
A fetch never removes the snapshot that `latest` names.

### Device fields

| Field | Meaning |
| --- | --- |
| `name` | The name you select the device by. Letters, digits, `.`, `_` and `-`. |
| `host` | The management address or host name. |
| `labels` | Free key/value pairs, selected with `--label key=value`. |
| `username`, `password_env` | Override the defaults for this device. |
| `insecure_tls`, `timeout` | Override the defaults for this device. |
| `ha_peer` | The reachable host of the HA peer, when the address that the device reports is unreachable. |
| `identity` | `true` by default: `fetch` stores the User-ID data of the device with each snapshot. `identity: false` turns that step off, and the fetch adds `note.identity-off`. See [User-ID data](../commands/fetch.md#user-id-data). |

### Passwords

Put the password in an environment variable and name the variable in
`password_env`. A literal `password:` field also works, but it keeps the password
on disk.

### TLS

!!! warning "The template turns certificate verification off"
    `insecure_tls: true` turns off TLS certificate verification, because lab
    firewalls present self-signed certificates. Anyone on the network path can
    then read the password during login and send false data, and every answer
    from false data is false.

Set `insecure_tls: false` for each firewall whose certificate this machine trusts.
You can set it per device.

## Settings

Each setting comes from, in rising precedence: the built-in default, the
inventory's `defaults:`, an environment variable, and a flag.

| Setting | Inventory key | Variable | Flag | Default |
| --- | --- | --- | --- | --- |
| inventory file | | `PROTEUS_CONFIG` | `--config` | `~/.config/proteus/config.yaml` |
| snapshot store | `store` | `PROTEUS_STORE` | `--store` | `~/.local/share/proteus` |
| snapshot age limit | `max_snapshot_age` | `PROTEUS_MAX_SNAPSHOT_AGE` | `--max-age` | `24h` |
| output format | `output` | `PROTEUS_OUTPUT` | `--output` | `text` |
| color | `color` | `PROTEUS_COLOR` | `--color` | `auto` |
| log level | `log_level` | `PROTEUS_LOG_LEVEL` | `--log-level` | `info` |
| log directory | `log_dir` | `PROTEUS_LOG_DIR` | `--log-dir` | `~/.local/state/proteus/log` |
| logs kept | `log_keep` | | | `20` |
| inventory export | `export_inventory` | | | `false` |

The `XDG_CONFIG_HOME`, `XDG_DATA_HOME` and `XDG_STATE_HOME` variables move the
default paths.

## The identity file

A configuration holds no mapping from users to groups or addresses. `fetch`
stores the User-ID data of each single-vsys firewall with its snapshot, as
`identity.json.gz`. A question about a snapshot reads that file.

With `--file <config.xml>`, proteus reads `identity.json.gz` in the directory of
the configuration file, when it exists. Copy the file out of a snapshot (see
[User-ID data](../commands/snapshot.md#user-id-data)). The answer then carries
`note.identity-file`, which names the file and the time the data was taken, and
`gap.user-directory-stale` when the file is older than `max_snapshot_age`.
Nothing checks that the file belongs to the configuration.

The file is gzip-compressed JSON with `"format": 1`:

| Key | Content |
| --- | --- |
| `taken_at` | when `fetch` read the data |
| `sources` | the LDAP group-mapping profiles and the Cloud Identity Engine profiles |
| `users` | each user with its primary name, alternate names, email, and groups |
| `groups` | each group with its source and member count |
| `dugs` | the dynamic user groups |
| `tags` | the registered tags of each user |
| `mappings` | each mapped address with its user, type and timeout |
| `parts_missing` | the parts that the firewall refused or that proteus could not read |
| `mappings_partial` | `true` when `fetch` cut the mapping table or read it while it changed |

A file that proteus cannot read, such as a damaged gzip file, bad JSON or another
`format`, gives `gap.no-user-directory` with the cause. The answer is then the same
as without data.

## The inventory export

`proteus mcp` reads its device list from an export of the inventory in the store.
Set `export_inventory: true` under `defaults:`, and every `fetch` run writes
`<store>/.proteus/inventory.yaml`, also when the run fails.

| Property | Value |
| --- | --- |
| Content | the inventory without `username`, `password` and `password_env`, in the defaults and on every device |
| Write | a temporary file, renamed into place, mode `0600` |
| Export fails, snapshots stored | exit 3 with `note.export-failed` |
| Nothing stored | exit 1 |

The server refuses an export that holds a credential. It ignores the exported
`store` and `log_dir` and uses its own. `.proteus` cannot clash with a device
name, because a device name starts with a letter or a digit.

## The mcp section

The `mcp:` section configures [`proteus mcp`](../commands/mcp.md). Write it in the
inventory, and the export carries it to the server. Each key is optional. The
values below are the defaults, except for `token_file`, `allowed_hosts` and
`audit_log`, which have none.

```yaml
mcp:
  listen: 127.0.0.1:8765                 # host:port for --http
  token_file: /run/secrets/proteus-mcp-token
  allowed_hosts: [proteus.example.org]   # optional: Host header values --http accepts
  identity_header: X-User-Claims         # the header with the caller's claims
  audit_claims: [sub]                    # the claims each audit line records
  audit_log: /var/log/proteus/mcp-audit.jsonl   # or - for standard output (--http only)
  audit_max_mb: 100                      # the audit file's size before it rotates
  audit_keep: 10                         # rotated audit files kept
  log_dir: ~/.local/state/proteus/log/mcp  # run logs of the calls
  log_keep: 200
  max_concurrent: 4                      # calls answered at once
  max_queue: 16                          # calls waiting for a slot
  max_wait: 10s
  call_timeout: 60s
  max_loads: 2                           # snapshot loads at once
  max_cache: 2048                        # MB
```

Proteus refuses an unknown key, a negative number, a duration it cannot read, a
`listen` without a port, an `identity_header` that is not an HTTP header name, and
an empty `audit_claims` entry. A number that is left out or set to `0` takes its
default, so `max_queue: 0` keeps the queue at 16.

Each mcp setting comes from, in rising precedence: its default, the export's
`mcp:` section, a variable, and a flag. The server reads no other file.

| Key | Variable | Flag |
| --- | --- | --- |
| `listen` | `PROTEUS_MCP_LISTEN` | `--listen` |
| `token_file` | `PROTEUS_MCP_TOKEN_FILE` | `--token-file` |
| `allowed_hosts` | `PROTEUS_MCP_ALLOWED_HOSTS` (comma-separated) | `--allowed-host` (repeatable) |
| `identity_header` | `PROTEUS_MCP_IDENTITY_HEADER` | |
| `audit_claims` | `PROTEUS_MCP_AUDIT_CLAIMS` (comma-separated) | |
| `audit_log` | `PROTEUS_MCP_AUDIT_LOG` | `--audit-log` |
| `audit_max_mb` | `PROTEUS_MCP_AUDIT_MAX_MB` | `--audit-max-mb` |
| `audit_keep` | `PROTEUS_MCP_AUDIT_KEEP` | `--audit-keep` |
| `log_dir` | `PROTEUS_MCP_LOG_DIR` | |
| `log_keep` | `PROTEUS_MCP_LOG_KEEP` | |
| `max_concurrent` | `PROTEUS_MCP_MAX_CONCURRENT` | `--max-concurrent` |
| `max_queue` | `PROTEUS_MCP_MAX_QUEUE` | `--max-queue` |
| `max_wait` | `PROTEUS_MCP_MAX_WAIT` | `--max-wait` |
| `call_timeout` | `PROTEUS_MCP_CALL_TIMEOUT` | `--call-timeout` |
| `max_loads` | `PROTEUS_MCP_MAX_LOADS` | `--max-loads` |
| `max_cache` | `PROTEUS_MCP_MAX_CACHE` | `--max-cache` |

### The token

The inventory never holds the token: `token_file` names the file that holds it.

| Source | Precedence |
| --- | --- |
| `--token-file` | highest |
| `PROTEUS_MCP_TOKEN`, the token itself | middle |
| `PROTEUS_MCP_TOKEN_FILE`, or `token_file` from the export | lowest |

Proteus has no `--token` flag, because the process list shows every flag. It trims
trailing whitespace from the token and refuses a token file that other users can
write. A read-only secret mount (mode 0444, owned by root) is accepted. `--http`
needs a token of at least 32 bytes.

### Host check

`allowed_hosts` is optional. When you set it, `--http` answers only a request
whose Host is in the list and gives 403 to every other request. When you leave it
out, the server accepts every Host, and its start line says `Host check off`.

The token alone keeps out a request that DNS rebinding sends, so the Host check
is defense in depth. Set it when the proxy forwards a fixed host name. Write each
entry as a host name or address with no port and no brackets: the server removes
the port from the request's Host before it compares.

### Audit

`--http` needs `audit_log`. Over stdio, the server writes an audit file only when
`audit_log` is set.

| Transport | Identity in the audit line |
| --- | --- |
| stdio | the operating system user (`auth: stdio`, `identity_source: os`) |
| HTTP, header present | the `audit_claims` of `identity_header` (`auth: token`, `identity_source: header`) |
| HTTP, header missing or not a JSON object | `unknown` (`identity_source: none`) |
| HTTP, JSON object with none of the `audit_claims` | `unknown` (`identity_source: header`) |

Before a line takes the audit file past `audit_max_mb`, Proteus renames the file
to `<audit_log>.<UTC time>-<sequence>` and starts a new one with mode 0600. It
keeps the `audit_keep` renamed files with the highest sequence numbers and removes
the older ones. Proteus also sets an existing audit file to mode 0600.

`audit_log: -` writes the lines to standard output, for a container platform that
collects them. With `--http`, nothing else goes to standard output. Over stdio,
standard output carries MCP, so the server refuses `-` with exit 2. The
[MCP guide](../commands/mcp.md#audit-and-run-logs) lists the fields of an audit
line.

### Run logs of calls

`log_dir` defaults to `mcp` under the CLI's log directory (`--log-dir`,
`PROTEUS_LOG_DIR`). Keep it a separate directory: each directory keeps only its
newest logs, so call logs in the CLI's directory push out the CLI's logs.

The server writes a call's run log only when the call ends `internal` or
`timeout`. At `--log-level debug` it writes one for every call. `--max-age`,
`--log-level` and `--store` apply to the server too, and `max_snapshot_age` comes
from the export's `defaults:`.

## Files Proteus writes

| Path | Mode | Content |
| --- | --- | --- |
| `~/.config/proteus/config.yaml` | 0600 | the inventory, written once by `inventory init` |
| `~/.local/share/proteus/<device>/<time>/` | 0700 / 0600 | one snapshot |
| `<store>/<device>/<time>/identity.json.gz` | 0600 | the User-ID data of the snapshot, see [The identity file](#the-identity-file) |
| `<store>/.content/` | 0700 / 0600 | one App-ID content file per content version, `<version>.v<trim>.xml.gz` |
| `~/.local/state/proteus/log/` | 0700 / 0600 | one log file per run, `<command>-<time>-<seq>.log` |
| `<store>/.proteus/inventory.yaml` | 0700 / 0600 | the inventory export, with `export_inventory: true` |
| `~/.local/state/proteus/log/mcp/` | 0700 / 0600 | one log file per MCP call, `mcp-<tool>-<time>-<seq>.log` |
| `audit_log` | 0600 | the MCP audit, one JSON line per call, appended |
