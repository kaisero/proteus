# Configuration

## The inventory

The inventory is a YAML file. `proteus inventory init` writes a template.

- Default path: `~/.config/proteus/config.yaml`, or `$XDG_CONFIG_HOME/proteus/config.yaml`.
- Other path: `--config <path>` or `PROTEUS_CONFIG`.
- proteus refuses to read the file when other users can read it. Keep it at mode
  `0600`.

```yaml
version: 1

defaults:
  insecure_tls: true             # see "TLS" below
  timeout: 60                    # seconds per API call
  snapshot_keep: 20              # snapshots kept per device
  username: admin                # the login used to get an API key
  password_env: PANOS_PASSWORD   # the variable that holds the password
  max_snapshot_age: 24h          # answers from older snapshots carry a note
  output: text                   # text or json
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
```

### Device fields

| Field | Meaning |
| --- | --- |
| `name` | The name you select the device by. Letters, digits, `.`, `_` and `-`. |
| `host` | The management address or host name. |
| `labels` | Free key/value pairs, selected with `--label key=value`. |
| `username`, `password_env` | Override the defaults for this device. |
| `insecure_tls`, `timeout` | Override the defaults for this device. |
| `ha_peer` | The reachable host of the HA peer, when the address the device reports is not reachable. |

### Passwords

Put the password in an environment variable and name the variable in
`password_env`. A literal `password:` field also works, but then the password is
on disk.

### TLS

!!! warning "Verification is off by default"
    `insecure_tls: true` turns off TLS certificate verification. Lab firewalls
    present self-signed certificates, which verification would reject. The risk:
    anyone on the network path can read the password during login and send false
    data. Every answer drawn from false data is false.

Set `insecure_tls: false` when your firewalls present certificates that this
machine trusts. You can set it per device.

## The inventory export

`proteus mcp` reads its device list from the store, not from this file. Set
`export_inventory: true` under `defaults:`, and every `fetch` run writes
`<store>/.proteus/inventory.yaml`, a failed run too. The export is this inventory
without `username`, `password` and `password_env`, in the defaults and on every
device. `fetch` writes it to a temporary file and renames it into place, mode
`0600`. A run that stored its snapshots but cannot write the export exits 3 with
the note `note.export-failed`; a run that stored nothing still exits 1.

The server refuses an export that holds a credential. It ignores the exported
`store` and `log_dir`: it sets its own. `.proteus` cannot clash with a device,
because a device name starts with a letter or a digit.

## The mcp section

The `mcp:` section configures `proteus mcp` (see the [MCP guide](guides/mcp.md)).
Write it in this inventory; the export carries it to the server. Each key is optional. The values below are the defaults,
except `token_file`, `allowed_hosts` and `audit_log`, which have none.

```yaml
mcp:
  listen: 127.0.0.1:8765                 # host:port for --http
  token_file: /run/secrets/proteus-mcp-token
  allowed_hosts: [proteus.example.org]   # Host header values --http accepts
  identity_header: X-User-Claims         # the header with the caller's claims
  audit_claims: [sub]                    # the claims each audit line records
  audit_log: /var/log/proteus/mcp-audit.jsonl
  log_dir: ~/.local/state/proteus/log/mcp  # run logs of the calls: mcp under the CLI's log directory
  log_keep: 200
  max_concurrent: 4                      # calls answered at once
  max_queue: 16                          # calls waiting for a slot
  max_wait: 10s
  call_timeout: 60s
  max_loads: 2                           # snapshot loads at once
  max_cache: 2048                        # MB
```

The token is never in the inventory: `token_file` names the file that holds it.
proteus refuses an unknown key, a negative number, a duration it cannot read, a
`listen` without a port, an `identity_header` that is not an HTTP header name and an
empty `audit_claims` entry. A number left out or set to `0` takes its default:
`max_queue: 0` does not turn the queue off.

`log_dir` defaults to `mcp` under the CLI's log directory (`--log-dir`,
`PROTEUS_LOG_DIR`). Keep it a directory of its own: each directory keeps its newest
logs only, so call logs in the CLI's directory would push out the CLI's logs, and
the reverse.

`allowed_hosts` entries are host names or addresses without a port and without
brackets: the server compares the request's Host with its port removed.

Each mcp setting comes from, in rising precedence: its default, the export's `mcp:`
section, a variable, and a flag. The server reads no other file: not the inventory
with credentials, and not the export's `store` or `log_dir`.

| Key | Variable | Flag |
| --- | --- | --- |
| `listen` | `PROTEUS_MCP_LISTEN` | `--listen` |
| `token_file` | `PROTEUS_MCP_TOKEN_FILE` | `--token-file` |
| `allowed_hosts` | `PROTEUS_MCP_ALLOWED_HOSTS` (comma-separated) | `--allowed-host` (repeatable) |
| `identity_header` | `PROTEUS_MCP_IDENTITY_HEADER` | |
| `audit_claims` | `PROTEUS_MCP_AUDIT_CLAIMS` (comma-separated) | |
| `audit_log` | `PROTEUS_MCP_AUDIT_LOG` | `--audit-log` |
| `log_dir` | `PROTEUS_MCP_LOG_DIR` | |
| `log_keep` | `PROTEUS_MCP_LOG_KEEP` | |
| `max_concurrent` | `PROTEUS_MCP_MAX_CONCURRENT` | `--max-concurrent` |
| `max_queue` | `PROTEUS_MCP_MAX_QUEUE` | `--max-queue` |
| `max_wait` | `PROTEUS_MCP_MAX_WAIT` | `--max-wait` |
| `call_timeout` | `PROTEUS_MCP_CALL_TIMEOUT` | `--call-timeout` |
| `max_loads` | `PROTEUS_MCP_MAX_LOADS` | `--max-loads` |
| `max_cache` | `PROTEUS_MCP_MAX_CACHE` | `--max-cache` |

`PROTEUS_MCP_TOKEN` holds the token itself. It wins over `token_file` from the export
or `PROTEUS_MCP_TOKEN_FILE`; `--token-file` wins over it. There is no `--token`
flag: a flag shows in the process list. proteus trims trailing whitespace from the
token and refuses a token file that others can write. A read-only secret mount
(mode 0444, owned by root) is fine.

`--http` needs a token of at least 32 bytes, `allowed_hosts` and `audit_log`. Over
stdio no audit file is written unless `audit_log` is set; its lines record the
operating system user (`auth: stdio`, `identity_source: os`). Over HTTP they record
the claims of `identity_header` (`auth: token`, `identity_source: header`), or the
identity `unknown` when the header is missing or is not a JSON object
(`identity_source: none`). A JSON object with none of the `audit_claims` gives the
identity `unknown` with `identity_source: header`. proteus makes an existing audit
file mode 0600. The [MCP guide](guides/mcp.md#audit-and-run-logs) lists the fields
of an audit line.

The `--max-age`, `--log-level` and `--store` settings apply to the server too;
`max_snapshot_age` comes from the export's `defaults:`.

## Settings

Each setting comes from, in rising precedence: the built-in default, the
inventory's `defaults:`, an environment variable, and a flag.

| Setting | Inventory key | Variable | Flag | Default |
| --- | --- | --- | --- | --- |
| inventory file | | `PROTEUS_CONFIG` | `--config` | `~/.config/proteus/config.yaml` |
| snapshot store | `store` | `PROTEUS_STORE` | `--store` | `~/.local/share/proteus` |
| snapshot age limit | `max_snapshot_age` | `PROTEUS_MAX_SNAPSHOT_AGE` | `--max-age` | `24h` |
| output format | `output` | `PROTEUS_OUTPUT` | `--output` | `text` |
| log level | `log_level` | `PROTEUS_LOG_LEVEL` | `--log-level` | `info` |
| log directory | `log_dir` | `PROTEUS_LOG_DIR` | `--log-dir` | `~/.local/state/proteus/log` |
| logs kept | `log_keep` | | | `20` |
| inventory export | `export_inventory` | | | `false` |
| user snapshot | | `PROTEUS_USERS` | | none |

The `XDG_CONFIG_HOME`, `XDG_DATA_HOME` and `XDG_STATE_HOME` variables move the
default paths.

## The user snapshot

A configuration does not say which directory groups a user belongs to.
`PROTEUS_USERS` points to a JSON file that does:

```json
{
  "taken_at": "2026-09-28T08:00:00Z",
  "groups": {
    "ACME\\carol": ["engineering"],
    "ACME\\alice": ["engineering", "finance"]
  }
}
```

`taken_at` is required. An answer that uses an old user snapshot carries a note.

## Files proteus writes

| Path | Mode | Content |
| --- | --- | --- |
| `~/.config/proteus/config.yaml` | 0600 | the inventory, written once by `inventory init` |
| `~/.local/share/proteus/<device>/<time>/` | 0700 / 0600 | one snapshot |
| `~/.local/state/proteus/log/` | 0700 / 0600 | one log file per run, `<command>-<time>-<seq>.log` |
| `<store>/.proteus/inventory.yaml` | 0700 / 0600 | the inventory export, with `export_inventory: true` |
| `~/.local/state/proteus/log/mcp/` | 0700 / 0600 | one log file per MCP call, `mcp-<tool>-<time>-<seq>.log` |
| `audit_log` | 0600 | the MCP audit, one JSON line per call, appended |
