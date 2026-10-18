# Connect your firewalls

Write an inventory, fetch a snapshot of each firewall, and ask questions of all
of them.

## 1. Write an inventory

```bash
proteus inventory init            # writes ~/.config/proteus/config.yaml, mode 0600
$EDITOR ~/.config/proteus/config.yaml
```

Add one entry per firewall:

```yaml
version: 1
defaults:
  username: admin
  password_env: PANOS_PASSWORD      # the variable that holds the password
devices:
  - name: fw01
    host: fw01.example.net
    labels:
      site: vienna
```

!!! warning "The template turns certificate verification off"
    Lab firewalls present self-signed certificates, so the template sets
    `insecure_tls: true`. Anyone on the network path can then read the password
    and send false data. Set `insecure_tls: false` for each firewall whose
    certificate this machine trusts; see [TLS](../reference/configuration.md#tls).

Proteus refuses to read the inventory when other users can read it, so keep the
file at mode `0600`.

## 2. Fetch

```bash
export PANOS_PASSWORD='...'
proteus fetch --all
proteus snapshot show
```

[`fetch`](../commands/fetch.md) logs in to each firewall, reads its configuration
and operational state, and stores one snapshot per firewall. It fetches up to
eight firewalls at the same time, and a failed firewall leaves the others
running.

## 3. Ask

Without `--file`, each question reads the latest snapshot of every firewall in the
inventory:

```bash
proteus search 10.20.0.0/16
proteus simulate policy 10.20.1.5 10.1.250.10 --port 443
proteus simulate routing 10.20.1.5 8.8.8.8
proteus snapshot diff                  # after a second fetch
```

| To | Add |
| --- | --- |
| ask one firewall | `--device fw01` |
| ask the firewalls of one site | `--label site=vienna` |
| ask one vsys | `--vsys vsys1` |
| read older snapshots | `--at 2026-09-23` |
| fetch before you ask | `--fresh` |

`simulate policy` follows the routed path from the source and gives one verdict
for all firewalls on it. With that command, `--device` names the firewall where
the path starts.

## Next

- [How Proteus works](../concepts/index.md) explains snapshots, scopes and
  fidelity.
- [Commands](../commands/index.md) lists every command with its examples and
  flags.
- [Output and exit codes](../reference/output.md) shows how to use Proteus in
  scripts.
