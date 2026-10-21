package inventory

import (
	"fmt"
	"os"
	"path/filepath"
)

// Template is the inventory proteus init writes. It is a working file once a
// host and the password variable are filled in, and it states the TLS choice rather
// than leaving it to a default nobody reads.
const Template = `# proteus inventory. Keep this file private: proteus refuses to read
# it when anyone but its owner can.
version: 1

defaults:
  # TLS certificate verification is OFF. Lab firewalls present self-signed
  # certificates, which verification would reject. The cost: anyone on the network
  # path can read the password at login and feed proteus a false configuration,
  # and every answer drawn from it is then false. Once your devices present
  # certificates this machine trusts, opt in with:
  #   insecure_tls: false
  # A device can also set insecure_tls on its own entry.
  insecure_tls: true
  timeout: 60                    # seconds per API call
  snapshot_keep: 20              # snapshots kept per device, with and without a configuration
  username: admin                # the login used to fetch an API key
  password_env: PANOS_PASSWORD   # the environment variable holding its password
  max_snapshot_age: 24h          # answers from older snapshots carry a note
  output: text                   # text or json
  log_level: info                # error, warn, info or debug; debug explains every answer
  log_keep: 20                   # run logs kept
  # log_dir: ~/.local/state/proteus/log
  # store: ~/.local/share/proteus   # where snapshots are kept
  # export_inventory: true          # fetch writes <store>/.proteus/inventory.yaml for proteus mcp

devices:
  - name: fw01
    host: fw01.example.net
    labels:
      site: vienna
    # When fw01 is the passive member of an HA pair, fetch reads its active peer at
    # the management address fw01 reports. Set ha_peer when that address is not
    # reachable from here.
    # ha_peer: fw01-b.example.net
    # identity: false   # do not fetch the User-ID data of this device
`

// WriteTemplate writes Template to path with mode 0600, creating its directory. It
// never overwrites an existing file.
func WriteTemplate(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	if _, err := f.WriteString(Template); err != nil {
		_ = f.Close()
		return fmt.Errorf("inventory: %w", err)
	}
	return f.Close()
}
