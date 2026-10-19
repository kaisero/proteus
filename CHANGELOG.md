# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Check which rule a flow hits by its user.** `proteus simulate policy --user`
  matches the source user and the user groups of a rule as the firewall does,
  and the user mapped to the source address wins over the flag.
- **Find users, groups and the user of an address.** `proteus search` and
  `proteus lookup` show the groups and addresses of a user, the members of a
  group and the user mapped to an address, and `proteus snapshot diff` shows
  changed group membership.
- **Store the User-ID data of each firewall.** `proteus fetch` keeps the users,
  their groups and the user-to-address mappings of a single-vsys firewall with
  its snapshot, and `proteus mcp` answers with them as the commands do.

### Changed

- **A snapshot holds the template values the firewall runs.** `proteus fetch`
  merges the template that Panorama pushes into the running configuration, so
  the first `proteus snapshot diff` after the upgrade shows those values as
  added.

### Fixed

- **A snapshot no longer holds uncommitted changes.** `proteus fetch` reads the
  running configuration of each firewall, not the configuration export that also
  held the changes an admin had not committed yet.

### Removed

- **`PROTEUS_USERS` is gone.** The User-ID data that `proteus fetch` stores with
  each snapshot replaces the hand-made user file. With `--file`, put
  `identity.json.gz` next to the configuration.

## [0.0.1] - 2026-10-18

### Added

- **Store a snapshot of each firewall.** `proteus fetch` keeps the configuration,
  routes and state of every firewall in your inventory, so each answer comes from
  a stored copy and never touches a device.
- **Find where anything is used.** `proteus search` finds every object, group,
  rule and profile that uses an address, port, URL, user, application or name,
  across all firewalls and vsys.
- **Show a rule or an object in full.** `proteus lookup` prints a security rule
  as the firewall's rule editor lays it out, or an object with its value and the
  groups that hold it.
- **Check which security rule a flow hits.** `proteus simulate policy` answers
  allowed, denied or undecided for a flow by address, port, application and zone,
  on one firewall or along its whole path.
- **Trace NAT and the routed path.** `proteus simulate nat` shows the NAT rule a
  packet hits and the packet after translation, and `proteus simulate routing`
  shows which firewalls the packet crosses.
- **See what changed.** `proteus snapshot diff` lists the objects, rules and
  settings that changed on a firewall between two snapshots.
- **Know how certain an answer is.** Every answer names what Proteus could not
  evaluate, and an incomplete answer exits 3, so a script can refuse to act on it.
- **Script it or hand it to an agent.** Every command answers in JSON or YAML with
  stable exit codes, and `proteus mcp` serves the same answers to an AI agent.
- **Read the docs online.** The documentation is a website, in light and dark.
