# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
