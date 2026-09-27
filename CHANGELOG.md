# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A lookup now says how it reached its answer.** Asking which rules a value can
  reach returns the objects that matched and the value in each that matched it — a
  prefix, an FQDN — so the reasoning can be checked instead of trusted.
- **Value matching is per value space, and the wiring comes from the schema.** A
  rule field is matched by the resolvers for the object kinds the schema allows
  there, so a field that accepts an address, a region and an external list is asked
  of each rather than treated as an address field. Addresses answer exactly as
  before; other value spaces arrive behind the same seam.
- **Objects nested under a sub-container are visible.** A custom URL category, and
  every security profile, lives under `profiles/` rather than directly under its
  scope, so the library found none of them. Where a kind sits now comes from the
  schema, so a kind added later needs no code change.
- **An incomplete answer now says so.** Asking which rules a value can reach
  returns the rules together with a list of what could not be evaluated. A value
  that is not an address, not a prefix and not a known object name — a URL, for
  instance — previously came back as the rules whose field is `any`, which reads
  like a real answer and omits the rule that actually names the value.
- **Load a whole PAN-OS or Panorama configuration and ask what a firewall
  actually gets.** Point the library at a configuration file and it tells you
  which device groups a firewall inherits from, the security rules that apply in
  the order the firewall evaluates them, which objects are visible and which are
  shadowed by a more specific definition, and what a shared dynamic address group
  resolves to in that device group specifically. It also indexes the result, so
  finding every rule that touches an address is immediate.
- **A Go model of the PAN-OS configuration, generated from the schema PAN-OS
  itself ships.** Point the generator at a firewall or Panorama schema and it
  produces typed Go structs for every configuration object, so a tool can read a
  configuration without hand-writing any of that structure.
- **Repository skeleton.** Project layout, build and lint configuration, CI, and
  the mandatory rules that govern the library.

### Fixed

- **Looking up an unknown name no longer corrupts a shared index.** Indexes are
  cached and handed to every caller, and a lookup by name added that name to the
  index's internal name table. Two callers asking about unknown names at the same
  time raced on it.
- **Service objects report their port.** Every service read back with an empty
  value, because the port sits under the protocol rather than on the entry.
  `svc-pve` now reads `tcp/8006`. A custom URL category likewise reports its member
  list as its value.
- **An FQDN address object is found by its own name.** Asking for
  `host.example.com` now finds the object holding it, case-insensitively, and says
  that the addresses the name resolves to are not in the configuration.
