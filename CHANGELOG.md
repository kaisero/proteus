# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
