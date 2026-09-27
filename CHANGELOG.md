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
- **Ask which zone an address would arrive on.** `reaches ... from 10.1.0.50` reads the
  configuration as a small routing table — interface addresses and static routes, mapped
  through each interface to the zone holding it, longest prefix winning — and reports the
  zone plus the interface and route that placed it. Every limit is reported rather than
  hidden: a zone with no interface, an interface in no zone, a virtual router that learns
  routes at runtime, an address no route covers, and a Panorama device group whose zones
  live in a template.
- **`simulate` takes zones, and with them it agrees with the firewall.**
  `simulate <config> <scope> <source> <destination> <from-zone> <to-zone>` narrows the
  answer the way the device does. Measured against `test security-policy-match` on a lab
  firewall with probes built from each rule's own zones and ports: 3 of 7 agreed without
  zones, 7 of 7 with them. Without zones the answer is not slightly wrong but often
  wrong — one probe reported an allow where the device denies — because a single rule
  with `source any` and a wide destination covers nearly every address pair, and only
  its zones hold it back.
- **Ask which rules a user reaches, with group membership from outside the file.**
  `reaches ... source-user alice` finds the local user, the local groups holding it and
  the rules naming either. Supply a user snapshot and the directory groups are added
  too. Without one the answer says that only the local database was searched, and a
  dynamic user group is always reported rather than matched, because User-ID fills it in
  at runtime.
- **A user snapshot format, defined by the library and fetched by the caller.**
  A small JSON file of user-to-group mappings with the time it was taken. A snapshot
  older than a day is reported on every lookup that used it, because a mapping read
  days ago can place a user in a group they have since left. Point `PANOS_USERS` at one.
- **Ask which rules a port reaches.** `reaches ... service tcp/8006` reports the
  service objects covering that port, the groups holding them and the rules naming
  either. Port ranges are matched as ranges, a bare `443` matches whichever protocol
  carries it, and the hit reports the range that matched. Tags need nothing new: a tag
  is a name, so asking for one already worked.
- **Find which rules apply a profile that mentions a URL category.**
  `panos-explore uses <config> <scope> <category|url>` follows the path a rule takes
  to a category through its security profiles — profile group or named profile, then
  which action list the category sits in. This is how URL filtering is normally
  deployed: on a lab firewall every rule has `category any` and all URL policy runs
  through profile settings, so asking about the category field alone reports nothing.
  It is not a match and no allow-or-block verdict is given: what a profile does with a
  request depends on the response and the session, neither of which is in a
  configuration.
- **Search every object value by fragment.**
  `panos-explore search <config> <scope> <substring>` finds objects whose value
  contains a fragment, case-insensitively, across addresses, FQDNs and URL category
  members. This is the answer to a name that cannot hold its own value: a custom URL
  category name may be 31 characters and one of its members 255, so searching
  `azureapps` finds the category holding a 41-character URL that appears in no name
  anywhere.
- **`panos-explore reaches <config> <scope> <field> <value>`** asks which rules one
  rule field could match one value, whatever kind of value it is: an address, a
  prefix, a URL or an object name. It prints what matched and via which value, and
  says when rules are included only because the field is `any`.
- **Ask which rules a URL reaches.** Give the library a URL and it reports the
  custom URL categories covering it, the rules naming those categories, and the
  member that matched — an exact URL or a wildcard alike. A category name still works
  as before. On a lab firewall, `superlong.example.azureapps.microsoft.com` and
  `foo.wildcard-example.com` both reach the rule `URL-Example`, which no lookup
  previously found.
- **A recognised value that matches nothing is a complete answer.** A URL belonging to
  no category reaches only the rules whose category is `any`, and says nothing about
  being incomplete. Only a value no value space recognises is reported as incomplete.
- **Custom URL category members are parsed the way a firewall writes them.** A
  member is matched by tokens, not by substring: `wildcard-example.com` does not
  cover `wildcard-example.com.evil.net`. The host must match in full and the path
  matches as a prefix, `*` takes one or more tokens and `^` exactly one, and a
  pattern a firewall would refuse is refused here with the reason.
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

- **Thousands of reference edges were being discarded.** Any schema target beginning
  `#myentry(` counted as a template variable, but almost all of them are ordinary
  scope-relative references — `#myentry(vsys)/zone/entry/@name` names a zone. Recovering
  them adds 1,413 object references in the Panorama schema and 1,455 in the firewall
  schema, and it is what lets a zone be resolved at all: a firewall schema contains no
  template variables, so every one of its scope-relative targets was thrown away.

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
