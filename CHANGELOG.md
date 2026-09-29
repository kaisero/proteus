# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **See which NAT rule a packet hits.** `panos-analyst simulate nat <source>
  <destination> --device <name>` names the NAT rule a packet hits on one firewall,
  shows the packet before and after translation, and what security policy then
  matches: the addresses and port before NAT, the zones after it. `--why` lists
  every rule above the match and what excluded it; rules it cannot decide, such as
  one naming a service when no port is given, are named with the reason.
- **See which firewalls a packet crosses.** `panos-analyst simulate routing <source>
  <destination>` follows the fetched firewalls' forwarding tables from the firewall
  the source enters to the one that delivers it, and draws a box per firewall with
  the zones in and out, the interfaces and the route. NAT on the way is applied: a
  port forward changes where the packet goes, and later firewalls see the
  translated packet. It says where the path may be incomplete: ECMP, policy-based
  forwarding, or a path that leaves the inventory. `--port` decides NAT and PBF
  rules that name a service.
- **Fetch stores the routing table and reads the active firewall of an HA pair.**
  Every `fetch` now also stores the routing table and the HA state. When an
  inventory entry names the passive member of an active-passive pair, `fetch` reads
  the active peer instead and says so; `ha_peer` sets the peer's host when the
  address the device reports is not reachable.
- **Look up the whole rule or object behind a name.** `panos-analyst lookup <name>`
  prints a security rule laid out like the firewall's rule editor, or an object with
  its value, members and the groups holding it. `--expand` puts each name's value in
  parentheses and opens groups as a tree, and `--full` shows lists longer than five
  items. A name that several kinds share needs `--kind`.
- **Security policy simulation uses the zone after NAT.** When `simulate policy`
  derives the zones and a destination NAT applies, the destination zone is the one
  the translated address is routed to, as the firewall matches it. A zone you give
  still wins, with a note when NAT would give another.
- **A simulation says how certain its answer is.** `panos-analyst simulate
  policy` runs named stages that narrow the candidate rules by source and
  destination (an address, or an FQDN resolved through DNS), zone, port and URL
  category. Each stage declares whether its output is exact, may over-match, is
  inferred or may be missing matches, and the answer carries the weakest. `--why`
  shows every stage. Negated sources and destinations are evaluated, and rules the
  configuration cannot judge, such as `application-default` or a PAN-DB category,
  are kept and named rather than dropped.
- **Every run writes a log you can read back.** Each command writes one file under
  `~/.local/state/panos-analyst/log` with its settings, the snapshot each device
  resolved to, every API call and what each search or simulation stage kept.
  `--log-level debug` records every detail, `--verbose` echoes it to the terminal,
  passwords and API keys never reach it, and a run that ends badly prints where its
  log is.
- **Fetch a firewall into a snapshot store.** `panos-analyst inventory init` writes
  an inventory, `panos-analyst fetch` logs in with a username and password, and stores
  the running configuration, interfaces, forwarding table and system info as a
  timestamped snapshot, up to eight devices at once, so every analysis can be
  repeated against exactly what the device said. TLS certificate verification is off by default for self-signed lab
  devices, and the inventory says so and shows how to turn it on.
- **Search every device for a value or a name in one command.** `panos-analyst
  search 10.124.0.1` finds the objects holding it, the objects named by it, the
  groups holding those, every reference to them and the rules that write it
  directly, per device and vsys, across the whole inventory. `--exact`, `--within`
  and `--contains` change how it matches; `--kind`, `--field`, `--show` and
  `--direct` narrow it.
- **See what changed between two snapshots.** `panos-analyst snapshot diff` lists
  the objects and rules added, removed or changed per vsys since the previous
  fetch, or between any two points in time.
- **Choose devices, vsys and a point in time for every question.** `--device`,
  `--label`, `--vsys`, `--at` and `--fresh` work the same everywhere, `--file` reads
  one configuration with no inventory, `--output json` prints a versioned envelope
  for scripts, and an answer with gaps exits 3 so a script can refuse to act on it.
- **A lookup now says how it reached its answer.** Asking which rules a value can
  reach returns the objects that matched and the value in each that matched it — a
  prefix, an FQDN — so the reasoning can be checked instead of trusted.
- **Value matching is per value space, and the wiring comes from the schema.** A
  rule field is matched by the resolvers for the object kinds the schema allows
  there, so a field that accepts an address, a region and an external list is asked
  of each rather than treated as an address field. Addresses answer exactly as
  before; other value spaces arrive behind the same seam.
- **Applications resolve as far as a configuration allows.** A custom application and an
  application group resolve, so naming a custom application finds the rules naming the
  group holding it, and a predefined name such as `ssl` still works as a name. An
  application filter or container is reported rather than guessed: it selects predefined
  applications by category, risk and behaviour, and that metadata is in the content
  database a firewall downloads, not in its configuration.
- **Place an address in a zone from the firewall's own forwarding table.** Capture
  `show interface all` and `show advanced-routing fib` into a snapshot, hand it to the
  library through `Providers{Zones: …}`, and a zone answer comes from what the device
  is doing rather than from what its configuration says. Each answer names the
  interface, the logical router and the route that decided it. Point `PANOS_ZONES` at
  the file, or capture one with `scripts/capture-zones.sh`.
- **A snapshot is authoritative, and a configuration answer says that it is.** Where a
  snapshot places nothing, the configuration is not consulted instead. Where no
  snapshot is supplied the configuration still answers, and reports that it is an
  inference: on a lab firewall the configuration held one static route where the device
  held 25, and the two disagreed about the default route.
- **Several routers covering one address are all reported.** Which applies depends on
  the interface a packet arrives on, so every zone is named and none is chosen.
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

### Changed

- **The project and its command are now `proteus`.** Run `proteus` instead of
  `panos-analyst`; settings variables are `PROTEUS_*` instead of `PANOS_*`, and the
  inventory, snapshots and run logs now live in `proteus` directories, so move
  existing ones there.
- **Zones no longer have to be given to simulate.** Without `--from-zone` and
  `--to-zone`, they are derived from the device's stored forwarding table, or from its
  configuration, and the answer says which and marks them as inferred.
- **The project is now `panos-analyst`.** The module path is
  `github.com/okaiser/panos-analyst`; update imports that used
  `github.com/okaiser/go-panos-schema`.
- **A configuration from a release without a bundled schema now loads.** It is read
  with the nearest schema this build carries, and every answer from it says which two
  versions were involved, because a field that moved between them can make a lookup
  miss rules without looking incomplete.

### Removed

- **The Go packages can no longer be imported.** proteus is now an application
  only, so code that imported its packages has to copy what it needs.
- **`panos-explore` is gone.** Its questions live in `panos-analyst`: `reaches`,
  `lookup`, `search`, `uses`, `whereused` and `group` are `search`; `simulate` is
  `simulate policy`; `info`, `groups` and `target` are `snapshot show`.

- **Panorama configurations are no longer read.** panos-analyst works from each
  firewall's own configuration, so device groups, templates and the device-group
  hierarchy are gone, and loading a Panorama export returns an error that says so.
  A firewall's pushed shared pre- and post-rules are still read in evaluation order.

### Fixed

- **A custom URL category entry now covers the paths below its host.** An entry
  such as `shop.example.com` matched only that exact URL, so `shop.example.com/cart`
  reached no category and the rules using it were missed.
- **A reference is listed in a column wide enough to hold it.** A field is a path
  wherever the reference is nested, and `profile-setting/profiles/file-blocking` is
  six times the width of `source`, so the fixed column truncated the long ones. Both
  `panos-explore whereused` and the search server's `where_used` now size the scope
  and field columns to the rows they are about to print, and the `could be`
  continuation lines up with them.

- **A configuration was read once per scope to build the same reference edges.**
  Each scope's index walked the whole file and discarded everything it could not
  see, so a Panorama file with 29 scopes was read 29 times. The read is now shared
  and the indexes still are not: an index holds positions into one edge list rather
  than its own copies, and still sees only its own scope and shared. Building every
  scope's index now costs barely more than reading the file once —
  `BenchmarkRefsIndexEveryScope` against `BenchmarkReadEdges` — and holds less,
  because 29 overlapping scopes stored 419,042 edges to describe 479,482.
  `TestNoGlobalIndex`, which R10 has always named as its check, now exists.

- **Four fifths of the configuration's reference edges were never read.** The walk
  recognised one shape, `entry/<field>/member`, which is 397 of the firewall schema's
  1,991 reference leaves and 834 of Panorama's 4,524. Three things were missed: a
  value that is an element's text rather than a member, such as a rule's
  `log-setting` or `schedule`; a leaf below the first level, such as
  `profile-setting/profiles/url-filtering/member`; and anything under a named choice
  or union, because those were flattened away with the anonymous ones although they
  are real elements — the firewall schema has 358 of them. A security rule declares
  30 reference leaves and 16 were seen, so asking what used a rule's profile group,
  file-blocking profile or log-forwarding profile answered that nothing did.
  `Walk` is superseded by `WalkPaths`, which locates every leaf by its path below
  the entry and finds half again as many edges on a 29 MB Panorama configuration —
  in 109 ms against the old walk's 183 ms, because the entry's instance path is now
  built once per entry rather than once per value.

- **Two code comments carried a stale field census.** The scope-relative classifier
  fix changed the counts and the comments were not updated: a Panorama schema has
  2,961 reference fields, 1,034 of which declare more than one candidate kind, and
  the worst declares 153 — not 2,420, 919 and 31. `TestReferenceFieldCensus` now pins
  them against the committed digest.

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
