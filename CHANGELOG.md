# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Keep a broad answer short with `--limit`.** `search`, `lookup` and
  `snapshot diff`, and their MCP tools with `limit`, can keep only the first N
  findings, cards or changes; the summary says how many it left out and what
  narrows the question. There is no default, so an answer without a limit is
  whole as before. `snapshot diff` now ends with a count line and has a
  `summary` in JSON and YAML, as `search` and `lookup` do.
- **Let an AI agent ask proteus questions.** `proteus mcp` serves simulate,
  search, lookup and snapshot diff as MCP tools, over stdio or token-protected
  HTTP behind a TLS proxy, with an audit line per call and a container sample.
- **The MCP server marks its tools read-only and keeps its logs lean.** Gateways
  and clients see that every tool only reads; the audit file rotates by size or
  goes to standard output, and a call keeps its own run log only when it fails,
  times out, or runs at `--log-level debug`.
- **Fetch can write the inventory without credentials for the server.** With
  `export_inventory: true`, every fetch writes a credential-free copy into the
  store; a run that stored its snapshots but could not write the copy exits 3.
- **Ask whether the estate allows a flow end to end.** `proteus simulate policy
  <source> <destination>` now follows the routed path and checks the security policy
  of every firewall and vsys on it, and answers allowed, denied or undecided, with the
  hop that decided. Each box of the path shows that hop's policy answer, and an
  undecided answer exits 3.
- **Colour shows what needs attention.** On a terminal, holes, failures and denies are
  red, unresolved and partial results yellow, allows and successes green, and target
  headers bold. `--color auto|always|never`, `PROTEUS_COLOR` or the inventory's
  `color:` chooses it; `auto` turns it off for `NO_COLOR` or a pipe, and JSON and YAML
  are never coloured. Columns stay aligned whatever the names' length.
- **Fetch shows its stages and speaks JSON.** `fetch --why` lists each device's stages
  (resolve, login, ha, documents, store) and what each did; on a terminal each stage
  shows as it ends. `fetch` and `inventory init` answer in JSON and YAML like every
  other command. A failed device is reported once, and Ctrl-C still reports every
  device named.
- **Read any answer as YAML.** `--output yaml` prints the same envelope as
  `--output json`, with the same keys, in YAML that YAML 1.1 and 1.2 readers both read
  back unchanged.
- **See which NAT rule a packet hits.** `proteus simulate nat <source>
  <destination> --device <name>` names the NAT rule a packet hits on one firewall,
  shows the packet before and after translation, and what security policy then
  matches: the addresses and port before NAT, the zones after it. `--why` lists
  every rule above the match and what excluded it; rules it cannot decide, such as
  one naming a service when no port is given, are named with the reason.
- **See which firewalls a packet crosses.** `proteus simulate routing <source>
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
- **Look up the whole rule or object behind a name.** `proteus lookup <name>`
  prints a security rule laid out like the firewall's rule editor, or an object with
  its value, members and the groups holding it. `--expand` puts each name's value in
  parentheses and opens groups as a tree, and `--full` shows lists longer than five
  items. A name that several kinds share needs `--kind`.
- **Security policy simulation uses the zone after NAT.** When `simulate policy`
  derives the zones and a destination NAT applies, the destination zone is the one
  the translated address is routed to, as the firewall matches it. A zone you give
  still wins, with a note when NAT would give another.
- **A simulation says how certain its answer is.** `proteus simulate
  policy` runs named stages that narrow the candidate rules by source and
  destination (an address, or an FQDN resolved through DNS), zone, port and URL
  category. Each stage declares whether its output is exact, may over-match, is
  inferred or may be missing matches, and the answer carries the weakest. `--why`
  shows every stage. Negated sources and destinations are evaluated, and rules the
  configuration cannot judge, such as `application-default` or a PAN-DB category,
  are kept and named rather than dropped.
- **Every run writes a log you can read back.** Each command writes one file under
  `~/.local/state/proteus/log` with its settings, the snapshot each device
  resolved to, every API call and what each search or simulation stage kept.
  `--log-level debug` records every detail, `--verbose` echoes it to the terminal,
  passwords and API keys never reach it, and a run that ends badly prints where its
  log is.
- **Fetch a firewall into a snapshot store.** `proteus inventory init` writes
  an inventory, `proteus fetch` logs in with a username and password, and stores
  the running configuration, interfaces, forwarding table and system info as a
  timestamped snapshot, up to eight devices at once, so every analysis can be
  repeated against exactly what the device said. TLS certificate verification is off by default for self-signed lab
  devices, and the inventory says so and shows how to turn it on.
- **Search every device for a value or a name in one command.** `proteus
  search 10.124.0.1` finds the objects holding it, the objects named by it, the
  groups holding those, every reference to them and the rules that write it
  directly, per device and vsys, across the whole inventory. `--exact`, `--within`
  and `--contains` change how it matches; `--kind`, `--field`, `--show` and
  `--direct` narrow it.
- **See what changed between two snapshots.** `proteus snapshot diff` lists
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

- **JSON format 2: every reason has a code, and every result says its answer.**
  Reasons are `{code, text}` objects a script can match by code, each result has a
  one-line `answer` and, when held back, the `needs` a second question can give;
  see the scripting guide.
- **A rule matched only through an FQDN object is in doubt.** The firewall resolves
  an FQDN address object itself, so its addresses can differ from this machine's
  DNS answer. `simulate policy` keeps such a rule as a candidate in doubt instead of
  treating the match as certain.
- **A flag given an empty value counts as not given.** `--router ""`, `--at ""` and
  `--from-zone ""` now act as if the flag were left out.
- **A NAT answer asks only for what can decide it.** When a NAT rule needs the
  port, the answer says "give the destination port", and `needs` stops at the first
  rule in doubt that no input can decide.
- **Run log names end in a sequence number.** A log is now
  `<command>-<time>-<seq>.log`, so runs that start in the same millisecond write
  separate files.
- **`simulate policy --device X --vsys V` now exits 2.** Without `--file` the command
  answers along the path, so `--vsys`, `--label` and the zone flags exit 2; use
  `--file <path> --vsys <name>` for one configuration. `--file` does not check NAT: a
  derived zone is the zone before NAT, and a given zone gets no NAT note.
- **Default rules decide a flow that no rule matches, and rule-type is applied.**
  The answer names `interzone-default` or `intrazone-default` with its action, from
  a local or pushed override or the built-in one. Local and pushed overrides that
  disagree leave the flow undecided.
- **A policy answer says when it cannot decide.** A rule that names an application,
  `application-default`, a predefined or absent service, or a user above the match
  can leave the flow undecided (exit 3), and rules naming an external list, a region
  or a dynamic group stay as candidates in doubt instead of being dropped. A schema
  version gap is now a note and no longer forces exit 3.
- **`snapshot diff` no longer offers `--file`, `--at` or `--fresh`.** It always
  refused them; they are now unknown flags. Shared flags have one help text in every
  command.
- **Exit codes are the same in every command, and machine output ends stderr with one
  JSON line.** An unknown command or help topic exits 2 at every level. Ctrl-C exits 130
  and SIGTERM 143, with the run log closed. With `--output json`, the last stderr line
  of a non-zero exit is `{"format":1,"exit":N,"error":…,"log":…}`, also for errors in
  the command line itself. `fetch` of a name not in the inventory or of a selection
  that matches no device, `inventory init` on an existing file, and `simulate nat`
  without `--device` exit 2.
- **Simulations answer with holes instead of failing, in one JSON shape.** A device
  without a snapshot makes `simulate policy`, `nat` and `routing` exit 3 with a hole,
  not 1 or 2. `results` is an array for every simulation, each stage has the same keys,
  and notes the text shows are in the JSON `notes` too.
- **A missing snapshot is a hole everywhere, and a name found nowhere is an empty
  answer.** `snapshot list` for a device with no snapshot exits 3 with a hole
  instead of 1, and a name the inventory does not have exits 2. A lookup name found
  nowhere exits 0 with `results` `[]`, like a search with no results, instead of 1.
- **Settings say where they came from, and a bad one exits 2.** The run log records
  each setting with its source (flag, `PROTEUS_*` variable, inventory or default). A
  bad `output`, `log_level`, `max_snapshot_age` or `color` value now names its source
  and exits 2, from the inventory too, instead of failing the whole inventory load.
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

- **`panos-demo` and `panos-schemagen` are gone.** `proteus` is now the only
  binary; a schema digest for a new PAN-OS version is made with `make
  schema-digest`.
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

- **A NAT rule whose source or destination is an external list, a region or a
  dynamic group is a doubt.** Such a rule may hold an address without the
  configuration saying so, so a flow it may take now lists it as a doubt, as
  PBF and the security check do. Before, NAT skipped the rule as a sure miss and
  a later rule answered, marked exact.
- **A NAT pool whose address groups hold each other no longer stops the
  program.** Each group of a translated address now adds its members once, so a
  cycle ends and a group held twice adds its addresses once. Before, such a pool
  recursed until the stack ran out, which ended `simulate` and the MCP server
  with a fatal error.
- **A search finding names the scope that defines the object.** An object found
  by its name, and a group holding an object found, now carry their own `scope`
  in JSON, YAML and MCP answers, such as `shared` or `predefined`. Before, they
  carried the vsys searched, as if that vsys defined them.
- **A /32 or a range of one address finds a wildcard object, as the address
  does.** `search 10.88.7.1/32` and `search 10.88.7.1-10.88.7.1` now find a
  wildcard address object that matches the address, the groups holding it and
  the rules naming them. Before, they listed the object as unresolved and exited
  with code 3, while `search 10.88.7.1` found it.
- **NAT translates to a large address group quickly.** A source pool that is
  a static group of 200 address objects, among 20,000, now takes about 5 ms and
  25 MB per translation (`BenchmarkTranslatePoolGroup`). Before, each name and
  each group member read every address object again, which took 0.9 s and
  4.7 GB per translation.
- **A service name that two scopes define now means the nearest one, whatever
  its kind.** A vsys service hides a shared service group of the same name, and
  a vsys service group hides the predefined service, in NAT, security policy and
  `lookup` alike. Before, NAT took the service group first from any scope, the
  security policy matched both objects, and a rule's card could show the hidden
  one, so each could give a wrong answer marked exact.
- **The MCP server's cache counts what a loaded snapshot really keeps.** A cached
  snapshot now counts 32 MiB plus 13 times its file size, as measured. Before, it
  counted 13 times the file size alone, so the cache could grow past `max_cache`.
  A `max_cache` sized by the old rule can now be too small, and the server then
  loads snapshots again.
- **`snapshot diff` tells pushed pre-rules from post-rules.** A rule pushed from
  Panorama now reads `pre-rulebase security rule` or `post-rulebase security
  rule`, and a vsys's own rule still reads `security rule`. Before, both pushed
  rulebases read `security rule`, so two pushed rules of one name looked the same.
- **`snapshot diff` compares the settings of a vsys and of shared.** A setting
  outside any object or rule, such as the interfaces a vsys imports, its captive
  portal or the trusted root CAs, now shows as a change of kind `setting`, named
  by its path; a vsys user group's members show as kind `user-group`. Before,
  the diff said "no changes" when only such a setting changed.
- **An added or removed object in `snapshot diff` no longer shows undescribed
  values.** An object that holds a value the schema does not describe, or a
  secret, now has no short line, and a rule's line shows every list the schema
  describes. Before, a zone's tags could show in the line, and a rule that held an
  undescribed list of `any` read `(not shown)` in place of its own `any` values.
- **`snapshot diff` hides SNMP communities and other clear-text credentials.** An
  SNMP v2c trap community, a SCEP fixed challenge, the URL, payload, header and
  parameter values of an HTTP server profile and the values of an MFA server profile now read
  `(secret)`, as passwords do. Before, their old and new values showed, because
  the schema does not mark them as encrypted.
- **A path held back by a PBF rule's service now asks for the port.** Asked
  without a port, a PBF rule that names a service left the path undecided with
  `needs: []`. The hop now says why the rule only may match, and `needs` asks
  for the port.
- **A PBF rule from an external list, a region or a dynamic group now may
  match.** Only the addresses the configuration places in them counted, so such
  a rule was skipped for every other address and the path was called exact. A
  forward or discard rule now leaves the path undecided, and a no-pbf rule is
  passed over with its doubt.
- **A PBF rule with a schedule now only may match.** The schedule was not
  read, so a scheduled no-pbf rule always left the packet to routing and hid
  the forward rule below it, and a scheduled forward rule counted as certain.
- **`simulate policy --file` no longer takes a default static route as the
  source zone.** With no zones given, a source that only a `0.0.0.0/0` static
  route reaches was placed in that route's zone, so the default rule decided
  on a zone the packet may not arrive in. The source zone now stays open, as it
  does with a forwarding table.
- **A rule that names a service group holding an unknown service is now in
  doubt.** In a snapshot without the predefined services, a group such as `web`
  with `service-https` and `tcp/8443` counted as known, so a PBF or security
  rule naming it was ruled out for `tcp/443` and a later rule answered, marked
  exact.
- **The version-gap note counts what the older schema does not know.** When a
  configuration is read with an older release's schema, the `gap.version` note now
  says how many of its elements that schema does not describe, such as fields a
  newer release added. Before, it warned of the gap but not whether this
  configuration held anything the schema missed.
- **`--at` and `snapshot diff` pass over a damaged snapshot.** They read the
  next older snapshot that can be read, and a `note.snapshot-skipped` note names
  the one passed over; when none can be read, the hole is `gap.load-failed` and
  names the damaged ones. Before, `--at` stopped at it with a hole, and
  `snapshot diff` said there was only one snapshot to compare.
- **NAT answers quickly on a configuration with many bi-directional rules.**
  One flow against 300 bi-directional rules among 20,000 address objects now
  takes about 6 ms and 27 MB (`BenchmarkMatchBidirectional`). Before, each
  implicit rule read every address object again, which took 1.4 s and 7 GB.
- **Long group cycles and large group trees no longer stall a question.** Each
  group's members and doubts are worked out once per index build, and groups
  that hold each other are joined first. Before, one cycle of 5,000 address
  groups took 29 s to index and one of 2,000 took 11 s; now both take under
  75 ms (`BenchmarkIndexBuildGroupCycle`). 30 groups that each hold three
  others took 41 s; 40 such groups now take 57 ms
  (`BenchmarkIndexBuildDenseGroups`). The `lookup` card of a rule whose group
  tree holds 364 groups took 290 ms and 1.2 GB; now 8 ms and 34 MB
  (`BenchmarkRuleCardNestedGroups`). A card now opens each group once and marks
  it `members shown above` where it meets it again. The card of one of 24
  groups that each hold three others took 1.1 s and 1.8 GB; one of 30 now takes
  9 ms and 34 MB (`BenchmarkObjectCardDenseGroups`). The card of a rule on a
  cycle of 5,000 groups took 0.53 s and 1.2 GB; now 12 ms and 43 MB
  (`BenchmarkRuleCardGroupRing`).
- **The sample containers stop cleanly, and the proxy log keeps no identity
  claims.** `docker compose down` now lets proteus-mcp finish its running calls,
  and proteus-fetch stops its fetch at once and exits 143. The server's whole
  stop ends within `call_timeout` + `max_wait` + 10 s, also when a call hangs.
  Caddy drops the `X-User-Claims` header from every log line, also from the
  error line of a request that fails while proteus-mcp restarts. Before, the
  fetch container ignored SIGTERM until Docker killed it after 10 seconds, the
  server's running calls got only those 10 seconds, and each proxy log line held
  the user's claims.
- **`snapshot list` shows the good snapshots when one is damaged.** A snapshot
  whose `meta.json` is missing or unreadable becomes a hole, and the list goes
  on. Before, one such snapshot stopped the command with an error and no list.
  Questions that read such a snapshot through `latest` or `device@id` now give
  the hole code `gap.load-failed`, not `gap.snapshot-missing`.
- **A device named twice in `fetch` is fetched once.** Before, both fetches
  ran together and wrote the same snapshot, so one failed and the run exited 3.
  Two runs that store one device in the same second now fail the second one at
  once, and it no longer removes the first one's files.
- **A run of failed fetches no longer removes the last good snapshots.**
  `snapshot_keep` now keeps the newest N snapshots with a configuration and the
  newest N without one. Before, it counted both together, so N failed exports in
  a row removed every snapshot but the one `latest` names.
- **`proteus mcp` reads the `PROTEUS_USERS` file once, at start.** A missing or
  invalid file stops the start with exit 2 and names the file; a change needs a
  restart. Before, every call read the file again: the server started with a bad
  file and failed each call that needed it, and calls could answer from
  different versions of the file.
- **The run log of an MCP call that timed out now keeps what came late.** It
  records what the work did after the timeout, when it returned, and the stack
  of a panic. Before, the log closed at the timeout, so a later panic was lost.
- **A broad MCP answer now writes a short audit line.** The `verdict` keeps the
  summary line and the first 20 result lines, and `verdict_count` holds the full
  count. Before, a search with thousands of findings wrote all of them into one
  audit line.
- **A bad `--from` or `--to` in `snapshot diff` is now a usage error.** It exits
  2 and names the flag, as a bad `--at` does; the MCP tool names `from` or `to`.
  Before, every device became a hole that blamed `--at`, and the command exited 3.
- **`snapshot diff` now reports every changed setting of objects and rules.** A
  changed entry lists each setting that differs, such as
  `negate-destination: (unset) -> yes`. Secrets, and values the schema does not
  describe, show only that they changed; such values are common on a newer
  PAN-OS, which proteus reads with the 11.2 schema. Before, it missed negation,
  NAT translations, profiles, zones and the PBF and other rulebases.
- **A zone the vsys does not define is now refused.** `--from-zone` and `--to-zone`
  of `simulate policy --file`, and `--from-zone` of `simulate nat`, exit 2 with the
  vsys's zones listed. Before, a typo in a zone name could still let an intrazone
  rule decide the answer.
- **`search` now lists references from the device's own configuration.** A static
  route or an IKE gateway that names an address object shows as a reference with
  scope `config`. Before, only rules and objects inside a vsys or shared were
  found, so such an object looked unused.
- **`search --within` and `--exact` now compare an address's whole value.** An
  address range, as an object or written into a rule, matched when one part of it
  did: `10.0.0.2-10.0.0.9` was found within `10.0.0.0/29` and exactly
  `10.0.0.4/30`, and so were the rules that use it.
- **A name used by several kinds of object now counts as each of them.** When a
  tag and an address group, or an address group and a service group, shared a
  name, `search` kept only one kind: it missed the references to the other and
  could give a group the wrong kind, and a service group could pass as holding an
  address. A reference to such a name now says which kind its field names.
- **Groups that hold each other now give the same answer on every run.** When
  address groups formed a cycle, which groups held an address depended on the order
  the index was built in, so a rule on one of them was found on some runs and
  missed on others.
- **`search` now refuses a kind it does not know.** `--kind adress` (or `kind` in the
  MCP tool) exits 2 and lists the kinds the configuration can hold. Before, a
  misspelt kind found nothing, which read like an answer.
- **`simulate policy --file` now checks the first address of a host name.** It
  matched every address the name resolved to, so a rule for the second address
  could answer, unlike path mode. A note now names the other addresses.
- **Intrazone and interzone rules and the default rules now check derived zones.**
  With `--file` and no zones given, an intrazone rule from `inside` was a candidate
  for a flow from `inside` to `out`, and the answer could name it. One derived zone
  on each side now decides rule-type and the default rule; with several, such a
  rule is in doubt, and `needs` asks for the zones.
- **A NAT rule that names a service now waits for the protocol.** Asked with a
  port and no protocol, a NAT rule for `udp/443` took a `tcp/443` flow for sure.
  It is now in doubt, and `needs` asks for the protocol. A protocol given as `6`,
  `17` or `132` counts as tcp, udp or sctp.
- **A path with a NAT rule in doubt is now undecided.** When a NAT rule above the
  one applied might match instead, `simulate policy` answered allowed or denied as
  if the applied rule were certain, and a derived destination zone could lose the
  zone the flow has without that NAT.
- **Rules that name `service-http` or `service-https` now decide after the next
  fetch.** `fetch` stores the firewall's predefined services with each snapshot.
  Before, proteus did not know their ports, so every rule naming one stayed in doubt
  and could leave a NAT or policy answer undecided.
- **A PBF rule now matches only the services it names, and a no-pbf rule that
  names an application no longer ends the search.** A no-pbf rule for `tcp/22`
  also took `tcp/443`, so a later forward rule was never found and the path was
  called exact.
- **A wildcard address object now matches the addresses its mask allows.** An
  object such as `10.88.2.1/0.0.255.0` matched no address, so a simulation skipped
  the rules using it and a later rule answered. A search for a prefix or a range
  wider than one address, or with `--within` or `--exact`, now lists such an
  object as unresolved (`gap.address-wildcard`) and exits 3, because a prefix
  cannot decide a mask.
- **A dynamic group whose filter starts with a parenthesis now counts as dynamic.**
  A filter such as `('web' or 'db')` was read as one member name, so no address
  reached the group and the rules using it were skipped.
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
