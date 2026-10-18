# Output and exit codes

Proteus prints text for people, and JSON or YAML for scripts. The exit code tells
a script whether the answer is complete.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | A complete answer. An empty answer is complete. |
| 1 | An error stopped the command, and no answer exists. |
| 2 | A usage error: a bad flag, a missing argument, or a name with several kinds. Change the command line. |
| 3 | An answer with [holes or unresolved entries](../concepts/fidelity.md#holes-unresolved-entries-and-notes). The output is valid, but it can miss matches. |
| 130 | Interrupted by SIGINT (Ctrl-C). |
| 143 | Interrupted by SIGTERM. |

`fetch` uses the codes differently:

| Code | `fetch` result |
| --- | --- |
| 0 | every device stored every document |
| 3 | a device or a document failed, and at least one device stored |
| 1 | no device stored |

`fetch` prints its answer in all three cases.

### Fail a pipeline on an incomplete answer

```bash
proteus simulate policy 10.20.1.5 10.1.250.10 --port 443 --output json > answer.json
case $? in
  0) echo "complete" ;;
  3) echo "incomplete or undecided: check holes and unresolved"; exit 1 ;;
  *) echo "error"; exit 1 ;;
esac
```

## The envelope

`--output json` and `--output yaml` print one envelope per command. Both formats
have the same keys, the same values and the same shape.

| Key | Holds |
| --- | --- |
| `format` | the envelope version, `2` |
| `command` | the command name, for example `search` |
| `detail` | `full` or `summary` |
| `input` | the typed input: term, selection and flags |
| `results` | the answer; always an array, empty when there is nothing to show |
| `summary` | counts and the count line, for `search`, `lookup` and `snapshot diff` |
| `holes` | devices or vsys that the command could not read |
| `unresolved` | entries that the command could not evaluate |
| `notes` | facts that qualify the answer and leave it unchanged |

`holes`, `unresolved` and `notes` are at the top level, so a script cannot miss
them. `format` changes only when a field changes its meaning or is removed.

```text
$ proteus search 10.124.0.1 --vsys vsys1 --show objects --output json \
    --file testdata/config/firewall-multivsys.xml
{
  "format": 2,
  "command": "search",
  "detail": "full",
  "input": {
    "direct": false,
    "fields": null,
    "kinds": null,
    "limit": 0,
    "mode": "covers",
    "selection": {
      "file": "testdata/config/firewall-multivsys.xml",
      "vsys": [
        "vsys1"
      ]
    },
    "show": [
      "objects"
    ],
    "term": "10.124.0.1"
  },
  "results": [
    {
      "answer": "file/vsys1: address corp-dc-vienna",
      "device": "file",
      "vsys": "vsys1",
      "stage": "object",
      "kind": "address",
      "name": "corp-dc-vienna",
      "via": "10.124.0.1/32",
      "scope": "vsys:vsys1"
    },
    {
      "answer": "file/vsys1: address corp-location-vienna",
      "device": "file",
      "vsys": "vsys1",
      "stage": "object",
      "kind": "address",
      "name": "corp-location-vienna",
      "via": "10.124.0.0/16",
      "scope": "vsys:vsys1"
    }
  ],
  "summary": {
    "answer": "1 with results, 0 without, 0 holes",
    "found": 2,
    "with": 1,
    "without": 0,
    "omitted": 0
  },
  "holes": [],
  "unresolved": [],
  "notes": []
}
```

### Results

Each result of `simulate`, `search`, `lookup` and `snapshot diff` has an `answer`:
the line of the text output that says what the result found, for example
`denied at hop 2: fw01 / vsys1, rule block-servers (deny)`. The `summary` of
`search`, `lookup` and `snapshot diff` has the counts, with the count line as its
`answer`.

`--limit N` keeps the first N results, and `summary.omitted` counts the results
that it left out. For `snapshot diff`, N counts single changes: `results` holds
the scopes up to the scope where the limit falls.

### Detail

The questions take `--detail full` (the default) or `--detail summary`.

| Detail | Each result keeps |
| --- | --- |
| `full` | everything: candidates, stage tables, each hop's interfaces and lookups |
| `summary` | the answer, the verdict, the fidelity, the reasons and the needs; of a path, each hop's device, vsys, snapshot, zones, route and policy verdict |

Holes, unresolved entries and notes stay in both.

### Needs

A simulate result that is undecided, or whose fidelity is `undermatch`, has a
`needs` list. It names the inputs that can change the answer when you give them
in a second question.

| Code | Input |
| --- | --- |
| `input.port` | `--port` |
| `input.protocol` | `--protocol` |
| `input.url` | `--url` |
| `input.application` | `--application`, when the device has App-ID data |
| `input.from-zone`, `input.to-zone` | `--from-zone`, `--to-zone`, for `--file` with derived zones |

Each entry has the `code`, the `input` name, and a `text` that names the rules
the input decides.

- The list stops at the first rule in doubt that no input can settle, such as a
  rule that names only a user. Past that rule, no input changes the verdict.
- A rule in doubt for a port and for a user still lists the port, because the
  port can rule it out.
- An empty list means that no input can help.
- A decided result has a `needs` key only when its fidelity is `undermatch`.
- `simulate nat` without a protocol lists `input.protocol` beside `input.port`.
  With a port and no protocol, it lists `input.protocol` for each NAT rule whose
  service holds that port.

## Reason codes

Every hole, unresolved entry and note is an object with a `code` and a `text`,
beside `device` and `vsys`. Lists of reasons, such as `fidelity.reasons`, hold
`{"code", "text"}` objects too. Match the `code` in a script. The `text` is for
people and can change.

```json
"unresolved": [
  {
    "device": "file",
    "vsys": "vsys1",
    "code": "doubt.not-evaluated.user",
    "text": "dmz-user (deny) at position 7 may match first: user not evaluated (corp\\alice)"
  }
]
```

A code reads `<class>.<name>`. The class is one of `doubt`, `gap`, `path`, `zone`,
`default`, `dns`, `input`, `note`, `call` and `verdict`. Every code comes from the
closed registry in `internal/reason/registry.go`, where each entry has a one-line
description.

A reason built from several parts lists each part with its own code. The text
output can join consecutive unresolved entries of one composite on one line, and
JSON lists them separately.

## JSON schemas

`schemas/out/` holds the JSON schema of each envelope, one file per command and
detail: `simulate-policy.full.json`, `search.summary.json` and so on.
`simulate-policy-file.*` is `simulate policy --file`. Every JSON example in the
tests validates against these schemas.

## Errors in JSON and YAML mode

On a non-zero exit, the last line of stderr is one JSON object:

```json
{"format":2,"exit":3,"log":"/home/u/.local/state/proteus/log/search-….log"}
{"format":2,"exit":2,"error":"unknown flag: --bogus"}
```

| Key | Present |
| --- | --- |
| `error` | on every exit except 3; on exit 3 the answer on stdout says what is missing |
| `log` | when a run log opened |

Earlier stderr lines, such as the `--verbose` echo, can come before this line.

## Run logs

Every command writes one log file in the log directory. A command that fails or
exits with code 3 prints the path of its log. `--log-level debug` records every
API call and, for a simulation, what each stage kept. Proteus redacts passwords
and API keys from every log.
