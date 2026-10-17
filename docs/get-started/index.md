# Install

proteus is a single Go binary with no runtime dependency. Build it from source,
then [ask a config file](config-file.md) to see your first answer.

## Requirements

| Requirement | For |
| --- | --- |
| Go, at the version in `go.mod` | building proteus; the code is pure Go and needs no C compiler |
| network access to the firewall management interface | [connecting your firewalls](firewalls.md) |
| an account that can use the XML API | [connecting your firewalls](firewalls.md) |

## Build

```bash
git clone https://github.com/kaisero/proteus.git && cd proteus
make build-local                 # writes bin/proteus
export PATH="$PWD/bin:$PATH"
proteus --version
```

To install into `$(go env GOPATH)/bin` instead, run:

```bash
go install ./cmd/proteus
```

## Shell completion

Load the completion script for your shell, for example:

```bash
proteus completion zsh > "${fpath[1]}/_proteus"
```

[Global flags](../reference/global-flags.md#shell-completion) lists the other
shells.
