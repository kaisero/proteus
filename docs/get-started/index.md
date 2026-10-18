# Install

Proteus is a single Go binary with no runtime dependency. Download a release or
build it from source, then [ask a config file](config-file.md) to see your first
answer.

## Requirements

| Requirement | For |
| --- | --- |
| Go, at the version in `go.mod` | building Proteus from source; the code is pure Go and needs no C compiler |
| network access to the firewall management interface | [connecting your firewalls](firewalls.md) |
| an account that can use the XML API | [connecting your firewalls](firewalls.md) |

## Download a release

Each [release](https://github.com/kaisero/proteus/releases/latest) holds an
archive per platform and a `SHA256SUMS` file:

| Platform | Archive |
| --- | --- |
| Linux | `proteus_<version>_linux_amd64.tar.gz`, `proteus_<version>_linux_arm64.tar.gz` |
| macOS | `proteus_<version>_darwin_amd64.tar.gz`, `proteus_<version>_darwin_arm64.tar.gz` |
| Windows | `proteus_<version>_windows_amd64.zip`, `proteus_<version>_windows_arm64.zip` |

Check the archive, unpack it and put `proteus` on your `PATH`:

```bash
shasum -a 256 --ignore-missing -c SHA256SUMS
tar -xzf proteus_<version>_darwin_arm64.tar.gz
sudo mv proteus_<version>_darwin_arm64/proteus /usr/local/bin/
proteus --version
```

The binary is not signed. When macOS refuses to open a binary that a browser
downloaded, remove the quarantine flag with
`xattr -d com.apple.quarantine /usr/local/bin/proteus`.

The GitHub CLI also checks where an archive was built:
`gh attestation verify <archive> -R kaisero/proteus`.

## Build from source

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
