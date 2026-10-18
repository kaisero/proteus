#!/usr/bin/env bash
# Build the release archives into dist/: one per platform, and SHA256SUMS.
#
# Each archive holds the static binary, the licence and the README. The version
# comes from the VERSION file, so a local run builds what the release publishes.
# The release workflow runs this script; make release-build runs it locally.
set -euo pipefail

version="$(tr -d '[:space:]' <VERSION)"
out="dist"
platforms="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

rm -rf "$out"
mkdir -p "$out"
for platform in $platforms; do
	os="${platform%/*}"
	arch="${platform#*/}"
	name="proteus_${version}_${os}_${arch}"
	binary="proteus"
	[ "$os" = windows ] && binary="proteus.exe"

	mkdir -p "$out/$name"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
		-ldflags "-s -w -X main.version=v$version" -o "$out/$name/$binary" ./cmd/proteus
	cp LICENSE README.md "$out/$name/"
	if [ "$os" = windows ]; then
		(cd "$out" && zip -qr "$name.zip" "$name")
	else
		tar -C "$out" -czf "$out/$name.tar.gz" "$name"
	fi
	rm -rf "${out:?}/$name"
done

# shasum is on macOS and on the Ubuntu runners; sha256sum is not on macOS.
(cd "$out" && shasum -a 256 -- *.tar.gz *.zip >SHA256SUMS)
