package config

import "embed"

// digestFS carries the committed digests, so a consumer of this library needs
// nothing on disk. Each is roughly 200 to 400 KB.
//
// The files are copied in from the repository's schemadigest directory by the
// Makefile, because a go:embed directive cannot reach outside its own package.
//
//go:embed schemadigest
var digestFS embed.FS
