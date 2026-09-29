package config

import "embed"

// digestFS carries the committed digests, so proteus needs nothing on disk. Each
// is roughly 200 to 400 KB.
//
// This directory is the only copy. The schemadigest tool writes new digests here,
// so there is no second set to keep in step.
//
//go:embed schemadigest
var digestFS embed.FS
