package config

import "embed"

// digestFS carries the committed digests, so a consumer of this library needs
// nothing on disk. Each is roughly 200 to 400 KB.
//
// This directory is the only copy. panos-schemagen writes new digests here and
// generates the model from them, so the embedded set cannot drift from it.
//
//go:embed schemadigest
var digestFS embed.FS
