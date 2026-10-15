package config

import "embed"

// digestFS carries the committed digest, so proteus needs nothing on disk. It is
// roughly 200 to 400 KB.
//
// This directory is the only copy. The schemadigest tool writes the digest here,
// so there is no second copy to keep in step.
//
//go:embed schemadigest
var digestFS embed.FS
