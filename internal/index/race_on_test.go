//go:build race

package index

// raceEnabled reports a build with the race detector, whose instrumentation
// allocates on its own: an allocation count then varies from run to run.
const raceEnabled = true
