// Package simulate is the simulation framework of spec §11: a simulation is a run
// of named stages over one flow and one device, and every stage declares how
// certain its output is. It is a leaf: it imports the read-only core and the run
// log, and no simulation implementation. simulate/securitypolicy is the first
// implementation; estate holds the registry that names them.
package simulate
