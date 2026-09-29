// Package routing is the routing simulation: which firewalls a packet crosses,
// and by which interfaces, zones and routes. It reads each device's interface
// state and forwarding table through simulate.Network and, for devices on the
// path, the configuration through simulate.Env.Load. Spec §17.
package routing
