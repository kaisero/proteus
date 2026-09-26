// Package schema reads and queries a PAN-OS configuration schema.
//
// PAN-OS ships its schema on the appliance at /opt/pancfg/mgmt/factory:
// schema.xml describes a firewall configuration and cms-schema.xml describes a
// Panorama configuration. Neither is published, and the device API does not
// serve them.
//
// The schema answers questions that need no config file: what may this field
// reference, how long may this object's name be, what does this field mean, and
// which values does it accept.
//
// The design of this package is not settled. See ARCHITECTURE.md.
package schema
