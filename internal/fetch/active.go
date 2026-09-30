package fetch

import (
	"context"

	"github.com/okaiser/proteus/internal/resolve"
)

// ActiveOptions tune the ha step.
type ActiveOptions struct {
	// PeerHost turns the peer's management address, as the HA state reports it,
	// into the host to connect to. Nil uses the address as it is. Tests map it to a
	// second fake device.
	PeerHost func(mgmtIP string) string
}

// haState reads a device's HA state; false when it cannot be read.
func haState(ctx context.Context, c *Client) (resolve.HAState, bool) {
	b, err := c.Op(ctx, haStateCmd)
	if err != nil {
		return resolve.HAState{}, false
	}
	st, err := resolve.ReadHAState(b)
	return st, err == nil
}
