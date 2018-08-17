package conntrack

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// Conn represents a Netlink connection to the Netfilter
// subsystem and implements all Conntrack actions.
type Conn struct {
	conn *netfilter.Conn
}

// Open opens a new Netfilter Netlink connection and returns it
// wrapped in a Conn structure that implements the Conntrack API.
func Open() (*Conn, error) {
	c, err := netfilter.Open()
	if err != nil {
		return nil, err
	}

	return &Conn{c}, nil
}

// Close closes a Conn.
func (c *Conn) Close() error {

	// Call through to the Netfilter Close().
	return c.conn.Close()
}

// Dump gets all Conntrack connections from the kernel in the form of a list
// of Flow objects.
func (c *Conn) Dump() ([]Flow, error) {

	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump,
		},
	}

	netfilter.HeaderType{
		SubsystemID: netfilter.NFSubsysCTNetlink,
		MessageType: netfilter.MessageType(CTGet),
	}.ToNetlinkHeader(&req.Header)

	netfilter.Header{
		Family: netfilter.ProtoUnspec, // Dumps both IPv4 and IPv6
	}.ToNetlinkMessage(&req)

	nlm, err := c.conn.Query(req)
	if err != nil {
		return nil, err
	}

	return FlowsFromNetlink(nlm)
}
