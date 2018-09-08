package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
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
	return c.conn.Close()
}

// Listen joins the Netfilter connection to a multicast group and starts a given
// amount of Flow decoders from the Conn to the Flow channel. Returns an error channel
// the workers will return any errors on. Any errors during Flow decoding are fatal.
//
// The Conn will be marked as having listeners active, which will prevent Listen from being
// called again. For listening on other groups, open another socket.
func (c *Conn) Listen(evChan chan<- Event, numWorkers uint8, groups []netfilter.NetlinkGroup) (chan error, error) {

	if numWorkers < 1 {
		return nil, errors.Errorf(errWorkerCount, numWorkers)
	}

	// Prevent Listen() from being called twice on the same Conn.
	if c.conn.IsMulticast() {
		return nil, errConnHasListeners
	}

	err := c.conn.JoinGroups(groups)
	if err != nil {
		return nil, err
	}

	errChan := make(chan error)

	// Start numWorkers amount of worker goroutines
	for id := uint8(0); id < numWorkers; id++ {
		go c.eventWorker(id, evChan, errChan)
	}

	return errChan, nil
}

// eventWorker is a worker function that decodes Netlink messages into Events.
func (c *Conn) eventWorker(workerID uint8, evChan chan<- Event, errChan chan<- error) {

	var err error
	var recv []netlink.Message
	var ev Event

	for {
		// Receive data from the Netlink socket
		recv, err = c.conn.Receive()
		if err != nil {
			errChan <- errors.Wrap(err, fmt.Sprintf(errWorkerReceive, workerID))
			return
		}

		// Receive() always returns a list of Netlink Messages, but multicast messages should never be multi-part
		if len(recv) > 1 {
			errChan <- errMultipartEvent
			return
		}

		// Decode event and send on channel
		ev = *new(Event)
		err := ev.FromNetlinkMessage(recv[0])
		if err != nil {
			errChan <- err
			return
		}

		evChan <- ev
	}
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

// Flush empties the Conntrack table.
func (c *Conn) Flush() error {

	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
		},
	}

	netfilter.HeaderType{
		SubsystemID: netfilter.NFSubsysCTNetlink,
		MessageType: netfilter.MessageType(CTDelete),
	}.ToNetlinkHeader(&req.Header)

	netfilter.Header{
		Family: netfilter.ProtoInet,
	}.ToNetlinkMessage(&req)

	_, err := c.conn.Query(req)
	if err != nil {
		return err
	}

	return nil
}

// Create creates a new Conntrack entry.
func (c *Conn) Create(f Flow) error {

	// Conntrack create requires timeout to be set.
	if !f.Timeout.Filled() {
		return errNeedTimeout
	}

	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge |
				netlink.HeaderFlagsExcl | netlink.HeaderFlagsCreate,
		},
	}

	netfilter.HeaderType{
		SubsystemID: netfilter.NFSubsysCTNetlink,
		MessageType: netfilter.MessageType(CTNew),
	}.ToNetlinkHeader(&req.Header)

	netfilter.Header{
		Family: netfilter.ProtoFamily(2), //TODO: Family constant
	}.ToNetlinkMessage(&req)

	attrs, err := f.MarshalAttributes()
	if err != nil {
		return err
	}

	err = netfilter.AttributesToNetlink(attrs, &req)
	if err != nil {
		return err
	}

	_, err = c.conn.Query(req)
	if err != nil {
		return err
	}

	return nil
}
