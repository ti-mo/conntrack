//+build integration

package conntrack

import (
	"net"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
)

func TestConnListen(t *testing.T) {

	// Dial a send connection to Netlink in a new namespace
	sc, nsid, err := makeNSConn()
	require.NoError(t, err)

	// Create a listener connection in the same namespace
	lc, err := Dial(&netlink.Config{NetNS: nsid})
	require.NoError(t, err)

	// This needs to be an unbuffered channel with a single producer worker. Multicast connections
	// currently cannot be terminated gracefully when stuck in Receive(), so we have to inject an event
	// ourselves, while making sure the worker exits before re-entering Receive().
	ev := make(chan Event)
	errChan, err := lc.Listen(ev, 1, []netfilter.NetlinkGroup{netfilter.GroupCTNew, netfilter.GroupCTUpdate})
	require.NoError(t, err)

	// Watch for listen channel errors in the background
	go func() {
		err, ok := <-errChan
		if ok {
			opErr := errors.Cause(err)
			require.IsType(t, &netlink.OpError{}, opErr)
			require.Equal(t, opErr.(*netlink.OpError).Err, os.NewSyscallError("recvmsg", unix.EBADF))
		}
	}()

	numFlows := 100

	var f Flow
	var warn bool

	for i := 1; i <= numFlows; i++ {

		// Create the Flow
		f = NewFlow(
			17, 0,
			net.ParseIP("2a00:1450:400e:804::200e"),
			net.ParseIP("2a00:1450:400e:804::200f"),
			1234, uint16(i), 120, 0,
		)
		err = sc.Create(f)
		require.NoError(t, err, "creating IPv6 flow", i)

		// Read a new event from the channel
		re := <-ev

		// Validate new event attributes
		// Kernels 4.10 and earlier have a bug in ctnetlink_new_conntrack() that incorrectly sets
		// the event type to 'update' when creating a new conntrack.
		if re.Type == EventUpdate {
			if !warn {
				t.Log("Received an Update event upon creating a Flow, this is a known bug in kernels <=4.10")
				warn = true // Disable futher warnings
			}
		} else {
			assert.Equal(t, EventNew, re.Type)
		}
		assert.Equal(t, f.TupleOrig.Proto.DestinationPort, re.Flow.TupleOrig.Proto.DestinationPort)

		// Update the flow
		f.Timeout = 240
		err = sc.Update(f)
		require.NoError(t, err)

		// Read an update event from the channel
		re = <-ev

		// Validate update event attributes
		assert.Equal(t, EventUpdate, re.Type)
		assert.Equal(t, f.TupleOrig.Proto.DestinationPort, re.Flow.TupleOrig.Proto.DestinationPort)
		assert.Equal(t, f.Timeout, re.Flow.Timeout, "timeout")
	}

	// Generate an event to unblock the listen worker goroutine
	go func() {
		f.Timeout = 1
		sc.Update(f)
	}()

	// Close the sockets
	assert.NoError(t, lc.Close())
	assert.NoError(t, sc.Close())
}

func TestConnListenError(t *testing.T) {
	c, _, err := makeNSConn()
	require.NoError(t, err)

	// Too few listen workers
	_, err = c.Listen(make(chan Event), 0, nil)
	require.EqualError(t, err, "invalid worker count 0")

	_, err = c.Listen(make(chan Event), 1, nil)
	require.EqualError(t, err, "need one or more multicast groups to join")

	// Successfully join a multicast group
	_, err = c.Listen(make(chan Event), 1, netfilter.GroupsCT)
	require.NoError(t, err)

	// Fail when joining another multicast group
	_, err = c.Listen(make(chan Event), 1, netfilter.GroupsCT)
	require.EqualError(t, err, "Conn has existing listeners, open another to listen on more groups")
}
