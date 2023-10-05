//go:build integration

package conntrack

import (
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/ti-mo/netfilter"
)

func TestConnListen(t *testing.T) {
	// Dial a send connection to Netlink in a new namespace.
	sc, nsid, err := makeNSConn()
	require.NoError(t, err)

	// Create a listener connection in the same namespace.
	lc, err := Dial(&netlink.Config{NetNS: nsid})
	require.NoError(t, err)

	// Subscribe to new/update conntrack events using a single worker.
	ev := make(chan Event)
	errChan, err := lc.Listen(ev, 1, []netfilter.NetlinkGroup{
		netfilter.GroupCTNew,
		netfilter.GroupCTUpdate,
		netfilter.GroupCTDestroy,
	})
	require.NoError(t, err)

	go func() {
		err, ok := <-errChan
		if !ok {
			return
		}
		require.NoError(t, err)
	}()
	defer close(errChan)

	var warn bool

	ip := netip.MustParseAddr("::f00")
	for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_DCCP, unix.IPPROTO_SCTP} {
		// Create the Flow.
		f := NewFlow(
			proto, 0,
			ip, ip, 123, 123,
			120, 0,
		)
		require.NoError(t, sc.Create(f))

		// Read a new event from the channel.
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
		assert.Equal(t, ip, re.Flow.TupleOrig.IP.SourceAddress)

		// Update the Flow.
		f.Timeout = 240
		require.NoError(t, sc.Update(f))

		// Read an update event from the channel.
		re = <-ev

		// Validate update event attributes.
		assert.Equal(t, EventUpdate, re.Type)
		assert.Equal(t, ip, re.Flow.TupleOrig.IP.SourceAddress)

		// Compare the timeout on the connection, but within a 2-second window.
		assert.GreaterOrEqual(t, re.Flow.Timeout, f.Timeout-2, "timeout")

		// Delete the Flow.
		require.NoError(t, sc.Delete(f))

		// Read destroy event from the channel.
		re = <-ev
		assert.Equal(t, EventDestroy, re.Type)
		assert.Equal(t, ip, re.Flow.TupleOrig.IP.SourceAddress)
	}

	// Close the sockets, interrupting any blocked listeners.
	assert.NoError(t, lc.Close())
	assert.NoError(t, sc.Close())
}

func TestConnListenError(t *testing.T) {
	c, _, err := makeNSConn()
	require.NoError(t, err)

	// Too few listen workers
	_, err = c.Listen(make(chan Event), 0, nil)
	require.ErrorIs(t, err, errNoWorkers)

	// Successfully join a multicast group
	_, err = c.Listen(make(chan Event), 1, netfilter.GroupsCT)
	require.NoError(t, err)

	// Fail when joining another multicast group
	_, err = c.Listen(make(chan Event), 1, netfilter.GroupsCT)
	require.ErrorIs(t, err, errConnHasListeners)
}
