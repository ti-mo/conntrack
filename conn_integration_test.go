//+build integration

package conntrack

import (
	"net"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
)

// makeNSConn creates a Conn in a new network namespace to use for testing.
func makeNSConn() (*Conn, error) {

	newns, err := netns.New()
	if err != nil {
		return nil, err
	}
	defer newns.Close()

	newConn, err := Dial(&netlink.Config{NetNS: int(newns)})
	if err != nil {
		return nil, err
	}

	return newConn, nil
}

// Create a given number of flows with a randomized component and check the amount
// of flows present in the table. Clean up by flushing the table.
func TestConnCreateFlows(t *testing.T) {

	c, err := makeNSConn()
	if err != nil {
		t.Fatalf("unexpected error creating namespaced connection: %s", err)
	}

	numFlows := 1337

	var f Flow

	for i := 1; i <= numFlows; i++ {
		f.Build(6, 0, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234, uint16(i), 120)

		err = c.Create(f)
		if err != nil {
			t.Fatalf("unexpected error creating flow %d: %s", i, err)
		}
	}

	flows, err := c.Dump()
	if err != nil {
		t.Fatalf("unexpected error dumping table: %s", err)
	}
	if want, got := numFlows, len(flows); want != got {
		t.Fatalf("unexpected amount of flows in table:\n- want: %d\n-  got: %d", want, got)
	}

	err = c.Flush()
	if err != nil {
		t.Fatalf("error flushing table: %s", err)
	}
}
