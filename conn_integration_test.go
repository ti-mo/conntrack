//+build integration

package conntrack

import (
	"log"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
)

var c *Conn

func TestMain(m *testing.M) {

	runtime.LockOSThread()

	// Create network namespace for this test suite.
	newns, err := netns.New()
	if err != nil {
		log.Fatalf("error creating network namespace: %s", err)
	}
	defer newns.Close()

	newConn, err := Dial(&netlink.Config{NetNS: int(newns)})
	if err != nil {
		log.Fatalf("error creating netlink connection: %s", err)
	}

	// Assign Conn to package.
	c = newConn

	// Run test suite and exit.
	ret := m.Run()
	os.Exit(ret)
}

func TestConnCreate(t *testing.T) {

	numFlows := 1337

	var f Flow

	for i := 1; i <= numFlows; i++ {
		f.Build(6, 0, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234, uint16(i), 120)

		err := c.Create(f)
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
}
