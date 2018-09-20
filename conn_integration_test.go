//+build integration

package conntrack

import (
	"fmt"
	"log"
	"net"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
)

func TestMain(m *testing.M) {

	if err := checkKmod(); err != nil {
		log.Fatal(err)
	}

	rc := m.Run()
	os.Exit(rc)
}

// checkKmod checks if the kernel modules required for this test suite are loaded into the kernel.
func checkKmod() error {

	kmods := []string{
		"nf_conntrack_ipv4",
		"nf_conntrack_ipv6",
	}

	for _, km := range kmods {
		if _, err := os.Stat(fmt.Sprintf("/sys/module/%s", km)); os.IsNotExist(err) {
			return fmt.Errorf("required kernel module not loaded: %s", km)
		}
	}

	return nil
}

// makeNSConn creates a Conn in a new network namespace to use for testing.
func makeNSConn() (*Conn, error) {

	newns, err := netns.New()
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating network namespace: %s", err)
	}
	defer newns.Close()

	newConn, err := Dial(&netlink.Config{NetNS: int(newns)})
	if err != nil {
		return nil, fmt.Errorf("unexpected error dialing namespaced connection: %s", err)
	}

	return newConn, nil
}

// Create a given number of flows with a randomized component and check the amount
// of flows present in the table. Clean up by flushing the table.
func TestConnCreateFlows(t *testing.T) {

	c, err := makeNSConn()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = c.Flush()
		if err != nil {
			t.Fatalf("error flushing table: %s", err)
		}
	}()

	numFlows := 1337

	var f Flow

	// Create IPv4 flows
	for i := 1; i <= numFlows; i++ {
		f.Build(6, 0, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234, uint16(i), 120)

		err = c.Create(f)
		if err != nil {
			t.Fatalf("unexpected error creating IPv4 flow %d: %s", i, err)
		}
	}

	// Create IPv6 flows
	for i := 1; i <= numFlows; i++ {
		f.Build(
			17, 0,
			net.ParseIP("2a00:1450:400e:804::200e"),
			net.ParseIP("2a00:1450:400e:804::200f"),
			1234, uint16(i), 120,
		)

		err = c.Create(f)
		if err != nil {
			t.Fatalf("unexpected error creating IPv6 flow %d: %s", i, err)
		}
	}

	flows, err := c.Dump()
	if err != nil {
		t.Fatalf("unexpected error dumping table: %s", err)
	}

	// Expect twice the amount of numFlows, both for IPv4 and IPv6
	if want, got := numFlows*2, len(flows); want != got {
		t.Fatalf("unexpected amount of flows in table:\n- want: %d\n-  got: %d", want, got)
	}
}

// Creates and deletes a number of flows with a randomized component.
// Expects table to be empty at the end of the run.
func TestConnCreateDeleteFlows(t *testing.T) {

	c, err := makeNSConn()
	if err != nil {
		t.Fatal(err)
	}

	numFlows := 42

	var f Flow

	for i := 1; i <= numFlows; i++ {
		f.Build(
			17, 0,
			net.ParseIP("2a00:1450:400e:804::223e"),
			net.ParseIP("2a00:1450:400e:804::223f"),
			1234, uint16(i), 120,
		)

		err = c.Create(f)
		if err != nil {
			t.Fatalf("unexpected error creating flow %d: %s", i, err)
		}
		err = c.Delete(f)
		if err != nil {
			t.Fatalf("unexpected error deleting flow %d: %s", i, err)
		}
	}

	flows, err := c.Dump()
	if err != nil {
		t.Fatalf("unexpected error dumping table: %s", err)
	}

	if want, got := 0, len(flows); want != got {
		t.Fatalf("unexpected amount of flows in table:\n- want: %d\n-  got: %d", want, got)
	}
}

// Bench scenario that calls Conn.Create and Conn.Delete on the same Flow once per iteration.
// This includes two marshaling operations for create/delete, two syscalls and output validation.
func BenchmarkCreateDeleteFlow(b *testing.B) {

	b.ReportAllocs()

	c, err := makeNSConn()
	if err != nil {
		b.Fatal(err)
	}

	var f Flow
	f.Build(6, 0, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234, 80, 120)

	for n := 0; n < b.N; n++ {
		err = c.Create(f)
		if err != nil {
			b.Fatalf("unexpected error creating flow %d: %s", n, err)
		}
		err = c.Delete(f)
		if err != nil {
			b.Fatalf("unexpected error deleting flow %d: %s", n, err)
		}
	}
}
