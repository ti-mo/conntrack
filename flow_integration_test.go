//+build integration

package conntrack

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

// Creates a flow, updates it and checks the result.
func TestConnCreateUpdateFlow(t *testing.T) {

	c, err := makeNSConn()
	if err != nil {
		t.Fatal(err)
	}
	var f Flow

	f.Build(
		17, 0,
		net.ParseIP("1.2.3.4"),
		net.ParseIP("5.6.7.8"),
		1234, 5678, 120,
	)

	err = c.Create(f)
	if err != nil {
		t.Fatalf("unexpected error creating flow: %s", err)
	}

	// Increase the flow's timeout from 120 in Build().
	f.Timeout = 240

	err = c.Update(f)
	if err != nil {
		t.Fatalf("unexpected error updating flow: %s", err)
	}

	flows, err := c.Dump()
	if err != nil {
		t.Fatalf("unexpected error dumping table: %s", err)
	}

	if got := flows[0].Timeout; !(got > 120) {
		t.Fatalf("unexpected updated flow:\n- want: > 120\n-  got: %d", got)
	}
}

// Creates IPv4 and IPv6 flows and queries them using a simple get.
func TestConnCreateGetFlow(t *testing.T) {

	c, err := makeNSConn()
	if err != nil {
		t.Fatal(err)
	}

	var v4m1, v4m2, v6m1, v6m2 Flow
	v4m1.Build(17, 0, net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8"), 1234, 5678, 120)
	v4m2.Build(17, 0, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 24000, 80, 120)
	v6m1.Build(17, 0, net.ParseIP("2a12:1234:200f:600::200a"), net.ParseIP("2a12:1234:200f:600::200b"), 6554, 53, 120)
	v6m2.Build(17, 0, net.ParseIP("900d:f00d:24::7"), net.ParseIP("baad:beef:b00::b00"), 1323, 22, 120)

	flows := map[string]Flow{"v4m1": v4m1, "v4m2": v4m2, "v6m1": v6m1, "v6m2": v6m2}

	for n, f := range flows {
		err = c.Create(f)
		if err != nil {
			t.Fatalf("unexpected error creating flow %s: %s", n, err)
		}

		qflow, err := c.Get(f)
		if err != nil {
			t.Fatalf("unexpected error getting flow %s: %s", n, err)
		}

		assert.Equal(t, qflow.TupleOrig.IP.SourceAddress, f.TupleOrig.IP.SourceAddress)
		assert.Equal(t, qflow.TupleOrig.IP.DestinationAddress, f.TupleOrig.IP.DestinationAddress)
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
