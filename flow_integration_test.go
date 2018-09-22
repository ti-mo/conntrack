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
	require.NoError(t, err)

	defer func() {
		err = c.Flush()
		assert.NoError(t, err, "error flushing table")
	}()

	numFlows := 1337

	var f Flow

	// Create IPv4 flows
	for i := 1; i <= numFlows; i++ {
		f = NewFlow(6, 0, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234, uint16(i), 120, 0)

		err = c.Create(f)
		require.NoError(t, err, "unexpected error creating IPv4 flow", i)
	}

	// Create IPv6 flows
	for i := 1; i <= numFlows; i++ {
		f = NewFlow(
			17, 0,
			net.ParseIP("2a00:1450:400e:804::200e"),
			net.ParseIP("2a00:1450:400e:804::200f"),
			1234, uint16(i), 120, 0,
		)

		err = c.Create(f)
		require.NoError(t, err, "unexpected error creating IPv6 flow", i)
	}

	flows, err := c.Dump()
	require.NoError(t, err, "unexpected error dumping table")

	// Expect twice the amount of numFlows, both for IPv4 and IPv6
	assert.Equal(t, numFlows*2, len(flows))
}

// Creates and deletes a number of flows with a randomized component.
// Expects table to be empty at the end of the run.
func TestConnCreateDeleteFlows(t *testing.T) {

	c, err := makeNSConn()
	require.NoError(t, err)

	numFlows := 42

	var f Flow

	for i := 1; i <= numFlows; i++ {
		f = NewFlow(
			17, 0,
			net.ParseIP("2a00:1450:400e:804::223e"),
			net.ParseIP("2a00:1450:400e:804::223f"),
			1234, uint16(i), 120, 0,
		)

		err = c.Create(f)
		require.NoError(t, err, "unexpected error creating flow", i)

		err = c.Delete(f)
		require.NoError(t, err, "unexpected error deleting flow", i)
	}

	flows, err := c.Dump()
	require.NoError(t, err, "unexpected error dumping table")

	assert.Equal(t, 0, len(flows))
}

// Creates a flow, updates it and checks the result.
func TestConnCreateUpdateFlow(t *testing.T) {

	c, err := makeNSConn()
	require.NoError(t, err)

	f := NewFlow(
		17, 0,
		net.ParseIP("1.2.3.4"),
		net.ParseIP("5.6.7.8"),
		1234, 5678, 120, 0,
	)

	err = c.Create(f)
	if err != nil {
		t.Fatalf("unexpected error creating flow: %s", err)
	}

	// Increase the flow's timeout from 120 in NewFlow().
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
	require.NoError(t, err)

	flows := map[string]Flow{
		"v4m1": NewFlow(17, 0, net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8"), 1234, 5678, 120, 0),
		"v4m2": NewFlow(17, 0, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 24000, 80, 120, 0),
		"v6m1": NewFlow(17, 0, net.ParseIP("2a12:1234:200f:600::200a"), net.ParseIP("2a12:1234:200f:600::200b"), 6554, 53, 120, 0),
		"v6m2": NewFlow(17, 0, net.ParseIP("900d:f00d:24::7"), net.ParseIP("baad:beef:b00::b00"), 1323, 22, 120, 0),
	}

	for n, f := range flows {
		err = c.Create(f)
		require.NoError(t, err, "unexpected error creating flow", n)

		qflow, err := c.Get(f)
		require.NoError(t, err, "unexpected error getting flow", n)

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

	f := NewFlow(6, 0, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234, 80, 120, 0)

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
