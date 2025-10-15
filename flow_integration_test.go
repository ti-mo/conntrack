//go:build integration

package conntrack

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Create a given number of flows with a randomized component and check the amount
// of flows present in the table. Clean up by flushing the table.
func TestConnCreateFlows(t *testing.T) {

	c, _, err := makeNSConn()
	require.NoError(t, err)

	defer func() {
		err = c.Flush()
		assert.NoError(t, err, "error flushing table")
	}()

	// Expect empty result from empty table dump
	de, err := c.Dump(nil)
	require.NoError(t, err, "dumping empty table")
	require.Len(t, de, 0, "expecting 0-length dump from empty table")

	numFlows := 1337

	var f Flow

	// Create IPv4 flows
	for i := 1; i <= numFlows; i++ {
		f = NewFlow(6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"), 1234, uint16(i), 120, 0)

		err = c.Create(f)
		require.NoError(t, err, "creating IPv4 flow", i)
	}

	// Create IPv6 flows
	for i := 1; i <= numFlows; i++ {
		err = c.Create(NewFlow(
			17, 0,
			netip.MustParseAddr("2a00:1450:400e:804::200e"),
			netip.MustParseAddr("2a00:1450:400e:804::200f"),
			1234, uint16(i), 120, 0,
		))
		require.NoError(t, err, "creating IPv6 flow", i)
	}

	flows, err := c.Dump(nil)
	require.NoError(t, err, "dumping table")

	// Expect twice the amount of numFlows, both for IPv4 and IPv6
	assert.Equal(t, numFlows*2, len(flows))
}

func TestConnCreateError(t *testing.T) {

	c, _, err := makeNSConn()
	require.NoError(t, err)

	err = c.Create(Flow{Timeout: 0})
	require.ErrorIs(t, err, errNeedTimeout)
}

func TestConnFlush(t *testing.T) {

	c, _, err := makeNSConn()
	require.NoError(t, err)

	// Expect empty result from empty table dump
	de, err := c.Dump(nil)
	require.NoError(t, err, "dumping empty table")
	require.Len(t, de, 0, "expecting 0-length dump from empty table")

	// Create IPv4 flow
	err = c.Create(NewFlow(
		6, 0,
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
		1234, 80, 120, 0,
	))
	require.NoError(t, err, "creating IPv4 flow")

	// Create IPv6 flow
	err = c.Create(NewFlow(
		17, 0,
		netip.MustParseAddr("2a00:1450:400e:804::200e"),
		netip.MustParseAddr("2a00:1450:400e:804::200f"),
		1234, 80, 120, 0,
	))
	require.NoError(t, err, "creating IPv6 flow")

	// Expect both flows to be in the table
	flows, err := c.Dump(nil)
	require.NoError(t, err, "dumping table before flush")
	assert.Equal(t, 2, len(flows))

	err = c.Flush()
	require.NoError(t, err, "flushing table")

	// Expect empty table
	flows, err = c.Dump(nil)
	require.NoError(t, err, "dumping table after flush")
	assert.Equal(t, 0, len(flows))
}

func TestConnFlushFilter(t *testing.T) {
	// Kernels 3.x and earlier don't have filtered flush implemented yet.
	// This is implemented in a separate function, ctnetlink_flush_conntrack,
	// so we check if it is present before executing and checking the result.
	if !findKsym("ctnetlink_flush_iterate") {
		t.Skip("FlushFilter not supported in this kernel")
	}

	c, _, err := makeNSConn()
	require.NoError(t, err)

	// Expect empty result from empty table dump
	de, err := c.Dump(nil)
	require.NoError(t, err, "dumping empty table")
	require.Len(t, de, 0, "expecting 0-length dump from empty table")

	// Create IPv4 flow
	err = c.Create(NewFlow(
		6, 0,
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
		1234, 80, 120, 0,
	))
	require.NoError(t, err, "creating IPv4 flow")

	// Create IPv6 flow with mark
	err = c.Create(NewFlow(
		17, 0,
		netip.MustParseAddr("2a00:1450:400e:804::200e"),
		netip.MustParseAddr("2a00:1450:400e:804::200f"),
		1234, 80, 120, 0xff00,
	))
	require.NoError(t, err, "creating IPv6 flow")

	// Expect both flows to be in the table
	flows, err := c.Dump(nil)
	require.NoError(t, err, "dumping table before filtered flush")
	assert.Equal(t, 2, len(flows))

	// Nil filter should not panic.
	require.Error(t, c.FlushFilter(nil))

	// Flush only the flow matching the filter
	err = c.FlushFilter(NewFilter().Mark(0xff00))
	require.NoError(t, err, "flushing table")

	// Expect only one flow to remain in the table
	flows, err = c.Dump(nil)
	require.NoError(t, err, "dumping table after filtered flush")
	assert.Equal(t, 1, len(flows))
}

// Creates and deletes a number of flows with a randomized component.
// Expects table to be empty at the end of the run.
func TestConnCreateDeleteFlows(t *testing.T) {

	c, _, err := makeNSConn()
	require.NoError(t, err)

	numFlows := 42

	var f Flow

	for i := 1; i <= numFlows; i++ {
		f = NewFlow(
			17, 0,
			netip.MustParseAddr("2a00:1450:400e:804::223e"),
			netip.MustParseAddr("2a00:1450:400e:804::223f"),
			1234, uint16(i), 120, 0,
		)

		err = c.Create(f)
		require.NoError(t, err, "creating flow", i)

		err = c.Delete(f)
		require.NoError(t, err, "deleting flow", i)
	}

	flows, err := c.Dump(nil)
	require.NoError(t, err, "dumping table")

	assert.Equal(t, 0, len(flows))
}

// Creates a flow, updates it and checks the result.
func TestConnCreateUpdateFlow(t *testing.T) {
	c, _, err := makeNSConn()
	require.NoError(t, err)

	f := NewFlow(
		17, 0,
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
		1234, 5678, 120, 0,
	)

	err = c.Create(f)
	require.NoError(t, err, "creating flow")

	// Increase the flow's timeout from 120 in NewFlow().
	f.Timeout = 210

	err = c.Update(f)
	require.NoError(t, err, "updating flow")

	flows, err := c.Dump(nil)
	require.NoError(t, err, "dumping table")

	if got := flows[0].Timeout; !(got > 200) {
		t.Fatalf("unexpected updated flow:\n- want: > 200\n-  got: %d", got)
	}

	// Update the flow using only the TupleReply.
	// The kernel allows an existing flow to be updated
	// using only the TupleReply.
	fNoOrig := f
	fNoOrig.TupleOrig = Tuple{}
	fNoOrig.Timeout = 310

	err = c.Update(fNoOrig)
	require.NoError(t, err, "updating flow without TupleOrig")

	flows, err = c.Dump(nil)
	require.NoError(t, err, "dumping table")

	if got := flows[0].Timeout; !(got > 300) {
		t.Fatalf("unexpected updated flow:\n- want: > 300\n-  got: %d", got)
	}

	// Update the flow using only the TupleOrig.
	// The kernel allows an existing flow to be updated
	// using only the TupleOrig.
	fNoReply := f
	fNoReply.TupleReply = Tuple{}
	fNoReply.Timeout = 410

	err = c.Update(fNoReply)
	require.NoError(t, err, "updating flow without TupleReply")

	flows, err = c.Dump(nil)
	require.NoError(t, err, "dumping table")

	if got := flows[0].Timeout; !(got > 400) {
		t.Fatalf("unexpected updated flow:\n- want: > 400\n-  got: %d", got)
	}
}

func TestConnUpdateError(t *testing.T) {

	c, _, err := makeNSConn()
	require.NoError(t, err)

	f := NewFlow(
		17, 0,
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
		1234, 5678, 120, 0,
	)

	f.TupleMaster = f.TupleOrig

	err = c.Update(f)
	require.ErrorIs(t, err, errUpdateMaster)
}

// Creates IPv4 and IPv6 flows and queries them using a simple get.
func TestConnCreateGetFlow(t *testing.T) {

	c, _, err := makeNSConn()
	require.NoError(t, err)

	flows := map[string]Flow{
		"v4m1": NewFlow(17, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"), 1234, 5678, 120, 0),
		"v4m2": NewFlow(17, 0, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 24000, 80, 120, 0),
		"v6m1": NewFlow(17, 0, netip.MustParseAddr("2a12:1234:200f:600::200a"), netip.MustParseAddr("2a12:1234:200f:600::200b"), 6554, 53, 120, 0),
		"v6m2": NewFlow(17, 0, netip.MustParseAddr("900d:f00d:24::7"), netip.MustParseAddr("baad:beef:b00::b00"), 1323, 22, 120, 0),
	}

	for n, f := range flows {
		_, err := c.Get(f)
		require.ErrorIs(t, err, unix.ENOENT, "get flow before creating")

		err = c.Create(f)
		require.NoError(t, err, "creating flow", n)

		qflow, err := c.Get(f)
		require.NoError(t, err, "get flow after creating", n)

		assert.Equal(t, qflow.TupleOrig.IP.SourceAddress, f.TupleOrig.IP.SourceAddress)
		assert.Equal(t, qflow.TupleOrig.IP.DestinationAddress, f.TupleOrig.IP.DestinationAddress)

		fOrig := f
		fOrig.TupleReply = Tuple{}
		qflow, err = c.Get(fOrig)
		require.NoError(t, err, "get flow by TupleOrig", n)

		assert.Equal(t, qflow.TupleReply.IP.SourceAddress, f.TupleReply.IP.SourceAddress)
		assert.Equal(t, qflow.TupleReply.IP.DestinationAddress, f.TupleReply.IP.DestinationAddress)

		fReply := f
		fReply.TupleOrig = Tuple{}
		qflow, err = c.Get(fReply)
		require.NoError(t, err, "get flow by TupleReply", n)

		assert.Equal(t, qflow.TupleOrig.IP.SourceAddress, f.TupleOrig.IP.SourceAddress)
		assert.Equal(t, qflow.TupleOrig.IP.DestinationAddress, f.TupleOrig.IP.DestinationAddress)
	}
}

// Creates IPv4 and IPv6 flows and dumps them while zeroing the accounting counters.
func TestDumpZero(t *testing.T) {
	c, _, err := makeNSConn()
	require.NoError(t, err)

	f := NewFlow(17, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"), 1234, 5678, 120, 0xff000000)

	f.CountersOrig.Bytes = 1337
	f.CountersReply.Bytes = 9001
	require.NoError(t, c.Create(f), "creating flow")

	df, err := c.Dump(&DumpOptions{
		ZeroCounters: true,
	})
	require.NoError(t, err, "dumping flows (zeroing enabled)")

	assert.Equal(t, df[0].CountersOrig.Bytes, uint64(0))
	assert.Equal(t, df[0].CountersReply.Bytes, uint64(0))
}

// Creates IPv4 and IPv6 flows with connmarks and queries them using a filtered dump.
func TestConnDumpFilter(t *testing.T) {
	if !findKsym("ctnetlink_alloc_filter") {
		t.Skip("DumpFilter not supported in this kernel")
	}

	c, _, err := makeNSConn()
	require.NoError(t, err)

	flows := map[string]Flow{
		"v4m1": NewFlow(17, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"), 1234, 5678, 120, 0xff000000),
		"v4m2": NewFlow(17, 0, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 24000, 80, 120, 0xff00ff00),
		"v6m1": NewFlow(17, 0, netip.MustParseAddr("2a12:1234:200f:600::200a"), netip.MustParseAddr("2a12:1234:200f:600::200b"), 6554, 53, 120, 0x0000ff00),
		"v6m2": NewFlow(17, 0, netip.MustParseAddr("900d:f00d:24::7"), netip.MustParseAddr("baad:beef:b00::b00"), 1323, 22, 120, 0x000000ff),
	}

	// Nil filter should not panic.
	_, err = c.DumpFilter(nil, nil)
	require.Error(t, err)

	// Expect empty result from empty table dump with empty filter.
	de, err := c.DumpFilter(NewFilter(), nil)
	require.NoError(t, err, "dumping empty table")
	require.Len(t, de, 0, "expecting 0-length dump from empty table")

	for n, f := range flows {
		err = c.Create(f)
		require.NoError(t, err, "creating flow", n)

		df, err := c.DumpFilter(NewFilter().Mark(f.Mark), nil)
		require.NoError(t, err, "dumping filtered flows", n)

		assert.Len(t, df, 1)
		assert.Equal(t, df[0].TupleOrig.IP.SourceAddress, f.TupleOrig.IP.SourceAddress)
		assert.Equal(t, df[0].TupleOrig.IP.DestinationAddress, f.TupleOrig.IP.DestinationAddress)
	}

	// Expect two flows to match the filter (0xff000000 and 0xff00ff00) since the
	// rightmost 16 bits are masked off.
	df, err := c.DumpFilter(NewFilter().Mark(0xff000000).MarkMask(0xffff0000), nil)
	require.NoError(t, err)
	assert.Len(t, df, 2, "expecting 2 flows to match filter")

	// Expect table to be empty at end of run
	d, err := c.Dump(nil)
	require.NoError(t, err, "dumping flows")
	assert.Len(t, d, len(flows))
}

// Bench scenario that calls Conn.Create and Conn.Delete on the same Flow once per iteration.
// This includes two marshaling operations for create/delete, two syscalls and output validation.
func BenchmarkCreateDeleteFlow(b *testing.B) {

	b.ReportAllocs()

	c, _, err := makeNSConn()
	if err != nil {
		b.Fatal(err)
	}

	f := NewFlow(6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"), 1234, 80, 120, 0)

	for n := 0; n < b.N; n++ {
		err = c.Create(f)
		if err != nil {
			b.Fatalf("creating flow %d: %s", n, err)
		}
		err = c.Delete(f)
		if err != nil {
			b.Fatalf("deleting flow %d: %s", n, err)
		}
	}
}
