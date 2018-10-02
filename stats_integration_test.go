//+build integration

package conntrack

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnStats(t *testing.T) {

	c, err := makeNSConn()
	require.NoError(t, err)

	stats, err := c.Stats()
	require.NoError(t, err)

	for i, s := range stats {
		// Make sure the array index corresponds to the CPUID of each entry.
		assert.EqualValues(t, i, s.CPUID)
	}
}

func TestConnStatsExpect(t *testing.T) {

	c, err := makeNSConn()
	require.NoError(t, err)

	statsExpect, err := c.StatsExpect()
	require.NoError(t, err)

	for i, s := range statsExpect {
		// Make sure the array index corresponds to the CPUID of each entry.
		assert.EqualValues(t, i, s.CPUID)
	}
}

func TestConnStatsGlobal(t *testing.T) {

	c, err := makeNSConn()
	require.NoError(t, err)

	numFlows := 42

	var f Flow

	// Create IPv4 flows
	for i := 1; i <= numFlows; i++ {
		f = NewFlow(6, 0, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234, uint16(i), 120, 0)

		err = c.Create(f)
		require.NoError(t, err, "creating IPv4 flow", i)
	}

	// Create IPv6 flows
	for i := 1; i <= numFlows; i++ {
		err = c.Create(NewFlow(
			17, 0,
			net.ParseIP("2a00:1450:400e:804::200e"),
			net.ParseIP("2a00:1450:400e:804::200f"),
			1234, uint16(i), 120, 0,
		))
		require.NoError(t, err, "creating IPv6 flow", i)
	}

	sg, err := c.StatsGlobal()
	require.NoError(t, err, "query StatsGlobal")

	assert.EqualValues(t, numFlows*2, sg.Entries)
}
