//+build integration

package conntrack

import (
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
