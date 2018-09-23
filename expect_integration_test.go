//+build integration

package conntrack

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// No meaningful integration test possible until we can figure out how
// to create expects from userspace.
func TestConnDumpExpect(t *testing.T) {

	c, err := makeNSConn()
	require.NoError(t, err)

	_, err = c.DumpExpect()
	require.NoError(t, err, "unexpected error dumping expect table")
}
