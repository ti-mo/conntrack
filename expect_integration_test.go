//go:build integration

package conntrack

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

// No meaningful integration test possible until we can figure out how
// to create expects from userspace.
func TestConnDumpExpect(t *testing.T) {

	c, _, err := makeNSConn()
	require.NoError(t, err)

	_, err = c.DumpExpect()
	require.NoError(t, err, "unexpected error dumping expect table")
}

// Attempt at creating conntrack expectation from userspace.
func TestConnCreateExpect(t *testing.T) {
	c, _, err := makeNSConn()
	require.NoError(t, err)

	f := NewFlow(6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"), 42000, 21, 120, 0)

	err = c.Create(f)
	require.NoError(t, err, "unexpected error creating flow", f)

	ex := Expect{
		Timeout:     300,
		TupleMaster: f.TupleOrig,
		Tuple: Tuple{
			IP: IPTuple{
				SourceAddress:      netip.MustParseAddr("1.2.3.4"),
				DestinationAddress: netip.MustParseAddr("5.6.7.8"),
			},
			Proto: ProtoTuple{
				Protocol:        6,
				SourcePort:      0,
				DestinationPort: 30000,
			},
		},
		Mask: Tuple{
			IP: IPTuple{
				SourceAddress:      netip.MustParseAddr("255.255.255.255"),
				DestinationAddress: netip.MustParseAddr("255.255.255.255"),
			},
			Proto: ProtoTuple{
				Protocol:        6,
				SourcePort:      0,
				DestinationPort: 65535,
			},
		},
		HelpName: "ftp",
		Class:    0x30,
	}

	require.ErrorIs(t, c.CreateExpect(ex), unix.EINVAL)
}
