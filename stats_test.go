package conntrack

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/netfilter"
)

func TestStatsUnmarshal(t *testing.T) {

	nfa := []netfilter.Attribute{
		{
			Type: uint16(ctaStatsFound),
			Data: []byte{0x01, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsInvalid),
			Data: []byte{0x02, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsIgnore),
			Data: []byte{0x03, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsInsert),
			Data: []byte{0x04, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsInsertFailed),
			Data: []byte{0x05, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsDrop),
			Data: []byte{0x06, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsEarlyDrop),
			Data: []byte{0x07, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsError),
			Data: []byte{0x08, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsSearchRestart),
			Data: []byte{0x09, 0xab, 0xcd, 0xef},
		},
	}

	want := Stats{
		Found:         0x01abcdef,
		Invalid:       0x02abcdef,
		Ignore:        0x03abcdef,
		Insert:        0x04abcdef,
		InsertFailed:  0x05abcdef,
		Drop:          0x06abcdef,
		EarlyDrop:     0x07abcdef,
		Error:         0x08abcdef,
		SearchRestart: 0x09abcdef,
	}

	var s Stats
	err := s.unmarshal(nfa)
	require.NoError(t, err)

	if diff := cmp.Diff(want, s); diff != "" {
		t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
	}

	assert.EqualError(t, s.unmarshal([]netfilter.Attribute{{Type: 255}}), "attribute type '255' unknown")
}

func TestUnmarshalStatsError(t *testing.T) {

	_, err := unmarshalStats([]netlink.Message{{}})
	assert.EqualError(t, err, "expected at least 4 bytes in netlink message payload")

	// Use netfilter.MarshalNetlink to assemble a Netlink message with a single attribute of unknown type
	nlm, _ := netfilter.MarshalNetlink(netfilter.Header{}, []netfilter.Attribute{{Type: 255}})
	_, err = unmarshalStats([]netlink.Message{nlm})
	assert.EqualError(t, err, "attribute type '255' unknown")
}
