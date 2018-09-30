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
			Type: uint16(ctaStatsSearched),
			Data: []byte{0x01, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsFound),
			Data: []byte{0x02, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsNew),
			Data: []byte{0x03, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsInvalid),
			Data: []byte{0x04, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsIgnore),
			Data: []byte{0x05, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsDelete),
			Data: []byte{0x06, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsDeleteList),
			Data: []byte{0x07, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsInsert),
			Data: []byte{0x08, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsInsertFailed),
			Data: []byte{0x09, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsDrop),
			Data: []byte{0x0a, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsEarlyDrop),
			Data: []byte{0x0b, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsError),
			Data: []byte{0x0c, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsSearchRestart),
			Data: []byte{0x0d, 0xab, 0xcd, 0xef},
		},
	}

	want := Stats{
		Searched:      0x01abcdef,
		Found:         0x02abcdef,
		New:           0x03abcdef,
		Invalid:       0x04abcdef,
		Ignore:        0x05abcdef,
		Delete:        0x06abcdef,
		DeleteList:    0x07abcdef,
		Insert:        0x08abcdef,
		InsertFailed:  0x09abcdef,
		Drop:          0x0aabcdef,
		EarlyDrop:     0x0babcdef,
		Error:         0x0cabcdef,
		SearchRestart: 0x0dabcdef,
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

func TestStatsExpectUnmarshal(t *testing.T) {

	nfa := []netfilter.Attribute{
		{
			Type: uint16(ctaStatsExpNew),
			Data: []byte{0x01, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsExpCreate),
			Data: []byte{0x02, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsExpDelete),
			Data: []byte{0x03, 0xab, 0xcd, 0xef},
		},
	}

	want := StatsExpect{
		New:    0x01abcdef,
		Create: 0x02abcdef,
		Delete: 0x03abcdef,
	}

	var se StatsExpect
	err := se.unmarshal(nfa)
	require.NoError(t, err)

	if diff := cmp.Diff(want, se); diff != "" {
		t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
	}

	assert.EqualError(t, se.unmarshal([]netfilter.Attribute{{Type: 255}}), "attribute type '255' unknown")
}

func TestUnmarshalExpectStatsError(t *testing.T) {

	_, err := unmarshalStatsExpect([]netlink.Message{{}})
	assert.EqualError(t, err, "expected at least 4 bytes in netlink message payload")

	// Use netfilter.MarshalNetlink to assemble a Netlink message with a single attribute of unknown type
	nlm, _ := netfilter.MarshalNetlink(netfilter.Header{}, []netfilter.Attribute{{Type: 255}})
	_, err = unmarshalStatsExpect([]netlink.Message{nlm})
	assert.EqualError(t, err, "attribute type '255' unknown")
}
