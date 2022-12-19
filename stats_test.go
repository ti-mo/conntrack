package conntrack

import (
	"testing"

	"github.com/google/go-cmp/cmp"

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
		{Type: uint16(ctaStatsSearched)},
		{Type: uint16(ctaStatsNew)},
		{Type: uint16(ctaStatsDelete)},
		{Type: uint16(ctaStatsDeleteList)},
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
	s.unmarshal(nfa)

	if diff := cmp.Diff(want, s); diff != "" {
		t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
	}
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
	se.unmarshal(nfa)

	if diff := cmp.Diff(want, se); diff != "" {
		t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
	}
}

func TestStatsGlobalUnmarshal(t *testing.T) {

	nfa := []netfilter.Attribute{
		{
			Type: uint16(ctaStatsGlobalEntries),
			Data: []byte{0x01, 0xab, 0xcd, 0xef},
		},
		{
			Type: uint16(ctaStatsGlobalMaxEntries),
			Data: []byte{0x02, 0xab, 0xcd, 0xef},
		},
	}

	want := StatsGlobal{
		Entries:    0x01abcdef,
		MaxEntries: 0x02abcdef,
	}

	var sg StatsGlobal
	sg.unmarshal(nfa)

	if diff := cmp.Diff(want, sg); diff != "" {
		t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
	}
}
