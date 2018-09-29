package conntrack

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProtoLookup(t *testing.T) {

	// Existing proto
	if got := protoLookup(6); got != "tcp" {
		t.Fatalf("unexpected string representation of proto 6: %s", got)
	}

	// Non-existent proto
	if got := protoLookup(255); got != "255" {
		t.Fatalf("unexpected string representation of proto 255: %s", got)
	}
}

func TestEventString(t *testing.T) {

	tpl := Tuple{
		IP: IPTuple{
			SourceAddress:      net.IPv4(1, 2, 3, 4),
			DestinationAddress: net.ParseIP("fe80::1"),
		},
		Proto: ProtoTuple{
			SourcePort:      54321,
			DestinationPort: 80,
		},
	}

	// Empty event
	e := Event{}

	assert.Equal(t, "[EventUnknown] <Empty Event>", e.String())

	// Event with Flow
	ef := Event{Flow: &Flow{}}

	ef.Flow.Status.Value = StatusAssured

	ef.Flow.TupleOrig = tpl

	ef.Flow.CountersOrig.Bytes = 42
	ef.Flow.CountersOrig.Packets = 1

	ef.Flow.Labels = []byte{0xf0, 0xf0}
	ef.Flow.LabelsMask = []byte{0xff, 0xff}

	ef.Flow.Mark = 0xf000baaa

	ef.Flow.SeqAdjOrig = SequenceAdjust{OffsetBefore: 80, OffsetAfter: 747811, Position: 42}
	ef.Flow.SeqAdjReply = SequenceAdjust{OffsetBefore: 123, OffsetAfter: 456, Position: 889999}

	ef.Flow.SecurityContext = "selinux_t"

	assert.Equal(t,
		"[EventUnknown] (Unreplied) Timeout: 0, <0, Src: 1.2.3.4:54321, Dst: [fe80::1]:80>, Zone 0, Acct: [orig: 1 pkts/42 B] [orig: 0 pkts/0 B], Label: <0xf0f0/0xffff>, Mark: <0xf000baaa>, SeqAdjOrig: [dir: orig, pos: 42, before: 80, after: 747811], SeqAdjReply: [dir: orig, pos: 889999, before: 123, after: 456], SecCtx: selinux_t",
		ef.String())

	// Event with Expect
	ee := Event{Type: EventExpDestroy, Expect: &Expect{}}

	ee.Expect.TupleMaster = tpl
	ee.Expect.Tuple = tpl
	ee.Expect.Mask = tpl

	ee.Expect.HelpName = "ftp"
	ee.Expect.Class = 0x42

	assert.Equal(t,
		"[EventExpDestroy] Timeout: 0, Master: <0, Src: 1.2.3.4:54321, Dst: [fe80::1]:80>, Tuple: <0, Src: 1.2.3.4:54321, Dst: [fe80::1]:80>, Mask: <0, Src: 1.2.3.4:54321, Dst: [fe80::1]:80>, Zone: 0, Helper: 'ftp', Class: 0x42",
		ee.String())
}

func TestStatsString(t *testing.T) {
	s := Stats{CPUID: 42, Found: 2, SearchRestart: 999}
	assert.Equal(t, "<CPU 42 - Searched: 0, Found: 2, New: 0, Invalid: 0, Ignore: 0, Delete: 0, DeleteList: 0, Insert: 0, InsertFailed: 0, Drop: 0, EarlyDrop: 0, Error: 0, SearchRestart: 999>", s.String())
}
