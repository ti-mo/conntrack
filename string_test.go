package conntrack_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ti-mo/netfilter/conntrack"
)

func TestProtoLookup(t *testing.T) {

	// Existing proto
	if got := conntrack.ProtoLookup(6); got != "tcp" {
		t.Fatalf("unexpected string representation of proto 6: %s", got)
	}

	// Non-existent proto
	if got := conntrack.ProtoLookup(255); got != "255" {
		t.Fatalf("unexpected string representation of proto 255: %s", got)
	}
}

func TestEventString(t *testing.T) {

	tpl := conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      net.IPv4(1, 2, 3, 4),
			DestinationAddress: net.ParseIP("fe80::1"),
		},
		Proto: conntrack.ProtoTuple{
			SourcePort:      54321,
			DestinationPort: 80,
		},
	}

	// Empty event
	e := conntrack.Event{}

	assert.Equal(t, "[EventUnknown] <Empty Event>", e.String())

	// Event with Flow
	ef := conntrack.Event{Flow: &conntrack.Flow{}}

	ef.Flow.Status.Set(conntrack.IPSAssured)

	ef.Flow.TupleOrig = tpl

	ef.Flow.CountersOrig.Bytes = 42
	ef.Flow.CountersOrig.Packets = 1

	ef.Flow.Labels = conntrack.Binary{Data: []byte{0xf0, 0xf0}}
	ef.Flow.LabelsMask = conntrack.Binary{Data: []byte{0xff, 0xff}}

	ef.Flow.Mark = conntrack.Num32{Value: 0xf000baaa}
	ef.Flow.MarkMask = conntrack.Num32{Value: 0xffffffff}

	ef.Flow.SeqAdjOrig = conntrack.SequenceAdjust{OffsetBefore: 80, OffsetAfter: 747811, Position: 42}
	ef.Flow.SeqAdjReply = conntrack.SequenceAdjust{OffsetBefore: 123, OffsetAfter: 456, Position: 889999}

	ef.Flow.SecurityContext.Name = "selinux_t"

	assert.Equal(t,
		"[EventUnknown] (Unreplied) Timeout: 0, <0, Src: 1.2.3.4:54321, Dst: [fe80::1]:80>, Zone 0, Acct: [orig: 1 pkts/42 B] [orig: 0 pkts/0 B], Label: <0xf0f0/0xffff>, Mark: <0xf000baaa/0xffffffff>, SeqAdjOrig: [dir: orig, pos: 42, before: 80, after: 747811], SeqAdjReply: [dir: orig, pos: 889999, before: 123, after: 456], SecCtx: selinux_t",
		ef.String())

	// Event with Expect
	ee := conntrack.Event{Expect: &conntrack.Expect{}}

	ee.Expect.TupleMaster = tpl
	ee.Expect.Tuple = tpl
	ee.Expect.Mask = tpl

	ee.Expect.HelpName = "ftp"
	ee.Expect.Class = conntrack.Num32{Value: 0x42}

	assert.Equal(t,
		"[EventUnknown] Timeout: 0, Master: <0, Src: 1.2.3.4:54321, Dst: [fe80::1]:80>, Tuple: <0, Src: 1.2.3.4:54321, Dst: [fe80::1]:80>, Mask: <0, Src: 1.2.3.4:54321, Dst: [fe80::1]:80>, Zone: 0, Helper: 'ftp', Class: 0x42",
		ee.String())
}
