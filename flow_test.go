package conntrack

import (
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/stretchr/testify/require"

	"github.com/ti-mo/netfilter"
)

var (
	corpusFlow = []struct {
		name  string
		attrs []netfilter.Attribute
		flow  Flow
		err   error
	}{
		{
			name: "scalar and simple binary attributes",
			attrs: []netfilter.Attribute{
				{
					Type: uint16(CTATimeout),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(CTAID),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(CTAUse),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(CTAMark),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(CTAMarkMask),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(CTAZone),
					Data: []byte{4, 5},
				},
				{
					Type: uint16(CTALabels),
					Data: []byte{0x4b, 0x1d, 0xbe, 0xef},
				},
				{
					Type: uint16(CTALabelsMask),
					Data: []byte{0x00, 0xba, 0x1b, 0xe1},
				},
			},
			flow: Flow{
				ID: 0x010203, Timeout: 0x010203, Zone: 0x0405,
				Labels: []byte{0x4b, 0x1d, 0xbe, 0xef}, LabelsMask: []byte{0x00, 0xba, 0x1b, 0xe1},
				Mark: 0x010203, MarkMask: 0x010203, Use: 0x010203,
			},
		},
		{
			name: "ip/port/proto tuple attributes",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(CTATupleOrig),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type:   uint16(CTATupleIP),
							Nested: true,
							Children: []netfilter.Attribute{
								{
									Type: uint16(CTAIPv4Src),
									Data: []byte{1, 2, 3, 4},
								},
								{
									Type: uint16(CTAIPv4Dst),
									Data: []byte{4, 3, 2, 1},
								},
							},
						},
						{
							Type:   uint16(CTATupleProto),
							Nested: true,
							Children: []netfilter.Attribute{
								{
									Type: uint16(CTAProtoNum),
									Data: []byte{0x06},
								},
								{
									Type: uint16(CTAProtoSrcPort),
									Data: []byte{0xff, 0x00},
								},
								{
									Type: uint16(CTAProtoDstPort),
									Data: []byte{0x00, 0xff},
								},
							},
						},
					},
				},
			},
			flow: Flow{
				TupleOrig: Tuple{
					IP: IPTuple{
						SourceAddress:      net.IP{1, 2, 3, 4},
						DestinationAddress: net.IP{4, 3, 2, 1},
					},
					Proto: ProtoTuple{
						Protocol:        6,
						SourcePort:      65280,
						DestinationPort: 255,
					},
				},
			},
		},
		{
			name: "status attribute",
			attrs: []netfilter.Attribute{
				{
					Type: uint16(CTAStatus),
					Data: []byte{0xff, 0x00, 0xff, 0x00},
				},
			},
			flow: Flow{Status: Status{value: 0xff00ff00}},
		},
		{
			name: "protoinfo attribute w/ tcp info",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(CTAProtoInfo),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type:   uint16(CTAProtoInfoTCP),
							Nested: true,
							Children: []netfilter.Attribute{
								{
									Type: uint16(CTAProtoInfoTCPState),
									Data: []byte{1},
								},
								{
									Type: uint16(CTAProtoInfoTCPFlagsOriginal),
									Data: []byte{2, 3},
								},
								{
									Type: uint16(CTAProtoInfoTCPFlagsReply),
									Data: []byte{4, 5},
								},
							},
						},
					},
				},
			},
			flow: Flow{ProtoInfo: ProtoInfo{TCP: &ProtoInfoTCP{State: 1, OriginalFlags: 0x0203, ReplyFlags: 0x0405}}},
		},
		{
			name: "helper attribute",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(CTAHelp),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(CTAHelpName),
							Data: []byte("helper"),
						},
						{
							Type: uint16(CTAHelpInfo),
							Data: []byte("info"),
						},
					},
				},
			},
			flow: Flow{Helper: Helper{Name: "helper", Info: []byte("info")}},
		},
		{
			name: "counter attribute",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(CTACountersOrig),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(CTACountersPackets),
							Data: []byte{0x00, 0x00, 0x00, 0x00, 0xf0, 0x0d, 0x00, 0x00},
						},
						{
							Type: uint16(CTACountersBytes),
							Data: []byte{0xba, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00},
						},
					},
				},
				{
					Type:   uint16(CTACountersReply),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(CTACountersPackets),
							Data: []byte{0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d},
						},
						{
							Type: uint16(CTACountersBytes),
							Data: []byte{0xfa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0xce},
						},
					},
				},
			},
			flow: Flow{
				CountersOrig:  Counter{Packets: 0xf00d0000, Bytes: 0xbaaaaa0000000000},
				CountersReply: Counter{Packets: 0xb00000000000000d, Bytes: 0xfaaaaa00000000ce, Direction: true},
			},
		},
		{
			name: "security attribute",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(CTASecCtx),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(CTASecCtxName),
							Data: []byte("jail"),
						},
					},
				},
			},
			flow: Flow{SecurityContext: Security{Name: "jail"}},
		},
		{
			name: "timestamp attribute",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(CTATimestamp),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(CTATimestampStart),
							Data: []byte{
								0x0f, 0x12, 0x34, 0x56,
								0x78, 0x9a, 0xbc, 0xde},
						},
						{
							Type: uint16(CTATimestampStop),
							Data: []byte{
								0xff, 0x12, 0x34, 0x56,
								0x78, 0x9a, 0xbc, 0xde},
						},
					},
				},
			},
			flow: Flow{Timestamp: Timestamp{
				Start: time.Unix(0, 0x0f123456789abcde),
				Stop:  time.Unix(0, -66933498461897506)}},
		},
		{
			name: "sequence adjust attribute",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(CTASeqAdjOrig),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(CTASeqAdjCorrectionPos),
							Data: []byte{0x0f, 0x12, 0x34, 0x56},
						},
						{
							Type: uint16(CTASeqAdjOffsetAfter),
							Data: []byte{0x0f, 0x12, 0x34, 0x99},
						},
					},
				},
			},
			flow: Flow{SeqAdjOrig: SequenceAdjust{Position: 0x0f123456, OffsetAfter: 0x0f123499}},
		},
	}
)

func TestFlow_Unmarshal(t *testing.T) {
	for _, tt := range corpusFlow {
		t.Run(tt.name, func(t *testing.T) {
			var f Flow
			err := f.unmarshal(tt.attrs)

			if err != nil || tt.err != nil {
				require.Error(t, err)
				require.EqualError(t, tt.err, err.Error())
				return
			}

			if diff := cmp.Diff(tt.flow, f, cmp.AllowUnexported(Status{})); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkFlow_Unmarshal(b *testing.B) {

	b.ReportAllocs()

	var tests []netfilter.Attribute
	var f Flow

	// Collect all tests from corpus that aren't expected to fail
	for _, test := range corpusFlow {
		if test.err == nil {
			tests = append(tests, test.attrs...)
		}
	}

	for n := 0; n < b.N; n++ {
		f.unmarshal(tests)
	}
}
