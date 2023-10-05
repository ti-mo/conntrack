package conntrack

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/netlink"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ti-mo/netfilter"
)

var (
	// Re-usable structures and netfilter atttibutes for tests
	nfaIPPT = []netfilter.Attribute{
		{
			Type:   uint16(ctaTupleIP),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(ctaIPv4Src),
					Data: []byte{1, 2, 3, 4},
				},
				{
					Type: uint16(ctaIPv4Dst),
					Data: []byte{4, 3, 2, 1},
				},
			},
		},
		{
			Type:   uint16(ctaTupleProto),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(ctaProtoNum),
					Data: []byte{0x06},
				},
				{
					Type: uint16(ctaProtoSrcPort),
					Data: []byte{0xff, 0x00},
				},
				{
					Type: uint16(ctaProtoDstPort),
					Data: []byte{0x00, 0xff},
				},
			},
		},
	}
	flowIPPT = Tuple{
		IP: IPTuple{
			SourceAddress:      netip.MustParseAddr("1.2.3.4"),
			DestinationAddress: netip.MustParseAddr("4.3.2.1"),
		},
		Proto: ProtoTuple{
			Protocol:        6,
			SourcePort:      65280,
			DestinationPort: 255,
		},
	}
	flowBadIPPT = Tuple{
		IP: IPTuple{
			SourceAddress:      netip.MustParseAddr("1.2.3.4"),
			DestinationAddress: netip.MustParseAddr("::1"),
		},
		Proto: ProtoTuple{
			Protocol:        6,
			SourcePort:      65280,
			DestinationPort: 255,
		},
	}

	corpusFlow = []struct {
		name  string
		attrs []netfilter.Attribute
		flow  Flow
	}{
		{
			name: "scalar and simple binary attributes",
			attrs: []netfilter.Attribute{
				{
					Type: uint16(ctaTimeout),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(ctaID),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(ctaUse),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(ctaMark),
					Data: []byte{0, 1, 2, 3},
				},
				{
					Type: uint16(ctaZone),
					Data: []byte{4, 5},
				},
				{
					Type: uint16(ctaLabels),
					Data: []byte{0x4b, 0x1d, 0xbe, 0xef},
				},
				{
					Type: uint16(ctaLabelsMask),
					Data: []byte{0x00, 0xba, 0x1b, 0xe1},
				},
			},
			flow: Flow{
				ID: 0x010203, Timeout: 0x010203, Zone: 0x0405,
				Labels: []byte{0x4b, 0x1d, 0xbe, 0xef}, LabelsMask: []byte{0x00, 0xba, 0x1b, 0xe1},
				Mark: 0x010203, Use: 0x010203,
			},
		},
		{
			name: "ip/port/proto tuple attributes as orig/reply/master",
			attrs: []netfilter.Attribute{
				{
					Type:     uint16(ctaTupleOrig),
					Nested:   true,
					Children: nfaIPPT,
				},
				{
					Type:     uint16(ctaTupleReply),
					Nested:   true,
					Children: nfaIPPT,
				},
				{
					Type:     uint16(ctaTupleMaster),
					Nested:   true,
					Children: nfaIPPT,
				},
			},
			flow: Flow{
				TupleOrig:   flowIPPT,
				TupleReply:  flowIPPT,
				TupleMaster: flowIPPT,
			},
		},
		{
			name: "status attribute",
			attrs: []netfilter.Attribute{
				{
					Type: uint16(ctaStatus),
					Data: []byte{0xff, 0x00, 0xff, 0x00},
				},
			},
			flow: Flow{Status: Status{Value: 0xff00ff00}},
		},
		{
			name: "protoinfo attribute w/ tcp info",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(ctaProtoInfo),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type:   uint16(ctaProtoInfoTCP),
							Nested: true,
							Children: []netfilter.Attribute{
								{
									Type: uint16(ctaProtoInfoTCPState),
									Data: []byte{1},
								},
								{
									Type: uint16(ctaProtoInfoTCPFlagsOriginal),
									Data: []byte{2, 3},
								},
								{
									Type: uint16(ctaProtoInfoTCPFlagsReply),
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
					Type:   uint16(ctaHelp),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(ctaHelpName),
							Data: []byte("helper"),
						},
						{
							Type: uint16(ctaHelpInfo),
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
					Type:   uint16(ctaCountersOrig),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(ctaCountersPackets),
							Data: []byte{0x00, 0x00, 0x00, 0x00, 0xf0, 0x0d, 0x00, 0x00},
						},
						{
							Type: uint16(ctaCountersBytes),
							Data: []byte{0xba, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00},
						},
					},
				},
				{
					Type:   uint16(ctaCountersReply),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(ctaCountersPackets),
							Data: []byte{0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d},
						},
						{
							Type: uint16(ctaCountersBytes),
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
					Type:   uint16(ctaSecCtx),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(ctaSecCtxName),
							Data: []byte("jail"),
						},
					},
				},
			},
			flow: Flow{SecurityContext: "jail"},
		},
		{
			name: "timestamp attribute",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(ctaTimestamp),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(ctaTimestampStart),
							Data: []byte{
								0x0f, 0x12, 0x34, 0x56,
								0x78, 0x9a, 0xbc, 0xde},
						},
						{
							Type: uint16(ctaTimestampStop),
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
					Type:   uint16(ctaSeqAdjOrig),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(ctaSeqAdjCorrectionPos),
							Data: []byte{0x0f, 0x12, 0x34, 0x56},
						},
						{
							Type: uint16(ctaSeqAdjOffsetAfter),
							Data: []byte{0x0f, 0x12, 0x34, 0x99},
						},
					},
				},
				{
					Type:   uint16(ctaSeqAdjReply),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(ctaSeqAdjCorrectionPos),
							Data: []byte{0x0f, 0x12, 0x34, 0x56},
						},
						{
							Type: uint16(ctaSeqAdjOffsetAfter),
							Data: []byte{0x0f, 0x12, 0x34, 0x99},
						},
					},
				},
			},
			flow: Flow{
				SeqAdjOrig:  SequenceAdjust{Position: 0x0f123456, OffsetAfter: 0x0f123499},
				SeqAdjReply: SequenceAdjust{Direction: true, Position: 0x0f123456, OffsetAfter: 0x0f123499},
			},
		},
		{
			name: "synproxy attribute",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(ctaSynProxy),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(ctaSynProxyISN),
							Data: []byte{0x12, 0x34, 0x56, 0x78},
						},
						{
							Type: uint16(ctaSynProxyITS),
							Data: []byte{0x87, 0x65, 0x43, 0x21},
						},
						{
							Type: uint16(ctaSynProxyTSOff),
							Data: []byte{0xab, 0xcd, 0xef, 0x00},
						},
					},
				},
			},
			flow: Flow{SynProxy: SynProxy{ISN: 0x12345678, ITS: 0x87654321, TSOff: 0xabcdef00}},
		},
	}

	corpusFlowUnmarshalError = []struct {
		name string
		nfa  netfilter.Attribute
	}{
		{
			name: "error unmarshal original tuple",
			nfa:  netfilter.Attribute{Type: uint16(ctaTupleOrig)},
		},
		{
			name: "error unmarshal reply tuple",
			nfa:  netfilter.Attribute{Type: uint16(ctaTupleReply)},
		},
		{
			name: "error unmarshal master tuple",
			nfa:  netfilter.Attribute{Type: uint16(ctaTupleMaster)},
		},
		{
			name: "error unmarshal protoinfo",
			nfa:  netfilter.Attribute{Type: uint16(ctaProtoInfo)},
		},
		{
			name: "error unmarshal helper",
			nfa:  netfilter.Attribute{Type: uint16(ctaHelp)},
		},
		{
			name: "error unmarshal original counter",
			nfa:  netfilter.Attribute{Type: uint16(ctaCountersOrig)},
		},
		{
			name: "error unmarshal reply counter",
			nfa:  netfilter.Attribute{Type: uint16(ctaCountersReply)},
		},
		{
			name: "error unmarshal security context",
			nfa:  netfilter.Attribute{Type: uint16(ctaSecCtx)},
		},
		{
			name: "error unmarshal timestamp",
			nfa:  netfilter.Attribute{Type: uint16(ctaTimestamp)},
		},
		{
			name: "error unmarshal original seqadj",
			nfa:  netfilter.Attribute{Type: uint16(ctaSeqAdjOrig)},
		},
		{
			name: "error unmarshal reply seqadj",
			nfa:  netfilter.Attribute{Type: uint16(ctaSeqAdjReply)},
		},
		{
			name: "error unmarshal synproxy",
			nfa:  netfilter.Attribute{Type: uint16(ctaSynProxy)},
		},
	}
)

func TestFlowUnmarshal(t *testing.T) {
	for _, tt := range corpusFlow {
		t.Run(tt.name, func(t *testing.T) {
			var f Flow
			require.NoError(t, f.unmarshal(mustDecodeAttributes(tt.attrs)))
			assert.Equal(t, tt.flow, f, "unexpected unmarshal")
		})
	}

	for _, tt := range corpusFlowUnmarshalError {
		t.Run(tt.name, func(t *testing.T) {
			var f Flow
			err := f.unmarshal(mustDecodeAttributes([]netfilter.Attribute{tt.nfa}))
			assert.ErrorIs(t, err, errNotNested)
		})
	}
}

func TestFlowMarshal(t *testing.T) {
	// Expect a marshal without errors
	attrs, err := Flow{
		TupleOrig: flowIPPT, TupleReply: flowIPPT, TupleMaster: flowIPPT,
		ProtoInfo: ProtoInfo{TCP: &ProtoInfoTCP{State: 42}},
		Timeout:   123, Status: Status{Value: 1234}, Mark: 0x1234, Zone: 2,
		Helper:      Helper{Name: "ftp"},
		SeqAdjOrig:  SequenceAdjust{Position: 1, OffsetBefore: 2, OffsetAfter: 3},
		SeqAdjReply: SequenceAdjust{Position: 5, OffsetBefore: 6, OffsetAfter: 7},
		SynProxy:    SynProxy{ISN: 0x12345678, ITS: 0x87654321, TSOff: 0xabcdef00},
		Labels:      []byte{0x13, 0x37},
		LabelsMask:  []byte{0xff, 0xff},
	}.marshal()
	assert.NoError(t, err)

	want := []netfilter.Attribute{
		{Type: uint16(ctaTupleOrig), Nested: true, Children: []netfilter.Attribute{
			{Type: uint16(ctaTupleIP), Nested: true, Children: []netfilter.Attribute{
				{Type: uint16(ctaIPv4Src), Data: []byte{0x1, 0x2, 0x3, 0x4}},
				{Type: uint16(ctaIPv4Dst), Data: []byte{0x4, 0x3, 0x2, 0x1}},
			}},
			{Type: uint16(ctaTupleProto), Nested: true, Children: []netfilter.Attribute{
				{Type: uint16(ctaProtoNum), Data: []byte{0x6}},
				{Type: uint16(ctaProtoSrcPort), Data: []byte{0xff, 0x0}},
				{Type: uint16(ctaProtoDstPort), Data: []byte{0x0, 0xff}}}},
		}},
		{Type: uint16(ctaTupleReply), Nested: true, Children: []netfilter.Attribute{
			{Type: uint16(ctaTupleIP), Nested: true, Children: []netfilter.Attribute{
				{Type: uint16(ctaIPv4Src), Data: []byte{0x1, 0x2, 0x3, 0x4}},
				{Type: uint16(ctaIPv4Dst), Data: []byte{0x4, 0x3, 0x2, 0x1}}}},
			{Type: uint16(ctaTupleProto), Nested: true, Children: []netfilter.Attribute{
				{Type: uint16(ctaProtoNum), Data: []byte{0x6}},
				{Type: uint16(ctaProtoSrcPort), Data: []byte{0xff, 0x0}},
				{Type: uint16(ctaProtoDstPort), Data: []byte{0x0, 0xff}}}}}},
		{Type: uint16(ctaTimeout), Data: []byte{0x0, 0x0, 0x0, 0x7b}},
		{Type: uint16(ctaStatus), Data: []byte{0x0, 0x0, 0x4, 0xd2}},
		{Type: uint16(ctaMark), Data: []byte{0x0, 0x0, 0x12, 0x34}},
		{Type: uint16(ctaZone), Data: []byte{0x0, 0x2}},
		{Type: uint16(ctaProtoInfo), Nested: true, Children: []netfilter.Attribute{
			{Type: uint16(ctaProtoInfoTCP), Nested: true, Children: []netfilter.Attribute{
				{Type: uint16(ctaProtoInfoTCPState), Data: []byte{0x2a}},
				{Type: uint16(ctaProtoInfoTCPWScaleOriginal), Data: []byte{0x0}},
				{Type: uint16(ctaProtoInfoTCPWScaleReply), Data: []byte{0x0}}}}}},
		{Type: uint16(ctaHelp), Nested: true, Children: []netfilter.Attribute{
			{Type: uint16(ctaHelpName), Data: []byte{0x66, 0x74, 0x70}}}},
		{Type: uint16(ctaTupleMaster), Nested: true, Children: []netfilter.Attribute{
			{Type: uint16(ctaTupleIP), Nested: true, Children: []netfilter.Attribute{
				{Type: uint16(ctaIPv4Src), Data: []byte{0x1, 0x2, 0x3, 0x4}},
				{Type: uint16(ctaIPv4Dst), Data: []byte{0x4, 0x3, 0x2, 0x1}}}},
			{Type: uint16(ctaTupleProto), Nested: true, Children: []netfilter.Attribute{
				{Type: uint16(ctaProtoNum), Data: []byte{0x6}},
				{Type: uint16(ctaProtoSrcPort), Data: []byte{0xff, 0x0}},
				{Type: uint16(ctaProtoDstPort), Data: []byte{0x0, 0xff}}}}}},
		{Type: uint16(ctaSeqAdjOrig), Nested: true, Children: []netfilter.Attribute{
			{Type: uint16(ctaSeqAdjCorrectionPos), Data: []byte{0x0, 0x0, 0x0, 0x1}},
			{Type: uint16(ctaSeqAdjOffsetBefore), Data: []byte{0x0, 0x0, 0x0, 0x2}},
			{Type: uint16(ctaSeqAdjOffsetAfter), Data: []byte{0x0, 0x0, 0x0, 0x3}}}},
		{Type: uint16(ctaSeqAdjReply), Nested: true, Children: []netfilter.Attribute{
			{Type: uint16(ctaSeqAdjCorrectionPos), Data: []byte{0x0, 0x0, 0x0, 0x5}},
			{Type: uint16(ctaSeqAdjOffsetBefore), Data: []byte{0x0, 0x0, 0x0, 0x6}},
			{Type: uint16(ctaSeqAdjOffsetAfter), Data: []byte{0x0, 0x0, 0x0, 0x7}}}},
		{Type: uint16(ctaSynProxy), Nested: true, Children: []netfilter.Attribute{
			{Type: uint16(ctaSynProxyISN), Data: []byte{0x12, 0x34, 0x56, 0x78}},
			{Type: uint16(ctaSynProxyITS), Data: []byte{0x87, 0x65, 0x43, 0x21}},
			{Type: uint16(ctaSynProxyTSOff), Data: []byte{0xab, 0xcd, 0xef, 0x0}}}},
		{Type: uint16(ctaLabels), Data: []byte{0x13, 0x37}},
		{Type: uint16(ctaLabelsMask), Data: []byte{0xff, 0xff}}}

	assert.Equal(t, attrs, want)

	// Can marshal with either orig or reply tuple available
	_, err = Flow{TupleOrig: flowIPPT}.marshal()
	assert.NoError(t, err)
	_, err = Flow{TupleReply: flowIPPT}.marshal()
	assert.NoError(t, err)

	// Cannot marshal with both orig and reply tuples empty.
	_, err = Flow{}.marshal()
	assert.ErrorIs(t, err, errNeedTuples)

	// Return error from orig/reply/master IPTuple marshals
	_, err = Flow{TupleOrig: flowBadIPPT, TupleReply: flowIPPT}.marshal()
	assert.ErrorIs(t, err, errBadIPTuple)
	_, err = Flow{TupleOrig: flowIPPT, TupleReply: flowBadIPPT}.marshal()
	assert.ErrorIs(t, err, errBadIPTuple)
	_, err = Flow{TupleOrig: flowIPPT, TupleReply: flowIPPT, TupleMaster: flowBadIPPT}.marshal()
	assert.ErrorIs(t, err, errBadIPTuple)
}

func TestUnmarshalFlowsError(t *testing.T) {
	// Use netfilter.MarshalNetlink to assemble a Netlink message with a single attribute with empty data.
	// Cause a random error in unmarshalFlows to cover error return.
	nlm, _ := netfilter.MarshalNetlink(netfilter.Header{}, []netfilter.Attribute{{Type: 1}})
	_, err := unmarshalFlows([]netlink.Message{nlm})
	assert.ErrorIs(t, err, errNotNested)
}

func TestNewFlow(t *testing.T) {
	f := NewFlow(
		13, StatusNATMask, netip.MustParseAddr("2a01:1450:200e:985::200e"),
		netip.MustParseAddr("2a12:1250:200e:123::100d"), 64732, 443, 400, 0xf00,
	)

	want := Flow{
		Status:  Status{Value: StatusNATMask},
		Timeout: 400,
		TupleOrig: Tuple{
			IP: IPTuple{
				SourceAddress:      netip.MustParseAddr("2a01:1450:200e:985::200e"),
				DestinationAddress: netip.MustParseAddr("2a12:1250:200e:123::100d"),
			},
			Proto: ProtoTuple{
				Protocol:        13,
				SourcePort:      64732,
				DestinationPort: 443,
			},
		},
		TupleReply: Tuple{
			IP: IPTuple{
				DestinationAddress: netip.MustParseAddr("2a01:1450:200e:985::200e"),
				SourceAddress:      netip.MustParseAddr("2a12:1250:200e:123::100d"),
			},
			Proto: ProtoTuple{
				Protocol:        13,
				DestinationPort: 64732,
				SourcePort:      443,
			},
		},
		Mark: 0xf00,
	}

	assert.Equal(t, want, f, "unexpected builder output")
}

func BenchmarkFlowUnmarshal(b *testing.B) {
	b.ReportAllocs()

	// Collect all test.attrs from corpus. This amounts to unmarshaling a flow
	// with all attributes (including extensions) sent by the kernel.
	var tests []netfilter.Attribute
	for _, test := range corpusFlow {
		tests = append(tests, test.attrs...)
	}

	// Marshal these netfilter attributes and return netlink.AttributeDecoder.
	ad := mustDecodeAttributes(tests)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		// Make a new copy of the AD to avoid reinstantiation.
		iad := *ad

		var f Flow
		_ = f.unmarshal(&iad)
	}
}
