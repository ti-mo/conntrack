package conntrack

import (
	"net"
	"testing"
	"time"

	"github.com/mdlayher/netlink"

	"github.com/google/go-cmp/cmp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ti-mo/netfilter"
)

var (
	// Re-usable structures and netfilter atttibutes for tests
	nfaIPPT = []netfilter.Attribute{
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
	}
	flowIPPT = Tuple{
		IP: IPTuple{
			SourceAddress:      net.IP{1, 2, 3, 4},
			DestinationAddress: net.IP{4, 3, 2, 1},
		},
		Proto: ProtoTuple{
			Protocol:        6,
			SourcePort:      65280,
			DestinationPort: 255,
		},
	}
	flowBadIPPT = Tuple{
		IP: IPTuple{
			SourceAddress:      net.IP{1, 2, 3, 4},
			DestinationAddress: net.ParseIP("::1"),
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
				Mark: 0x010203, Use: 0x010203,
			},
		},
		{
			name: "ip/port/proto tuple attributes as orig/reply/master",
			attrs: []netfilter.Attribute{
				{
					Type:     uint16(CTATupleOrig),
					Nested:   true,
					Children: nfaIPPT,
				},
				{
					Type:     uint16(CTATupleReply),
					Nested:   true,
					Children: nfaIPPT,
				},
				{
					Type:     uint16(CTATupleMaster),
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
					Type: uint16(CTAStatus),
					Data: []byte{0xff, 0x00, 0xff, 0x00},
				},
			},
			flow: Flow{Status: Status{Value: 0xff00ff00}},
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
				{
					Type:   uint16(CTASeqAdjReply),
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
			flow: Flow{
				SeqAdjOrig:  SequenceAdjust{Position: 0x0f123456, OffsetAfter: 0x0f123499},
				SeqAdjReply: SequenceAdjust{Direction: true, Position: 0x0f123456, OffsetAfter: 0x0f123499},
			},
		},
		{
			name: "synproxy attribute",
			attrs: []netfilter.Attribute{
				{
					Type:   uint16(CTASynProxy),
					Nested: true,
					Children: []netfilter.Attribute{
						{
							Type: uint16(CTASynProxyISN),
							Data: []byte{0x12, 0x34, 0x56, 0x78},
						},
						{
							Type: uint16(CTASynProxyITS),
							Data: []byte{0x87, 0x65, 0x43, 0x21},
						},
						{
							Type: uint16(CTASynProxyTSOff),
							Data: []byte{0xab, 0xcd, 0xef, 0x00},
						},
					},
				},
			},
			flow: Flow{SynProxy: SynProxy{ISN: 0x12345678, ITS: 0x87654321, TSOff: 0xabcdef00}},
		},
	}

	corpusFlowUnmarshalError = []struct {
		name   string
		errStr string
		nfa    netfilter.Attribute
	}{
		{
			name:   "error unmarshal original tuple",
			nfa:    netfilter.Attribute{Type: uint16(CTATupleOrig)},
			errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal reply tuple",
			nfa:    netfilter.Attribute{Type: uint16(CTATupleReply)},
			errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal master tuple",
			nfa:    netfilter.Attribute{Type: uint16(CTATupleMaster)},
			errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal status",
			nfa:    netfilter.Attribute{Type: uint16(CTAStatus), Nested: true},
			errStr: "Status unmarshal: unexpected Nested attribute",
		},
		{
			name:   "error unmarshal protoinfo",
			nfa:    netfilter.Attribute{Type: uint16(CTAProtoInfo)},
			errStr: "ProtoInfo unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal helper",
			nfa:    netfilter.Attribute{Type: uint16(CTAHelp)},
			errStr: "Helper unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal original counter",
			nfa:    netfilter.Attribute{Type: uint16(CTACountersOrig)},
			errStr: "Counter unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal reply counter",
			nfa:    netfilter.Attribute{Type: uint16(CTACountersReply)},
			errStr: "Counter unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal security context",
			nfa:    netfilter.Attribute{Type: uint16(CTASecCtx)},
			errStr: "Security unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal timestamp",
			nfa:    netfilter.Attribute{Type: uint16(CTATimestamp)},
			errStr: "Timestamp unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal original seqadj",
			nfa:    netfilter.Attribute{Type: uint16(CTASeqAdjOrig)},
			errStr: "SeqAdj unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal reply seqadj",
			nfa:    netfilter.Attribute{Type: uint16(CTASeqAdjReply)},
			errStr: "SeqAdj unmarshal: need a Nested attribute to decode this structure",
		},
		{
			name:   "error unmarshal synproxy",
			nfa:    netfilter.Attribute{Type: uint16(CTASynProxy)},
			errStr: "SynProxy unmarshal: need a Nested attribute to decode this structure",
		},
	}
)

func TestFlowUnmarshal(t *testing.T) {
	for _, tt := range corpusFlow {
		t.Run(tt.name, func(t *testing.T) {
			var f Flow
			err := f.unmarshal(tt.attrs)

			if err != nil || tt.err != nil {
				require.Error(t, err)
				require.EqualError(t, tt.err, err.Error())
				return
			}

			if diff := cmp.Diff(tt.flow, f); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}
		})
	}

	for _, tt := range corpusFlowUnmarshalError {
		t.Run(tt.name, func(t *testing.T) {
			var f Flow
			assert.EqualError(t, f.unmarshal([]netfilter.Attribute{tt.nfa}), tt.errStr)
		})
	}
}

func TestFlowMarshal(t *testing.T) {

	// Expect a marshal without errors
	_, err := Flow{
		TupleOrig: flowIPPT, TupleReply: flowIPPT, TupleMaster: flowIPPT,
		ProtoInfo: ProtoInfo{TCP: &ProtoInfoTCP{State: 42}},
		Timeout:   123, Status: Status{Value: 1234}, Mark: 0x1234, Zone: 2,
		Helper:      Helper{Name: "ftp"},
		SeqAdjOrig:  SequenceAdjust{Position: 1, OffsetBefore: 2, OffsetAfter: 3},
		SeqAdjReply: SequenceAdjust{Position: 5, OffsetBefore: 6, OffsetAfter: 7},
		SynProxy:    SynProxy{ISN: 0x12345678, ITS: 0x87654321, TSOff: 0xabcdef00},
	}.marshal()
	assert.NoError(t, err)

	// Cannot marshal without orig and reply tuples
	_, err = Flow{}.marshal()
	assert.EqualError(t, err, errNeedTuples.Error())

	// Return error from orig/reply/master IPTuple marshals
	_, err = Flow{TupleOrig: flowBadIPPT, TupleReply: flowIPPT}.marshal()
	assert.EqualError(t, err, errBadIPTuple.Error())
	_, err = Flow{TupleOrig: flowIPPT, TupleReply: flowBadIPPT}.marshal()
	assert.EqualError(t, err, errBadIPTuple.Error())
	_, err = Flow{TupleOrig: flowIPPT, TupleReply: flowIPPT, TupleMaster: flowBadIPPT}.marshal()
	assert.EqualError(t, err, errBadIPTuple.Error())
}

func TestUnmarshalFlowsError(t *testing.T) {

	_, err := unmarshalFlows([]netlink.Message{{}})
	assert.EqualError(t, err, "expected at least 4 bytes in netlink message payload")

	// Use netfilter.MarshalNetlink to assemble a Netlink message with a single attribute of unknown type
	nlm, _ := netfilter.MarshalNetlink(netfilter.Header{}, []netfilter.Attribute{{Type: 255}})
	_, err = unmarshalFlows([]netlink.Message{nlm})
	assert.EqualError(t, err, "attribute type '255' unknown")
}

func TestFlowBuilder(t *testing.T) {

	var f Flow

	f.Build(
		13, StatusNATMask, net.ParseIP("2a01:1450:200e:985::200e"),
		net.ParseIP("2a12:1250:200e:123::100d"), 64732, 443, 400,
	)

	want := Flow{
		Status:  Status{Value: StatusNATMask},
		Timeout: 400,
		TupleOrig: Tuple{
			IP: IPTuple{
				SourceAddress:      net.ParseIP("2a01:1450:200e:985::200e"),
				DestinationAddress: net.ParseIP("2a12:1250:200e:123::100d"),
			},
			Proto: ProtoTuple{
				Protocol:        13,
				SourcePort:      64732,
				DestinationPort: 443,
			},
		},
		TupleReply: Tuple{
			IP: IPTuple{
				DestinationAddress: net.ParseIP("2a01:1450:200e:985::200e"),
				SourceAddress:      net.ParseIP("2a12:1250:200e:123::100d"),
			},
			Proto: ProtoTuple{
				Protocol:        13,
				DestinationPort: 64732,
				SourcePort:      443,
			},
		},
	}

	if diff := cmp.Diff(want, f); diff != "" {
		t.Fatalf("unexpected builder output (-want +got):\n%s", diff)
	}
}

func BenchmarkFlowUnmarshal(b *testing.B) {

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
