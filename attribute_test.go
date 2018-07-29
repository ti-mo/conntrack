package conntrack

import (
	"testing"

	"github.com/ti-mo/netfilter"
)

var (
	corpus = []struct {
		name   string
		attrs  []netfilter.Attribute
		filter AttributeFilter
		err    error
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
		},
		{
			name: "status attribute",
			attrs: []netfilter.Attribute{
				{
					Type: uint16(CTAStatus),
					Data: []byte{0xff, 0x00, 0xff, 0x00},
				},
			},
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
		},
	}
)

func TestAttribute_Unmarshal(t *testing.T) {
	for _, tt := range corpus {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalAttributes(tt.attrs, tt.filter)
			if err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
		})
	}
}

var tb map[AttributeType]interface{}

func BenchmarkAttribute_UnmarshalAttribute(b *testing.B) {

	var tests []netfilter.Attribute

	// Collect all tests from corpus that aren't expected to fail
	for _, test := range corpus {
		if test.err == nil {
			tests = append(tests, test.attrs...)
		}
	}

	for n := 0; n < b.N; n++ {
		tb, _ = UnmarshalAttributes(tests, AttributeFilter(0))
	}
}
