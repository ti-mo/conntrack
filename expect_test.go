package conntrack

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/netfilter"
)

var corpusExpect = []struct {
	name  string
	attrs []netfilter.Attribute
	exp   Expect
	err   error
}{
	{
		name: "scalar and simple binary attributes",
		attrs: []netfilter.Attribute{
			{
				Type: uint16(CTAExpectID),
				Data: []byte{0, 1, 2, 3},
			},
			{
				Type: uint16(CTAExpectTimeout),
				Data: []byte{0, 1, 2, 3},
			},
			{
				Type: uint16(CTAExpectZone),
				Data: []byte{4, 5},
			},
			{
				Type: uint16(CTAExpectFlags),
				Data: []byte{5, 6, 7, 8},
			},
			{
				Type: uint16(CTAExpectClass),
				Data: []byte{5, 6, 7, 8},
			},
		},
		exp: Expect{
			ID:      0x010203,
			Timeout: 0x010203,
			Zone:    0x0405,
			Flags:   0x05060708,
			Class:   0x05060708,
		},
	},
	{
		name: "master, tuple, mask tuple attributes",
		attrs: []netfilter.Attribute{
			{
				Type:   uint16(CTAExpectMaster),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type:   uint16(CTATupleIP),
						Nested: true,
						Children: []netfilter.Attribute{
							{
								Type: uint16(CTAIPv4Src),
								Data: []byte{127, 0, 0, 1},
							},
							{
								Type: uint16(CTAIPv4Dst),
								Data: []byte{127, 0, 0, 2},
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
								Data: []byte{0xa6, 0xd2},
							},
							{
								Type: uint16(CTAProtoDstPort),
								Data: []byte{0x00, 0x0c},
							},
						},
					},
				},
			},
			{
				Type:   uint16(CTAExpectTuple),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type:   uint16(CTATupleIP),
						Nested: true,
						Children: []netfilter.Attribute{
							{
								Type: uint16(CTAIPv4Src),
								Data: []byte{127, 0, 0, 1},
							},
							{
								Type: uint16(CTAIPv4Dst),
								Data: []byte{127, 0, 0, 2},
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
								Data: []byte{0x0, 0x0},
							},
							{
								Type: uint16(CTAProtoDstPort),
								Data: []byte{0x75, 0x30},
							},
						},
					},
				},
			},
			{
				Type:   uint16(CTAExpectMask),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type:   uint16(CTATupleIP),
						Nested: true,
						Children: []netfilter.Attribute{
							{
								Type: uint16(CTAIPv4Src),
								Data: []byte{0xff, 0xff, 0xff, 0xff},
							},
							{
								Type: uint16(CTAIPv4Dst),
								Data: []byte{0xff, 0xff, 0xff, 0xff},
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
								Data: []byte{0x0, 0x0},
							},
							{
								Type: uint16(CTAProtoDstPort),
								Data: []byte{0xff, 0xff},
							},
						},
					},
				},
			},
			{
				Type:   uint16(CTAExpectNAT),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(CTAExpectNATDir),
						Data: []byte{0x00, 0x00, 0x00, 0x01},
					},
					{
						Type:     uint16(CTAExpectNATTuple),
						Nested:   true,
						Children: nfaIPPT,
					},
				},
			},
		},
		exp: Expect{
			TupleMaster: Tuple{
				IP: IPTuple{
					SourceAddress:      []byte{127, 0, 0, 1},
					DestinationAddress: []byte{127, 0, 0, 2},
				},
				Proto: ProtoTuple{
					Protocol:        6,
					SourcePort:      42706,
					DestinationPort: 12,
				},
			},
			Tuple: Tuple{
				IP: IPTuple{
					SourceAddress:      []byte{127, 0, 0, 1},
					DestinationAddress: []byte{127, 0, 0, 2},
				},
				Proto: ProtoTuple{
					Protocol:        6,
					DestinationPort: 30000,
				},
			},
			Mask: Tuple{
				IP: IPTuple{
					SourceAddress:      []byte{255, 255, 255, 255},
					DestinationAddress: []byte{255, 255, 255, 255},
				},
				Proto: ProtoTuple{
					Protocol:        6,
					DestinationPort: 0xffff,
				},
			},
			NAT: ExpectNAT{
				Direction: true,
				Tuple:     flowIPPT,
			},
		},
	},
	{
		name: "string attributes",
		attrs: []netfilter.Attribute{
			{
				Type: uint16(CTAExpectHelpName),
				Data: []byte("ftp"),
			},
			{
				Type: uint16(CTAExpectFN),
				Data: []byte("func_name"),
			},
		},
		exp: Expect{
			HelpName: "ftp",
			Function: "func_name",
		},
	},
}

var corpusExpectUnmarshalError = []struct {
	name   string
	errStr string
	nfa    netfilter.Attribute
}{
	{
		name:   "error unmarshal unknown attribute",
		nfa:    netfilter.Attribute{Type: 255},
		errStr: "attribute type '255' unknown",
	},
	{
		name:   "error unmarshal invalid master tuple",
		nfa:    netfilter.Attribute{Type: uint16(CTAExpectMaster)},
		errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
	},
	{
		name:   "error unmarshal invalid tuple",
		nfa:    netfilter.Attribute{Type: uint16(CTAExpectTuple)},
		errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
	},
	{
		name:   "error unmarshal invalid mask tuple",
		nfa:    netfilter.Attribute{Type: uint16(CTAExpectMask)},
		errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
	},
	{
		name:   "error unmarshal invalid nat",
		nfa:    netfilter.Attribute{Type: uint16(CTAExpectNAT)},
		errStr: "need a Nested attribute to decode this structure",
	},
}

func TestExpect_Unmarshal(t *testing.T) {

	for _, tt := range corpusExpect {
		t.Run(tt.name, func(t *testing.T) {

			var ex Expect
			err := ex.unmarshal(tt.attrs)

			if err != nil || tt.err != nil {
				require.Error(t, err)
				require.EqualError(t, tt.err, err.Error())
				return
			}

			if diff := cmp.Diff(tt.exp, ex); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}
		})
	}

	for _, tt := range corpusExpectUnmarshalError {
		t.Run(tt.name, func(t *testing.T) {
			var ex Expect
			assert.EqualError(t, ex.unmarshal([]netfilter.Attribute{tt.nfa}), tt.errStr)
		})
	}
}

var corpusExpectNAT = []struct {
	name string
	attr netfilter.Attribute
	enat ExpectNAT
	err  error
}{
	{
		name: "simple direction, tuple unmarshal",
		attr: netfilter.Attribute{
			Type:   uint16(CTAExpectNAT),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(CTAExpectNATDir),
					Data: []byte{0x00, 0x00, 0x00, 0x01},
				},
				{
					Type:     uint16(CTAExpectNATTuple),
					Nested:   true,
					Children: nfaIPPT,
				},
			},
		},
		enat: ExpectNAT{
			Direction: true,
			Tuple:     flowIPPT,
		},
	},
	{
		name: "error bad tuple",
		attr: netfilter.Attribute{
			Type:   uint16(CTAExpectNAT),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(CTAExpectNATDir),
					Data: []byte{0x00, 0x00, 0x00, 0x00},
				},
				{
					Type: uint16(CTAExpectNATTuple),
				},
			},
		},
		err: errors.New("Tuple unmarshal: need a Nested attribute to decode this structure"),
	},
	{
		name: "error unknown type",
		attr: netfilter.Attribute{Type: 255},
		err:  fmt.Errorf(errAttributeWrongType, 255, CTAExpectNAT),
	},
	{
		name: "error not nested",
		attr: netfilter.Attribute{Type: uint16(CTAExpectNAT)},
		err:  errNotNested,
	},
	{
		name: "error no children",
		attr: netfilter.Attribute{Type: uint16(CTAExpectNAT), Nested: true},
		err:  errNeedSingleChild,
	},
	{
		name: "error unknown child type",
		attr: netfilter.Attribute{
			Type:   uint16(CTAExpectNAT),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: 255,
				},
			},
		},
		err: fmt.Errorf(errAttributeChild, 255, CTAExpectNAT),
	},
}

func TestExpectNAT_Unmarshal(t *testing.T) {

	for _, tt := range corpusExpectNAT {
		t.Run(tt.name, func(t *testing.T) {

			var enat ExpectNAT
			err := enat.unmarshal(tt.attr)

			if err != nil || tt.err != nil {
				require.Error(t, err)
				require.EqualError(t, tt.err, err.Error())
				return
			}

			if diff := cmp.Diff(tt.enat, enat); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExpectType_String(t *testing.T) {
	if ExpectType(255).String() == "" {
		t.Fatal("ExpectType string representation empty - did you run `go generate`?")
	}

	assert.Equal(t, "CTAExpectFN", CTAExpectFN.String())
}

func BenchmarkExpect_Unmarshal(b *testing.B) {

	b.ReportAllocs()

	var tests []netfilter.Attribute
	var ex Expect

	// Collect all tests from corpus that aren't expected to fail
	for _, test := range corpusExpect {
		if test.err == nil {
			tests = append(tests, test.attrs...)
		}
	}

	for n := 0; n < b.N; n++ {
		ex.unmarshal(tests)
	}
}
