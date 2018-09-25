package conntrack

import (
	"fmt"
	"net"
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
				Type: uint16(ctaExpectID),
				Data: []byte{0, 1, 2, 3},
			},
			{
				Type: uint16(ctaExpectTimeout),
				Data: []byte{0, 1, 2, 3},
			},
			{
				Type: uint16(ctaExpectZone),
				Data: []byte{4, 5},
			},
			{
				Type: uint16(ctaExpectFlags),
				Data: []byte{5, 6, 7, 8},
			},
			{
				Type: uint16(ctaExpectClass),
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
				Type:   uint16(ctaExpectMaster),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type:   uint16(ctaTupleIP),
						Nested: true,
						Children: []netfilter.Attribute{
							{
								Type: uint16(ctaIPv4Src),
								Data: []byte{127, 0, 0, 1},
							},
							{
								Type: uint16(ctaIPv4Dst),
								Data: []byte{127, 0, 0, 2},
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
								Data: []byte{0xa6, 0xd2},
							},
							{
								Type: uint16(ctaProtoDstPort),
								Data: []byte{0x00, 0x0c},
							},
						},
					},
				},
			},
			{
				Type:   uint16(ctaExpectTuple),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type:   uint16(ctaTupleIP),
						Nested: true,
						Children: []netfilter.Attribute{
							{
								Type: uint16(ctaIPv4Src),
								Data: []byte{127, 0, 0, 1},
							},
							{
								Type: uint16(ctaIPv4Dst),
								Data: []byte{127, 0, 0, 2},
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
								Data: []byte{0x0, 0x0},
							},
							{
								Type: uint16(ctaProtoDstPort),
								Data: []byte{0x75, 0x30},
							},
						},
					},
				},
			},
			{
				Type:   uint16(ctaExpectMask),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type:   uint16(ctaTupleIP),
						Nested: true,
						Children: []netfilter.Attribute{
							{
								Type: uint16(ctaIPv4Src),
								Data: []byte{0xff, 0xff, 0xff, 0xff},
							},
							{
								Type: uint16(ctaIPv4Dst),
								Data: []byte{0xff, 0xff, 0xff, 0xff},
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
								Data: []byte{0x0, 0x0},
							},
							{
								Type: uint16(ctaProtoDstPort),
								Data: []byte{0xff, 0xff},
							},
						},
					},
				},
			},
			{
				Type:   uint16(ctaExpectNAT),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(ctaExpectNATDir),
						Data: []byte{0x00, 0x00, 0x00, 0x01},
					},
					{
						Type:     uint16(ctaExpectNATTuple),
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
				Type: uint16(ctaExpectHelpName),
				Data: []byte("ftp"),
			},
			{
				Type: uint16(ctaExpectFN),
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
		nfa:    netfilter.Attribute{Type: uint16(ctaExpectMaster)},
		errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
	},
	{
		name:   "error unmarshal invalid tuple",
		nfa:    netfilter.Attribute{Type: uint16(ctaExpectTuple)},
		errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
	},
	{
		name:   "error unmarshal invalid mask tuple",
		nfa:    netfilter.Attribute{Type: uint16(ctaExpectMask)},
		errStr: "Tuple unmarshal: need a Nested attribute to decode this structure",
	},
	{
		name:   "error unmarshal invalid nat",
		nfa:    netfilter.Attribute{Type: uint16(ctaExpectNAT)},
		errStr: "ExpectNAT unmarshal: need a Nested attribute to decode this structure",
	},
}

func TestExpectUnmarshal(t *testing.T) {

	for _, tt := range corpusExpect {
		t.Run(tt.name, func(t *testing.T) {

			var ex Expect
			err := ex.unmarshal(tt.attrs)

			if err != nil || tt.err != nil {
				require.Error(t, err)
				require.Error(t, tt.err)
				require.EqualError(t, err, tt.err.Error())
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

func TestExpectMarshal(t *testing.T) {

	ex := Expect{
		TupleMaster: flowIPPT, Tuple: flowIPPT, Mask: flowIPPT,
		Timeout:  240,
		Zone:     5,
		HelpName: "ftp",
		Function: "func",
		Flags:    123,
		Class:    456,
		NAT: ExpectNAT{
			Direction: true,
			Tuple:     flowIPPT,
		},
	}

	exm, err := ex.marshal()
	require.NoError(t, err, "Expect marshal")

	want := []netfilter.Attribute{
		{
			Type:     uint16(ctaExpectMaster),
			Nested:   true,
			Children: nfaIPPT,
		},
		{
			Type:     uint16(ctaExpectTuple),
			Nested:   true,
			Children: nfaIPPT,
		},
		{
			Type:     uint16(ctaExpectMask),
			Nested:   true,
			Children: nfaIPPT,
		},
		{
			Type: uint16(ctaExpectTimeout),
			Data: []byte{0x00, 0x00, 0x00, 0xf0},
		},
		{
			Type: uint16(ctaExpectHelpName),
			Data: []byte("ftp"),
		},
		{
			Type: uint16(ctaExpectZone),
			Data: []byte{0x00, 0x05},
		},
		{
			Type: uint16(ctaExpectClass),
			Data: []byte{0x00, 0x00, 0x01, 0xc8},
		},
		{
			Type: uint16(ctaExpectFlags),
			Data: []byte{0x00, 0x00, 0x00, 0x7b},
		},
		{
			Type: uint16(ctaExpectFN),
			Data: []byte("func"),
		},
		{
			Type:   uint16(ctaExpectNAT),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(ctaExpectNATDir),
					Data: []byte{0x0, 0x0, 0x0, 0x1},
				},
				{
					Type:     uint16(ctaExpectNATTuple),
					Nested:   true,
					Children: nfaIPPT,
				},
			},
		},
	}

	if diff := cmp.Diff(want, exm); diff != "" {
		t.Fatalf("unexpected Expect marshal (-want +got):\n%s", diff)
	}

	// Cannot marshal without tuple/mask/master Tuples
	_, err = Expect{}.marshal()
	assert.EqualError(t, err, errExpectNeedTuples.Error())

	// Return error from tuple/mask/master Tuple marshals
	_, err = Expect{TupleMaster: flowBadIPPT, Tuple: flowIPPT, Mask: flowIPPT}.marshal()
	assert.EqualError(t, err, errBadIPTuple.Error())
	_, err = Expect{TupleMaster: flowIPPT, Tuple: flowBadIPPT, Mask: flowIPPT}.marshal()
	assert.EqualError(t, err, errBadIPTuple.Error())
	_, err = Expect{TupleMaster: flowIPPT, Tuple: flowIPPT, Mask: flowBadIPPT}.marshal()
	assert.EqualError(t, err, errBadIPTuple.Error())

	// Return error from Tuple marshal in ExpectNAT
	_, err = Expect{TupleMaster: flowIPPT, Tuple: flowIPPT, Mask: flowIPPT, NAT: ExpectNAT{Tuple: flowBadIPPT}}.marshal()
	assert.EqualError(t, err, errBadIPTuple.Error())
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
			Type:   uint16(ctaExpectNAT),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(ctaExpectNATDir),
					Data: []byte{0x00, 0x00, 0x00, 0x01},
				},
				{
					Type:     uint16(ctaExpectNATTuple),
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
			Type:   uint16(ctaExpectNAT),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(ctaExpectNATDir),
					Data: []byte{0x00, 0x00, 0x00, 0x00},
				},
				{
					Type: uint16(ctaExpectNATTuple),
				},
			},
		},
		err: errors.New("Tuple unmarshal: need a Nested attribute to decode this structure"),
	},
	{
		name: "error unknown type",
		attr: netfilter.Attribute{Type: 255},
		err:  fmt.Errorf(errAttributeWrongType, 255, ctaExpectNAT),
	},
	{
		name: "error not nested",
		attr: netfilter.Attribute{Type: uint16(ctaExpectNAT)},
		err:  errors.Wrap(errNotNested, opUnExpectNAT),
	},
	{
		name: "error no children",
		attr: netfilter.Attribute{Type: uint16(ctaExpectNAT), Nested: true},
		err:  errors.Wrap(errNeedSingleChild, opUnExpectNAT),
	},
	{
		name: "error unknown child type",
		attr: netfilter.Attribute{
			Type:   uint16(ctaExpectNAT),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: 255,
				},
			},
		},
		err: errors.Wrap(fmt.Errorf(errAttributeChild, 255, ctaExpectNAT), opUnExpectNAT),
	},
}

func TestExpectNATUnmarshal(t *testing.T) {

	for _, tt := range corpusExpectNAT {
		t.Run(tt.name, func(t *testing.T) {

			var enat ExpectNAT
			err := enat.unmarshal(tt.attr)

			if err != nil || tt.err != nil {
				require.Error(t, err)
				require.Error(t, tt.err)
				require.EqualError(t, err, tt.err.Error())
				return
			}

			if diff := cmp.Diff(tt.enat, enat); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExpectNATMarshal(t *testing.T) {

	// Expect a marshal without errors
	en := ExpectNAT{
		Direction: true,
		Tuple: Tuple{
			IP: IPTuple{
				SourceAddress:      net.ParseIP("baa:baa::b"),
				DestinationAddress: net.ParseIP("ef00:3f00::ba13"),
			},
			Proto: ProtoTuple{
				Protocol:        13,
				SourcePort:      123,
				DestinationPort: 456,
			},
			Zone: 5,
		},
	}
	enm, err := en.marshal()
	require.NoError(t, err, "ExpectNAT marshal", en)

	_, err = ExpectNAT{}.marshal()
	assert.EqualError(t, err, errBadIPTuple.Error())

	// Only verify first attribute (direction); Tuple marshal has its own tests
	want := netfilter.Attribute{Type: uint16(ctaExpectNATDir), Data: []byte{0, 0, 0, 1}}
	if diff := cmp.Diff(want, enm.Children[0]); diff != "" {
		t.Fatalf("unexpected ExpectNAT marshal (-want +got):\n%s", diff)
	}
}

func TestExpectTypeString(t *testing.T) {
	if expectType(255).String() == "" {
		t.Fatal("ExpectType string representation empty - did you run `go generate`?")
	}

	assert.Equal(t, "ctaExpectFN", ctaExpectFN.String())
}

func BenchmarkExpectUnmarshal(b *testing.B) {

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
