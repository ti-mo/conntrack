package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ti-mo/netfilter"
)

var (
	corpusExpect = []struct {
		name  string
		attrs []netfilter.Attribute
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
		},
		{
			name: "master/tuple/mask tuple attributes",
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
		},
	}
)

func TestExpect_Unmarshal(t *testing.T) {

	var ex Expect

	for _, tt := range corpusExpect {
		t.Run(tt.name, func(t *testing.T) {
			err := ex.unmarshal(tt.attrs)
			if err != nil {
				t.Fatalf("unmarshal error: %v", err)
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
