package conntrack

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ti-mo/netfilter"
)

var (
	// Template attribute with Nested disabled
	attrDefault = netfilter.Attribute{Nested: false}
	// Attribute with random, unused type 16383
	attrUnknown = netfilter.Attribute{Type: 0x3FFF}
	// Nested structure of attributes with random, unused type 65535
	attrTupleUnknownNested = netfilter.Attribute{Type: uint16(ctaTupleOrig),
		Nested: true, Children: []netfilter.Attribute{attrUnknown, attrUnknown}}
	// Tuple attribute with Nested flag
	attrTupleNestedOneChild = netfilter.Attribute{Type: uint16(ctaTupleOrig),
		Nested: true, Children: []netfilter.Attribute{attrDefault}}
)

var ipTupleTests = []struct {
	name string
	nfa  netfilter.Attribute
	cta  IPTuple
	err  error
}{
	{
		name: "correct ipv4 tuple",
		nfa: netfilter.Attribute{
			Type:   uint16(ctaTupleIP),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// CTA_IP_V4_SRC
					Type: 0x1,
					Data: []byte{0x1, 0x2, 0x3, 0x4},
				},
				{
					// CTA_IP_V4_DST
					Type: 0x2,
					Data: []byte{0x4, 0x3, 0x2, 0x1},
				},
			},
		},
		cta: IPTuple{
			SourceAddress:      net.ParseIP("1.2.3.4"),
			DestinationAddress: net.ParseIP("4.3.2.1"),
		},
	},
	{
		name: "correct ipv6 tuple",
		nfa: netfilter.Attribute{
			Type:   uint16(ctaTupleIP),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// CTA_IP_V6_SRC
					Type: 0x3,
					Data: []byte{0x0, 0x1, 0x0, 0x1,
						0x0, 0x2, 0x0, 0x2,
						0x0, 0x3, 0x0, 0x3,
						0x0, 0x4, 0x0, 0x4},
				},
				{
					// CTA_IP_V6_DST
					Type: 0x4,
					Data: []byte{0x0, 0x4, 0x0, 0x4,
						0x0, 0x3, 0x0, 0x3,
						0x0, 0x2, 0x0, 0x2,
						0x0, 0x1, 0x0, 0x1},
				},
			},
		},
		cta: IPTuple{
			SourceAddress:      net.ParseIP("1:1:2:2:3:3:4:4"),
			DestinationAddress: net.ParseIP("4:4:3:3:2:2:1:1"),
		},
	},
	{
		name: "error incorrect amount of children",
		nfa: netfilter.Attribute{
			Type:     uint16(ctaTupleIP),
			Nested:   true,
			Children: []netfilter.Attribute{attrDefault},
		},
		err: errNeedChildren,
	},
	{
		name: "error child incorrect length",
		nfa: netfilter.Attribute{
			Type:   uint16(ctaTupleIP),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// CTA_IP_V4_SRC
					Type: 0x1,
					Data: []byte{0x1, 0x2, 0x3, 0x4, 0x5},
				},
				attrDefault,
			},
		},
		err: errIncorrectSize,
	},
	{
		name: "error iptuple unmarshal with unknown IPTupleType",
		nfa: netfilter.Attribute{
			Type:   uint16(ctaTupleIP),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// Unknown type
					Type: 0x3FFF,
					// Correct IP address length
					Data: []byte{0, 0, 0, 0},
				},
				// Padding
				attrDefault,
			},
		},
		err: errUnknownAttribute,
	},
}

func TestIPTupleMarshalTwoWay(t *testing.T) {
	for _, tt := range ipTupleTests {
		t.Run(tt.name, func(t *testing.T) {
			var ipt IPTuple
			err := ipt.unmarshal(mustDecodeAttributes(tt.nfa.Children))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.NoError(t, err)

			if diff := cmp.Diff(tt.cta, ipt); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}

			mipt, err := ipt.marshal()
			require.NoError(t, err, "error during marshal:", ipt)
			if diff := cmp.Diff(tt.nfa, mipt); diff != "" {
				t.Fatalf("unexpected marshal (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIPTupleMarshalError(t *testing.T) {
	v4v6Mismatch := IPTuple{
		SourceAddress:      net.ParseIP("1.2.3.4"),
		DestinationAddress: net.ParseIP("::1"),
	}

	_, err := v4v6Mismatch.marshal()
	require.ErrorIs(t, err, errBadIPTuple)
}

var protoTupleTests = []struct {
	name string
	nfa  netfilter.Attribute
	cta  ProtoTuple
	err  error
}{
	{
		name: "error unmarshal with wrong type",
		nfa: netfilter.Attribute{
			Type:     uint16(ctaTupleProto),
			Nested:   true,
			Children: []netfilter.Attribute{attrUnknown},
		},
		err: errUnknownAttribute,
	},
	{
		name: "error unmarshal with incorrect amount of children",
		nfa: netfilter.Attribute{
			Type:   uint16(ctaTupleProto),
			Nested: true,
		},
		err: errNeedSingleChild,
	},
	{
		name: "error unmarshal unknown ProtoTupleType",
		nfa: netfilter.Attribute{
			Type:   uint16(ctaTupleProto),
			Nested: true,
			Children: []netfilter.Attribute{
				attrUnknown,
				attrDefault,
				attrDefault,
			},
		},
		err: errUnknownAttribute,
	},
	{
		name: "correct icmpv4 prototuple",
		nfa: netfilter.Attribute{
			Type:   uint16(ctaTupleProto),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(ctaProtoNum),
					Data: []byte{unix.IPPROTO_ICMP},
				},
				{
					Type: uint16(ctaProtoICMPType),
					Data: []byte{0x1},
				},
				{
					Type: uint16(ctaProtoICMPCode),
					Data: []byte{0xf},
				},
				{
					Type: uint16(ctaProtoICMPID),
					Data: []byte{0x12, 0x34},
				},
			},
		},
		cta: ProtoTuple{
			Protocol: unix.IPPROTO_ICMP,
			ICMPv4:   true,
			ICMPType: 1,
			ICMPCode: 0xf,
			ICMPID:   0x1234,
		},
	},
	{
		name: "correct icmpv6 prototuple",
		nfa: netfilter.Attribute{
			Type:   uint16(ctaTupleProto),
			Nested: true,
			Children: []netfilter.Attribute{
				{
					Type: uint16(ctaProtoNum),
					Data: []byte{unix.IPPROTO_ICMPV6},
				},
				{
					Type: uint16(ctaProtoICMPv6Type),
					Data: []byte{0x2},
				},
				{
					Type: uint16(ctaProtoICMPv6Code),
					Data: []byte{0xe},
				},
				{
					Type: uint16(ctaProtoICMPv6ID),
					Data: []byte{0x56, 0x78},
				},
			},
		},
		cta: ProtoTuple{
			Protocol: unix.IPPROTO_ICMPV6,
			ICMPv6:   true,
			ICMPType: 2,
			ICMPCode: 0xe,
			ICMPID:   0x5678,
		},
	},
}

func TestProtoTupleMarshalTwoWay(t *testing.T) {
	for _, tt := range protoTupleTests {
		t.Run(tt.name, func(t *testing.T) {
			var pt ProtoTuple
			err := pt.unmarshal(mustDecodeAttributes(tt.nfa.Children))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.NoError(t, err)

			if diff := cmp.Diff(tt.cta, pt); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}

			mpt := pt.marshal()
			if diff := cmp.Diff(tt.nfa, mpt); diff != "" {
				t.Fatalf("unexpected marshal (-want +got):\n%s", diff)
			}
		})
	}
}

var tupleTests = []struct {
	name string
	nfa  netfilter.Attribute
	cta  Tuple
	err  error
}{
	{
		name: "complete orig dir tuple with ip, proto and zone",
		nfa: netfilter.Attribute{
			// CTA_TUPLE_ORIG
			Type:   0x1,
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// CTA_TUPLE_IP
					Type:   0x1,
					Nested: true,
					Children: []netfilter.Attribute{
						{
							// CTA_IP_V6_SRC
							Type: 0x3,
							Data: []byte{0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x1},
						},
						{
							// CTA_IP_V6_DST
							Type: 0x4,
							Data: []byte{0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x1},
						},
					},
				},
				{
					// CTA_TUPLE_PROTO
					Type:   0x2,
					Nested: true,
					Children: []netfilter.Attribute{
						{
							// CTA_PROTO_NUM
							Type: 0x1,
							Data: []byte{0x6},
						},
						{
							// CTA_PROTO_SRC_PORT
							Type: 0x2,
							Data: []byte{0x80, 0xc},
						},
						{
							// CTA_PROTO_DST_PORT
							Type: 0x3,
							Data: []byte{0x0, 0x50},
						},
					},
				},
				{
					// CTA_TUPLE_ZONE
					Type: 0x3,
					Data: []byte{0x00, 0x7B}, // Zone 123
				},
			},
		},
		cta: Tuple{
			IP: IPTuple{
				SourceAddress:      net.ParseIP("::1"),
				DestinationAddress: net.ParseIP("::1"),
			},
			Proto: ProtoTuple{6, 32780, 80, false, false, 0, 0, 0},
			Zone:  0x7B, // Zone 123
		},
	},
	{
		name: "error too few children",
		nfa:  attrTupleNestedOneChild,
		err:  errNeedChildren,
	},
	{
		name: "error unknown nested tuple type",
		nfa:  attrTupleUnknownNested,
		err:  errUnknownAttribute,
	},
}

func TestTupleMarshalTwoWay(t *testing.T) {
	for _, tt := range tupleTests {
		t.Run(tt.name, func(t *testing.T) {
			var tpl Tuple
			err := tpl.unmarshal(mustDecodeAttributes(tt.nfa.Children))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.NoError(t, err)

			if diff := cmp.Diff(tt.cta, tpl); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}

			mtpl, err := tpl.marshal(tt.nfa.Type)
			require.NoError(t, err, "error during marshal:", tpl)
			if diff := cmp.Diff(tt.nfa, mtpl); diff != "" {
				t.Fatalf("unexpected marshal (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTupleMarshalError(t *testing.T) {

	ipTupleError := Tuple{
		IP: IPTuple{
			SourceAddress:      net.ParseIP("1.2.3.4"),
			DestinationAddress: net.ParseIP("::1"),
		},
	}

	_, err := ipTupleError.marshal(uint16(ctaTupleOrig))
	require.ErrorIs(t, err, errBadIPTuple)
}

func TestTupleFilled(t *testing.T) {
	// Empty Tuple
	assert.Equal(t, false, Tuple{}.filled())

	// Tuple with empty IPTuple and ProtoTuples
	assert.Equal(t, false, Tuple{IP: IPTuple{}, Proto: ProtoTuple{}}.filled())

	// Tuple with empty ProtoTuple
	assert.Equal(t, false, Tuple{
		IP:    IPTuple{DestinationAddress: []byte{0}, SourceAddress: []byte{0}},
		Proto: ProtoTuple{},
	}.filled())

	// Tuple with empty IPTuple
	assert.Equal(t, false, Tuple{
		IP:    IPTuple{},
		Proto: ProtoTuple{Protocol: 6},
	}.filled())

	// Filled tuple with all minimum required fields set
	assert.Equal(t, true, Tuple{
		IP:    IPTuple{DestinationAddress: []byte{0}, SourceAddress: []byte{0}},
		Proto: ProtoTuple{Protocol: 6},
	}.filled())
}

func TestTupleIPv6(t *testing.T) {
	var ipt IPTuple

	// Uninitialized Tuple cannot be IPv6 (nor IPv4)
	assert.Equal(t, false, ipt.IsIPv6())

	// Non-matching address lengths are not considered an IPv6 tuple
	ipt.SourceAddress = net.ParseIP("1.2.3.4")
	ipt.DestinationAddress = net.ParseIP("::1")
	assert.Equal(t, false, ipt.IsIPv6())

	ipt.SourceAddress = net.ParseIP("::2")
	assert.Equal(t, true, ipt.IsIPv6())
}

func TestTupleTypeString(t *testing.T) {

	if tupleType(255).String() == "" {
		t.Fatal("TupleType string representation empty - did you run `go generate`?")
	}
}
