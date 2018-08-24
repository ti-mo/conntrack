package conntrack

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/pkg/errors"

	"github.com/ti-mo/netfilter"
)

var (
	// Template attribute with Nested disabled
	attrDefault = netfilter.Attribute{Nested: false}
	// Nested attribute without any children
	attrNoChildren = netfilter.Attribute{Nested: true, Children: []netfilter.Attribute{}}
	// Nested attribute with one child
	attrOneChild = netfilter.Attribute{Nested: true, Children: []netfilter.Attribute{attrDefault}}
	// Attribute with random, unused type 65535
	attrUnknown = netfilter.Attribute{Type: 0xFFFF}
	// Nested structure of attributes with random, unused type 65535
	attrTupleUnknownNested = netfilter.Attribute{Type: uint16(CTATupleOrig), Nested: true,
		Children: []netfilter.Attribute{attrUnknown, attrUnknown}}
	// Tuple attribute without Nested flag
	attrTupleNotNested = netfilter.Attribute{Type: uint16(CTATupleOrig)}
	// Tuple attribute with Nested flag
	attrTupleNestedOneChild = netfilter.Attribute{Type: uint16(CTATupleOrig), Nested: true, Children: []netfilter.Attribute{attrDefault}}
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
			Type:   0x1,
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
			net.ParseIP("1.2.3.4"),
			net.ParseIP("4.3.2.1"),
		},
	},
	{
		name: "correct ipv6 tuple",
		nfa: netfilter.Attribute{
			Type:   0x1,
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// CTA_IP_V6_SRC
					Length: 0x14,
					Type:   0x3,
					Data: []byte{0x0, 0x1, 0x0, 0x1,
						0x0, 0x2, 0x0, 0x2,
						0x0, 0x3, 0x0, 0x3,
						0x0, 0x4, 0x0, 0x4},
				},
				{
					// CTA_IP_V6_DST
					Length: 0x14,
					Type:   0x4,
					Data: []byte{0x0, 0x4, 0x0, 0x4,
						0x0, 0x3, 0x0, 0x3,
						0x0, 0x2, 0x0, 0x2,
						0x0, 0x1, 0x0, 0x1},
				},
			},
		},
		cta: IPTuple{
			net.ParseIP("1:1:2:2:3:3:4:4"),
			net.ParseIP("4:4:3:3:2:2:1:1"),
		},
	},
	{
		name: "error nested flag not set on attribute",
		nfa: netfilter.Attribute{
			Type:   0x1,
			Nested: false,
		},
		err: errors.Wrap(errNotNested, opUnIPTup),
	},
	{
		name: "error incorrect amount of children",
		nfa: netfilter.Attribute{
			Type:     0x1,
			Nested:   true,
			Children: []netfilter.Attribute{attrDefault},
		},
		err: errors.Wrap(errNeedChildren, opUnIPTup),
	},
	{
		name: "error child incorrect length",
		nfa: netfilter.Attribute{
			Type:   0x1,
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
		name: "error iptuple unmarshal with wrong type",
		nfa:  attrUnknown,
		err:  fmt.Errorf(errAttributeWrongType, attrUnknown.Type, CTATupleIP),
	},
	{
		name: "error iptuple unmarshal with unknown IPTupleType",
		nfa: netfilter.Attribute{
			// CTA_TUPLE_IP
			Type:   0x1,
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// Unknown type
					Type: 0xFFFF,
					// Correct IP address length
					Data: []byte{0, 0, 0, 0},
				},
				// Padding
				attrDefault,
			},
		},
		err: errors.Wrap(fmt.Errorf(errAttributeChild, 0xFFFF, CTATupleIP), opUnIPTup),
	},
}

var protoTupleTests = []struct {
	name string
	nfa  netfilter.Attribute
	cta  ProtoTuple
	err  error
}{
	{
		name: "error unmarshal with wrong type",
		nfa:  attrUnknown,
		err:  fmt.Errorf(errAttributeWrongType, attrUnknown.Type, CTATupleProto),
	},
	{
		name: "error unmarshal with incorrect amount of children",
		nfa: netfilter.Attribute{
			// CTA_TUPLE_PROTO
			Type:   0x2,
			Nested: true,
		},
		err: errors.Wrap(errNeedSingleChild, opUnPTup),
	},
	{
		name: "error unmarshal unknown ProtoTupleType",
		nfa: netfilter.Attribute{
			// CTA_TUPLE_PROTO
			Type:   0x2,
			Nested: true,
			Children: []netfilter.Attribute{
				attrUnknown,
				attrDefault,
				attrDefault,
			},
		},
		err: errors.Wrap(fmt.Errorf(errAttributeChild, attrUnknown.Type, CTATupleProto), opUnPTup),
	},
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
							Length: 0x14,
							Type:   0x3,
							Data: []byte{0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x1},
						},
						{
							// CTA_IP_V6_DST
							Length: 0x14,
							Type:   0x4,
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
							Length: 0x5,
							Type:   0x1,
							Data:   []byte{0x6},
						},
						{
							// CTA_PROTO_SRC_PORT
							Length: 0x6,
							Type:   0x2,
							Data:   []byte{0x80, 0xc},
						},
						{
							// CTA_PROTO_DST_PORT
							Length: 0x6,
							Type:   0x3,
							Data:   []byte{0x0, 0x50},
						},
					},
				},
				{
					// CTA_TUPLE_ZONE
					Length: 0x5,
					Type:   0x3,
					Data:   []byte{0x00, 0x7B}, // Zone 123
				},
			},
		},
		cta: Tuple{
			IP: IPTuple{
				net.ParseIP("::1"),
				net.ParseIP("::1"),
			},
			Proto: ProtoTuple{6, 32780, 80, false, false, 0, 0, 0},
			Zone:  0x7B, // Zone 123
		},
	},
	{
		name: "error reply tuple with incorrect zone size",
		nfa: netfilter.Attribute{
			// CTA_TUPLE_REPLY
			Type:   0x2,
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// CTA_TUPLE_ZONE
					Length: 0x8,
					Type:   0x3,
					Data:   []byte{0xAB, 0xCD, 0xEF, 0x01},
				},
				// Order-dependent, this is to pad the length of Children.
				// Test should error before this attribute is parsed.
				attrDefault,
			},
		},
		err: errIncorrectSize,
	},
	{
		name: "error returned from iptuple unmarshal",
		nfa: netfilter.Attribute{
			// CTA_TUPLE_ORIG
			Type:   0x1,
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// CTA_TUPLE_IP
					Type: 0x1,
				},
				// Padding element
				attrDefault,
			},
		},
		err: errors.Wrap(errNotNested, opUnIPTup),
	},
	{
		name: "error returned from prototuple unmarshal",
		nfa: netfilter.Attribute{
			// CTA_TUPLE_ORIG
			Type:   0x1,
			Nested: true,
			Children: []netfilter.Attribute{
				{
					// CTA_TUPLE_PROTO
					Type: 0x2,
				},
				// Padding element
				attrDefault,
			},
		},
		err: errors.Wrap(errNotNested, opUnPTup),
	},
	{
		name: "error wrong tuple type",
		nfa:  attrDefault,
		err:  errors.Wrap(fmt.Errorf(errAttributeWrongType, attrDefault.Type, ctaTupleOrigReplyMasterCat), opUnTup),
	},
	{
		name: "error nested flag not set on tuple",
		nfa:  attrTupleNotNested,
		err:  errors.Wrap(errNotNested, opUnTup),
	},
	{
		name: "error too few children",
		nfa:  attrTupleNestedOneChild,
		err:  errors.Wrap(errNeedChildren, opUnTup),
	},
	{
		name: "error unknown nested tuple type",
		nfa:  attrTupleUnknownNested,
		err:  errors.Wrap(fmt.Errorf(errAttributeChild, attrTupleUnknownNested.Children[0].Type, CTATupleOrig), opUnTup),
	},
}

func TestIPTuple_UnmarshalAttribute(t *testing.T) {
	for _, test := range ipTupleTests {

		t.Run(test.name, func(t *testing.T) {

			// Unmarshal the test's netfilter.Attribute into an IPTuple
			var attr IPTuple

			err := (&attr).UnmarshalAttribute(test.nfa)

			// Compare the error result to the test's 'err' field
			if want, got := test.err, err; want != nil && got != nil {
				// Both are set, try to compare their Error()s
				if want.Error() != got.Error() {
					t.Fatalf("mismatching errors:\n- want: %v\n-  got: %v",
						want.Error(), got.Error())
				}
			} else if want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}

			if want, got := test.cta, attr; !want.DestinationAddress.Equal(got.DestinationAddress) ||
				!want.SourceAddress.Equal(got.SourceAddress) {
				t.Fatalf("unexpected attribute:\n- want: %v (%p)\n-  got: %v (%p)",
					want, want, got, got)
			}
		})
	}
}

func TestProtoTuple_UnmarshalAttribute(t *testing.T) {
	for _, test := range protoTupleTests {

		t.Run(test.name, func(t *testing.T) {

			// Unmarshal the test's netfilter.Attribute into an IPTuple
			var attr ProtoTuple

			err := (&attr).UnmarshalAttribute(test.nfa)

			// Compare the error result to the test's 'err' field
			if want, got := test.err, err; want != nil && got != nil {
				// Both are set, try to compare their Error()s
				if want.Error() != got.Error() {
					t.Fatalf("mismatching errors:\n- want: %v\n-  got: %v",
						want.Error(), got.Error())
				}
			} else if want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}

			if want, got := test.cta, attr; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected attribute:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}

func TestTuple_UnmarshalAttribute(t *testing.T) {
	for _, test := range tupleTests {

		t.Run(test.name, func(t *testing.T) {

			// Unmarshal the test's netfilter.Attribute into a Tuple
			var attr Tuple

			err := (&attr).UnmarshalAttribute(test.nfa)

			// Compare the error result to the test's 'err' field
			if want, got := test.err, err; want != nil && got != nil {
				// Both are set, try to compare their Error()s
				if want.Error() != got.Error() {
					t.Fatalf("mismatching errors:\n- want: %v\n-  got: %v",
						want.Error(), got.Error())
				}
			} else if want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}

			if want, got := test.cta, attr; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected attribute:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}
