package conntrack

import (
	"errors"
	"github.com/gonetlink/netfilter"
	"github.com/mdlayher/netlink"
	"net"
	"reflect"
	"testing"
)

var (
	// Template attribute with Nested disabled
	attrDefault = netfilter.Attribute{Attribute: netlink.Attribute{Nested: false}}
	// Nested attribute without any children
	attrNoChildren = netfilter.Attribute{Attribute: netlink.Attribute{Nested: true}, Children: []netfilter.Attribute{}}
	// Nested attribute with one child
	attrOneChild = netfilter.Attribute{Attribute: netlink.Attribute{Nested: true}, Children: []netfilter.Attribute{attrDefault}}
	// Attribute with random, unused type 65535
	attrUnknown = netfilter.Attribute{Attribute: netlink.Attribute{Type: 0xFFFF}}
	// Nested structure of attributes with random, unused type 65535
	attrUnknownNested = netfilter.Attribute{Attribute: netlink.Attribute{Nested: true, Type: 0xFFFF},
		Children: []netfilter.Attribute{attrUnknown, attrUnknown}}
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
			Attribute: netlink.Attribute{
				Type:   0x1,
				Nested: true,
			},
			Children: []netfilter.Attribute{
				{
					// CTA_IP_V4_SRC
					Attribute: netlink.Attribute{
						Type: 0x1,
						Data: []byte{0x1, 0x2, 0x3, 0x4},
					},
				},
				{
					// CTA_IP_V4_DST
					Attribute: netlink.Attribute{
						Type: 0x2,
						Data: []byte{0x4, 0x3, 0x2, 0x1},
					},
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
			Attribute: netlink.Attribute{
				Type:   0x1,
				Nested: true,
			},
			Children: []netfilter.Attribute{
				{
					// CTA_IP_V6_SRC
					Attribute: netlink.Attribute{
						Length: 0x14,
						Type:   0x3,
						Data: []byte{0x0, 0x1, 0x0, 0x1,
							0x0, 0x2, 0x0, 0x2,
							0x0, 0x3, 0x0, 0x3,
							0x0, 0x4, 0x0, 0x4},
					},
				},
				{
					// CTA_IP_V6_DST
					Attribute: netlink.Attribute{
						Length: 0x14,
						Type:   0x4,
						Data: []byte{0x0, 0x4, 0x0, 0x4,
							0x0, 0x3, 0x0, 0x3,
							0x0, 0x2, 0x0, 0x2,
							0x0, 0x1, 0x0, 0x1},
					},
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
			Attribute: netlink.Attribute{
				Type:   0x1,
				Nested: false,
			},
		},
		err: errNotNested,
	},
	{
		name: "error incorrect amount of children",
		nfa: netfilter.Attribute{
			Attribute: netlink.Attribute{
				Type:   0x1,
				Nested: true,
			},
			Children: []netfilter.Attribute{attrDefault},
		},
		err: errors.New("error: UnmarshalAttribute - IPTuple expects exactly two children"),
	},
	{
		name: "error child incorrect length",
		nfa: netfilter.Attribute{
			Attribute: netlink.Attribute{
				Type:   0x1,
				Nested: true,
			},
			Children: []netfilter.Attribute{
				{
					// CTA_IP_V4_SRC
					Attribute: netlink.Attribute{
						Type: 0x1,
						Data: []byte{0x1, 0x2, 0x3, 0x4, 0x5},
					},
				},
				attrDefault,
			},
		},
		err: errIncorrectSize,
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
			Attribute: netlink.Attribute{
				Type:   0x1,
				Nested: true,
			},
			Children: []netfilter.Attribute{
				{
					// CTA_TUPLE_IP
					Attribute: netlink.Attribute{
						Type:   0x1,
						Nested: true,
					},
					Children: []netfilter.Attribute{
						{
							// CTA_IP_V6_SRC
							Attribute: netlink.Attribute{
								Length: 0x14,
								Type:   0x3,
								Data: []byte{0x0, 0x0, 0x0, 0x0,
									0x0, 0x0, 0x0, 0x0,
									0x0, 0x0, 0x0, 0x0,
									0x0, 0x0, 0x0, 0x1},
							},
						},
						{
							// CTA_IP_V6_DST
							Attribute: netlink.Attribute{
								Length: 0x14,
								Type:   0x4,
								Data: []byte{0x0, 0x0, 0x0, 0x0,
									0x0, 0x0, 0x0, 0x0,
									0x0, 0x0, 0x0, 0x0,
									0x0, 0x0, 0x0, 0x1},
							},
						},
					},
				},
				{
					// CTA_TUPLE_PROTO
					Attribute: netlink.Attribute{
						Type:   0x2,
						Nested: true,
					},
					Children: []netfilter.Attribute{
						{
							// CTA_PROTO_NUM
							Attribute: netlink.Attribute{
								Length: 0x5,
								Type:   0x1,
								Data:   []byte{0x6},
							},
						},
						{
							// CTA_PROTO_SRC_PORT
							Attribute: netlink.Attribute{
								Length: 0x6,
								Type:   0x2,
								Data:   []byte{0x80, 0xc},
							},
						},
						{
							// CTA_PROTO_DST_PORT
							Attribute: netlink.Attribute{
								Length: 0x6,
								Type:   0x3,
								Data:   []byte{0x0, 0x50},
							},
						},
					},
				},
				{
					// CTA_TUPLE_ZONE
					Attribute: netlink.Attribute{
						Length: 0x5,
						Type:   0x3,
						Data:   []byte{0x00, 0x7B}, // Zone 123
					},
				},
			},
		},
		cta: Tuple{
			IP: IPTuple{
				net.ParseIP("::1"),
				net.ParseIP("::1"),
			},
			Proto: ProtoTuple{6, 32780, 80},
			Zone:  0x7B, // Zone 123
		},
	},
	{
		name: "error reply tuple with incorrect zone size",
		nfa: netfilter.Attribute{
			// CTA_TUPLE_REPLY
			Attribute: netlink.Attribute{
				Type:   0x2,
				Nested: true,
			},
			Children: []netfilter.Attribute{
				{
					// CTA_TUPLE_ZONE
					Attribute: netlink.Attribute{
						Length: 0x8,
						Type:   0x3,
						Data:   []byte{0xAB, 0xCD, 0xEF, 0x01},
					},
				},
				// Order-dependent, this is to pad the length of Children.
				// Test should error before this attribute is parsed.
				attrDefault,
			},
		},
		err: errIncorrectSize,
	},
	{
		name: "error nested flag not set on attribute",
		nfa:  attrDefault,
		err:  errNotNested,
	},
	{
		name: "error too few children",
		nfa:  attrOneChild,
		err:  errNeedChildren,
	},
	{
		name: "error unknown tuple type",
		nfa:  attrUnknownNested,
		err:  errors.New("error: UnmarshalAttribute - unknown TupleType 65535"),
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
