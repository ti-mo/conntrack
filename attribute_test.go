package conntrack

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ti-mo/netfilter"
)

var (
	nfaBadType = netfilter.Attribute{Type: uint16(CTAUnspec)}
)

func TestAttribute_Helper(t *testing.T) {

	hlp := Helper{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAHelp)}

	assert.EqualError(t, hlp.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAHelp))
	assert.EqualError(t, hlp.UnmarshalAttribute(nfaNotNested), errNotNested.Error())

	nfaNameInfo := netfilter.Attribute{
		Type:   uint16(CTAHelp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAHelpName),
				Data: []byte("foo"),
			},
			{
				Type: uint16(CTAHelpInfo),
				Data: []byte{1, 2},
			},
		},
	}

	assert.Nil(t, hlp.UnmarshalAttribute(nfaNameInfo))

	nfaUnknownChild := netfilter.Attribute{
		Type:   uint16(CTAHelp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAHelpUnspec),
			},
		},
	}

	assert.EqualError(t, hlp.UnmarshalAttribute(nfaUnknownChild), fmt.Sprintf(errAttributeChild, CTAHelpUnspec, CTAHelp))
}

func TestAttribute_ProtoInfo(t *testing.T) {

	pi := ProtoInfo{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfo)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfo), Nested: true}

	assert.EqualError(t, pi.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfo))
	assert.EqualError(t, pi.UnmarshalAttribute(nfaNotNested), errNotNested.Error())
	assert.EqualError(t, pi.UnmarshalAttribute(nfaNestedNoChildren), errNeedSingleChild.Error())

	// TCP protocol info
	nfaInfoTCP := netfilter.Attribute{
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
						Data: []byte{0, 2},
					},
					{
						Type: uint16(CTAProtoInfoTCPFlagsReply),
						Data: []byte{0, 3},
					},
					{
						Type: uint16(CTAProtoInfoTCPWScaleOriginal),
						Data: []byte{0, 4},
					},
					{
						Type: uint16(CTAProtoInfoTCPWScaleReply),
						Data: []byte{0, 5},
					},
				},
			},
		},
	}

	nfaInfoTCPError := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(CTAProtoInfoTCP),
				Nested: false,
			},
		},
	}

	assert.Nil(t, pi.UnmarshalAttribute(nfaInfoTCP))
	assert.EqualError(t, pi.UnmarshalAttribute(nfaInfoTCPError), errNotNested.Error())

	// Not implemented
	nfaInfoDCCP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAProtoInfoDCCP),
			},
		},
	}

	nfaInfoSCTP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAProtoInfoSCTP),
			},
		},
	}

	assert.EqualError(t, pi.UnmarshalAttribute(nfaInfoDCCP), errNotImplemented.Error())
	assert.EqualError(t, pi.UnmarshalAttribute(nfaInfoSCTP), errNotImplemented.Error())

	// Unknown child attribute type
	nfaUnknownChild := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAProtoInfoUnspec),
			},
		},
	}

	assert.EqualError(t, pi.UnmarshalAttribute(nfaUnknownChild), fmt.Sprintf(errAttributeChild, CTAProtoInfoUnspec, CTAProtoInfo))
}

func TestAttribute_ProtoInfoTCP(t *testing.T) {

	pit := ProtoInfoTCP{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfoTCP)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfoTCP), Nested: true}

	assert.EqualError(t, pit.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfoTCP))
	assert.EqualError(t, pit.UnmarshalAttribute(nfaNotNested), errNotNested.Error())
	assert.EqualError(t, pit.UnmarshalAttribute(nfaNestedNoChildren), errNeedChildren.Error())

	nfaProtoInfoTCP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfoTCP),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAProtoInfoTCPState),
				Data: []byte{1},
			},
			{
				Type: uint16(CTAProtoInfoTCPFlagsOriginal),
				Data: []byte{0, 2},
			},
			{
				Type: uint16(CTAProtoInfoTCPFlagsReply),
				Data: []byte{0, 3},
			},
			{
				Type: uint16(CTAProtoInfoTCPWScaleOriginal),
				Data: []byte{0, 4},
			},
			{
				Type: uint16(CTAProtoInfoTCPWScaleReply),
				Data: []byte{0, 5},
			},
		},
	}

	nfaProtoInfoTCPError := netfilter.Attribute{
		Type:   uint16(CTAProtoInfoTCP),
		Nested: true,
		Children: []netfilter.Attribute{
			{Type: uint16(CTAProtoInfoTCPUnspec)},
			{Type: uint16(CTAProtoInfoTCPUnspec)},
			{Type: uint16(CTAProtoInfoTCPUnspec)},
		},
	}

	assert.Nil(t, pit.UnmarshalAttribute(nfaProtoInfoTCP))
	assert.EqualError(t, pit.UnmarshalAttribute(nfaProtoInfoTCPError), fmt.Sprintf(errAttributeChild, CTAProtoInfoTCPUnspec, CTAProtoInfoTCP))

}

func TestAttribute_Counters(t *testing.T) {

	ctr := Counter{}

	// Counters can be unmarshaled from both CTACountersOrig and CTACountersReply
	attrTypes := []AttributeType{CTACountersOrig, CTACountersReply}

	for _, at := range attrTypes {
		t.Run(at.String(), func(t *testing.T) {
			nfaNotNested := netfilter.Attribute{Type: uint16(at)}
			nfaNestedNoChildren := netfilter.Attribute{Type: uint16(at), Nested: true}

			assert.EqualError(t, ctr.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, ctaCountersOrigReplyCat))
			assert.EqualError(t, ctr.UnmarshalAttribute(nfaNotNested), errNotNested.Error())
			assert.EqualError(t, ctr.UnmarshalAttribute(nfaNestedNoChildren), fmt.Sprintf(errExactChildren, 2, ctaCountersOrigReplyCat))

			nfaCounter := netfilter.Attribute{
				Type:   uint16(at),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(CTACountersBytes),
						Data: make([]byte, 8),
					},
					{
						Type: uint16(CTACountersPackets),
						Data: make([]byte, 8),
					},
				},
			}

			nfaCounterError := netfilter.Attribute{
				Type:   uint16(at),
				Nested: true,
				Children: []netfilter.Attribute{
					{Type: uint16(CTACountersUnspec)},
					{Type: uint16(CTACountersUnspec)},
				},
			}

			assert.Nil(t, ctr.UnmarshalAttribute(nfaCounter))
			assert.EqualError(t, ctr.UnmarshalAttribute(nfaCounterError), fmt.Sprintf(errAttributeChild, CTACountersUnspec, ctaCountersOrigReplyCat))

			if at == CTACountersOrig {
				assert.Equal(t, "[orig: 0 pkts/0 B]", ctr.String())
			} else {
				assert.Equal(t, "[reply: 0 pkts/0 B]", ctr.String())
			}
		})
	}
}

func TestAttribute_Timestamp(t *testing.T) {

	ts := Timestamp{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTATimestamp)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTATimestamp), Nested: true}

	assert.EqualError(t, ts.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTATimestamp))
	assert.EqualError(t, ts.UnmarshalAttribute(nfaNotNested), errNotNested.Error())
	assert.EqualError(t, ts.UnmarshalAttribute(nfaNestedNoChildren), errNeedSingleChild.Error())

	nfaCounter := netfilter.Attribute{
		Type:   uint16(CTATimestamp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTATimestampStart),
				Data: make([]byte, 8),
			},
			{
				Type: uint16(CTATimestampStop),
				Data: make([]byte, 8),
			},
		},
	}

	nfaTimestampError := netfilter.Attribute{
		Type:   uint16(CTATimestamp),
		Nested: true,
		Children: []netfilter.Attribute{
			{Type: uint16(CTATimestampUnspec)},
		},
	}

	assert.Nil(t, ts.UnmarshalAttribute(nfaCounter))
	assert.EqualError(t, ts.UnmarshalAttribute(nfaTimestampError), fmt.Sprintf(errAttributeChild, CTATimestampUnspec, CTATimestamp))

}
