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
