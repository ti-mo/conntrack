package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ti-mo/netfilter"
)

var (
	nfaBadType = netfilter.Attribute{Type: 0}
)

func TestAttribute_Helper(t *testing.T) {

	hlp := Helper{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAHelp)}

	assert.NotNil(t, hlp.UnmarshalAttribute(nfaBadType))
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

	nfaUnknown := netfilter.Attribute{
		Type:   uint16(CTAHelp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: 0xffff,
			},
		},
	}

	assert.NotNil(t, hlp.UnmarshalAttribute(nfaUnknown))
}
