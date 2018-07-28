package conntrack

import (
	"testing"

	"github.com/ti-mo/netfilter"
)

func TestAttribute_Helper(t *testing.T) {

	hlp := Helper{}

	nfaBadType := netfilter.Attribute{Type: 0}
	nfaNotNested := netfilter.Attribute{Type: uint16(CTAHelp)}

	if err := hlp.UnmarshalAttribute(nfaBadType); err == nil {
		t.Fatal("expected error")
	}
	if err := hlp.UnmarshalAttribute(nfaNotNested); err != errNotNested {
		t.Fatalf("expected errNotNested")
	}

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

	err := hlp.UnmarshalAttribute(nfaNameInfo)
	if err != nil {
		t.Fatalf("unmarshal failed with error: %s", err.Error())
	}

	nfaUnknown := netfilter.Attribute{
		Type:   uint16(CTAHelp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: 0xffff,
			},
		},
	}

	if err := hlp.UnmarshalAttribute(nfaUnknown); err == nil {
		t.Fatal("expected error")
	}
}
