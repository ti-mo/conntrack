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
}
