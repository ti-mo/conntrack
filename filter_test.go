package conntrack

import (
	"testing"

	"github.com/ti-mo/netfilter"

	"github.com/google/go-cmp/cmp"
)

func TestFilterMarshal(t *testing.T) {

	f := Filter{Mark: 0xf0000000, Mask: 0x0000000f}
	fm := []netfilter.Attribute{
		{
			Type: uint16(CTAMark),
			Data: []byte{0xf0, 0, 0, 0},
		},
		{
			Type: uint16(CTAMarkMask),
			Data: []byte{0, 0, 0, 0x0f},
		},
	}

	if diff := cmp.Diff(fm, f.marshal()); diff != "" {
		t.Fatalf("unexpected Filter marshal (-want +got):\n%s", diff)
	}
}
