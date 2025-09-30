package conntrack

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ti-mo/netfilter"
)

func TestFilterMarshal(t *testing.T) {
	f := NewFilter().Mark(0xf0000000).MarkMask(0x0000000f).Zone(42)
	want := []netfilter.Attribute{
		{
			Type: uint16(ctaMark),
			Data: []byte{0xf0, 0, 0, 0},
		},
		{
			Type: uint16(ctaZone),
			Data: []byte{0, 42},
		},
		{
			Type: uint16(ctaMarkMask),
			Data: []byte{0, 0, 0, 0x0f},
		},
	}

	got := f.marshal()
	slices.SortStableFunc(got, func(a, b netfilter.Attribute) int {
		return int(a.Type) - int(b.Type)
	})

	assert.Equal(t, want, got)
}
