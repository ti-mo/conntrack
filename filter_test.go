package conntrack

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ti-mo/netfilter"
)

func TestFilterMarshal(t *testing.T) {
	f := NewFilter().
		Mark(0xf0000000).MarkMask(0x0000000f).
		Zone(42).
		Status(StatusDying).StatusMask(0xdeadbeef)

	want := []netfilter.Attribute{
		{
			Type: uint16(ctaStatus),
			Data: []byte{0, 0, 0x2, 0},
		},
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
		{
			Type: uint16(ctaStatusMask),
			Data: []byte{0xde, 0xad, 0xbe, 0xef},
		},
	}

	got := f.marshal()
	slices.SortStableFunc(got, func(a, b netfilter.Attribute) int {
		return int(a.Type) - int(b.Type)
	})

	assert.Equal(t, want, got)
}

func TestFilterMutate(t *testing.T) {
	f := NewFilter().
		Mark(1).
		Family(1)

	mod := f.
		Mark(2).
		Family(2)

	// Ensure original filter is unchanged.
	assert.NotEqual(t, f, mod)
	assert.Equal(t, []byte{0, 0, 0, 1}, f.(*filter).f[ctaMark])
	assert.Equal(t, netfilter.ProtoFamily(1), f.(*filter).l3)

	assert.Equal(t, []byte{0, 0, 0, 2}, mod.(*filter).f[ctaMark])
	assert.Equal(t, netfilter.ProtoFamily(2), mod.(*filter).l3)
}
