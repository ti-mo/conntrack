package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ti-mo/netfilter"
)

func TestFilterMarshal(t *testing.T) {

	f := Filter{Mark: 0xf0000000, Mask: 0x0000000f}
	fm := []netfilter.Attribute{
		{
			Type: uint16(ctaMark),
			Data: []byte{0xf0, 0, 0, 0},
		},
		{
			Type: uint16(ctaMarkMask),
			Data: []byte{0, 0, 0, 0x0f},
		},
	}

	assert.Equal(t, fm, f.marshal(), "unexpected Filter marshal")
}

func TestFilterMarshalZoneOnly(t *testing.T) {
	zone := uint16(123)
	f := Filter{Zone: &zone}
	fm := []netfilter.Attribute{
		{
			Type: uint16(ctaMark),
			Data: []byte{0, 0, 0, 0},
		},
		{
			Type: uint16(ctaMarkMask),
			Data: []byte{0, 0, 0, 0},
		},
		{
			Type: uint16(ctaZone),
			Data: []byte{0, 123},
		},
	}

	assert.Equal(t, fm, f.marshal(), "unexpected Filter marshal")
}

func TestFilterMarshalMarkAndZone(t *testing.T) {
	zone := uint16(42)
	f := Filter{Mark: 0xf0000000, Mask: 0x0000000f, Zone: &zone}
	fm := []netfilter.Attribute{
		{
			Type: uint16(ctaMark),
			Data: []byte{0xf0, 0, 0, 0},
		},
		{
			Type: uint16(ctaMarkMask),
			Data: []byte{0, 0, 0, 0x0f},
		},
		{
			Type: uint16(ctaZone),
			Data: []byte{0, 42},
		},
	}

	assert.Equal(t, fm, f.marshal(), "unexpected Filter marshal")
}
