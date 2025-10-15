package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ti-mo/netfilter"
)

func TestFilterMarkMask(t *testing.T) {
	f := NewFilter().Mark(0xf0000000).MarkMask(0x0000000f)
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
