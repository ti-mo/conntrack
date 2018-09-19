package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterAttributeFilter(t *testing.T) {

	var af AttributeFilter

	// AttributeFilter is a bitfield of 32 bits, so can represent values 0-31
	assert.Panics(t, func() { af.Check(0x32) })
	assert.Panics(t, func() { af.Set(0x32) })

	// A default AttributeFilter will answer positively to any checks
	assert.Equal(t, true, af.Check(CTAUnspec))

	// Set and check some types in the bitfield
	af.Set(CTAZone, CTACountersReply)
	assert.Equal(t, true, af.Check(CTAZone))
	assert.Equal(t, true, af.Check(CTACountersReply))

	// Make sure Set() zeroes the bitfield before writing
	af.Set(CTAHelp)
	assert.Equal(t, true, af.Check(CTAHelp))
	assert.Equal(t, false, af.Check(CTAZone)) // Erased by Set(CTAHelp)

}
