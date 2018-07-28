package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilter_AttributeFilter(t *testing.T) {

	var af AttributeFilter

	// AttributeFilter is a bitfield of 32 bits, so can represent values 0-31
	assert.Panics(t, func() { af.CheckType(0x32) })
	assert.Panics(t, func() { af.SetType(0x32) })

	// A default AttributeFilter will answer positively to any checks
	assert.Equal(t, true, af.CheckType(CTAUnspec))

	// Set and check a type in the bitfield
	af.SetType(CTALabels)
	assert.Equal(t, true, af.CheckType(CTALabels))

}
