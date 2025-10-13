package conntrack

import (
	"github.com/ti-mo/netfilter"
)

// Filter is a structure used in dump operations to filter the response
// based on a given connmark and mask. The mask is applied to the Mark field of
// all flows in the conntrack table, the result is compared to the filter's Mark.
// Each flow that matches will be returned by the kernel.
// Zone can be used to filter connections by conntrack zone.
type Filter struct {
	Mark, Mask uint32
	// Requires at least Linux 6.8.
	// If omitted, the default behavior is to consider ALL zones.
	Zone *uint16
}

// marshal marshals a Filter into a list of netfilter.Attributes.
func (f Filter) marshal() []netfilter.Attribute {
	attrs := []netfilter.Attribute{
		{
			Type: uint16(ctaMark),
			Data: netfilter.Uint32Bytes(f.Mark),
		},
		{
			Type: uint16(ctaMarkMask),
			Data: netfilter.Uint32Bytes(f.Mask),
		},
	}

	// Add CTA_ZONE attribute if Zone is specified
	if f.Zone != nil {
		attrs = append(attrs, netfilter.Attribute{
			Type: uint16(ctaZone),
			Data: netfilter.Uint16Bytes(*f.Zone),
		})
	}

	return attrs
}
