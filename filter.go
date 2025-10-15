package conntrack

import (
	"github.com/ti-mo/netfilter"
)

// Filter is an object used to limit dump and flush operations to flows matching
// certain fields. Use [NewFilter] to create a new filter, then chain methods to
// set filter fields. Methods mutate the Filter in place and return it for
// chaining purposes.
//
// Pass a filter to [Conn.DumpFilter] or [Conn.FlushFilter].
type Filter interface {
	// Mark sets the connmark to filter on, similar to conntrack's --mark option.
	//
	// When not specifying a mark mask, the kernel defaults to 0xFFFFFFFF, meaning
	// the mark must match exactly. To specify a mark mask, use [Filter.MarkMask].
	Mark(mark uint32) Filter

	// MarkMask sets the connmark mask to apply before filtering on connmark,
	// similar to conntrack's --mark <mark>/<mask> option.
	//
	// If not specified, the kernel defaults to 0xFFFFFFFF, meaning the mark must
	// match exactly.
	MarkMask(mask uint32) Filter

	// Status sets the conntrack status bits to filter on, similar to conntrack's
	// -u/--status option.
	//
	// Requires Linux 5.15 or later.
	Status(status Status) Filter

	// StatusMask overrides the mask to apply before filtering on flow status.
	// Since Status is a bitfield, mask defaults to the mark value itself since
	// matching on the entire field would typically yield few matches. It's
	// recommended to leave this unset unless you have a specific need.
	//
	// Doesn't have an equivalent in the conntrack CLI.
	//
	// Requires Linux 5.15 or later.
	StatusMask(mask uint32) Filter

	// Zone sets the conntrack zone to filter on, similar to conntrack's -w/--zone
	// option.
	//
	// If not specified, flows from all zones are returned.
	//
	// Requires Linux 6.8 or later.
	Zone(zone uint16) Filter

	marshal() []netfilter.Attribute
}

// NewFilter returns an empty Filter.
func NewFilter() Filter {
	return &filter{f: make(map[attributeType][]byte)}
}

type filter struct {
	f map[attributeType][]byte
}

func (f *filter) Mark(mark uint32) Filter {
	f.f[ctaMark] = netfilter.Uint32Bytes(mark)
	return f
}

func (f *filter) MarkMask(mask uint32) Filter {
	f.f[ctaMarkMask] = netfilter.Uint32Bytes(mask)
	return f
}

func (f *filter) Status(status Status) Filter {
	f.f[ctaStatus] = netfilter.Uint32Bytes(uint32(status.Value))
	return f
}

func (f *filter) StatusMask(mask uint32) Filter {
	f.f[ctaStatusMask] = netfilter.Uint32Bytes(mask)
	return f
}

func (f *filter) Zone(zone uint16) Filter {
	f.f[ctaZone] = netfilter.Uint16Bytes(zone)
	return f
}

func (f *filter) marshal() []netfilter.Attribute {
	attrs := make([]netfilter.Attribute, 0, len(f.f))

	for t, v := range f.f {
		attrs = append(attrs, netfilter.Attribute{Type: uint16(t), Data: v})
	}

	return attrs
}
