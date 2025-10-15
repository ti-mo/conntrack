package conntrack

import (
	"github.com/ti-mo/netfilter"
)

// Filter is an object used to limit dump and flush operations to flows matching
// certain fields. Use [NewFilter] to create a new filter, then chain methods to
// set filter fields.
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

func (f *filter) marshal() []netfilter.Attribute {
	attrs := make([]netfilter.Attribute, 0, len(f.f))

	for t, v := range f.f {
		attrs = append(attrs, netfilter.Attribute{Type: uint16(t), Data: v})
	}

	return attrs
}
