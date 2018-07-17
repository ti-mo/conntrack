package conntrack

// An AttributeFilter is a bitfield used for selective decoding of
// netfilter.Attributes into Conntrack structures.
type AttributeFilter uint32

// CheckBit checks whether the nr'th bit of the AttributeFilter is enabled.
func (bf AttributeFilter) CheckBit(nr uint32) bool {
	return bf&(1<<nr) != 0
}

// SetBit enables the nr'th bit of the AttributeFilter.
func (bf *AttributeFilter) SetBit(nr uint32) {
	nf := AttributeFilter(uint32(*bf) | 1<<nr)
	bf = &nf
}
