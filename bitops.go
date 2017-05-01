package conntrack

// An AttributeFilter is a bitfield used for selective decoding of
// netfilter.Attributes into Conntrack structures.
type AttributeFilter uint32

func (bf AttributeFilter) CheckBit(nr uint32) bool {
	if bf&(1<<nr) != 0 {
		return true
	}

	return false
}

func (bf *AttributeFilter) SetBit(nr uint32) error {
	nf := AttributeFilter(uint32(*bf) | 1<<nr)
	bf = &nf

	return nil
}
