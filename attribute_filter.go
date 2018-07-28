package conntrack

const (
	errAttrTypeTooLarge = "AttributeType too large for AttributeFilter bitfield"
)

// An AttributeFilter is a bitfield used for selective decoding of
// netfilter.Attributes into Conntrack structures.
type AttributeFilter uint32

// CheckType checks whether the AttributeType is whitelisted in the filter.
// Panics if the type value is larger than 31. Always returns true if the
// filter is 0. (default)
func (bf AttributeFilter) CheckType(t AttributeType) bool {

	if t > 31 {
		panic(errAttrTypeTooLarge)
	}

	// Filter uninitialized/default, return true
	if bf == 0 {
		return true
	}

	return bf&(1<<t) != 0
}

// SetType whitelists an AttributeType's bit in the filter.
// Panics if the type value is larger than 31.
func (bf *AttributeFilter) SetType(t AttributeType) {

	if t > 31 {
		panic(errAttrTypeTooLarge)
	}

	nf := AttributeFilter(uint32(*bf) | 1<<t)
	bf = &nf
}
