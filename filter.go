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
func (af AttributeFilter) CheckType(t AttributeType) bool {

	if t > 31 {
		panic(errAttrTypeTooLarge)
	}

	// Filter uninitialized/default, return true
	if af == 0 {
		return true
	}

	return af&(1<<t) != 0
}

// SetType whitelists an AttributeType's bit in the filter.
// Panics if the type value is larger than 31.
func (af *AttributeFilter) SetType(t AttributeType) {

	if t > 31 {
		panic(errAttrTypeTooLarge)
	}

	*af = AttributeFilter(uint32(*af) | 1<<t)
}
