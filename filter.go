package conntrack

const (
	errAttrTypeTooLarge = "AttributeType too large for AttributeFilter bitfield"
)

// An AttributeFilter is a bitfield used for selective decoding of
// netfilter.Attributes into Conntrack structures.
type AttributeFilter uint32

// Check checks whether the AttributeType is whitelisted in the filter.
// Panics if the type value is larger than 31. Always returns true if the
// filter is 0. (default)
func (af AttributeFilter) Check(t AttributeType) bool {

	if t > 31 {
		panic(errAttrTypeTooLarge)
	}

	// Filter uninitialized/default, return true
	if af == 0 {
		return true
	}

	return af&(1<<t) != 0
}

// Set takes a list of AttributeTypes and flags them in the filter. Re-initializes the filter
// before setting flags. Panics if any type value is larger than 31.
func (af *AttributeFilter) Set(types ...AttributeType) {

	*af = 0

	for _, t := range types {
		if t > 31 {
			panic(errAttrTypeTooLarge)
		}
		*af = AttributeFilter(uint32(*af) | 1<<t)
	}
}
