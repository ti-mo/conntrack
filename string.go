//+build !test

package conntrack

import "fmt"

// This file contains string representation composition
// of all structures in the package. It's excluded from test coverage.

func (s Status) String() string {
	names := []string{
		"EXPECTED",
		"SEEN_REPLY",
		"ASSURED",
		"CONFIRMED",
		"SRC_NAT",
		"DST_NAT",
		"SEQ_ADJUST",
		"SRC_NAT_DONE",
		"DST_NAT_DONE",
		"DYING",
		"FIXED_TIMEOUT",
		"TEMPLATE",
		"UNTRACKED",
	}

	var rs string

	// Loop over the field's bits
	for i, name := range names {
		if s.value&(1<<uint32(i)) != 0 {
			if rs != "" {
				rs += "|"
			}
			rs += name
		}
	}

	// Set default value if none of the flags were set
	if rs == "" {
		rs = fmt.Sprintf("DEFAULT|%.8b", s.value)
	}

	return rs
}
