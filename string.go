package conntrack

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
		"HELPER",
		"OFFLOAD",
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

	if rs == "" {
		rs = "NONE"
	}

	return rs
}
