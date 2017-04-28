package conntrack

import (
	"encoding/binary"
)

type Status struct {
	Expected bool
	SeenReply bool
	Assured bool
	Confirmed bool
	SrcNat bool
	DstNat bool
	SeqAdjust bool
	SrcNatDone bool
	DstNatDone bool
	Dying bool
	FixedTimeout bool
	Template bool
	Untracked bool

	value uint32
}

func (s Status) String() string {
	names := []string{
		"EXPECTED",
		"SEEN_REPLY",
		"ASSURED",
		"CONFIRMED",
		"SRC_NAT",
		"DST_NAT",
		"NAT_MASK",
		"SEQ_ADJUST",
		"SRC_NAT_DONE",
		"DST_NAT_DONE",
		"NAT_DONE_MASK",
		"DYING",
		"FIXED_TIMEOUT",
		"TEMPLATE",
		"UNTRACKED",
	}

	var rs string

	// Loop over the field's bits
	for i, name := range names {
		if s.value & (1 << uint32(i)) != 0 {
			if rs != "" {
				rs += "|"
			}
			rs += name
		}
	}

	// Set default value if none of the flags were set
	if rs == "" {
		rs = "DEFAULT"
	}

	return rs
}

func (s *Status) UnmarshalBinary(b []byte) error {

	if len(b) != 4 {
		return errIncorrectSize
	}

	si := binary.BigEndian.Uint32(b)

	if si & IPS_EXPECTED != 0 { s.Expected = true }
	if si & IPS_SEEN_REPLY != 0 { s.SeenReply = true }
	if si & IPS_ASSURED != 0 { s.Assured = true }
	if si & IPS_CONFIRMED != 0 { s.Confirmed = true	}
	if si & IPS_SRC_NAT != 0 { s.SrcNat = true }
	if si & IPS_DST_NAT != 0 { s.DstNat = true }
	if si & IPS_SEQ_ADJUST != 0 { s.SeqAdjust = true }
	if si & IPS_SRC_NAT_DONE != 0 { s.SrcNatDone = true }
	if si & IPS_DST_NAT_DONE != 0 {	s.SrcNatDone = true }
	if si & IPS_DYING != 0 { s.Dying = true	}
	if si & IPS_FIXED_TIMEOUT != 0 { s.FixedTimeout = true }
	if si & IPS_TEMPLATE != 0 { s.Template = true }
	if si & IPS_UNTRACKED != 0 { s.Untracked = true	}

	s.value = si

	return nil
}

func (s Status) MarshalBinary() ([]byte, error) {
	return nil, errNotImplemented
}

// This is based on enum ip_conntrack_status
// Linux/uapi/linux/netfilter/nf_conntrack_common.h
const (
	// It's an expected connection: bit 0 set.  This bit never changed
	IPS_EXPECTED = 1

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	IPS_SEEN_REPLY = 1 << 1

	/* Conntrack should never be early-expired. */
	IPS_ASSURED = 1 << 2

	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED = 1 << 3

	/* Connection needs src nat in orig dir.  This bit never changed. */
	IPS_SRC_NAT = 1 << 4

	/* Connection needs dst nat in orig dir.  This bit never changed. */
	IPS_DST_NAT = 1 << 5

	/* Both together. */
	IPS_NAT_MASK = IPS_DST_NAT | IPS_SRC_NAT

	/* Connection needs TCP sequence adjusted. */
	IPS_SEQ_ADJUST = 1 << 6

	/* NAT initialization bits. */
	IPS_SRC_NAT_DONE = 1 << 7
	IPS_DST_NAT_DONE = 1 << 8

	/* Both together */
	IPS_NAT_DONE_MASK = IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE

	/* Connection is dying (removed from lists), can not be unset. */
	IPS_DYING = 1 << 9

	/* Connection has fixed timeout. */
	IPS_FIXED_TIMEOUT = 1 << 10

	/* Conntrack is a template */
	IPS_TEMPLATE = 1 << 11

	/* Conntrack is a fake untracked entry */
	IPS_UNTRACKED = 1 << 12
)
