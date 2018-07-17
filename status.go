package conntrack

import (
	"encoding/binary"
	"fmt"

	"github.com/ti-mo/netfilter"
)

// Status represents a snapshot of a conntrack connection's state.
type Status struct {
	Expected     bool
	SeenReply    bool
	Assured      bool
	Confirmed    bool
	SrcNat       bool
	DstNat       bool
	SeqAdjust    bool
	SrcNatDone   bool
	DstNatDone   bool
	Dying        bool
	FixedTimeout bool
	Template     bool
	Untracked    bool

	value uint32
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a Status structure.
func (s *Status) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTA_STATUS {
		return fmt.Errorf("error: UnmarshalAttribute - %v is not a CTA_STATUS", attr.Type)
	}

	if attr.Nested {
		return errNested
	}

	if len(attr.Data) != 4 {
		return errIncorrectSize
	}

	si := binary.BigEndian.Uint32(attr.Data)

	if si&IPSExpected != 0 {
		s.Expected = true
	}
	if si&IPSSeenReply != 0 {
		s.SeenReply = true
	}
	if si&IPSAssured != 0 {
		s.Assured = true
	}
	if si&IPSConfirmed != 0 {
		s.Confirmed = true
	}
	if si&IPSSrcNat != 0 {
		s.SrcNat = true
	}
	if si&IPSDstNat != 0 {
		s.DstNat = true
	}
	if si&IPSSeqAdjust != 0 {
		s.SeqAdjust = true
	}
	if si&IPSSrcNatDone != 0 {
		s.SrcNatDone = true
	}
	if si&IPSDstNatDone != 0 {
		s.DstNatDone = true
	}
	if si&IPSDying != 0 {
		s.Dying = true
	}
	if si&IPSFixedTimeout != 0 {
		s.FixedTimeout = true
	}
	if si&IPSTemplate != 0 {
		s.Template = true
	}
	if si&IPSUntracked != 0 {
		s.Untracked = true
	}

	s.value = si

	return nil
}

// Conntrack connection's status flags, from enum ip_conntrack_status.
// uapi/linux/netfilter/nf_conntrack_common.h
const (

	// It's an expected connection: bit 0 set.  This bit never changed
	IPSExpected = 1 // IPS_EXPECTED

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	IPSSeenReply = 1 << 1 // IPS_SEEN_REPLY

	/* Conntrack should never be early-expired. */
	IPSAssured = 1 << 2 // IPS_ASSURED

	/* Connection is confirmed: originating packet has left box */
	IPSConfirmed = 1 << 3 // IPS_CONFIRMED

	/* Connection needs src nat in orig dir.  This bit never changed. */
	IPSSrcNat = 1 << 4 // IPS_SRC_NAT

	/* Connection needs dst nat in orig dir.  This bit never changed. */
	IPSDstNat = 1 << 5 // IPS_DST_NAT

	/* Both together. */
	IPSNatMask = IPSDstNat | IPSSrcNat // IPS_NAT_MASK

	/* Connection needs TCP sequence adjusted. */
	IPSSeqAdjust = 1 << 6 // IPS_SEQ_ADJUST

	/* NAT initialization bits. */
	IPSSrcNatDone = 1 << 7 // IPS_SRC_NAT_DONE
	IPSDstNatDone = 1 << 8 // IPS_DST_NAT_DONE

	/* Both together */
	IPSNatDoneMask = IPSDstNatDone | IPSSrcNatDone // IPS_NAT_DONE_MASK

	/* Connection is dying (removed from lists), can not be unset. */
	IPSDying = 1 << 9

	/* Connection has fixed timeout. */
	IPSFixedTimeout = 1 << 10 // IPS_FIXED_TIMEOUT

	/* Conntrack is a template */
	IPSTemplate = 1 << 11 // IPS_TEMPLATE

	/* Conntrack is a fake untracked entry */
	IPSUntracked = 1 << 12 // IPS_UNTRACKED
)
