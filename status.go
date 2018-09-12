package conntrack

import (
	"fmt"

	"github.com/ti-mo/netfilter"
)

// Status represents a snapshot of a conntrack connection's state.
type Status struct {
	value uint32
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a Status structure.
func (s *Status) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTAStatus {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTAStatus)
	}

	if attr.Nested {
		return errNested
	}

	if len(attr.Data) != 4 {
		return errIncorrectSize
	}

	s.value = attr.Uint32()

	return nil
}

// MarshalAttribute marshals a Status into a netfilter.Attribute.
func (s Status) MarshalAttribute() netfilter.Attribute {
	return netfilter.Attribute{
		Type: uint16(CTAStatus),
		Data: netfilter.Uint32Bytes(s.value),
	}
}

// Expected indicates that this connection is an expected connection,
// created by Conntrack helpers based on the state of another, related connection.
func (s Status) Expected() bool {
	return s.value&IPSExpected != 0
}

// SeenReply is set when the flow has seen traffic both ways.
func (s Status) SeenReply() bool {
	return s.value&IPSSeenReply != 0
}

// Assured is set when eg. three-way handshake is completed on a TCP flow.
func (s Status) Assured() bool {
	return s.value&IPSAssured != 0
}

// Confirmed is set when the original packet has left the box.
func (s Status) Confirmed() bool {
	return s.value&IPSConfirmed != 0
}

// SrcNAT means the connection needs source NAT in the original direction.
func (s Status) SrcNAT() bool {
	return s.value&IPSSrcNat != 0
}

// DstNAT means the connection needs destination NAT in the original direction.
func (s Status) DstNAT() bool {
	return s.value&IPSDstNat != 0
}

// SeqAdjust means the connection needs its TCP sequence to be adjusted.
func (s Status) SeqAdjust() bool {
	return s.value&IPSSeqAdjust != 0
}

// SrcNATDone is set when source NAT was applied onto the connection.
func (s Status) SrcNATDone() bool {
	return s.value&IPSSrcNatDone != 0
}

// DstNATDone is set when destination NAT was applied onto the connection.
func (s Status) DstNATDone() bool {
	return s.value&IPSDstNatDone != 0
}

// Dying means the connection has concluded and needs to be cleaned up by GC.
func (s Status) Dying() bool {
	return s.value&IPSDying != 0
}

// FixedTimeout means the connection's timeout value cannot be changed.
func (s Status) FixedTimeout() bool {
	return s.value&IPSFixedTimeout != 0
}

// Template indicates if the connection is a template.
func (s Status) Template() bool {
	return s.value&IPSTemplate != 0
}

// Helper is set when a helper was explicitly attached using a Conntrack target.
func (s Status) Helper() bool {
	return s.value&IPSHelper != 0
}

// Offload is set when the connection was offloaded to flow table.
func (s Status) Offload() bool {
	return s.value&IPSOffload != 0
}

// Conntrack connection's status flags, from enum ip_conntrack_status.
// uapi/linux/netfilter/nf_conntrack_common.h
const (
	IPSExpected  = 1      // IPS_EXPECTED
	IPSSeenReply = 1 << 1 // IPS_SEEN_REPLY
	IPSAssured   = 1 << 2 // IPS_ASSURED
	IPSConfirmed = 1 << 3 // IPS_CONFIRMED
	IPSSrcNat    = 1 << 4 // IPS_SRC_NAT
	IPSDstNat    = 1 << 5 // IPS_DST_NAT

	IPSNatMask = IPSDstNat | IPSSrcNat // IPS_NAT_MASK

	IPSSeqAdjust  = 1 << 6 // IPS_SEQ_ADJUST
	IPSSrcNatDone = 1 << 7 // IPS_SRC_NAT_DONE
	IPSDstNatDone = 1 << 8 // IPS_DST_NAT_DONE

	IPSNatDoneMask = IPSDstNatDone | IPSSrcNatDone // IPS_NAT_DONE_MASK

	IPSDying        = 1 << 9
	IPSFixedTimeout = 1 << 10 // IPS_FIXED_TIMEOUT
	IPSTemplate     = 1 << 11 // IPS_TEMPLATE
	IPSUntracked    = 1 << 12 // IPS_UNTRACKED
	IPSHelper       = 1 << 13 // IPS_HELPER
	IPSOffload      = 1 << 14 // IPS_OFFLOAD
)
