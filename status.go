package conntrack

import (
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// unmarshal unmarshals a Status from ad.
func (s *Status) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() != 1 {
		return errNeedSingleChild
	}

	if !ad.Next() {
		return ad.Err()
	}

	if len(ad.Bytes()) != 4 {
		return errIncorrectSize
	}

	*s = Status(ad.Uint32())

	return ad.Err()
}

// marshal marshals a Status into a netfilter.Attribute.
func (s Status) marshal() netfilter.Attribute {
	return netfilter.Attribute{
		Type: uint16(ctaStatus),
		Data: netfilter.Uint32Bytes(uint32(s)),
	}
}

// Expected indicates that this connection is an expected connection,
// created by Conntrack helpers based on the state of another, related connection.
func (s Status) Expected() bool {
	return s&StatusExpected != 0
}

// SeenReply is set when the flow has seen traffic both ways.
func (s Status) SeenReply() bool {
	return s&StatusSeenReply != 0
}

// Assured is set when eg. three-way handshake is completed on a TCP flow.
func (s Status) Assured() bool {
	return s&StatusAssured != 0
}

// Confirmed is set when the original packet has left the box.
func (s Status) Confirmed() bool {
	return s&StatusConfirmed != 0
}

// SrcNAT means the connection needs source NAT in the original direction.
func (s Status) SrcNAT() bool {
	return s&StatusSrcNAT != 0
}

// DstNAT means the connection needs destination NAT in the original direction.
func (s Status) DstNAT() bool {
	return s&StatusDstNAT != 0
}

// SeqAdjust means the connection needs its TCP sequence to be adjusted.
func (s Status) SeqAdjust() bool {
	return s&StatusSeqAdjust != 0
}

// SrcNATDone is set when source NAT was applied onto the connection.
func (s Status) SrcNATDone() bool {
	return s&StatusSrcNATDone != 0
}

// DstNATDone is set when destination NAT was applied onto the connection.
func (s Status) DstNATDone() bool {
	return s&StatusDstNATDone != 0
}

// Dying means the connection has concluded and needs to be cleaned up by GC.
func (s Status) Dying() bool {
	return s&StatusDying != 0
}

// FixedTimeout means the connection's timeout value cannot be changed.
func (s Status) FixedTimeout() bool {
	return s&StatusFixedTimeout != 0
}

// Template indicates if the connection is a template.
func (s Status) Template() bool {
	return s&StatusTemplate != 0
}

// Helper is set when a helper was explicitly attached using a Conntrack target.
func (s Status) Helper() bool {
	return s&StatusHelper != 0
}

// Offload is set when the connection was offloaded to flow table.
func (s Status) Offload() bool {
	return s&StatusOffload != 0
}

// Status is a bitfield describing the state of a Flow.
type Status uint32

// Conntrack connection's status flags, from enum ip_conntrack_status.
// uapi/linux/netfilter/nf_conntrack_common.h
const (
	StatusExpected  Status = 1      // IPS_EXPECTED
	StatusSeenReply Status = 1 << 1 // IPS_SEEN_REPLY
	StatusAssured   Status = 1 << 2 // IPS_ASSURED
	StatusConfirmed Status = 1 << 3 // IPS_CONFIRMED
	StatusSrcNAT    Status = 1 << 4 // IPS_SRC_NAT
	StatusDstNAT    Status = 1 << 5 // IPS_DST_NAT

	StatusNATMask = StatusDstNAT | StatusSrcNAT // IPS_NAT_MASK

	StatusSeqAdjust  Status = 1 << 6 // IPS_SEQ_ADJUST
	StatusSrcNATDone Status = 1 << 7 // IPS_SRC_NAT_DONE
	StatusDstNATDone Status = 1 << 8 // IPS_DST_NAT_DONE

	StatusNATDoneMask = StatusDstNATDone | StatusSrcNATDone // IPS_NAT_DONE_MASK

	StatusDying        Status = 1 << 9
	StatusFixedTimeout Status = 1 << 10 // IPS_FIXED_TIMEOUT
	StatusTemplate     Status = 1 << 11 // IPS_TEMPLATE
	StatusUntracked    Status = 1 << 12 // IPS_UNTRACKED
	StatusHelper       Status = 1 << 13 // IPS_HELPER
	StatusOffload      Status = 1 << 14 // IPS_OFFLOAD
)
