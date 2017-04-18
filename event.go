package conntrack

import (
	"github.com/mdlayher/netlink"
	"github.com/gonetlink/netfilter"
	"net"
	"errors"
	"golang.org/x/sys/unix"
)

var (
	errNotConntrack = errors.New("trying to decode a non-conntrack or conntrack-exp message")
)

// Shorthand for masking all Conntrack subsystems.
const NFNL_SUBSYS_CT_ALL = netfilter.NFNL_SUBSYS_CTNETLINK | netfilter.NFNL_SUBSYS_CTNETLINK_EXP | netfilter.NFNL_SUBSYS_CTNETLINK_TIMEOUT

// Event can hold all information needed to process a Conntrack event in userspace.
type Event struct {
	Type		EventType
	Proto		int
	SrcAddress	net.IP
	SrcPort		uint16
	DstAddress	net.IP
	DstPort		uint16
}

// EventType is a type of Conntrack event derived from the Netlink header.
// It describes an action to the state table in the kernel.
type EventType uint8

const (
	EventUnknown EventType = 0x0
	EventNew     EventType = 0x1
	EventUpdate  EventType = 0x2
	EventDestroy EventType = 0x4
)

func (et EventType) String() string {
	switch et {
	case EventUpdate:
		return "UPDATE"
	case EventNew:
		return "NEW"
	case EventDestroy:
		return "DESTROY"
	default:
		return "UNKNOWN"
	}
}

// DecodeEventType derives a Conntrack EventType from a Netlink message header.
func DecodeEventType(nlh netlink.Header) (EventType, error) {

	// Get Netfilter Subsystem and MessageType from Netlink header
	ht := netfilter.UnmarshalNetlinkHeaderType(nlh.Type)

	// Fail when the message is not a conntrack or conntrack-exp message
	if ht.SubsystemID & NFNL_SUBSYS_CT_ALL == 0 {
		return EventUnknown, errNotConntrack
	}

	switch(Messagetype(ht.MessageType)) {
	// Since the MessageType is only of kind new, get or delete,
	// the header's flags are used to distinguish between NEW and UPDATE.
	case IPCTNL_MSG_CT_NEW:
		if nlh.Flags & (unix.NLM_F_CREATE | unix.NLM_F_EXCL) != 0 {
			return EventNew, nil
		} else {
			return EventUpdate, nil
		}
	case IPCTNL_MSG_CT_DELETE:
		return EventDestroy, nil
	default:
		return EventUnknown, nil
	}
}
