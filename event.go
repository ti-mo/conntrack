package conntrack

import (
	"fmt"
	"log"
	"net"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// NFSubsysCTAll is a shorthand mask fo all Conntrack subsystems
const NFSubsysCTAll = netfilter.NFSubsysCTNetlink | netfilter.NFSubsysCTNetlinkExp | netfilter.NFSubsysCTNetlinkTimeout

// Event can hold all information needed to process a Conntrack event in userspace.
type Event struct {
	Type       EventType
	Proto      int
	SrcAddress net.IP
	SrcPort    uint16
	DstAddress net.IP
	DstPort    uint16
}

// EventType is a type of Conntrack event derived from the Netlink header.
// It describes an action to the state table in the kernel.
type EventType uint8

// From libnfnetlink/include/libnfnetlink/linux_nfnetlink_compat.h, NF_NETLINK_CONNTRACK_*
// This table is still actively used in upstream conntrack-tools and libnfnetlink
// It is in a _compat file because these values presumably stem from a time where there were
// only 32 multicast Netlink groups available. (before genetlink?)
const (
	EventNew        EventType = 1
	EventUpdate     EventType = 1 << 1
	EventDestroy    EventType = 1 << 2
	EventExpNew     EventType = 1 << 3
	EventExpUpdate  EventType = 1 << 4
	EventExpDestroy EventType = 1 << 5

	EventAll EventType = EventNew | EventUpdate | EventDestroy
)

func (et EventType) String() string {
	switch et {
	case EventUpdate:
		return "UPDATE"
	case EventNew:
		return "NEW"
	case EventDestroy:
		return "DESTROY"
	case EventExpUpdate:
		return "EXP_UPDATE"
	case EventExpNew:
		return "EXP_NEW"
	case EventExpDestroy:
		return "EXP_DESTROY"
	default:
		return "UNKNOWN"
	}
}

// DecodeEventType derives a Conntrack EventType from a Netlink message header.
func DecodeEventType(nlh netlink.Header) (EventType, error) {

	// Get Netfilter Subsystem and MessageType from Netlink header
	var ht netfilter.HeaderType
	ht.UnmarshalNetlink(nlh.Type)

	// Fail when the message is not a conntrack or conntrack-exp message
	if ht.SubsystemID&NFSubsysCTAll == 0 {
		return 0, errNotConntrack
	}

	switch Messagetype(ht.MessageType) {
	case CTNew:
		// Since the MessageType is only of kind new, get or delete,
		// the header's flags are used to distinguish between NEW and UPDATE.
		if nlh.Flags&(netfilter.NLFlagCreate|netfilter.NLFlagExcl) != 0 {
			return EventNew, nil
		}

		return EventUpdate, nil

	case CTDelete:
		return EventDestroy, nil
	default:
		return 0, nil
	}
}

// DecodeEventAttributes generates and populates an Event from a netlink.Message.
// Pure function, pointer argument for performance purposes.
// TODO: name this something proper, this is a helper that needs to be broken up
func DecodeEventAttributes(nlmsg *netlink.Message) (Event, error) {

	// Decode the header to make sure we're dealing with a Conntrack event
	et, err := DecodeEventType(nlmsg.Header)
	if err != nil {
		return Event{}, err
	}

	// Successfully decoded Conntrack event header, allocate Event
	e := Event{Type: et}

	// Unmarshal a netlink.Message into netfilter.Attributes
	attrs, err := netfilter.UnmarshalMessage(*nlmsg)
	if err != nil {
		return Event{}, err
	}

	nfa, err := DecodeAttributes(attrs, 0xFFFF)
	if err != nil {
		var nfht netfilter.HeaderType
		nfht.UnmarshalNetlink(nlmsg.Header.Type)

		log.Println(nfht)
		log.Println(attrs)

		return Event{}, err
	}

	fmt.Println(nfa)

	return e, nil
}
