package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// Event can hold all information needed to process a Conntrack event in userspace.
type Event struct {
	Type EventType
	Flow Flow
}

// EventType is a custom type that describes the Conntrack event type.
//go:generate stringer -type=EventType
type EventType uint8

// List of all types of Conntrack events.
const (
	EventNew EventType = iota
	EventUpdate
	EventDestroy
	EventExpNew
	EventExpDestroy
)

// FromNetlinkHeader unmarshals a Conntrack EventType from a Netlink message header.
// TODO: Support conntrack-exp
func (et *EventType) FromNetlinkHeader(nlh netlink.Header) error {

	// Get Netfilter Subsystem and MessageType from Netlink header
	var ht netfilter.HeaderType
	ht.FromNetlinkHeader(nlh)

	// Fail when the message is not a conntrack message
	if ht.SubsystemID != netfilter.NFSubsysCTNetlink {
		return errNotConntrack
	}

	switch MessageType(ht.MessageType) {
	case CTNew:
		// Since the MessageType is only of kind new, get or delete,
		// the header's flags are used to distinguish between NEW and UPDATE.
		if nlh.Flags&(netlink.HeaderFlagsCreate|netlink.HeaderFlagsExcl) != 0 {
			*et = EventNew
		} else {
			*et = EventUpdate
		}
	case CTDelete:
		*et = EventDestroy
	default:
		return fmt.Errorf(errUnknownEventType, ht.MessageType)
	}

	return nil
}

// FromNetlink unmarshals a Netlink message into an Event structure.
func (e *Event) FromNetlink(nlmsg netlink.Message) error {

	var err error

	// Decode the header to make sure we're dealing with a Conntrack event
	err = e.Type.FromNetlinkHeader(nlmsg.Header)
	if err != nil {
		return err
	}

	// Unmarshal a netlink.Message into netfilter.Attributes
	attrs, err := netfilter.AttributesFromNetlink(nlmsg)
	if err != nil {
		return err
	}

	var f Flow
	err = f.UnmarshalAttributes(attrs)
	if err != nil {
		return err
	}

	return nil
}
