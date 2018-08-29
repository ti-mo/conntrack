package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// Event holds information about a Conntrack event.
type Event struct {
	Type EventType

	Flow   *Flow
	Expect *Expect
}

// EventType is a custom type that describes the Conntrack event type.
//go:generate stringer -type=EventType
type EventType uint8

// List of all types of Conntrack events.
const (
	EventUnknown EventType = iota
	EventNew
	EventUpdate
	EventDestroy
	EventExpNew
	EventExpDestroy
)

// FromHeaders unmarshals a Conntrack EventType from a Netlink header and a Netfilter header.
func (et *EventType) FromHeaders(nlh netlink.Header, ht netfilter.HeaderType) error {

	// Fail when the message is not a conntrack message
	if ht.SubsystemID == netfilter.NFSubsysCTNetlink {
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
	} else if ht.SubsystemID == netfilter.NFSubsysCTNetlinkExp {
		switch ExpMessageType(ht.MessageType) {
		case CTExpNew:
			*et = EventExpNew
		case CTExpDelete:
			*et = EventExpDestroy
		default:
			return fmt.Errorf(errUnknownEventType, ht.MessageType)
		}
	} else {
		return errNotConntrack
	}

	return nil
}

// FromNetlinkMessage unmarshals a Netlink message into an Event structure.
func (e *Event) FromNetlinkMessage(nlmsg netlink.Message) error {

	// Make sure we don't re-use an Event structure
	if e.Expect != nil || e.Flow != nil {
		return errReusedEvent
	}

	var err error

	// Get Netfilter Subsystem and MessageType from Netlink header
	var ht netfilter.HeaderType
	ht.FromNetlinkHeader(nlmsg.Header)

	// Decode the header to make sure we're dealing with a Conntrack event
	err = e.Type.FromHeaders(nlmsg.Header, ht)
	if err != nil {
		return err
	}

	// Unmarshal a netlink.Message into netfilter.Attributes
	attrs, err := netfilter.AttributesFromNetlink(nlmsg)
	if err != nil {
		return err
	}

	// Unmarshal Netfilter attributes into the event's Flow or Expect entry
	if ht.SubsystemID == netfilter.NFSubsysCTNetlink {
		e.Flow = new(Flow)
		err = e.Flow.UnmarshalAttributes(attrs)
	} else if ht.SubsystemID == netfilter.NFSubsysCTNetlinkExp {
		e.Expect = new(Expect)
		err = e.Expect.UnmarshalAttributes(attrs)
	}

	if err != nil {
		return err
	}

	return nil
}
