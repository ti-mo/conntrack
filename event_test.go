package conntrack

import (
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/netfilter"
)

var eventTypeTests = []struct {
	name string
	et   EventType
	nfh  netfilter.Header
	err  error
}{
	{
		name: "error unmarshal not conntrack",
		err:  errNotConntrack,
	},
	{
		name: "conntrack new",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			MessageType: netfilter.MessageType(CTNew),
			Flags:       netlink.HeaderFlagsCreate | netlink.HeaderFlagsExcl,
		},
		et: EventNew,
	},
	{
		name: "conntrack update",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			MessageType: netfilter.MessageType(CTNew),
		},
		et: EventUpdate,
	},
	{
		name: "conntrack destroy",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			MessageType: netfilter.MessageType(CTDelete),
		},
		et: EventDestroy,
	},
	{
		name: "error unmarshal conntrack unknown event",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			MessageType: 255,
		},
		err: errors.New("unknown event type 255"),
	},
	{
		name: "conntrack exp new",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlinkExp,
			MessageType: netfilter.MessageType(CTExpNew),
		},
		et: EventExpNew,
	},
	{
		name: "conntrack exp destroy",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlinkExp,
			MessageType: netfilter.MessageType(CTExpDelete),
		},
		et: EventExpDestroy,
	},
	{
		name: "error unmarshal conntrack exp unknown event",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlinkExp,
			MessageType: 255,
		},
		err: errors.New("unknown event type 255"),
	},
}

func TestEventType_Unmarshal(t *testing.T) {
	for _, tt := range eventTypeTests {

		t.Run(tt.name, func(t *testing.T) {
			var et EventType

			err := et.unmarshal(tt.nfh)
			if err != nil || tt.err != nil {
				require.Error(t, err)
				require.EqualError(t, tt.err, err.Error())
				return
			}

			assert.Equal(t, tt.et, et, "event type mismatch")
		})
	}
}

func TestEventType_String(t *testing.T) {
	assert.Equal(t, "EventType(255)", EventType(255).String())
}

var eventTests = []struct {
	name    string
	e       Event
	nfh     netfilter.Header
	nfattrs []netfilter.Attribute
	err     error
}{
	{
		name: "correct empty new flow event",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			Flags:       netlink.HeaderFlagsCreate | netlink.HeaderFlagsExcl,
		},
		e: Event{
			Type: EventNew,
			Flow: &Flow{},
		},
	},
	{
		name: "correct empty expect destroy event",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlinkExp,
			MessageType: netfilter.MessageType(CTExpDelete),
		},
		e: Event{
			Type:   EventExpDestroy,
			Expect: &Expect{},
		},
	},
}

func TestEvent_Unmarshal(t *testing.T) {
	for _, tt := range eventTests {

		t.Run(tt.name, func(t *testing.T) {

			// Re-use netfilter's MarshalNetlink because we don't want to roll binary netlink messages by hand.
			nlm, err := netfilter.MarshalNetlink(tt.nfh, tt.nfattrs)
			require.NoError(t, err)

			var e Event

			err = e.unmarshal(nlm)
			if err != nil || tt.err != nil {
				require.Error(t, err)
				require.EqualError(t, tt.err, err.Error(), "unmarshal errors do not match")
				return
			}

			assert.Equal(t, tt.e, e, "unexpected unmarshal")
		})
	}
}

func TestEvent_UnmarshalError(t *testing.T) {

	// Unmarshal into event with existing Flow
	eventExistingFlow := Event{Flow: &Flow{}}
	assert.EqualError(t, eventExistingFlow.unmarshal(netlink.Message{}), errReusedEvent.Error())

	// Netlink unmarshal error
	emptyEvent := Event{}
	assert.EqualError(t, emptyEvent.unmarshal(netlink.Message{}), "expected at least 4 bytes in netlink message payload")

	// EventType unmarshal error, blank SubsystemID
	assert.EqualError(t, emptyEvent.unmarshal(netlink.Message{
		Header: netlink.Header{}, Data: []byte{1, 2, 3, 4}}), "trying to decode a non-conntrack or conntrack-exp message")

	// Flow unmarshal error
	assert.EqualError(t, emptyEvent.unmarshal(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(netfilter.NFSubsysCTNetlink) << 8},
		Data: []byte{
			1, 2, 3, 4, // random 4-byte nfgenmsg
			4, 0, 0xff, 0, // 4-byte (empty) netlink attribute with maxed-out MessageType byte
		}}), "attribute type '255' unknown")

}
