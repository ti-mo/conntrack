package conntrack

import (
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/netfilter"
)

var eventTypeTests = []struct {
	name string
	et   eventType
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
			MessageType: netfilter.MessageType(ctNew),
			Flags:       netlink.Create | netlink.Excl,
		},
		et: EventNew,
	},
	{
		name: "conntrack update",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			MessageType: netfilter.MessageType(ctNew),
		},
		et: EventUpdate,
	},
	{
		name: "conntrack destroy",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			MessageType: netfilter.MessageType(ctDelete),
		},
		et: EventDestroy,
	},
	{
		name: "error unmarshal conntrack unknown event",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			MessageType: 255,
		},
		err: errUnknownEventType,
	},
	{
		name: "conntrack exp new",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlinkExp,
			MessageType: netfilter.MessageType(ctExpNew),
		},
		et: EventExpNew,
	},
	{
		name: "conntrack exp destroy",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlinkExp,
			MessageType: netfilter.MessageType(ctExpDelete),
		},
		et: EventExpDestroy,
	},
	{
		name: "error unmarshal conntrack exp unknown event",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlinkExp,
			MessageType: 255,
		},
		err: errUnknownEventType,
	},
}

func TestEventTypeUnmarshal(t *testing.T) {
	for _, tt := range eventTypeTests {
		t.Run(tt.name, func(t *testing.T) {
			var et eventType
			err := et.unmarshal(tt.nfh)
			if err != nil || tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			assert.Equal(t, tt.et, et, "event type mismatch")
		})
	}
}

func TestEventTypeString(t *testing.T) {
	assert.Equal(t, "eventType(255)", eventType(255).String())
}

var eventTests = []struct {
	name    string
	e       Event
	nfh     netfilter.Header
	nfattrs []netfilter.Attribute
}{
	{
		name: "correct empty new flow event",
		nfh: netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			Flags:       netlink.Create | netlink.Excl,
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
			MessageType: netfilter.MessageType(ctExpDelete),
		},
		e: Event{
			Type:   EventExpDestroy,
			Expect: &Expect{},
		},
	},
}

func TestEventUnmarshal(t *testing.T) {
	for _, tt := range eventTests {
		t.Run(tt.name, func(t *testing.T) {
			// Re-use netfilter's MarshalNetlink because we don't want to roll binary netlink messages by hand.
			nlm, err := netfilter.MarshalNetlink(tt.nfh, tt.nfattrs)
			require.NoError(t, err)

			var e Event
			assert.NoError(t, e.unmarshal(nlm))
			assert.Equal(t, tt.e, e, "unexpected unmarshal")
		})
	}
}

func TestEventUnmarshalError(t *testing.T) {
	// Unmarshal into event with existing Flow
	eventExistingFlow := Event{Flow: &Flow{}}
	assert.ErrorIs(t, eventExistingFlow.unmarshal(netlink.Message{}), errReusedEvent)

	// EventType unmarshal error, blank SubsystemID
	var emptyEvent Event
	assert.ErrorIs(t, emptyEvent.unmarshal(netlink.Message{
		Header: netlink.Header{},
		Data:   []byte{1, 2, 3, 4},
	}), errNotConntrack)

	// Cause a random error during Flow unmarshal
	assert.ErrorIs(t, emptyEvent.unmarshal(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(netfilter.NFSubsysCTNetlink) << 8},
		Data: []byte{
			1, 2, 3, 4, // random 4-byte nfgenmsg
			4, 0, 1, 0, // 4-byte (empty) netlink attribute of type 1
		}}), errNotNested)
}
