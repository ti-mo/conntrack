package conntrack

import "errors"

var (
	errNotConntrack     = errors.New("trying to decode a non-conntrack or conntrack-exp message")
	errConnHasListeners = errors.New("Conn has existing listeners, open another to listen on more groups")
	errMultipartEvent   = errors.New("received multicast event with more than one Netlink message")
	errNotImplemented   = errors.New("sorry, not implemented yet")
	errNested           = errors.New("unexpected Nested attribute")
	errNotNested        = errors.New("need a Nested attribute to decode this structure")
	errNeedSingleChild  = errors.New("need (at least) 1 child attribute")
	errNeedChildren     = errors.New("need (at least) 2 child attributes")
	errIncorrectSize    = errors.New("binary attribute data has incorrect size")
	errReusedEvent      = errors.New("cannot to unmarshal into existing event")
)

const (
	errUnknownEventType   = "unknown event type %d"
	errWorkerCount        = "invalid worker count %s"
	errMessageTypeRange   = "message (event) type %x out of range for Netlink subscription"
	errRecover            = "recovered from panic in function %s: %s"
	errWorkerReceive      = "netlink.Receive error in listenWorker %d, exiting"
	errAttributeWrongType = "attribute type '%d' is not a %s"
	errAttributeChild     = "child Type '%d' unknown for attribute type %s"
	errAttributeUnknown   = "attribute type '%d' unknown"
	errExactChildren      = "need exactly %d child attributes for attribute type %s"
)
