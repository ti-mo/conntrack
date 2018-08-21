package conntrack

import "errors"

var (
	errNotConntrack     = errors.New("trying to decode a non-conntrack or conntrack-exp message")
	errConnHasListeners = errors.New("Conn has existing listeners, open another to listen on more groups")
	errMultipartEvent   = errors.New("received multicast event with more than one Netlink message")
)

const (
	errUnknownEventType = "unknown event type %d"
	errWorkerCount      = "invalid worker count %s"
	errMessageTypeRange = "message (event) type %x out of range for Netlink subscription"
	errRecover          = "recovered from panic in function %s: %s"
	errWorkerReceive    = "netlink.Receive error in listenWorker %d, exiting"
)
