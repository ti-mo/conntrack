package conntrack

import (
	"errors"
	"fmt"
	"github.com/gonetlink/netfilter"
	"log"
	"net"
	"time"
)

var (
	errNotImplemented = errors.New("sorry, not implemented yet")
	errNested         = errors.New("unexpected Nested attribute")
	errNotNested      = errors.New("need a Nested attribute to decode this structure")
	errNeedChildren   = errors.New("need at least 2 child attributes")
	errIncorrectSize  = errors.New("binary attribute data has incorrect size")
)

type Attribute interface{}

type Tuple interface{}

type ProtoTuple struct {
	Protocol        uint8
	SourcePort      uint16
	DestinationPort uint16
}

type ProtoInfo interface{}

type ProtoInfoTCP struct {
	State               uint8
	OriginalWindowScale uint8
	ReplyWindowScale    uint8
	OriginalFlags       uint16
	ReplyFlags          uint16
}

type IPTuple struct {
	SourceAddress      net.IP
	DestinationAddress net.IP
}

type Timestamp struct {
	Start time.Time
	Stop  time.Time
}

type Counter struct {
	Packets uint64
	Bytes   uint64
}

func (c Counter) String() string {
	return fmt.Sprintf("[%d pkts/%d B]", c.Packets, c.Bytes)
}

func UnmarshalIPTuple(attr netfilter.Attribute) (IPTuple, error) {

	if TupleType(attr.Type) != CTA_TUPLE_IP {
		return IPTuple{},
			errors.New(fmt.Sprintf("error: UnmarshalIPTuple - %v is not a CTA_TUPLE_IP", attr.Type))
	}

	var it IPTuple

	for _, iattr := range attr.Children {
		switch IPTupleType(iattr.Type) {
		case CTA_IP_V4_SRC, CTA_IP_V6_SRC:
			it.SourceAddress = net.IP(iattr.Data)
		case CTA_IP_V4_DST, CTA_IP_V6_DST:
			it.DestinationAddress = net.IP(iattr.Data)
		default:
			return IPTuple{},
				errors.New(fmt.Sprintf("error: UnmarshalIPTuple - unknown IPTupleType %s", iattr.Type))

		}
	}

	return it, nil
}

func UnmarshalProtoTuple(attr netfilter.Attribute) (ProtoTuple, error) {

	if TupleType(attr.Type) != CTA_TUPLE_PROTO {
		return ProtoTuple{},
			errors.New(fmt.Sprintf("error: UnmarshalProtoTuple - %v is not a CTA_TUPLE_PROTO", attr.Type))
	}

	var pt ProtoTuple

	for _, iattr := range attr.Children {
		switch ProtoTupleType(iattr.Type) {
		case CTA_PROTO_NUM:
			pt.Protocol = iattr.Data[0]
		case CTA_PROTO_SRC_PORT:
			pt.SourcePort = iattr.Uint16()
		case CTA_PROTO_DST_PORT:
			pt.DestinationPort = iattr.Uint16()
		default:
			return ProtoTuple{},
				errors.New(fmt.Sprintf("error: UnmarshalProtoTuple - unknown ProtoTupleType %s", iattr.Type))
		}
	}

	return pt, nil
}

func UnmarshalProtoInfo(attr netfilter.Attribute) (ProtoInfo, error) {

	if !attr.Nested {
		return nil, errNotNested
	}

	if len(attr.Children) != 1 {
		return nil, errors.New("error: UnmarshalProtoInfo - decode expects exactly one child")
	}

	// Step into the single nested child
	iattr := attr.Children[0]

	switch ProtoInfoType(iattr.Type) {
	case CTA_PROTOINFO_TCP:
		return UnmarshalProtoInfoTCP(iattr)
	case CTA_PROTOINFO_DCCP:
		return nil, errNotImplemented
	case CTA_PROTOINFO_SCTP:
		return nil, errNotImplemented
	default:
		return nil, errors.New(
			fmt.Sprintf("error: UnmarshalProtoInfo - unknown ProtoInfoType %v", attr.Type))
	}

	return nil, nil
}

func UnmarshalProtoInfoTCP(attr netfilter.Attribute) (ProtoInfoTCP, error) {

	if !attr.Nested {
		return ProtoInfoTCP{}, errNotNested
	}

	// A ProtoInfoTCP has at least 3 members,
	// TCP_STATE and TCP_FLAGS_ORIG/REPLY
	if len(attr.Children) < 3 {
		return ProtoInfoTCP{}, errNeedChildren
	}

	var pi ProtoInfoTCP

	for _, iattr := range attr.Children {
		switch ProtoInfoTCPType(iattr.Type) {
		case CTA_PROTOINFO_TCP_STATE:
			pi.State = iattr.Data[0]
		case CTA_PROTOINFO_TCP_WSCALE_ORIGINAL:
			pi.OriginalWindowScale = iattr.Data[0]
		case CTA_PROTOINFO_TCP_WSCALE_REPLY:
			pi.ReplyWindowScale = iattr.Data[0]
		case CTA_PROTOINFO_TCP_FLAGS_ORIGINAL:
			pi.OriginalFlags = iattr.Uint16()
		case CTA_PROTOINFO_TCP_FLAGS_REPLY:
			pi.ReplyFlags = iattr.Uint16()
		default:
			return ProtoInfoTCP{}, errors.New(
				fmt.Sprintf("error: UnmarshalProtoInfoTCP - unknown ProtoInfoTCPType %s", iattr.Type))
		}
	}

	return pi, nil
}

func UnmarshalTuples(attr netfilter.Attribute) (map[TupleType]Tuple, error) {

	mt := make(map[TupleType]Tuple)

	if !attr.Nested {
		return nil, errNotNested
	}

	// A Tuple will always consist of more than one child attribute
	if len(attr.Children) < 2 {
		return nil, errNeedChildren
	}

	for _, iattr := range attr.Children {
		var err error

		switch TupleType(iattr.Type) {
		case CTA_TUPLE_IP:
			mt[CTA_TUPLE_IP], err = UnmarshalIPTuple(iattr)
			if err != nil {
				return nil, err
			}
		case CTA_TUPLE_PROTO:
			mt[CTA_TUPLE_PROTO], err = UnmarshalProtoTuple(iattr)
			if err != nil {
				return nil, err
			}
		case CTA_TUPLE_ZONE:
			mt[CTA_TUPLE_ZONE] = iattr.Uint16()
		default:
			return nil, errors.New(
				fmt.Sprintf("error: UnmarshalTuples - unknown TupleType %s", iattr.Type))
		}
	}

	return mt, nil
}

// UnmarshalCounters unmarshals a nested counter attribute into
// a conntrack.Counter structure.
func UnmarshalCounters(attr netfilter.Attribute) (Counter, error) {

	if !attr.Nested {
		return Counter{}, errNotNested
	}

	// A Counter will always consist of packet and byte attributes
	if len(attr.Children) != 2 {
		return Counter{}, errNeedChildren
	}

	var ctr Counter

	for _, iattr := range attr.Children {
		switch CounterType(iattr.Type) {
		case CTA_COUNTERS_PACKETS:
			ctr.Packets = iattr.Uint64()
		case CTA_COUNTERS_BYTES:
			ctr.Bytes = iattr.Uint64()
		default:
			return Counter{}, errors.New(
				fmt.Sprintf("error: UnmarshalCounters - unknown type %s", iattr.Type))
		}
	}

	return ctr, nil
}

// UnmarshalStatus unmarshals a Netfilter attribute into a conntrack.Status.
// It is a convenience method that wraps conntrack.Status' UnmarshalBinary for safety.
func UnmarshalStatus(attr netfilter.Attribute) (Status, error) {

	if AttributeType(attr.Type) != CTA_STATUS {
		return Status{},
			errors.New(fmt.Sprintf("error: UnmarshalStatus - %v is not a CTA_STATUS", attr.Type))

	}

	if attr.Nested {
		log.Println(attr)
		return Status{}, errNested
	}

	var s Status

	err := s.UnmarshalBinary(attr.Data)
	if err != nil {
		return Status{}, err
	}

	return s, nil
}

// UnmarshalTimestamp unmarshals a nested timestamp attribute into
// a conntrack.Timestamp structure.
func UnmarshalTimestamp(attr netfilter.Attribute) (Timestamp, error) {

	if AttributeType(attr.Type) != CTA_TIMESTAMP {
		return Timestamp{},
			errors.New(fmt.Sprintf("error: UnmarshalTimestamp - %v is not a CTA_TIMESTAMP", attr.Type))

	}

	if !attr.Nested {
		return Timestamp{}, errNotNested
	}

	var ts Timestamp

	for _, iattr := range attr.Children {
		switch TimestampType(iattr.Type) {
		case CTA_TIMESTAMP_START:
			ts.Start = time.Unix(0, iattr.Int64())
		case CTA_TIMESTAMP_STOP:
			ts.Stop = time.Unix(0, iattr.Int64())
		default:
			return Timestamp{}, errors.New(
				fmt.Sprintf("error: UnmarshalTimestamp - unknown type %s", iattr.Type))
		}
	}

	return ts, nil
}

// UnmarshalNetfilterAttributes unmarshals a list of Netfilter attributes into an AttributeType map of
// conntrack.Attributes. An error is returned when attempting to decode an unknown attribute.
func UnmarshalNetfilterAttributes(attrs []netfilter.Attribute) (map[AttributeType]Attribute, error) {

	ra := make(map[AttributeType]Attribute)

	for _, attr := range attrs {
		var err error

		switch at := AttributeType(attr.Type); AttributeType(attr.Type) {
		// CTA_TUPLE_* attributes are nested and contain source and destination values for:
		// - the IPv4/IPv6 addresses involved
		// - ports used in the connection
		// - (optional) the Conntrack Zone of the originating/replying side of the flow
		case CTA_TUPLE_ORIG, CTA_TUPLE_REPLY:
			ra[at], err = UnmarshalTuples(attr)
			if err != nil {
				return nil, err
			}
		// CTA_STATUS is a bitfield of the state of the connection
		// (eg. if packets are seen in both directions, etc.)
		case CTA_STATUS:
			ra[at], err = UnmarshalStatus(attr)
			if err != nil {
				return nil, err
			}
		// CTA_PROTOINFO is sent for TCP, DCCP and SCTP protocols only. It conveys extra metadata
		// about the state flags seen on the wire. Update events are sent when these change.
		case CTA_PROTOINFO:
			ra[at], err = UnmarshalProtoInfo(attr)
			if err != nil {
				return nil, err
			}
		case CTA_HELP:
			fmt.Println(attr)
		// CTA_TIMEOUT is the time until the Conntrack entry is automatically destroyed.
		// CTA_ID is the tuple hash value generated by the kernel. It can be relied on for flow identification.
		// CTA_USE's purpose is shrouded in mystery.
		case CTA_TIMEOUT, CTA_ID, CTA_USE:
			ra[at] = attr.Uint32()
		// CTA_MARK is the connection's connmark
		// CTA_MARK_MASK is never sent by the kernel, but can be used for kernel-space dump filtering!
		case CTA_MARK, CTA_MARK_MASK:
			ra[at] = attr.Uint32()
		// CTA_COUNTERS_* attributes are nested and contain byte and packet counters for flows in either direction.
		case CTA_COUNTERS_ORIG, CTA_COUNTERS_REPLY:
			ra[at], err = UnmarshalCounters(attr)
			if err != nil {
				return nil, err
			}
		// CTA_ZONE describes the Conntrack zone the flow is placed in. This can be combined with a CTA_TUPLE_ZONE
		// to specify which zone an event originates from.
		case CTA_ZONE:
			ra[at] = attr.Uint16()
		// CTA_TIMESTAMP is a nested attribute that describes the start and end timestamp of a flow.
		// It is sent by the kernel with dumps and DESTROY events.
		case CTA_TIMESTAMP:
			ra[at], err = UnmarshalTimestamp(attr)
			if err != nil {
				return nil, err
			}
		// CTA_LABELS is a binary bitfield attached to a connection that is sent in
		// events when changed, as well as in response to dump queries.
		// CTA_LABELS_MASK is never sent by the kernel, but it can be used
		// in set / update queries to mask label operations on the kernel state table.
		// it needs to be exactly as wide as the CTA_LABELS field it intends to mask.
		case CTA_LABELS, CTA_LABELS_MASK:
			ra[at] = attr.Data
		default:
			return nil, errors.New(
				fmt.Sprintf("error: UnmarshalNetfilterAttributes - unknown type %s", attr.Type))
		}
	}

	return ra, nil
}
