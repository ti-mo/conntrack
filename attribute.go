package conntrack

import (
	"errors"
	"fmt"
	"github.com/gonetlink/netfilter"
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

// A Tuple holds an IPTuple, ProtoTuple and a Zone.
// IP and Proto are pointers and possibly 'nil' as a result.
type Tuple struct {
	IP    *IPTuple
	Proto *ProtoTuple
	Zone  uint16
}

func (t *Tuple) UnmarshalAttribute(attr netfilter.Attribute) error {

	if !attr.Nested {
		return errNotNested
	}

	// A Tuple will always consist of more than one child attribute
	if len(attr.Children) < 2 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch TupleType(iattr.Type) {
		case CTA_TUPLE_IP:
			var ti IPTuple
			if err := (&ti).UnmarshalAttribute(iattr); err != nil {
				return err
			}
			t.IP = &ti
		case CTA_TUPLE_PROTO:
			var tp ProtoTuple
			if err := (&tp).UnmarshalAttribute(iattr); err != nil {
				return err
			}
			t.Proto = &tp
		case CTA_TUPLE_ZONE:
			t.Zone = iattr.Uint16()
		default:
			return fmt.Errorf("error: DecodeTuple - unknown TupleType %s", iattr.Type)
		}
	}

	return nil
}

// An IPTuple encodes a source and destination address.
// Both of its members are of type net.IP.
type IPTuple struct {
	SourceAddress      net.IP
	DestinationAddress net.IP
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into an IPTuple.
// IPv4 addresses will be represented by a 4-byte net.IP, IPv6 addresses by 16-byte.
// The net.IP object is created with the raw bytes, NOT with net.ParseIP().
// Use IP.Equal() to compare addresses in implementations and tests.
func (ipt *IPTuple) UnmarshalAttribute(attr netfilter.Attribute) error {

	if TupleType(attr.Type) != CTA_TUPLE_IP {
		return fmt.Errorf("error: UnmarshalAttribute - %v is not a CTA_TUPLE_IP", attr.Type)
	}

	if !attr.Nested {
		return errNotNested
	}

	if len(attr.Children) != 2 {
		return errors.New("error: UnmarshalAttribute - IPTuple expects exactly two children")
	}

	for _, iattr := range attr.Children {

		if len(iattr.Data) != 4 && len(iattr.Data) != 16 {
			return errIncorrectSize
		}

		switch IPTupleType(iattr.Type) {
		case CTA_IP_V4_SRC, CTA_IP_V6_SRC:
			ipt.SourceAddress = net.IP(iattr.Data)
		case CTA_IP_V4_DST, CTA_IP_V6_DST:
			ipt.DestinationAddress = net.IP(iattr.Data)
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown IPTupleType %s", iattr.Type)
		}
	}

	return nil
}

// A ProtoTuple encodes a protocol number, source port and destination port.
type ProtoTuple struct {
	Protocol        uint8
	SourcePort      uint16
	DestinationPort uint16
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a ProtoTuple.
func (pt *ProtoTuple) UnmarshalAttribute(attr netfilter.Attribute) error {

	if TupleType(attr.Type) != CTA_TUPLE_PROTO {
		return fmt.Errorf("error: UnmarshalAttribute - %v is not a CTA_TUPLE_PROTO", attr.Type)
	}

	if !attr.Nested {
		return errNotNested
	}

	for _, iattr := range attr.Children {
		switch ProtoTupleType(iattr.Type) {
		case CTA_PROTO_NUM:
			pt.Protocol = iattr.Data[0]
		case CTA_PROTO_SRC_PORT:
			pt.SourcePort = iattr.Uint16()
		case CTA_PROTO_DST_PORT:
			pt.DestinationPort = iattr.Uint16()
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown ProtoTupleType %s", iattr.Type)
		}
	}

	return nil
}

// A Helper holds the name and info the helper that creates a related connection.
type Helper struct {
	Name string
	Info []byte
}

// UnmarshalAttributes unmarshals a netfilter.Attribute into a Helper.
func (hlp *Helper) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTA_HELP {
		return fmt.Errorf("error: UnmarshalAttribute - %v is not a CTA_HELP", attr.Type)
	}

	if !attr.Nested {
		return errNotNested
	}

	for _, iattr := range attr.Children {
		switch HelperType(iattr.Type) {
		case CTA_HELP_NAME:
			hlp.Name = string(iattr.Data)
		case CTA_HELP_INFO:
			hlp.Info = iattr.Data
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown HelperType %s", iattr.Type)
		}
	}

	return nil
}

// The ProtoInfo structure holds one of three types:
// a ProtoInfoTCP in the TCP field,
// a ProtoInfoDCCP in the DCCP field, or
// a ProtoInfoSCTP in the SCTP field.
type ProtoInfo struct {
	TCP *ProtoInfoTCP
	// TODO: DCCP *ProtoInfoDCCP
	// TODO: SCTP *ProtoInfoSCTP
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a ProtoInfo structure.
// one of three ProtoInfo types; TCP, DCCP or SCTP.
func (pi *ProtoInfo) UnmarshalAttribute(attr netfilter.Attribute) error {

	if !attr.Nested {
		return errNotNested
	}

	if len(attr.Children) != 1 {
		return errors.New("error: UnmarshalAttribute - decode expects exactly one child")
	}

	// Step into the single nested child
	iattr := attr.Children[0]

	switch ProtoInfoType(iattr.Type) {
	case CTA_PROTOINFO_TCP:
		var tpi ProtoInfoTCP
		if err := (&tpi).UnmarshalProtoInfo(iattr); err != nil {
			return err
		}
		pi.TCP = &tpi
	case CTA_PROTOINFO_DCCP:
		return errNotImplemented
	case CTA_PROTOINFO_SCTP:
		return errNotImplemented
	default:
		return fmt.Errorf("error: UnmarshalAttribute - unknown ProtoInfoType %v", attr.Type)
	}

	return nil
}

// A ProtoInfoTCP describes the state of a TCP session in both directions.
// It contains state, window scale and TCP flags.
type ProtoInfoTCP struct {
	State               uint8
	OriginalWindowScale uint8
	ReplyWindowScale    uint8
	OriginalFlags       uint16
	ReplyFlags          uint16
}

// UnmarshalProtoInfo unmarshals a netfilter.Attribute into a ProtoInfoTCP.
func (tpi *ProtoInfoTCP) UnmarshalProtoInfo(attr netfilter.Attribute) error {

	if !attr.Nested {
		return errNotNested
	}

	// A ProtoInfoTCP has at least 3 members,
	// TCP_STATE and TCP_FLAGS_ORIG/REPLY
	if len(attr.Children) < 3 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch ProtoInfoTCPType(iattr.Type) {
		case CTA_PROTOINFO_TCP_STATE:
			tpi.State = iattr.Data[0]
		case CTA_PROTOINFO_TCP_WSCALE_ORIGINAL:
			tpi.OriginalWindowScale = iattr.Data[0]
		case CTA_PROTOINFO_TCP_WSCALE_REPLY:
			tpi.ReplyWindowScale = iattr.Data[0]
		case CTA_PROTOINFO_TCP_FLAGS_ORIGINAL:
			tpi.OriginalFlags = iattr.Uint16()
		case CTA_PROTOINFO_TCP_FLAGS_REPLY:
			tpi.ReplyFlags = iattr.Uint16()
		default:
			return fmt.Errorf("error: UnmarshalProtoInfo - unknown ProtoInfoTCPType %s", iattr.Type)
		}
	}

	return nil
}

// A Counter holds a pair of counters that represent
// packets and bytes sent over a Conntrack connection.
type Counter struct {
	Packets uint64
	Bytes   uint64
}

func (c Counter) String() string {
	return fmt.Sprintf("[%d pkts/%d B]", c.Packets, c.Bytes)
}

// UnmarshalAttribute unmarshals a nested counter attribute into a Counter structure.
func (ctr *Counter) UnmarshalAttribute(attr netfilter.Attribute) error {

	if !attr.Nested {
		return errNotNested
	}

	// A Counter will always consist of packet and byte attributes
	if len(attr.Children) != 2 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch CounterType(iattr.Type) {
		case CTA_COUNTERS_PACKETS:
			ctr.Packets = iattr.Uint64()
		case CTA_COUNTERS_BYTES:
			ctr.Bytes = iattr.Uint64()
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown CounterType %s", iattr.Type)
		}
	}

	return nil
}

// A Timestamp represents the start and end time of a flow.
// The timer resolution in the kernel is in nanosecond-epoch.
type Timestamp struct {
	Start time.Time
	Stop  time.Time
}

// UnmarshalTimestamp unmarshals a nested timestamp attribute into a conntrack.Timestamp structure.
func (ts *Timestamp) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTA_TIMESTAMP {
		return fmt.Errorf("error: UnmarshalAttribute - %v is not a CTA_TIMESTAMP", attr.Type)
	}

	if !attr.Nested {
		return errNotNested
	}

	// A Timestamp will always have at least a start time
	if len(attr.Children) < 1 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch TimestampType(iattr.Type) {
		case CTA_TIMESTAMP_START:
			ts.Start = time.Unix(0, iattr.Int64())
		case CTA_TIMESTAMP_STOP:
			ts.Stop = time.Unix(0, iattr.Int64())
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown TimestampType %s", iattr.Type)
		}
	}

	return nil
}

// A Security structure holds the security info belonging to a connection.
// Kernel uses this to store and match SELinux context name.
type Security struct {
	Name string
}

func (ctx *Security) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTA_SECCTX {
		return fmt.Errorf("error: UnmarshalAttribute - %v is not a CTA_SECCTX", attr.Type)
	}

	if !attr.Nested {
		return errNotNested
	}

	// A SecurityContext has at least a name
	if len(attr.Children) < 1 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch SecurityType(iattr.Type) {
		case CTA_SECCTX_NAME:
			ctx.Name = string(iattr.Data)
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown SecurityType %s", iattr.Type)
		}
	}

	return nil
}

type SequenceAdjust struct {
	Position     uint32
	OffsetBefore uint32
	OffsetAfter  uint32
}

func (seq *SequenceAdjust) UnmarshalAttribute(attr netfilter.Attribute) error {

	if !attr.Nested {
		return errNotNested
	}

	// A SequenceAdjust message should come with at least 1 child.
	if len(attr.Children) < 1 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch SequenceAdjustType(iattr.Type) {
		case CTA_SEQADJ_CORRECTION_POS:
			seq.Position = iattr.Uint32()
		case CTA_SEQADJ_OFFSET_BEFORE:
			seq.OffsetBefore = iattr.Uint32()
		case CTA_SEQADJ_OFFSET_AFTER:
			seq.OffsetAfter = iattr.Uint32()
		}
	}

	return nil
}

// DecodeAttributes calls unmarshal operations on all given netfilter.Attributes.
// It returns a map of AttributeTypes to their respective values.
func DecodeAttributes(attrs []netfilter.Attribute, filter AttributeFilter) (map[AttributeType]interface{}, error) {

	ra := make(map[AttributeType]interface{})

	for _, attr := range attrs {

		// Skip decoding the attribute if the AttributeType's bit is not enabled in filter.
		if filter&1<<attr.Type == 0 {
			continue
		}

		switch at := AttributeType(attr.Type); at {
		// CTA_TUPLE_* attributes are nested and contain source and destination values for:
		// - the IPv4/IPv6 addresses involved
		// - ports used in the connection
		// - (optional) the Conntrack Zone of the originating/replying side of the flow
		case CTA_TUPLE_ORIG, CTA_TUPLE_REPLY, CTA_TUPLE_MASTER:
			var tpl Tuple
			if err := (&tpl).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = tpl
		// CTA_STATUS is a bitfield of the state of the connection
		// (eg. if packets are seen in both directions, etc.)
		case CTA_STATUS:
			var sta Status
			if err := (&sta).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = sta
		// CTA_PROTOINFO is sent for TCP, DCCP and SCTP protocols only. It conveys extra metadata
		// about the state flags seen on the wire. Update events are sent when these change.
		case CTA_PROTOINFO:
			var pi ProtoInfo
			if err := (&pi).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = pi
		case CTA_HELP:
			var hlp Helper
			if err := (&hlp).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = hlp
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
			var ctr Counter
			if err := (&ctr).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = ctr
		// CTA_SECCTX is the SELinux security context of a Conntrack entry.
		case CTA_SECCTX:
			var sctx Security
			if err := (&sctx).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = sctx
		// CTA_ZONE describes the Conntrack zone the flow is placed in. This can be combined with a CTA_TUPLE_ZONE
		// to specify which zone an event originates from.
		case CTA_ZONE:
			ra[at] = attr.Uint16()
		// CTA_TIMESTAMP is a nested attribute that describes the start and end timestamp of a flow.
		// It is sent by the kernel with dumps and DESTROY events.
		case CTA_TIMESTAMP:
			var ts Timestamp
			if err := (&ts).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = ts
		// CTA_SEQADJ_* is generalized TCP window adjustment metadata. It is not (yet) emitted in Conntrack events.
		// The reason for its introduction is outlined in https://lwn.net/Articles/563151.
		// Patch set is at http://www.spinics.net/lists/netdev/msg245785.html.
		case CTA_SEQ_ADJ_ORIG, CTA_SEQ_ADJ_REPLY:
			var sa SequenceAdjust
			if err := (&sa).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = sa
		// CTA_LABELS is a binary bitfield attached to a connection that is sent in
		// events when changed, as well as in response to dump queries.
		// CTA_LABELS_MASK is never sent by the kernel, but it can be used
		// in set / update queries to mask label operations on the kernel state table.
		// it needs to be exactly as wide as the CTA_LABELS field it intends to mask.
		case CTA_LABELS, CTA_LABELS_MASK:
			ra[at] = attr.Data
		default:
			return nil, fmt.Errorf("error: DecodeAttributes - unknown type %s", AttributeType(attr.Type))
		}
	}

	return ra, nil
}
