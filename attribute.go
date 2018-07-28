package conntrack

import (
	"errors"
	"fmt"
	"time"

	"github.com/ti-mo/netfilter"
)

var (
	errNotImplemented  = errors.New("sorry, not implemented yet")
	errNested          = errors.New("unexpected Nested attribute")
	errNotNested       = errors.New("need a Nested attribute to decode this structure")
	errNeedSingleChild = errors.New("need (at least) 1 child attribute")
	errNeedChildren    = errors.New("need at least 2 child attributes")
	errIncorrectSize   = errors.New("binary attribute data has incorrect size")

	ctaCountersOrigReplyCat = fmt.Sprintf("%s/%s", CTACountersOrig, CTACountersReply)
	ctaSeqAdjOrigReplyCat   = fmt.Sprintf("%s/%s", CTASeqAdjOrig, CTASeqAdjReply)
)

const (
	errAttributeWrongType = "attribute Type '%d' is not a %s"
	errAttributeChild     = "child Type '%d' unknown for attribute type %s"
	errExactChildren      = "need exactly %d child attributes for attribute type %s"
)

// A Helper holds the name and info the helper that creates a related connection.
type Helper struct {
	Name string
	Info []byte
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a Helper.
func (hlp *Helper) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTAHelp {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTAHelp)
	}

	if !attr.Nested {
		return errNotNested
	}

	for _, iattr := range attr.Children {
		switch HelperType(iattr.Type) {
		case CTAHelpName:
			hlp.Name = string(iattr.Data)
		case CTAHelpInfo:
			hlp.Info = iattr.Data
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, CTAHelp)
		}
	}

	return nil
}

// The ProtoInfo structure holds one of three types:
// a ProtoInfoTCP in the TCP field,
// a ProtoInfoDCCP in the DCCP field, or
// a ProtoInfoSCTP in the SCTP field.
type ProtoInfo struct {
	TCP ProtoInfoTCP
	// TODO: DCCP *ProtoInfoDCCP
	// TODO: SCTP *ProtoInfoSCTP
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a ProtoInfo structure.
// one of three ProtoInfo types; TCP, DCCP or SCTP.
func (pi *ProtoInfo) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTAProtoInfo {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTAProtoInfo)
	}

	if !attr.Nested {
		return errNotNested
	}

	if len(attr.Children) != 1 {
		return errNeedSingleChild
	}

	// Step into the single nested child
	iattr := attr.Children[0]

	switch ProtoInfoType(iattr.Type) {
	case CTAProtoInfoTCP:
		var tpi ProtoInfoTCP
		if err := (&tpi).UnmarshalAttribute(iattr); err != nil {
			return err
		}
		pi.TCP = tpi
	case CTAProtoInfoDCCP:
		return errNotImplemented
	case CTAProtoInfoSCTP:
		return errNotImplemented
	default:
		return fmt.Errorf(errAttributeChild, iattr.Type, CTAProtoInfo)
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

// UnmarshalAttribute unmarshals a netfilter.Attribute into a ProtoInfoTCP.
func (tpi *ProtoInfoTCP) UnmarshalAttribute(attr netfilter.Attribute) error {

	if ProtoInfoType(attr.Type) != CTAProtoInfoTCP {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTAProtoInfoTCP)
	}

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
		case CTAProtoInfoTCPState:
			tpi.State = iattr.Data[0]
		case CTAProtoInfoTCPWScaleOriginal:
			tpi.OriginalWindowScale = iattr.Data[0]
		case CTAProtoInfoTCPWScaleReply:
			tpi.ReplyWindowScale = iattr.Data[0]
		case CTAProtoInfoTCPFlagsOriginal:
			tpi.OriginalFlags = iattr.Uint16()
		case CTAProtoInfoTCPFlagsReply:
			tpi.ReplyFlags = iattr.Uint16()
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, CTAProtoInfoTCP)
		}
	}

	return nil
}

// A Counter holds a pair of counters that represent packets and bytes sent over
// a Conntrack connection. Direction is true when it's a reply counter.
type Counter struct {

	// true means it's a reply counter,
	// false is the original direction
	Direction bool

	Packets uint64
	Bytes   uint64
}

func (ctr Counter) String() string {
	dir := "orig"
	if ctr.Direction {
		dir = "reply"
	}

	return fmt.Sprintf("[%s: %d pkts/%d B]", dir, ctr.Packets, ctr.Bytes)
}

// UnmarshalAttribute unmarshals a nested counter attribute into a Counter structure.
func (ctr *Counter) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTACountersOrig &&
		AttributeType(attr.Type) != CTACountersReply {
		return fmt.Errorf(errAttributeWrongType, attr.Type, ctaCountersOrigReplyCat)
	}

	if !attr.Nested {
		return errNotNested
	}

	// A Counter will always consist of packet and byte attributes
	if len(attr.Children) != 2 {
		return fmt.Errorf(errExactChildren, 2, ctaCountersOrigReplyCat)
	}

	// Set Direction to true if it's a reply counter
	ctr.Direction = AttributeType(attr.Type) == CTACountersReply

	for _, iattr := range attr.Children {
		switch CounterType(iattr.Type) {
		case CTACountersPackets:
			ctr.Packets = iattr.Uint64()
		case CTACountersBytes:
			ctr.Bytes = iattr.Uint64()
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, ctaCountersOrigReplyCat)
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

// UnmarshalAttribute unmarshals a nested timestamp attribute into a conntrack.Timestamp structure.
func (ts *Timestamp) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTATimestamp {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTATimestamp)
	}

	if !attr.Nested {
		return errNotNested
	}

	// A Timestamp will always have at least a start time
	if len(attr.Children) < 1 {
		return errNeedSingleChild
	}

	for _, iattr := range attr.Children {
		switch TimestampType(iattr.Type) {
		case CTATimestampStart:
			ts.Start = time.Unix(0, iattr.Int64())
		case CTATimestampStop:
			ts.Stop = time.Unix(0, iattr.Int64())
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, CTATimestamp)
		}
	}

	return nil
}

// A Security structure holds the security info belonging to a connection.
// Kernel uses this to store and match SELinux context name.
type Security struct {
	Name string
}

// UnmarshalAttribute unmarshals a nested security attribute into a conntrack.Security structure.
func (ctx *Security) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTASecCtx {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTASecCtx)
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
		case CTASecCtxName:
			ctx.Name = string(iattr.Data)
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, CTASecCtx)
		}
	}

	return nil
}

// SequenceAdjust represents a TCP sequence number adjustment event.
// Direction is true when it's a reply adjustment.
type SequenceAdjust struct {
	// true means it's a reply adjustment,
	// false is the original direction
	Direction bool

	Position     uint32
	OffsetBefore uint32
	OffsetAfter  uint32
}

func (seq SequenceAdjust) String() string {
	dir := "orig"
	if seq.Direction {
		dir = "reply"
	}

	return fmt.Sprintf("[dir: %s, pos: %d, before: %d, after: %d]", dir, seq.Position, seq.OffsetBefore, seq.OffsetAfter)
}

// UnmarshalAttribute unmarshals a nested sequence adjustment attribute into a
// conntrack.SequenceAdjust structure.
func (seq *SequenceAdjust) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTASeqAdjOrig &&
		AttributeType(attr.Type) != CTASeqAdjReply {
		return fmt.Errorf(errAttributeWrongType, attr.Type, ctaSeqAdjOrigReplyCat)
	}

	if !attr.Nested {
		return errNotNested
	}

	// A SequenceAdjust message should come with at least 1 child.
	if len(attr.Children) < 1 {
		return errNeedSingleChild
	}

	// Set Direction to true if it's a reply adjustment
	seq.Direction = AttributeType(attr.Type) == CTASeqAdjReply

	for _, iattr := range attr.Children {
		switch SequenceAdjustType(iattr.Type) {
		case CTASeqAdjCorrectionPos:
			seq.Position = iattr.Uint32()
		case CTASeqAdjOffsetBefore:
			seq.OffsetBefore = iattr.Uint32()
		case CTASeqAdjOffsetAfter:
			seq.OffsetAfter = iattr.Uint32()
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, ctaSeqAdjOrigReplyCat)
		}
	}

	return nil
}

// UnmarshalAttributes calls unmarshal operations on all given netfilter.Attributes.
// It returns a map of AttributeTypes to their respective values.
func UnmarshalAttributes(attrs []netfilter.Attribute, filter AttributeFilter) (map[AttributeType]interface{}, error) {

	ra := make(map[AttributeType]interface{})

	for _, attr := range attrs {

		// Skip decoding the attribute if the AttributeType's bit is not enabled in filter.
		if !filter.Check(AttributeType(attr.Type)) {
			continue
		}

		switch at := AttributeType(attr.Type); at {

		// CTA_TUPLE_* attributes are nested and contain source and destination values for:
		// - the IPv4/IPv6 addresses involved
		// - ports used in the connection
		// - (optional) the Conntrack Zone of the originating/replying side of the flow
		case CTATupleOrig, CTATupleReply, CTATupleMaster:
			var tpl Tuple
			if err := (&tpl).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = tpl

		// CTA_STATUS is a bitfield of the state of the connection
		// (eg. if packets are seen in both directions, etc.)
		case CTAStatus:
			var sta Status
			if err := (&sta).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = sta

		// CTA_PROTOINFO is sent for TCP, DCCP and SCTP protocols only. It conveys extra metadata
		// about the state flags seen on the wire. Update events are sent when these change.
		case CTAProtoInfo:
			var pi ProtoInfo
			if err := (&pi).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = pi

		case CTAHelp:
			var hlp Helper
			if err := (&hlp).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = hlp

		// CTA_TIMEOUT is the time until the Conntrack entry is automatically destroyed.
		// CTA_ID is the tuple hash value generated by the kernel. It can be relied on for flow identification.
		// CTA_USE's purpose is shrouded in mystery.
		case CTATimeout, CTAID, CTAUse:
			ra[at] = attr.Uint32()

		// CTA_MARK is the connection's connmark
		// CTA_MARK_MASK is never sent by the kernel, but can be used for kernel-space dump filtering!
		case CTAMark, CTAMarkMask:
			ra[at] = attr.Uint32()

		// CTA_COUNTERS_* attributes are nested and contain byte and packet counters for flows in either direction.
		case CTACountersOrig, CTACountersReply:
			var ctr Counter
			if err := (&ctr).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = ctr

		// CTA_SECCTX is the SELinux security context of a Conntrack entry.
		case CTASecCtx:
			var sctx Security
			if err := (&sctx).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = sctx

		// CTA_ZONE describes the Conntrack zone the flow is placed in. This can be combined with a CTA_TUPLE_ZONE
		// to specify which zone an event originates from.
		case CTAZone:
			ra[at] = attr.Uint16()

		// CTA_TIMESTAMP is a nested attribute that describes the start and end timestamp of a flow.
		// It is sent by the kernel with dumps and DESTROY events.
		case CTATimestamp:
			var ts Timestamp
			if err := (&ts).UnmarshalAttribute(attr); err != nil {
				return nil, err
			}
			ra[at] = ts

		// CTA_SEQADJ_* is generalized TCP window adjustment metadata. It is not (yet) emitted in Conntrack events.
		// The reason for its introduction is outlined in https://lwn.net/Articles/563151.
		// Patch set is at http://www.spinics.net/lists/netdev/msg245785.html.
		case CTASeqAdjOrig, CTASeqAdjReply:
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
		case CTALabels, CTALabelsMask:
			ra[at] = attr.Data

		default:
			return nil, fmt.Errorf("error: DecodeAttributes - unknown type %s", AttributeType(attr.Type))
		}
	}

	return ra, nil
}
