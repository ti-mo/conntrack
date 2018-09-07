package conntrack

import (
	"fmt"
	"time"

	"github.com/ti-mo/netfilter"
)

var (
	ctaCountersOrigReplyCat = fmt.Sprintf("%s/%s", CTACountersOrig, CTACountersReply)
	ctaSeqAdjOrigReplyCat   = fmt.Sprintf("%s/%s", CTASeqAdjOrig, CTASeqAdjReply)
)

// Attribute is an interface implemented by all Conntrack attribute types.
type Attribute interface {
	UnmarshalAttribute(netfilter.Attribute) error
}

// Num16 is a generic numeric attribute. It is represented by a uint32
// and holds its own AttributeType.
type Num16 struct {
	Type  AttributeType
	Value uint16
}

// Filled returns true if the Num16's type is non-zero.
func (i Num16) Filled() bool {
	return i.Type != 0
}

func (i Num16) String() string {
	return fmt.Sprintf("%d", i.Value)
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a Num16.
func (i *Num16) UnmarshalAttribute(attr netfilter.Attribute) error {

	if len(attr.Data) != 2 {
		return errIncorrectSize
	}

	i.Type = AttributeType(attr.Type)
	i.Value = attr.Uint16()

	return nil
}

// MarshalAttribute marshals a Num16 into a netfilter.Attribute. If the AttributeType parameter is non-zero,
// it is used as Attribute's type; otherwise, the Num16's Type field is used.
func (i Num16) MarshalAttribute(t AttributeType) netfilter.Attribute {

	var nfa netfilter.Attribute

	if t == 0 {
		nfa.Type = uint16(i.Type)
	} else {
		nfa.Type = uint16(t)
	}

	nfa.PutUint16(i.Value)

	return nfa
}

// Num32 is a generic numeric attribute. It is represented by a uint32
// and holds its own AttributeType.
type Num32 struct {
	Type  AttributeType
	Value uint32
}

// Filled returns true if the Num32's type is non-zero.
func (i Num32) Filled() bool {
	return i.Type != 0
}

func (i Num32) String() string {
	return fmt.Sprintf("%d", i.Value)
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a Num32.
func (i *Num32) UnmarshalAttribute(attr netfilter.Attribute) error {

	if len(attr.Data) != 4 {
		return errIncorrectSize
	}

	i.Type = AttributeType(attr.Type)
	i.Value = attr.Uint32()

	return nil
}

// MarshalAttribute marshals a Num32 into a netfilter.Attribute. If the AttributeType parameter is non-zero,
// it is used as Attribute's type; otherwise, the Num32's Type field is used.
func (i Num32) MarshalAttribute(t AttributeType) netfilter.Attribute {

	var nfa netfilter.Attribute

	if t == 0 {
		nfa.Type = uint16(i.Type)
	} else {
		nfa.Type = uint16(t)
	}

	nfa.PutUint32(i.Value)

	return nfa
}

// Binary is a binary attribute that is backed by a byte slice.
type Binary struct {
	Type AttributeType
	Data []byte
}

// Filled returns true if the bitfield's values are non-zero.
func (b Binary) Filled() bool {
	return len(b.Data) != 0
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a Binary struct.
func (b *Binary) UnmarshalAttribute(attr netfilter.Attribute) error {

	b.Type = AttributeType(attr.Type)
	b.Data = attr.Data

	return nil
}

// A Helper holds the name and info the helper that creates a related connection.
type Helper struct {
	Name string
	Info []byte
}

// Filled returns true if the Helper's values are non-zero.
func (hlp Helper) Filled() bool {
	return hlp.Name != "" || len(hlp.Info) > 0
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

// MarshalAttribute marshals a Helper into a netfilter.Attribute.
func (hlp Helper) MarshalAttribute() netfilter.Attribute {

	var nfa netfilter.Attribute
	nfa.Type = uint16(CTAHelp)
	nfa.Nested = true

	nfa.Children = []netfilter.Attribute{
		{Type: uint16(CTAHelpName), Data: []byte(hlp.Name)},
	}

	if len(hlp.Info) > 0 {
		nfa.Children = append(nfa.Children, netfilter.Attribute{Type: uint16(CTAHelpInfo), Data: hlp.Info})
	}

	return nfa
}

// The ProtoInfo structure holds a pointer to
// one of ProtoInfoTCP, ProtoInfoDCCP or ProtoInfoSCTP.
type ProtoInfo struct {
	TCP  *ProtoInfoTCP
	DCCP *ProtoInfoDCCP
	SCTP *ProtoInfoSCTP
}

// Filled returns true if one of the ProtoInfo's values are non-zero.
func (pi ProtoInfo) Filled() bool {
	return pi.TCP != nil || pi.DCCP != nil || pi.SCTP != nil
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a ProtoInfo structure.
// one of three ProtoInfo types; TCP, DCCP or SCTP.
func (pi *ProtoInfo) UnmarshalAttribute(attr netfilter.Attribute) error {

	// Make sure we don't unmarshal into the same ProtoInfo twice.
	if pi.TCP != nil || pi.DCCP != nil || pi.SCTP != nil {
		return errReusedProtoInfo
	}

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
		pi.TCP = &tpi
	case CTAProtoInfoDCCP:
		var dpi ProtoInfoDCCP
		if err := (&dpi).UnmarshalAttribute(iattr); err != nil {
			return err
		}
		pi.DCCP = &dpi
	case CTAProtoInfoSCTP:
		var spi ProtoInfoSCTP
		if err := (&spi).UnmarshalAttribute(iattr); err != nil {
			return err
		}
		pi.SCTP = &spi
	default:
		return fmt.Errorf(errAttributeChild, iattr.Type, CTAProtoInfo)
	}

	return nil
}

// MarshalAttribute marshals a ProtoInfo into a netfilter.Attribute.
func (pi ProtoInfo) MarshalAttribute() (netfilter.Attribute, error) {

	nfa := netfilter.Attribute{Type: uint16(CTAProtoInfo), Nested: true}

	if pi.TCP != nil {
		nfa.Children[0] = pi.TCP.MarshalAttribute()
	} else if pi.DCCP != nil {
		nfa.Children[0] = pi.DCCP.MarshalAttribute()
	} else if pi.SCTP != nil {
		nfa.Children[0] = pi.SCTP.MarshalAttribute()
	} else {
		return netfilter.Attribute{}, errEmptyProtoInfo
	}

	return nfa, nil
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

	// A ProtoInfoTCP has at least 3 members, TCP_STATE and TCP_FLAGS_ORIG/REPLY.
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

// MarshalAttribute marshals a ProtoInfoTCP into a netfilter.Attribute.
func (tpi ProtoInfoTCP) MarshalAttribute() netfilter.Attribute {

	nfa := netfilter.Attribute{Type: uint16(CTAProtoInfoTCP), Nested: true, Children: make([]netfilter.Attribute, 3, 5)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(CTAProtoInfoTCPState), Data: []byte{tpi.State}}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(CTAProtoInfoTCPWScaleOriginal), Data: []byte{tpi.OriginalWindowScale}}
	nfa.Children[2] = netfilter.Attribute{Type: uint16(CTAProtoInfoTCPWScaleReply), Data: []byte{tpi.ReplyWindowScale}}

	// Only append TCP flags to attributes when either of them is non-zero.
	if tpi.OriginalFlags != 0 || tpi.ReplyFlags != 0 {

		of := netfilter.Attribute{Type: uint16(CTAProtoInfoTCPFlagsOriginal)}
		of.PutUint16(tpi.OriginalFlags)
		rf := netfilter.Attribute{Type: uint16(CTAProtoInfoTCPFlagsReply)}
		rf.PutUint16(tpi.ReplyFlags)

		nfa.Children = append(nfa.Children, of, rf)
	}

	return nfa
}

// ProtoInfoDCCP describes the state of a DCCP connection.
type ProtoInfoDCCP struct {
	State, Role  uint8
	HandshakeSeq uint64
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a ProtoInfoTCP.
func (dpi *ProtoInfoDCCP) UnmarshalAttribute(attr netfilter.Attribute) error {

	if ProtoInfoType(attr.Type) != CTAProtoInfoDCCP {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTAProtoInfoDCCP)
	}

	if !attr.Nested {
		return errNotNested
	}

	if len(attr.Children) == 0 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch ProtoInfoDCCPType(iattr.Type) {
		case CTAProtoInfoDCCPState:
			dpi.State = iattr.Data[0]
		case CTAProtoInfoDCCPRole:
			dpi.Role = iattr.Data[0]
		case CTAProtoInfoDCCPHandshakeSeq:
			dpi.HandshakeSeq = iattr.Uint64()
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, CTAProtoInfoDCCP)
		}
	}

	return nil
}

// MarshalAttribute marshals a ProtoInfoDCCP into a netfilter.Attribute.
func (dpi ProtoInfoDCCP) MarshalAttribute() netfilter.Attribute {

	nfa := netfilter.Attribute{Type: uint16(CTAProtoInfoDCCP), Nested: true, Children: make([]netfilter.Attribute, 3)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(CTAProtoInfoDCCPState), Data: []byte{dpi.State}}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(CTAProtoInfoDCCPRole), Data: []byte{dpi.Role}}

	hs := netfilter.Attribute{Type: uint16(CTAProtoInfoDCCPHandshakeSeq)}
	hs.PutUint64(dpi.HandshakeSeq)
	nfa.Children[2] = hs

	return nfa
}

// ProtoInfoSCTP describes the state of an SCTP connection.
type ProtoInfoSCTP struct {
	State                   uint8
	VTagOriginal, VTagReply uint32
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a ProtoInfoSCTP.
func (spi *ProtoInfoSCTP) UnmarshalAttribute(attr netfilter.Attribute) error {

	if ProtoInfoType(attr.Type) != CTAProtoInfoSCTP {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTAProtoInfoSCTP)
	}

	if !attr.Nested {
		return errNotNested
	}

	if len(attr.Children) == 0 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch ProtoInfoSCTPType(iattr.Type) {
		case CTAProtoInfoSCTPState:
			spi.State = iattr.Data[0]
		case CTAProtoInfoSCTPVTagOriginal:
			spi.VTagOriginal = iattr.Uint32()
		case CTAProtoInfoSCTPVtagReply:
			spi.VTagReply = iattr.Uint32()
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, CTAProtoInfoSCTP)
		}
	}

	return nil
}

// MarshalAttribute marshals a ProtoInfoSCTP into a netfilter.Attribute.
func (spi ProtoInfoSCTP) MarshalAttribute() netfilter.Attribute {

	nfa := netfilter.Attribute{Type: uint16(CTAProtoInfoSCTP), Nested: true, Children: make([]netfilter.Attribute, 3)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(CTAProtoInfoSCTPState), Data: []byte{spi.State}}

	vto := netfilter.Attribute{Type: uint16(CTAProtoInfoSCTPVTagOriginal)}
	vtr := netfilter.Attribute{Type: uint16(CTAProtoInfoSCTPVtagReply)}

	vto.PutUint32(spi.VTagOriginal)
	vtr.PutUint32(spi.VTagReply)

	return nfa
}

// A Counter holds a pair of counters that represent packets and bytes sent over
// a Conntrack connection. Direction is true when it's a reply counter.
// This attribute cannot be changed on a connection and thus cannot be marshaled.
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

// Filled returns true if the counter's values are non-zero.
func (ctr Counter) Filled() bool {
	return ctr.Bytes != 0 && ctr.Packets != 0
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
// This attribute cannot be changed on a connection and thus cannot be marshaled.
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
	if len(attr.Children) == 0 {
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
// This attribute cannot be changed on a connection and thus cannot be marshaled.
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
	if len(attr.Children) == 0 {
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

// Filled returns true if the SequenceAdjust's values are non-zero.
// SeqAdj qualify as filled if all of its members are non-zero.
func (seq SequenceAdjust) Filled() bool {
	return seq.Position != 0 && seq.OffsetAfter != 0 && seq.OffsetBefore != 0
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
	if len(attr.Children) == 0 {
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

// MarshalAttribute marshals a SequenceAdjust into a netfilter.Attribute.
func (seq SequenceAdjust) MarshalAttribute() netfilter.Attribute {

	// Set orig/reply AttributeType
	at := CTASeqAdjOrig
	if seq.Direction {
		at = CTASeqAdjReply
	}

	nfa := netfilter.Attribute{Type: uint16(at), Nested: true, Children: make([]netfilter.Attribute, 3)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(CTASeqAdjCorrectionPos)}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(CTASeqAdjOffsetBefore)}
	nfa.Children[2] = netfilter.Attribute{Type: uint16(CTASeqAdjOffsetAfter)}

	nfa.Children[0].PutUint32(seq.Position)
	nfa.Children[1].PutUint32(seq.OffsetBefore)
	nfa.Children[2].PutUint32(seq.OffsetAfter)

	return nfa
}

// SynProxy represents the SYN proxy parameters of a Conntrack flow.
type SynProxy struct {
	ISN   uint32
	ITS   uint32
	TSOff uint32
}

// Filled returns true if the SynProxy's values are non-zero.
// SynProxy qualifies as filled if one of its members is non-zero.
func (sp SynProxy) Filled() bool {
	return sp.ISN != 0 || sp.ITS != 0 || sp.TSOff != 0
}

// UnmarshalAttribute unmarshals a SYN proxy attribute into a SynProxy structure.
func (sp *SynProxy) UnmarshalAttribute(attr netfilter.Attribute) error {

	if AttributeType(attr.Type) != CTASynProxy {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTASynProxy)
	}

	if !attr.Nested {
		return errNotNested
	}

	if len(attr.Children) == 0 {
		return errNeedSingleChild
	}

	for _, iattr := range attr.Children {
		switch SynProxyType(iattr.Type) {
		case CTASynProxyISN:
			sp.ISN = iattr.Uint32()
		case CTASynProxyITS:
			sp.ITS = iattr.Uint32()
		case CTASynProxyTSOff:
			sp.TSOff = iattr.Uint32()
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, CTASynProxy)
		}
	}

	return nil
}

// MarshalAttribute marshals a SynProxy into a netfilter.Attribute.
func (sp SynProxy) MarshalAttribute() netfilter.Attribute {

	nfa := netfilter.Attribute{Type: uint16(CTASynProxy), Nested: true, Children: make([]netfilter.Attribute, 3)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(CTASynProxyISN)}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(CTASynProxyITS)}
	nfa.Children[2] = netfilter.Attribute{Type: uint16(CTASynProxyTSOff)}

	nfa.Children[0].PutUint32(sp.ISN)
	nfa.Children[1].PutUint32(sp.ITS)
	nfa.Children[2].PutUint32(sp.TSOff)

	return nfa
}

// TODO: CTAStats
// TODO: CTAStatsGlobal
// TODO: CTAStatsExp
