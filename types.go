package conntrack

import "github.com/gonetlink/netfilter"

// MessageType is a Conntrack-specific representation of a netfilter.MessageType.
// It is used to specify the type of action to execute on
// the kernel's state table (get, create, delete, etc.).
type Messagetype netfilter.MessageType

const (
	IPCTNL_MSG_CT_NEW Messagetype = iota
	IPCTNL_MSG_CT_GET
	IPCTNL_MSG_CT_DELETE
	IPCTNL_MSG_CT_GET_CTRZERO
	IPCTNL_MSG_CT_GET_STATS_CPU
	IPCTNL_MSG_CT_GET_STATS
	IPCTNL_MSG_CT_GET_DYING
	IPCTNL_MSG_CT_GET_UNCONFIRMED
)

// AttributeType defines the meaning of a root-level Type
// value of a Conntrack-specific Netfilter attribute.
type AttributeType uint8

// This is enum ctattr_type defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_UNSPEC AttributeType = iota
	CTA_TUPLE_ORIG
	CTA_TUPLE_REPLY
	CTA_STATUS
	CTA_PROTOINFO
	CTA_HELP
	CTA_NAT_SRC // Deprecated
	CTA_TIMEOUT
	CTA_MARK
	CTA_COUNTERS_ORIG
	CTA_COUNTERS_REPLY
	CTA_USE
	CTA_ID
	CTA_NAT_DST // Deprecated
	CTA_TUPLE_MASTER
	CTA_SEQ_ADJ_ORIG
	CTA_SEQ_ADJ_REPLY
	CTA_SECMARK // Deprecated
	CTA_ZONE
	CTA_SECCTX
	CTA_TIMESTAMP
	CTA_MARK_MASK
	CTA_LABELS
	CTA_LABELS_MASK
	__CTA_MAX
)

// TupleType describes the type of tuple contained in this container.
type TupleType uint8

// This is enum ctattr_tuple defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_TUPLE_UNSPEC TupleType = iota
	CTA_TUPLE_IP
	CTA_TUPLE_PROTO
	CTA_TUPLE_ZONE
)

// ProtoTupleType describes the type of Layer 4 protocol metadata in this container.
type ProtoTupleType uint8

// This is enum ctattr_l4proto defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_PROTO_UNSPEC ProtoTupleType = iota
	CTA_PROTO_NUM
	CTA_PROTO_SRC_PORT
	CTA_PROTO_DST_PORT
	CTA_PROTO_ICMP_ID
	CTA_PROTO_ICMP_TYPE
	CTA_PROTO_ICMP_CODE
	CTA_PROTO_ICMPV6_ID
	CTA_PROTO_ICMPV6_TYPE
	CTA_PROTO_ICMPV6_CODE
)

type IPTupleType uint8

// This is enum ctattr_ip defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_IP_UNSPEC IPTupleType = iota
	CTA_IP_V4_SRC
	CTA_IP_V4_DST
	CTA_IP_V6_SRC
	CTA_IP_V6_DST
)

type HelperType uint8

// This is enum ctattr_help defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_HELP_UNSPEC HelperType = iota
	CTA_HELP_NAME
	CTA_HELP_INFO
)

type CounterType uint8

// This is enum ctattr_counters defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_COUNTERS_UNSPEC CounterType = iota
	CTA_COUNTERS_PACKETS
	CTA_COUNTERS_BYTES
)

type TimestampType uint8

// This is enum ctattr_tstamp defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_TIMESTAMP_UNSPEC TimestampType = iota
	CTA_TIMESTAMP_START
	CTA_TIMESTAMP_STOP
	CTA_TIMESTAMP_PAD
)

type SecurityType uint8

// This is enum enum ctattr_secctx defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_SECCTX_UNSPEC SecurityType = iota
	CTA_SECCTX_NAME
)

type ProtoInfoType uint8

// This is enum ctattr_protoinfo defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_PROTOINFO_UNSPEC ProtoInfoType = iota
	CTA_PROTOINFO_TCP
	CTA_PROTOINFO_DCCP
	CTA_PROTOINFO_SCTP
)

type ProtoInfoTCPType uint8

const (
	CTA_PROTOINFO_TCP_UNSPEC ProtoInfoTCPType = iota
	CTA_PROTOINFO_TCP_STATE
	CTA_PROTOINFO_TCP_WSCALE_ORIGINAL
	CTA_PROTOINFO_TCP_WSCALE_REPLY
	CTA_PROTOINFO_TCP_FLAGS_ORIGINAL
	CTA_PROTOINFO_TCP_FLAGS_REPLY
)

type SequenceAdjustType uint8

// This is enum ctattr_seqadj defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_SEQADJ_UNSPEC SequenceAdjustType = iota
	CTA_SEQADJ_CORRECTION_POS
	CTA_SEQADJ_OFFSET_BEFORE
	CTA_SEQADJ_OFFSET_AFTER
)
