package conntrack

import "github.com/gonetlink/netfilter"

// From libnfnetlink/include/libnfnetlink/linux_nfnetlink_compat.h
// This table is still actively used in upstream conntrack-tools and libnfnetlink
// It is in a _compat file because these values presumably stem from a time where there were
// only 32 multicast Netlink groups available. (before genetlink?)
const (
	NF_NETLINK_CONNTRACK_NEW         = 1
	NF_NETLINK_CONNTRACK_UPDATE      = 1 << 1
	NF_NETLINK_CONNTRACK_DESTROY     = 1 << 2
	NF_NETLINK_CONNTRACK_EXP_NEW     = 1 << 3
	NF_NETLINK_CONNTRACK_EXP_UPDATE  = 1 << 4
	NF_NETLINK_CONNTRACK_EXP_DESTROY = 1 << 5

	NFCT_ALL_CT_GROUPS = (NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE | NF_NETLINK_CONNTRACK_DESTROY)
)

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
	CTA_NAT_SRC
	CTA_TIMEOUT
	CTA_MARK
	CTA_COUNTERS_ORIG
	CTA_COUNTERS_REPLY
	CTA_USE
	CTA_ID
	CTA_NAT_DST
	CTA_TUPLE_MASTER
	CTA_SEQ_ADJ_ORIG
	CTA_NAT_SEQ_ADJ_ORIG = CTA_SEQ_ADJ_ORIG
	CTA_SEQ_ADJ_REPLY
	CTA_NAT_SEQ_ADJ_REPLY = CTA_SEQ_ADJ_REPLY
	CTA_SECMARK
	CTA_ZONE
	CTA_SECCTX
	CTA_TIMESTAMP
	CTA_MARK_MASK
	CTA_LABELS
	CTA_LABELS_MASK
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

// ProtoType describes the type of Layer 4 protocol metadata in this container.
type ProtoType uint8

// This is enum ctattr_l4proto defined in
// Linux/include/uapi/linux/netfilter/nfnetlink_conntrack.h
const (
	CTA_PROTO_UNSPEC ProtoType = iota
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

type IPType uint8

const (
	CTA_IP_UNSPEC IPType = iota
	CTA_IP_V4_SRC
	CTA_IP_V4_DST
	CTA_IP_V6_SRC
	CTA_IP_V6_DST
)
