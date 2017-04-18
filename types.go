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
