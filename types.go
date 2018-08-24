package conntrack

import "github.com/ti-mo/netfilter"

// All enums in this file are translated from the Linux kernel source at
// include/uapi/linux/netfilter/nfnetlink_conntrack.h

// MessageType is a Conntrack-specific representation of a netfilter.MessageType.
// It is used to specify the type of action to execute on the kernel's state table
// (get, create, delete, etc.).
type MessageType netfilter.MessageType

// enum cntl_msg_types (typo)
// The first three members are similar to NF_NETLINK_CONNTRACK_*, which is still used
// in libnetfilter_conntrack. They can still be used to subscribe to Netlink groups with bind(),
// but subscribing using setsockopt() (like mdlayher/netlink) requires the NFNLGRP_* enum.
const (
	CTNew MessageType = iota // IPCTNL_MSG_CT_NEW

	CTGet            // IPCTNL_MSG_CT_GET
	CTDelete         // IPCTNL_MSG_CT_DELETE
	CTGetCtrZero     // IPCTNL_MSG_CT_GET_CTRZERO
	CTGetStatsCPU    // IPCTNL_MSG_CT_GET_STATS_CPU
	CTGetStats       // IPCTNL_MSG_CT_GET_STATS
	CTGetDying       // IPCTNL_MSG_CT_GET_DYING
	CTGetUnconfirmed // IPCTNL_MSG_CT_GET_UNCONFIRMED
)

// ExpMessageType is a Conntrack-specific representation of a netfilter.MessageType.
// It holds information about Conntrack Expect events; state created by Conntrack helpers.
type ExpMessageType netfilter.MessageType

// enum ctnl_exp_msg_types
const (
	CTExpNew ExpMessageType = iota // IPCTNL_MSG_EXP_NEW

	CTExpGet         // IPCTNL_MSG_EXP_GET
	CTExpDelete      // IPCTNL_MSG_EXP_DELETE
	CTExpGetStatsCPU // IPCTNL_MSG_EXP_GET_STATS_CPU
)

// AttributeType defines the meaning of a root-level Type
// value of a Conntrack-specific Netfilter attribute.
//go:generate stringer -type=AttributeType
type AttributeType uint8

// enum ctattr_type
const (
	CTAUnspec AttributeType = iota // CTA_UNSPEC

	CTATupleOrig     // CTA_TUPLE_ORIG
	CTATupleReply    // CTA_TUPLE_REPLY
	CTAStatus        // CTA_STATUS
	CTAProtoInfo     // CTA_PROTOINFO
	CTAHelp          // CTA_HELP
	CTANatSrc        // CTA_NAT_SRC, Deprecated
	CTATimeout       // CTA_TIMEOUT
	CTAMark          // CTA_MARK
	CTACountersOrig  // CTA_COUNTERS_ORIG
	CTACountersReply // CTA_COUNTERS_REPLY
	CTAUse           // CTA_USE
	CTAID            // CTA_ID
	CTANatDst        // CTA_NAT_DST, Deprecated
	CTATupleMaster   // CTA_TUPLE_MASTER
	CTASeqAdjOrig    // CTA_SEQ_ADJ_ORIG
	CTASeqAdjReply   // CTA_SEQ_ADJ_REPLY
	CTASecMark       // CTA_SECMARK, Deprecated
	CTAZone          // CTA_ZONE
	CTASecCtx        // CTA_SECCTX
	CTATimestamp     // CTA_TIMESTAMP
	CTAMarkMask      // CTA_MARK_MASK
	CTALabels        // CTA_LABELS
	CTALabelsMask    // CTA_LABELS_MASK
	CTASynProxy      // CTA_SYNPROXY
)

// TupleType describes the type of tuple contained in this container.
//go:generate stringer -type=TupleType
type TupleType uint8

// enum ctattr_tuple
const (
	CTATupleUnspec TupleType = iota //CTA_TUPLE_UNSPEC

	CTATupleIP    // CTA_TUPLE_IP
	CTATupleProto // CTA_TUPLE_PROTO
	CTATupleZone  // CTA_TUPLE_ZONE
)

// ProtoTupleType describes the type of Layer 4 protocol metadata in this container.
type ProtoTupleType uint8

// enum ctattr_l4proto
const (
	CTAProtoUnspec ProtoTupleType = iota // CTA_PROTO_UNSPEC

	CTAProtoNum        // CTA_PROTO_NUM
	CTAProtoSrcPort    // CTA_PROTO_SRC_PORT
	CTAProtoDstPort    // CTA_PROTO_DST_PORT
	CTAProtoICMPID     // CTA_PROTO_ICMP_ID
	CTAProtoICMPType   // CTA_PROTO_ICMP_TYPE
	CTAProtoICMPCode   // CTA_PROTO_ICMP_CODE
	CTAProtoICMPv6ID   // CTA_PROTO_ICMPV6_ID
	CTAProtoICMPv6Type // CTA_PROTO_ICMPV6_TYPE
	CTAProtoICMPv6Code // CTA_PROTO_ICMPV6_CODE
)

// IPTupleType describes the type of IP address in this container.
type IPTupleType uint8

// enum ctattr_ip
const (
	CTAIPUnspec IPTupleType = iota // CTA_IP_UNSPEC

	CTAIPv4Src // CTA_IP_V4_SRC
	CTAIPv4Dst // CTA_IP_V4_DST
	CTAIPv6Src // CTA_IP_V6_SRC
	CTAIPv6Dst // CTA_IP_V6_DST
)

// HelperType describes the kind of helper in this container.
type HelperType uint8

// enum ctattr_help
const (
	CTAHelpUnspec HelperType = iota // CTA_HELP_UNSPEC

	CTAHelpName // CTA_HELP_NAME
	CTAHelpInfo // CTA_HELP_INFO
)

// CounterType describes the kind of counter in this container.
type CounterType uint8

// enum ctattr_counters
const (
	CTACountersUnspec CounterType = iota // CTA_COUNTERS_UNSPEC

	CTACountersPackets // CTA_COUNTERS_PACKETS
	CTACountersBytes   // CTA_COUNTERS_BYTES
)

// TimestampType describes the type of timestamp in this container.
type TimestampType uint8

// enum ctattr_tstamp
const (
	CTATimestampUnspec TimestampType = iota // CTA_TIMESTAMP_UNSPEC

	CTATimestampStart // CTA_TIMESTAMP_START
	CTATimestampStop  // CTA_TIMESTAMP_STOP
	CTATimestampPad   // CTA_TIMESTAMP_PAD
)

// SecurityType describes the type of SecCtx value in this container.
type SecurityType uint8

// enum ctattr_secctx
const (
	CTASecCtxUnspec SecurityType = iota // CTA_SECCTX_UNSPEC
	CTASecCtxName                       // CTA_SECCTX_NAME
)

// ProtoInfoType describes the kind of protocol info in this container.
//go:generate stringer -type=ProtoInfoType
type ProtoInfoType uint8

// enum ctattr_protoinfo
const (
	CTAProtoInfoUnspec ProtoInfoType = iota // CTA_PROTOINFO_UNSPEC

	CTAProtoInfoTCP  // CTA_PROTOINFO_TCP
	CTAProtoInfoDCCP // CTA_PROTOINFO_DCCP
	CTAProtoInfoSCTP // CTA_PROTOINFO_SCTP
)

// ProtoInfoTCPType describes the kind of TCP protocol info attribute in this container.
type ProtoInfoTCPType uint8

// enum ctattr_protoinfo_tcp
const (
	CTAProtoInfoTCPUnspec ProtoInfoTCPType = iota // CTA_PROTOINFO_TCP_UNSPEC

	CTAProtoInfoTCPState          // CTA_PROTOINFO_TCP_STATE
	CTAProtoInfoTCPWScaleOriginal // CTA_PROTOINFO_TCP_WSCALE_ORIGINAL
	CTAProtoInfoTCPWScaleReply    // CTA_PROTOINFO_TCP_WSCALE_REPLY
	CTAProtoInfoTCPFlagsOriginal  // CTA_PROTOINFO_TCP_FLAGS_ORIGINAL
	CTAProtoInfoTCPFlagsReply     // CTA_PROTOINFO_TCP_FLAGS_REPLY
)

// ProtoInfoDCCPType describes the kind of DCCP protocol info attribute in this container.
type ProtoInfoDCCPType uint8

// enum ctattr_protoinfo_dccp
const (
	CTAPProtoInfoDCCPUnspec ProtoInfoDCCPType = iota // CTA_PROTOINFO_DCCP_UNSPEC

	CTAPProtoInfoDCCPState        // CTA_PROTOINFO_DCCP_STATE
	CTAPProtoInfoDCCPRole         // CTA_PROTOINFO_DCCP_ROLE
	CTAPProtoInfoDCCPHandshakeSeq // CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ
	CTAPProtoInfoDCCPPad          // CTA_PROTOINFO_DCCP_PAD
)

// ProtoInfoSCTPType describes the kind of SCTP protocol info attribute in this container.
type ProtoInfoSCTPType uint8

// enum ctattr_protoinfo_sctp
const (
	CTAProtoInfoSCTPUnspec ProtoInfoSCTPType = iota // CTA_PROTOINFO_SCTP_UNSPEC

	CTAProtoInfoSCTPState        // CTA_PROTOINFO_SCTP_STATE
	CTAProtoInfoSCTPVTagOriginal // CTA_PROTOINFO_SCTP_VTAG_ORIGINAL
	CTAProtoInfoSCTPVtagReply    // CTA_PROTOINFO_SCTP_VTAG_REPLY
)

// SequenceAdjustType describes the type of sequence adjustment in this container.
type SequenceAdjustType uint8

// enum ctattr_seqadj
const (
	CTASeqAdjUnspec SequenceAdjustType = iota // CTA_SEQADJ_UNSPEC

	CTASeqAdjCorrectionPos // CTA_SEQADJ_CORRECTION_POS
	CTASeqAdjOffsetBefore  // CTA_SEQADJ_OFFSET_BEFORE
	CTASeqAdjOffsetAfter   // CTA_SEQADJ_OFFSET_AFTER
)

// SynProxyType describes the type of SYNproxy attribute in this container.
type SynProxyType uint8

// enum ctattr_synproxy
const (
	CTASynProxyUnspec SynProxyType = iota // CTA_SYNPROXY_UNSPEC

	CTASynProxyISN   // CTA_SYNPROXY_ISN
	CTASynProxyITS   // CTA_SYNPROXY_ITS
	CTASynProxyTSOff // CTA_SYNPROXY_TSOFF
)

// ExpectType describes the type of expect attribute in this container.
type ExpectType uint8

// enum ctattr_expect
const (
	CTAExpectUnspec ExpectType = iota // CTA_EXPECT_UNSPEC

	CTAExpectMaster   // CTA_EXPECT_MASTER
	CTAExpectTuple    // CTA_EXPECT_TUPLE
	CTAExpectMask     // CTA_EXPECT_MASK
	CTAExpectTimeout  // CTA_EXPECT_TIMEOUT
	CTAExpectID       // CTA_EXPECT_ID
	CTAExpectHelpName // CTA_EXPECT_HELP_NAME
	CTAExpectZone     // CTA_EXPECT_ZONE
	CTAExpectFlags    // CTA_EXPECT_FLAGS
	CTAExpectClass    // CTA_EXPECT_CLASS
	CTAExpectNAT      // CTA_EXPECT_NAT
	CTAExpectFN       // CTA_EXPECT_FN
)

// ExpectNATType describes the type of NAT expect attribute in this container.
type ExpectNATType uint8

// enum ctattr_expect_nat
const (
	CTAExpectNATUnspec ExpectNATType = iota // CTA_EXPECT_NAT_UNSPEC

	CTAExpectNATDir   // CTA_EXPECT_NAT_DIR
	CTAExpectNATTuple // CTA_EXPECT_NAT_TUPLE
)

// CPUStatsType describes the type of CPU-specific conntrack statistics attribute in this container.
type CPUStatsType uint8

// ctattr_stats_cpu
const (
	CTAStatsUnspec CPUStatsType = iota // CTA_STATS_UNSPEC

	CTAStatsSearched      // CTA_STATS_SEARCHED, no longer used
	CTAStatsFound         // CTA_STATS_FOUND
	CTAStatsNew           // CTA_STATS_NEW, no longer used
	CTAStatsInvalid       // CTA_STATS_INVALID
	CTAStatsIgnore        // CTA_STATS_IGNORE
	CTAStatsDelete        // CTA_STATS_DELETE, no longer used
	CTAStatsDeleteList    // CTA_STATS_DELETE_LIST, no longer used
	CTAStatsInsert        // CTA_STATS_INSERT
	CTAStatsInsertFailed  // CTA_STATS_INSERT_FAILED
	CTAStatsDrop          // CTA_STATS_DROP
	CTAStatsEarlyDrop     // CTA_STATS_EARLY_DROP
	CTAStatsError         // CTA_STATS_ERROR
	CTAStatsSearchRestart // CTA_STATS_SEARCH_RESTART
)

// GlobalStatsType describes the type of global conntrack statistics attribute in this container.
type GlobalStatsType uint8

// enum ctattr_stats_global
const (
	CTAStatsGlobalUnspec GlobalStatsType = iota // CTA_STATS_GLOBAL_UNSPEC

	CTAStatsGlobalEntries // CTA_STATS_GLOBAL_ENTRIES
)

// ExpectStatsType describes the type of expectation statistics attribute in this container.
type ExpectStatsType uint8

// enum ctattr_expect_stats
const (
	CTAStatsExpUnspec ExpectStatsType = iota // CTA_STATS_EXP_UNSPEC

	CTAStatsExpNew    // CTA_STATS_EXP_NEW
	CTAStatsExpCreate // CTA_STATS_EXP_CREATE
	CTAStatsExpDelete // CTA_STATS_EXP_DELETE
)

// enum ctattr_natseq is unused in the kernel source
