package conntrack

import (
	"fmt"
	"strconv"
)

// ProtoLookup translates a protocol integer into its string representation.
func ProtoLookup(p uint8) string {
	protos := map[uint8]string{
		1:   "icmp",
		2:   "igmp",
		6:   "tcp",
		17:  "udp",
		47:  "gre",
		58:  "ipv6-icmp",
		94:  "ipip",
		115: "l2tp",
		132: "sctp",
		136: "udplite",
	}

	if val, ok := protos[p]; ok {
		return val
	}

	return strconv.FormatUint(uint64(p), 10)
}

func (s Status) String() string {
	names := []string{
		"EXPECTED",
		"SEEN_REPLY",
		"ASSURED",
		"CONFIRMED",
		"SRC_NAT",
		"DST_NAT",
		"SEQ_ADJUST",
		"SRC_NAT_DONE",
		"DST_NAT_DONE",
		"DYING",
		"FIXED_TIMEOUT",
		"TEMPLATE",
		"UNTRACKED",
		"HELPER",
		"OFFLOAD",
	}

	var rs string

	// Loop over the field's bits
	for i, name := range names {
		if s.value&(1<<uint32(i)) != 0 {
			if rs != "" {
				rs += "|"
			}
			rs += name
		}
	}

	if rs == "" {
		rs = "NONE"
	}

	return rs
}

func (e Event) String() string {

	if e.Flow != nil {

		// Status flag
		status := ""
		if !e.Flow.Status.SeenReply() {
			status = " (Unreplied)"
		}

		// Accounting information
		acct := "<No Accounting>"
		if e.Flow.CountersOrig.Filled() || e.Flow.CountersReply.Filled() {
			acct = fmt.Sprintf("Acct: %s %s", e.Flow.CountersOrig, e.Flow.CountersReply)
		}

		// Labels/mask
		labels := "<No Labels>"
		if e.Flow.Labels.Filled() && e.Flow.LabelsMask.Filled() {
			labels = fmt.Sprintf("Label: <%#x/%#x>", e.Flow.Labels.Data, e.Flow.LabelsMask.Data)
		}

		// Mark/mask
		mark := "<No Mark>"
		if e.Flow.Mark.Value != 0 && e.Flow.MarkMask.Value != 0 {
			mark = fmt.Sprintf("Mark: <%#x/%#x>", e.Flow.Mark.Value, e.Flow.MarkMask.Value)
		}

		// SeqAdj
		seqadj := "<No SeqAdj>"
		if e.Flow.SeqAdjOrig.Filled() || e.Flow.SeqAdjReply.Filled() {
			seqadj = fmt.Sprintf("SeqAdj: %s %s", e.Flow.SeqAdjOrig, e.Flow.SeqAdjReply)
		}

		// Security Context
		secctx := "<No SecCtx>"
		if e.Flow.SecurityContext.Name != "" {
			secctx = fmt.Sprintf("SecCtx: %s", e.Flow.SecurityContext.Name)
		}

		return fmt.Sprintf("[%s]%s Timeout: %d, %s, Zone %d, %s, %s, %s, %s, %s",
			e.Type, status,
			e.Flow.Timeout.Value,
			e.Flow.TupleOrig,
			e.Flow.Zone.Value,
			acct, labels, mark, seqadj, secctx)

	} else if e.Expect != nil {

		return fmt.Sprintf("[%s] Timeout: %d, Master: %s, Tuple: %s, Mask: %s, Zone: %d, Helper: %s, Class: %#x",
			e.Type, e.Expect.Timeout.Value,
			e.Expect.TupleMaster, e.Expect.Tuple, e.Expect.Mask,
			e.Expect.Zone, e.Expect.HelpName, e.Expect.Class,
		)

	} else {
		return fmt.Sprintf("[%s] <Empty Event>", e.Type)
	}

}
