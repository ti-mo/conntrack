package conntrack

import "fmt"

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

	// Important status flag
	status := ""
	if !e.Flow.Status.SeenReply() {
		status = "(Unreplied)"
	}

	// Accounting information
	acct := "<No Accounting>"
	if e.Flow.CountersOrig.Filled() || e.Flow.CountersReply.Filled() {
		acct = fmt.Sprintf("Acct: %s %s", e.Flow.CountersOrig, e.Flow.CountersReply)
	}

	// Labels/mask
	labels := "<No Labels>"
	if e.Flow.Labels.Filled() && e.Flow.LabelsMask.Filled() {
		labels = fmt.Sprintf("Label: <%x/%x>", e.Flow.Labels.Data, e.Flow.LabelsMask.Data)
	}

	// Mark/mask
	mark := "<No Mark>"
	if e.Flow.Mark.Value != 0 && e.Flow.MarkMask.Value != 0 {
		mark = fmt.Sprintf("Mark: <%x/%x>", e.Flow.Mark.Value, e.Flow.MarkMask.Value)
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

	return fmt.Sprintf("[%s] %s %d Timeout: %d, Src: %v %v, Dest: %v %v, Zone %d, %s, %s, %s, %s, %s",
		e.Type, status,
		e.Flow.TupleOrig.Proto.Protocol, e.Flow.Timeout.Value,
		e.Flow.TupleOrig.IP.SourceAddress, e.Flow.TupleOrig.Proto.SourcePort,
		e.Flow.TupleOrig.IP.DestinationAddress, e.Flow.TupleOrig.Proto.DestinationPort,
		e.Flow.Zone.Value,
		acct, labels, mark, seqadj, secctx)
}
