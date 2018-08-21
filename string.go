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

	rt := fmt.Sprintf("[%s] ", e.Type)

	if !e.Flow.Status.SeenReply() {
		rt += "(Unreplied) "
	}

	rt += fmt.Sprintf("%d ", e.Flow.TupleOrig.Proto.Protocol)

	rt += fmt.Sprintf("Source: <%v:%v> Dest: <%v:%v>", e.Flow.TupleOrig.IP.SourceAddress, e.Flow.TupleOrig.Proto.SourcePort,
		e.Flow.TupleOrig.IP.DestinationAddress, e.Flow.TupleOrig.Proto.DestinationPort)

	return rt
}
