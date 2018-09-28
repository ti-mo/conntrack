package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"

	"github.com/ti-mo/netfilter"
)

// Statistics
type Statistics struct {
	CPUID         uint16
	Searched      uint32 // Not used
	Found         uint32
	New           uint32 // Not used
	Invalid       uint32
	Ignore        uint32
	Delete        uint32 // Not used
	DeleteList    uint32 // Not used
	Insert        uint32
	InsertFailed  uint32
	Drop          uint32
	EarlyDrop     uint32
	Error         uint32
	SearchRestart uint32
}

func unmarshalStatistics(nlm []netlink.Message) ([]Statistics, error) {
	stats := make([]Statistics, len(nlm))
	for idx, m := range nlm {
		s, err := unmarshalStatistic(m)
		if err != nil {
			return nil, err
		}
		stats[idx] = s
	}

	return stats, nil
}

func unmarshalStatistic(nlm netlink.Message) (Statistics, error) {
	var s Statistics

	hdr, nfa, err := netfilter.UnmarshalNetlink(nlm)
	if err != nil {
		return s, err
	}
	s.CPUID = hdr.ResourceID

	err = s.unmarshal(nfa)
	if err != nil {
		return s, err
	}

	return s, nil
}

func (s *Statistics) unmarshal(attrs []netfilter.Attribute) error {
	for _, attr := range attrs {
		switch at := cpuStatsType(attr.Type); at {
		case ctaStatsUnspec:
			return fmt.Errorf("Unexpected unspecified statistic")
		case ctaStatsSearched:
			// TODO: Error instead? Should never be used
			s.Searched = attr.Uint32()
		case ctaStatsFound:
			s.Found = attr.Uint32()
		case ctaStatsNew:
			// TODO: Error instead? Should never be used
			s.New = attr.Uint32()
		case ctaStatsInvalid:
			s.Invalid = attr.Uint32()
		case ctaStatsIgnore:
			s.Ignore = attr.Uint32()
		case ctaStatsDelete:
			// TODO: Error instead? Should never be used
			s.Delete = attr.Uint32()
		case ctaStatsDeleteList:
			// TODO: Error instead? Should never be used
			s.DeleteList = attr.Uint32()
		case ctaStatsInsert:
			s.Insert = attr.Uint32()
		case ctaStatsInsertFailed:
			s.InsertFailed = attr.Uint32()
		case ctaStatsDrop:
			s.Drop = attr.Uint32()
		case ctaStatsEarlyDrop:
			s.EarlyDrop = attr.Uint32()
		case ctaStatsError:
			s.Error = attr.Uint32()
		case ctaStatsSearchRestart:
			s.SearchRestart = attr.Uint32()
		default:
			return fmt.Errorf(errAttributeUnknown, at)
		}
	}

	return nil
}
