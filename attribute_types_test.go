package conntrack

import (
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/ti-mo/netfilter"
)

var (
	nfaBadType  = netfilter.Attribute{Type: uint16(CTAUnspec)}
	nfaTooShort = netfilter.Attribute{}
)

func TestAttributeTypeString(t *testing.T) {
	if AttributeType(255).String() == "" {
		t.Fatal("AttributeType string representation empty - did you run `go generate`?")
	}
}

func TestAttributeNum16(t *testing.T) {

	n16 := Num16{}
	assert.Equal(t, false, n16.Filled())
	assert.Equal(t, true, Num16{Type: 1}.Filled())
	assert.Equal(t, true, Num16{Value: 1}.Filled())

	assert.EqualError(t, n16.UnmarshalAttribute(nfaTooShort), errIncorrectSize.Error())

	nfa := netfilter.Attribute{
		Type: uint16(CTAZone),
		Data: []byte{0, 1},
	}
	assert.Nil(t, n16.UnmarshalAttribute(nfa))
	assert.Equal(t, n16.String(), "1")

	// Marshal with zero type (auto-fill from struct)
	assert.EqualValues(t, netfilter.Attribute{Type: uint16(CTAZone), Data: []byte{0, 1}}, n16.MarshalAttribute(0))
	// Marshal with explicit type parameter
	assert.EqualValues(t, netfilter.Attribute{Type: uint16(CTAZone), Data: []byte{0, 1}}, n16.MarshalAttribute(CTAZone))
}

func TestAttributeNum32(t *testing.T) {

	n32 := Num32{}
	assert.Equal(t, false, n32.Filled())
	assert.Equal(t, true, Num32{Type: 1}.Filled())
	assert.Equal(t, true, Num32{Value: 1}.Filled())

	assert.EqualError(t, n32.UnmarshalAttribute(nfaTooShort), errIncorrectSize.Error())

	nfa := netfilter.Attribute{
		Type: uint16(CTAMark),
		Data: []byte{0, 1, 2, 3},
	}
	assert.Nil(t, n32.UnmarshalAttribute(nfa))
	assert.Equal(t, n32.String(), "66051")

	// Marshal with zero type (auto-fill from struct)
	assert.EqualValues(t, netfilter.Attribute{Type: uint16(CTAMark), Data: []byte{0, 1, 2, 3}}, n32.MarshalAttribute(0))
	// Marshal with explicit type parameter
	assert.EqualValues(t, netfilter.Attribute{Type: uint16(CTAMark), Data: []byte{0, 1, 2, 3}}, n32.MarshalAttribute(CTAMark))
}

func TestAttributeBitfield(t *testing.T) {
	bin := Binary{}
	assert.Equal(t, false, bin.Filled())
	assert.Equal(t, true, Binary{Type: 1}.Filled())
	assert.Equal(t, true, Binary{Data: []byte{1}}.Filled())

	assert.Nil(t, bin.UnmarshalAttribute(netfilter.Attribute{}))
}

func TestAttributeHelper(t *testing.T) {

	hlp := Helper{}
	assert.Equal(t, false, hlp.Filled())
	assert.Equal(t, true, Helper{Info: []byte{1}}.Filled())
	assert.Equal(t, true, Helper{Name: "1"}.Filled())

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAHelp)}

	assert.EqualError(t, hlp.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAHelp))
	assert.EqualError(t, hlp.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnHelper).Error())

	nfaNameInfo := netfilter.Attribute{
		Type:   uint16(CTAHelp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAHelpName),
				Data: []byte("foo"),
			},
			{
				Type: uint16(CTAHelpInfo),
				Data: []byte{1, 2},
			},
		},
	}
	assert.Nil(t, hlp.UnmarshalAttribute(nfaNameInfo))

	assert.EqualValues(t, hlp.MarshalAttribute(), nfaNameInfo)

	nfaUnknownChild := netfilter.Attribute{
		Type:   uint16(CTAHelp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAHelpUnspec),
			},
		},
	}
	assert.EqualError(t, hlp.UnmarshalAttribute(nfaUnknownChild), fmt.Sprintf(errAttributeChild, CTAHelpUnspec, CTAHelp))
}

func TestAttributeProtoInfo(t *testing.T) {

	pi := ProtoInfo{}
	assert.Equal(t, false, pi.Filled())
	assert.Equal(t, true, ProtoInfo{DCCP: &ProtoInfoDCCP{}}.Filled())
	assert.Equal(t, true, ProtoInfo{TCP: &ProtoInfoTCP{}}.Filled())
	assert.Equal(t, true, ProtoInfo{SCTP: &ProtoInfoSCTP{}}.Filled())

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfo)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfo), Nested: true}

	assert.EqualError(t, pi.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfo))
	assert.EqualError(t, pi.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnProtoInfo).Error())
	assert.EqualError(t, pi.UnmarshalAttribute(nfaNestedNoChildren), errors.Wrap(errNeedSingleChild, opUnProtoInfo).Error())

	// Attempt marshal of empty ProtoInfo, expect attribute with zero children
	assert.Len(t, pi.MarshalAttribute().Children, 0)

	// TCP protocol info
	nfaInfoTCP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(CTAProtoInfoTCP),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(CTAProtoInfoTCPState),
						Data: []byte{1},
					},
					{
						Type: uint16(CTAProtoInfoTCPWScaleOriginal),
						Data: []byte{2},
					},
					{
						Type: uint16(CTAProtoInfoTCPWScaleReply),
						Data: []byte{3},
					},
					{
						Type: uint16(CTAProtoInfoTCPFlagsOriginal),
						Data: []byte{0, 4},
					},
					{
						Type: uint16(CTAProtoInfoTCPFlagsReply),
						Data: []byte{0, 5},
					},
				},
			},
		},
	}

	// Full ProtoInfoTCP unmarshal
	var tpi ProtoInfo
	assert.Nil(t, tpi.UnmarshalAttribute(nfaInfoTCP))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoTCP, tpi.MarshalAttribute())

	// Error during ProtoInfoTCP unmarshal
	nfaInfoTCPError := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(CTAProtoInfoTCP),
				Nested: false,
			},
		},
	}

	assert.EqualError(t, pi.UnmarshalAttribute(nfaInfoTCPError), errors.Wrap(errNotNested, opUnProtoInfoTCP).Error())

	// DCCP protocol info
	nfaInfoDCCP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(CTAProtoInfoDCCP),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(CTAProtoInfoDCCPState),
						Data: []byte{1},
					},
					{
						Type: uint16(CTAProtoInfoDCCPRole),
						Data: []byte{2},
					},
					{
						Type: uint16(CTAProtoInfoDCCPHandshakeSeq),
						Data: []byte{3, 4, 5, 6, 7, 8, 9, 10},
					},
				},
			},
		},
	}

	// Error during ProtoInfoDCCP unmarshal
	nfaInfoDCCPError := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(CTAProtoInfoDCCP),
				Nested: false,
			},
		},
	}

	assert.EqualError(t, pi.UnmarshalAttribute(nfaInfoDCCPError), errors.Wrap(errNotNested, opUnProtoInfoDCCP).Error())

	// Full ProtoInfoDCCP unmarshal
	var dpi ProtoInfo
	assert.Nil(t, dpi.UnmarshalAttribute(nfaInfoDCCP))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoDCCP, dpi.MarshalAttribute())

	nfaInfoSCTP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(CTAProtoInfoSCTP),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(CTAProtoInfoSCTPState),
						Data: []byte{1},
					},
					{
						Type: uint16(CTAProtoInfoSCTPVTagOriginal),
						Data: []byte{2, 3, 4, 5},
					},
					{
						Type: uint16(CTAProtoInfoSCTPVtagReply),
						Data: []byte{6, 7, 8, 9},
					},
				},
			},
		},
	}

	// Full ProtoInfoSCTP unmarshal
	var spi ProtoInfo
	assert.Nil(t, spi.UnmarshalAttribute(nfaInfoSCTP))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoSCTP, spi.MarshalAttribute())

	// Error during ProtoInfoSCTP unmarshal
	nfaInfoSCTPError := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(CTAProtoInfoSCTP),
				Nested: false,
			},
		},
	}

	assert.EqualError(t, pi.UnmarshalAttribute(nfaInfoSCTPError), errors.Wrap(errNotNested, opUnProtoInfoSCTP).Error())

	// Unknown child attribute type
	nfaUnknownChild := netfilter.Attribute{
		Type:   uint16(CTAProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAProtoInfoUnspec),
			},
		},
	}

	assert.EqualError(t, pi.UnmarshalAttribute(nfaUnknownChild), fmt.Sprintf(errAttributeChild, CTAProtoInfoUnspec, CTAProtoInfo))

	// Attempt to unmarshal into re-used ProtoInfo
	pi.TCP = &ProtoInfoTCP{}
	assert.EqualError(t, pi.UnmarshalAttribute(nfaInfoTCP), errReusedProtoInfo.Error())
}

func TestProtoInfoTypeString(t *testing.T) {
	ssid := ProtoInfoType(255)

	ssidStr := ssid.String()

	if ssidStr == "" {
		t.Fatal("ProtoInfoType string representation empty - did you run `go generate`?")
	}
}

func TestAttributeProtoInfoTCP(t *testing.T) {

	pit := ProtoInfoTCP{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfoTCP)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfoTCP), Nested: true}

	assert.EqualError(t, pit.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfoTCP))
	assert.EqualError(t, pit.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnProtoInfoTCP).Error())
	assert.EqualError(t, pit.UnmarshalAttribute(nfaNestedNoChildren), errors.Wrap(errNeedChildren, opUnProtoInfoTCP).Error())

	nfaProtoInfoTCP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfoTCP),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAProtoInfoTCPState),
				Data: []byte{1},
			},
			{
				Type: uint16(CTAProtoInfoTCPFlagsOriginal),
				Data: []byte{0, 2},
			},
			{
				Type: uint16(CTAProtoInfoTCPFlagsReply),
				Data: []byte{0, 3},
			},
			{
				Type: uint16(CTAProtoInfoTCPWScaleOriginal),
				Data: []byte{0, 4},
			},
			{
				Type: uint16(CTAProtoInfoTCPWScaleReply),
				Data: []byte{0, 5},
			},
		},
	}

	nfaProtoInfoTCPError := netfilter.Attribute{
		Type:   uint16(CTAProtoInfoTCP),
		Nested: true,
		Children: []netfilter.Attribute{
			{Type: uint16(CTAProtoInfoTCPUnspec)},
			{Type: uint16(CTAProtoInfoTCPUnspec)},
			{Type: uint16(CTAProtoInfoTCPUnspec)},
		},
	}

	assert.Nil(t, pit.UnmarshalAttribute(nfaProtoInfoTCP))
	assert.EqualError(t, pit.UnmarshalAttribute(nfaProtoInfoTCPError), fmt.Sprintf(errAttributeChild, CTAProtoInfoTCPUnspec, CTAProtoInfoTCP))

}

func TestAttributeProtoInfoDCCP(t *testing.T) {

	pid := ProtoInfoDCCP{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfoDCCP)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfoDCCP), Nested: true}

	assert.EqualError(t, pid.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfoDCCP))
	assert.EqualError(t, pid.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnProtoInfoDCCP).Error())
	assert.EqualError(t, pid.UnmarshalAttribute(nfaNestedNoChildren), errors.Wrap(errNeedChildren, opUnProtoInfoDCCP).Error())

	nfaProtoInfoDCCP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfoDCCP),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAProtoInfoDCCPState),
				Data: []byte{1},
			},
			{
				Type: uint16(CTAProtoInfoDCCPRole),
				Data: []byte{2},
			},
			{
				Type: uint16(CTAProtoInfoDCCPHandshakeSeq),
				Data: []byte{3, 4, 5, 6, 7, 8, 9, 10},
			},
		},
	}

	nfaProtoInfoDCCPError := netfilter.Attribute{
		Type:   uint16(CTAProtoInfoDCCP),
		Nested: true,
		Children: []netfilter.Attribute{
			{Type: uint16(CTAProtoInfoDCCPUnspec)},
			{Type: uint16(CTAProtoInfoDCCPUnspec)},
			{Type: uint16(CTAProtoInfoDCCPUnspec)},
		},
	}

	assert.Nil(t, pid.UnmarshalAttribute(nfaProtoInfoDCCP))
	assert.EqualError(t, pid.UnmarshalAttribute(nfaProtoInfoDCCPError), fmt.Sprintf(errAttributeChild, CTAProtoInfoTCPUnspec, CTAProtoInfoDCCP))

}

func TestAttributeProtoInfoSCTP(t *testing.T) {

	pid := ProtoInfoSCTP{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfoSCTP)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfoSCTP), Nested: true}

	assert.EqualError(t, pid.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfoSCTP))
	assert.EqualError(t, pid.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnProtoInfoSCTP).Error())
	assert.EqualError(t, pid.UnmarshalAttribute(nfaNestedNoChildren), errors.Wrap(errNeedChildren, opUnProtoInfoSCTP).Error())

	nfaProtoInfoSCTP := netfilter.Attribute{
		Type:   uint16(CTAProtoInfoSCTP),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAProtoInfoSCTPState),
				Data: []byte{1},
			},
			{
				Type: uint16(CTAProtoInfoSCTPVTagOriginal),
				Data: []byte{2, 3, 4, 5},
			},
			{
				Type: uint16(CTAProtoInfoSCTPVtagReply),
				Data: []byte{6, 7, 8, 9},
			},
		},
	}

	nfaProtoInfoSCTPError := netfilter.Attribute{
		Type:   uint16(CTAProtoInfoSCTP),
		Nested: true,
		Children: []netfilter.Attribute{
			{Type: uint16(CTAProtoInfoSCTPUnspec)},
			{Type: uint16(CTAProtoInfoSCTPUnspec)},
			{Type: uint16(CTAProtoInfoSCTPUnspec)},
		},
	}

	assert.Nil(t, pid.UnmarshalAttribute(nfaProtoInfoSCTP))
	assert.EqualError(t, pid.UnmarshalAttribute(nfaProtoInfoSCTPError), fmt.Sprintf(errAttributeChild, CTAProtoInfoTCPUnspec, CTAProtoInfoSCTP))

}

func TestAttributeCounters(t *testing.T) {

	ctr := Counter{}

	assert.Equal(t, false, ctr.Filled())
	assert.Equal(t, true, Counter{Packets: 1, Bytes: 1}.Filled())

	// Counters can be unmarshaled from both CTACountersOrig and CTACountersReply
	attrTypes := []AttributeType{CTACountersOrig, CTACountersReply}

	for _, at := range attrTypes {
		t.Run(at.String(), func(t *testing.T) {
			nfaNotNested := netfilter.Attribute{Type: uint16(at)}
			nfaNestedNoChildren := netfilter.Attribute{Type: uint16(at), Nested: true}

			assert.EqualError(t, ctr.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, ctaCountersOrigReplyCat))
			assert.EqualError(t, ctr.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnCounter).Error())
			assert.EqualError(t, ctr.UnmarshalAttribute(nfaNestedNoChildren), fmt.Sprintf(errExactChildren, 2, ctaCountersOrigReplyCat))

			nfaCounter := netfilter.Attribute{
				Type:   uint16(at),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(CTACountersBytes),
						Data: make([]byte, 8),
					},
					{
						Type: uint16(CTACountersPackets),
						Data: make([]byte, 8),
					},
				},
			}

			nfaCounterError := netfilter.Attribute{
				Type:   uint16(at),
				Nested: true,
				Children: []netfilter.Attribute{
					{Type: uint16(CTACountersUnspec)},
					{Type: uint16(CTACountersUnspec)},
				},
			}

			assert.Nil(t, ctr.UnmarshalAttribute(nfaCounter))
			assert.EqualError(t, ctr.UnmarshalAttribute(nfaCounterError), fmt.Sprintf(errAttributeChild, CTACountersUnspec, ctaCountersOrigReplyCat))

			if at == CTACountersOrig {
				assert.Equal(t, "[orig: 0 pkts/0 B]", ctr.String())
			} else {
				assert.Equal(t, "[reply: 0 pkts/0 B]", ctr.String())
			}
		})
	}
}

func TestAttributeTimestamp(t *testing.T) {

	ts := Timestamp{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTATimestamp)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTATimestamp), Nested: true}

	assert.EqualError(t, ts.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTATimestamp))
	assert.EqualError(t, ts.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnTimestamp).Error())
	assert.EqualError(t, ts.UnmarshalAttribute(nfaNestedNoChildren), errors.Wrap(errNeedSingleChild, opUnTimestamp).Error())

	nfaTimestamp := netfilter.Attribute{
		Type:   uint16(CTATimestamp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTATimestampStart),
				Data: make([]byte, 8),
			},
			{
				Type: uint16(CTATimestampStop),
				Data: make([]byte, 8),
			},
		},
	}

	nfaTimestampError := netfilter.Attribute{
		Type:   uint16(CTATimestamp),
		Nested: true,
		Children: []netfilter.Attribute{
			{Type: uint16(CTATimestampUnspec)},
		},
	}

	assert.Nil(t, ts.UnmarshalAttribute(nfaTimestamp))
	assert.EqualError(t, ts.UnmarshalAttribute(nfaTimestampError), fmt.Sprintf(errAttributeChild, CTATimestampUnspec, CTATimestamp))

}

func TestAttributeSecCtx(t *testing.T) {

	var sc Security

	nfaNotNested := netfilter.Attribute{Type: uint16(CTASecCtx)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTASecCtx), Nested: true}

	assert.EqualError(t, sc.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTASecCtx))
	assert.EqualError(t, sc.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnSecurity).Error())
	assert.EqualError(t, sc.UnmarshalAttribute(nfaNestedNoChildren), errors.Wrap(errNeedChildren, opUnSecurity).Error())

	nfaSecurity := netfilter.Attribute{
		Type:   uint16(CTASecCtx),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTASecCtxName),
				Data: []byte("foo"),
			},
		},
	}

	nfaSecurityError := netfilter.Attribute{
		Type:   uint16(CTASecCtx),
		Nested: true,
		Children: []netfilter.Attribute{
			{Type: uint16(CTASecCtxUnspec)},
		},
	}

	assert.Nil(t, sc.UnmarshalAttribute(nfaSecurity))
	assert.EqualError(t, sc.UnmarshalAttribute(nfaSecurityError), fmt.Sprintf(errAttributeChild, CTASecCtxUnspec, CTASecCtx))

}

func TestAttributeSeqAdj(t *testing.T) {

	sa := SequenceAdjust{}

	assert.Equal(t, false, sa.Filled())
	assert.Equal(t, true, SequenceAdjust{Position: 1, OffsetBefore: 1, OffsetAfter: 1}.Filled())

	// SequenceAdjust can be unmarshaled from both CTASeqAdjOrig and CTASeqAdjReply
	attrTypes := []AttributeType{CTASeqAdjOrig, CTASeqAdjReply}

	for _, at := range attrTypes {
		t.Run(at.String(), func(t *testing.T) {
			nfaNotNested := netfilter.Attribute{Type: uint16(at)}
			nfaNestedNoChildren := netfilter.Attribute{Type: uint16(at), Nested: true}

			assert.EqualError(t, sa.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, ctaSeqAdjOrigReplyCat))
			assert.EqualError(t, sa.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnSeqAdj).Error())
			assert.EqualError(t, sa.UnmarshalAttribute(nfaNestedNoChildren), errors.Wrap(errNeedSingleChild, opUnSeqAdj).Error())

			nfaSeqAdj := netfilter.Attribute{
				Type:   uint16(at),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(CTASeqAdjCorrectionPos),
						Data: make([]byte, 4),
					},
					{
						Type: uint16(CTASeqAdjOffsetBefore),
						Data: make([]byte, 4),
					},
					{
						Type: uint16(CTASeqAdjOffsetAfter),
						Data: make([]byte, 4),
					},
				},
			}

			nfaSeqAdjError := netfilter.Attribute{
				Type:   uint16(at),
				Nested: true,
				Children: []netfilter.Attribute{
					{Type: uint16(CTASeqAdjUnspec)},
					{Type: uint16(CTASeqAdjUnspec)},
				},
			}

			assert.Nil(t, sa.UnmarshalAttribute(nfaSeqAdj))
			assert.EqualError(t, sa.UnmarshalAttribute(nfaSeqAdjError), fmt.Sprintf(errAttributeChild, CTASeqAdjUnspec, ctaSeqAdjOrigReplyCat))

			assert.EqualValues(t, nfaSeqAdj, sa.MarshalAttribute())

			if at == CTASeqAdjOrig {
				assert.Equal(t, "[dir: orig, pos: 0, before: 0, after: 0]", sa.String())
			} else {
				assert.Equal(t, "[dir: reply, pos: 0, before: 0, after: 0]", sa.String())
			}
		})
	}
}

func TestAttributeSynProxy(t *testing.T) {

	sp := SynProxy{}
	assert.Equal(t, false, sp.Filled())
	assert.Equal(t, true, SynProxy{ISN: 1}.Filled())
	assert.Equal(t, true, SynProxy{ITS: 1}.Filled())
	assert.Equal(t, true, SynProxy{TSOff: 1}.Filled())

	nfaNotNested := netfilter.Attribute{Type: uint16(CTASynProxy)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTASynProxy), Nested: true}

	assert.EqualError(t, sp.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTASynProxy))
	assert.EqualError(t, sp.UnmarshalAttribute(nfaNotNested), errors.Wrap(errNotNested, opUnSynProxy).Error())
	assert.EqualError(t, sp.UnmarshalAttribute(nfaNestedNoChildren), errors.Wrap(errNeedSingleChild, opUnSynProxy).Error())

	nfaSynProxy := netfilter.Attribute{
		Type:   uint16(CTASynProxy),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTASynProxyISN),
				Data: []byte{0, 1, 2, 3},
			},
			{
				Type: uint16(CTASynProxyITS),
				Data: []byte{4, 5, 6, 7},
			},
			{
				Type: uint16(CTASynProxyTSOff),
				Data: []byte{8, 9, 10, 11},
			},
		},
	}

	nfaSynProxyError := netfilter.Attribute{
		Type:   uint16(CTASynProxy),
		Nested: true,
		Children: []netfilter.Attribute{
			{Type: uint16(CTASynProxyUnspec)},
		},
	}

	assert.Nil(t, sp.UnmarshalAttribute(nfaSynProxy))
	assert.EqualError(t, sp.UnmarshalAttribute(nfaSynProxyError), fmt.Sprintf(errAttributeChild, CTASynProxyUnspec, CTASynProxy))

	assert.EqualValues(t, nfaSynProxy, sp.MarshalAttribute())
}
