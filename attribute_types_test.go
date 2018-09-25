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
	assert.Equal(t, false, n16.filled())
	assert.Equal(t, true, Num16{Type: 1}.filled())
	assert.Equal(t, true, Num16{Value: 1}.filled())

	assert.EqualError(t, n16.unmarshal(nfaTooShort), errIncorrectSize.Error())

	nfa := netfilter.Attribute{
		Type: uint16(CTAZone),
		Data: []byte{0, 1},
	}
	assert.Nil(t, n16.unmarshal(nfa))
	assert.Equal(t, n16.String(), "1")

	// Marshal with zero type (auto-fill from struct)
	assert.EqualValues(t, netfilter.Attribute{Type: uint16(CTAZone), Data: []byte{0, 1}}, n16.marshal(0))
	// Marshal with explicit type parameter
	assert.EqualValues(t, netfilter.Attribute{Type: uint16(CTAZone), Data: []byte{0, 1}}, n16.marshal(CTAZone))
}

func TestAttributeNum32(t *testing.T) {

	n32 := Num32{}
	assert.Equal(t, false, n32.filled())
	assert.Equal(t, true, Num32{Type: 1}.filled())
	assert.Equal(t, true, Num32{Value: 1}.filled())

	assert.EqualError(t, n32.unmarshal(nfaTooShort), errIncorrectSize.Error())

	nfa := netfilter.Attribute{
		Type: uint16(CTAMark),
		Data: []byte{0, 1, 2, 3},
	}
	assert.Nil(t, n32.unmarshal(nfa))
	assert.Equal(t, n32.String(), "66051")

	// Marshal with zero type (auto-fill from struct)
	assert.EqualValues(t, netfilter.Attribute{Type: uint16(CTAMark), Data: []byte{0, 1, 2, 3}}, n32.marshal(0))
	// Marshal with explicit type parameter
	assert.EqualValues(t, netfilter.Attribute{Type: uint16(CTAMark), Data: []byte{0, 1, 2, 3}}, n32.marshal(CTAMark))
}

func TestAttributeBitfield(t *testing.T) {
	bin := Binary{}
	assert.Equal(t, false, bin.filled())
	assert.Equal(t, true, Binary{Type: 1}.filled())
	assert.Equal(t, true, Binary{Data: []byte{1}}.filled())

	assert.Nil(t, bin.unmarshal(netfilter.Attribute{}))
}

func TestAttributeHelper(t *testing.T) {

	hlp := Helper{}
	assert.Equal(t, false, hlp.filled())
	assert.Equal(t, true, Helper{Info: []byte{1}}.filled())
	assert.Equal(t, true, Helper{Name: "1"}.filled())

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAHelp)}

	assert.EqualError(t, hlp.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAHelp))
	assert.EqualError(t, hlp.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnHelper).Error())

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
	assert.Nil(t, hlp.unmarshal(nfaNameInfo))

	assert.EqualValues(t, hlp.marshal(), nfaNameInfo)

	nfaUnknownChild := netfilter.Attribute{
		Type:   uint16(CTAHelp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(CTAHelpUnspec),
			},
		},
	}
	assert.EqualError(t, hlp.unmarshal(nfaUnknownChild), fmt.Sprintf(errAttributeChild, CTAHelpUnspec, CTAHelp))
}

func TestAttributeProtoInfo(t *testing.T) {

	pi := ProtoInfo{}
	assert.Equal(t, false, pi.filled())
	assert.Equal(t, true, ProtoInfo{DCCP: &ProtoInfoDCCP{}}.filled())
	assert.Equal(t, true, ProtoInfo{TCP: &ProtoInfoTCP{}}.filled())
	assert.Equal(t, true, ProtoInfo{SCTP: &ProtoInfoSCTP{}}.filled())

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfo)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfo), Nested: true}

	assert.EqualError(t, pi.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfo))
	assert.EqualError(t, pi.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnProtoInfo).Error())
	assert.EqualError(t, pi.unmarshal(nfaNestedNoChildren), errors.Wrap(errNeedSingleChild, opUnProtoInfo).Error())

	// Attempt marshal of empty ProtoInfo, expect attribute with zero children
	assert.Len(t, pi.marshal().Children, 0)

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
	assert.Nil(t, tpi.unmarshal(nfaInfoTCP))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoTCP, tpi.marshal())

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

	assert.EqualError(t, pi.unmarshal(nfaInfoTCPError), errors.Wrap(errNotNested, opUnProtoInfoTCP).Error())

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

	assert.EqualError(t, pi.unmarshal(nfaInfoDCCPError), errors.Wrap(errNotNested, opUnProtoInfoDCCP).Error())

	// Full ProtoInfoDCCP unmarshal
	var dpi ProtoInfo
	assert.Nil(t, dpi.unmarshal(nfaInfoDCCP))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoDCCP, dpi.marshal())

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
	assert.Nil(t, spi.unmarshal(nfaInfoSCTP))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoSCTP, spi.marshal())

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

	assert.EqualError(t, pi.unmarshal(nfaInfoSCTPError), errors.Wrap(errNotNested, opUnProtoInfoSCTP).Error())

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

	assert.EqualError(t, pi.unmarshal(nfaUnknownChild), fmt.Sprintf(errAttributeChild, CTAProtoInfoUnspec, CTAProtoInfo))

	// Attempt to unmarshal into re-used ProtoInfo
	pi.TCP = &ProtoInfoTCP{}
	assert.EqualError(t, pi.unmarshal(nfaInfoTCP), errReusedProtoInfo.Error())
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

	assert.EqualError(t, pit.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfoTCP))
	assert.EqualError(t, pit.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnProtoInfoTCP).Error())
	assert.EqualError(t, pit.unmarshal(nfaNestedNoChildren), errors.Wrap(errNeedChildren, opUnProtoInfoTCP).Error())

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

	assert.Nil(t, pit.unmarshal(nfaProtoInfoTCP))
	assert.EqualError(t, pit.unmarshal(nfaProtoInfoTCPError), fmt.Sprintf(errAttributeChild, CTAProtoInfoTCPUnspec, CTAProtoInfoTCP))

}

func TestAttributeProtoInfoDCCP(t *testing.T) {

	pid := ProtoInfoDCCP{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfoDCCP)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfoDCCP), Nested: true}

	assert.EqualError(t, pid.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfoDCCP))
	assert.EqualError(t, pid.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnProtoInfoDCCP).Error())
	assert.EqualError(t, pid.unmarshal(nfaNestedNoChildren), errors.Wrap(errNeedChildren, opUnProtoInfoDCCP).Error())

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

	assert.Nil(t, pid.unmarshal(nfaProtoInfoDCCP))
	assert.EqualError(t, pid.unmarshal(nfaProtoInfoDCCPError), fmt.Sprintf(errAttributeChild, CTAProtoInfoTCPUnspec, CTAProtoInfoDCCP))

}

func TestAttributeProtoInfoSCTP(t *testing.T) {

	pid := ProtoInfoSCTP{}

	nfaNotNested := netfilter.Attribute{Type: uint16(CTAProtoInfoSCTP)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTAProtoInfoSCTP), Nested: true}

	assert.EqualError(t, pid.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAProtoInfoSCTP))
	assert.EqualError(t, pid.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnProtoInfoSCTP).Error())
	assert.EqualError(t, pid.unmarshal(nfaNestedNoChildren), errors.Wrap(errNeedChildren, opUnProtoInfoSCTP).Error())

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

	assert.Nil(t, pid.unmarshal(nfaProtoInfoSCTP))
	assert.EqualError(t, pid.unmarshal(nfaProtoInfoSCTPError), fmt.Sprintf(errAttributeChild, CTAProtoInfoTCPUnspec, CTAProtoInfoSCTP))

}

func TestAttributeCounters(t *testing.T) {

	ctr := Counter{}

	assert.Equal(t, false, ctr.filled())
	assert.Equal(t, true, Counter{Packets: 1, Bytes: 1}.filled())

	// Counters can be unmarshaled from both CTACountersOrig and CTACountersReply
	attrTypes := []AttributeType{CTACountersOrig, CTACountersReply}

	for _, at := range attrTypes {
		t.Run(at.String(), func(t *testing.T) {
			nfaNotNested := netfilter.Attribute{Type: uint16(at)}
			nfaNestedNoChildren := netfilter.Attribute{Type: uint16(at), Nested: true}

			assert.EqualError(t, ctr.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, ctaCountersOrigReplyCat))
			assert.EqualError(t, ctr.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnCounter).Error())
			assert.EqualError(t, ctr.unmarshal(nfaNestedNoChildren), fmt.Sprintf(errExactChildren, 2, ctaCountersOrigReplyCat))

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

			assert.Nil(t, ctr.unmarshal(nfaCounter))
			assert.EqualError(t, ctr.unmarshal(nfaCounterError), fmt.Sprintf(errAttributeChild, CTACountersUnspec, ctaCountersOrigReplyCat))

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

	assert.EqualError(t, ts.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTATimestamp))
	assert.EqualError(t, ts.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnTimestamp).Error())
	assert.EqualError(t, ts.unmarshal(nfaNestedNoChildren), errors.Wrap(errNeedSingleChild, opUnTimestamp).Error())

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

	assert.Nil(t, ts.unmarshal(nfaTimestamp))
	assert.EqualError(t, ts.unmarshal(nfaTimestampError), fmt.Sprintf(errAttributeChild, CTATimestampUnspec, CTATimestamp))

}

func TestAttributeSecCtx(t *testing.T) {

	var sc Security

	nfaNotNested := netfilter.Attribute{Type: uint16(CTASecCtx)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTASecCtx), Nested: true}

	assert.EqualError(t, sc.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTASecCtx))
	assert.EqualError(t, sc.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnSecurity).Error())
	assert.EqualError(t, sc.unmarshal(nfaNestedNoChildren), errors.Wrap(errNeedChildren, opUnSecurity).Error())

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

	assert.Nil(t, sc.unmarshal(nfaSecurity))
	assert.EqualError(t, sc.unmarshal(nfaSecurityError), fmt.Sprintf(errAttributeChild, CTASecCtxUnspec, CTASecCtx))

}

func TestAttributeSeqAdj(t *testing.T) {

	sa := SequenceAdjust{}

	assert.Equal(t, false, sa.filled())
	assert.Equal(t, true, SequenceAdjust{Position: 1, OffsetBefore: 1, OffsetAfter: 1}.filled())

	// SequenceAdjust can be unmarshaled from both CTASeqAdjOrig and CTASeqAdjReply
	attrTypes := []AttributeType{CTASeqAdjOrig, CTASeqAdjReply}

	for _, at := range attrTypes {
		t.Run(at.String(), func(t *testing.T) {
			nfaNotNested := netfilter.Attribute{Type: uint16(at)}
			nfaNestedNoChildren := netfilter.Attribute{Type: uint16(at), Nested: true}

			assert.EqualError(t, sa.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, ctaSeqAdjOrigReplyCat))
			assert.EqualError(t, sa.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnSeqAdj).Error())
			assert.EqualError(t, sa.unmarshal(nfaNestedNoChildren), errors.Wrap(errNeedSingleChild, opUnSeqAdj).Error())

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

			assert.Nil(t, sa.unmarshal(nfaSeqAdj))
			assert.EqualError(t, sa.unmarshal(nfaSeqAdjError), fmt.Sprintf(errAttributeChild, CTASeqAdjUnspec, ctaSeqAdjOrigReplyCat))

			assert.EqualValues(t, nfaSeqAdj, sa.marshal())

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
	assert.Equal(t, false, sp.filled())
	assert.Equal(t, true, SynProxy{ISN: 1}.filled())
	assert.Equal(t, true, SynProxy{ITS: 1}.filled())
	assert.Equal(t, true, SynProxy{TSOff: 1}.filled())

	nfaNotNested := netfilter.Attribute{Type: uint16(CTASynProxy)}
	nfaNestedNoChildren := netfilter.Attribute{Type: uint16(CTASynProxy), Nested: true}

	assert.EqualError(t, sp.unmarshal(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTASynProxy))
	assert.EqualError(t, sp.unmarshal(nfaNotNested), errors.Wrap(errNotNested, opUnSynProxy).Error())
	assert.EqualError(t, sp.unmarshal(nfaNestedNoChildren), errors.Wrap(errNeedSingleChild, opUnSynProxy).Error())

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

	assert.Nil(t, sp.unmarshal(nfaSynProxy))
	assert.EqualError(t, sp.unmarshal(nfaSynProxyError), fmt.Sprintf(errAttributeChild, CTASynProxyUnspec, CTASynProxy))

	assert.EqualValues(t, nfaSynProxy, sp.marshal())
}
