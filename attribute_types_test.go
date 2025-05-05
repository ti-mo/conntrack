package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

var (
	adEmpty, _   = netfilter.NewAttributeDecoder([]byte{})
	adOneUnknown = *mustDecodeAttribute(netfilter.Attribute{Type: uint16(ctaUnspec)})
	adTwoUnknown = *mustDecodeAttributes(
		[]netfilter.Attribute{
			{Type: uint16(ctaUnspec)},
			{Type: uint16(ctaUnspec)},
		})
	adThreeUnknown = *mustDecodeAttributes(
		[]netfilter.Attribute{
			{Type: uint16(ctaUnspec)},
			{Type: uint16(ctaUnspec)},
			{Type: uint16(ctaUnspec)},
		})
)

// mustDecodeAttribute wraps attr in a list of netfilter.Attributes and calls
// mustDecodeAttributes.
func mustDecodeAttribute(attr netfilter.Attribute) *netlink.AttributeDecoder {
	return mustDecodeAttributes([]netfilter.Attribute{attr})
}

// mustDecodeAttributes marshals a list of netfilter.Attributes and returns
// an AttributeDecoder holding the binary output of the unmarshal.
func mustDecodeAttributes(attrs []netfilter.Attribute) *netlink.AttributeDecoder {
	ba, err := netfilter.MarshalAttributes(attrs)
	if err != nil {
		panic(err)
	}

	ad, err := netfilter.NewAttributeDecoder(ba)
	if err != nil {
		panic(err)
	}

	return ad
}

func TestAttributeTypeString(t *testing.T) {
	if attributeType(255).String() == "" {
		t.Fatal("AttributeType string representation empty - did you run `go generate`?")
	}
}

func TestAttributeHelper(t *testing.T) {
	hlp := Helper{}
	assert.Equal(t, false, hlp.filled())
	assert.Equal(t, true, Helper{Info: []byte{1}}.filled())
	assert.Equal(t, true, Helper{Name: "1"}.filled())

	nfaNameInfo := netfilter.Attribute{
		Type:   uint16(ctaHelp),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(ctaHelpName),
				Data: []byte("foo"),
			},
			{
				Type: uint16(ctaHelpInfo),
				Data: []byte{1, 2},
			},
		},
	}
	assert.Nil(t, hlp.unmarshal(mustDecodeAttributes(nfaNameInfo.Children)))

	assert.EqualValues(t, hlp.marshal(), nfaNameInfo)

	ad := adOneUnknown
	assert.ErrorIs(t, hlp.unmarshal(&ad), errUnknownAttribute)
}

func TestAttributeProtoInfo(t *testing.T) {
	var pi ProtoInfo
	assert.Equal(t, false, pi.filled())
	assert.Equal(t, true, ProtoInfo{DCCP: &ProtoInfoDCCP{}}.filled())
	assert.Equal(t, true, ProtoInfo{TCP: &ProtoInfoTCP{}}.filled())
	assert.Equal(t, true, ProtoInfo{SCTP: &ProtoInfoSCTP{}}.filled())

	assert.ErrorIs(t, pi.unmarshal(adEmpty), errNeedSingleChild)

	// Exhaust the AttributeDecoder before passing to unmarshal.
	ead := mustDecodeAttribute(nfaUnspecU16)
	ead.Next()
	assert.NoError(t, pi.unmarshal(ead))

	ad := adOneUnknown
	assert.ErrorIs(t, pi.unmarshal(&ad), errUnknownAttribute)

	// Attempt marshal of empty ProtoInfo, expect attribute with zero children.
	assert.Len(t, pi.marshal().Children, 0)

	// TCP protocol info
	nfaInfoTCP := netfilter.Attribute{
		Type:   uint16(ctaProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(ctaProtoInfoTCP),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(ctaProtoInfoTCPState),
						Data: []byte{1},
					},
					{
						Type: uint16(ctaProtoInfoTCPWScaleOriginal),
						Data: []byte{2},
					},
					{
						Type: uint16(ctaProtoInfoTCPWScaleReply),
						Data: []byte{3},
					},
					{
						Type: uint16(ctaProtoInfoTCPFlagsOriginal),
						Data: []byte{0, 4},
					},
					{
						Type: uint16(ctaProtoInfoTCPFlagsReply),
						Data: []byte{0, 5},
					},
				},
			},
		},
	}

	// Full ProtoInfoTCP unmarshal.
	var tpi ProtoInfo
	assert.NoError(t, tpi.unmarshal(mustDecodeAttributes(nfaInfoTCP.Children)))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoTCP, tpi.marshal())

	// DCCP protocol info
	nfaInfoDCCP := netfilter.Attribute{
		Type:   uint16(ctaProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(ctaProtoInfoDCCP),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(ctaProtoInfoDCCPState),
						Data: []byte{1},
					},
					{
						Type: uint16(ctaProtoInfoDCCPRole),
						Data: []byte{2},
					},
					{
						Type: uint16(ctaProtoInfoDCCPHandshakeSeq),
						Data: []byte{3, 4, 5, 6, 7, 8, 9, 10},
					},
				},
			},
		},
	}

	// Full ProtoInfoDCCP unmarshal
	var dpi ProtoInfo
	assert.Nil(t, dpi.unmarshal(mustDecodeAttributes(nfaInfoDCCP.Children)))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoDCCP, dpi.marshal())

	nfaInfoSCTP := netfilter.Attribute{
		Type:   uint16(ctaProtoInfo),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type:   uint16(ctaProtoInfoSCTP),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(ctaProtoInfoSCTPState),
						Data: []byte{1},
					},
					{
						Type: uint16(ctaProtoInfoSCTPVTagOriginal),
						Data: []byte{2, 3, 4, 5},
					},
					{
						Type: uint16(ctaProtoInfoSCTPVtagReply),
						Data: []byte{6, 7, 8, 9},
					},
				},
			},
		},
	}

	// Full ProtoInfoSCTP unmarshal
	var spi ProtoInfo
	assert.Nil(t, spi.unmarshal(mustDecodeAttributes(nfaInfoSCTP.Children)))

	// Re-marshal into netfilter Attribute
	assert.EqualValues(t, nfaInfoSCTP, spi.marshal())

	// Attempt to unmarshal into re-used ProtoInfo
	pi.TCP = &ProtoInfoTCP{}
	assert.ErrorIs(t, pi.unmarshal(mustDecodeAttribute(nfaInfoTCP)), errReusedProtoInfo)
}

func TestProtoInfoTypeString(t *testing.T) {
	ssid := protoInfoType(255)

	ssidStr := ssid.String()

	if ssidStr == "" {
		t.Fatal("ProtoInfoType string representation empty - did you run `go generate`?")
	}
}

func TestAttributeProtoInfoTCP(t *testing.T) {
	var pit ProtoInfoTCP
	assert.ErrorIs(t, pit.unmarshal(adEmpty), errNeedSingleChild)

	ad := adThreeUnknown
	assert.ErrorIs(t, pit.unmarshal(&ad), errUnknownAttribute)

	nfaProtoInfoTCP := []netfilter.Attribute{
		{
			Type: uint16(ctaProtoInfoTCPState),
			Data: []byte{1},
		},
		{
			Type: uint16(ctaProtoInfoTCPFlagsOriginal),
			Data: []byte{0, 2},
		},
		{
			Type: uint16(ctaProtoInfoTCPFlagsReply),
			Data: []byte{0, 3},
		},
		{
			Type: uint16(ctaProtoInfoTCPWScaleOriginal),
			Data: []byte{4},
		},
		{
			Type: uint16(ctaProtoInfoTCPWScaleReply),
			Data: []byte{5},
		},
	}
	assert.NoError(t, pit.unmarshal(mustDecodeAttributes(nfaProtoInfoTCP)))
}

func TestAttributeProtoInfoDCCP(t *testing.T) {
	var pid ProtoInfoDCCP
	assert.ErrorIs(t, pid.unmarshal(adEmpty), errNeedSingleChild)

	ad := adThreeUnknown
	assert.ErrorIs(t, pid.unmarshal(&ad), errUnknownAttribute)

	nfaProtoInfoDCCP := []netfilter.Attribute{
		{
			Type: uint16(ctaProtoInfoDCCPState),
			Data: []byte{1},
		},
		{
			Type: uint16(ctaProtoInfoDCCPRole),
			Data: []byte{2},
		},
		{
			Type: uint16(ctaProtoInfoDCCPHandshakeSeq),
			Data: []byte{3, 4, 5, 6, 7, 8, 9, 10},
		},
	}
	assert.NoError(t, pid.unmarshal(mustDecodeAttributes(nfaProtoInfoDCCP)))
}

func TestAttributeProtoInfoSCTP(t *testing.T) {
	var pid ProtoInfoSCTP
	assert.ErrorIs(t, pid.unmarshal(adEmpty), errNeedSingleChild)

	ad := adOneUnknown
	assert.ErrorIs(t, pid.unmarshal(&ad), errUnknownAttribute)

	nfaProtoInfoSCTP := []netfilter.Attribute{
		{
			Type: uint16(ctaProtoInfoSCTPState),
			Data: []byte{1},
		},
		{
			Type: uint16(ctaProtoInfoSCTPVTagOriginal),
			Data: []byte{2, 3, 4, 5},
		},
		{
			Type: uint16(ctaProtoInfoSCTPVtagReply),
			Data: []byte{6, 7, 8, 9},
		},
	}
	assert.NoError(t, pid.unmarshal(mustDecodeAttributes(nfaProtoInfoSCTP)))
}

func TestAttributeCounters(t *testing.T) {
	ctr := Counter{}
	assert.Equal(t, false, ctr.filled())
	assert.Equal(t, true, Counter{Packets: 1, Bytes: 1}.filled())

	// Counters can be unmarshaled from both ctaCountersOrig and ctaCountersReply
	attrTypes := []attributeType{ctaCountersOrig, ctaCountersReply}

	for _, at := range attrTypes {
		t.Run(at.String(), func(t *testing.T) {
			assert.ErrorIs(t, ctr.unmarshal(adEmpty), errNeedChildren)

			nfaCounter := []netfilter.Attribute{
				{
					Type: uint16(ctaCountersBytes),
					Data: make([]byte, 8),
				},
				{
					Type: uint16(ctaCountersPackets),
					Data: make([]byte, 8),
				},
				{
					Type: uint16(ctaCountersPad),
					Data: make([]byte, 8),
				},
			}
			assert.NoError(t, ctr.unmarshal(mustDecodeAttributes(nfaCounter)))

			ad := adTwoUnknown
			assert.ErrorIs(t, ctr.unmarshal(&ad), errUnknownAttribute)
		})
	}
}

func TestAttributeTimestamp(t *testing.T) {
	var ts Timestamp
	assert.ErrorIs(t, ts.unmarshal(adEmpty), errNeedSingleChild)

	ad := adOneUnknown
	assert.ErrorIs(t, ts.unmarshal(&ad), errUnknownAttribute)

	nfaTimestamp := []netfilter.Attribute{
		{
			Type: uint16(ctaTimestampStart),
			Data: make([]byte, 8),
		},
		{
			Type: uint16(ctaTimestampStop),
			Data: make([]byte, 8),
		},
	}
	assert.NoError(t, ts.unmarshal(mustDecodeAttributes(nfaTimestamp)))
}

func TestAttributeSecCtx(t *testing.T) {
	var sc Security
	assert.ErrorIs(t, sc.unmarshal(adEmpty), errNeedChildren)

	ad := adOneUnknown
	assert.ErrorIs(t, sc.unmarshal(&ad), errUnknownAttribute)

	nfaSecurity := []netfilter.Attribute{
		{
			Type: uint16(ctaSecCtxName),
			Data: []byte("foo"),
		},
	}
	assert.NoError(t, sc.unmarshal(mustDecodeAttributes(nfaSecurity)))
}

func TestAttributeSeqAdj(t *testing.T) {
	sa := SequenceAdjust{}
	assert.Equal(t, false, sa.filled())
	assert.Equal(t, true, SequenceAdjust{Position: 1, OffsetBefore: 1, OffsetAfter: 1}.filled())

	// SequenceAdjust can be unmarshaled from both ctaSeqAdjOrig and ctaSeqAdjReply
	attrTypes := []attributeType{ctaSeqAdjOrig, ctaSeqAdjReply}

	for _, at := range attrTypes {
		t.Run(at.String(), func(t *testing.T) {
			assert.ErrorIs(t, sa.unmarshal(adEmpty), errNeedSingleChild)

			ad := adOneUnknown
			assert.ErrorIs(t, sa.unmarshal(&ad), errUnknownAttribute)

			nfaSeqAdj := netfilter.Attribute{
				Type:   uint16(at),
				Nested: true,
				Children: []netfilter.Attribute{
					{
						Type: uint16(ctaSeqAdjCorrectionPos),
						Data: make([]byte, 4),
					},
					{
						Type: uint16(ctaSeqAdjOffsetBefore),
						Data: make([]byte, 4),
					},
					{
						Type: uint16(ctaSeqAdjOffsetAfter),
						Data: make([]byte, 4),
					},
				},
			}
			assert.NoError(t, sa.unmarshal(mustDecodeAttributes(nfaSeqAdj.Children)))

			// The AttributeDecoder unmarshal() no longer has the tuple direction, set it manually.
			// TODO: Remove when marshal() switches to AttributeEncoder.
			if at == ctaSeqAdjReply {
				sa.Direction = true
			} else {
				sa.Direction = false
			}

			assert.EqualValues(t, nfaSeqAdj, sa.marshal(false))
		})
	}
}

func TestAttributeSynProxy(t *testing.T) {
	sp := SynProxy{}
	assert.Equal(t, false, sp.filled())
	assert.Equal(t, true, SynProxy{ISN: 1}.filled())
	assert.Equal(t, true, SynProxy{ITS: 1}.filled())
	assert.Equal(t, true, SynProxy{TSOff: 1}.filled())

	assert.ErrorIs(t, sp.unmarshal(adEmpty), errNeedSingleChild)

	ad := adOneUnknown
	assert.ErrorIs(t, sp.unmarshal(&ad), errUnknownAttribute)

	nfaSynProxy := netfilter.Attribute{
		Type:   uint16(ctaSynProxy),
		Nested: true,
		Children: []netfilter.Attribute{
			{
				Type: uint16(ctaSynProxyISN),
				Data: []byte{0, 1, 2, 3},
			},
			{
				Type: uint16(ctaSynProxyITS),
				Data: []byte{4, 5, 6, 7},
			},
			{
				Type: uint16(ctaSynProxyTSOff),
				Data: []byte{8, 9, 10, 11},
			},
		},
	}
	assert.NoError(t, sp.unmarshal(mustDecodeAttributes(nfaSynProxy.Children)))

	assert.EqualValues(t, nfaSynProxy, sp.marshal())
}
