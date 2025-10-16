package conntrack

import (
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/netlink/nltest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/netfilter"
)

var nfaUnspecU16 = netfilter.Attribute{Type: uint16(ctaUnspec), Data: []byte{0, 0}}

func TestStatusError(t *testing.T) {
	var s Status
	assert.ErrorIs(t, s.unmarshal(adEmpty), errNeedSingleChild)
	assert.ErrorIs(t, s.unmarshal(mustDecodeAttribute(nfaUnspecU16)), errIncorrectSize)

	// Exhaust the AttributeDecoder before passing to unmarshal.
	ad := mustDecodeAttribute(nfaUnspecU16)
	ad.Next()
	assert.NoError(t, s.unmarshal(ad))
}

func TestStatusMarshalTwoWay(t *testing.T) {
	tests := []struct {
		name   string
		b      []byte
		status Status
		err    error
	}{
		{
			name:   "default values",
			b:      []byte{0x00, 0x00, 0x00, 0x00},
			status: 0,
		},
		{
			name:   "assured",
			b:      []byte{0x00, 0x00, 0x00, 0xc},
			status: StatusAssured | StatusConfirmed,
		},
		{
			name:   "out of range, only highest bits flipped",
			b:      []byte{0xFF, 0xFF, 0x80, 0x00},
			status: 0xFFFF8000,
		},
		{
			name: "error, byte array too short",
			b:    []byte{0xBE, 0xEF},
			err:  errIncorrectSize,
		},
		{
			name: "error, byte array too long",
			b:    []byte{0xDE, 0xAD, 0xC0, 0xDE, 0x00, 0x00},
			err:  errIncorrectSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wrap in status attribute container
			nfa := netfilter.Attribute{
				Type: uint16(ctaStatus),
				Data: tt.b,
			}

			var s Status
			err := s.unmarshal(mustDecodeAttribute(nfa))
			if err != nil || tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.Equal(t, tt.status, s, "unexpected unmarshal")

			ms := s.marshal()
			assert.Equal(t, nfa, ms, "unexpected marshal")
		})
	}
}

func TestStatusFieldTest(t *testing.T) {
	assert.Equal(t, true, StatusExpected.Expected(), "expected")
	assert.Equal(t, true, StatusSeenReply.SeenReply(), "seenreply")
	assert.Equal(t, true, StatusAssured.Assured(), "assured")
	assert.Equal(t, true, StatusConfirmed.Confirmed(), "confirmed")
	assert.Equal(t, true, StatusSrcNAT.SrcNAT(), "srcnat")
	assert.Equal(t, true, StatusDstNAT.DstNAT(), "dstnat")
	assert.Equal(t, true, StatusSeqAdjust.SeqAdjust(), "seqadjust")
	assert.Equal(t, true, StatusSrcNATDone.SrcNATDone(), "srcnatdone")
	assert.Equal(t, true, StatusDstNATDone.DstNATDone(), "dstnatdone")
	assert.Equal(t, true, StatusDying.Dying(), "dying")
	assert.Equal(t, true, StatusFixedTimeout.FixedTimeout(), "fixedtimeout")
	assert.Equal(t, true, StatusTemplate.Template(), "template")
	assert.Equal(t, true, StatusHelper.Helper(), "helper")
	assert.Equal(t, true, StatusOffload.Offload(), "offload")
}

func TestStatusString(t *testing.T) {
	full, empty := Status(0xffffffff), Status(0)

	wantFull := "EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED|SRC_NAT|DST_NAT|SEQ_ADJUST|SRC_NAT_DONE|DST_NAT_DONE|" +
		"DYING|FIXED_TIMEOUT|TEMPLATE|UNTRACKED|HELPER|OFFLOAD"
	if want, got := wantFull, full.String(); want != got {
		t.Errorf("unexpected string:\n- want: %s\n-  got: %s", wantFull, got)
	}

	wantEmpty := "NONE"
	if want, got := wantEmpty, empty.String(); wantEmpty != got {
		t.Errorf("unexpected string:\n- want: %s\n-  got: %s", want, got)
	}

}

func BenchmarkStatusUnmarshalAttribute(b *testing.B) {

	var ads []netlink.AttributeDecoder
	for i := 1; i <= 8; i++ {
		nla := netlink.Attribute{Data: nlenc.Uint32Bytes(uint32(i))}
		ad, err := netfilter.NewAttributeDecoder(nltest.MustMarshalAttributes([]netlink.Attribute{nla}))
		if err != nil {
			b.Error(err)
		}
		ads = append(ads, *ad)
	}

	var ss Status
	var ad netlink.AttributeDecoder
	adl := len(ads)

	for n := 0; n < b.N; n++ {
		// Make a fresh copy of the AttributeDecoder.
		ad = ads[n%adl]
		if err := ss.unmarshal(&ad); err != nil {
			b.Fatal(err)
		}
	}
}
