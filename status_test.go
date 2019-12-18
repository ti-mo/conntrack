package conntrack

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/netlink/nltest"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/netfilter"
)

var nfaUnspecU16 = netfilter.Attribute{Type: uint16(ctaUnspec), Data: []byte{0, 0}}

func TestStatusError(t *testing.T) {

	var s Status

	assert.EqualError(t, s.unmarshal(adEmpty), errors.Wrap(errNeedSingleChild, opUnStatus).Error())
	assert.EqualError(t, s.unmarshal(mustDecodeAttribute(nfaUnspecU16)), errors.Wrap(errIncorrectSize, opUnStatus).Error())

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
			status: Status{},
		},
		{
			name:   "out of range, only highest bits flipped",
			b:      []byte{0xFF, 0xFF, 0x80, 0x00},
			status: Status{Value: 0xFFFF8000},
		},
		{
			name: "error, byte array too short",
			b:    []byte{0xBE, 0xEF},
			err:  errors.Wrap(errIncorrectSize, opUnStatus),
		},
		{
			name: "error, byte array too long",
			b:    []byte{0xDE, 0xAD, 0xC0, 0xDE, 0x00, 0x00},
			err:  errors.Wrap(errIncorrectSize, opUnStatus),
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
				require.Error(t, err)
				require.EqualError(t, tt.err, err.Error())
				return
			}

			if diff := cmp.Diff(tt.status.Value, s.Value); diff != "" {
				t.Fatalf("unexpected unmarshal (-want +got):\n%s", diff)
			}

			ms := s.marshal()
			require.NoError(t, err, "error during marshal:", s)
			if diff := cmp.Diff(nfa, ms); diff != "" {
				t.Fatalf("unexpected marshal (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStatusFieldTest(t *testing.T) {

	var s Status

	s.Value = StatusExpected
	assert.Equal(t, true, s.Expected(), "expected")

	s.Value = StatusSeenReply
	assert.Equal(t, true, s.SeenReply(), "seenreply")

	s.Value = StatusAssured
	assert.Equal(t, true, s.Assured(), "assured")

	s.Value = StatusConfirmed
	assert.Equal(t, true, s.Confirmed(), "confirmed")

	s.Value = StatusSrcNAT
	assert.Equal(t, true, s.SrcNAT(), "srcnat")

	s.Value = StatusDstNAT
	assert.Equal(t, true, s.DstNAT(), "dstnat")

	s.Value = StatusSeqAdjust
	assert.Equal(t, true, s.SeqAdjust(), "seqadjust")

	s.Value = StatusSrcNATDone
	assert.Equal(t, true, s.SrcNATDone(), "srcnatdone")

	s.Value = StatusDstNATDone
	assert.Equal(t, true, s.DstNATDone(), "dstnatdone")

	s.Value = StatusDying
	assert.Equal(t, true, s.Dying(), "dying")

	s.Value = StatusFixedTimeout
	assert.Equal(t, true, s.FixedTimeout(), "fixedtimeout")

	s.Value = StatusTemplate
	assert.Equal(t, true, s.Template(), "template")

	s.Value = StatusHelper
	assert.Equal(t, true, s.Helper(), "helper")

	s.Value = StatusOffload
	assert.Equal(t, true, s.Offload(), "offload")
}

func TestStatusString(t *testing.T) {
	full := Status{Value: 0xffffffff}
	empty := Status{}

	wantFull := "EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED|SRC_NAT|DST_NAT|SEQ_ADJUST|SRC_NAT_DONE|DST_NAT_DONE|DYING|FIXED_TIMEOUT|TEMPLATE|UNTRACKED|HELPER|OFFLOAD"
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
