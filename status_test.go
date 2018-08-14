package conntrack

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ti-mo/netfilter"
)

func TestStatus_Error(t *testing.T) {

	nfaNested := netfilter.Attribute{Type: uint16(CTAStatus), Nested: true}

	var s Status

	assert.EqualError(t, s.UnmarshalAttribute(nfaBadType), fmt.Sprintf(errAttributeWrongType, CTAUnspec, CTAStatus))
	assert.EqualError(t, s.UnmarshalAttribute(nfaNested), errNested.Error())
}

func TestStatus_UnmarshalAttribute(t *testing.T) {

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
			status: Status{value: 0xFFFF8000},
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

		// Status attribute container
		var nfa netfilter.Attribute
		nfa.Type = uint16(CTAStatus)

		t.Run(tt.name, func(t *testing.T) {

			var s Status

			// Wrap binary contents in netfilter.Attribute
			nfa.Data = tt.b

			err := (&s).UnmarshalAttribute(nfa)

			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}

			if want, got := tt.status, s; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected status:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}

func TestStatus_FieldTest(t *testing.T) {

	var s Status

	s.value = IPSExpected
	assert.Equal(t, true, s.Expected(), "expected")

	s.value = IPSSeenReply
	assert.Equal(t, true, s.SeenReply(), "seenreply")

	s.value = IPSAssured
	assert.Equal(t, true, s.Assured(), "assured")

	s.value = IPSConfirmed
	assert.Equal(t, true, s.Confirmed(), "confirmed")

	s.value = IPSSrcNat
	assert.Equal(t, true, s.SrcNAT(), "srcnat")

	s.value = IPSDstNat
	assert.Equal(t, true, s.DstNAT(), "dstnat")

	s.value = IPSSeqAdjust
	assert.Equal(t, true, s.SeqAdjust(), "seqadjust")

	s.value = IPSSrcNatDone
	assert.Equal(t, true, s.SrcNATDone(), "srcnatdone")

	s.value = IPSDstNatDone
	assert.Equal(t, true, s.DstNATDone(), "dstnatdone")

	s.value = IPSDying
	assert.Equal(t, true, s.Dying(), "dying")

	s.value = IPSFixedTimeout
	assert.Equal(t, true, s.FixedTimeout(), "fixedtimeout")

	s.value = IPSTemplate
	assert.Equal(t, true, s.Template(), "template")

	s.value = IPSHelper
	assert.Equal(t, true, s.Helper(), "helper")

	s.value = IPSOffload
	assert.Equal(t, true, s.Offload(), "offload")
}

func TestStatus_String(t *testing.T) {
	full := Status{value: 0xffffffff}
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

func BenchmarkStatus_UnmarshalAttribute(b *testing.B) {
	inputs := [][]byte{
		{0x00, 0x00, 0x00, 0x01}, {0x00, 0x00, 0x00, 0x02}, {0x00, 0x00, 0x00, 0x03}, {0x00, 0x00, 0x00, 0x04},
		{0x00, 0x00, 0x00, 0x05}, {0x00, 0x00, 0x00, 0x06}, {0x00, 0x00, 0x00, 0x07}, {0x00, 0x00, 0x00, 0x08},
	}

	var ss Status
	var nfa netfilter.Attribute
	nfa.Type = uint16(CTAStatus)

	for n := 0; n < b.N; n++ {
		nfa.Data = inputs[n%len(inputs)]
		if err := (&ss).UnmarshalAttribute(nfa); err != nil {
			b.Fatal(err)
		}
	}
}
