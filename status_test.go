package conntrack

import (
	"github.com/ti-mo/netfilter"
	"reflect"
	"testing"
)

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
			name: "snake pattern",
			b:    []byte{0xAA, 0xAA, 0xAA, 0xAA},
			status: Status{
				SeenReply:  true,
				Confirmed:  true,
				DstNat:     true,
				SrcNatDone: true,
				Dying:      true,
				Template:   true,
				value:      0xAAAAAAAA,
			},
		},
		{
			name:   "out of range, only highest bits flipped",
			b:      []byte{0xFF, 0xFF, 0x80, 0x00},
			status: Status{value: 0xFFFF8000},
		},
		{
			name: "byte array too short",
			b:    []byte{0xBE, 0xEF},
			err:  errIncorrectSize,
		},
		{
			name: "byte array too long",
			b:    []byte{0xDE, 0xAD, 0xC0, 0xDE, 0x00, 0x00},
			err:  errIncorrectSize,
		},
	}

	for _, tt := range tests {

		// Status attribute container
		var nfa netfilter.Attribute
		nfa.Type = uint16(CTA_STATUS)

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

func BenchmarkStatus_UnmarshalAttribute(b *testing.B) {
	inputs := [][]byte{
		{0x00, 0x00, 0x00, 0x01}, {0x00, 0x00, 0x00, 0x02}, {0x00, 0x00, 0x00, 0x03}, {0x00, 0x00, 0x00, 0x04},
		{0x00, 0x00, 0x00, 0x05}, {0x00, 0x00, 0x00, 0x06}, {0x00, 0x00, 0x00, 0x07}, {0x00, 0x00, 0x00, 0x08},
	}

	var ss Status
	var nfa netfilter.Attribute
	nfa.Type = uint16(CTA_STATUS)

	for n := 0; n < b.N; n++ {
		nfa.Data = inputs[n%len(inputs)]
		if err := (&ss).UnmarshalAttribute(nfa); err != nil {
			b.Fatal(err)
		}
	}
}
