package conntrack

import (
	"testing"
	"reflect"
)

func TestStatus_UnmarshalBinary(t *testing.T) {

	tests := []struct {
		name   string
		b      []byte
		status Status
		err    error
	}{
		{
			name: "default values",
			b: []byte{0x00, 0x00, 0x00, 0x00},
			status: Status{},
		},
		{
			name: "snake pattern",
			b: []byte{0xAA, 0xAA, 0xAA, 0xAA},
			status: Status{
				SeenReply: true,
				Confirmed: true,
				DstNat: true,
				SrcNatDone: true,
				Dying: true,
				Template: true,
			},
		},
		{
			name: "out of range, only highest bits flipped",
			b: []byte{0xFF, 0xFF, 0xE0, 0x00},
			status: Status{},
		},
		{
			name: "byte array too short",
			b: []byte{0xBE, 0xEF},
			status: Status{},
			err: errIncorrectSize,
		},
		{
			name: "byte array too long",
			b: []byte{0xDE, 0xAD, 0xC0, 0xDE, 0x00, 0x00},
			status: Status{},
			err: errIncorrectSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s Status

			err := (&s).UnmarshalBinary(tt.b)

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

func BenchmarkStatus_UnmarshalBinary(b *testing.B) {
	inputs := [][]byte{
		{0x00, 0x00, 0x00, 0x01}, {0x00, 0x00, 0x00, 0x02}, {0x00, 0x00, 0x00, 0x03}, {0x00, 0x00, 0x00, 0x04},
		{0x00, 0x00, 0x00, 0x05}, {0x00, 0x00, 0x00, 0x06}, {0x00, 0x00, 0x00, 0x07}, {0x00, 0x00, 0x00, 0x08},
	}

	var ss Status

	for n := 0; n < b.N; n++ {
		ss.UnmarshalBinary(inputs[n%len(inputs)])
	}
}
