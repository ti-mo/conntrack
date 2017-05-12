package conntrack

import (
	"errors"
	"fmt"
	"github.com/ti-mo/netfilter"
	"net"
)

// A Tuple holds an IPTuple, ProtoTuple and a Zone.
// IP and Proto are pointers and possibly 'nil' as a result.
type Tuple struct {
	IP    IPTuple
	Proto ProtoTuple
	Zone  uint16
}

func (t *Tuple) UnmarshalAttribute(attr netfilter.Attribute) error {

	if !attr.Nested {
		return errNotNested
	}

	// A Tuple will always consist of more than one child attribute
	if len(attr.Children) < 2 {
		return errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch TupleType(iattr.Type) {
		case CTA_TUPLE_IP:
			var ti IPTuple
			if err := (&ti).UnmarshalAttribute(iattr); err != nil {
				return err
			}
			t.IP = ti
		case CTA_TUPLE_PROTO:
			var tp ProtoTuple
			if err := (&tp).UnmarshalAttribute(iattr); err != nil {
				return err
			}
			t.Proto = tp
		case CTA_TUPLE_ZONE:
			if len(iattr.Data) != 2 {
				return errIncorrectSize
			}
			t.Zone = iattr.Uint16()
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown TupleType %v", iattr.Type)
		}
	}

	return nil
}

// An IPTuple encodes a source and destination address.
// Both of its members are of type net.IP.
type IPTuple struct {
	SourceAddress      net.IP
	DestinationAddress net.IP
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into an IPTuple.
// IPv4 addresses will be represented by a 4-byte net.IP, IPv6 addresses by 16-byte.
// The net.IP object is created with the raw bytes, NOT with net.ParseIP().
// Use IP.Equal() to compare addresses in implementations and tests.
func (ipt *IPTuple) UnmarshalAttribute(attr netfilter.Attribute) error {

	if TupleType(attr.Type) != CTA_TUPLE_IP {
		return fmt.Errorf("error: UnmarshalAttribute - %v is not a CTA_TUPLE_IP", attr.Type)
	}

	if !attr.Nested {
		return errNotNested
	}

	if len(attr.Children) != 2 {
		return errors.New("error: UnmarshalAttribute - IPTuple expects exactly two children")
	}

	for _, iattr := range attr.Children {

		if len(iattr.Data) != 4 && len(iattr.Data) != 16 {
			return errIncorrectSize
		}

		switch IPTupleType(iattr.Type) {
		case CTA_IP_V4_SRC, CTA_IP_V6_SRC:
			ipt.SourceAddress = net.IP(iattr.Data)
		case CTA_IP_V4_DST, CTA_IP_V6_DST:
			ipt.DestinationAddress = net.IP(iattr.Data)
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown IPTupleType %v", iattr.Type)
		}
	}

	return nil
}

// A ProtoTuple encodes a protocol number, source port and destination port.
type ProtoTuple struct {
	Protocol        uint8
	SourcePort      uint16
	DestinationPort uint16
}

// UnmarshalAttribute unmarshals a netfilter.Attribute into a ProtoTuple.
func (pt *ProtoTuple) UnmarshalAttribute(attr netfilter.Attribute) error {

	if TupleType(attr.Type) != CTA_TUPLE_PROTO {
		return fmt.Errorf("error: UnmarshalAttribute - %v is not a CTA_TUPLE_PROTO", attr.Type)
	}

	if !attr.Nested {
		return errNotNested
	}

	for _, iattr := range attr.Children {
		switch ProtoTupleType(iattr.Type) {
		case CTA_PROTO_NUM:
			pt.Protocol = iattr.Data[0]
		case CTA_PROTO_SRC_PORT:
			pt.SourcePort = iattr.Uint16()
		case CTA_PROTO_DST_PORT:
			pt.DestinationPort = iattr.Uint16()
		default:
			return fmt.Errorf("error: UnmarshalAttribute - unknown ProtoTupleType %v", iattr.Type)
		}
	}

	return nil
}
