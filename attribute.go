package conntrack

import (
	"github.com/gonetlink/netfilter"
	"encoding/binary"
	"log"
	"fmt"
	"errors"
	"net"
)

var (
	errNotImplemented = errors.New("sorry, not implemented yet")
	errNested = errors.New("unexpected Nested attribute")
	errNotNested = errors.New("need a Nested attribute to decode this structure")
	errNeedChildren = errors.New("need at least 2 child attributes to decode a Tuple")
	errNotStatus = errors.New("attribute is not of type CTA_STATUS")
	errIncorrectSize = errors.New("binary attribute data has incorrect size")
)

type Attribute interface {}

type Tuple interface {}

type ProtoTuple struct {
	Protocol uint8
	SourcePort uint16
	DestinationPort uint16
}

type IPTuple struct {
	SourceAddress net.IP
	DestinationAddress net.IP
}

func UnmarshalIPTuple(attr netfilter.Attribute) (IPTuple, error) {

	if TupleType(attr.Type) != CTA_TUPLE_IP {
		return IPTuple{},
			errors.New(fmt.Sprintf("%v is not a CTA_TUPLE_IP", attr.Type))
	}

	var it IPTuple

	for _, iattr := range attr.Children {
		switch IPType(iattr.Type) {
		case CTA_IP_V4_SRC, CTA_IP_V6_SRC:
			it.SourceAddress = net.IP(iattr.Data)
		case CTA_IP_V4_DST, CTA_IP_V6_DST:
			it.DestinationAddress = net.IP(iattr.Data)
		default:
			return IPTuple{},
				errors.New(fmt.Sprintf("unknown IPType %v", iattr.Type))

		}
	}

	return it, nil
}

func UnmarshalProtoTuple(attr netfilter.Attribute) (ProtoTuple, error) {

	if TupleType(attr.Type) != CTA_TUPLE_PROTO {
		return ProtoTuple{},
			errors.New(fmt.Sprintf("%v is not a CTA_TUPLE_PROTO", attr.Type))
	}

	var pt ProtoTuple

	for _, iattr := range attr.Children {
		switch ProtoType(iattr.Type) {
		case CTA_PROTO_NUM:
			pt.Protocol = iattr.Data[0]
		case CTA_PROTO_SRC_PORT:
			// Ports are always big-endian, even though
			// the NetByteOrder flag might not be set.
			pt.SourcePort = binary.BigEndian.Uint16(iattr.Data[:2])
		case CTA_PROTO_DST_PORT:
			pt.DestinationPort = binary.BigEndian.Uint16(iattr.Data[:2])
		default:
			return ProtoTuple{},
				errors.New(fmt.Sprintf("unknown ProtoType %v", iattr.Type))
		}
	}

	return pt, nil
}

func UnmarshalTuples(attr netfilter.Attribute) ([]Tuple, error) {

	var at []Tuple

	// The Nested flag always needs to be set on a Tuple Attribute
	if !attr.Nested {
		return nil, errNotNested
	}

	// A Tuple will always consist of more than one child attribute
	if len(attr.Children) > 2 {
		return nil, errNeedChildren
	}

	for _, iattr := range attr.Children {
		switch TupleType(iattr.Type) {
		case CTA_TUPLE_IP:
			t, err := UnmarshalIPTuple(iattr)
			if err != nil {
				return nil, err
			}

			at = append(at, t)
		case CTA_TUPLE_PROTO:
			t, err := UnmarshalProtoTuple(iattr)
			if err != nil {
				return nil, err
			}

			at = append(at, t)
		case CTA_TUPLE_ZONE:
			log.Println("TupleType CTA_TUPLE_ZONE")
		case CTA_TUPLE_UNSPEC:
			log.Println("TupleType CTA_TUPLE_UNSPEC")
		default:
			log.Println("Decoding unknown TupleType", attr.Type)
		}
	}

	return at, nil
}

func UnmarshalStatus(attr netfilter.Attribute) (Status, error) {

	if AttributeType(attr.Type) != CTA_STATUS {
		return Status{}, errNotStatus
	}

	if attr.Nested {
		return Status{}, errNested
	}

	var s Status
	s.UnmarshalBinary(attr.Data)

	return s, nil
}

// DecodeRootAttributes decodes a list of root-level attributes using the list
// of AttributeTypes. All attribute types we know how to decode are listed here.
func DecodeRootAttributes(attrs []netfilter.Attribute) ([]Attribute, error) {

	var ra []Attribute

	for _, attr := range attrs {
		switch AttributeType(attr.Type) {
		case CTA_TUPLE_ORIG:
			a, err := UnmarshalTuples(attr)
			if err != nil {
				return nil, err
			}
			ra = append(ra, a)
		case CTA_TUPLE_REPLY:
			a, err := UnmarshalTuples(attr)
			if err != nil {
				return nil, err
			}
			ra = append(ra, a)
		case CTA_STATUS:
			a, err := UnmarshalStatus(attr)
			if err != nil {
				return nil, err
			}
			ra = append(ra, a)
		case CTA_PROTOINFO:
			// Nested
			log.Println("Decoding CTA_PROTOINFO")
		case CTA_TIMEOUT:
			// U32
			log.Println("Decoding CTA_TIMEOUT")
		case CTA_ID:
			// U32
			log.Println("Decoding CTA_ID")
		case CTA_MARK:
			// U32
		case CTA_ZONE:
			// U16
		default:
			log.Println("Decoding unknown AttributeType", attr.Type)
		}
	}

	return ra, nil
}
