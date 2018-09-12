package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// Expect represents an 'expected' conenction, created by Conntrack/IPTables helpers.
// Active connections created by helpers are shown by the conntrack tooling as 'RELATED'.
type Expect struct {
	ID, Timeout Num32

	TupleMaster, Tuple, Mask Tuple

	Zone Num16

	HelpName, Function string

	Flags, Class Num32

	NAT ExpectNAT
}

// ExpectNAT holds NAT information about an expected connection.
type ExpectNAT struct {
	Direction bool
	Tuple     Tuple
}

// unmarshal unmarshals a netfilter.Attribute into an ExpectNAT.
func (en *ExpectNAT) unmarshal(attr netfilter.Attribute) error {

	if ExpectType(attr.Type) != CTAExpectNAT {
		return fmt.Errorf(errAttributeWrongType, attr.Type, CTAExpectNAT)
	}

	if !attr.Nested {
		return errNotNested
	}

	if len(attr.Children) == 0 {
		return errNeedSingleChild
	}

	for _, iattr := range attr.Children {
		switch ExpectNATType(iattr.Type) {
		case CTAExpectNATDir:
			en.Direction = iattr.Uint32() == 1
		case CTAExpectNATTuple:
			if err := en.Tuple.UnmarshalAttribute(iattr); err != nil {
				return err
			}
		default:
			return fmt.Errorf(errAttributeChild, iattr.Type, CTAExpectNAT)
		}
	}

	return nil
}

// unmarshal unmarshals a list of netfilter.Attributes into an Expect structure.
func (ex *Expect) unmarshal(attrs []netfilter.Attribute) error {

	for _, attr := range attrs {

		switch at := ExpectType(attr.Type); at {

		case CTAExpectMaster:
			if err := ex.TupleMaster.UnmarshalAttribute(attr); err != nil {
				return err
			}
		case CTAExpectTuple:
			if err := ex.Tuple.UnmarshalAttribute(attr); err != nil {
				return err
			}
		case CTAExpectMask:
			if err := ex.Mask.UnmarshalAttribute(attr); err != nil {
				return err
			}
		case CTAExpectTimeout:
			if err := ex.Timeout.UnmarshalAttribute(attr); err != nil {
				return err
			}
		case CTAExpectID:
			if err := ex.ID.UnmarshalAttribute(attr); err != nil {
				return err
			}
		case CTAExpectHelpName:
			ex.HelpName = string(attr.Data)
		case CTAExpectZone:
			if err := ex.Zone.UnmarshalAttribute(attr); err != nil {
				return err
			}
		case CTAExpectFlags:
			if err := ex.Flags.UnmarshalAttribute(attr); err != nil {
				return err
			}
		case CTAExpectClass:
			if err := ex.Class.UnmarshalAttribute(attr); err != nil {
				return err
			}
		case CTAExpectNAT:
			if err := ex.NAT.unmarshal(attr); err != nil {
				return err
			}
		case CTAExpectFN:
			ex.Function = string(attr.Data)
		default:
			return fmt.Errorf(errAttributeUnknown, at)
		}
	}

	return nil
}

// unmarshalExpects unmarshals a list of expected connectinos from a list of Netlink messages.
// This method can be used to parse the result of a dump or get query.
func unmarshalExpects(nlm []netlink.Message) ([]Expect, error) {

	// Pre-allocate to avoid extending output slice on every op
	out := make([]Expect, len(nlm))

	for i := 0; i < len(nlm); i++ {

		_, attrs, err := netfilter.UnmarshalNetlink(nlm[i])
		if err != nil {
			return nil, err
		}

		var ex Expect
		err = ex.unmarshal(attrs)
		if err != nil {
			return nil, err
		}

		out[i] = ex
	}

	return out, nil
}
