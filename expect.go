package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"github.com/ti-mo/netfilter"
)

const (
	opUnExpectNAT = "ExpectNAT unmarshal"
)

// Expect represents an 'expected' conenction, created by Conntrack/IPTables helpers.
// Active connections created by helpers are shown by the conntrack tooling as 'RELATED'.
type Expect struct {
	ID, Timeout uint32

	TupleMaster, Tuple, Mask Tuple

	Zone uint16

	HelpName, Function string

	Flags, Class uint32

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
		return errors.Wrap(errNotNested, opUnExpectNAT)
	}

	if len(attr.Children) == 0 {
		return errors.Wrap(errNeedSingleChild, opUnExpectNAT)
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
			return errors.Wrap(fmt.Errorf(errAttributeChild, iattr.Type, CTAExpectNAT), opUnExpectNAT)
		}
	}

	return nil
}

func (en ExpectNAT) marshal() (netfilter.Attribute, error) {

	nfa := netfilter.Attribute{Type: uint16(CTAExpectNAT), Nested: true, Children: make([]netfilter.Attribute, 2)}

	var dir uint32
	if en.Direction {
		dir = 1
	}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(CTAExpectNATDir), Data: netfilter.Uint32Bytes(dir)}

	ta, err := en.Tuple.MarshalAttribute(uint16(CTAExpectNATTuple))
	if err != nil {
		return nfa, err
	}
	nfa.Children[1] = ta

	return nfa, nil
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
			ex.Timeout = attr.Uint32()
		case CTAExpectID:
			ex.ID = attr.Uint32()
		case CTAExpectHelpName:
			ex.HelpName = string(attr.Data)
		case CTAExpectZone:
			ex.Zone = attr.Uint16()
		case CTAExpectFlags:
			ex.Flags = attr.Uint32()
		case CTAExpectClass:
			ex.Class = attr.Uint32()
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

func (ex Expect) marshal() ([]netfilter.Attribute, error) {

	// Expectations need Tuple, Mask and TupleMaster filled to be valid.
	if !ex.Tuple.Filled() || !ex.Mask.Filled() || !ex.TupleMaster.Filled() {
		return nil, errNeedTuples
	}

	attrs := make([]netfilter.Attribute, 3, 9)

	tm, err := ex.TupleMaster.MarshalAttribute(uint16(CTAExpectMaster))
	if err != nil {
		return nil, err
	}
	attrs[0] = tm

	tp, err := ex.Tuple.MarshalAttribute(uint16(CTAExpectTuple))
	if err != nil {
		return nil, err
	}
	attrs[1] = tp

	ts, err := ex.Mask.MarshalAttribute(uint16(CTAExpectMask))
	if err != nil {
		return nil, err
	}
	attrs[2] = ts

	if ex.HelpName != "" {
		attrs = append(attrs, netfilter.Attribute{Type: uint16(CTAExpectHelpName), Data: []byte(ex.HelpName)})
	}

	if ex.Zone != 0 {
		attrs = append(attrs, netfilter.Attribute{Type: uint16(CTAExpectZone), Data: netfilter.Uint16Bytes(ex.Zone)})
	}

	if ex.Class != 0 {
		attrs = append(attrs, netfilter.Attribute{Type: uint16(CTAExpectClass), Data: netfilter.Uint32Bytes(ex.Class)})
	}

	if ex.Flags != 0 {
		attrs = append(attrs, netfilter.Attribute{Type: uint16(CTAExpectFlags), Data: netfilter.Uint32Bytes(ex.Flags)})
	}

	if ex.Function != "" {
		attrs = append(attrs, netfilter.Attribute{Type: uint16(CTAExpectFN), Data: []byte(ex.Function)})
	}

	if ex.NAT.Tuple.Filled() {
		en, err := ex.NAT.marshal()
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, en)
	}

	return attrs, nil
}

// unmarshalExpect unmarshals an Expect from a netlink.Message.
// The Message must contain valid attributes.
func unmarshalExpect(nlm netlink.Message) (Expect, error) {

	var ex Expect

	_, nfa, err := netfilter.UnmarshalNetlink(nlm)
	if err != nil {
		return ex, err
	}

	err = ex.unmarshal(nfa)
	if err != nil {
		return ex, err
	}

	return ex, nil
}

// unmarshalExpects unmarshals a list of expected connections from a list of Netlink messages.
// This method can be used to parse the result of a dump or get query.
func unmarshalExpects(nlm []netlink.Message) ([]Expect, error) {

	// Pre-allocate to avoid re-allocating output slice on every op
	out := make([]Expect, 0, len(nlm))

	for i := 0; i < len(nlm); i++ {

		ex, err := unmarshalExpect(nlm[i])
		if err != nil {
			return nil, err
		}

		out = append(out, ex)
	}

	return out, nil
}
