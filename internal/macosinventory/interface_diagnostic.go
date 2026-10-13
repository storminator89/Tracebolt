package macosinventory

import (
	"bytes"
	"unicode/utf8"
)

// InterfaceParseCode is a content-free first-rejection classification. It
// contains no input bytes, identifiers, indexes, measurements, or error text.
// It is separate from Status and the product wire format.
type InterfaceParseCode uint8

const (
	InterfaceParseNotRun InterfaceParseCode = iota
	InterfaceParseOK
	interfaceSourceSize
	interfaceSourceControl
	interfaceSourceNewline
	interfaceSourceLineSize
	interfaceSourceEncoding
	interfaceEmptyRecord
	interfaceRowLimit
	interfaceHeaderShape
	interfaceHeaderFlags
	interfaceHeaderName
	interfaceMTUMissing
	interfaceMTUDuplicate
	interfaceMTUValue
	interfaceOrphanRecord
	interfaceBlankRecord
	interfaceAddressShape
	interfaceAddressNumeric
	interfaceAddressFamily
	interfaceAddressZone
	interfacePrefixMissing
	interfacePrefixDuplicate
	interfacePrefixValue
	interfaceAddressLimit
	interfaceResultEmpty
	interfaceDuplicateRow
	interfaceDuplicateAddress
	interfaceResultInvalid
)

// String uses only fixed reviewed text, even for a forged or unknown code.
func (c InterfaceParseCode) String() string {
	switch c {
	case InterfaceParseNotRun:
		return "not_run"
	case InterfaceParseOK:
		return "none"
	case interfaceSourceSize:
		return "source_size"
	case interfaceSourceControl:
		return "source_control"
	case interfaceSourceNewline:
		return "source_newline"
	case interfaceSourceLineSize:
		return "source_line_size"
	case interfaceSourceEncoding:
		return "source_encoding"
	case interfaceEmptyRecord:
		return "empty_record"
	case interfaceRowLimit:
		return "interface_limit"
	case interfaceHeaderShape:
		return "header_shape"
	case interfaceHeaderFlags:
		return "header_flags"
	case interfaceHeaderName:
		return "header_name"
	case interfaceMTUMissing:
		return "mtu_missing"
	case interfaceMTUDuplicate:
		return "mtu_duplicate"
	case interfaceMTUValue:
		return "mtu_value"
	case interfaceOrphanRecord:
		return "orphan_record"
	case interfaceBlankRecord:
		return "blank_record"
	case interfaceAddressShape:
		return "address_shape"
	case interfaceAddressNumeric:
		return "address_numeric"
	case interfaceAddressFamily:
		return "address_family"
	case interfaceAddressZone:
		return "address_zone"
	case interfacePrefixMissing:
		return "prefix_missing"
	case interfacePrefixDuplicate:
		return "prefix_duplicate"
	case interfacePrefixValue:
		return "prefix_value"
	case interfaceAddressLimit:
		return "address_limit"
	case interfaceResultEmpty:
		return "result_empty"
	case interfaceDuplicateRow:
		return "duplicate_interface"
	case interfaceDuplicateAddress:
		return "duplicate_address"
	case interfaceResultInvalid:
		return "result_invalid"
	default:
		return "unclassified"
	}
}

// Called only after the unchanged shared sourceLines parser rejects input.
// Match its existing decision order. Rechecking framing in memory does not
// parse interfaces again or invoke a provider.
func interfaceSourceFailure(raw []byte) InterfaceParseCode {
	if len(raw) > MaxSourceBytes {
		return interfaceSourceSize
	}
	if bytes.ContainsAny(raw, "\x00\r") {
		return interfaceSourceControl
	}
	if len(raw) != 0 && raw[len(raw)-1] != '\n' {
		return interfaceSourceNewline
	}
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(line) > 4096 {
			return interfaceSourceLineSize
		}
	}
	if !utf8.Valid(raw) {
		return interfaceSourceEncoding
	}
	return interfaceResultInvalid
}

// Called only after the unchanged wire validator rejects the sorted result.
func interfaceResultFailure(v Interfaces) InterfaceParseCode {
	if len(v.Rows) == 0 {
		return interfaceResultEmpty
	}
	for i, r := range v.Rows {
		if i > 0 && r.Name == v.Rows[i-1].Name {
			return interfaceDuplicateRow
		}
		for j, a := range r.Addresses {
			if j > 0 && addressKey(a) == addressKey(r.Addresses[j-1]) {
				return interfaceDuplicateAddress
			}
		}
	}
	return interfaceResultInvalid
}
