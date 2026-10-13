package macosinventory

import (
	"bytes"
	"encoding/xml"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// ParseReceipts uses pkgutil's plist array rather than newline-delimited IDs:
// a hostile receipt identifier must not be able to forge additional rows.
// The XML decoder does not fetch DTDs or resolve external entities.
func ParseReceipts(raw []byte) (Receipts, error) {
	if len(raw) > MaxSourceBytes {
		return Receipts{}, ErrBounds
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return Receipts{}, ErrMetadata
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	stage := 0
	identifiers := []string{}
	declaration, directive := false, false
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return Receipts{}, ErrMetadata
		}
		switch t := t.(type) {
		case xml.ProcInst:
			if stage != 0 || declaration || t.Target != "xml" {
				return Receipts{}, ErrMetadata
			}
			declaration = true
		case xml.Directive:
			if stage != 0 || directive || strings.TrimSpace(string(t)) != `DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"` {
				return Receipts{}, ErrMetadata
			}
			directive = true
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return Receipts{}, ErrMetadata
			}
		case xml.StartElement:
			if t.Name.Space != "" {
				return Receipts{}, ErrMetadata
			}
			switch {
			case stage == 0 && t.Name.Local == "plist":
				if len(t.Attr) != 1 || t.Attr[0].Name.Space != "" || t.Attr[0].Name.Local != "version" || t.Attr[0].Value != "1.0" {
					return Receipts{}, ErrMetadata
				}
				stage = 1
			case stage == 1 && t.Name.Local == "array":
				if len(t.Attr) != 0 {
					return Receipts{}, ErrMetadata
				}
				stage = 2
			case stage == 2 && t.Name.Local == "string":
				if len(t.Attr) != 0 {
					return Receipts{}, ErrMetadata
				}
				if len(identifiers) >= MaxReceipts {
					return Receipts{}, ErrBounds
				}
				// Read a single text token plus its exact closing element. Nested markup
				// and unexpected fields are invalid, rather than silently discarded.
				var b strings.Builder
				for {
					tokenValue, e := d.Token()
					if e != nil {
						return Receipts{}, ErrMetadata
					}
					if text, ok := tokenValue.(xml.CharData); ok {
						if b.Len()+len(text) > 256 {
							return Receipts{}, ErrBounds
						}
						b.Write(text)
						continue
					}
					close, ok := tokenValue.(xml.EndElement)
					if !ok || close.Name != t.Name {
						return Receipts{}, ErrMetadata
					}
					break
				}
				s := b.String()
				if !token(s, 256, "._+-") {
					return Receipts{}, ErrMetadata
				}
				identifiers = append(identifiers, s)
			default:
				return Receipts{}, ErrMetadata
			}
		case xml.EndElement:
			if t.Name.Space != "" {
				return Receipts{}, ErrMetadata
			}
			if stage == 2 && t.Name.Local == "array" {
				stage = 3
			} else if stage == 3 && t.Name.Local == "plist" {
				stage = 4
			} else {
				return Receipts{}, ErrMetadata
			}
		default:
			return Receipts{}, ErrMetadata
		}
	}
	if stage != 4 {
		return Receipts{}, ErrMetadata
	}
	sort.Strings(identifiers)
	r := Receipts{Status{ReceiptSource, "observed", ""}, identifiers}
	if !validReceipts(r) {
		return Receipts{}, ErrMetadata
	}
	return r, nil
}
