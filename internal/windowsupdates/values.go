package windowsupdates

import "unicode/utf16"

// decodeNativeString is shared by the bounded BSTR reader and portable fixtures.
// It refuses malformed UTF-16 rather than replacing invalid identity/title bytes.
func decodeNativeString(units []uint16) (string, error) {
	if len(units) > MaxNativeStringUnits {
		return "", ErrBounds
	}
	for i := 0; i < len(units); i++ {
		c := units[i]
		if c >= 0xd800 && c <= 0xdbff {
			if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", ErrMetadata
			}
			i++
		} else if c >= 0xdc00 && c <= 0xdfff {
			return "", ErrMetadata
		}
	}
	return string(utf16.Decode(units)), nil
}
