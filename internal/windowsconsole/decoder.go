package windowsconsole

import "encoding/base64"

// INPUT_RECORD has a WORD event type, two alignment bytes and a 16-byte
// union aligned to four bytes on Windows 386, amd64 and arm64. Keeping its
// native uint32 alignment avoids passing a byte-aligned buffer to Kernel32.
// https://learn.microsoft.com/en-us/windows/console/input-record-str
// https://learn.microsoft.com/en-us/windows/console/key-event-record-str
type inputRecord struct {
	eventType uint16
	padding   uint16
	data      [4]uint32
}

func (r *inputRecord) clear() { *r = inputRecord{} }

type invitationDecoder struct {
	bytes    [invitationLength]byte
	length   int
	finished bool
}

func (d *invitationDecoder) clear() {
	clear(d.bytes[:])
	d.length = 0
	d.finished = false
}

// consume uses only key-down Unicode character and repeat-count fields. Mouse,
// window, focus, menu, key-up and noncharacter keys cannot complete input.
func (d *invitationDecoder) consume(r inputRecord) (bool, error) {
	defer r.clear()
	if d.finished {
		return false, ErrInput
	}
	if r.eventType != 0x0001 || r.data[0] == 0 {
		return false, nil
	}
	count := int(uint16(r.data[1]))
	virtualKey := uint16(r.data[1] >> 16)
	character := uint16(r.data[2] >> 16)
	if character == 0 {
		if virtualKey == 0x03 { // VK_CANCEL (Ctrl+Break)
			return false, ErrInput
		}
		return false, nil
	}
	if count == 0 {
		return false, ErrInput
	}
	switch character {
	case '\b':
		if count > d.length {
			count = d.length
		}
		clear(d.bytes[d.length-count : d.length])
		d.length -= count
		return false, nil
	case '\r':
		if d.length != invitationLength {
			return false, ErrInput
		}
		// Strict decoding rejects nonzero unused bits in the last character;
		// no secret-to-string conversion or decoded secret is retained.
		var decoded [32]byte
		defer clear(decoded[:])
		n, err := base64.RawURLEncoding.Strict().Decode(decoded[:], d.bytes[:])
		if err != nil || n != len(decoded) {
			return false, ErrInput
		}
		d.finished = true
		return true, nil
	default:
		if !invitationCharacter(character) || count > invitationLength-d.length {
			return false, ErrInput
		}
		for range count {
			d.bytes[d.length] = byte(character)
			d.length++
		}
		return false, nil
	}
}

func (d *invitationDecoder) take() []byte {
	if !d.finished {
		return nil
	}
	result := make([]byte, invitationLength)
	copy(result, d.bytes[:])
	d.clear()
	return result
}

func invitationCharacter(c uint16) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}
