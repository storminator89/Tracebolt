package windowsevents

import (
	"encoding/binary"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	metadataPropertyCount = 6
	variantSize           = 16
	maxRenderBytes        = 16 * 1024
	maxProviderUnits      = 256
	variantString         = 1
	variantByte           = 4
	variantUInt16         = 6
	variantUInt64         = 10
	variantFileTime       = 17
)

// Fixed selectors read only the approved System properties. Deliberately do not
// use EvtRenderContextSystem: it would also materialize Computer and UserID/SID.
// No XML or event-content parser is involved. This list is not caller editable.
func metadataPaths() [metadataPropertyCount]string {
	return [metadataPropertyCount]string{
		"Event/System/EventRecordID",
		"Event/System/EventID",
		"Event/System/Level",
		"Event/System/Provider/@Name",
		"Event/System/TimeCreated/@SystemTime",
		"Event/System/Channel",
	}
}

// parseMetadataValues decodes the fixed EVT_VARIANT array from EvtRender.
// Pointer-valued fields are treated only as bounded offsets into buffer; this
// portable parser never dereferences a native pointer or reads beyond the buffer.
func parseMetadataValues(buffer []byte, base uint64, count uint32, channel string) (Event, error) {
	if !allowedChannel(channel) || count != metadataPropertyCount ||
		len(buffer) < metadataPropertyCount*variantSize || len(buffer) > maxRenderBytes {
		return Event{}, ErrInvalidData
	}
	wantTypes := [metadataPropertyCount]uint32{variantUInt64, variantUInt16, variantByte, variantString, variantFileTime, variantString}
	var values [metadataPropertyCount]uint64
	for i, typ := range wantTypes {
		at := i * variantSize
		// Arrays and Null properties are rejected rather than silently converted.
		if binary.LittleEndian.Uint32(buffer[at+12:]) != typ {
			return Event{}, ErrInvalidData
		}
		values[i] = binary.LittleEndian.Uint64(buffer[at:])
	}
	// The union's unused bytes and scalar Count are not specified by Win32.
	values[1] &= 0xffff
	values[2] &= 0xff
	if strconv.IntSize == 32 {
		values[3] &= 0xffffffff
		values[5] &= 0xffffffff
	}
	if values[0] == 0 {
		return Event{}, ErrInvalidData
	}
	provider, err := valueString(buffer, base, values[3], maxProviderUnits)
	if err != nil || !validProvider(provider) {
		return Event{}, ErrInvalidData
	}
	gotChannel, err := valueString(buffer, base, values[5], len("Application"))
	if err != nil || gotChannel != channel {
		return Event{}, ErrInvalidData
	}
	// FILETIME ticks are 100 ns since 1601. Divide before converting to int64
	// to avoid the nanosecond overflow of Filetime.Nanoseconds after year 2262.
	stamp := time.Unix(int64(values[4]/10000000)-11644473600, int64(values[4]%10000000)*100).UTC()
	event := Event{RecordID: values[0], EventID: uint16(values[1]), Level: uint8(values[2]),
		Provider: provider, Timestamp: stamp, Channel: gotChannel}
	if !validEvent(event, channel) {
		return Event{}, ErrInvalidData
	}
	return event, nil
}

func valueString(buffer []byte, base, pointer uint64, maxUnits int) (string, error) {
	if pointer < base {
		return "", ErrInvalidData
	}
	offset := pointer - base
	if offset < metadataPropertyCount*variantSize || offset%2 != 0 || offset >= uint64(len(buffer)) {
		return "", ErrInvalidData
	}
	units := make([]uint16, 0, maxUnits)
	for at := offset; at+2 <= uint64(len(buffer)) && len(units) <= maxUnits; at += 2 {
		u := binary.LittleEndian.Uint16(buffer[at:])
		if u == 0 {
			for i := 0; i < len(units); i++ {
				if units[i] >= 0xd800 && units[i] <= 0xdbff {
					if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
						return "", ErrInvalidData
					}
					i++
				} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
					return "", ErrInvalidData
				}
			}
			return string(utf16.Decode(units)), nil
		}
		units = append(units, u)
	}
	return "", ErrInvalidData
}

func validProvider(provider string) bool {
	if provider == "" || !utf8.ValidString(provider) || strings.TrimSpace(provider) != provider {
		return false
	}
	units := 0
	for _, r := range provider {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
		units++
		if r > 0xffff {
			units++
		}
		if units > maxProviderUnits {
			return false
		}
	}
	return true
}
