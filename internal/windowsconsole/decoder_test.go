package windowsconsole

import (
	"bytes"
	"encoding/base64"
	"testing"
	"unsafe"
)

// All invitation-shaped values in this package are inert, deterministic
// fixtures. These tests never open a console or provision an identity.
func key(c uint16, repeat uint16) inputRecord {
	return inputRecord{eventType: 1, data: [4]uint32{1, uint32(repeat), uint32(c) << 16, 0}}
}

func fixtureRecords() []inputRecord {
	return []inputRecord{key('A', invitationLength), key('\r', 1)}
}

func TestInputRecordABI(t *testing.T) {
	var record inputRecord
	if unsafe.Sizeof(record) != 20 || unsafe.Alignof(record) != 4 || unsafe.Offsetof(record.data) != 4 {
		t.Fatal("console input ABI mismatch")
	}
	if unsafe.Sizeof(record.data[0]) != 4 || unsafe.Offsetof(record.eventType) != 0 {
		t.Fatal("console record field ABI mismatch")
	}
}

func TestDecoderCanonicalInvitationAndClearing(t *testing.T) {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	fixture := make([]byte, invitationLength)
	base64.RawURLEncoding.Encode(fixture, raw[:])
	var decoder invitationDecoder
	for _, c := range fixture {
		if done, err := decoder.consume(key(uint16(c), 1)); done || err != nil {
			t.Fatal("fixture character rejected")
		}
	}
	if done, err := decoder.consume(key('\r', 1)); !done || err != nil {
		t.Fatal("canonical fixture rejected")
	}
	if _, err := decoder.consume(key('A', 1)); err != ErrInput {
		t.Fatal("completed decoder accepted more input")
	}
	result := decoder.take()
	defer clear(result)
	if !bytes.Equal(result, fixture) {
		t.Fatal("decoded invitation differs")
	}
	if decoder.length != 0 || decoder.finished || decoder.bytes != [invitationLength]byte{} {
		t.Fatal("decoder retained consumed material")
	}
	if decoder.take() != nil {
		t.Fatal("uncompleted decoder returned material")
	}
}

func TestDecoderRejectsInvalidInput(t *testing.T) {
	cases := map[string][]inputRecord{
		"empty":         {key('\r', 1)},
		"short":         {key('A', invitationLength-1), key('\r', 1)},
		"overflow":      {key('A', invitationLength+1)},
		"late overflow": {key('A', invitationLength), key('A', 1)},
		"huge repeat":   {key('A', 65535)},
		"zero repeat":   {key('A', 0)},
		"padding":       {key('=', 1)},
		"space":         {key(' ', 1)},
		"tab":           {key('\t', 1)},
		"line feed":     {key('\n', 1)},
		"ctrl c":        {key(3, 1)},
		"ctrl d":        {key(4, 1)},
		"ctrl z":        {key(26, 1)},
		"escape":        {key(27, 1)},
		"unicode":       {key(0x1234, 1)},
		"surrogate":     {key(0xd800, 1)},
		"slash":         {key('/', 1)},
		"plus":          {key('+', 1)},
		"noncanonical":  {key('A', invitationLength-1), key('B', 1), key('\r', 1)},
		"ctrl break":    {{eventType: 1, data: [4]uint32{1, 0x00030001, 0, 0}}},
	}
	for name, records := range cases {
		t.Run(name, func(t *testing.T) {
			var decoder invitationDecoder
			defer decoder.clear()
			failed := false
			for _, record := range records {
				done, err := decoder.consume(record)
				if done {
					t.Fatal("invalid fixture completed")
				}
				if err != nil {
					if err != ErrInput {
						t.Fatal("unsanitized decoder error")
					}
					failed = true
					break
				}
			}
			if !failed || decoder.take() != nil {
				t.Fatal("invalid fixture accepted")
			}
		})
	}
}

func TestDecoderEditingRepeatsAndIgnoredRecords(t *testing.T) {
	var decoder invitationDecoder
	defer decoder.clear()
	records := []inputRecord{key('\b', 65535), key('B', 4), key('\b', 2)}
	for _, record := range records {
		if done, err := decoder.consume(record); done || err != nil {
			t.Fatal("editing fixture rejected")
		}
	}
	if decoder.length != 2 || decoder.bytes[2] != 0 || decoder.bytes[3] != 0 {
		t.Fatal("backspace did not clear removed material")
	}
	ignored := []inputRecord{{eventType: 2}, {eventType: 4}, {eventType: 8}, {eventType: 16}, {}, {eventType: 1}, key(0, 1)}
	for _, record := range ignored {
		if done, err := decoder.consume(record); done || err != nil || decoder.length != 2 {
			t.Fatal("noncharacter record affected input")
		}
	}
	_, _ = decoder.consume(key('\b', 65535))
	if decoder.length != 0 || decoder.bytes != [invitationLength]byte{} {
		t.Fatal("repeated backspace did not clear buffer")
	}
	for _, record := range fixtureRecords() {
		if _, err := decoder.consume(record); err != nil {
			t.Fatal("edited fixture rejected")
		}
	}
	if !decoder.finished {
		t.Fatal("edited fixture incomplete")
	}
}

func TestDecoderAlphabet(t *testing.T) {
	for c := range uint32(65536) {
		want := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if invitationCharacter(uint16(c)) != want {
			t.Fatal("invitation alphabet mismatch")
		}
	}
}
