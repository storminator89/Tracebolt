package windowseventcontent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

func TestBoundedTwoPhaseNativeFormatting(t *testing.T) {
	want := "synthetic 😀 message\r\n"
	units := append(utf16.Encode([]rune(want)), 0)
	calls := 0
	got, err := formatMessage(context.Background(), func(buffer []uint16) (uint32, error) {
		calls++
		if calls == 1 {
			if buffer != nil {
				t.Fatal("first call allocated")
			}
			return uint32(len(units)), errInsufficientBuffer
		}
		if len(buffer) != len(units) {
			t.Fatal("buffer character size changed")
		}
		copy(buffer, units)
		return uint32(len(units)), nil
	})
	if err != nil || got != want || calls != 2 {
		t.Fatal("two-phase format failed")
	}
}

func TestNativeAllocationProbeBounds(t *testing.T) {
	for _, size := range []uint32{0, maxNativeMessageUnits + 1, ^uint32(0)} {
		calls := 0
		got, err := formatMessage(context.Background(), func([]uint16) (uint32, error) { calls++; return size, errInsufficientBuffer })
		if got != "" || err == nil || calls != 1 {
			t.Fatal("invalid allocation size accepted")
		}
	}
	for _, probeErr := range []error{nil, ErrPublisherUnavailable, ErrMessageUnavailable, errors.New("raw-secret")} {
		got, err := formatMessage(context.Background(), func([]uint16) (uint32, error) { return 3, probeErr })
		if err == nil || got != "" || strings.Contains(err.Error(), "raw-secret") {
			t.Fatal("invalid probe accepted/leaked")
		}
	}
}

func TestFormattingFailureDiscardsPopulatedText(t *testing.T) {
	for _, failure := range []error{errInsufficientBuffer, ErrMessageUnavailable, errors.New("private OS error")} {
		calls := 0
		got, err := formatMessage(context.Background(), func(buffer []uint16) (uint32, error) {
			calls++
			if calls == 1 {
				return 8, errInsufficientBuffer
			}
			copy(buffer, []uint16{'s', 'e', 'c', 'r', 'e', 't', 0})
			return 7, failure
		})
		if got != "" || err == nil || calls != 2 || strings.Contains(err.Error(), "private") {
			t.Fatal("partial message exposed or retried")
		}
	}
}

func TestMalformedFormattedBuffers(t *testing.T) {
	for _, tt := range []struct {
		buffer []uint16
		used   uint32
	}{
		{nil, 0}, {[]uint16{0}, 2}, {[]uint16{'a'}, 1}, {[]uint16{'a', 0, 'b', 0}, 4},
		{[]uint16{0xd800, 0}, 2}, {[]uint16{0xdc00, 0}, 2}, {[]uint16{0xd800, 'a', 0}, 3},
		{make([]uint16, maxNativeMessageUnits+1), 1},
	} {
		if text, err := decodeMessage(tt.buffer, tt.used); err == nil || text != "" {
			t.Fatal("malformed UTF-16 accepted")
		}
	}
	got, err := decodeMessage([]uint16{0}, 1)
	if err != nil || got != "" {
		t.Fatal("valid empty message rejected")
	}
	got, err = formatMessage(context.Background(), func(buffer []uint16) (uint32, error) {
		if buffer == nil {
			return 2, errInsufficientBuffer
		}
		buffer[0] = 'a'
		return 2, nil
	})
	if err == nil || got != "" {
		t.Fatal("unwritten terminator accepted")
	}
}

func TestFormatCancellationNoSecondNativeCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	got, err := formatMessage(ctx, func([]uint16) (uint32, error) { calls++; cancel(); return 100, errInsufficientBuffer })
	if got != "" || !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("format continued after cancellation")
	}
}

func FuzzFormattedMessage(f *testing.F) {
	f.Add([]byte{'a', 0, 0, 0}, uint32(2))
	f.Add([]byte{}, uint32(0))
	f.Fuzz(func(t *testing.T, b []byte, used uint32) {
		if len(b) > 2*(maxNativeMessageUnits+1) {
			return
		}
		units := make([]uint16, len(b)/2)
		for i := range units {
			units[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		text, err := decodeMessage(units, used)
		if err == nil && (!utf8.ValidString(text) || strings.ContainsRune(text, 0) || len(text) > 3*maxNativeMessageUnits) {
			t.Fatal("invalid message escaped decoder")
		}
	})
}
