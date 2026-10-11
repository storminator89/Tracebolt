package windowsfullsoftware

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

type fixtureView struct {
	rows   []nativeRegistration
	fail   error
	change bool
	stamps int
	closed bool
}

func (v *fixtureView) stamp(context.Context) (viewStamp, error) {
	v.stamps++
	m := uint64(1)
	if v.change && v.stamps > 1 {
		m++
	}
	return viewStamp{uint32(len(v.rows)), m}, nil
}
func (v *fixtureView) next(_ context.Context, i uint32) (nativeRegistration, bool, error) {
	if v.fail != nil {
		return nativeRegistration{}, false, v.fail
	}
	if int(i) == len(v.rows) {
		return nativeRegistration{}, true, nil
	}
	return v.rows[i], false, nil
}
func (v *fixtureView) close() error { v.closed = true; return nil }
func softwareAt() time.Time         { return time.Date(2026, 10, 11, 7, 0, 0, 0, time.UTC) }
func ptr(v string) *string          { return &v }
func registration(k string) nativeRegistration {
	return nativeRegistration{key: utf16.Encode([]rune(k)), name: ptr("Same program"), version: ptr("1.0"), publisher: ptr("Publisher")}
}
func TestCompleteRegistryAboveBothPreviewLimitsPreservesDuplicatePrograms(t *testing.T) {
	views := map[string]*fixtureView{"64": {}, "32": {}}
	for _, view := range []string{"64", "32"} {
		for i := 0; i < 2050; i++ {
			views[view].rows = append(views[view].rows, registration(fmt.Sprintf("key-%04d", i)))
		}
	}
	views["64"].rows[0].name = nil
	views["64"].rows[1].version = nil
	views["32"].rows[2].publisher = nil
	capture, e := collectRegistry(context.Background(), func(_ context.Context, v string, b *nativeBudget) (registryView, error) { return views[v], nil }, softwareAt)
	if e != nil || !capture.Complete || len(capture.Rows) != 4100 {
		t.Fatalf("capture %d %v %s", len(capture.Rows), e, capture.Reason)
	}
	if capture.Rows[0].Name != nil || capture.Rows[0].NameQuality != "unavailable" || capture.Rows[0].RegistrationID == capture.Rows[2050].RegistrationID {
		t.Fatal("identity/field loss")
	}
	for _, v := range views {
		if !v.closed {
			t.Fatal("handle leaked")
		}
	}
}
func TestRegistryFailureNeverPromotesPrefix(t *testing.T) {
	for _, e := range []error{ErrDenied, ErrChanged, ErrInvalid, ErrBudget, context.Canceled, context.DeadlineExceeded, ErrUnavailable} {
		t.Run(e.Error(), func(t *testing.T) {
			v := &fixtureView{rows: []nativeRegistration{registration("key")}, fail: e}
			c, err := collectRegistry(context.Background(), func(context.Context, string, *nativeBudget) (registryView, error) { return v, nil }, softwareAt)
			if err == nil || c.Complete || len(c.Rows) != 0 || !ValidFailureReason(c.Reason) {
				t.Fatal("failure promoted")
			}
		})
	}
	for _, v := range []*fixtureView{{rows: []nativeRegistration{registration("key")}, change: true}, {rows: []nativeRegistration{registration("key"), registration("key")}}} {
		c, e := collectRegistry(context.Background(), func(context.Context, string, *nativeBudget) (registryView, error) { return v, nil }, softwareAt)
		if e == nil || c.Reason != "source_changed" || len(c.Rows) != 0 {
			t.Fatal("changed prefix promoted")
		}
	}
}
func TestRegistryCompleteZeroAndClock(t *testing.T) {
	c, e := collectRegistry(context.Background(), func(context.Context, string, *nativeBudget) (registryView, error) { return nil, nil }, softwareAt)
	if e != nil || !c.Complete || len(c.Rows) != 0 {
		t.Fatal("positive empty unavailable")
	}
	count := 0
	now := func() time.Time {
		count++
		if count > 1 {
			return softwareAt().Add(CaptureTimeout + time.Nanosecond)
		}
		return softwareAt()
	}
	c, e = collectRegistry(context.Background(), func(context.Context, string, *nativeBudget) (registryView, error) {
		t.Fatal("read after deadline")
		return nil, nil
	}, now)
	if e == nil || c.Reason != "deadline" {
		t.Fatal("deadline lost")
	}
}
func regBytes(units []uint16) []byte {
	out := []byte{}
	for _, v := range units {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}
func TestRegistryOptionalUTF16BoundedWithoutRepairOrTruncation(t *testing.T) {
	text := strings.Repeat("🙂", 256)
	units := append(utf16.Encode([]rune(text)), 0)
	value := decodeRegistryValue(1, regBytes(units))
	if value == nil || *value != text {
		t.Fatal("valid surrogate pair boundary rejected")
	}
	for _, raw := range [][]byte{nil, {0}, {65, 0}, {0, 0, 0, 0}, regBytes([]uint16{0xd800, 0}), regBytes([]uint16{0xdc00, 0}), regBytes(append(utf16.Encode([]rune(text+"a")), 0))} {
		if decodeRegistryValue(1, raw) != nil {
			t.Fatal("malformed/oversized value became observed")
		}
	}
	if decodeRegistryValue(2, regBytes([]uint16{'x', 0})) != nil {
		t.Fatal("expand value accepted")
	}
	if v := decodeRegistryValue(1, []byte{0, 0}); v == nil || *v != "" {
		t.Fatal("empty observed lost")
	}
}
func TestNativeBudgetAndExactRegistrationIdentity(t *testing.T) {
	b := nativeBudget{bytes: MaxNativeWork}
	if !errors.Is(b.charge(1), ErrBudget) {
		t.Fatal("work exceeded")
	}
	b = nativeBudget{calls: MaxNativeCalls}
	if !errors.Is(b.charge(0), ErrBudget) {
		t.Fatal("calls exceeded")
	}
	a, _ := RegistrationID("64", []uint16{'a'})
	bID, _ := RegistrationID("64", []uint16{'A'})
	v, _ := RegistrationID("32", []uint16{'a'})
	if a == bID || a == v {
		t.Fatal("exact source-key identity merged")
	}
}

func TestRegistrationIdentityRejectsPathsAndInvalidNativeNames(t *testing.T) {
	for _, key := range [][]uint16{nil, {'a', 0}, {0xd800}, utf16.Encode([]rune(`parent\child`)), utf16.Encode([]rune(strings.Repeat("a", 256)))} {
		if _, e := RegistrationID("64", key); e == nil {
			t.Fatal("invalid source key accepted")
		}
	}
}
