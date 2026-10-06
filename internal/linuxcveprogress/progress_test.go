package linuxcveprogress

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 6, 4, 0, 0, 1234, time.UTC)

func testKey(c byte) string { return strings.Repeat(string(c), 64) }

type memoryStorage struct {
	files map[string][]byte
	err   error
}

func (s *memoryStorage) read(name string) ([]byte, error) {
	if data, ok := s.files[name]; ok {
		return bytes.Clone(data), nil
	}
	return nil, os.ErrNotExist
}

func (s *memoryStorage) replace(name string, raw []byte) error {
	if s.err != nil {
		return s.err
	}
	s.files[name] = bytes.Clone(raw)
	return nil
}

func (*memoryStorage) close() error { return nil }

func memoryCache() (*Cache, *memoryStorage) {
	disk := &memoryStorage{files: map[string][]byte{}}
	return &Cache{disk: disk}, disk
}

func mustSave(t *testing.T, c *Cache, key string, expires, now time.Time, raw string) {
	t.Helper()
	if err := c.Save(key, expires, now, []byte(raw)); err != nil {
		t.Fatal(err)
	}
}

func mustLoad(t *testing.T, c *Cache, key string, now time.Time, want string) {
	t.Helper()
	got, err := c.Load(key, now)
	if err != nil || string(got) != want {
		t.Fatalf("load got %q, %v; want %q", got, err, want)
	}
}

func TestExactOpaquePayloadRoundTripAndOriginalTimes(t *testing.T) {
	c, disk := memoryCache()
	expires := testNow.Add(24 * time.Hour)
	raw := " \n { \"pending\": [1, 2], \"opaque\": {\"unknown\":true} }\t\n"
	mustSave(t, c, testKey('a'), expires, testNow, raw)
	mustLoad(t, c, testKey('a'), testNow, raw)
	first, err := decode(disk.files[slotNames[0]], testNow)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := c.Load(testKey('a'), testNow)
	if err != nil {
		t.Fatal(err)
	}
	copy[0] = '!'
	mustLoad(t, c, testKey('a'), testNow.Add(time.Hour), raw)
	mustSave(t, c, testKey('a'), expires, testNow.Add(2*time.Hour), `{"pending":[3]}`)
	updated, err := decode(disk.files[slotNames[0]], testNow.Add(2*time.Hour))
	if err != nil || !updated.CreatedAt.Equal(first.CreatedAt) || !updated.ExpiresAt.Equal(first.ExpiresAt) || !updated.UpdatedAt.Equal(testNow.Add(2*time.Hour)) {
		t.Fatal("save refreshed original checkpoint provenance", err)
	}
	before := bytes.Clone(disk.files[slotNames[0]])
	if err := c.Save(testKey('a'), expires.Add(time.Hour), testNow.Add(3*time.Hour), []byte(`{}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry extension: %v", err)
	}
	if !bytes.Equal(before, disk.files[slotNames[0]]) {
		t.Fatal("expiry extension changed disk")
	}
	mustLoad(t, c, testKey('a'), expires, "")
	mustLoad(t, c, testKey('b'), expires, "")
	if err := c.Save(testKey('a'), expires, expires, []byte(`{}`)); !errors.Is(err, ErrInvalid) {
		t.Fatal("revived expired checkpoint", err)
	}
}

func TestFourSlotsDeterministicEvictionAndIsolation(t *testing.T) {
	c, disk := memoryCache()
	expires := testNow.Add(24 * time.Hour)
	for _, key := range []byte{'a', 'b', 'c', 'd'} {
		mustSave(t, c, testKey(key), expires, testNow, `{"binding":"`+string(key)+`"}`)
	}
	if len(disk.files) != SlotCount {
		t.Fatal("wrong slot count")
	}
	// A tie evicts slot zero; updating a binding later protects it from eviction.
	mustSave(t, c, testKey('e'), expires, testNow.Add(time.Hour), `{"binding":"e"}`)
	mustLoad(t, c, testKey('a'), testNow.Add(time.Hour), "")
	for _, key := range []byte{'b', 'c', 'd', 'e'} {
		mustLoad(t, c, testKey(key), testNow.Add(time.Hour), `{"binding":"`+string(key)+`"}`)
	}
	mustSave(t, c, testKey('b'), expires, testNow.Add(2*time.Hour), `{"binding":"new-b"}`)
	mustSave(t, c, testKey('f'), expires, testNow.Add(3*time.Hour), `{"binding":"f"}`)
	mustLoad(t, c, testKey('c'), testNow.Add(3*time.Hour), "")
	mustLoad(t, c, testKey('b'), testNow.Add(3*time.Hour), `{"binding":"new-b"}`)
	if len(disk.files) != SlotCount {
		t.Fatal("capacity grew")
	}
}

func TestExpiredSlotEvictionPreferredOverOlderLiveSlot(t *testing.T) {
	c, _ := memoryCache()
	for i, key := range []byte{'a', 'b', 'c', 'd'} {
		expires := testNow.Add(24 * time.Hour)
		if key == 'd' {
			expires = testNow.Add(5 * time.Hour)
		}
		mustSave(t, c, testKey(key), expires, testNow.Add(time.Duration(i)*time.Hour), `{}`)
	}
	mustSave(t, c, testKey('e'), testNow.Add(24*time.Hour), testNow.Add(6*time.Hour), `{"new":true}`)
	mustLoad(t, c, testKey('a'), testNow.Add(6*time.Hour), `{}`)
	mustLoad(t, c, testKey('d'), testNow.Add(6*time.Hour), "")
	mustLoad(t, c, testKey('e'), testNow.Add(6*time.Hour), `{"new":true}`)
}

func TestPayloadAndRequestBounds(t *testing.T) {
	c, _ := memoryCache()
	expires := testNow.Add(time.Hour)
	maximum := `"` + strings.Repeat("a", MaxPayloadBytes-2) + `"`
	mustSave(t, c, testKey('a'), expires, testNow, maximum)
	mustLoad(t, c, testKey('a'), testNow, maximum)
	for _, raw := range []string{"", " ", "{", "{} {}", maximum + " ", "\"\xff\"", strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000)} {
		if err := c.Save(testKey('a'), expires, testNow, []byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid payload accepted, size=%d: %v", len(raw), err)
		}
	}
	for _, key := range []string{"", "../slot-0.json", strings.Repeat("a", 63), testKey('g'), testKey('A')} {
		if _, err := c.Load(key, testNow); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid load key accepted: %v", err)
		}
		if err := c.Save(key, expires, testNow, []byte(`{}`)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid save key accepted: %v", err)
		}
	}
	for _, now := range []time.Time{{}, time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1970, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 14*60*60))} {
		if _, err := c.Load(testKey('a'), now); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid time accepted", err)
		}
	}
}

func TestStrictEnvelopeRejectsTamperingAndDuplicateKeys(t *testing.T) {
	c, disk := memoryCache()
	mustSave(t, c, testKey('a'), testNow.Add(time.Hour), testNow, `{"cursor":12}`)
	good := bytes.Clone(disk.files[slotNames[0]])
	mutations := map[string]func([]byte) []byte{
		"payload checksum": func(b []byte) []byte { return bytes.Replace(b, []byte(`"cursor":12`), []byte(`"cursor":13`), 1) },
		"binding checksum": func(b []byte) []byte { return bytes.Replace(b, []byte(testKey('a')), []byte(testKey('b')), 1) },
		"schema":           func(b []byte) []byte { return bytes.Replace(b, []byte(checkpointSchema), []byte("other.schema"), 1) },
		"missing field":    func(b []byte) []byte { return bytes.Replace(b, []byte(`"key":"`+testKey('a')+`",`), nil, 1) },
		"duplicate field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"key":`), []byte(`"key":"`+testKey('b')+`","key":`), 1)
		},
		"unknown field":       func(b []byte) []byte { return append([]byte(`{"unexpected":true,`), b[1:]...) },
		"trailing document":   func(b []byte) []byte { return append(b, []byte(` {}`)...) },
		"trailing whitespace": func(b []byte) []byte { return append(b, '\n') },
		"empty":               func([]byte) []byte { return nil },
		"oversized":           func([]byte) []byte { return bytes.Repeat([]byte(" "), MaxEnvelopeBytes+1) },
		"invalid UTF-8": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"cursor":12`), []byte("\"cursor\":\"\xff\""), 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			disk.files[slotNames[0]] = mutate(bytes.Clone(good))
			before := bytes.Clone(disk.files[slotNames[0]])
			if got, err := c.Load(testKey('a'), testNow); !errors.Is(err, ErrCorrupt) || got != nil {
				t.Fatalf("trusted corruption: %q, %v", got, err)
			}
			if got, err := c.Load(testKey('f'), testNow); !errors.Is(err, ErrCorrupt) || got != nil {
				t.Fatalf("hid corruption behind miss: %q, %v", got, err)
			}
			if err := c.Save(testKey('f'), testNow.Add(time.Hour), testNow, []byte(`{}`)); !errors.Is(err, ErrCorrupt) {
				t.Fatal("overwrote corruption", err)
			}
			if !bytes.Equal(before, disk.files[slotNames[0]]) {
				t.Fatal("corruption repaired")
			}
		})
	}
	disk.files[slotNames[0]] = good
	disk.files[slotNames[1]] = bytes.Clone(good)
	if _, err := c.Load(testKey('a'), testNow); !errors.Is(err, ErrCorrupt) {
		t.Fatal("duplicate binding accepted", err)
	}
}

func TestEnvelopeTimestampValidationEvenWithCorrectChecksum(t *testing.T) {
	cases := map[string]func(*envelope){
		"created after update": func(e *envelope) { e.CreatedAt = e.UpdatedAt.Add(time.Second) },
		"updated at expiry":    func(e *envelope) { e.UpdatedAt = e.ExpiresAt },
		"future update":        func(e *envelope) { e.UpdatedAt = testNow.Add(time.Second) },
		"zero created":         func(e *envelope) { e.CreatedAt = time.Time{} },
		"zero expiry":          func(e *envelope) { e.ExpiresAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := &envelope{Schema: checkpointSchema, Key: testKey('a'), CreatedAt: testNow, UpdatedAt: testNow, ExpiresAt: testNow.Add(time.Hour), Data: json.RawMessage(`{}`)}
			mutate(e)
			raw, err := encode(e)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decode(raw, testNow); !errors.Is(err, ErrCorrupt) {
				t.Fatal("invalid timestamp accepted", err)
			}
		})
	}
}

func TestUncertainInstanceCannotResumeWithoutReopen(t *testing.T) {
	c, disk := memoryCache()
	disk.err = ErrUncertain
	if err := c.Save(testKey('a'), testNow.Add(time.Hour), testNow, []byte(`{}`)); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	disk.err = nil
	if _, err := c.Load(testKey('a'), testNow); !errors.Is(err, ErrUncertain) {
		t.Fatal("uncertain instance permitted load", err)
	}
	if err := c.Save(testKey('b'), testNow.Add(time.Hour), testNow, []byte(`{}`)); !errors.Is(err, ErrUncertain) {
		t.Fatal("uncertain instance permitted save", err)
	}
}

func TestCloseAndNilCache(t *testing.T) {
	c, _ := memoryCache()
	for _, cache := range []*Cache{c, nil, {}} {
		if err := cache.Close(); err != nil {
			t.Fatal(err)
		}
		if err := cache.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.Load(testKey('a'), testNow); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if err := cache.Save(testKey('a'), testNow.Add(time.Hour), testNow, []byte(`{}`)); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
}
