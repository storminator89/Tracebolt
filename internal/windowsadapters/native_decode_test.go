package windowsadapters

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

const fixtureBase = uint64(0x10000)

func nativeFixture() []byte {
	b := make([]byte, 1024)
	u32 := func(o int, v uint32) { binary.LittleEndian.PutUint32(b[o:], v) }
	u64 := func(o int, v uint64) { binary.LittleEndian.PutUint64(b[o:], v) }
	u32(0, adapterFull)
	u32(4, 7)
	u32(100, 6)
	u32(104, 2)
	u32(108, 7)
	u64(72, fixtureBase+256)
	for i, c := range "Fixture Ethernet" {
		binary.LittleEndian.PutUint16(b[256+i*2:], uint16(c))
	}
	u64(184, 1_000_000_000)
	u64(192, 100_000_000)
	u64(48, fixtureBase+320)
	u32(320, addressNodeSize)
	u64(336, fixtureBase+400)
	u32(344, 16)
	binary.LittleEndian.PutUint16(b[400:], 2)
	copy(b[404:], []byte{192, 0, 2, 53})
	u64(208, fixtureBase+448)
	u32(448, addressNodeSize)
	u64(464, fixtureBase+512)
	u32(472, 28)
	binary.LittleEndian.PutUint16(b[512:], 23)
	copy(b[520:], []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	u32(536, 7)
	// Forbidden aggregate pointers are deliberately outside the allocation.
	for _, o := range []int{16, 24, 32, 40, 56, 64, 176, 200} {
		u64(o, math.MaxUint64)
	}
	return b
}
func TestAdapterContextNativeDecoderFieldsAndExclusions(t *testing.T) {
	b := nativeFixture()
	r := decodeNative(context.Background(), b, fixtureBase)
	if !r.Complete || r.Err != nil || len(r.Rows) != 1 {
		t.Fatal(r)
	}
	a := r.Rows[0]
	if a.State != "down" || *a.TxLinkBps != 1_000_000_000 || *a.RxLinkBps != 100_000_000 || a.DNSServers.Addresses[0] != "192.0.2.53" || a.Gateways.Addresses[0] != "fe80::1%7" {
		t.Fatalf("wrong typed fields: %+v", a)
	}
	for n := uint32(0); n < 10; n++ {
		binary.LittleEndian.PutUint32(b[104:], n)
		got := decodeNative(context.Background(), b, fixtureBase)
		if !got.Complete || got.Rows[0].State != operState(n) {
			t.Fatal("state inferred rather than decoded")
		}
	}
	binary.LittleEndian.PutUint64(b[184:], math.MaxUint64)
	binary.LittleEndian.PutUint64(b[192:], 0)
	a = decodeNative(context.Background(), b, fixtureBase).Rows[0]
	if a.TxLinkBps != nil || a.RxLinkBps != nil || a.TxQuality != "unknown" || a.RxQuality != "unknown" {
		t.Fatal("sentinel speed exposed")
	}
	binary.LittleEndian.PutUint32(b, adapterMin)
	a = decodeNative(context.Background(), b, fixtureBase).Rows[0]
	if a.TxQuality != "unavailable" || a.Gateways.Quality != "unavailable" || a.DNSServers.Quality != "observed" {
		t.Fatal("short structure fabricated optional fields")
	}
}
func TestAdapterContextNativeDecoderBoundsAndPartial(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func([]byte)
		rows     int
		complete bool
		list     string
	}{
		{"adapter-cycle", func(b []byte) { binary.LittleEndian.PutUint64(b[8:], fixtureBase) }, 1, false, "observed"},
		{"outside-next", func(b []byte) { binary.LittleEndian.PutUint64(b[8:], math.MaxUint64) }, 1, false, "observed"},
		{"dns-cycle", func(b []byte) { binary.LittleEndian.PutUint64(b[328:], fixtureBase+320) }, 1, true, "partial"},
		{"dns-outside", func(b []byte) { binary.LittleEndian.PutUint64(b[48:], math.MaxUint64) }, 1, true, "partial"},
		{"dns-short-socket", func(b []byte) { binary.LittleEndian.PutUint32(b[344:], 3) }, 1, true, "partial"},
		{"short-adapter", func(b []byte) { binary.LittleEndian.PutUint32(b, 8) }, 0, false, ""},
		{"missing-name", func(b []byte) { binary.LittleEndian.PutUint64(b[72:], 0) }, 0, false, ""},
		{"loopback", func(b []byte) { binary.LittleEndian.PutUint32(b[100:], 24) }, 0, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := nativeFixture()
			tc.change(b)
			r := decodeNative(context.Background(), b, fixtureBase)
			if len(r.Rows) != tc.rows || r.Complete != tc.complete {
				t.Fatal(r)
			}
			if tc.rows > 0 && r.Rows[0].DNSServers.Quality != tc.list {
				t.Fatal(r.Rows[0])
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := decodeNative(ctx, nativeFixture(), fixtureBase); !errors.Is(r.Err, context.Canceled) || len(r.Rows) != 0 {
		t.Fatal(r)
	}
	// Source work stays bounded even with 129 well-formed adapters.
	b := make([]byte, 256*(MaxObservedRows+1))
	for i := 0; i <= MaxObservedRows; i++ {
		o := i * 256
		binary.LittleEndian.PutUint32(b[o:], adapterFull)
		binary.LittleEndian.PutUint32(b[o+4:], uint32(i+1))
		binary.LittleEndian.PutUint32(b[o+100:], 6)
		binary.LittleEndian.PutUint64(b[o+72:], fixtureBase+uint64(o+224))
		binary.LittleEndian.PutUint16(b[o+224:], 'x')
		if i < MaxObservedRows {
			binary.LittleEndian.PutUint64(b[o+8:], fixtureBase+uint64(o+256))
		}
	}
	r := decodeNative(context.Background(), b, fixtureBase)
	if r.Complete || !errors.Is(r.Err, ErrBounds) || len(r.Rows) != MaxObservedRows {
		t.Fatal("adapter traversal cap failed")
	}
}
func TestAdapterContextCollectionContractAndBudget(t *testing.T) {
	at := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	g := "sample_" + strings.Repeat("a", 32)
	grant := strings.Repeat("b", 32)
	for _, failure := range []error{nil, ErrDenied, ErrUnsupported, ErrUnavailable, ErrBounds} {
		s, e := collectUsing(context.Background(), g, grant, at, func(ctx context.Context) Result {
			if failure != nil {
				return Result{Err: failure}
			}
			return decodeNative(ctx, nativeFixture(), fixtureBase)
		})
		if e != nil || Validate(s) != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(s)
		if _, e = Decode(raw); e != nil {
			t.Fatal(e)
		}
		if failure != nil && (s.CountExact || s.ObservedCount != 0 || s.Quality == "observed") {
			t.Fatal("failure represented as empty success")
		}
		if failure == nil {
			small, e := FitBudget(s, 500)
			if e != nil || !small.Truncated || len(small.Rows) != 0 || small.ObservedCount != 1 || !small.CollectedAt.Equal(at) {
				t.Fatal("budget rewrote source", e)
			}
		}
	}
	called := false
	if _, e := collectUsing(context.Background(), g, "invalid", at, func(context.Context) Result { called = true; return Result{} }); e == nil || called {
		t.Fatal("invalid grant reached source")
	}
}
